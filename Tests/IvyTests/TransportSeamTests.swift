import Crypto
import Foundation
import Testing
@testable import Ivy

/// One end of an in-memory byte stream. Bytes the other end sends wait here
/// until they are asked for; nothing about it is a socket or a NIO channel.
private final class MemoryStream: TransportConnection, @unchecked Sendable {
    let observedHost: String?
    let localHost: String? = nil

    private let lock = NSLock()
    /// Sink calls arrive one at a time, off the caller's stack.
    private let delivery = DispatchQueue(label: "ivy.tests.memory-stream")
    private weak var peer: MemoryStream?
    private var sink: (any TransportConnectionSink)?
    private var inbox = Data()
    private var requested = false
    private var closed = false
    private var requests = 0
    private var deliveries = 0
    /// What successive reads of `isWritable` report; the last one repeats.
    private var writability: [Bool]

    private init(observedHost: String?, writability: [Bool]) {
        self.observedHost = observedHost
        self.writability = writability
    }

    /// Two connected ends; each observes the other at the given host.
    static func pair(
        _ firstObserves: String? = "203.0.113.7",
        _ secondObserves: String? = "198.51.100.9",
        firstWritability: [Bool] = [true]
    ) -> (MemoryStream, MemoryStream) {
        let first = MemoryStream(observedHost: firstObserves, writability: firstWritability)
        let second = MemoryStream(observedHost: secondObserves, writability: [true])
        first.peer = second
        second.peer = first
        return (first, second)
    }

    var isActive: Bool { lock.withLock { !closed } }
    var isWritable: Bool {
        lock.withLock { writability.count > 1 ? writability.removeFirst() : writability[0] }
    }
    var requestCount: Int { lock.withLock { requests } }
    var deliveryCount: Int { lock.withLock { deliveries } }
    var undeliveredByteCount: Int { lock.withLock { inbox.count } }

    func attach(_ sink: any TransportConnectionSink) {
        let alreadyClosed = lock.withLock { () -> Bool in
            guard !closed else { return true }
            self.sink = sink
            return false
        }
        if alreadyClosed { delivery.async { sink.transportDidClose() } }
    }

    func requestBytes() {
        lock.withLock {
            requests += 1
            requested = true
        }
        deliverIfRequested()
    }

    func send(_ bytes: Data) {
        peer?.enqueue(bytes)
    }

    func close() {
        closeThisEnd()
        peer?.closeThisEnd()
    }

    private func enqueue(_ bytes: Data) {
        lock.withLock {
            guard !closed else { return }
            inbox.append(bytes)
        }
        deliverIfRequested()
    }

    private func deliverIfRequested() {
        let ready = lock.withLock { () -> (any TransportConnectionSink, Data)? in
            guard requested, !closed, !inbox.isEmpty, let sink else { return nil }
            defer { inbox = Data() }
            requested = false
            deliveries += 1
            return (sink, inbox)
        }
        guard let (sink, bytes) = ready else { return }
        delivery.async { sink.transportDidReceive(bytes) }
    }

    private func closeThisEnd() {
        let sink = lock.withLock { () -> (any TransportConnectionSink)? in
            guard !closed else { return nil }
            closed = true
            defer { self.sink = nil }
            return self.sink
        }
        guard let sink else { return }
        delivery.async { sink.transportDidClose() }
    }
}

private func framed(_ records: [Data]) -> Data {
    var bytes = Data()
    for record in records {
        withUnsafeBytes(of: UInt32(record.count).bigEndian) { bytes.append(contentsOf: $0) }
        bytes.append(record)
    }
    return bytes
}

private final class SynchronousFeed: @unchecked Sendable {
    private let lock = NSLock()
    private var remaining: Data
    private var didClose = false
    private var requests = 0
    var decoder: SessionFrameDecoder?

    init(_ bytes: Data) {
        remaining = bytes
    }

    /// Delivers one byte before returning, the way a stream with buffered
    /// input may.
    func requestBytes() {
        let byte = lock.withLock { () -> UInt8? in
            requests += 1
            return remaining.popFirst()
        }
        guard let byte else { return }
        decoder?.receive(Data([byte]))
    }

    func close() { lock.withLock { didClose = true } }
    var isClosed: Bool { lock.withLock { didClose } }
    var requestCount: Int { lock.withLock { requests } }
}

/// A stream that hands out seeded chunks, some before `requestBytes()` returns
/// and some after, and records how many requests were ever outstanding at once.
private final class SeededFeed: @unchecked Sendable {
    private let lock = NSLock()
    private let delivery = DispatchQueue(label: "ivy.tests.seeded-feed")
    private var generator: TestSeededGenerator
    private var remaining: Data
    private let maxChunk: Int
    private var outstanding = 0
    private var peakOutstanding = 0
    private var didClose = false
    var decoder: SessionFrameDecoder?

    init(_ bytes: Data, maxChunk: Int, seed: UInt64) {
        remaining = bytes
        self.maxChunk = maxChunk
        generator = TestSeededGenerator(seed: seed)
    }

    func requestBytes() {
        let inline = lock.withLock { () -> Bool in
            outstanding += 1
            peakOutstanding = max(peakOutstanding, outstanding)
            return generator.next() & 1 == 0
        }
        if inline { deliver() } else { delivery.async { self.deliver() } }
    }

    private func deliver() {
        let chunk = lock.withLock { () -> Data? in
            guard outstanding > 0, !remaining.isEmpty else { return nil }
            outstanding -= 1
            let count = min(remaining.count, Int(generator.next() % UInt64(maxChunk)) + 1)
            defer { remaining.removeFirst(count) }
            return Data(remaining.prefix(count))
        }
        if let chunk { decoder?.receive(chunk) }
    }

    func close() { lock.withLock { didClose = true } }
    var isClosed: Bool { lock.withLock { didClose } }
    var mostRequestsOutstanding: Int { lock.withLock { peakOutstanding } }
}

@Suite("Byte stream seam")
struct TransportSeamTests {
    private func node(
        _ label: String,
        port: UInt16? = nil,
        maxConnections: Int = IvyConfig.defaultMaxConnections
    ) -> (Ivy, Curve25519.Signing.PrivateKey, TransportTestRecorder) {
        let identity = TransportTestHarness.identity(label)
        let ivy = Ivy(config: TransportTestHarness.config(
            identity,
            port: port ?? TransportTestHarness.nextPort(),
            maxConnections: maxConnections))
        return (ivy, identity, TransportTestRecorder())
    }

    @Test("two nodes authenticate and exchange messages over streams pushed into them")
    func sessionOverPushedStreams() async throws {
        let (responder, responderIdentity, responderRecorder) = node("seam-session-responder")
        let (initiator, initiatorIdentity, initiatorRecorder) = node("seam-session-initiator")
        await responder.setTestDelegate(responderRecorder)
        await initiator.setTestDelegate(initiatorRecorder)
        try await responder.start()
        try await initiator.start()

        let (responderEnd, initiatorEnd) = MemoryStream.pair()
        let lease = try #require(
            responder.reserveInboundAdmission(observedHost: responderEnd.observedHost))
        responder.accept(responderEnd, admission: lease)
        let responderKey = TransportTestHarness.key(responderIdentity)
        let initiatorKey = TransportTestHarness.key(initiatorIdentity)
        try await initiator.connect(
            to: PeerEndpoint(publicKey: responderKey.hex, host: "198.51.100.9", port: 4001),
            over: initiatorEnd)

        try await responderRecorder.waitForConnect(initiatorKey.peerID)
        try await initiatorRecorder.waitForConnect(responderKey.peerID)
        #expect(responderRecorder.authenticatedPeers.map(\.key) == [initiatorKey])
        #expect(initiatorRecorder.authenticatedPeers.map(\.key) == [responderKey])
        #expect(responderEnd.isActive)
        #expect(initiatorEnd.isActive)

        let ping = Data("over the seam".utf8)
        let pong = Data("and back".utf8)
        _ = await initiator.sendMessage(to: responderKey.peerID, topic: "seam", payload: ping)
        _ = await responder.sendMessage(to: initiatorKey.peerID, topic: "seam", payload: pong)
        #expect(try await TransportTestHarness.eventually {
            responderRecorder.receivedMessage(topic: "seam", payload: ping, from: initiatorKey.peerID)
                && initiatorRecorder.receivedMessage(
                    topic: "seam", payload: pong, from: responderKey.peerID)
        })

        await initiator.stop()
        await responder.stop()
        #expect(!responderEnd.isActive)
        #expect(!initiatorEnd.isActive)
    }

    @Test("nothing is read from a stream before admission, and a refused stream is never read")
    func admissionPrecedesReading() async throws {
        let (ivy, _, _) = node("seam-admission", maxConnections: 1)
        #expect(ivy.reserveInboundAdmission(observedHost: "203.0.113.7") == nil)
        try await ivy.start()

        let stale = try #require(ivy.reserveInboundAdmission(observedHost: "203.0.113.7"))
        // The node's one inbound slot is taken: the next peer is refused
        // before a stream to it exists.
        #expect(ivy.reserveInboundAdmission(observedHost: "192.0.2.44") == nil)

        // A lease does not outlive the run that issued it. Its stream holds
        // input the peer already sent; none of it is asked for.
        await ivy.stop()
        try await ivy.start()
        let (refused, refusedPeer) = MemoryStream.pair()
        refusedPeer.send(Data([0, 0]))
        ivy.accept(refused, admission: stale)
        #expect(try await TransportTestHarness.eventually { !refused.isActive })
        #expect(refused.requestCount == 0)
        #expect(refused.deliveryCount == 0)

        let lease = try #require(ivy.reserveInboundAdmission(observedHost: "203.0.113.7"))
        let (admitted, admittedPeer) = MemoryStream.pair()
        admittedPeer.send(Data([0, 0]))
        #expect(admitted.requestCount == 0)
        #expect(admitted.deliveryCount == 0)
        #expect(admitted.undeliveredByteCount == 2)
        ivy.accept(admitted, admission: lease)
        #expect(try await TransportTestHarness.eventually { admitted.deliveryCount == 1 })
        #expect(admitted.undeliveredByteCount == 0)
        #expect(admitted.isActive)

        // A lease admits one stream.
        let (reused, reusedPeer) = MemoryStream.pair()
        reusedPeer.send(Data([0, 0]))
        ivy.accept(reused, admission: lease)
        #expect(!reused.isActive)
        #expect(reused.requestCount == 0)
        #expect(reused.deliveryCount == 0)

        await ivy.stop()
        #expect(!admitted.isActive)
    }

    @Test("a consumer out of budget stops asking the stream and resumes when budget is released")
    func exhaustedBudgetStopsRequests() async throws {
        let maxFrameSize: UInt32 = 1024
        let budget = InboundByteBudget(limit: IvyConfig.defaultMaxInboundBufferedBytes)
        let (local, remote) = MemoryStream.pair()
        let connection = PeerConnection.direct(
            endpoint: PeerEndpoint(publicKey: "", host: "unknown", port: 0),
            stream: local,
            inboundByteBudget: budget,
            maxFrameSize: maxFrameSize)
        let decoder = try #require(connection.frameDecoder)
        let records = (0..<7).map { Data(repeating: UInt8($0), count: Int(maxFrameSize)) }

        // Six maximum frames in one delivery overrun the two-frame connection
        // budget: two are decoded and the rest wait undecoded.
        remote.send(framed(Array(records.prefix(6))))
        connection.startReading()
        var held: [InboundFrame] = []
        held.append(try #require(await decoder.next()))
        held.append(try #require(await decoder.next()))
        #expect(held.map(\.bytes) == Array(records.prefix(2)))
        #expect(budget.currentUsage == 2 * Int(maxFrameSize))
        // Let anything still in flight land before asserting nothing was asked.
        try await Task.sleep(for: .milliseconds(50))
        #expect(local.requestCount == 1)

        // While the consumer holds its frames nothing more is asked for: what
        // the peer sends next stays in the stream.
        remote.send(framed([records[6]]))
        #expect(local.requestCount == 1)
        #expect(local.deliveryCount == 1)
        #expect(local.undeliveredByteCount == 4 + Int(maxFrameSize))
        #expect(connection.isLive)

        held.removeAll()
        var received = Array(records.prefix(2))
        while received.count < records.count {
            received.append(try #require(await decoder.next()).bytes)
        }
        #expect(received == records)
        #expect(local.requestCount > 1)
        #expect(local.undeliveredByteCount == 0)
        #expect(try await TransportTestHarness.eventually { budget.currentUsage == 0 })

        connection.cancel()
        #expect(!remote.isActive)
    }

    @Test("a stream that delivers inside the request is decoded without recursion")
    func synchronousDelivery() async throws {
        let record = Data(repeating: 0xAB, count: 200_000)
        let feed = SynchronousFeed(framed([record]))
        let decoder = SessionFrameDecoder(
            maxFrameSize: 1 << 20,
            budget: InboundByteBudget(limit: IvyConfig.defaultMaxInboundBufferedBytes),
            connectionBudget: InboundByteBudget(limit: 1 << 21),
            requestBytes: { feed.requestBytes() },
            close: { feed.close() })
        feed.decoder = decoder

        decoder.start()
        #expect(await decoder.next()?.bytes == record)
        #expect(!feed.isClosed)
        decoder.finish()
    }

    @Test("an empty delivery leaves the request outstanding")
    func emptyDelivery() async throws {
        let record = Data([1, 2, 3])
        let feed = SynchronousFeed(Data())
        let decoder = SessionFrameDecoder(
            maxFrameSize: 1024,
            budget: InboundByteBudget(limit: IvyConfig.defaultMaxInboundBufferedBytes),
            connectionBudget: InboundByteBudget(limit: 2052),
            requestBytes: { feed.requestBytes() },
            close: { feed.close() })

        decoder.start()
        decoder.receive(Data())
        decoder.receive(Data())
        #expect(feed.requestCount == 1)
        #expect(!feed.isClosed)

        decoder.receive(framed([record]))
        #expect(await decoder.next()?.bytes == record)
        #expect(!feed.isClosed)
        decoder.finish()
    }

    @Test("seeded streams sharing one budget decode in order, one request at a time, and leak nothing")
    func seededSharedBudget() async throws {
        let maxFrameSize: UInt32 = 64
        var generator = TestSeededGenerator(seed: 0x5EA4_0001)
        for iteration in 0..<48 {
            let streams = Int(generator.next() % 4) + 1
            let budget = InboundByteBudget(
                limit: streams * Int(maxFrameSize) + 4 + Int(generator.next() % 40))
            var feeds: [SeededFeed] = []
            var decoders: [SessionFrameDecoder] = []
            var expected: [[Data]] = []
            for stream in 0..<streams {
                let records = (0..<Int(generator.next() % 40) + 1).map { index in
                    Data(
                        repeating: UInt8(truncatingIfNeeded: index &+ stream),
                        count: Int(generator.next() % UInt64(maxFrameSize)) + 1)
                }
                let feed = SeededFeed(
                    framed(records),
                    maxChunk: [1, 3, 17, 200, 4000][Int(generator.next() % 5)],
                    seed: generator.next())
                let decoder = SessionFrameDecoder(
                    maxFrameSize: maxFrameSize,
                    budget: budget,
                    connectionBudget: InboundByteBudget(
                        limit: PeerConnection.inboundByteBudgetLimit(for: maxFrameSize)),
                    requestBytes: { feed.requestBytes() },
                    close: { feed.close() })
                feed.decoder = decoder
                feeds.append(feed)
                decoders.append(decoder)
                expected.append(records)
            }

            let consumers = zip(decoders, expected).map { decoder, records in
                BoundedTestTask { () -> [Data] in
                    var received: [Data] = []
                    decoder.start()
                    while received.count < records.count, let frame = await decoder.next() {
                        received.append(frame.bytes)
                    }
                    return received
                }
            }
            for (index, consumer) in consumers.enumerated() {
                let received = try await consumer.value(waitingFor: "stream \(index), iteration \(iteration)")
                #expect(received == expected[index], "iteration \(iteration)")
            }
            for feed in feeds {
                #expect(feed.mostRequestsOutstanding == 1, "iteration \(iteration)")
                #expect(!feed.isClosed, "iteration \(iteration)")
            }
            for decoder in decoders { decoder.finish() }
            #expect(budget.currentUsage == 0, "iteration \(iteration)")
        }
    }

    @Test("a lease admits only a stream of the netgroup it was reserved for")
    func leaseBoundToNetgroup() async throws {
        let (ivy, _, _) = node("seam-lease-netgroup", maxConnections: 1)
        try await ivy.start()

        let lease = try #require(ivy.reserveInboundAdmission(observedHost: "203.0.113.7"))
        let (stream, peer) = MemoryStream.pair("192.0.2.44")
        peer.send(Data([0, 0]))
        ivy.accept(stream, admission: lease)
        #expect(!stream.isActive)
        #expect(stream.requestCount == 0)
        #expect(stream.deliveryCount == 0)
        // The refused lease gave its slot back: the node's one slot is free.
        #expect(ivy.reserveInboundAdmission(observedHost: "203.0.113.7") != nil)

        await ivy.stop()
    }

    @Test("a stream that reports no observed host is refused on both entry points")
    func hostlessStreamIsRefused() async throws {
        let (ivy, _, _) = node("seam-hostless", maxConnections: 1)
        let remoteIdentity = TransportTestHarness.identity("seam-hostless-remote")
        try await ivy.start()
        #expect(ivy.reserveInboundAdmission(observedHost: nil) == nil)
        #expect(ivy.reserveInboundAdmission(observedHost: "") == nil)

        for host in [nil, ""] as [String?] {
            // Reserved under the bucket a missing host used to fall into.
            let lease = try #require(ivy.reserveInboundAdmission(observedHost: "unknown"))
            let (stream, peer) = MemoryStream.pair(host)
            peer.send(Data([0, 0]))
            ivy.accept(stream, admission: lease)
            #expect(!stream.isActive)
            #expect(stream.requestCount == 0)
            #expect(stream.deliveryCount == 0)
        }
        // No lease is left held: the node's one slot is free.
        #expect(ivy.reserveInboundAdmission(observedHost: "unknown") != nil)

        let (_, outbound) = MemoryStream.pair("203.0.113.7", nil)
        await #expect(throws: IvyError.streamHasNoObservedHost) {
            try await ivy.connect(
                to: PeerEndpoint(
                    publicKey: TransportTestHarness.key(remoteIdentity).hex,
                    host: "198.51.100.9",
                    port: 4001),
                over: outbound)
        }
        #expect(!outbound.isActive)
        #expect(outbound.requestCount == 0)

        await ivy.stop()
    }

    @Test("a lease from another node is refused unread")
    func leaseBoundToItsNode() async throws {
        let (ivy, _, _) = node("seam-lease-own-node", maxConnections: 1)
        let (other, _, _) = node("seam-lease-other-node", maxConnections: 1)
        try await ivy.start()
        try await other.start()

        let foreign = try #require(other.reserveInboundAdmission(observedHost: "203.0.113.7"))
        let (stream, peer) = MemoryStream.pair("203.0.113.7")
        peer.send(Data([0, 0]))
        ivy.accept(stream, admission: foreign)
        #expect(try await TransportTestHarness.eventually { !stream.isActive })
        #expect(stream.requestCount == 0)
        #expect(stream.deliveryCount == 0)
        #expect(await ivy.pendingSessionCountForTesting == 0)
        // The issuing node gets its one slot back.
        #expect(other.reserveInboundAdmission(observedHost: "203.0.113.7") != nil)

        await ivy.stop()
        await other.stop()
    }

    @Test("writability that changes between creation and attach is not lost")
    func writabilityBetweenInitAndAttach() async throws {
        let budget = InboundByteBudget(limit: IvyConfig.defaultMaxInboundBufferedBytes)
        let endpoint = PeerEndpoint(publicKey: "", host: "unknown", port: 0)

        let (blocked, _) = MemoryStream.pair(firstWritability: [true, false])
        let backpressured = PeerConnection.direct(
            endpoint: endpoint, stream: blocked, inboundByteBudget: budget)
        #expect(backpressured.sendReadiness() == .backpressured)

        let (recovered, _) = MemoryStream.pair(firstWritability: [false, true])
        let ready = PeerConnection.direct(
            endpoint: endpoint, stream: recovered, inboundByteBudget: budget)
        #expect(ready.sendReadiness() == .ready)
    }

    @Test("a supplied stream that does not become the session is closed")
    func unusedSuppliedStreamIsClosed() async throws {
        let (responder, responderIdentity, responderRecorder) = node("seam-unused-responder")
        let (initiator, initiatorIdentity, _) = node("seam-unused-initiator")
        await responder.setTestDelegate(responderRecorder)
        let responderKey = TransportTestHarness.key(responderIdentity)
        let endpoint = PeerEndpoint(publicKey: responderKey.hex, host: "198.51.100.9", port: 4001)

        // Not running: nothing is attempted.
        let (_, early) = MemoryStream.pair()
        await #expect(throws: IvyError.self) {
            try await initiator.connect(to: endpoint, over: early)
        }
        #expect(!early.isActive)
        #expect(early.requestCount == 0)

        try await responder.start()
        try await initiator.start()

        let (_, misaddressed) = MemoryStream.pair()
        await #expect(throws: IvyError.self) {
            try await initiator.connect(
                to: PeerEndpoint(publicKey: "not a key", host: "198.51.100.9", port: 4001),
                over: misaddressed)
        }
        #expect(!misaddressed.isActive)

        let (responderEnd, initiatorEnd) = MemoryStream.pair()
        let lease = try #require(
            responder.reserveInboundAdmission(observedHost: responderEnd.observedHost))
        responder.accept(responderEnd, admission: lease)
        try await initiator.connect(to: endpoint, over: initiatorEnd)
        try await responderRecorder.waitForConnect(TransportTestHarness.key(initiatorIdentity).peerID)

        // Already connected: the second stream is not needed.
        let (_, spare) = MemoryStream.pair()
        try await initiator.connect(to: endpoint, over: spare)
        #expect(!spare.isActive)
        #expect(spare.requestCount == 0)
        #expect(initiatorEnd.isActive)

        await initiator.stop()
        await responder.stop()
    }

    @Test("a supplied stream's address does not enter routing")
    func suppliedStreamAddressIsNotRouted() async throws {
        // The responder advertises no listen address, so the initiator has
        // only the caller's endpoint to fall back on.
        let (responder, responderIdentity, _) = node("seam-routing-responder", port: 0)
        let (initiator, _, initiatorRecorder) = node("seam-routing-initiator")
        await initiator.setTestDelegate(initiatorRecorder)
        try await responder.start()
        try await initiator.start()

        let (responderEnd, initiatorEnd) = MemoryStream.pair()
        let lease = try #require(
            responder.reserveInboundAdmission(observedHost: responderEnd.observedHost))
        responder.accept(responderEnd, admission: lease)
        let responderKey = TransportTestHarness.key(responderIdentity)
        try await initiator.connect(
            to: PeerEndpoint(publicKey: responderKey.hex, host: "198.51.100.9", port: 4001),
            over: initiatorEnd)
        try await initiatorRecorder.waitForConnect(responderKey.peerID)

        #expect(await initiator.peerConnectionCount == 1)
        #expect(await initiator.knownPeerEndpoints.isEmpty)
        #expect(await initiator.connectedPeerEndpoints.map(\.host) == ["unknown"])

        await initiator.stop()
        await responder.stop()
    }

    @Test("bytes the decoder did not ask for close the connection")
    func unrequestedBytesClose() async throws {
        let budget = InboundByteBudget(limit: IvyConfig.defaultMaxInboundBufferedBytes)
        let feed = SynchronousFeed(Data())
        let decoder = SessionFrameDecoder(
            maxFrameSize: 1024,
            budget: budget,
            connectionBudget: InboundByteBudget(limit: 2052),
            requestBytes: {},
            close: { feed.close() })

        decoder.receive(framed([Data([1, 2, 3])]))
        #expect(feed.isClosed)
        #expect(budget.currentUsage == 0)
        #expect(await decoder.next()?.bytes == nil)
    }
}
