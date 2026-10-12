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

    private init(observedHost: String?) {
        self.observedHost = observedHost
    }

    /// Two connected ends; each observes the other at the given host.
    static func pair(
        _ firstObserves: String? = "203.0.113.7",
        _ secondObserves: String? = "198.51.100.9"
    ) -> (MemoryStream, MemoryStream) {
        let first = MemoryStream(observedHost: firstObserves)
        let second = MemoryStream(observedHost: secondObserves)
        first.peer = second
        second.peer = first
        return (first, second)
    }

    var isActive: Bool { lock.withLock { !closed } }
    var isWritable: Bool { true }
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
    var decoder: SessionFrameDecoder?

    init(_ bytes: Data) {
        remaining = bytes
    }

    /// Delivers one byte before returning, the way a stream with buffered
    /// input may.
    func requestBytes() {
        let byte = lock.withLock { remaining.popFirst() }
        guard let byte else { return }
        decoder?.receive(Data([byte]))
    }

    func close() { lock.withLock { didClose = true } }
    var isClosed: Bool { lock.withLock { didClose } }
}

@Suite("Byte stream seam")
struct TransportSeamTests {
    private func node(
        _ label: String,
        maxConnections: Int = IvyConfig.defaultMaxConnections
    ) -> (Ivy, Curve25519.Signing.PrivateKey, TransportTestRecorder) {
        let identity = TransportTestHarness.identity(label)
        let ivy = Ivy(config: TransportTestHarness.config(
            identity,
            port: TransportTestHarness.nextPort(),
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
