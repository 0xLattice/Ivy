import Foundation
import NIOCore
import NIOPosix
import Testing
@testable import Ivy

/// A one-shot latch: `wait()` suspends until `open()`; no polling.
private final class Latch: @unchecked Sendable {
    private let lock = NSLock()
    private var isOpen = false
    private var waiters: [CheckedContinuation<Void, Never>] = []

    func open() {
        let resumed = lock.withLock { () -> [CheckedContinuation<Void, Never>] in
            isOpen = true
            defer { waiters.removeAll() }
            return waiters
        }
        for waiter in resumed { waiter.resume() }
    }

    func wait() async {
        await withCheckedContinuation { continuation in
            let resumeNow = lock.withLock { () -> Bool in
                if isOpen { return true }
                waiters.append(continuation)
                return false
            }
            if resumeNow { continuation.resume() }
        }
    }
}

private struct DeadlineExceeded: Error, CustomStringConvertible {
    let operation: String
    var description: String { "deadline exceeded waiting for \(operation)" }
}

/// Fails, rather than hangs, if `operation` never completes. The clock only
/// bounds a broken run; it never orders events. The body is not awaited after
/// the deadline, since latches and `Task.value` ignore cancellation.
private func withinDeadline<T: Sendable>(
    _ operation: String,
    _ body: @escaping @Sendable () async throws -> T
) async throws -> T {
    let outcome = DeadlineOutcome<T>()
    return try await withCheckedThrowingContinuation { continuation in
        outcome.install(continuation)
        let timer = Task {
            try await Task.sleep(for: .seconds(30))
            outcome.finish(.failure(DeadlineExceeded(operation: operation)))
        }
        Task {
            outcome.finish(await Result(catching: body))
            timer.cancel()
        }
    }
}

private final class DeadlineOutcome<T: Sendable>: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<T, Error>?

    func install(_ continuation: CheckedContinuation<T, Error>) {
        lock.withLock { self.continuation = continuation }
    }

    func finish(_ result: Result<T, Error>) {
        let continuation = lock.withLock { () -> CheckedContinuation<T, Error>? in
            defer { self.continuation = nil }
            return self.continuation
        }
        continuation?.resume(with: result)
    }
}

extension Result where Failure == Error {
    fileprivate init(catching body: () async throws -> Success) async {
        do { self = .success(try await body()) } catch { self = .failure(error) }
    }
}

private let maxFrameSize: UInt32 = 1024

private func frame(_ index: Int) -> Data {
    var bytes = Data(repeating: UInt8(truncatingIfNeeded: index), count: Int(maxFrameSize))
    bytes[0] = 0xF0
    bytes[1] = UInt8(truncatingIfNeeded: index)
    return bytes
}

private func framed(_ records: [Data], allocator: ByteBufferAllocator) -> ByteBuffer {
    var buffer = allocator.buffer(capacity: records.reduce(0) { $0 + 4 + $1.count })
    for record in records {
        buffer.writeInteger(UInt32(record.count), endianness: .big)
        buffer.writeBytes(record)
    }
    return buffer
}

/// One accepted server-side connection built with Ivy's inbound pipeline.
private struct Accepted: @unchecked Sendable {
    let channel: Channel
    let connection: PeerConnection
    let decoder: SessionFrameDecoder
    let connectionBudget: InboundByteBudget

    func onPaused(_ report: @escaping @Sendable (Int) -> Void) async throws {
        decoder.onPausedForTesting = report
    }

    /// Consumes `count` frames the way `Ivy.startInboundTask` does: each frame
    /// keeps its reservation until handled; handling waits on `gate`.
    func consume(
        _ count: Int,
        gate: Latch?,
        firstReceived: Latch? = nil
    ) -> Task<[Data], Error> {
        let decoder = decoder
        let connection = connection
        let task = Task<[Data], Error> {
            var received: [Data] = []
            while let frame = await decoder.next() {
                firstReceived?.open()
                await gate?.wait()
                received.append(frame.bytes)
                if received.count == count { break }
            }
            connection.cancel()
            return received
        }
        connection.startReading()
        return task
    }
}

/// A listener whose child pipeline matches `Ivy.startListener`: a NIO-backed
/// stream that reads only on request, under the session frame decoder.
private struct Server {
    let listener: Channel
    let accepted: AsyncStream<Accepted>
    let budget: InboundByteBudget

    static func open(
        budget: InboundByteBudget = InboundByteBudget(limit: IvyConfig.defaultMaxInboundBufferedBytes)
    ) async throws -> Server {
        let (accepted, continuation) = AsyncStream<Accepted>.makeStream()
        let listener = try await ServerBootstrap(group: MultiThreadedEventLoopGroup.singleton)
            .childChannelOption(ChannelOptions.autoRead, value: false)
            .childChannelInitializer { channel in
                let connectionBudget = InboundByteBudget(
                    limit: PeerConnection.inboundByteBudgetLimit(for: maxFrameSize))
                let stream = NIOTransportConnection(channel: channel)
                let decoder = SessionFrameDecoder(
                    maxFrameSize: maxFrameSize,
                    budget: budget,
                    connectionBudget: connectionBudget,
                    requestBytes: { stream.requestBytes() },
                    close: { stream.close() })
                do {
                    try channel.pipeline.syncOperations.addHandler(stream)
                    let connection = PeerConnection(
                        endpoint: PeerEndpoint(publicKey: "", host: "unknown", port: 0),
                        stream: stream,
                        decoder: decoder,
                        inboundByteBudget: budget,
                        connectionInboundByteBudget: connectionBudget,
                        localMaxFrameSize: maxFrameSize)
                    stream.attach(connection)
                    continuation.yield(Accepted(
                        channel: channel,
                        connection: connection,
                        decoder: decoder,
                        connectionBudget: connectionBudget))
                    return channel.eventLoop.makeSucceededVoidFuture()
                } catch {
                    return channel.eventLoop.makeFailedFuture(error)
                }
            }
            .bind(host: "127.0.0.1", port: 0).get()
        return Server(listener: listener, accepted: accepted, budget: budget)
    }

    func connect() async throws -> (client: Channel, accepted: Accepted) {
        let address = try #require(listener.localAddress)
        let client = try await ClientBootstrap(group: MultiThreadedEventLoopGroup.singleton)
            .connect(to: address).get()
        let accepted = try await withinDeadline("accept") { [accepted] in
            var iterator = accepted.makeAsyncIterator()
            return try #require(await iterator.next())
        }
        return (client, accepted)
    }
}

@Suite("Inbound byte budget backpressure")
struct InboundBackpressureTests {
    @Test("a held consumer receives every frame, in order, once released")
    func heldConsumerReceivesEveryFrame() async throws {
        let server = try await Server.open()
        defer { _ = server.listener.close() }
        let (client, accepted) = try await server.connect()
        defer { _ = client.close() }

        let frames = (0..<6).map(frame)
        let gate = Latch()
        let firstReceived = Latch()
        let consumer = accepted.consume(frames.count, gate: gate, firstReceived: firstReceived)
        // One write of six maximum frames: the socket read event that delivers
        // them overruns the two-frame connection budget while the consumer
        // holds the first frame.
        try await client.writeAndFlush(framed(frames, allocator: client.allocator)).get()
        try await withinDeadline("first frame") { await firstReceived.wait() }
        gate.open()

        let received = try await withinDeadline("all frames") { try await consumer.value }
        #expect(received == frames)
    }

    @Test("while the consumer is held, reservations stay within the budget")
    func heldConsumerStaysWithinBudget() async throws {
        let server = try await Server.open()
        defer { _ = server.listener.close() }
        let (client, accepted) = try await server.connect()
        defer { _ = client.close() }

        let paused = Latch()
        let peakUsage = PeakUsage()
        let connectionBudget = accepted.connectionBudget
        try await accepted.onPaused { _ in
            peakUsage.record(connectionBudget.currentUsage)
            paused.open()
        }

        let frames = (0..<6).map(frame)
        let gate = Latch()
        let consumer = accepted.consume(frames.count, gate: gate)
        try await client.writeAndFlush(framed(frames, allocator: client.allocator)).get()
        try await withinDeadline("decoder pause") { await paused.wait() }

        let limit = PeerConnection.inboundByteBudgetLimit(for: maxFrameSize)
        #expect(accepted.channel.isActive)
        #expect(connectionBudget.currentUsage <= limit)
        #expect(server.budget.currentUsage == connectionBudget.currentUsage)

        gate.open()
        let received = try await withinDeadline("all frames") { try await consumer.value }
        #expect(received == frames)
        #expect(peakUsage.value > 0 && peakUsage.value <= limit)
    }

    @Test("a declared length above the maximum frame closes even while the consumer is held")
    func oversizeHeaderCloses() async throws {
        let server = try await Server.open()
        defer { _ = server.listener.close() }
        let (client, accepted) = try await server.connect()
        defer { _ = client.close() }

        let gate = Latch()
        let consumer = accepted.consume(3, gate: gate)
        var bytes = framed([frame(0), frame(1)], allocator: client.allocator)
        bytes.writeInteger(maxFrameSize + 1, endianness: .big)
        bytes.writeBytes(Data(repeating: 0xAA, count: 16))
        try await client.writeAndFlush(bytes).get()

        let channel = accepted.channel
        try await withinDeadline("violator close") { try await channel.closeFuture.get() }
        #expect(!channel.isActive)
        gate.open()
        _ = try? await consumer.value
    }

    @Test("a held consumer on one connection does not slow another")
    func slowConnectionDoesNotAffectFastOne() async throws {
        let server = try await Server.open()
        defer { _ = server.listener.close() }
        let (slowClient, slow) = try await server.connect()
        defer { _ = slowClient.close() }

        let slowPaused = Latch()
        try await slow.onPaused { _ in slowPaused.open() }
        let slowFrames = (0..<6).map(frame)
        let slowGate = Latch()
        let slowConsumer = slow.consume(slowFrames.count, gate: slowGate)
        try await slowClient.writeAndFlush(framed(slowFrames, allocator: slowClient.allocator)).get()
        try await withinDeadline("slow decoder pause") { await slowPaused.wait() }

        let (fastClient, fast) = try await server.connect()
        defer { _ = fastClient.close() }
        let fastFrames = (10..<20).map(frame)
        let fastConsumer = fast.consume(fastFrames.count, gate: nil)
        try await fastClient.writeAndFlush(framed(fastFrames, allocator: fastClient.allocator)).get()
        let fastReceived = try await withinDeadline("fast frames") { try await fastConsumer.value }
        #expect(fastReceived == fastFrames)

        #expect(slow.channel.isActive)
        #expect(slow.connectionBudget.currentUsage == 2 * Int(maxFrameSize))
        slowGate.open()
        let slowReceived = try await withinDeadline("slow frames") { try await slowConsumer.value }
        #expect(slowReceived == slowFrames)
    }

    @Test("a connection paused on the global budget resumes when another connection releases")
    func globalBudgetReleaseWakesAnotherConnection() async throws {
        // Room for one connection's two held frames plus two headers, so the
        // second connection's first body is refused by the GLOBAL budget.
        let server = try await Server.open(budget: InboundByteBudget(limit: 2 * Int(maxFrameSize) + 8))
        defer { _ = server.listener.close() }
        let (aClient, a) = try await server.connect()
        defer { _ = aClient.close() }
        let aPaused = Latch()
        try await a.onPaused { _ in aPaused.open() }
        let aGate = Latch()
        let aFrames = (0..<4).map(frame)
        let aConsumer = a.consume(aFrames.count, gate: aGate)
        try await aClient.writeAndFlush(framed(aFrames, allocator: aClient.allocator)).get()
        try await withinDeadline("a pause") { await aPaused.wait() }

        let (bClient, b) = try await server.connect()
        defer { _ = bClient.close() }
        let bPaused = Latch()
        try await b.onPaused { _ in bPaused.open() }
        let bFrames = (10..<20).map(frame)
        let bConsumer = b.consume(bFrames.count, gate: nil)
        try await bClient.writeAndFlush(framed(bFrames, allocator: bClient.allocator)).get()
        try await withinDeadline("b pause") { await bPaused.wait() }
        #expect(b.channel.isActive)
        // B holds nothing, so its refusal came from the global budget, which
        // A's two held frames fill beyond room for another frame body.
        #expect(b.connectionBudget.currentUsage == 0)
        #expect(server.budget.currentUsage == a.connectionBudget.currentUsage)
        #expect(server.budget.currentUsage + Int(maxFrameSize) > server.budget.limit)

        aGate.open()
        let bReceived = try await withinDeadline("b frames") { try await bConsumer.value }
        #expect(bReceived == bFrames)
        let aReceived = try await withinDeadline("a frames") { try await aConsumer.value }
        #expect(aReceived == aFrames)
    }

    @Test("a paused decoder withholds socket reads and forwards one when budget frees")
    func pausedDecoderWithholdsReads() async throws {
        let connectionBudget = InboundByteBudget(
            limit: PeerConnection.inboundByteBudgetLimit(for: maxFrameSize))
        let budget = InboundByteBudget(limit: IvyConfig.defaultMaxInboundBufferedBytes)
        let reads = ReadCounter()
        let holder = FrameHolder()
        let decoder = SessionFrameDecoder(
            maxFrameSize: maxFrameSize,
            budget: budget,
            connectionBudget: connectionBudget,
            requestBytes: { reads.requested() },
            close: { reads.closed() })
        let carryOver = PausedReports()
        decoder.onPausedForTesting = { carryOver.append($0) }
        decoder.start()

        let frames = (0..<3).map(frame)
        let bytes = framed(frames, allocator: ByteBufferAllocator())
        decoder.receive(Data(bytes.readableBytesView))
        holder.take(from: decoder)
        #expect(!reads.isClosed)
        #expect(holder.frames.map(\.bytes) == Array(frames.prefix(2)))
        // Two held frames; the third frame's body waits for budget.
        #expect(connectionBudget.currentUsage == 2 * Int(maxFrameSize))
        #expect(carryOver.values == [Int(maxFrameSize)])

        // The request that follows the delivery is withheld while paused.
        let baseline = reads.count
        #expect(baseline == 1)

        holder.releaseFirst()
        try await TestSynchronization.wait(for: "withheld read") { reads.count > baseline }
        holder.take(from: decoder)
        #expect(holder.delivered == frames)
        #expect(reads.count == baseline + 1)
        #expect(!reads.isClosed)

        holder.releaseAll()
        #expect(connectionBudget.currentUsage == 0)
        #expect(budget.currentUsage == 0)
        decoder.finish()
    }
}

private final class PeakUsage: @unchecked Sendable {
    private let lock = NSLock()
    private var peak = 0

    func record(_ usage: Int) { lock.withLock { peak = max(peak, usage) } }
    var value: Int { lock.withLock { peak } }
}

private final class ReadCounter: @unchecked Sendable {
    private let lock = NSLock()
    private var requests = 0
    private var didClose = false

    func requested() { lock.withLock { requests += 1 } }
    func closed() { lock.withLock { didClose = true } }
    var count: Int { lock.withLock { requests } }
    var isClosed: Bool { lock.withLock { didClose } }
}

private final class PausedReports: @unchecked Sendable {
    private let lock = NSLock()
    private var reports: [Int] = []

    func append(_ carryOverBytes: Int) { lock.withLock { reports.append(carryOverBytes) } }
    var values: [Int] { lock.withLock { reports } }
}

private final class FrameHolder: @unchecked Sendable {
    private(set) var frames: [InboundFrame] = []
    private(set) var delivered: [Data] = []

    func take(from decoder: SessionFrameDecoder) {
        for frame in decoder.takeFramesForTesting() {
            frames.append(frame)
            delivered.append(frame.bytes)
        }
    }

    func releaseFirst() { frames.removeFirst() }
    func releaseAll() { frames.removeAll() }
}
