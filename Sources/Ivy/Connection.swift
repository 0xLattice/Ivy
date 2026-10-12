import Foundation
import NIOCore

final class InboundAdmissionGate: @unchecked Sendable {
    private let lock = NSLock()
    private let maxConnections: Int
    private let maxConnectionsPerNetgroup: Int
    private let generation: UInt64
    private var accepting = true
    private var count = 0
    private var countsByNetgroup: [String: Int] = [:]

    init(maxConnections: Int, maxConnectionsPerNetgroup: Int, generation: UInt64 = 0) {
        self.maxConnections = maxConnections
        self.maxConnectionsPerNetgroup = maxConnectionsPerNetgroup
        self.generation = generation
    }

    func reserve(observedHost: String?) -> InboundAdmissionLease? {
        let netgroup = NetGroup.group(observedHost ?? "unknown")
        return lock.withLock {
            guard accepting,
                  count < maxConnections,
                  countsByNetgroup[netgroup, default: 0] < maxConnectionsPerNetgroup else {
                return nil
            }
            count += 1
            countsByNetgroup[netgroup, default: 0] += 1
            return InboundAdmissionLease(
                gate: self,
                netgroup: netgroup,
                generation: generation
            ) { [weak self] in
                self?.release(netgroup: netgroup)
            }
        }
    }

    func invalidate() {
        lock.withLock { accepting = false }
    }

    private func release(netgroup: String) {
        lock.withLock {
            count -= 1
            if countsByNetgroup[netgroup] == 1 {
                countsByNetgroup.removeValue(forKey: netgroup)
            } else {
                countsByNetgroup[netgroup, default: 0] -= 1
            }
        }
    }
}

/// The running node's admission gate, readable off the actor so a stream can
/// be admitted before anything is spent on its peer.
final class CurrentInboundAdmissionGate: @unchecked Sendable {
    private let lock = NSLock()
    private var gate: InboundAdmissionGate?

    var current: InboundAdmissionGate? { lock.withLock { gate } }

    @discardableResult
    func replace(with gate: InboundAdmissionGate?) -> InboundAdmissionGate? {
        lock.withLock {
            defer { self.gate = gate }
            return self.gate
        }
    }
}

/// One reserved inbound connection slot, from `Ivy.reserveInboundAdmission`.
/// The slot is freed when the connection it admitted closes or authenticates,
/// or when an unused lease is dropped.
public final class InboundAdmissionLease: @unchecked Sendable {
    private let lock = NSLock()
    private var releaseAction: (() -> Void)?
    private var claimed = false
    /// The gate that issued this lease and the netgroup it counted; a lease
    /// admits only a stream of that netgroup, into that gate's run.
    private(set) weak var gate: InboundAdmissionGate?
    let netgroup: String
    let generation: UInt64

    init(
        gate: InboundAdmissionGate,
        netgroup: String,
        generation: UInt64,
        release: @escaping () -> Void
    ) {
        self.gate = gate
        self.netgroup = netgroup
        self.generation = generation
        releaseAction = release
    }

    /// A lease admits one connection: true only for its first caller.
    func claim() -> Bool {
        lock.withLock {
            guard !claimed else { return false }
            claimed = true
            return true
        }
    }

    func release() {
        let action = lock.withLock { () -> (() -> Void)? in
            defer { releaseAction = nil }
            return releaseAction
        }
        action?()
    }

    deinit { release() }
}

/// Wakes a paused `SessionFrameDecoder` when budget it waits on is released.
final class InboundBudgetWaiter: Sendable {
    let wake: @Sendable () -> Void

    init(wake: @escaping @Sendable () -> Void) {
        self.wake = wake
    }
}

final class InboundByteBudget: @unchecked Sendable {
    private let lock = NSLock()
    let limit: Int
    private var used = 0
    private var waiters: [ObjectIdentifier: InboundBudgetWaiter] = [:]

    init(limit: Int) {
        self.limit = limit
    }

    /// Reserves `byteCount`, or registers `waiter` to be woken on the next
    /// release. Check and registration share the lock, so no release is missed.
    fileprivate func reserve(_ byteCount: Int, waiter: InboundBudgetWaiter?) -> Bool {
        guard byteCount >= 0 else { return false }
        return lock.withLock {
            guard byteCount <= limit - used else {
                if let waiter { waiters[ObjectIdentifier(waiter)] = waiter }
                return false
            }
            used += byteCount
            return true
        }
    }

    var currentUsage: Int { lock.withLock { used } }

    fileprivate func release(_ byteCount: Int) {
        let woken = lock.withLock { () -> [InboundBudgetWaiter] in
            used -= byteCount
            guard byteCount > 0, !waiters.isEmpty else { return [] }
            defer { waiters.removeAll() }
            return Array(waiters.values)
        }
        for waiter in woken { waiter.wake() }
    }

    fileprivate func cancelWait(_ waiter: InboundBudgetWaiter) {
        lock.withLock { _ = waiters.removeValue(forKey: ObjectIdentifier(waiter)) }
    }
}

final class InboundByteReservation: @unchecked Sendable {
    private let budgets: [InboundByteBudget]
    private var byteCount = 0

    init(budgets: [InboundByteBudget]) {
        self.budgets = budgets
    }

    /// All-or-nothing across every budget. On failure `waiter`, if given, is
    /// registered with the budget that refused, to be woken when it frees.
    func acquire(_ count: Int, waiter: InboundBudgetWaiter? = nil) -> Bool {
        var acquired: [InboundByteBudget] = []
        for budget in budgets {
            guard budget.reserve(count, waiter: waiter) else {
                for budget in acquired { budget.release(count) }
                return false
            }
            acquired.append(budget)
        }
        byteCount += count
        return true
    }

    deinit {
        for budget in budgets { budget.release(byteCount) }
    }
}

struct InboundFrame: Sendable {
    let bytes: Data
    private let reservation: InboundByteReservation

    init(bytes: Data, reservation: InboundByteReservation) {
        self.bytes = bytes
        self.reservation = reservation
    }
}

private final class WritabilityWaiter: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<Bool, Never>?
    private var result: Bool?

    func install(_ continuation: CheckedContinuation<Bool, Never>) {
        let result = lock.withLock { () -> Bool? in
            guard let result = self.result else {
                self.continuation = continuation
                return nil
            }
            return result
        }
        if let result { continuation.resume(returning: result) }
    }

    func resume(_ result: Bool) {
        let continuation = lock.withLock { () -> CheckedContinuation<Bool, Never>? in
            guard self.result == nil else { return nil }
            self.result = result
            defer { self.continuation = nil }
            return self.continuation
        }
        continuation?.resume(returning: result)
    }
}

final class PeerConnection: @unchecked Sendable {
    static let maxInboundBufferedRecords = 4

    let connectionID = UUID()
    var endpoint: PeerEndpoint
    var observedHost: String?
    /// Max frame the PEER advertised it will accept (set from the handshake
    /// metadata). Outbound frames are capped here so we never send more than the
    /// peer will take. Defaults to the protocol default until the handshake lands.
    var peerMaxFrameSize: UInt32 = IvyConfig.defaultProtocolMaxFrameSize
    /// Max frame THIS node accepts inbound on this connection (the operator's
    /// configured `protocolMaxFrameSize`). Bounds `feedRecord` and the connection
    /// byte budget so both scale with the configured size, not the default.
    let localMaxFrameSize: UInt32
    /// Inbound byte budget that holds one maximum local frame plus its header.
    static func inboundByteBudgetLimit(for maxFrameSize: UInt32) -> Int {
        2 * Int(maxFrameSize) + 4
    }

    enum Transport {
        case direct(any TransportConnection)
        case relayed(routeID: Data, carrier: PeerKey)
    }

    enum SendResult: Sendable, Equatable {
        case sent
        case backpressured
        case locallyRejected
        case notConnected
    }

    enum SendReadiness: Sendable, Equatable {
        case ready
        case backpressured
        case notConnected
    }

    let transport: Transport
    let inboundBufferLimit: Int
    private let stateLock = NSLock()
    private var closed = false
    private var writable: Bool
    private var closeHandler: (@Sendable () -> Void)?
    private var writabilityWaiters: [UUID: WritabilityWaiter] = [:]
    private var inboundAdmission: InboundAdmissionLease?
    private let inboundByteBudget: InboundByteBudget
    private let connectionInboundByteBudget: InboundByteBudget
    private let decoder: SessionFrameDecoder?
    private let inbound: AsyncStream<InboundFrame>
    private let inboundContinuation: AsyncStream<InboundFrame>.Continuation

    var stream: (any TransportConnection)? {
        guard case .direct(let stream) = transport else { return nil }
        return stream
    }

    var route: AuthenticatedRoute {
        switch transport {
        case .direct:
            return .direct
        case .relayed(let routeID, let carrier):
            return .relayed(carrier: carrier, routeID: routeID)
        }
    }

    init(
        endpoint: PeerEndpoint,
        stream: any TransportConnection,
        decoder: SessionFrameDecoder? = nil,
        inboundAdmission: InboundAdmissionLease? = nil,
        inboundByteBudget: InboundByteBudget = InboundByteBudget(
            limit: IvyConfig.defaultMaxInboundBufferedBytes),
        connectionInboundByteBudget: InboundByteBudget? = nil,
        localMaxFrameSize: UInt32 = IvyConfig.defaultProtocolMaxFrameSize
    ) {
        self.endpoint = endpoint
        self.transport = .direct(stream)
        self.writable = stream.isWritable
        self.inboundAdmission = inboundAdmission
        self.localMaxFrameSize = localMaxFrameSize
        self.inboundByteBudget = inboundByteBudget
        self.connectionInboundByteBudget = connectionInboundByteBudget
            ?? InboundByteBudget(limit: Self.inboundByteBudgetLimit(for: localMaxFrameSize))
        self.decoder = decoder
        self.inboundBufferLimit = Self.maxInboundBufferedRecords
        (self.inbound, self.inboundContinuation) = AsyncStream<InboundFrame>.makeStream(
            bufferingPolicy: .bufferingOldest(inboundBufferLimit))
    }

    init(
        endpoint: PeerEndpoint,
        routeID: Data,
        carrier: PeerKey,
        inboundByteBudget: InboundByteBudget = InboundByteBudget(
            limit: IvyConfig.defaultMaxInboundBufferedBytes),
        connectionInboundByteBudget: InboundByteBudget? = nil,
        localMaxFrameSize: UInt32 = IvyConfig.defaultProtocolMaxFrameSize
    ) {
        self.endpoint = endpoint
        self.transport = .relayed(routeID: routeID, carrier: carrier)
        self.writable = false
        self.localMaxFrameSize = localMaxFrameSize
        self.inboundByteBudget = inboundByteBudget
        self.connectionInboundByteBudget = connectionInboundByteBudget
            ?? InboundByteBudget(limit: Self.inboundByteBudgetLimit(for: localMaxFrameSize))
        self.decoder = nil
        self.inboundBufferLimit = Self.maxInboundBufferedRecords
        (self.inbound, self.inboundContinuation) = AsyncStream<InboundFrame>.makeStream(
            bufferingPolicy: .bufferingOldest(inboundBufferLimit))
    }

    /// A connection over `stream`, with the framing and byte budgets every
    /// stream gets. Nothing is read until `startReading()`.
    static func direct(
        endpoint: PeerEndpoint,
        stream: any TransportConnection,
        inboundAdmission: InboundAdmissionLease? = nil,
        inboundByteBudget: InboundByteBudget,
        maxFrameSize: UInt32 = IvyConfig.defaultProtocolMaxFrameSize
    ) -> PeerConnection {
        let connectionInboundByteBudget = InboundByteBudget(
            limit: Self.inboundByteBudgetLimit(for: maxFrameSize))
        let connection = PeerConnection(
            endpoint: endpoint,
            stream: stream,
            decoder: SessionFrameDecoder(
                maxFrameSize: maxFrameSize,
                budget: inboundByteBudget,
                connectionBudget: connectionInboundByteBudget,
                requestBytes: { stream.requestBytes() },
                close: { stream.close() }),
            inboundAdmission: inboundAdmission,
            inboundByteBudget: inboundByteBudget,
            connectionInboundByteBudget: connectionInboundByteBudget,
            localMaxFrameSize: maxFrameSize)
        connection.observedHost = stream.observedHost
        stream.attach(connection)
        // Changes are reported only from `attach` on; one that came between
        // the sample taken at init and here is picked up now.
        connection.channelWritabilityChanged(isWritable: stream.isWritable)
        return connection
    }

    @discardableResult
    func sendRecord(_ record: SessionWireRecord) -> SendResult {
        // Serialize up to what the peer advertised it will accept (negotiated).
        sendSerializedRecord(record.serialize(maxPayload: peerMaxFrameSize))
    }

    @discardableResult
    func sendSerializedRecord(_ payload: Data) -> SendResult {
        guard !payload.isEmpty,
              payload.count <= Int(peerMaxFrameSize) else {
            return .locallyRejected
        }
        switch sendReadiness() {
        case .ready:
            break
        case .backpressured:
            return .backpressured
        case .notConnected:
            return .notConnected
        }
        switch transport {
        case .direct(let stream):
            var frame = Data(capacity: 4 + payload.count)
            withUnsafeBytes(of: UInt32(payload.count).bigEndian) { frame.append(contentsOf: $0) }
            frame.append(payload)
            stream.send(frame)
        case .relayed:
            return .notConnected
        }
        return .sent
    }

    func sendReadiness() -> SendReadiness {
        stateLock.withLock {
            guard !closed else { return .notConnected }
            return writable ? .ready : .backpressured
        }
    }

    func waitUntilWritable() async -> Bool {
        guard stream != nil else { return false }
        let id = UUID()
        let waiter = WritabilityWaiter()
        let result = stateLock.withLock { () -> Bool? in
            guard !closed else { return false }
            guard !writable else { return true }
            writabilityWaiters[id] = waiter
            return nil
        }
        if let result { return result }
        return await withTaskCancellationHandler(operation: {
            await withCheckedContinuation { waiter.install($0) }
        }, onCancel: {
            self.finishWritabilityWaiter(id, result: false)
        })
    }

    func channelWritabilityChanged(isWritable: Bool) {
        let waiters = stateLock.withLock { () -> [WritabilityWaiter] in
            guard !closed else { return [] }
            writable = isWritable
            guard isWritable else { return [] }
            let waiters = Array(writabilityWaiters.values)
            writabilityWaiters.removeAll()
            return waiters
        }
        for waiter in waiters { waiter.resume(true) }
    }

    var records: AsyncStream<InboundFrame> { inbound }
    var frameDecoder: SessionFrameDecoder? { decoder }
    var isDirect: Bool { if case .direct = transport { return true }; return false }
    var isLive: Bool { !isClosed && (stream?.isActive ?? true) }

    /// Asks the stream for its first bytes; the decoder asks for the rest.
    func startReading() {
        decoder?.start()
    }

    private var isClosed: Bool {
        stateLock.withLock { closed }
    }

    private func markClosed() -> (
        didClose: Bool,
        closeHandler: (@Sendable () -> Void)?
    ) {
        stateLock.withLock {
            guard !closed else { return (false, nil) }
            closed = true
            defer { closeHandler = nil }
            return (true, closeHandler)
        }
    }

    private func finishWritabilityWaiter(_ id: UUID, result: Bool) {
        let waiter = stateLock.withLock { writabilityWaiters.removeValue(forKey: id) }
        waiter?.resume(result)
    }

    private func finishWritabilityWaiters(result: Bool) {
        let waiters = stateLock.withLock { () -> [WritabilityWaiter] in
            let waiters = Array(writabilityWaiters.values)
            writabilityWaiters.removeAll()
            return waiters
        }
        for waiter in waiters { waiter.resume(result) }
    }

    func installCloseHandler(_ handler: @escaping @Sendable () -> Void) {
        let invokeNow = stateLock.withLock {
            if closed { return true }
            guard closeHandler == nil else { return false }
            closeHandler = handler
            return false
        }
        if invokeNow { handler() }
    }

    func releaseInboundAdmission() {
        let lease = stateLock.withLock { () -> InboundAdmissionLease? in
            defer { inboundAdmission = nil }
            return inboundAdmission
        }
        lease?.release()
    }

    @discardableResult
    func feedRecord(_ data: Data) -> Bool {
        let reservation = InboundByteReservation(
            budgets: [connectionInboundByteBudget, inboundByteBudget])
        guard !data.isEmpty,
              data.count <= Int(localMaxFrameSize),
              reservation.acquire(data.count) else {
            cancel()
            return false
        }
        return feedFrame(InboundFrame(bytes: data, reservation: reservation))
    }

    @discardableResult
    func feedFrame(_ frame: InboundFrame) -> Bool {
        guard !isClosed else { return false }
        switch inboundContinuation.yield(frame) {
        case .enqueued:
            return true
        case .dropped, .terminated:
            cancel()
            return false
        @unknown default:
            cancel()
            return false
        }
    }

    func connectionClosed() {
        let state = markClosed()
        guard state.didClose else { return }
        releaseInboundAdmission()
        finishWritabilityWaiters(result: false)
        decoder?.finish()
        inboundContinuation.finish()
        state.closeHandler?()
    }

    func cancel() {
        let state = markClosed()
        guard state.didClose else { return }
        releaseInboundAdmission()
        finishWritabilityWaiters(result: false)
        stream?.close()
        decoder?.finish()
        inboundContinuation.finish()
        state.closeHandler?()
    }
}

extension PeerConnection: TransportConnectionSink {
    func transportDidReceive(_ bytes: Data) {
        frameDecoder?.receive(bytes)
    }

    func transportWritabilityChanged(isWritable: Bool) {
        channelWritabilityChanged(isWritable: isWritable)
    }

    func transportDidClose() {
        connectionClosed()
    }
}

/// Decodes length-prefixed frames from a connection's byte stream, reserving
/// each byte against the connection and global inbound budgets until the
/// consumer releases its frame.
///
/// An exhausted budget is backpressure, not a violation: the decoder stops
/// consuming input, keeps the undecoded bytes, and stops asking the stream for
/// more, so the transport holds the sender. When a reservation is released the
/// decoder resumes, then issues a withheld request. Malformed framing (a zero
/// or over-`maxFrameSize` length) and bytes the decoder did not ask for close
/// the connection.
///
/// Memory per connection is the reserved bytes (at most the connection budget)
/// plus the undecoded carry-over, which is at most the one delivery that was
/// in flight when the decoder paused.
final class SessionFrameDecoder: @unchecked Sendable {
    private let maxFrameSize: UInt32
    private let budget: InboundByteBudget
    private let connectionBudget: InboundByteBudget
    private let requestBytes: @Sendable () -> Void
    private let close: @Sendable () -> Void
    private let lock = NSLock()
    private var header: [UInt8] = []
    private var headerReservation: InboundByteReservation?
    private var expectedBodyLength: Int?
    private var body = Data()
    private var bodyReservation: InboundByteReservation?
    private var waiter: InboundBudgetWaiter?
    /// Received bytes not yet decoded because the budget was exhausted.
    private var carryOver = Data()
    private var paused = false
    /// Decoded frames the consumer has not taken yet.
    private var frames = CircularBuffer<InboundFrame>()
    private var consumer: CheckedContinuation<InboundFrame?, Never>?
    private var started = false
    private var finished = false
    /// One request follows every delivery. It is issued once the consumer has
    /// taken every decoded frame and the decoder is not paused; until then it
    /// is held in one of these two places.
    private var readAwaitingConsumer = false
    private var readWithheld = false
    private var readOutstanding = false
    private var requesting = false
    private var requestAgain = false

#if DEBUG || IVY_TESTING
    /// Called whenever the decoder pauses or buffers input while paused, with
    /// the undecoded carry-over byte count.
    var onPausedForTesting: (@Sendable (_ carryOverBytes: Int) -> Void)?

    /// Takes every decoded frame at once, as a consumer that never waits.
    func takeFramesForTesting() -> [InboundFrame] {
        var taken: [InboundFrame] = []
        perform(lock.withLock {
            var effects = Effects()
            taken = Array(frames)
            frames.removeAll()
            effects.request = framesTaken()
            return effects
        })
        return taken
    }
#endif

    /// What a locked step leaves to do once the lock is released.
    private struct Effects {
        var frame: InboundFrame?
        var consumer: CheckedContinuation<InboundFrame?, Never>?
        var request = false
        var close = false
        var pausedCarryOver: Int?
    }

    init(
        maxFrameSize: UInt32 = IvyConfig.defaultProtocolMaxFrameSize,
        budget: InboundByteBudget,
        connectionBudget: InboundByteBudget,
        requestBytes: @escaping @Sendable () -> Void,
        close: @escaping @Sendable () -> Void
    ) {
        self.maxFrameSize = maxFrameSize
        self.budget = budget
        self.connectionBudget = connectionBudget
        self.requestBytes = requestBytes
        self.close = close
        header.reserveCapacity(4)
        // A release can come from any thread, this decoder's own included, so
        // the wake never runs inline.
        waiter = InboundBudgetWaiter { [weak self] in
            Task { [weak self] in self?.budgetReleased() }
        }
    }

    /// Issues the first request. Nothing is asked of the stream before this.
    func start() {
        perform(lock.withLock {
            var effects = Effects()
            guard !started, !finished else { return effects }
            started = true
            effects.request = readDue()
            return effects
        })
    }

    func receive(_ bytes: Data) {
        perform(lock.withLock {
            var effects = Effects()
            // An empty delivery carries nothing: the request stays outstanding.
            guard !finished, !bytes.isEmpty else { return effects }
            guard readOutstanding else {
                fail(&effects)
                return effects
            }
            readOutstanding = false
            carryOver.append(bytes)
            if paused {
                effects.pausedCarryOver = carryOver.count
            } else {
                decode(&effects)
            }
            guard !finished else { return effects }
            effects.request = readDue()
            return effects
        })
    }

    /// The next decoded frame, or nil once the connection has closed.
    func next() async -> InboundFrame? {
        await withCheckedContinuation { continuation in
            perform(lock.withLock {
                var effects = Effects()
                if let frame = frames.popFirst() {
                    effects.frame = frame
                    effects.consumer = continuation
                    effects.request = framesTaken()
                } else if finished {
                    effects.consumer = continuation
                } else {
                    consumer = continuation
                }
                return effects
            })
        }
    }

    /// Ends the stream of frames and releases every buffered byte.
    func finish() {
        perform(lock.withLock {
            var effects = Effects()
            terminate(&effects)
            return effects
        })
    }

    private func budgetReleased() {
        perform(lock.withLock {
            var effects = Effects()
            guard paused, !finished else { return effects }
            paused = false
            decode(&effects)
            guard !finished else { return effects }
            if !paused, readWithheld {
                readWithheld = false
                readOutstanding = true
                effects.request = true
            }
            return effects
        })
    }

    /// Decodes the carry-over until it is empty, the budget is exhausted, or
    /// the framing is malformed, then hands a waiting consumer its frame.
    private func decode(_ effects: inout Effects) {
        let incoming = carryOver
        carryOver = Data()
        var offset = incoming.startIndex

        while offset < incoming.endIndex {
            if expectedBodyLength == nil {
                if header.isEmpty {
                    let reservation = InboundByteReservation(
                        budgets: [connectionBudget, budget])
                    guard reservation.acquire(4, waiter: waiter) else {
                        pause(keeping: incoming[offset...], &effects)
                        break
                    }
                    headerReservation = reservation
                }
                let count = min(4 - header.count, incoming.endIndex - offset)
                header.append(contentsOf: incoming[offset..<offset + count])
                offset += count
                guard header.count == 4 else { break }

                let length = UInt32(header[0]) << 24
                    | UInt32(header[1]) << 16
                    | UInt32(header[2]) << 8
                    | UInt32(header[3])
                guard length > 0, length <= maxFrameSize else {
                    fail(&effects)
                    return
                }
                expectedBodyLength = Int(length)
                bodyReservation = InboundByteReservation(
                    budgets: [connectionBudget, budget])
                header.removeAll(keepingCapacity: true)
                headerReservation = nil
            }

            guard let expectedBodyLength,
                  let bodyReservation else { continue }
            let count = min(expectedBodyLength - body.count, incoming.endIndex - offset)
            guard bodyReservation.acquire(count, waiter: waiter) else {
                pause(keeping: incoming[offset...], &effects)
                break
            }
            body.append(incoming[offset..<offset + count])
            offset += count
            guard body.count == expectedBodyLength else { break }

            frames.append(InboundFrame(bytes: body, reservation: bodyReservation))
            body = Data()
            self.bodyReservation = nil
            self.expectedBodyLength = nil
        }

        if let consumer, let frame = frames.popFirst() {
            self.consumer = nil
            effects.consumer = consumer
            effects.frame = frame
        }
    }

    private func pause(keeping incoming: Data, _ effects: inout Effects) {
        carryOver = Data(incoming)
        paused = true
        effects.pausedCarryOver = carryOver.count
    }

    /// A request is due: hold it while decoded frames wait for the consumer.
    private func readDue() -> Bool {
        guard frames.isEmpty else {
            readAwaitingConsumer = true
            return false
        }
        return passPause()
    }

    /// The consumer took a frame: a request held for it moves on once it has
    /// taken them all.
    private func framesTaken() -> Bool {
        guard readAwaitingConsumer, frames.isEmpty else { return false }
        readAwaitingConsumer = false
        return passPause()
    }

    private func passPause() -> Bool {
        guard !paused else {
            readWithheld = true
            return false
        }
        readOutstanding = true
        return true
    }

    private func fail(_ effects: inout Effects) {
        terminate(&effects)
        effects.close = true
    }

    private func terminate(_ effects: inout Effects) {
        finished = true
        header.removeAll(keepingCapacity: true)
        headerReservation = nil
        expectedBodyLength = nil
        body = Data()
        bodyReservation = nil
        carryOver = Data()
        paused = false
        frames.removeAll()
        readAwaitingConsumer = false
        readWithheld = false
        readOutstanding = false
        if let waiter {
            connectionBudget.cancelWait(waiter)
            budget.cancelWait(waiter)
        }
        effects.frame = nil
        effects.consumer = consumer
        consumer = nil
    }

    private func perform(_ effects: Effects) {
#if DEBUG || IVY_TESTING
        if let carryOver = effects.pausedCarryOver {
            onPausedForTesting?(carryOver)
        }
#endif
        effects.consumer?.resume(returning: effects.frame)
        if effects.close { close() }
        guard effects.request else { return }
        // A stream may deliver from inside `requestBytes()`, which can make
        // the next request due before this one returns: loop, do not recurse.
        guard lock.withLock({
            guard !requesting else {
                requestAgain = true
                return false
            }
            requesting = true
            return true
        }) else { return }
        while true {
            requestBytes()
            let again = lock.withLock { () -> Bool in
                guard requestAgain else {
                    requesting = false
                    return false
                }
                requestAgain = false
                return true
            }
            guard again else { return }
        }
    }
}
