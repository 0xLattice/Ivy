import Foundation
import NIOCore
import NIOPosix
import Tally

typealias IvyTimer = Scheduled<Void>

public enum IvyError: Error, Sendable, Equatable {
    case notRunning
    case invalidPeerKey
    case peerOutsideMode
    case connectionInProgress
    case identityVerificationFailed
    case noRelayAvailable
    case streamHasNoObservedHost
}

struct PendingNeighborResponse: Sendable {
    let peer: PeerID
    let continuation: CheckedContinuation<[PeerEndpoint], Never>
    var timeoutTask: IvyTimer? = nil
}

private enum PendingSessionDirection {
    case initiator(expected: PeerKey, routeBinding: Data)
    case responder
}

private struct PendingSession {
    let connection: PeerConnection
    let direction: PendingSessionDirection
    let generation: UInt64
    var helloInitiator: SignedSessionHelloInitiator?
    var helloResponder: SignedSessionHelloResponder?
    var sessionID: SessionID?
    var remoteKey: PeerKey?
    var remoteMetadata: PeerMetadata?
    var continuation: CheckedContinuation<Bool, Never>? = nil
    var timeoutTask: IvyTimer? = nil
}

private struct PendingPeerConnectionWaiter {
    let generation: UInt64
    let id: UUID
    let continuation: CheckedContinuation<Bool, Never>
}

final class AuthenticatedSession: @unchecked Sendable {
    let connection: PeerConnection
    let peerKey: PeerKey
    let role: AuthenticatedPeerRole
    let sessionID: SessionID
    let metadata: PeerMetadata
    var sequenceState = SessionSequenceState()
    var didNotifyConnect = false

    init(
        connection: PeerConnection,
        peerKey: PeerKey,
        role: AuthenticatedPeerRole,
        sessionID: SessionID,
        metadata: PeerMetadata
    ) {
        self.connection = connection
        self.peerKey = peerKey
        self.role = role
        self.sessionID = sessionID
        self.metadata = metadata
    }
}

private struct RelayRoute {
    let source: PeerKey
    let target: PeerKey
    let lifecycleID: UUID
    var ready: Bool
    var lastActivity: ContinuousClock.Instant
    var expiryTask: IvyTimer? = nil
}

private struct InstalledRoute {
    let carrier: PeerKey
    let remote: PeerKey
    let lifecycleID: UUID
    var connection: PeerConnection? = nil
    var expiryTask: IvyTimer? = nil
}

private struct PendingRelayOpen {
    let carrier: PeerKey
    let target: PeerKey
    let timeoutToken: UUID
    let continuation: CheckedContinuation<Data?, Never>
    var timeoutTask: IvyTimer? = nil
}

private struct PendingOutgoingDial {
    var endpoint: PeerEndpoint
    let generation: UInt64
    var cancelled = false
    var connectionID: UUID? = nil
}

struct PendingReconnect {
    let generation: UInt64
    let token: UInt64
    let task: IvyTimer
}

enum ProtocolViolationEvidence {
    case unverified
    case signedTransport
    case signedPayload
}

private enum SessionRecordSendResult {
    case sent
    case backpressured
    case locallyRejected
    case notConnected
}

private enum SessionRecordReadiness {
    case ready
    case backpressured
    case notConnected
}

public actor Ivy {
    public let config: IvyConfig
    public let tally: Tally
    var router: Router
    public let localID: PeerID
    let localKey: PeerKey
    let group: EventLoopGroup
    let inboundByteBudget: InboundByteBudget

    public weak var delegate: IvyDelegate?
    var contentSource: (any IvyContentSource)?
    public func setContentSource(_ source: IvyContentSource?) { contentSource = source }

    private var pendingSessions: [UUID: PendingSession] = [:]
    private var pendingPeerConnectionWaiters: [PeerKey: PendingPeerConnectionWaiter] = [:]
    private var sessions: [PeerKey: AuthenticatedSession] = [:]
    private var relayRoutes: [Data: RelayRoute] = [:]
    private var installedRoutes: [Data: InstalledRoute] = [:]
    private var pendingRelayOpens: [Data: PendingRelayOpen] = [:]
    static let directRouteBinding = Data(repeating: 0, count: 32)
    static let maxRelayRoutes = 64
    static let maxRelayRoutesPerPeer = 8
    static let relayIdleTimeout: Duration = .seconds(300)

    func endpointConnection(for peer: PeerID) -> PeerConnection? {
        guard let key = try? PeerKey(peer.publicKey) else { return nil }
        return endpointSession(for: key)?.connection
    }

    /// Effective outbound frame size over a (possibly relayed) route: the peer's
    /// advertised accept, capped by the carrier connection's capacity on a relayed
    /// route so we never build a frame the carrier cannot forward.
    func effectiveOutboundFrameSize(for connection: PeerConnection?) -> UInt32 {
        guard let connection else { return IvyConfig.defaultProtocolMaxFrameSize }
        var limit = connection.peerMaxFrameSize
        // A configured carrier authenticates in the `.carrier` role, so it is not
        // found by endpoint-role lookups; use the direct-carrier session lookup so
        // an 8 MiB endpoint behind a 4 MiB carrier is capped at the carrier's 4 MiB
        // rather than building a frame the carrier will refuse to forward.
        if case .relayed(_, let carrier) = connection.transport,
           let carrierConnection = directRelayCarrierSession(for: carrier)?.connection {
            limit = min(limit, carrierConnection.peerMaxFrameSize)
        }
        return limit
    }

    var connectedEndpointPeers: [PeerID] {
        sessions.values.compactMap { $0.role == .endpoint ? $0.peerKey.peerID : nil }
    }
    var serverChannel: Channel?
    var running = false
    private var lifecycleTail: Task<Void, Never>?
    var runGeneration: UInt64 = 0
    private nonisolated let inboundAdmissionGate = CurrentInboundAdmissionGate()

    let stunClient: STUNClient
    private var publicAddressDiscoveryTask: Task<Void, Never>?
    private(set) public var publicAddress: ObservedAddress?
    var routingRefreshTimer: RepeatedTask?
    var pendingNeighborResponses: [UInt64: PendingNeighborResponse] = [:]
    var healthMonitor: PeerHealthMonitor?
    private var outgoingDials: [PeerID: PendingOutgoingDial] = [:]
    var reconnectAttempts: [PeerID: Int] = [:]
    var reconnectTasks: [PeerID: PendingReconnect] = [:]
    private var reconnectSuppressed: Set<PeerID> = []
    private var nextReconnectToken: UInt64 = 0
    static let reconnectBaseDelayMs: UInt64 = 500
    static let reconnectMaxDelayMs: UInt64 = 30_000
    static let reconnectJitterMs: UInt64 = 250
    static let kademliaLookupParallelism = 3

    var providerHints: [String: [ProviderHint]] = [:]
    /// Per remote source: roots holding its provider records, and how many.
    var providerRecordsBySource: [PeerID: [String: Int]] = [:]
    var providerRecordCounts: [PeerID: Int] = [:]
    /// Remote sources grouped by record count, to find the heaviest without a scan.
    var providerSourcesByCount: [Int: Set<PeerID>] = [:]
    var providerRecordTotal = 0
    /// Roots the locally reported deficiency table may hold; its entries come
    /// only from this node's own `reportDeficientContent` and expire on a fixed window.
    static let maxDeficiencySuppressionRoots = 10_000
    var deficientPeerSuppression: [String: [String: ContinuousClock.Instant]] = [:]
    static let deficiencySuppressionWindow: Duration = .seconds(30)

    var pendingContentRequests: [UInt64: PendingContentRequest] = [:]
    var pendingVolumeRequests: [UInt64: PendingVolumeRequest] = [:]
    var inFlightVolumeBytes = 0
    var reservedVolumeBytes = 0
    var reservedServingVolumeBytes = 0
    /// DHT provider lookups started, for tests that assert one was avoided.
    var freshProviderQueryCount = 0
    /// Volume reads waiting for serving capacity, in arrival order. Reads are
    /// short and slots are already shared by weight, so reads go first come,
    /// first served: ranking them could starve a peer's read.
    var servingVolumeReadWaiters: [(id: UUID, continuation: CheckedContinuation<Bool, Never>)] = []
    var pendingFetches: [ContentRequestKey: PendingFetch] = [:]
    var nextFetchToken: UInt64 = 0
    var activeFetchCount = 0
    var servingContentRequests: Set<InboundContentRequest> = []
    var servingContentTasks: [InboundContentRequest: Task<Void, Never>] = [:]
    /// Requests waiting for a serving slot; non-empty only under pressure.
    var servingTickets: [InboundContentRequest: ServingTicket] = [:]
    var nextServingTicketArrival: UInt64 = 0
    /// This node's Volume requests in flight to each peer, and requests
    /// waiting for one to free.
    var outstandingVolumeRequests: [PeerID: Int] = [:]
    /// Consecutive Volume requests each connected peer let time out; cleared
    /// when it serves one, dropped when it disconnects.
    var volumeTimeoutStreaks: [PeerID: Int] = [:]
    var outstandingVolumeSlotWaiters: [(id: UUID, continuation: CheckedContinuation<Bool, Never>)] = []
    /// Stride-scheduling state for contended serving: each waiting peer's
    /// pass and its waiting tickets, and the pass of the last grant.
    var waitingServingPeers: [PeerID: WaitingServingPeer] = [:]
    var waitingServingTicketCount = 0
    var servingVirtualTime: Double = 0
    var activeLocalContentRequestCount = 0
    var nextConnectedFallbackOffset = 0
    var pendingProviderQueries: [String: PendingProviderQuery] = [:]
    var nextWireOperationID: UInt64 = 0

    public init(config: IvyConfig, group: EventLoopGroup = MultiThreadedEventLoopGroup.singleton, tally: Tally? = nil) {
        self.config = config
        self.localID = PeerID(publicKey: config.publicKey)
        self.localKey = config.peerKey
        self.tally = tally ?? Tally(config: config.tallyConfig)
        self.router = Router(localID: PeerID(publicKey: config.publicKey), k: config.kBucketSize)
        self.group = group
        self.inboundByteBudget = InboundByteBudget(limit: config.maxInboundBufferedBytes)
        self.stunClient = STUNClient(group: group, servers: config.stunServers)
    }

    // MARK: - Lifecycle

    public func start() async throws {
#if DEBUG || IVY_TESTING
        lifecycleRequestCountForTesting += 1
#endif
        let previous = lifecycleTail
        let operation = Task { [weak self] in
            await previous?.value
            guard let self else { throw CancellationError() }
            try await self.startNow()
        }
        lifecycleTail = Task { _ = try? await operation.value }
#if DEBUG || IVY_TESTING
        await lifecycleRequestHookForTesting?(lifecycleRequestCountForTesting)
#endif
        try await operation.value
    }

    private func startNow() async throws {
        guard !running, serverChannel == nil else { return }
        try config.validate()
        runGeneration &+= 1
        let generation = runGeneration
#if DEBUG || IVY_TESTING
        await lifecycleStartHookForTesting?()
#endif
        let listener = try await startListener(generation: generation)
        serverChannel = listener.channel
        inboundAdmissionGate.replace(with: listener.gate)
        running = true
        publicAddressDiscoveryTask?.cancel()
        publicAddressDiscoveryTask = nil
        publicAddress = nil
        reconnectSuppressed.removeAll()
        nextConnectedFallbackOffset = 0

        let monitor = PeerHealthMonitor(
            config: config.healthConfig,
            onStale: { [weak self] peer, sessionID in
                guard let self else { return }
                Task {
                    await self.disconnectStale(
                        peer,
                        sessionID: sessionID,
                        generation: generation)
                }
            })
        healthMonitor = monitor
        await monitor.startMonitoring(on: group.next()) { [weak self] peer, sessionID, nonce in
            guard let self else { return }
            await self.sendHealthPing(
                peer,
                sessionID: sessionID,
                nonce: nonce,
                generation: generation)
        }
#if DEBUG || IVY_TESTING
        await listenerReadyHookForTesting?()
#endif
        guard isCurrentRun(generation) else { return }

        if let externalAddress = config.externalAddress {
            let address = ObservedAddress(host: externalAddress.host, port: externalAddress.port)
            publicAddress = address
            delegate?.ivy(self, didDiscoverPublicAddress: address)
        } else if !config.stunServers.isEmpty {
            startPublicAddressDiscovery(generation: generation)
        }
        guard isCurrentRun(generation) else { return }

        for peer in configuredPeerKeys(role: .endpoint) {
            Task {
                await self.maintainConfiguredConnection(
                    peer: peer,
                    role: .endpoint,
                    generation: generation)
            }
        }
        for peer in configuredPeerKeys(role: .carrier) {
            Task {
                await self.maintainConfiguredConnection(
                    peer: peer,
                    role: .carrier,
                    generation: generation)
            }
        }

        if config.mode.participatesInPublicDiscovery {
            startRoutingRefresh(generation: generation)
        }
    }

    public func stop() async {
#if DEBUG || IVY_TESTING
        lifecycleRequestCountForTesting += 1
#endif
        let previous = lifecycleTail
        let operation = Task { [weak self] in
            await previous?.value
            await self?.stopNow()
        }
        lifecycleTail = operation
#if DEBUG || IVY_TESTING
        await lifecycleRequestHookForTesting?(lifecycleRequestCountForTesting)
#endif
        await operation.value
    }

    private func stopNow() async {
        guard running || serverChannel != nil else {
            cleanupAllPending()
            return
        }
        runGeneration &+= 1
        running = false
        publicAddressDiscoveryTask?.cancel()
        publicAddressDiscoveryTask = nil
        inboundAdmissionGate.replace(with: nil)?.invalidate()
        routingRefreshTimer?.cancel()
        routingRefreshTimer = nil
        await healthMonitor?.stopMonitoring()
        cleanupAllPending()

        try? await serverChannel?.close().get()
        serverChannel = nil
        let authenticatedConnections = sessions.values.map(\.connection)
        sessions.removeAll()
        for connection in authenticatedConnections {
            connection.cancel()
        }
        for route in relayRoutes.values { route.expiryTask?.cancel() }
        for route in installedRoutes.values { route.expiryTask?.cancel() }
        relayRoutes.removeAll()
        installedRoutes.removeAll()

        for reconnect in reconnectTasks.values {
            reconnect.task.cancel()
        }
        reconnectTasks.removeAll()
        reconnectAttempts.removeAll()
    }

    private func startPublicAddressDiscovery(generation: UInt64) {
        let client = stunClient
#if DEBUG || IVY_TESTING
        let hook = publicAddressDiscoveryHookForTesting
#endif
        publicAddressDiscoveryTask = Task.detached { [weak self, client] in
#if DEBUG || IVY_TESTING
            let address = if let hook {
                await hook()
            } else {
                await client.discoverPublicAddress()
            }
#else
            let address = await client.discoverPublicAddress()
#endif
            await self?.completePublicAddressDiscovery(
                address,
                generation: generation
            )
        }
    }

    private func completePublicAddressDiscovery(
        _ address: ObservedAddress?,
        generation: UInt64
    ) {
        guard isCurrentRun(generation) else { return }
        publicAddressDiscoveryTask = nil
        guard let address else { return }
        publicAddress = address
        delegate?.ivy(self, didDiscoverPublicAddress: address)
    }

    func isCurrentRun(_ generation: UInt64) -> Bool {
        running && generation == runGeneration
    }

    func delayedTask(
        after delay: Duration,
        perform action: @escaping @Sendable () async -> Void
    ) -> IvyTimer {
        let eventLoop = group.next()
        return eventLoop.scheduleTask(in: TimeAmount(delay)) {
            _ = Task {
                await action()
            }
        }
    }

    private func sendHealthPing(
        _ peer: PeerID,
        sessionID: SessionID,
        nonce: UInt64,
        generation: UInt64
    ) {
        guard isCurrentRun(generation),
              let key = try? PeerKey(peer.publicKey),
              sessions[key]?.sessionID == sessionID else { return }
        fireToPeer(peer, .ping(nonce: nonce))
    }

    static func attributedPeer(
        _ peer: PeerKey,
        direct: Bool,
        evidence: ProtocolViolationEvidence
    ) -> PeerKey? {
        switch evidence {
        case .unverified:
            return nil
        case .signedTransport:
            return direct ? peer : nil
        case .signedPayload:
            return peer
        }
    }

    // MARK: - Authenticated Connections

    private func endpointSession(for key: PeerKey) -> AuthenticatedSession? {
        guard let session = sessions[key], session.role == .endpoint else { return nil }
        return session
    }

    private func carrierSession(for key: PeerKey) -> AuthenticatedSession? {
        guard let session = sessions[key], session.role == .carrier else { return nil }
        return session
    }

    private func session(for connectionID: UUID) -> AuthenticatedSession? {
        sessions.values.first { $0.connection.connectionID == connectionID }
    }

    func isCurrent(_ session: AuthenticatedSession) -> Bool {
        running && sessions[session.peerKey] === session
    }

    func hasEndpointSession(_ peer: PeerID) -> Bool {
        guard let key = try? PeerKey(peer.publicKey) else { return false }
        return endpointSession(for: key)?.connection.isLive == true
    }

    func connectionCount(inNetgroup group: String, excluding peer: PeerID?) -> Int {
        let excluded = peer.flatMap { try? PeerKey($0.publicKey) }
        return sessions.values.filter { session in
            session.peerKey != excluded
                && session.connection.isDirect
                && connectionNetgroup(session.connection) == group
        }.count
    }

    func connectionNetgroup(_ connection: PeerConnection) -> String {
        guard let host = connection.observedHost, !host.isEmpty else {
            return "raw:connection:" + connection.connectionID.uuidString
        }
        return NetGroup.group(host)
    }

    public var connectedPeers: [PeerID] {
        connectedEndpointPeers
    }

    public var connectedPeerEndpoints: [PeerEndpoint] {
        sessions.values.compactMap {
            $0.role == .endpoint ? $0.connection.endpoint : nil
        }
    }

    public var knownPeerEndpoints: [PeerEndpoint] {
        router.allPeers().map(\.endpoint)
    }

    public var peerConnectionCount: Int {
        sessions.values.lazy.filter { $0.role == .endpoint }.count
    }

    // MARK: - Connection Management

    public func connect(to endpoint: PeerEndpoint) async throws {
        guard let key = try? PeerKey(endpoint.publicKey) else { throw IvyError.invalidPeerKey }
        reconnectSuppressed.remove(key.peerID)
        guard try await connectEndpointIfAdmitted(to: [endpoint]) else {
            if outgoingDials[key.peerID] != nil || pendingPeerConnectionWaiters[key] != nil {
                throw IvyError.connectionInProgress
            }
            throw IvyError.identityVerificationFailed
        }
    }

    /// Reserves inbound admission for a peer observed at `observedHost`, or
    /// returns nil when the node is not accepting it. A supplier of inbound
    /// streams calls this before it spends anything on the peer, then hands
    /// the stream to `accept(_:admission:)`. `observedHost` must be the host
    /// the stream will report: the lease admits only a stream of the netgroup
    /// it was reserved for. A peer with no observed host is not admitted.
    public nonisolated func reserveInboundAdmission(
        observedHost: String?
    ) -> InboundAdmissionLease? {
        guard let observedHost, !observedHost.isEmpty else { return nil }
        return inboundAdmissionGate.current?.reserve(observedHost: observedHost)
    }

    /// Accepts a stream the caller established, with this node as the
    /// responder. Nothing is requested from the stream until the node has
    /// admitted it. Refusal is reported only by closing the stream.
    public nonisolated func accept(
        _ stream: any TransportConnection,
        admission: InboundAdmissionLease
    ) {
        guard admission.claim() else {
            stream.close()
            return
        }
        guard let host = stream.observedHost, !host.isEmpty,
              admission.netgroup == NetGroup.group(host) else {
            admission.release()
            stream.close()
            return
        }
        let connection = PeerConnection.direct(
            endpoint: PeerEndpoint(publicKey: "", host: "unknown", port: 0),
            stream: stream,
            inboundAdmission: admission,
            inboundByteBudget: inboundByteBudget,
            maxFrameSize: config.protocolMaxFrameSize)
        Task { [weak self] in
            guard let self,
                  let gate = admission.gate,
                  gate === self.inboundAdmissionGate.current else {
                connection.cancel()
                return
            }
            await self.registerInboundConnection(connection, generation: admission.generation)
        }
    }

    /// Connects to `endpoint` over a stream the caller established, with this
    /// node as the initiator. The stream is closed unless it becomes the
    /// peer's session, and it must report the host its peer was observed at.
    public func connect(
        to endpoint: PeerEndpoint,
        over stream: any TransportConnection
    ) async throws {
        do {
            guard let key = try? PeerKey(endpoint.publicKey) else { throw IvyError.invalidPeerKey }
            reconnectSuppressed.remove(key.peerID)
            guard config.allowsEndpoint(key) else { throw IvyError.peerOutsideMode }
            guard running, !Task.isCancelled else { throw IvyError.notRunning }
            guard let host = stream.observedHost, !host.isEmpty else {
                throw IvyError.streamHasNoObservedHost
            }
            let connected = try await connectDirect(
                to: endpoint,
                key: key,
                role: .endpoint,
                generation: runGeneration,
                over: stream)
            if sessions[key]?.connection.stream !== stream { stream.close() }
            guard connected else {
                if outgoingDials[key.peerID] != nil || pendingPeerConnectionWaiters[key] != nil {
                    throw IvyError.connectionInProgress
                }
                throw IvyError.identityVerificationFailed
            }
        } catch {
            stream.close()
            throw error
        }
    }

    func connectEndpointIfAdmitted(
        to routes: [PeerEndpoint],
        requiredGeneration: UInt64? = nil
    ) async throws -> Bool {
        guard let endpoint = routes.first else { throw IvyError.invalidPeerKey }
        guard let key = try? PeerKey(endpoint.publicKey) else { throw IvyError.invalidPeerKey }
        guard routes.allSatisfy({ (try? PeerKey($0.publicKey)) == key }) else {
            throw IvyError.invalidPeerKey
        }
        guard config.allowsEndpoint(key) else { throw IvyError.peerOutsideMode }
        guard running, !Task.isCancelled else { throw IvyError.notRunning }
        let generation = runGeneration
        if let requiredGeneration, requiredGeneration != generation {
            throw IvyError.notRunning
        }
        for route in routes {
            do {
                if try await connectDirect(
                    to: route,
                    key: key,
                    role: .endpoint,
                    generation: generation
                ) {
                    return true
                }
                return false
            } catch {
                guard !Task.isCancelled,
                      isCurrentRun(generation),
                      !reconnectSuppressed.contains(key.peerID) else {
                    throw CancellationError()
                }
            }
        }
        guard config.mode.usesOverlayServices else { throw IvyError.noRelayAvailable }
        try await connectViaRelay(to: endpoint, requiredGeneration: generation)
        return true
    }

    private func connectCarrier(to endpoint: PeerEndpoint) async throws {
        guard let key = try? PeerKey(endpoint.publicKey), config.isConfiguredCarrier(key) else {
            throw IvyError.peerOutsideMode
        }
        guard running, !Task.isCancelled else { throw IvyError.notRunning }
        let generation = runGeneration
        guard try await connectDirect(
            to: endpoint,
            key: key,
            role: .carrier,
            generation: generation
        ) else {
            throw IvyError.identityVerificationFailed
        }
    }

    private func connectDirect(
        to endpoint: PeerEndpoint,
        key: PeerKey,
        role: AuthenticatedPeerRole,
        generation: UInt64,
        over supplied: (any TransportConnection)? = nil
    ) async throws -> Bool {
        guard !reconnectSuppressed.contains(key.peerID) else { return false }
        if sessions[key]?.role == role,
           sessions[key]?.connection.isLive == true { return true }
        guard reserveOutgoingDial(to: endpoint) else {
            return sessions[key]?.role == role && sessions[key]?.connection.isLive == true
        }

        let canonical = PeerEndpoint(
            publicKey: key.hex,
            host: endpoint.host,
            port: endpoint.port)
#if DEBUG || IVY_TESTING
        let rewritten = role == .endpoint
            ? dialEndpointRewriteForTesting?(canonical) ?? canonical
            : canonical
#else
        let rewritten = canonical
#endif
        let stream: any TransportConnection
        do {
            if let supplied {
                stream = supplied
            } else {
                stream = try await NIOTransportConnection.dial(
                    host: rewritten.host,
                    port: rewritten.port,
                    group: group)
            }
        } catch {
            let connected = await finishOutgoingDialOrAwaitCompetingResponder(
                for: key,
                generation: generation)
            guard !Task.isCancelled,
                  isCurrentRun(generation),
                  !reconnectSuppressed.contains(key.peerID) else {
                throw CancellationError()
            }
            if connected { return true }
            throw error
        }
        // A supplied stream's address is not one Ivy can dial, so it is kept
        // out of the connection's endpoint and so out of routing.
        let connection = PeerConnection.direct(
            endpoint: PeerEndpoint(
                publicKey: key.hex,
                host: supplied == nil ? rewritten.host : "unknown",
                port: supplied == nil ? rewritten.port : 0),
            stream: stream,
            inboundByteBudget: inboundByteBudget,
            maxFrameSize: config.protocolMaxFrameSize)
        guard bindOutgoingDial(
            to: key.peerID,
            generation: generation,
            connection: connection
        ) else {
            connection.cancel()
            let connected = await finishOutgoingDialOrAwaitCompetingResponder(
                for: key,
                generation: generation)
            guard !Task.isCancelled,
                  isCurrentRun(generation),
                  !reconnectSuppressed.contains(key.peerID) else {
                throw CancellationError()
            }
            return connected
        }
        guard !Task.isCancelled,
              isCurrentRun(generation),
              outgoingDials[key.peerID]?.generation == generation,
              outgoingDials[key.peerID]?.cancelled == false,
              !reconnectSuppressed.contains(key.peerID) else {
            finishOutgoingDial(to: key.peerID, generation: generation)
            connection.cancel()
            throw CancellationError()
        }

        startInboundTask(connection)
        _ = await authenticateInitiator(
            connection,
            expected: key,
            routeBinding: Self.directRouteBinding)
        let connected = await finishOutgoingDialOrAwaitCompetingResponder(
            for: key,
            generation: generation)
        guard isCurrentRun(generation) else {
            connection.cancel()
            throw IvyError.notRunning
        }
        guard connected else {
            connection.cancel()
            guard !Task.isCancelled, !reconnectSuppressed.contains(key.peerID) else {
                throw CancellationError()
            }
            throw IvyError.identityVerificationFailed
        }
        return true
    }

    func reserveOutgoingDial(to endpoint: PeerEndpoint) -> Bool {
        guard let key = try? PeerKey(endpoint.publicKey),
              sessions[key] == nil,
              outgoingDials[key.peerID] == nil,
              pendingPeerConnectionWaiters[key] == nil,
              connectionCapacityUsed < config.maxConnections else { return false }

        let targetGroup = NetGroup.group(endpoint.host)
        guard directConnectionCount(inNetgroup: targetGroup)
                < config.maxConnectionsPerNetgroup else {
            return false
        }

        outgoingDials[key.peerID] = PendingOutgoingDial(
            endpoint: PeerEndpoint(publicKey: key.hex, host: endpoint.host, port: endpoint.port),
            generation: runGeneration)
        return true
    }

    private func bindOutgoingDial(
        to peer: PeerID,
        generation: UInt64,
        connection: PeerConnection
    ) -> Bool {
        guard var dial = outgoingDials[peer], dial.generation == generation else { return false }
        dial.connectionID = connection.connectionID
        if let host = connection.observedHost, !host.isEmpty {
            dial.endpoint = PeerEndpoint(
                publicKey: dial.endpoint.publicKey,
                host: host,
                port: dial.endpoint.port)
        }
        outgoingDials[peer] = dial
        return directConnectionCount(inNetgroup: NetGroup.group(dial.endpoint.host))
            <= config.maxConnectionsPerNetgroup
    }

    @discardableResult
    func finishOutgoingDial(to peer: PeerID, generation: UInt64) -> Bool {
        guard outgoingDials[peer]?.generation == generation else { return false }
        outgoingDials.removeValue(forKey: peer)
        let key = try? PeerKey(peer.publicKey)
        let hasCurrentSession = isCurrentRun(generation)
            && key.flatMap({ sessions[$0] })?.connection.isLive == true
        if hasCurrentSession {
            reconnectAttempts.removeValue(forKey: peer)
            reconnectTasks.removeValue(forKey: peer)?.task.cancel()
            return true
        }
        if running, let key {
            let role: AuthenticatedPeerRole = config.isConfiguredCarrier(key) ? .carrier : .endpoint
            if !configuredEndpoints(for: key, role: role).isEmpty {
                scheduleReconnect(peer: peer, role: role, generation: runGeneration)
            }
        }
        return false
    }

    private func finishOutgoingDialOrAwaitCompetingResponder(
        for peer: PeerKey,
        generation: UInt64
    ) async -> Bool {
        if finishOutgoingDial(to: peer.peerID, generation: generation) { return true }
        return await competingResponderCompletes(for: peer, generation: generation)
    }

    private func competingResponderCompletes(
        for peer: PeerKey,
        generation: UInt64
    ) async -> Bool {
        guard isCurrentRun(generation),
              !Task.isCancelled,
              !reconnectSuppressed.contains(peer.peerID) else { return false }
        if sessions[peer]?.connection.isLive == true { return true }
        guard pendingPeerConnectionWaiters[peer] == nil,
              hasVerifiedResponder(for: peer, generation: generation) else { return false }

        let waiterID = UUID()
        let connected = await withTaskCancellationHandler {
            await withCheckedContinuation { continuation in
                guard !Task.isCancelled,
                      isCurrentRun(generation),
                      !reconnectSuppressed.contains(peer.peerID),
                      pendingPeerConnectionWaiters[peer] == nil else {
                    continuation.resume(returning: sessions[peer]?.connection.isLive == true)
                    return
                }
                pendingPeerConnectionWaiters[peer] = PendingPeerConnectionWaiter(
                    generation: generation,
                    id: waiterID,
                    continuation: continuation)
                updatePeerConnectionWaiter(for: peer, generation: generation)
            }
        } onCancel: { [weak self] in
            guard let self else { return }
            Task {
                await self.cancelPeerConnectionWait(peer, waiterID: waiterID)
            }
        }
        return connected
    }

    private func hasVerifiedResponder(
        for peer: PeerKey,
        generation: UInt64
    ) -> Bool {
        pendingSessions.values.contains { pending in
            guard case .responder = pending.direction else { return false }
            return pending.generation == generation
                && pending.connection.isLive
                && pending.remoteKey == peer
                && pending.sessionID != nil
                && pending.helloInitiator != nil
                && pending.helloResponder != nil
        }
    }

    private func updatePeerConnectionWaiter(for peer: PeerKey, generation: UInt64) {
        guard let waiter = pendingPeerConnectionWaiters[peer],
              waiter.generation == generation else { return }
        if sessions[peer]?.connection.isLive == true {
            resolvePeerConnectionWaiter(for: peer, result: true)
        } else if !hasVerifiedResponder(for: peer, generation: generation) {
            resolvePeerConnectionWaiter(for: peer, result: false)
        }
    }

    private func resolvePeerConnectionWaiter(for peer: PeerKey, result: Bool) {
        pendingPeerConnectionWaiters.removeValue(forKey: peer)?.continuation.resume(
            returning: result)
    }

    private func cancelPeerConnectionWait(
        _ peer: PeerKey,
        waiterID: UUID
    ) {
        guard pendingPeerConnectionWaiters[peer]?.id == waiterID else { return }
        resolvePeerConnectionWaiter(for: peer, result: false)
    }

    public func disconnect(_ peer: PeerID) {
        guard let key = try? PeerKey(peer.publicKey) else { return }
        reconnectSuppressed.insert(key.peerID)
        reconnectTasks.removeValue(forKey: key.peerID)?.task.cancel()
        reconnectAttempts.removeValue(forKey: key.peerID)
        if var dial = outgoingDials[key.peerID] {
            dial.cancelled = true
            outgoingDials[key.peerID] = dial
        }
        let pendingIDs = pendingSessions.compactMap { connectionID, pending -> UUID? in
            switch pending.direction {
            case .initiator(let expected, _):
                return expected == key ? connectionID : nil
            case .responder:
                return pending.remoteKey == key ? connectionID : nil
            }
        }
        for connectionID in pendingIDs { failPendingSession(connectionID) }
        resolvePeerConnectionWaiter(for: key, result: false)
        removeRoutes(involving: key)
        if let session = sessions[key] {
            teardownAuthenticatedSession(session, reconnect: false)
            session.connection.cancel()
        }
    }

    /// Restart a configured peer without turning off its automatic reconnect.
    /// Prefer the exact-session overload when handling an authenticated callback.
    @available(*, deprecated, message: "Use recycleSession(ifCurrent:)")
    public func restartConfiguredSession(with peer: PeerID) {
        guard let key = try? PeerKey(peer.publicKey),
              let session = sessions[key],
              !configuredEndpoints(for: key, role: session.role).isEmpty else {
            return
        }
        teardownAuthenticatedSession(session, reconnect: true)
        session.connection.cancel()
    }

    /// Close only the represented authenticated session. Configured peers
    /// reconnect automatically; unconfigured peers may reconnect themselves.
    /// A stale callback cannot close a replacement session for the same key.
    @discardableResult
    public func recycleSession(ifCurrent peer: AuthenticatedPeer) -> Bool {
        guard let session = sessions[peer.key],
              session.sessionID.bytes == peer.sessionID else { return false }
        let reconnect = !configuredEndpoints(
            for: peer.key,
            role: session.role
        ).isEmpty
        teardownAuthenticatedSession(session, reconnect: reconnect)
        session.connection.cancel()
        return true
    }

    /// Permanently close only the represented authenticated session. A stale
    /// callback cannot suppress or close its replacement for the same key.
    @discardableResult
    public func disconnectSession(ifCurrent peer: AuthenticatedPeer) -> Bool {
        guard let session = sessions[peer.key],
              session.sessionID.bytes == peer.sessionID else { return false }
        reconnectSuppressed.insert(peer.id)
        reconnectTasks.removeValue(forKey: peer.id)?.task.cancel()
        reconnectAttempts.removeValue(forKey: peer.id)
        teardownAuthenticatedSession(session, reconnect: false)
        session.connection.cancel()
        return true
    }

    private func disconnectStale(
        _ peer: PeerID,
        sessionID: SessionID,
        generation: UInt64
    ) {
        guard isCurrentRun(generation),
              let key = try? PeerKey(peer.publicKey),
              let session = sessions[key],
              session.sessionID == sessionID else { return }
        teardownAuthenticatedSession(session, reconnect: true)
        session.connection.cancel()
    }

    private func scheduleReconnect(
        peer: PeerID,
        role: AuthenticatedPeerRole,
        generation: UInt64
    ) {
        guard let key = try? PeerKey(peer.publicKey),
              isCurrentRun(generation),
              !reconnectSuppressed.contains(peer),
              sessions[key] == nil,
              outgoingDials[peer] == nil,
              reconnectTasks[peer] == nil else { return }

        let delay = reconnectDelay(for: peer)
        nextReconnectToken &+= 1
        let token = nextReconnectToken
        let task = delayedTask(after: delay) { [weak self] in
            await self?.runScheduledReconnect(
                peer: peer,
                role: role,
                generation: generation,
                token: token)
        }
        reconnectTasks[peer] = PendingReconnect(
            generation: generation,
            token: token,
            task: task)
    }

    func reconnectDelay(for peer: PeerID) -> Duration {
        let attempt = min((reconnectAttempts[peer] ?? 0) + 1, 16)
        reconnectAttempts[peer] = attempt
        let shift = min(attempt - 1, 10)
        let exponential = Self.reconnectBaseDelayMs * (UInt64(1) << UInt64(shift))
        let capped = min(exponential, Self.reconnectMaxDelayMs)
        return .milliseconds(capped + UInt64.random(in: 0 ... Self.reconnectJitterMs))
    }

    func runScheduledReconnect(
        peer: PeerID,
        role: AuthenticatedPeerRole,
        generation: UInt64,
        token: UInt64
    ) async {
        guard reconnectTasks[peer]?.generation == generation,
              reconnectTasks[peer]?.token == token else { return }
        reconnectTasks.removeValue(forKey: peer)
        guard isCurrentRun(generation),
              !reconnectSuppressed.contains(peer),
              let key = try? PeerKey(peer.publicKey) else { return }
        await maintainConfiguredConnection(peer: key, role: role, generation: generation)
    }

    private func maintainConfiguredConnection(
        peer key: PeerKey,
        role: AuthenticatedPeerRole,
        generation: UInt64
    ) async {
        guard isCurrentRun(generation), !reconnectSuppressed.contains(key.peerID) else { return }
        let endpoints = configuredEndpoints(for: key, role: role)
        if role == .endpoint {
            if (try? await connectEndpointIfAdmitted(
                to: endpoints,
                requiredGeneration: generation)) == true {
                return
            }
        } else {
            for endpoint in endpoints {
                guard isCurrentRun(generation),
                      !Task.isCancelled,
                      sessions[key]?.connection.isLive != true else { return }
                do {
                    try await connectCarrier(to: endpoint)
                    return
                } catch {
                    if Task.isCancelled { return }
                }
            }
        }
        scheduleReconnect(peer: key.peerID, role: role, generation: generation)
    }

    // MARK: - Session Authentication

    private var unrepresentedOutgoingDials: [PendingOutgoingDial] {
        let represented = Set(pendingSessions.keys).union(
            sessions.values.map(\.connection.connectionID))
        return outgoingDials.values.filter { dial in
            guard let connectionID = dial.connectionID else { return true }
            return !represented.contains(connectionID)
        }
    }

    private var connectionCapacityUsed: Int {
        sessions.count + pendingSessions.count + unrepresentedOutgoingDials.count
    }

    private func directConnectionCount(inNetgroup group: String) -> Int {
        let authenticated = sessions.values.lazy.filter {
            $0.connection.isDirect && self.connectionNetgroup($0.connection) == group
        }.count
        let pending = pendingSessions.values.lazy.filter {
            $0.connection.isDirect && self.connectionNetgroup($0.connection) == group
        }.count
        let reserved = unrepresentedOutgoingDials.lazy.filter {
            NetGroup.group($0.endpoint.host) == group
        }.count
        return authenticated + pending + reserved
    }

    @discardableResult
    func registerInboundConnection(_ connection: PeerConnection, generation: UInt64) -> Bool {
        let netgroup = connectionNetgroup(connection)
        guard isCurrentRun(generation),
              connection.isLive,
              connectionCapacityUsed < config.maxInboundConnections,
              (!connection.isDirect
                || directConnectionCount(inNetgroup: netgroup)
                    < config.maxConnectionsPerNetgroup) else {
            connection.cancel()
            return false
        }

        pendingSessions[connection.connectionID] = PendingSession(
            connection: connection,
            direction: .responder,
            generation: generation)
        startInboundTask(connection)
        schedulePendingTimeout(connection.connectionID, generation: generation)
        return true
    }

    private func authenticateInitiator(
        _ connection: PeerConnection,
        expected: PeerKey,
        routeBinding: Data
    ) async -> Bool {
        guard let metadata = localMetadata(for: connection).encode() else { return false }
        let hello = SessionHelloInitiator(
            routeBinding: routeBinding,
            initiator: localKey,
            responder: expected,
            nonce: secureRandom32(),
            metadata: metadata)
        guard let signed = try? SignedSessionHelloInitiator.sign(hello, with: config.signingKey) else {
            return false
        }

        let generation = runGeneration
        pendingSessions[connection.connectionID] = PendingSession(
            connection: connection,
            direction: .initiator(expected: expected, routeBinding: routeBinding),
            generation: generation,
            helloInitiator: signed)

        let authenticated = await withTaskCancellationHandler {
            await withCheckedContinuation { continuation in
                guard var pending = pendingSessions[connection.connectionID] else {
                    continuation.resume(returning: false)
                    return
                }
                pending.continuation = continuation
                pendingSessions[connection.connectionID] = pending
                guard case .sent = sendSessionRecord(.helloInitiator(signed), on: connection) else {
                    failPendingSession(connection.connectionID)
                    return
                }
                schedulePendingTimeout(connection.connectionID, generation: generation)
            }
        } onCancel: { [weak self, weak connection] in
            guard let self, let connection else { return }
            Task {
                await self.cancelAuthentication(
                    connection.connectionID,
                    generation: generation)
            }
        }
        if Task.isCancelled {
            cancelAuthentication(connection.connectionID, generation: generation)
            return false
        }
        return authenticated
    }

    private func cancelAuthentication(_ connectionID: UUID, generation: UInt64) {
        if pendingSessions[connectionID]?.generation == generation {
            failPendingSession(connectionID)
            return
        }
        guard let session = session(for: connectionID) else { return }
        teardownAuthenticatedSession(session, reconnect: true)
        session.connection.cancel()
    }

    private func schedulePendingTimeout(_ connectionID: UUID, generation: UInt64) {
        guard var pending = pendingSessions[connectionID],
              pending.generation == generation else { return }
        pending.timeoutTask?.cancel()
        pending.timeoutTask = delayedTask(after: .seconds(30)) { [weak self] in
            await self?.timeoutPendingSession(connectionID, generation: generation)
        }
        pendingSessions[connectionID] = pending
    }

    private func timeoutPendingSession(_ connectionID: UUID, generation: UInt64) {
        guard isCurrentRun(generation),
              pendingSessions[connectionID]?.generation == generation else { return }
        failPendingSession(connectionID)
    }

    private func failPendingSession(_ connectionID: UUID) {
        guard let pending = pendingSessions.removeValue(forKey: connectionID) else { return }
        pending.timeoutTask?.cancel()
        pending.continuation?.resume(returning: false)
        if let peer = pending.remoteKey {
            updatePeerConnectionWaiter(for: peer, generation: pending.generation)
        }
        removeRouteConnection(pending.connection)
        pending.connection.cancel()
    }

    private func startInboundTask(_ connection: PeerConnection) {
        let task: Task<Void, Never>
        if let decoder = connection.frameDecoder {
            task = Task { [weak self, weak connection] in
                guard let connection else { return }
                while let frame = await decoder.next() {
                    guard let self,
                          !Task.isCancelled,
                          connection.isLive else { break }
                    await self.handleSessionRecord(frame.bytes, on: connection)
                    withExtendedLifetime(frame) {}
                }
                if connection.isLive { connection.cancel() }
            }
        } else {
            let records = connection.records
            task = Task { [weak self, weak connection] in
                for await frame in records {
                    guard let self, let connection else { return }
                    await self.handleSessionRecord(frame.bytes, on: connection)
                    withExtendedLifetime(frame) {}
                }
            }
        }
        connection.installCloseHandler { [weak self, weak connection] in
            task.cancel()
            guard let self, let connection else { return }
            Task { await self.connectionEnded(connection) }
        }
        connection.startReading()
    }

    private func handleSessionRecord(_ bytes: Data, on connection: PeerConnection) async {
        let record: SessionWireRecord
        do {
            // Inbound: accept up to what THIS node advertised it accepts.
            record = try SessionWireRecord.deserialize(bytes, maxPayload: config.protocolMaxFrameSize)
        } catch {
            rejectRecord(on: connection)
            return
        }

        if let session = session(for: connection.connectionID),
           session.connection === connection {
            guard case .data(let dataRecord) = record else {
                rejectAuthenticatedSession(session, attributedTo: Self.attributedPeer(
                    session.peerKey,
                    direct: session.connection.isDirect,
                    evidence: .unverified))
                return
            }
            await handleAuthenticatedData(dataRecord, session: session)
            return
        }

        guard pendingSessions[connection.connectionID] != nil else {
            connection.cancel()
            return
        }
        await handlePendingRecord(record, on: connection)
    }

    private func handlePendingRecord(_ record: SessionWireRecord, on connection: PeerConnection) async {
        guard var pending = pendingSessions[connection.connectionID] else { return }

        switch record {
        case .helloInitiator(let signed):
            guard case .responder = pending.direction,
                  pending.helloInitiator == nil,
                  signed.isValid(),
                  acceptsInboundHello(signed.hello, on: connection),
                  peerMeetsDifficulty(signed.hello.initiator),
                  let remoteMetadata = try? PeerMetadata.decodeCanonical(signed.hello.metadata),
                  let localMetadata = localMetadata(for: connection).encode() else {
                rejectRecord(on: connection)
                return
            }
            // Negotiated: cap what we send this peer at what it advertised it accepts.
            connection.peerMaxFrameSize = remoteMetadata.maxFrameSize

            let helloResponder = SessionHelloResponder(
                routeBinding: signed.hello.routeBinding,
                responder: localKey,
                initiator: signed.hello.initiator,
                initiatorNonce: signed.hello.nonce,
                responderNonce: secureRandom32(),
                metadata: localMetadata)
            guard let signedResponder = try? SignedSessionHelloResponder.sign(
                    helloResponder,
                    with: config.signingKey),
                  let sessionID = try? SessionID(initiator: signed, responder: signedResponder) else {
                rejectRecord(on: connection)
                return
            }

            pending.helloInitiator = signed
            pending.helloResponder = signedResponder
            pending.sessionID = sessionID
            pending.remoteKey = signed.hello.initiator
            pending.remoteMetadata = remoteMetadata
            pendingSessions[connection.connectionID] = pending
            guard case .sent = sendSessionRecord(.helloResponder(signedResponder), on: connection) else {
                failPendingSession(connection.connectionID)
                return
            }

        case .helloResponder(let signed):
            guard case .initiator(let expected, let routeBinding) = pending.direction,
                  let helloInitiator = pending.helloInitiator,
                  pending.helloResponder == nil,
                  signed.isValid(),
                  signed.hello.routeBinding == routeBinding,
                  signed.hello.responder == expected,
                  signed.hello.initiator == localKey,
                  signed.hello.initiatorNonce == helloInitiator.hello.nonce,
                  peerMeetsDifficulty(expected),
                  let remoteMetadata = try? PeerMetadata.decodeCanonical(signed.hello.metadata),
                  let sessionID = try? SessionID(initiator: helloInitiator, responder: signed),
                  let finish = try? SessionFinish.sign(
                    sessionID: sessionID,
                    sender: localKey,
                    receiver: expected,
                    with: config.signingKey) else {
                rejectRecord(on: connection)
                return
            }
            // Negotiated: cap what we send this peer at what it advertised it accepts.
            connection.peerMaxFrameSize = remoteMetadata.maxFrameSize

            pending.helloResponder = signed
            pending.sessionID = sessionID
            pending.remoteKey = expected
            pending.remoteMetadata = remoteMetadata
            pendingSessions[connection.connectionID] = pending
            guard case .sent = sendSessionRecord(.finish(finish), on: connection) else {
                failPendingSession(connection.connectionID)
                return
            }
            await promotePendingSession(pending)

        case .finish(let finish):
            guard case .responder = pending.direction,
                  let sessionID = pending.sessionID,
                  let remoteKey = pending.remoteKey,
                  finish.sessionID == sessionID,
                  finish.sender == remoteKey,
                  finish.receiver == localKey,
                  finish.isValid() else {
                rejectRecord(on: connection)
                return
            }
            await promotePendingSession(pending)

        case .data:
            rejectRecord(on: connection)
        }
    }

    func acceptsInboundHello(_ hello: SessionHelloInitiator, on connection: PeerConnection) -> Bool {
        guard hello.responder == localKey, hello.initiator != localKey else { return false }
        switch connection.transport {
        case .direct:
            guard hello.routeBinding == Self.directRouteBinding else { return false }
            return config.allowsEndpoint(hello.initiator)
                || config.isConfiguredCarrier(hello.initiator)
        case .relayed(let routeID, let carrier):
            guard hello.routeBinding == routeID,
                  let installed = installedRoutes[routeID],
                  installed.carrier == carrier,
                  installed.remote == hello.initiator else { return false }
            return config.allowsEndpoint(hello.initiator)
        }
    }

    private func peerMeetsDifficulty(_ key: PeerKey) -> Bool {
        config.minPeerKeyBits == 0
            || KeyDifficulty.trailingZeroBits(of: key.hex) >= config.minPeerKeyBits
    }

    private func localMetadata(for connection: PeerConnection) -> PeerMetadata {
        PeerMetadata(
            listenAddresses: advertisedListenAddresses(
                observedLocalHost: connection.stream?.localHost),
            maxFrameSize: config.protocolMaxFrameSize)
    }

    func advertisedListenAddresses(observedLocalHost: String?) -> [ListenAddress] {
        var addresses: [ListenAddress] = []
        if let external = config.externalAddress {
            addresses.append(ListenAddress(host: external.host, port: external.port))
        } else {
            if let publicAddress, config.listenPort != 0 {
                addresses.append(ListenAddress(host: publicAddress.host, port: config.listenPort))
            }
            if config.listenPort != 0,
               let localHost = observedLocalHost,
               localHost != "0.0.0.0", localHost != "::" {
                addresses.append(ListenAddress(host: localHost, port: config.listenPort))
            }
        }
        return addresses
    }

    private func promotePendingSession(_ pending: PendingSession) async {
        let connectionID = pending.connection.connectionID
        guard isCurrentRun(pending.generation),
              pendingSessions[connectionID]?.generation == pending.generation,
              pending.connection.isLive,
              let peerKey = pending.remoteKey,
              let metadata = pending.remoteMetadata,
              let sessionID = pending.sessionID,
              pending.helloInitiator != nil else {
            failPendingSession(connectionID)
            return
        }
        pendingSessions.removeValue(forKey: connectionID)?.timeoutTask?.cancel()

        // Role is local policy: configured carrier identities stay carrier-only.
        let role: AuthenticatedPeerRole = config.isConfiguredCarrier(peerKey) ? .carrier : .endpoint

        let session = AuthenticatedSession(
            connection: pending.connection,
            peerKey: peerKey,
            role: role,
            sessionID: sessionID,
            metadata: metadata)
        let existing = sessions[peerKey]

        if let existing,
           existing.connection.isLive,
           existing.sessionID == Self.preferredSessionID(existing.sessionID, sessionID) {
            pending.continuation?.resume(returning: true)
            resolvePeerConnectionWaiter(for: peerKey, result: true)
            removeRouteConnection(pending.connection)
            pending.connection.cancel()
            return
        }

        let isInbound: Bool
        if case .responder = pending.direction {
            isInbound = true
        } else {
            isInbound = false
        }
        if !canPromote(
            pending.connection,
            peerKey: peerKey,
            isInbound: isInbound
        ) {
            pending.continuation?.resume(returning: false)
            updatePeerConnectionWaiter(for: peerKey, generation: pending.generation)
            removeRouteConnection(pending.connection)
            pending.connection.cancel()
            return
        }

        if let existing {
            if existing.role == .endpoint {
                router.removePeer(peerKey.peerID)
                cleanupPendingForPeer(peerKey.peerID)
            }
            removeRoutes(involving: peerKey, preserving: pending.connection)
            existing.connection.cancel()
        }

        sessions[peerKey] = session
        resolvePeerConnectionWaiter(for: peerKey, result: true)
        if !reconnectSuppressed.contains(peerKey.peerID) {
            reconnectAttempts.removeValue(forKey: peerKey.peerID)
            reconnectTasks.removeValue(forKey: peerKey.peerID)?.task.cancel()
        }
        if role == .endpoint {
            let route: PeerEndpoint?
            if let endpoint = firstAdvertisedListenEndpoint(
                key: peerKey,
                addresses: metadata.listenAddresses,
                from: peerKey.peerID) {
                route = endpoint
            } else if case .initiator = pending.direction,
                      !pending.connection.endpoint.host.isEmpty,
                      pending.connection.endpoint.host != "unknown",
                      pending.connection.endpoint.port != 0 {
                route = PeerEndpoint(
                    publicKey: peerKey.hex,
                    host: pending.connection.endpoint.host,
                    port: pending.connection.endpoint.port)
            } else {
                route = nil
            }
            if let route {
                pending.connection.endpoint = route
                if config.mode.usesOverlayServices {
                    router.addPeer(peerKey.peerID, endpoint: route)
                }
            }
        }
        pending.connection.releaseInboundAdmission()

#if DEBUG || IVY_TESTING
        promotionHookForTesting?(pending.connection)
#endif
        await healthMonitor?.trackPeer(peerKey.peerID, sessionID: session.sessionID)
        if isCurrent(session), session.connection.isLive, !session.didNotifyConnect {
            session.didNotifyConnect = true
            await delegate?.ivy(self, didConnect: AuthenticatedPeer(
                key: peerKey,
                role: role,
                route: pending.connection.route,
                metadata: metadata,
                sessionID: session.sessionID.bytes))
        }
        if isCurrent(session), !session.connection.isLive {
            teardownAuthenticatedSession(session, reconnect: true)
        }
        let selected = sessions[peerKey]
        pending.continuation?.resume(returning: selected?.connection.isLive == true)
    }

    private func canPromote(
        _ connection: PeerConnection,
        peerKey: PeerKey,
        isInbound: Bool
    ) -> Bool {
        let limit = isInbound ? config.maxInboundConnections : config.maxConnections
        if sessions[peerKey] == nil, sessions.count >= limit {
            return false
        }
        return !connection.isDirect
            || connectionCount(
                inNetgroup: connectionNetgroup(connection),
                excluding: peerKey.peerID) < config.maxConnectionsPerNetgroup
    }

    private func firstAdvertisedListenEndpoint(
        key: PeerKey,
        addresses: [ListenAddress],
        from peer: PeerID
    ) -> PeerEndpoint? {
        for address in addresses {
            let endpoint = PeerEndpoint(publicKey: key.hex, host: address.host, port: address.port)
            if isAcceptableDiscoveredEndpoint(
                endpoint,
                provenance: .selfAdvertisement,
                from: peer
            ) {
                return endpoint
            }
        }
        return nil
    }

    private func rejectRecord(on connection: PeerConnection) {
        if let session = session(for: connection.connectionID) {
            rejectAuthenticatedSession(session, attributedTo: Self.attributedPeer(
                session.peerKey,
                direct: session.connection.isDirect,
                evidence: .unverified))
            return
        }
        failPendingSession(connection.connectionID)
    }

    private func rejectAuthenticatedSession(
        _ session: AuthenticatedSession,
        attributedTo peer: PeerKey?
    ) {
        if let peer {
            tally.recordProtocolViolation(peer: peer.peerID)
        }
        teardownAuthenticatedSession(session, reconnect: false)
        session.connection.cancel()
    }

    private func connectionEnded(_ connection: PeerConnection) {
        if pendingSessions[connection.connectionID] != nil {
            failPendingSession(connection.connectionID)
            return
        }
        guard let session = session(for: connection.connectionID),
              session.connection === connection else {
            removeRouteConnection(connection)
            return
        }
        teardownAuthenticatedSession(session, reconnect: true)
    }

    private func teardownAuthenticatedSession(
        _ session: AuthenticatedSession,
        reconnect: Bool
    ) {
        let key = session.peerKey
        guard sessions[key] === session else { return }
        sessions.removeValue(forKey: key)
        if session.role == .endpoint {
            router.removePeer(key.peerID)
            cleanupPendingForPeer(key.peerID)
        }

        removeRoutes(involving: key)
        if let monitor = healthMonitor {
            let peer = key.peerID
            let sessionID = session.sessionID
            Task {
                await monitor.removePeer(peer, sessionID: sessionID)
            }
        }
        if session.didNotifyConnect {
            delegate?.ivy(self, didDisconnect: key.peerID)
        }

        guard reconnect,
              running,
              !configuredEndpoints(for: key, role: session.role).isEmpty else { return }
        scheduleReconnect(peer: key.peerID, role: session.role, generation: runGeneration)
    }

    private func configuredEndpoints(
        for key: PeerKey,
        role: AuthenticatedPeerRole
    ) -> [PeerEndpoint] {
        let endpoints = role == .carrier ? config.carriers : config.bootstrapPeers
        return endpoints.filter { (try? PeerKey($0.publicKey)) == key }
    }

    private func configuredPeerKeys(role: AuthenticatedPeerRole) -> [PeerKey] {
        let endpoints = role == .carrier ? config.carriers : config.bootstrapPeers
        var seen: Set<PeerKey> = []
        return endpoints.compactMap { endpoint in
            guard let key = try? PeerKey(endpoint.publicKey), seen.insert(key).inserted else {
                return nil
            }
            return key
        }
    }

    private func removeRoutes(
        involving key: PeerKey,
        preserving connection: PeerConnection? = nil
    ) {
        let preservedRouteID: Data?
        if let connection, case .relayed(let routeID, _) = connection.transport {
            preservedRouteID = routeID
        } else {
            preservedRouteID = nil
        }
        let serviceRouteIDs = relayRoutes.compactMap { routeID, route in
            routeID != preservedRouteID && (route.source == key || route.target == key)
                ? routeID
                : nil
        }
        for routeID in serviceRouteIDs {
            closeRelayRoute(routeID, excluding: key)
        }

        let installedRouteIDs = installedRoutes.compactMap { routeID, route in
            routeID != preservedRouteID && (route.carrier == key || route.remote == key)
                ? routeID
                : nil
        }
        for routeID in installedRouteIDs {
            guard let route = installedRoutes[routeID] else { continue }
            closeInstalledRoute(routeID, notifyCarrier: route.carrier != key)
        }

        let requestIDs = pendingRelayOpens.compactMap { requestID, request in
            requestID != preservedRouteID && (request.carrier == key || request.target == key)
                ? requestID
                : nil
        }
        for requestID in requestIDs {
            timeoutRelayOpen(requestID)
        }
    }

    private func removeRouteConnection(_ connection: PeerConnection) {
        guard case .relayed(let routeID, _) = connection.transport,
              installedRoutes[routeID]?.connection === connection else { return }
        closeInstalledRoute(routeID, notifyCarrier: true)
    }

    private func closeRelayRoute(_ routeID: Data, excluding excluded: PeerKey? = nil) {
        guard let route = relayRoutes[routeID] else { return }
        for participant in [route.source, route.target] where participant != excluded {
            _ = sendRelayControl(.relayClose(routeID: routeID), to: participant)
        }
        relayRoutes.removeValue(forKey: routeID)?.expiryTask?.cancel()
    }

    private func closeInstalledRoute(_ routeID: Data, notifyCarrier: Bool) {
        guard let route = installedRoutes[routeID] else { return }
        if notifyCarrier {
            _ = sendRelayControl(.relayClose(routeID: routeID), to: route.carrier)
        }
        installedRoutes.removeValue(forKey: routeID)
        route.expiryTask?.cancel()
        route.connection?.cancel()
    }

    private func removePendingRelayOpen(_ routeID: Data) -> PendingRelayOpen? {
        let pending = pendingRelayOpens.removeValue(forKey: routeID)
        pending?.timeoutTask?.cancel()
        return pending
    }

    // MARK: - Signed Sending

    public func sendMessage(to peer: PeerID, topic: String, payload: Data) -> SendMessageResult {
        enqueueEndpoint(.peerMessage(topic: topic, payload: payload), to: peer)
    }

    /// Sends only if `peer` still names the selected authenticated session.
    public func sendMessage(
        to peer: AuthenticatedPeer,
        topic: String,
        payload: Data
    ) -> SendMessageResult {
        guard let session = endpointSession(for: peer.key),
              session.sessionID.bytes == peer.sessionID else {
            return .notConnected
        }
        return enqueue(
            .peerMessage(topic: topic, payload: payload),
            on: session
        )
    }

    func enqueueContentRequestOnCurrentSession(
        _ message: Message,
        to peer: AuthenticatedPeer
    ) -> Bool {
        guard let session = endpointSession(for: peer.key),
              session.sessionID.bytes == peer.sessionID else { return false }
#if DEBUG || IVY_TESTING
        if let hook = contentRequestEnqueueHookForTesting {
            return hook(peer.id)
        }
#endif
        if case .enqueued = enqueue(message, on: session) {
            return true
        }
        return false
    }

    func enqueueContentRequestOnCurrentSession(
        _ message: Message,
        to peer: PeerID
    ) -> Data? {
        guard let key = try? PeerKey(peer.publicKey),
              let session = endpointSession(for: key) else { return nil }
#if DEBUG || IVY_TESTING
        if let hook = contentRequestEnqueueHookForTesting,
           !hook(peer) { return nil }
#endif
        guard case .enqueued = enqueue(
            message,
            on: session
        ) else { return nil }
        return session.sessionID.bytes
    }

    /// Wait until the live route to `peer` can accept another outbound record.
    /// Returns false when that route closes before it becomes writable.
    public func waitUntilWritable(to peer: PeerID) async -> Bool {
        guard let key = try? PeerKey(peer.publicKey),
              let session = endpointSession(for: key) else {
            return false
        }
        switch session.connection.transport {
        case .direct:
            return await session.connection.waitUntilWritable()
        case .relayed(let routeID, let carrier):
            guard installedRoutes[routeID]?.carrier == carrier,
                  let carrier = directRelayCarrierSession(for: carrier) else {
                return false
            }
            return await carrier.connection.waitUntilWritable()
        }
    }

    /// Waits only on the transport represented by `peer`, never a replacement.
    public func waitUntilWritable(to peer: AuthenticatedPeer) async -> Bool {
        guard let session = endpointSession(for: peer.key),
              session.sessionID.bytes == peer.sessionID else {
            return false
        }
        switch session.connection.transport {
        case .direct:
            return await session.connection.waitUntilWritable()
        case .relayed(let routeID, let carrier):
            guard installedRoutes[routeID]?.carrier == carrier,
                  let carrier = directRelayCarrierSession(for: carrier) else {
                return false
            }
            return await carrier.connection.waitUntilWritable()
        }
    }

    public func broadcastMessage(topic: String, payload: Data) {
        guard config.mode.usesOverlayServices else { return }
        let message = Message.peerMessage(topic: topic, payload: payload)
        for session in sessions.values where session.role == .endpoint {
            _ = enqueue(message, on: session)
        }
    }

    @discardableResult
    func fireToPeer(
        _ peer: PeerID,
        _ message: Message
    ) -> SendMessageResult {
        guard let key = try? PeerKey(peer.publicKey) else { return .notConnected }
        if let session = endpointSession(for: key) {
            return enqueue(message, on: session)
        } else if message.isKeepalive, let session = carrierSession(for: key) {
            return enqueue(message, on: session)
        }
        return .notConnected
    }

    private func enqueueEndpoint(_ message: Message, to peer: PeerID) -> SendMessageResult {
        guard let key = try? PeerKey(peer.publicKey),
              let session = endpointSession(for: key) else {
            return .notConnected
        }
        return enqueue(message, on: session)
    }

    @discardableResult
    private func enqueue(
        _ message: Message,
        on session: AuthenticatedSession
    ) -> SendMessageResult {
        let payload = message.serialize(maxFrameSize: effectiveOutboundFrameSize(for: session.connection))
        guard !payload.isEmpty else { return .locallyRejected }
        return enqueuePayload(
            payload,
            on: session)
    }

    private func enqueuePayload(
        _ payload: Data,
        on session: AuthenticatedSession
    ) -> SendMessageResult {
        guard isCurrent(session) else { return .notConnected }
        switch sessionRecordReadiness(on: session.connection) {
        case .ready:
            break
        case .backpressured:
            return .backpressured
        case .notConnected:
            return .notConnected
        }
        var sequenceState = session.sequenceState
        guard let sequence = sequenceState.takeNextOutgoing() else { return .locallyRejected }
        guard let record = try? SessionDataRecord.sign(
            sessionID: session.sessionID,
            sender: localKey,
            receiver: session.peerKey,
            sequence: sequence,
            payload: payload,
            with: config.signingKey) else { return .locallyRejected }
        let sendResult = sendSessionRecord(.data(record), on: session.connection)
        switch sendResult {
        case .sent:
            session.sequenceState = sequenceState
        case .backpressured:
            return .backpressured
        case .locallyRejected:
            return .locallyRejected
        case .notConnected:
            return .notConnected
        }

        tally.recordSent(peer: session.peerKey.peerID, bytes: payload.count)

        return .enqueued(endpoint: session.peerKey.peerID, route: session.connection.route)
    }

    func enqueueIfCurrent(
        _ message: Message,
        on session: AuthenticatedSession
    ) -> SendMessageResult {
        guard isCurrent(session) else { return .notConnected }
        return enqueue(message, on: session)
    }

    private func sendRelayControl(_ message: Message, to key: PeerKey) -> Bool {
        if case .sent = sendRelayControlResult(message, to: key) { return true }
        return false
    }

    private func sendRelayControlResult(
        _ message: Message,
        to key: PeerKey
    ) -> SessionRecordSendResult {
        let session: AuthenticatedSession?
        if let carrier = carrierSession(for: key) {
            session = carrier
        } else if let endpoint = endpointSession(for: key),
                  endpoint.connection.isDirect,
                  endpointMayReceiveRelayControl(message, peer: key) {
            session = endpoint
        } else {
            session = nil
        }
        guard let session else { return .notConnected }
        switch enqueue(message, on: session) {
        case .enqueued:
            return .sent
        case .backpressured:
            return .backpressured
        case .locallyRejected:
            return .locallyRejected
        case .notConnected:
            return .notConnected
        }
    }

    private func sendRelayReply(_ message: Message, to key: PeerKey) -> Bool {
        let session = sessions[key]
        guard let session, session.connection.isDirect else { return false }
        if case .enqueued = enqueue(message, on: session) {
            return true
        }
        return false
    }

    private func sendSessionRecord(
        _ record: SessionWireRecord,
        on connection: PeerConnection
    ) -> SessionRecordSendResult {
        let payload = record.serialize(maxPayload: effectiveOutboundFrameSize(for: connection))
        guard !payload.isEmpty else { return .locallyRejected }
        switch connection.transport {
        case .direct:
            switch connection.sendSerializedRecord(payload) {
            case .sent:
                return .sent
            case .backpressured:
                return .backpressured
            case .locallyRejected:
                return .locallyRejected
            case .notConnected:
                return .notConnected
            }
        case .relayed(let routeID, let carrier):
            guard connection.isLive,
                  installedRoutes[routeID]?.carrier == carrier else { return .notConnected }
            return sendRelayControlResult(
                .relayPacket(routeID: routeID, opaqueEndpointRecord: payload),
                to: carrier)
        }
    }

    private func sessionRecordReadiness(on connection: PeerConnection) -> SessionRecordReadiness {
        switch connection.transport {
        case .direct:
            switch connection.sendReadiness() {
            case .ready:
                return .ready
            case .backpressured:
                return .backpressured
            case .notConnected:
                return .notConnected
            }
        case .relayed(let routeID, let carrier):
            guard connection.isLive,
                  installedRoutes[routeID]?.carrier == carrier,
                  let carrierSession = directRelayCarrierSession(for: carrier) else {
                return .notConnected
            }
            return sessionRecordReadiness(on: carrierSession.connection)
        }
    }

    private func directRelayCarrierSession(
        for carrier: PeerKey
    ) -> AuthenticatedSession? {
        if let session = carrierSession(for: carrier),
           session.connection.isDirect {
            return session
        }
        if let session = endpointSession(for: carrier),
           session.connection.isDirect {
            return session
        }
        return nil
    }

    // MARK: - Signed Receiving

    private func handleAuthenticatedData(
        _ record: SessionDataRecord,
        session: AuthenticatedSession
    ) async {
        guard isCurrent(session) else { return }
        guard record.sessionID == session.sessionID,
              session.sequenceState.canAcceptIncoming(record.sequence) else {
            rejectAuthenticatedSession(session, attributedTo: Self.attributedPeer(
                session.peerKey,
                direct: session.connection.isDirect,
                evidence: .unverified))
            return
        }
        guard record.isValid(sender: session.peerKey, receiver: localKey) else {
            rejectAuthenticatedSession(session, attributedTo: Self.attributedPeer(
                session.peerKey,
                direct: session.connection.isDirect,
                evidence: .unverified))
            return
        }
        let transportAttribution = Self.attributedPeer(
            session.peerKey,
            direct: session.connection.isDirect,
            evidence: .signedTransport)
        guard session.sequenceState.acceptIncoming(record.sequence) else {
            rejectAuthenticatedSession(session, attributedTo: transportAttribution)
            return
        }
        tally.recordReceived(peer: session.peerKey.peerID, bytes: record.payload.count)

        guard let message = Message.deserialize(record.payload, maxDataPayload: config.protocolMaxFrameSize) else {
            // A message a later version added is ignored, so a peer may be
            // sent one before this version knows it. A known message that
            // does not decode is a violation.
            guard !Message.hasUnknownTag(record.payload) else { return }
            rejectAuthenticatedSession(session, attributedTo: Self.attributedPeer(
                session.peerKey,
                direct: session.connection.isDirect,
                evidence: .signedPayload))
            return
        }

        if isRelayControl(message) {
            guard config.mode.usesOverlayServices else { return }
            guard sessionMayCarryRelayControl(message, session: session) else {
                rejectAuthenticatedSession(session, attributedTo: session.peerKey)
                return
            }
            await handleRelayControl(message, from: session.peerKey)
            return
        }

        if session.role == .carrier {
            switch message {
            case .ping, .pong:
                break
            default:
                rejectAuthenticatedSession(session, attributedTo: session.peerKey)
                return
            }
        }
        await handleMessage(message, from: session.peerKey.peerID, session: session)
    }

    private func isRelayControl(_ message: Message) -> Bool {
        switch message {
        case .relayOpen, .relayOffer, .relayAccept, .relayReady, .relayPacket, .relayClose:
            return true
        default:
            return false
        }
    }

    private func sessionMayCarryRelayControl(
        _ message: Message,
        session: AuthenticatedSession
    ) -> Bool {
        guard session.connection.isDirect else { return false }
        switch message {
        case .relayOpen:
            return config.relayEnabled
        case .relayOffer:
            // Inbound route offers do not grant endpoint authority. The
            // relayed handshake still authenticates both endpoint keys.
            return true
        case .relayAccept(let routeID, _):
            if let route = relayRoutes[routeID] { return route.target == session.peerKey }
            return config.relayEnabled && relayRouteIsUnknown(routeID)
        case .relayReady(let routeID, _):
            return pendingRelayOpens[routeID]?.carrier == session.peerKey
                || installedRoutes[routeID]?.carrier == session.peerKey
                || (config.isConfiguredCarrier(session.peerKey)
                    && relayRouteIsUnknown(routeID))
        case .relayPacket(let routeID, _), .relayClose(let routeID):
            // Unknown and late frames are idempotent, Tally-gated no-ops.
            return relayRouteIsUnknown(routeID)
                || relayParticipant(routeID, peer: session.peerKey)
        default:
            return false
        }
    }

    private func endpointMayReceiveRelayControl(_ message: Message, peer: PeerKey) -> Bool {
        switch message {
        case .relayOffer(let routeID, _):
            return config.relayEnabled && relayRoutes[routeID]?.target == peer
        case .relayReady(let routeID, _):
            return config.relayEnabled && relayRoutes[routeID]?.source == peer
        case .relayAccept(let routeID, _), .relayPacket(let routeID, _), .relayClose(let routeID):
            return relayParticipant(routeID, peer: peer)
        default:
            return false
        }
    }

    private func relayParticipant(_ routeID: Data, peer: PeerKey) -> Bool {
        if let route = relayRoutes[routeID] {
            return route.source == peer || route.target == peer
        }
        return installedRoutes[routeID]?.carrier == peer
            || pendingRelayOpens[routeID]?.carrier == peer
    }

    private func relayRouteIsUnknown(_ routeID: Data) -> Bool {
        routeID != Self.directRouteBinding
            && relayRoutes[routeID] == nil
            && installedRoutes[routeID] == nil
            && pendingRelayOpens[routeID] == nil
    }

    // MARK: - Relay Routes

    public func connectViaRelay(to endpoint: PeerEndpoint) async throws {
        guard let key = try? PeerKey(endpoint.publicKey) else { throw IvyError.invalidPeerKey }
        reconnectSuppressed.remove(key.peerID)
        try await connectViaRelay(to: endpoint, requiredGeneration: runGeneration)
    }

    private func connectViaRelay(
        to endpoint: PeerEndpoint,
        requiredGeneration generation: UInt64
    ) async throws {
        guard config.mode.usesOverlayServices else { throw IvyError.noRelayAvailable }
        guard let target = try? PeerKey(endpoint.publicKey) else { throw IvyError.invalidPeerKey }
        guard config.allowsEndpoint(target) else { throw IvyError.peerOutsideMode }
        guard isCurrentRun(generation),
              !Task.isCancelled,
              !reconnectSuppressed.contains(target.peerID) else { throw IvyError.notRunning }
        if endpointSession(for: target)?.connection.isLive == true { return }
        let candidates = sessions.values
            .filter { $0.role == .carrier && $0.connection.isDirect }
            .map(\.peerKey)

        for carrier in candidates.sorted() {
            guard isCurrentRun(generation),
                  !Task.isCancelled,
                  !reconnectSuppressed.contains(target.peerID) else {
                throw CancellationError()
            }
            guard let routeID = await requestRelayRoute(
                target: target,
                via: carrier,
                generation: generation) else {
                continue
            }
            guard isCurrentRun(generation),
                  !Task.isCancelled,
                  !reconnectSuppressed.contains(target.peerID) else {
                closeInstalledRoute(routeID, notifyCarrier: true)
                throw CancellationError()
            }
            guard let connection = openInstalledRouteConnection(
                endpoint: PeerEndpoint(
                    publicKey: target.hex,
                    host: endpoint.host,
                    port: endpoint.port),
                target: target,
                routeID: routeID,
                carrier: carrier) else {
                closeInstalledRoute(routeID, notifyCarrier: true)
                continue
            }
            startInboundTask(connection)
            let authenticated = await authenticateInitiator(
                connection,
                expected: target,
                routeBinding: routeID)
            guard isCurrentRun(generation),
                  !Task.isCancelled,
                  !reconnectSuppressed.contains(target.peerID) else {
                connection.cancel()
                throw CancellationError()
            }
            if authenticated,
               sessions[target]?.connection.isLive == true { return }
            closeInstalledRoute(routeID, notifyCarrier: true)
        }
        throw IvyError.noRelayAvailable
    }

    private func openInstalledRouteConnection(
        endpoint: PeerEndpoint,
        target: PeerKey,
        routeID: Data,
        carrier: PeerKey
    ) -> PeerConnection? {
        guard var route = installedRoutes[routeID],
              route.carrier == carrier,
              route.remote == target,
              route.connection == nil,
              connectionCapacityUsed < config.maxConnections else { return nil }
        let connection = makeRelayedConnection(
            endpoint: endpoint,
            routeID: routeID,
            carrier: carrier)
        route.connection = connection
        installedRoutes[routeID] = route
        return connection
    }

    private func requestRelayRoute(
        target: PeerKey,
        via carrier: PeerKey,
        generation: UInt64
    ) async -> Data? {
        guard isCurrentRun(generation), !Task.isCancelled,
              installedRoutes.count + pendingRelayOpens.count < Self.maxRelayRoutes,
              installedRoutes.values.lazy.filter({ $0.carrier == carrier }).count
                + pendingRelayOpens.values.lazy.filter({ $0.carrier == carrier }).count
                < Self.maxRelayRoutesPerPeer else { return nil }
        let routeID = freshRouteID()
        let timeoutToken = UUID()

        let opened = await withTaskCancellationHandler {
            await withCheckedContinuation { continuation in
                var pending = PendingRelayOpen(
                    carrier: carrier,
                    target: target,
                    timeoutToken: timeoutToken,
                    continuation: continuation)
                pendingRelayOpens[routeID] = pending
                guard sendRelayControl(
                    .relayOpen(routeID: routeID, targetKey: target),
                    to: carrier
                ) else {
                    _ = removePendingRelayOpen(routeID)
                    continuation.resume(returning: nil)
                    return
                }
                let timeout = config.relayTimeout
                pending.timeoutTask = delayedTask(after: timeout) { [weak self] in
                    await self?.timeoutRelayOpen(routeID, token: timeoutToken)
                }
                pendingRelayOpens[routeID] = pending
            }
        } onCancel: { [weak self] in
            guard let self else { return }
            Task {
                await self.timeoutRelayOpen(routeID, token: timeoutToken)
            }
        }
        if Task.isCancelled {
            if let opened {
                closeInstalledRoute(opened, notifyCarrier: true)
            } else {
                timeoutRelayOpen(routeID, token: timeoutToken)
            }
            return nil
        }
        return opened
    }

    private func timeoutRelayOpen(_ routeID: Data) {
        guard let pending = removePendingRelayOpen(routeID) else { return }
        _ = sendRelayControl(.relayClose(routeID: routeID), to: pending.carrier)
        pending.continuation.resume(returning: nil)
    }

    private func timeoutRelayOpen(_ routeID: Data, token: UUID) {
        guard pendingRelayOpens[routeID]?.timeoutToken == token else { return }
        timeoutRelayOpen(routeID)
    }

    private func handleRelayControl(_ message: Message, from sender: PeerKey) async {
        switch message {
        case .relayOpen(let routeID, let target):
            guard routeID.count == 32,
                  relayRouteIsUnknown(routeID) else {
                tally.recordProtocolViolation(peer: sender.peerID)
                return
            }
            guard relayRoutes.count < Self.maxRelayRoutes else {
                _ = sendRelayReply(.relayReady(routeID: routeID, status: 1), to: sender)
                return
            }
            guard relayRoutes.values.lazy.filter({ $0.source == sender }).count
                    < Self.maxRelayRoutesPerPeer else {
                _ = sendRelayReply(.relayReady(routeID: routeID, status: 1), to: sender)
                return
            }
            guard config.relayEnabled,
                  sender != target,
                  let targetSession = endpointSession(for: target),
                  targetSession.connection.isDirect else {
                _ = sendRelayReply(
                    .relayReady(
                        routeID: routeID,
                        status: 1),
                    to: sender)
                return
            }

            relayRoutes[routeID] = RelayRoute(
                source: sender,
                target: target,
                lifecycleID: UUID(),
                ready: false,
                lastActivity: .now)
            scheduleUnreadyRelayExpiry(routeID)
            guard sendRelayControl(.relayOffer(routeID: routeID, sourceKey: sender), to: target) else {
                relayRoutes.removeValue(forKey: routeID)?.expiryTask?.cancel()
                _ = sendRelayReply(
                    .relayReady(routeID: routeID, status: 1),
                    to: sender)
                return
            }

        case .relayOffer(let routeID, let source):
            guard routeID.count == 32,
                  source != localKey,
                  source != sender,
                  config.allowsEndpoint(source),
                  relayRouteIsUnknown(routeID) else {
                _ = sendRelayReply(.relayAccept(routeID: routeID, status: 1), to: sender)
                return
            }
            guard installedRoutes.count + pendingRelayOpens.count < Self.maxRelayRoutes else {
                _ = sendRelayReply(.relayAccept(routeID: routeID, status: 1), to: sender)
                return
            }
            guard installedRoutes.values.lazy.filter({ $0.carrier == sender }).count
                    + pendingRelayOpens.values.lazy.filter({ $0.carrier == sender }).count
                    < Self.maxRelayRoutesPerPeer else {
                _ = sendRelayReply(.relayAccept(routeID: routeID, status: 1), to: sender)
                return
            }
            installedRoutes[routeID] = InstalledRoute(
                carrier: sender,
                remote: source,
                lifecycleID: UUID())
            scheduleIdleInstalledRouteExpiry(routeID, carrier: sender)
            guard sendRelayControl(.relayAccept(routeID: routeID, status: 0), to: sender) else {
                installedRoutes.removeValue(forKey: routeID)?.expiryTask?.cancel()
                return
            }

        case .relayAccept(let routeID, let status):
            guard var route = relayRoutes[routeID] else { return }
            guard route.target == sender else {
                tally.recordProtocolViolation(peer: sender.peerID)
                return
            }
            guard status == 0 else {
                relayRoutes.removeValue(forKey: routeID)?.expiryTask?.cancel()
                _ = sendRelayReply(
                    .relayReady(routeID: routeID, status: status),
                    to: route.source)
                return
            }
            route.ready = true
            route.lastActivity = .now
            relayRoutes[routeID] = route
            scheduleRelayIdleExpiry(routeID)
            guard sendRelayControl(
                    .relayReady(routeID: routeID, status: 0),
                    to: route.source) else {
                closeRelayRoute(routeID)
                return
            }

        case .relayReady(let routeID, let status):
            guard let pending = pendingRelayOpens[routeID] else { return }
            guard pending.carrier == sender else {
                tally.recordProtocolViolation(peer: sender.peerID)
                return
            }
            _ = removePendingRelayOpen(routeID)
            guard status == 0 else {
                pending.continuation.resume(returning: nil)
                return
            }
            guard routeID.count == 32,
                  installedRoutes.count < Self.maxRelayRoutes,
                  installedRoutes.values.lazy.filter({ $0.carrier == sender }).count
                    < Self.maxRelayRoutesPerPeer,
                  relayRouteIsUnknown(routeID) else {
                _ = sendRelayControl(.relayClose(routeID: routeID), to: sender)
                pending.continuation.resume(returning: nil)
                return
            }
            installedRoutes[routeID] = InstalledRoute(
                carrier: sender,
                remote: pending.target,
                lifecycleID: UUID())
            scheduleIdleInstalledRouteExpiry(routeID, carrier: sender)
            pending.continuation.resume(returning: routeID)

        case .relayClose(let routeID):
            if let route = relayRoutes[routeID] {
                guard route.source == sender || route.target == sender else { return }
                closeRelayRoute(routeID, excluding: sender)
                return
            }
            if let pending = pendingRelayOpens[routeID], pending.carrier == sender {
                removePendingRelayOpen(routeID)?.continuation.resume(returning: nil)
                return
            }
            guard installedRoutes[routeID]?.carrier == sender else { return }
            closeInstalledRoute(routeID, notifyCarrier: false)

        case .relayPacket(let routeID, let opaqueRecord):
            if var route = relayRoutes[routeID] {
                guard route.ready else { return }
                let destination: PeerKey
                if route.source == sender {
                    destination = route.target
                } else if route.target == sender {
                    destination = route.source
                } else {
                    tally.recordProtocolViolation(peer: sender.peerID)
                    return
                }
                route.lastActivity = .now
                relayRoutes[routeID] = route
                guard let destinationSession = endpointSession(for: destination),
                      destinationSession.connection.isDirect else {
                    closeRelayRoute(routeID)
                    return
                }
                await forwardRelayPacket(
                    opaqueRecord,
                    routeID: routeID,
                    lifecycleID: route.lifecycleID,
                    destination: destinationSession
                )
                return
            }

            guard var installed = installedRoutes[routeID],
                  installed.carrier == sender else {
                return
            }
            if let connection = installed.connection {
                guard connection.feedRecord(opaqueRecord) else {
                    closeInstalledRoute(routeID, notifyCarrier: true)
                    return
                }
                return
            }

            guard let firstRecord = try? SessionWireRecord.deserialize(
                    opaqueRecord, maxPayload: config.protocolMaxFrameSize),
                  case .helloInitiator(let hello) = firstRecord,
                  hello.isValid(),
                  hello.hello.initiator == installed.remote,
                  hello.hello.responder == localKey,
                  hello.hello.routeBinding == routeID else {
                closeInstalledRoute(routeID, notifyCarrier: true)
                return
            }

            let endpoint = PeerEndpoint(
                publicKey: installed.remote.hex,
                host: "relay",
                port: 0)
            let connection = makeRelayedConnection(
                endpoint: endpoint,
                routeID: routeID,
                carrier: sender)
            guard registerInboundConnection(connection, generation: runGeneration) else {
                closeInstalledRoute(routeID, notifyCarrier: true)
                return
            }
            installed.connection = connection
            installedRoutes[routeID] = installed
            guard connection.feedRecord(opaqueRecord) else {
                failPendingSession(connection.connectionID)
                closeInstalledRoute(routeID, notifyCarrier: true)
                return
            }

        default:
            return
        }
    }

    private func forwardRelayPacket(
        _ opaqueRecord: Data,
        routeID: Data,
        lifecycleID: UUID,
        destination: AuthenticatedSession
    ) async {
        let message = Message.relayPacket(
            routeID: routeID,
            opaqueEndpointRecord: opaqueRecord
        )
        let deadline = ContinuousClock.now.advanced(by: config.requestTimeout)
        while relayRoutes[routeID]?.lifecycleID == lifecycleID,
              isCurrent(destination) {
            switch enqueue(message, on: destination) {
            case .enqueued:
                return
            case .backpressured:
                guard await waitUntilWritable(
                    destination.connection,
                    deadline: deadline
                ) else {
                    if relayRoutes[routeID]?.lifecycleID == lifecycleID {
                        closeRelayRoute(routeID)
                    }
                    return
                }
            case .notConnected, .locallyRejected:
                if relayRoutes[routeID]?.lifecycleID == lifecycleID {
                    closeRelayRoute(routeID)
                }
                return
            }
        }
    }

    private func waitUntilWritable(
        _ connection: PeerConnection,
        deadline: ContinuousClock.Instant
    ) async -> Bool {
        let remaining = ContinuousClock.now.duration(to: deadline)
        guard remaining > .zero else { return false }
        return await withTaskGroup(of: Bool.self) { group in
            group.addTask {
                await connection.waitUntilWritable()
            }
            group.addTask {
                do {
                    try await Task.sleep(for: remaining)
                } catch {
                    return false
                }
                return false
            }
            let result = await group.next() ?? false
            group.cancelAll()
            return result
        }
    }

    private func scheduleUnreadyRelayExpiry(_ routeID: Data) {
        guard var route = relayRoutes[routeID], !route.ready else { return }
        route.expiryTask?.cancel()
        let lifecycleID = route.lifecycleID
        let timeout = config.relayTimeout
        route.expiryTask = delayedTask(after: timeout) { [weak self] in
            await self?.expireUnreadyRelayRoute(routeID, lifecycleID: lifecycleID)
        }
        relayRoutes[routeID] = route
    }

    private func expireUnreadyRelayRoute(_ routeID: Data, lifecycleID: UUID) {
        guard let route = relayRoutes[routeID],
              route.lifecycleID == lifecycleID,
              !route.ready else { return }
        closeRelayRoute(routeID)
    }

    private func scheduleRelayIdleExpiry(_ routeID: Data, after delay: Duration? = nil) {
        guard var route = relayRoutes[routeID], route.ready else { return }
        route.expiryTask?.cancel()
        let lifecycleID = route.lifecycleID
        route.expiryTask = delayedTask(
            after: delay ?? Self.relayIdleTimeout
        ) { [weak self] in
            await self?.expireIdleRelayRoute(routeID, lifecycleID: lifecycleID)
        }
        relayRoutes[routeID] = route
    }

    private func expireIdleRelayRoute(_ routeID: Data, lifecycleID: UUID) {
        guard let route = relayRoutes[routeID],
              route.lifecycleID == lifecycleID,
              route.ready else { return }
        let idle = route.lastActivity.duration(to: .now)
        if idle >= Self.relayIdleTimeout {
            closeRelayRoute(routeID)
        } else {
            scheduleRelayIdleExpiry(routeID, after: Self.relayIdleTimeout - idle)
        }
    }

    private func scheduleIdleInstalledRouteExpiry(_ routeID: Data, carrier: PeerKey) {
        guard var route = installedRoutes[routeID], route.carrier == carrier else { return }
        route.expiryTask?.cancel()
        let lifecycleID = route.lifecycleID
        let timeout = config.relayTimeout
        route.expiryTask = delayedTask(after: timeout) { [weak self] in
            await self?.expireIdleInstalledRoute(
                routeID,
                carrier: carrier,
                lifecycleID: lifecycleID)
        }
        installedRoutes[routeID] = route
    }

    private func expireIdleInstalledRoute(
        _ routeID: Data,
        carrier: PeerKey,
        lifecycleID: UUID
    ) {
        guard let route = installedRoutes[routeID],
              route.connection == nil,
              route.carrier == carrier,
              route.lifecycleID == lifecycleID else { return }
        closeInstalledRoute(routeID, notifyCarrier: true)
    }

    private func freshRouteID() -> Data {
        var routeID = secureRandom32()
        while !relayRouteIsUnknown(routeID) {
            routeID = secureRandom32()
        }
        return routeID
    }

    private func makeRelayedConnection(
        endpoint: PeerEndpoint,
        routeID: Data,
        carrier: PeerKey
    ) -> PeerConnection {
        PeerConnection(
            endpoint: endpoint,
            routeID: routeID,
            carrier: carrier,
            inboundByteBudget: inboundByteBudget,
            localMaxFrameSize: config.protocolMaxFrameSize)
    }

    // MARK: - Message Handling

    func handleMessage(
        _ message: Message,
        from peer: PeerID,
        session: AuthenticatedSession? = nil
    ) async {
        if let session {
            guard isCurrent(session) else { return }
            if let monitor = healthMonitor {
                if case .pong(let nonce) = message {
                    _ = await monitor.recordPong(
                        from: peer,
                        sessionID: session.sessionID,
                        nonce: nonce)
                } else {
                    await monitor.recordActivity(from: peer, sessionID: session.sessionID)
                }
            }
#if DEBUG || IVY_TESTING
            await messageActivityHookForTesting?()
#endif
            guard isCurrent(session) else { return }
        }
        if !config.mode.usesOverlayServices {
            switch message {
            case .ping, .pong, .peerMessage:
                break
            case .contentRequest, .contentResponse, .contentUnavailable,
                 .volumeRequest, .volumeChunk, .volumeBundleRequest, .volumeBundleEnd:
                guard config.privateContentExchangeEnabled else { return }
            default:
                return
            }
        }
        switch message {
        case .ping(let nonce):
            fireToPeer(peer, .pong(nonce: nonce))

        case .pong:
            return

        case .relayOpen, .relayOffer, .relayAccept, .relayReady, .relayPacket, .relayClose:
            return

        case .findNode(let target, let nonce):
            let closest = router.closestPeers(to: Array(target), count: config.kBucketSize)
            let endpoints = closest.map { $0.endpoint }
            fireToPeer(peer, .neighbors(endpoints, nonce: nonce))

        case .neighbors(let endpoints, let nonce):
            guard isExpectedNeighborResponse(nonce: nonce, from: peer) else { return }
            var accepted: [PeerEndpoint] = []
            for ep in endpoints {
                guard isAcceptableDiscoveredEndpoint(
                        ep,
                        provenance: .referral("neighbors"),
                        from: peer),
                      let key = try? PeerKey(ep.publicKey) else { continue }
                let canonical = PeerEndpoint(
                    publicKey: key.hex,
                    host: ep.host.trimmingCharacters(in: .whitespacesAndNewlines),
                    port: ep.port)
                accepted.append(canonical)
            }
            receiveNeighborResponse(nonce: nonce, endpoints: accepted, from: peer)

        case .contentRequest(let requestID, let rootCID, let cids):
            scheduleContentRequest(
                requestID: requestID,
                rootCID: rootCID,
                cids: cids,
                from: peer,
                session: session
            )

        case .contentResponse(let requestID, let entries):
            handleContentResponse(
                requestID: requestID,
                entries: entries,
                from: peer,
                sessionID: session?.sessionID.bytes
            )

        case .contentUnavailable(let requestID):
            handleContentUnavailable(
                requestID: requestID,
                from: peer,
                sessionID: session?.sessionID.bytes
            )

        case .volumeRequest(let requestID, let rootCID):
            scheduleVolumeRequest(
                requestID: requestID,
                rootCID: rootCID,
                from: peer,
                session: session
            )

        case .volumeBundleRequest(let requestID, let rootCID):
            scheduleVolumeRequest(
                requestID: requestID,
                rootCID: rootCID,
                bundle: true,
                from: peer,
                session: session
            )

        case .volumeBundleEnd(let requestID):
            handleVolumeBundleEnd(
                requestID: requestID,
                from: peer,
                sessionID: session?.sessionID.bytes
            )

        case let .volumeChunk(
            requestID,
            rootCID,
            index,
            count,
            totalEntries,
            totalBytes,
            payload
        ):
            handleVolumeChunk(
                requestID: requestID,
                rootCID: rootCID,
                index: index,
                count: count,
                totalEntries: totalEntries,
                totalBytes: totalBytes,
                payload: payload,
                from: peer,
                sessionID: session?.sessionID.bytes,
                relayed: session?.connection.isDirect == false
            )

        case .findProviders(let rootCID, let requestID):
            handleFindProviders(rootCID: rootCID, requestID: requestID, from: peer)

        case .providers(let rootCID, let requestID, let records):
            handleProvidersResponse(
                rootCID: rootCID,
                requestID: requestID,
                records: records,
                from: peer)

        case .announceProvider(let rootCID, let expiresAt):
            handleAnnounceProvider(rootCID: rootCID, expiresAt: expiresAt, from: peer)

        case .peerMessage(let topic, let payload):
            guard let session else { return }
            await delegate?.ivy(
                self,
                didReceiveMessage: PeerMessage(topic: topic, payload: payload),
                from: AuthenticatedPeer(
                    key: session.peerKey,
                    role: session.role,
                    route: session.connection.route,
                    metadata: session.metadata,
                    sessionID: session.sessionID.bytes))
        }
    }

    func requestNeighbors(
        from peer: PeerID,
        targetHash: [UInt8],
        generation: UInt64,
        timeout: Duration
    ) async -> [PeerEndpoint] {
        guard config.mode.usesOverlayServices,
              isCurrentRun(generation),
              !Task.isCancelled else { return [] }
#if DEBUG || IVY_TESTING
        if let hook = neighborRequestHookForTesting {
            let endpoints = await hook(peer, targetHash)
            return isCurrentRun(generation) && !Task.isCancelled ? endpoints : []
        }
#endif
        guard hasEndpointSession(peer),
              pendingNeighborResponses.count < config.maxPendingRequests else { return [] }
        let nonce = makeFindNodeNonce()
        let endpoints = await withTaskCancellationHandler {
            guard !Task.isCancelled else { return [PeerEndpoint]() }
            return await withCheckedContinuation {
                (cont: CheckedContinuation<[PeerEndpoint], Never>) in
                guard !Task.isCancelled else {
                    cont.resume(returning: [])
                    return
                }
                pendingNeighborResponses[nonce] = PendingNeighborResponse(
                    peer: peer,
                    continuation: cont)
                guard case .enqueued = fireToPeer(
                    peer,
                    .findNode(target: Data(targetHash), nonce: nonce)) else {
                    resolveNeighborResponse(nonce: nonce, endpoints: [])
                    return
                }
                let timeoutTask = delayedTask(after: timeout) { [weak self] in
                    await self?.resolveNeighborResponse(nonce: nonce, endpoints: [])
                }
                pendingNeighborResponses[nonce]?.timeoutTask = timeoutTask
            }
        } onCancel: {
            Task { await self.resolveNeighborResponse(nonce: nonce, endpoints: []) }
        }
        return isCurrentRun(generation) && !Task.isCancelled ? endpoints : []
    }

    func receiveNeighborResponse(nonce: UInt64, endpoints: [PeerEndpoint], from peer: PeerID) {
        guard isExpectedNeighborResponse(nonce: nonce, from: peer) else { return }
        resolveNeighborResponse(nonce: nonce, endpoints: endpoints)
    }

    func resolveNeighborResponse(nonce: UInt64, endpoints: [PeerEndpoint]) {
        guard let pending = pendingNeighborResponses.removeValue(forKey: nonce) else { return }
        pending.timeoutTask?.cancel()
        pending.continuation.resume(returning: endpoints)
    }

    func isExpectedNeighborResponse(nonce: UInt64, from peer: PeerID) -> Bool {
        pendingNeighborResponses[nonce]?.peer == peer
    }

    func makeFindNodeNonce() -> UInt64 {
        makeWireOperationID(avoiding: Set(pendingNeighborResponses.keys))
    }

    func makeWireOperationID(avoiding inUse: Set<UInt64>) -> UInt64 {
        repeat {
            nextWireOperationID &+= 1
        } while nextWireOperationID == 0 || inUse.contains(nextWireOperationID)
        return nextWireOperationID
    }

    // MARK: - Cleanup

    func cleanupPendingForPeer(_ peer: PeerID) {
        volumeTimeoutStreaks[peer] = nil
        let serving = servingContentTasks.keys.filter { $0.peer == peer }
        for request in serving {
            servingContentTasks[request]?.cancel()
        }
        let requestIDs = pendingContentRequests.compactMap { requestID, request in
            request.candidates.contains(peer) ? requestID : nil
        }
        for requestID in requestIDs {
            markContentCandidateDone(requestID: requestID, peer: peer)
        }

        let volumeRequestIDs = pendingVolumeRequests.compactMap { requestID, request in
            request.candidateSessions[peer] != nil ? requestID : nil
        }
        for requestID in volumeRequestIDs {
            markVolumeCandidateDone(requestID: requestID, peer: peer)
        }

        let neighborNonces = pendingNeighborResponses.compactMap { nonce, pending in
            pending.peer == peer ? nonce : nil
        }
        for nonce in neighborNonces {
            resolveNeighborResponse(nonce: nonce, endpoints: [])
        }

        let peerKey = peer.publicKey
        let providerRoots = pendingProviderQueries.compactMap { rootCID, pending in
            pending.expectedPeers.contains(peerKey) ? rootCID : nil
        }
        for rootCID in providerRoots {
            guard var pending = pendingProviderQueries[rootCID] else { continue }
            pending.expectedPeers.remove(peerKey)
            if pending.expectedPeers.isEmpty {
                resolveProviderQuery(rootCID: rootCID, requestID: pending.requestID)
            } else {
                pendingProviderQueries[rootCID] = pending
            }
        }
    }

    /// Resume every in-flight continuation with an empty result. Shared by
    /// `cleanupAllPending` (stop/reset) and `deinit` (teardown safety net).
    private static func drainAllPending(
        pendingSessions: [UUID: PendingSession],
        pendingPeerConnectionWaiters: [PeerKey: PendingPeerConnectionWaiter],
        pendingContentRequests: [UInt64: PendingContentRequest],
        pendingVolumeRequests: [UInt64: PendingVolumeRequest],
        pendingNeighborResponses: [UInt64: PendingNeighborResponse],
        pendingProviderQueries: [String: PendingProviderQuery],
        pendingRelayOpens: [Data: PendingRelayOpen]
    ) {
        for pending in pendingSessions.values {
            pending.timeoutTask?.cancel()
            pending.continuation?.resume(returning: false)
        }
        for waiter in pendingPeerConnectionWaiters.values {
            waiter.continuation.resume(returning: false)
        }
        for (_, request) in pendingContentRequests {
            request.timeoutTask?.cancel()
            request.continuation.resume(returning: .empty)
        }
        for (_, request) in pendingVolumeRequests {
            request.timeoutTask?.cancel()
            request.continuation.resume(returning: .empty)
        }
        for (_, pending) in pendingNeighborResponses {
            pending.timeoutTask?.cancel()
            pending.continuation.resume(returning: [])
        }
        for (_, pending) in pendingProviderQueries {
            pending.timeoutTask?.cancel()
            for cont in pending.continuations.values { cont.resume(returning: []) }
        }
        for (_, request) in pendingRelayOpens {
            request.timeoutTask?.cancel()
            request.continuation.resume(returning: nil)
        }
    }

    /// Safety net for an instance released with requests still in flight.
    deinit {
        lifecycleTail?.cancel()
        publicAddressDiscoveryTask?.cancel()
        routingRefreshTimer?.cancel()
        serverChannel?.close(promise: nil)
        for reconnect in reconnectTasks.values { reconnect.task.cancel() }
        for route in relayRoutes.values { route.expiryTask?.cancel() }
        for route in installedRoutes.values {
            route.expiryTask?.cancel()
            route.connection?.cancel()
        }
        for pending in pendingSessions.values { pending.connection.cancel() }
        for session in sessions.values { session.connection.cancel() }
        for pending in pendingFetches.values {
            pending.operationTask?.cancel()
            pending.timeoutTask?.cancel()
            for continuation in pending.continuations.values {
                continuation.resume(returning: .empty)
            }
        }
        Self.drainAllPending(
            pendingSessions: pendingSessions,
            pendingPeerConnectionWaiters: pendingPeerConnectionWaiters,
            pendingContentRequests: pendingContentRequests,
            pendingVolumeRequests: pendingVolumeRequests,
            pendingNeighborResponses: pendingNeighborResponses,
            pendingProviderQueries: pendingProviderQueries,
            pendingRelayOpens: pendingRelayOpens
        )
    }

    func cleanupAllPending() {
        for task in servingContentTasks.values { task.cancel() }
        refuseAllServingTickets()
        releaseAllOutstandingVolumeSlotWaiters()
        Self.drainAllPending(
            pendingSessions: pendingSessions,
            pendingPeerConnectionWaiters: pendingPeerConnectionWaiters,
            pendingContentRequests: pendingContentRequests,
            pendingVolumeRequests: pendingVolumeRequests,
            pendingNeighborResponses: pendingNeighborResponses,
            pendingProviderQueries: pendingProviderQueries,
            pendingRelayOpens: pendingRelayOpens
        )
        for pending in pendingSessions.values { pending.connection.cancel() }
        pendingSessions.removeAll()
        pendingPeerConnectionWaiters.removeAll()
        pendingContentRequests.removeAll()
        pendingVolumeRequests.removeAll()
        inFlightVolumeBytes = 0
        reservedVolumeBytes = 0
        for pending in pendingFetches.values {
            pending.operationTask?.cancel()
            pending.timeoutTask?.cancel()
            for continuation in pending.continuations.values {
                continuation.resume(returning: .empty)
            }
        }
        pendingFetches.removeAll()
        pendingNeighborResponses.removeAll()
        pendingProviderQueries.removeAll()
        pendingRelayOpens.removeAll()
    }

    // MARK: - Private Helpers

    func closestCandidateEntries(
        _ entries: some Sequence<Router.BucketEntry>,
        to targetHash: [UInt8]
    ) -> [Router.BucketEntry] {
        Array(entries)
            .sorted { Router.isCloser($0.hash, than: $1.hash, to: targetHash) }
            .prefix(config.kBucketSize)
            .map { $0 }
    }

    static func preferredSessionID(_ first: SessionID, _ second: SessionID) -> SessionID {
        min(first, second)
    }

#if DEBUG || IVY_TESTING
    var contentReplyConnectionsForTesting: [UUID] = []
    var lifecycleRequestCountForTesting = 0
    var lifecycleStartHookForTesting: (@Sendable () async -> Void)?
    var listenerReadyHookForTesting: (@Sendable () async -> Void)?
    var publicAddressDiscoveryHookForTesting: (@Sendable () async -> ObservedAddress?)?
    var lifecycleRequestHookForTesting: (@Sendable (Int) async -> Void)?
    var neighborRequestHookForTesting: (@Sendable (PeerID, [UInt8]) async -> [PeerEndpoint])?
    var networkFetchHookForTesting: (
        @Sendable (ContentRequestKey, UInt64, UInt64) async -> AttributedContentResponse
    )?
    var messageActivityHookForTesting: (@Sendable () async -> Void)?
    var promotionHookForTesting: (@Sendable (PeerConnection) -> Void)?
    var dialEndpointRewriteForTesting: (@Sendable (PeerEndpoint) -> PeerEndpoint)?
    var contentRequestEnqueueHookForTesting: (@Sendable (PeerID) -> Bool)?

    func setLifecycleStartHookForTesting(_ hook: (@Sendable () async -> Void)?) {
        lifecycleStartHookForTesting = hook
    }

    func setListenerReadyHookForTesting(_ hook: (@Sendable () async -> Void)?) {
        listenerReadyHookForTesting = hook
    }

    func setPublicAddressDiscoveryHookForTesting(
        _ hook: (@Sendable () async -> ObservedAddress?)?
    ) {
        publicAddressDiscoveryHookForTesting = hook
    }

    func setLifecycleRequestHookForTesting(_ hook: (@Sendable (Int) async -> Void)?) {
        lifecycleRequestHookForTesting = hook
    }

    func publicAddressDiscoveryTaskForTesting() -> Task<Void, Never>? {
        publicAddressDiscoveryTask
    }

    func setNeighborRequestHookForTesting(
        _ hook: (@Sendable (PeerID, [UInt8]) async -> [PeerEndpoint])?
    ) {
        neighborRequestHookForTesting = hook
    }

    func setNetworkFetchHookForTesting(
        _ hook: (
            @Sendable (ContentRequestKey, UInt64, UInt64) async -> AttributedContentResponse
        )?
    ) {
        networkFetchHookForTesting = hook
    }

    func setMessageActivityHookForTesting(_ hook: (@Sendable () async -> Void)?) {
        messageActivityHookForTesting = hook
    }

    func setPromotionHookForTesting(_ hook: (@Sendable (PeerConnection) -> Void)?) {
        promotionHookForTesting = hook
    }

    func setDialEndpointRewriteForTesting(
        _ rewrite: (@Sendable (PeerEndpoint) -> PeerEndpoint)?
    ) {
        dialEndpointRewriteForTesting = rewrite
    }

    func setContentRequestEnqueueHookForTesting(
        _ hook: (@Sendable (PeerID) -> Bool)?
    ) {
        contentRequestEnqueueHookForTesting = hook
    }

    func setEndpointWritabilityForTesting(_ peer: PeerID, writable: Bool) {
        guard let key = try? PeerKey(peer.publicKey),
              let session = endpointSession(for: key) else { return }
        session.connection.channelWritabilityChanged(isWritable: writable)
    }

    var reservedServingVolumeBytesForTesting: Int {
        reservedServingVolumeBytes
    }

    var servingVolumeReadWaiterCountForTesting: Int {
        servingVolumeReadWaiters.count
    }

    /// Sends `payload` as a signed session record without encoding a message.
    func sendRawPayloadForTesting(_ payload: Data, to peer: AuthenticatedPeer) -> SendMessageResult {
        guard let session = endpointSession(for: peer.key) else { return .notConnected }
        return enqueuePayload(payload, on: session)
    }

    var providerQueryCountForTesting: Int {
        freshProviderQueryCount
    }

    var waitingServingTicketCountForTesting: Int {
        servingTickets.values.filter { $0.state == .waiting }.count
    }

    var servingTicketCountForTesting: Int {
        servingTickets.count
    }

    func seedConnectedEndpointForTesting(
        _ endpoint: PeerEndpoint,
        connection suppliedConnection: PeerConnection? = nil,
        role: AuthenticatedPeerRole = .endpoint,
        marker: UInt8
    ) throws {
        running = true
        let peerKey = try PeerKey(endpoint.publicKey)
        let connection = suppliedConnection ?? PeerConnection(
            endpoint: endpoint,
            routeID: Data(repeating: marker, count: 32),
            carrier: peerKey,
            inboundByteBudget: inboundByteBudget,
            localMaxFrameSize: config.protocolMaxFrameSize)
        let session = AuthenticatedSession(
            connection: connection,
            peerKey: peerKey,
            role: role,
            sessionID: try SessionID(bytes: Data(repeating: marker, count: 32)),
            metadata: PeerMetadata())
        sessions[peerKey] = session
    }

    func sendAuthenticatedMessageForTesting(_ message: Message, to peer: PeerID) -> Bool {
        guard let key = try? PeerKey(peer.publicKey),
              let session = sessions[key] else { return false }
        if case .enqueued = enqueue(message, on: session) {
            return true
        }
        return false
    }

    func handleRelayControlForTesting(_ message: Message, from sender: PeerKey) async {
        await handleRelayControl(message, from: sender)
    }

    var installedRouteCountForTesting: Int { installedRoutes.count }
    var relayRouteCountForTesting: Int { relayRoutes.count }
    var activeFetchCountForTesting: Int { activeFetchCount }
    var pendingRelayOpenCountForTesting: Int { pendingRelayOpens.count }
    var pendingRelayRouteForTesting: Data? { pendingRelayOpens.keys.first }
    var outgoingDialCountForTesting: Int { outgoingDials.count }
    var routeConnectionCountForTesting: Int {
        installedRoutes.values.lazy.filter { $0.connection != nil }.count
    }

    func isHealthTrackedForTesting(_ peer: PeerID) async -> Bool {
        guard let healthMonitor else { return false }
        return await healthMonitor.health(for: peer) != nil
    }

    func bindInstalledRouteForTesting(
        routeID: Data,
        carrier: PeerKey,
        remote: PeerKey,
        connection: PeerConnection? = nil
    ) {
        installedRoutes[routeID] = InstalledRoute(
            carrier: carrier,
            remote: remote,
            lifecycleID: UUID(),
            connection: connection)
    }

    func bindRelayRouteForTesting(routeID: Data, source: PeerKey, target: PeerKey) {
        relayRoutes[routeID] = RelayRoute(
            source: source,
            target: target,
            lifecycleID: UUID(),
            ready: true,
            lastActivity: .now)
    }

    func cleanupRoutesForReplacementForTesting(
        peer: PeerKey,
        preserving connection: PeerConnection?
    ) {
        removeRoutes(involving: peer, preserving: connection)
    }

    func hasInstalledRouteForTesting(_ routeID: Data) -> Bool {
        installedRoutes[routeID] != nil
    }

    func openInstalledRouteConnectionForTesting(
        endpoint: PeerEndpoint,
        target: PeerKey,
        routeID: Data,
        carrier: PeerKey
    ) -> Bool {
        openInstalledRouteConnection(
            endpoint: endpoint,
            target: target,
            routeID: routeID,
            carrier: carrier) != nil
    }

    func canPromoteForTesting(
        _ connection: PeerConnection,
        peerKey: PeerKey,
        isInbound: Bool = false
    ) -> Bool {
        canPromote(connection, peerKey: peerKey, isInbound: isInbound)
    }

    func seedOutgoingDialForTesting(
        endpoint: PeerEndpoint,
        pendingGeneration: UInt64,
        currentGeneration: UInt64
    ) {
        running = true
        runGeneration = currentGeneration
        let peer = PeerID(publicKey: endpoint.publicKey)
        outgoingDials[peer] = PendingOutgoingDial(
            endpoint: endpoint,
            generation: pendingGeneration)
    }

    func awaitRelayOpenForTesting(
        routeID: Data,
        carrier: PeerKey,
        target: PeerKey
    ) async -> Data? {
        await withCheckedContinuation { continuation in
            pendingRelayOpens[routeID] = PendingRelayOpen(
                carrier: carrier,
                target: target,
                timeoutToken: UUID(),
                continuation: continuation)
        }
    }

    func installedRouteLifecycleForTesting(_ routeID: Data) -> UUID? {
        installedRoutes[routeID]?.lifecycleID
    }

    func expireInstalledRouteForTesting(
        _ routeID: Data,
        carrier: PeerKey,
        lifecycleID: UUID
    ) {
        expireIdleInstalledRoute(routeID, carrier: carrier, lifecycleID: lifecycleID)
    }

    func handleCurrentMessageForTesting(_ message: Message, from peer: PeerID) async {
        guard let key = try? PeerKey(peer.publicKey),
              let session = sessions[key] else { return }
        await handleMessage(message, from: peer, session: session)
    }

    func retireTransportForTesting(_ peer: PeerID) {
        guard let key = try? PeerKey(peer.publicKey), let session = sessions[key] else { return }
        teardownAuthenticatedSession(session, reconnect: false)
        session.connection.cancel()
    }

    func setPublicAddressForTesting(_ address: ObservedAddress?) {
        publicAddress = address
    }

    func advertisedListenAddressesForTesting(observedLocalHost: String? = nil) -> [ListenAddress] {
        advertisedListenAddresses(observedLocalHost: observedLocalHost)
    }

    func runPendingReconnectForTesting(_ peer: PeerID) async {
        guard let pending = reconnectTasks[peer],
              let key = try? PeerKey(peer.publicKey) else { return }
        let role: AuthenticatedPeerRole = config.isConfiguredCarrier(key) ? .carrier : .endpoint
        guard !configuredEndpoints(for: key, role: role).isEmpty else { return }
        pending.task.cancel()
        await runScheduledReconnect(
            peer: peer,
            role: role,
            generation: pending.generation,
            token: pending.token)
    }

    func handleContentRequestForTesting(
        connection: PeerConnection,
        peerKey: PeerKey,
        sessionMarker: UInt8,
        requestID: UInt64
    ) async {
        let session = AuthenticatedSession(
            connection: connection,
            peerKey: peerKey,
            role: .endpoint,
            sessionID: try! SessionID(bytes: Data(repeating: sessionMarker, count: 32)),
            metadata: PeerMetadata())
        running = true
        sessions[session.peerKey] = session
        await handleContentRequest(
            requestID: requestID,
            rootCID: "root",
            cids: [],
            from: peerKey.peerID,
            session: session)
    }

    func selectedSessionIDForTesting(_ peer: PeerID) -> Data? {
        guard let key = try? PeerKey(peer.publicKey) else { return nil }
        return endpointSession(for: key)?.sessionID.bytes
    }

    func seedResponderAwaitingFinishForTesting(
        _ endpoint: PeerEndpoint,
        marker: UInt8
    ) throws -> UUID {
        let peer = try PeerKey(endpoint.publicKey)
        let metadata = PeerMetadata()
        guard let encodedMetadata = metadata.encode() else {
            throw SessionProtocolError.malformed
        }
        let nonce = Data(repeating: marker, count: 32)
        let initiator = SignedSessionHelloInitiator(
            hello: SessionHelloInitiator(
                routeBinding: Self.directRouteBinding,
                initiator: peer,
                responder: localKey,
                nonce: nonce,
                metadata: encodedMetadata),
            signature: Data(repeating: marker, count: 64))
        let responder = SignedSessionHelloResponder(
            hello: SessionHelloResponder(
                routeBinding: Self.directRouteBinding,
                responder: localKey,
                initiator: peer,
                initiatorNonce: nonce,
                responderNonce: nonce,
                metadata: encodedMetadata),
            signature: Data(repeating: marker, count: 64))
        let connection = PeerConnection(
            endpoint: endpoint,
            routeID: Data(repeating: marker, count: 32),
            carrier: peer,
            inboundByteBudget: inboundByteBudget,
            localMaxFrameSize: config.protocolMaxFrameSize)
        pendingSessions[connection.connectionID] = PendingSession(
            connection: connection,
            direction: .responder,
            generation: runGeneration,
            helloInitiator: initiator,
            helloResponder: responder,
            sessionID: try SessionID(bytes: Data(repeating: marker, count: 32)),
            remoteKey: peer,
            remoteMetadata: metadata)
        return connection.connectionID
    }

    func resolveOutgoingDialForTesting(
        to peer: PeerID,
        generation: UInt64
    ) async -> Bool {
        guard let key = try? PeerKey(peer.publicKey) else { return false }
        return await finishOutgoingDialOrAwaitCompetingResponder(
            for: key,
            generation: generation)
    }

    func peerConnectionHasWaiterForTesting(_ peer: PeerID) -> Bool {
        guard let key = try? PeerKey(peer.publicKey) else { return false }
        return pendingPeerConnectionWaiters[key] != nil
    }

    func promotePendingResponderForTesting(_ connectionID: UUID) async {
        guard let pending = pendingSessions[connectionID] else { return }
        await promotePendingSession(pending)
    }

    var pendingSessionCountForTesting: Int { pendingSessions.count }

    var sentContentRepliesForTesting: [UUID] { contentReplyConnectionsForTesting }
#endif

    func startListener(
        generation: UInt64
    ) async throws -> (channel: Channel, gate: InboundAdmissionGate) {
        let gate = InboundAdmissionGate(
            maxConnections: config.maxInboundConnections,
            maxConnectionsPerNetgroup: config.maxConnectionsPerNetgroup,
            generation: generation)
        let bootstrap = ServerBootstrap(group: group)
            .serverChannelOption(.backlog, value: 256)
            .serverChannelOption(.socketOption(.so_reuseaddr), value: 1)
            .childChannelOption(ChannelOptions.autoRead, value: false)
            .childChannelInitializer { [weak self] channel in
                guard let self else { return channel.close() }
                do {
                    let connection = NIOTransportConnection(channel: channel)
                    try channel.pipeline.syncOperations.addHandler(connection)
                    let acceptor = InboundConnectionAcceptor(
                        ivy: self,
                        admissionGate: gate,
                        connection: connection)
                    return channel.pipeline.addHandler(acceptor)
                } catch {
                    return channel.eventLoop.makeFailedFuture(error)
                }
            }

        let channel = try await bootstrap
            .bind(host: "0.0.0.0", port: Int(config.listenPort))
            .get()

        return (channel, gate)
    }

}
