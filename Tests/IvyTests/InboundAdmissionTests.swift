import Foundation
import NIOCore
import NIOEmbedded
import NIOPosix
import Testing
@testable import Ivy
import Tally

@Suite("Inbound admission")
struct InboundAdmissionTests {
    @Test("synchronous leases enforce global and netgroup limits")
    func synchronousGate() {
        let gate = InboundAdmissionGate(maxConnections: 3, maxConnectionsPerNetgroup: 2)
        let first = gate.reserve(observedHost: "10.1.1.1")
        let second = gate.reserve(observedHost: "10.1.2.1")
        #expect(first != nil)
        #expect(second != nil)
        #expect(gate.reserve(observedHost: "10.1.3.1") == nil)

        let otherGroup = gate.reserve(observedHost: "10.2.1.1")
        #expect(otherGroup != nil)
        #expect(gate.reserve(observedHost: "10.3.1.1") == nil)

        first?.release()
        #expect(gate.reserve(observedHost: "10.1.4.1") != nil)
        gate.invalidate()
        #expect(gate.reserve(observedHost: "10.4.1.1") == nil)
    }

    @Test("an outbound reservation survives inbound churn")
    func outboundReservationSurvivesInboundChurn() async throws {
        let identity = TransportTestHarness.identity("outbound-reservation-node")
        let ivy = Ivy(config: IvyConfig(
            signingKey: identity,
            listenPort: 0,
            stunServers: [],
            healthConfig: PeerHealthConfig(enabled: false),
            maxConnections: 2,
            reservedOutboundConnectionSlots: 1,
            maxConnectionsPerNetgroup: 2))
        try await ivy.start()
        let port = try #require(await ivy.serverChannel?.localAddress?.port)

        let first = try await ClientBootstrap(group: MultiThreadedEventLoopGroup.singleton)
            .connect(host: "127.0.0.1", port: port).get()
        #expect(try await TransportTestHarness.eventually {
            await ivy.pendingSessionCountForTesting == 1
        })

        let second = try await ClientBootstrap(group: MultiThreadedEventLoopGroup.singleton)
            .connect(host: "127.0.0.1", port: port).get()
        #expect(try await TransportTestHarness.eventually { !second.isActive })

        let parent = PeerEndpoint(
            publicKey: deterministicTestPeerKey("outbound-reservation-parent"),
            host: "10.1.1.1",
            port: 4001)
        #expect(await ivy.reserveOutgoingDial(to: parent))

        await ivy.finishOutgoingDial(
            to: PeerID(publicKey: parent.publicKey),
            generation: await ivy.runGeneration)
        try? await first.close().get()
        try? await second.close().get()
        await ivy.stop()
    }

    @Test("inbound promotion cannot consume an outbound reservation")
    func inboundPromotionKeepsOutboundReservation() async throws {
        let node = Ivy(config: IvyConfig(
            publicKey: "reserved-promotion-node",
            listenPort: 0,
            stunServers: [],
            healthConfig: PeerHealthConfig(enabled: false),
            maxConnections: 2,
            reservedOutboundConnectionSlots: 1))
        let existing = PeerEndpoint(
            publicKey: deterministicTestPeerKey("reserved-promotion-existing"),
            host: "10.1.0.1",
            port: 4001)
        try await node.seedConnectedEndpointForTesting(existing, marker: 1)
        let candidate = try PeerKey(deterministicTestPeerKey("reserved-promotion-candidate"))
        let connection = self.connection(label: "reserved-promotion")

        #expect(!(await node.canPromoteForTesting(
            connection,
            peerKey: candidate,
            isInbound: true)))
        #expect(await node.canPromoteForTesting(
            connection,
            peerKey: candidate,
            isInbound: false))
        connection.cancel()
        await node.stop()
    }

    @Test("session replacement still obeys the destination netgroup cap")
    func replacementObeysNetgroupCap() async throws {
        let node = Ivy(config: IvyConfig(
            publicKey: "replacement-netgroup-node",
            listenPort: 0,
            stunServers: [],
            healthConfig: PeerHealthConfig(enabled: false),
            maxConnections: 3,
            maxConnectionsPerNetgroup: 1))
        let replacedEndpoint = PeerEndpoint(
            publicKey: deterministicTestPeerKey("replacement-netgroup-peer"),
            host: "10.1.0.1",
            port: 4001)
        let occupyingEndpoint = PeerEndpoint(
            publicKey: deterministicTestPeerKey("replacement-netgroup-occupant"),
            host: "10.2.0.1",
            port: 4002)
        let oldChannel = EmbeddedChannel()
        let occupyingChannel = EmbeddedChannel()
        let replacementChannel = EmbeddedChannel()
        try await oldChannel.connect(to: SocketAddress(ipAddress: "10.1.0.1", port: 4001)).get()
        try await occupyingChannel.connect(to: SocketAddress(ipAddress: "10.2.0.1", port: 4002)).get()
        try await replacementChannel.connect(to: SocketAddress(ipAddress: "10.2.0.2", port: 4003)).get()
        let oldConnection = PeerConnection(endpoint: replacedEndpoint, stream: NIOTransportConnection(channel: oldChannel))
        oldConnection.observedHost = "10.1.0.1"
        let occupyingConnection = PeerConnection(
            endpoint: occupyingEndpoint,
            stream: NIOTransportConnection(channel: occupyingChannel))
        occupyingConnection.observedHost = "10.2.0.1"
        let replacement = PeerConnection(endpoint: replacedEndpoint, stream: NIOTransportConnection(channel: replacementChannel))
        replacement.observedHost = "10.2.0.2"
        try await node.seedConnectedEndpointForTesting(
            replacedEndpoint,
            connection: oldConnection,
            marker: 1)
        try await node.seedConnectedEndpointForTesting(
            occupyingEndpoint,
            connection: occupyingConnection,
            marker: 2)

        #expect(!(await node.canPromoteForTesting(
            replacement,
            peerKey: try PeerKey(replacedEndpoint.publicKey))))

        await node.disconnect(PeerID(publicKey: replacedEndpoint.publicKey))
        await node.disconnect(PeerID(publicKey: occupyingEndpoint.publicKey))
        replacement.cancel()
        _ = try? oldChannel.finish()
        _ = try? occupyingChannel.finish()
        _ = try? replacementChannel.finish()
    }

    @Test("actor admission rejects stale runs")
    func runScopedActorAdmission() async throws {
        let identity = TransportTestHarness.identity("inbound-admission")
        let port = TransportTestHarness.nextPort()
        let ivy = Ivy(config: IvyConfig(
            signingKey: identity,
            listenPort: port,
            stunServers: [],
            healthConfig: PeerHealthConfig(enabled: false),
            maxConnections: 3,
            maxConnectionsPerNetgroup: 1,
            externalAddress: ("127.0.0.1", port)))
        try await ivy.start()
        let generation = await ivy.runGeneration

        let first = connection(label: "current")
        #expect(await ivy.registerInboundConnection(first, generation: generation))

        await ivy.stop()
        try await ivy.start()
        let stale = connection(label: "stale")
        #expect(!(await ivy.registerInboundConnection(stale, generation: generation)))
        #expect(!stale.isLive)
        await ivy.stop()
    }

    @Test("stop and restart serialize with an in-flight start")
    func stopDuringStart() async throws {
        let identity = TransportTestHarness.identity("stop-during-start")
        let port = TransportTestHarness.nextPort()
        let ivy = Ivy(config: IvyConfig(
            signingKey: identity,
            listenPort: port,
            stunServers: [],
            healthConfig: PeerHealthConfig(enabled: false),
            externalAddress: ("127.0.0.1", port)))

        let startBarrier = TestBarrier("lifecycle start")
        let stopQueued = TestBarrier("queued stop")
        let restartQueued = TestBarrier("queued restart")
        await ivy.setLifecycleStartHookForTesting {
            do {
                try await startBarrier.arriveAndWait()
            } catch {
                Issue.record("\(error)")
            }
        }
        await ivy.setLifecycleRequestHookForTesting { request in
            if request == 2 {
                do {
                    try await stopQueued.arriveAndWait()
                } catch {
                    Issue.record("\(error)")
                }
            } else if request == 3 {
                do {
                    try await restartQueued.arriveAndWait()
                } catch {
                    Issue.record("\(error)")
                }
            }
        }

        let starting = Task { try await ivy.start() }
        try await startBarrier.waitForArrivals()
        let stopping = Task { await ivy.stop() }
        try await stopQueued.waitForArrivals()
        let restarting = Task { try await ivy.start() }
        try await restartQueued.waitForArrivals()
        await stopQueued.release()
        await restartQueued.release()
        await startBarrier.release()
        try await starting.value
        await stopping.value
        try await restarting.value

        #expect(await ivy.running)
        #expect(await ivy.serverChannel != nil)
        await ivy.stop()
    }

    @Test("an in-flight dial keeps its capacity reservation across restart")
    func inFlightDialRemainsCountedAcrossRestart() async throws {
        let identity = TransportTestHarness.identity("dial-reservation-node")
        let firstIdentity = TransportTestHarness.identity("dial-reservation-first")
        let secondIdentity = TransportTestHarness.identity("dial-reservation-second")
        let port = TransportTestHarness.nextPort()
        let ivy = Ivy(config: IvyConfig(
            signingKey: identity,
            listenPort: port,
            stunServers: [],
            healthConfig: PeerHealthConfig(enabled: false),
            maxConnections: 1,
            maxConnectionsPerNetgroup: 1,
            externalAddress: ("127.0.0.1", port)))
        let first = TransportTestHarness.endpoint(firstIdentity, port: 4001)
        let second = TransportTestHarness.endpoint(secondIdentity, port: 4002)

        try await ivy.start()
        let generation = await ivy.runGeneration
        #expect(await ivy.reserveOutgoingDial(to: first))
        await ivy.stop()

        try await ivy.start()
        #expect(await ivy.outgoingDialCountForTesting == 1)
        #expect(!(await ivy.reserveOutgoingDial(to: second)))

        await ivy.finishOutgoingDial(
            to: TransportTestHarness.key(firstIdentity).peerID,
            generation: generation)
        #expect(await ivy.outgoingDialCountForTesting == 0)
        await ivy.stop()
    }

    @Test("stale dial success schedules the restarted run's configured reconnect")
    func staleDialSuccessReconnectsCurrentRun() async {
        let endpoint = PeerEndpoint(
            publicKey: deterministicTestPeerKey("stale-success-peer"),
            host: "127.0.0.1",
            port: 4001)
        let peer = PeerID(publicKey: endpoint.publicKey)
        let ivy = Ivy(config: IvyConfig(
            publicKey: "stale-success-node",
            listenPort: 0,
            bootstrapPeers: [endpoint],
            stunServers: [],
            healthConfig: PeerHealthConfig(enabled: false)))

        await ivy.seedOutgoingDialForTesting(
            endpoint: endpoint,
            pendingGeneration: 1,
            currentGeneration: 2)
        let connected = await ivy.finishOutgoingDial(
            to: peer,
            generation: 1)

        #expect(!connected)
        #expect(await ivy.outgoingDialCountForTesting == 0)
        #expect(await ivy.testReconnectToken(peer: peer) != nil)
        await ivy.stop()
    }

    @Test("a concurrent dial is not reported as an identity failure")
    func concurrentDialHasAccurateError() async {
        let endpoint = PeerEndpoint(
            publicKey: deterministicTestPeerKey("concurrent-dial-peer"),
            host: "127.0.0.1",
            port: 4001)
        let peer = PeerID(publicKey: endpoint.publicKey)
        let ivy = Ivy(config: IvyConfig(
            publicKey: "concurrent-dial-node",
            listenPort: 0,
            stunServers: [],
            healthConfig: PeerHealthConfig(enabled: false)))

        await ivy.seedOutgoingDialForTesting(
            endpoint: endpoint,
            pendingGeneration: 2,
            currentGeneration: 2)

        await #expect(throws: IvyError.connectionInProgress) {
            try await ivy.connect(to: endpoint)
        }
        await ivy.finishOutgoingDial(to: peer, generation: 2)
        await ivy.stop()
    }

    @Test("dial success requires a live authenticated session")
    func dialSuccessRequiresCurrentSession() async {
        let endpoint = PeerEndpoint(
            publicKey: deterministicTestPeerKey("closed-success-peer"),
            host: "127.0.0.1",
            port: 4001)
        let peer = PeerID(publicKey: endpoint.publicKey)
        let ivy = Ivy(config: IvyConfig(
            publicKey: "closed-success-node",
            listenPort: 0,
            bootstrapPeers: [endpoint],
            stunServers: [],
            healthConfig: PeerHealthConfig(enabled: false)))

        await ivy.seedOutgoingDialForTesting(
            endpoint: endpoint,
            pendingGeneration: 2,
            currentGeneration: 2)
        let connected = await ivy.finishOutgoingDial(
            to: peer,
            generation: 2)

        #expect(!connected)
        #expect(await ivy.testReconnectToken(peer: peer) != nil)
        await ivy.stop()
    }

    @Test("a competing authenticated session satisfies an outgoing dial")
    func competingSessionSatisfiesOutgoingDial() async throws {
        let endpoint = PeerEndpoint(
            publicKey: deterministicTestPeerKey("cross-dial-winner-peer"),
            host: "127.0.0.1",
            port: 4001)
        let peer = PeerID(publicKey: endpoint.publicKey)
        let ivy = Ivy(config: IvyConfig(
            publicKey: "cross-dial-winner-node",
            listenPort: 0,
            bootstrapPeers: [endpoint],
            stunServers: [],
            healthConfig: PeerHealthConfig(enabled: false)))

        await ivy.seedOutgoingDialForTesting(
            endpoint: endpoint,
            pendingGeneration: 2,
            currentGeneration: 2)
        try await ivy.seedConnectedEndpointForTesting(endpoint, marker: 3)

        let connected = await ivy.finishOutgoingDial(to: peer, generation: 2)

        #expect(connected)
        #expect(await ivy.outgoingDialCountForTesting == 0)
        #expect(await ivy.testReconnectToken(peer: peer) == nil)
        await ivy.stop()
    }

    @Test("a responder awaiting Finish satisfies its losing outgoing dial")
    func pendingCompetingSessionSatisfiesOutgoingDial() async throws {
        let (ivy, _, peer, responder) = try await pendingCrossDial("winner")
        let completion = BoundedTestTask {
            await ivy.resolveOutgoingDialForTesting(to: peer, generation: 2)
        }
        #expect(try await TransportTestHarness.eventually {
            await ivy.peerConnectionHasWaiterForTesting(peer)
        })

        await ivy.promotePendingResponderForTesting(responder)

        #expect(try await completion.value(waitingFor: "competing responder promotion"))
        #expect(await ivy.hasEndpointSession(peer))
        #expect(await ivy.outgoingDialCountForTesting == 0)
        await ivy.stop()
    }

    @Test("any verified responder can satisfy a peer-level cross-dial")
    func alternatePendingResponderSatisfiesOutgoingDial() async throws {
        let (ivy, endpoint, peer, _) = try await pendingCrossDial("alternate")
        let alternate = try await ivy.seedResponderAwaitingFinishForTesting(endpoint, marker: 4)
        let completion = BoundedTestTask {
            await ivy.resolveOutgoingDialForTesting(to: peer, generation: 2)
        }
        #expect(try await TransportTestHarness.eventually {
            await ivy.peerConnectionHasWaiterForTesting(peer)
        })

        await ivy.promotePendingResponderForTesting(alternate)

        #expect(try await completion.value(waitingFor: "alternate responder promotion"))
        #expect(await ivy.hasEndpointSession(peer))
        await ivy.stop()
    }

    @Test("cancelling a cross-dial wait preserves its responder")
    func cancellingPendingResponderWait() async throws {
        let (ivy, _, peer, responder) = try await pendingCrossDial("cancel")
        let completion = BoundedTestTask {
            await ivy.resolveOutgoingDialForTesting(to: peer, generation: 2)
        }
        #expect(try await TransportTestHarness.eventually {
            await ivy.peerConnectionHasWaiterForTesting(peer)
        })

        completion.cancel()

        #expect(!(try await completion.value(waitingFor: "cancelled cross-dial wait")))
        #expect(!(await ivy.peerConnectionHasWaiterForTesting(peer)))
        #expect(await ivy.pendingSessionCountForTesting == 1)
        await ivy.promotePendingResponderForTesting(responder)
        #expect(await ivy.hasEndpointSession(peer))
        await ivy.stop()
    }

    @Test("disconnect cancels a cross-dial wait and its responder")
    func disconnectCancelsPendingResponderWait() async throws {
        let (ivy, _, peer, responder) = try await pendingCrossDial("disconnect")
        let completion = BoundedTestTask {
            await ivy.resolveOutgoingDialForTesting(to: peer, generation: 2)
        }
        #expect(try await TransportTestHarness.eventually {
            await ivy.peerConnectionHasWaiterForTesting(peer)
        })

        await ivy.disconnect(peer)

        #expect(!(try await completion.value(waitingFor: "disconnected cross-dial wait")))
        #expect(await ivy.pendingSessionCountForTesting == 0)
        await ivy.promotePendingResponderForTesting(responder)
        #expect(!(await ivy.hasEndpointSession(peer)))
        await ivy.stop()
    }

    @Test("stop drains a cross-dial wait")
    func stopDrainsPendingResponderWait() async throws {
        let (ivy, _, peer, _) = try await pendingCrossDial("stop")
        let completion = BoundedTestTask {
            await ivy.resolveOutgoingDialForTesting(to: peer, generation: 2)
        }
        #expect(try await TransportTestHarness.eventually {
            await ivy.peerConnectionHasWaiterForTesting(peer)
        })

        await ivy.stop()

        #expect(!(try await completion.value(waitingFor: "stopped cross-dial wait")))
        #expect(!(await ivy.peerConnectionHasWaiterForTesting(peer)))
        #expect(await ivy.pendingSessionCountForTesting == 0)
    }

    @Test("dial success rejects a closed session pending actor cleanup")
    func dialSuccessRequiresLiveSession() async throws {
        let endpoint = PeerEndpoint(
            publicKey: deterministicTestPeerKey("closed-installed-peer"),
            host: "127.0.0.1",
            port: 4001)
        let peer = PeerID(publicKey: endpoint.publicKey)
        let ivy = Ivy(config: IvyConfig(
            publicKey: "closed-installed-node",
            listenPort: 0,
            bootstrapPeers: [endpoint],
            stunServers: [],
            healthConfig: PeerHealthConfig(enabled: false)))
        let connection = PeerConnection(
            endpoint: endpoint,
            routeID: Ivy.directRouteBinding,
            carrier: try PeerKey(endpoint.publicKey))

        try await ivy.seedConnectedEndpointForTesting(
            endpoint,
            connection: connection,
            marker: 3)
        connection.cancel()
        await ivy.seedOutgoingDialForTesting(
            endpoint: endpoint,
            pendingGeneration: 2,
            currentGeneration: 2)
        let connected = await ivy.finishOutgoingDial(
            to: peer,
            generation: 2)

        #expect(!connected)
        #expect(!(await ivy.hasEndpointSession(peer)))
        await ivy.stop()
    }

    @Test("stale reconnect callback cannot remove its successor")
    func reconnectCompletionIsTokenScoped() async throws {
        let identity = TransportTestHarness.identity("reconnect-token")
        let port = TransportTestHarness.nextPort()
        let ivy = Ivy(config: IvyConfig(
            signingKey: identity,
            listenPort: port,
            stunServers: [],
            healthConfig: PeerHealthConfig(enabled: false),
            externalAddress: ("127.0.0.1", port)))
        let endpoint = PeerEndpoint(
            publicKey: deterministicTestPeerKey("reconnect-token-peer"),
            host: "127.0.0.1",
            port: TransportTestHarness.nextPort())
        let peer = PeerID(publicKey: endpoint.publicKey)

        try await ivy.start()
        let generation = await ivy.runGeneration
        await ivy.installTestReconnect(peer: peer, generation: generation, token: 2)
        await ivy.runScheduledReconnect(
            peer: peer,
            role: .endpoint,
            generation: generation,
            token: 1)

        #expect(await ivy.testReconnectToken(peer: peer) == 2)
        await ivy.stop()
    }

    @Test("a failed reserved dial rearms a reconnect consumed by that reservation")
    func reservedDialFailureRearmsReconnect() async {
        let endpoint = PeerEndpoint(
            publicKey: deterministicTestPeerKey("reserved-reconnect-peer"),
            host: "127.0.0.1",
            port: 4001)
        let peer = PeerID(publicKey: endpoint.publicKey)
        let ivy = Ivy(config: IvyConfig(
            publicKey: "reserved-reconnect-node",
            listenPort: 0,
            bootstrapPeers: [endpoint],
            stunServers: [],
            healthConfig: PeerHealthConfig(enabled: false)))

        await ivy.seedOutgoingDialForTesting(
            endpoint: endpoint,
            pendingGeneration: 2,
            currentGeneration: 2)
        await ivy.installTestReconnect(peer: peer, generation: 2, token: 1)
        await ivy.runScheduledReconnect(
            peer: peer,
            role: .endpoint,
            generation: 2,
            token: 1)
        #expect(await ivy.testReconnectToken(peer: peer) == nil)

        await ivy.finishOutgoingDial(to: peer, generation: 2)

        #expect(await ivy.testReconnectToken(peer: peer) != nil)
        await ivy.stop()
    }

    @Test("inbound handshakes and outbound reservations share one netgroup cap")
    func mixedDirectionNetgroupAdmission() async throws {
        let identity = TransportTestHarness.identity("mixed-netgroup-node")
        let port = TransportTestHarness.nextPort()
        let ivy = Ivy(config: IvyConfig(
            signingKey: identity,
            listenPort: port,
            stunServers: [],
            healthConfig: PeerHealthConfig(enabled: false),
            maxConnections: 4,
            maxConnectionsPerNetgroup: 1,
            externalAddress: ("127.0.0.1", port)))
        try await ivy.start()
        let generation = await ivy.runGeneration
        let first = PeerEndpoint(
            publicKey: deterministicTestPeerKey("mixed-netgroup-first"),
            host: "127.0.0.2",
            port: 4001)
        #expect(await ivy.reserveOutgoingDial(to: first))

        let rejected = try await ClientBootstrap(group: MultiThreadedEventLoopGroup.singleton)
            .connect(host: "127.0.0.1", port: Int(port)).get()
        #expect(try await TransportTestHarness.eventually { !rejected.isActive })

        await ivy.finishOutgoingDial(
            to: PeerID(publicKey: first.publicKey),
            generation: generation)
        let admitted = try await ClientBootstrap(group: MultiThreadedEventLoopGroup.singleton)
            .connect(host: "127.0.0.1", port: Int(port)).get()
        #expect(try await TransportTestHarness.eventually {
            await ivy.pendingSessionCountForTesting == 1
        })
        let second = PeerEndpoint(
            publicKey: deterministicTestPeerKey("mixed-netgroup-second"),
            host: "127.0.0.3",
            port: 4002)
        #expect(!(await ivy.reserveOutgoingDial(to: second)))
        try? await admitted.close().get()
        await ivy.stop()
    }

    @Test("a cross-dial reservation remains physical capacity after its peer authenticates")
    func crossDialCountsBothTransports() async throws {
        let sourceIdentity = TransportTestHarness.identity("cross-dial-capacity-node")
        let peerIdentity = TransportTestHarness.identity("cross-dial-capacity-first")
        let sourcePort = TransportTestHarness.nextPort()
        let peerPort = TransportTestHarness.nextPort()
        let ivy = Ivy(config: IvyConfig(
            signingKey: sourceIdentity,
            listenPort: sourcePort,
            stunServers: [],
            healthConfig: PeerHealthConfig(enabled: false),
            maxConnections: 2,
            maxConnectionsPerNetgroup: 4,
            externalAddress: ("127.0.0.1", sourcePort)))
        let peer = Ivy(config: TransportTestHarness.config(peerIdentity, port: peerPort))
        try await peer.start()
        try await ivy.start()
        let generation = await ivy.runGeneration
        let first = TransportTestHarness.endpoint(peerIdentity, port: peerPort)
        #expect(await ivy.reserveOutgoingDial(to: first))
        try await peer.connect(to: TransportTestHarness.endpoint(
            sourceIdentity,
            port: sourcePort))
        let peerID = TransportTestHarness.key(peerIdentity).peerID
        #expect(try await TransportTestHarness.eventually {
            await ivy.hasEndpointSession(peerID)
        })

        let excess = PeerEndpoint(
            publicKey: deterministicTestPeerKey("cross-dial-capacity-excess"),
            host: "10.9.1.1",
            port: 4002)
        #expect(!(await ivy.reserveOutgoingDial(to: excess)))
        await ivy.finishOutgoingDial(
            to: peerID,
            generation: generation)
        await ivy.stop()
        await peer.stop()
    }

    @Test("DNS aliases cannot evade the observed netgroup cap")
    func observedAddressRebindsNetgroupReservation() async throws {
        let firstListener = try await TestLoopback.open()
        let secondListener = try await TestLoopback.open()
        let identity = TransportTestHarness.identity("observed-netgroup-node")
        let firstIdentity = TransportTestHarness.identity("observed-netgroup-first")
        let secondIdentity = TransportTestHarness.identity("observed-netgroup-second")
        let node = Ivy(config: IvyConfig(
            signingKey: identity,
            listenPort: 0,
            stunServers: [],
            healthConfig: PeerHealthConfig(enabled: false),
            maxConnections: 4,
            maxConnectionsPerNetgroup: 1))
        let first = PeerEndpoint(
            publicKey: TransportTestHarness.key(firstIdentity).hex,
            host: "first.example",
            port: firstListener.port)
        let second = PeerEndpoint(
            publicKey: TransportTestHarness.key(secondIdentity).hex,
            host: "second.example",
            port: secondListener.port)

        await node.setDialEndpointRewriteForTesting { endpoint in
            PeerEndpoint(
                publicKey: endpoint.publicKey,
                host: "127.0.0.1",
                port: endpoint.port)
        }
        try await node.start()
        let firstConnect = Task { try? await node.connect(to: first) }
        #expect(try await TransportTestHarness.eventually {
            await node.pendingSessionCountForTesting == 1
        })

        let secondConnect = BoundedTestTask {
            do {
                try await node.connect(to: second)
                return true
            } catch {
                return false
            }
        }
        #expect(try await !secondConnect.value(waitingFor: "aliased netgroup rejection"))
        #expect(await node.pendingSessionCountForTesting == 1)
        #expect(await node.outgoingDialCountForTesting == 1)

        firstConnect.cancel()
        _ = await firstConnect.result
        await node.stop()
        await firstListener.close()
        await secondListener.close()
    }

    @Test("manual disconnect fences an already-started configured dial")
    func disconnectSuppressesInFlightReconnect() async {
        let endpoint = PeerEndpoint(
            publicKey: deterministicTestPeerKey("disconnect-inflight-peer"),
            host: "127.0.0.1",
            port: 4001)
        let peer = PeerID(publicKey: endpoint.publicKey)
        let ivy = Ivy(config: IvyConfig(
            publicKey: "disconnect-inflight-node",
            listenPort: 0,
            bootstrapPeers: [endpoint],
            stunServers: [],
            healthConfig: PeerHealthConfig(enabled: false)))
        await ivy.seedOutgoingDialForTesting(
            endpoint: endpoint,
            pendingGeneration: 2,
            currentGeneration: 2)

        await ivy.disconnect(peer)
        await ivy.finishOutgoingDial(to: peer, generation: 2)

        #expect(await ivy.outgoingDialCountForTesting == 0)
        #expect(await ivy.testReconnectToken(peer: peer) == nil)
        await ivy.stop()
    }

    private func pendingCrossDial(
        _ label: String
    ) async throws -> (Ivy, PeerEndpoint, PeerID, UUID) {
        let endpoint = PeerEndpoint(
            publicKey: deterministicTestPeerKey("pending-cross-dial-\(label)-peer"),
            host: "127.0.0.1",
            port: 4001)
        let peer = PeerID(publicKey: endpoint.publicKey)
        let ivy = Ivy(config: IvyConfig(
            publicKey: "pending-cross-dial-\(label)-node",
            listenPort: 0,
            bootstrapPeers: [endpoint],
            stunServers: [],
            healthConfig: PeerHealthConfig(enabled: false)))
        await ivy.seedOutgoingDialForTesting(
            endpoint: endpoint,
            pendingGeneration: 2,
            currentGeneration: 2)
        let responder = try await ivy.seedResponderAwaitingFinishForTesting(endpoint, marker: 3)
        return (ivy, endpoint, peer, responder)
    }

    private func connection(label: String) -> PeerConnection {
        PeerConnection(
            endpoint: PeerEndpoint(publicKey: "", host: "relay", port: 0),
            routeID: Data(label.utf8) + Data(repeating: 0, count: 32 - label.utf8.count),
            carrier: try! PeerKey(rawRepresentation: Data(repeating: 7, count: 32)))
    }

}

private extension Ivy {
    func installTestReconnect(peer: PeerID, generation: UInt64, token: UInt64) {
        reconnectTasks[peer] = PendingReconnect(
            generation: generation,
            token: token,
            task: MultiThreadedEventLoopGroup.singleton.next().scheduleTask(in: .seconds(60)) {})
    }

    func testReconnectToken(peer: PeerID) -> UInt64? {
        reconnectTasks[peer]?.token
    }
}
