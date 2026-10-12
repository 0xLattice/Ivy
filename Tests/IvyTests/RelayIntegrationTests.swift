import Foundation
import NIOCore
import NIOEmbedded
import NIOPosix
import Testing
@testable import Ivy

private struct RelayVolumeSource: IvyContentSource {
    let entries: [ContentEntry]

    func content(rootCID: String, cids: [String], maxDataBytes: Int) -> [ContentEntry] {
        []
    }

    func volume(rootCID: String, maxDataBytes: Int) -> [ContentEntry] {
        entries
    }
}

@Suite("Configured carrier relay", .serialized)
struct RelayIntegrationTests {
    @Test("relayed outbound frame is capped by the carrier's advertised limit")
    func relayedFrameCappedByCarrier() async throws {
        let carrierIdentity = TransportTestHarness.identity("relay-cap-carrier")
        let endpointIdentity = TransportTestHarness.identity("relay-cap-endpoint")
        let carrierKey = TransportTestHarness.key(carrierIdentity)
        let carrierEndpoint = TransportTestHarness.endpoint(carrierIdentity, port: 4001)
        let endpointEndpoint = TransportTestHarness.endpoint(endpointIdentity, port: 4002)

        let node = Ivy(config: TransportTestHarness.config(
            TransportTestHarness.identity("relay-cap-node"),
            port: TransportTestHarness.nextPort()))

        // The carrier authenticates in the .carrier role with a 4 MiB accept limit.
        let carrierChannel = EmbeddedChannel()
        try await carrierChannel.connect(
            to: SocketAddress(ipAddress: "127.0.0.1", port: 4001)).get()
        let carrierConnection = PeerConnection(endpoint: carrierEndpoint, stream: NIOTransportConnection(channel: carrierChannel))
        carrierConnection.peerMaxFrameSize = 4 * 1024 * 1024
        try await node.seedConnectedEndpointForTesting(
            carrierEndpoint,
            connection: carrierConnection,
            role: .carrier,
            marker: 1)

        // An endpoint reached over a relay through that carrier advertises 8 MiB.
        let relayed = PeerConnection(
            endpoint: endpointEndpoint,
            routeID: Data(repeating: 2, count: 32),
            carrier: carrierKey)
        relayed.peerMaxFrameSize = 8 * 1024 * 1024

        // Must cap at the carrier's 4 MiB — a .carrier-role session is invisible
        // to endpoint-role lookups, so before the fix this returned the full 8 MiB.
        let effective = await node.effectiveOutboundFrameSize(for: relayed)
        #expect(effective == 4 * 1024 * 1024)
    }

    @Test("unconfigured overlay peers cannot inject unrelated relay state")
    func unrelatedRelayControlIsRejected() async throws {
        let senderIdentity = TransportTestHarness.identity("relay-unrelated-sender")
        let targetIdentity = TransportTestHarness.identity("relay-unrelated-target")
        let sender = Ivy(config: TransportTestHarness.config(
            senderIdentity,
            port: TransportTestHarness.nextPort()))
        let targetPort = TransportTestHarness.nextPort()
        let target = Ivy(config: TransportTestHarness.config(
            targetIdentity,
            port: targetPort))
        let targetRecorder = TransportTestRecorder()
        await target.setTestDelegate(targetRecorder)

        try await sender.start()
        try await target.start()
        try await sender.connect(to: TransportTestHarness.endpoint(targetIdentity, port: targetPort))
        let senderID = TransportTestHarness.key(senderIdentity).peerID
        try await targetRecorder.waitForConnect(senderID)

        #expect(await sender.sendAuthenticatedMessageForTesting(
            .relayReady(routeID: Data(repeating: 1, count: 32), status: 0),
            to: TransportTestHarness.key(targetIdentity).peerID))
        try await targetRecorder.waitForDisconnect(senderID)
        #expect(await target.peerConnectionCount == 0)

        await sender.stop()
        await target.stop()
    }

    @Test("inbound offers from one authenticated carrier remain bounded")
    func inboundOfferCap() async throws {
        let targetIdentity = TransportTestHarness.identity("relay-offer-cap-target")
        let carrierIdentity = TransportTestHarness.identity("relay-offer-cap-carrier")
        let sourceIdentity = TransportTestHarness.identity("relay-offer-cap-source")
        let target = Ivy(config: TransportTestHarness.config(
            targetIdentity,
            port: TransportTestHarness.nextPort()))
        let carrierEndpoint = TransportTestHarness.endpoint(carrierIdentity, port: 4001)
        let carrierKey = TransportTestHarness.key(carrierIdentity)
        let channel = EmbeddedChannel()
        try await channel.connect(to: SocketAddress(ipAddress: "127.0.0.1", port: 4001)).get()
        let connection = PeerConnection(endpoint: carrierEndpoint, stream: NIOTransportConnection(channel: channel))
        try await target.seedConnectedEndpointForTesting(
            carrierEndpoint,
            connection: connection,
            marker: 1)

        await target.handleRelayControlForTesting(
            .relayOffer(
                routeID: Ivy.directRouteBinding,
                sourceKey: TransportTestHarness.key(sourceIdentity)),
            from: carrierKey)
        await target.handleRelayControlForTesting(
            .relayOffer(
                routeID: Data(repeating: 0xff, count: 32),
                sourceKey: carrierKey),
            from: carrierKey)
        #expect(await target.installedRouteCountForTesting == 0)

        for marker in 1...(Ivy.maxRelayRoutesPerPeer + 1) {
            await target.handleRelayControlForTesting(
                .relayOffer(
                    routeID: Data(repeating: UInt8(marker), count: 32),
                    sourceKey: TransportTestHarness.key(sourceIdentity)),
                from: carrierKey)
        }

        #expect(await target.installedRouteCountForTesting == Ivy.maxRelayRoutesPerPeer)
        await target.disconnect(carrierKey.peerID)
        _ = try? channel.finish()
    }

    @Test("an old relay timer cannot expire a reused route ID")
    func routeExpiryIsLifecycleScoped() async throws {
        let carrierIdentity = TransportTestHarness.identity("relay-reuse-carrier")
        let sourceIdentity = TransportTestHarness.identity("relay-reuse-source")
        let carrierEndpoint = TransportTestHarness.endpoint(carrierIdentity, port: 4001)
        let carrierKey = TransportTestHarness.key(carrierIdentity)
        let target = Ivy(config: IvyConfig(
            publicKey: "relay-reuse-target",
            listenPort: 0,
            relayTimeout: .seconds(60),
            stunServers: [],
            healthConfig: PeerHealthConfig(enabled: false)))
        let channel = EmbeddedChannel()
        try await channel.connect(to: SocketAddress(ipAddress: "127.0.0.1", port: 4001)).get()
        let connection = PeerConnection(endpoint: carrierEndpoint, stream: NIOTransportConnection(channel: channel))
        try await target.seedConnectedEndpointForTesting(
            carrierEndpoint,
            connection: connection,
            marker: 1)
        let routeID = Data(repeating: 9, count: 32)
        let offer = Message.relayOffer(
            routeID: routeID,
            sourceKey: TransportTestHarness.key(sourceIdentity))

        await target.handleRelayControlForTesting(offer, from: carrierKey)
        let oldLifecycle = try #require(
            await target.installedRouteLifecycleForTesting(routeID))
        await target.handleRelayControlForTesting(.relayClose(routeID: routeID), from: carrierKey)
        await target.handleRelayControlForTesting(offer, from: carrierKey)
        let replacementLifecycle = try #require(
            await target.installedRouteLifecycleForTesting(routeID))
        #expect(replacementLifecycle != oldLifecycle)

        await target.expireInstalledRouteForTesting(
            routeID,
            carrier: carrierKey,
            lifecycleID: oldLifecycle)
        #expect(await target.installedRouteCountForTesting == 1)

        await target.disconnect(carrierKey.peerID)
        _ = try? channel.finish()
    }

    @Test("duplicate cleanup preserves the winning relayed transport")
    func duplicateCleanupPreservesReplacementRoute() async {
        let node = Ivy(config: IvyConfig(
            publicKey: "relay-duplicate-cleanup",
            listenPort: 0,
            stunServers: [],
            healthConfig: PeerHealthConfig(enabled: false)))
        let carrier = TransportTestHarness.key(
            TransportTestHarness.identity("relay-duplicate-carrier"))
        let remote = TransportTestHarness.key(
            TransportTestHarness.identity("relay-duplicate-remote"))
        let routeID = Data(repeating: 0x5a, count: 32)
        let connection = PeerConnection(
            endpoint: PeerEndpoint(publicKey: remote.hex, host: "relay", port: 0),
            routeID: routeID,
            carrier: carrier)
        await node.bindInstalledRouteForTesting(
            routeID: routeID,
            carrier: carrier,
            remote: remote,
            connection: connection)

        await node.cleanupRoutesForReplacementForTesting(
            peer: remote,
            preserving: connection)
        #expect(await node.hasInstalledRouteForTesting(routeID))
        #expect(connection.isLive)

        await node.cleanupRoutesForReplacementForTesting(peer: remote, preserving: nil)
        #expect(!(await node.hasInstalledRouteForTesting(routeID)))
        #expect(!connection.isLive)
    }

    @Test("a stalled relay destination expires and closes its route")
    func stalledRelayDestinationExpires() async throws {
        let sourceIdentity = TransportTestHarness.identity("relay-stall-source")
        let targetIdentity = TransportTestHarness.identity("relay-stall-target")
        let carrierIdentity = TransportTestHarness.identity("relay-stall-carrier")
        let carrierPort = TransportTestHarness.nextPort()
        let sourcePort = TransportTestHarness.nextPort()
        let targetPort = TransportTestHarness.nextPort()
        let carrierEndpoint = TransportTestHarness.endpoint(
            carrierIdentity,
            port: carrierPort
        )
        let targetID = TransportTestHarness.key(targetIdentity).peerID
        let carrier = Ivy(config: TransportTestHarness.config(
            carrierIdentity,
            port: carrierPort,
            relayEnabled: true,
            requestTimeout: .milliseconds(30),
        ))
        let source = Ivy(config: TransportTestHarness.config(
            sourceIdentity,
            port: sourcePort,
            carriers: [carrierEndpoint],
            mode: .pinned(peer: targetID.publicKey)
        ))
        let target = Ivy(config: TransportTestHarness.config(
            targetIdentity,
            port: targetPort
        ))

        try await carrier.start()
        try await target.start()
        try await source.start()
        try await target.connect(to: carrierEndpoint)
        #expect(try await TransportTestHarness.eventually {
            await carrier.peerConnectionCount == 2
        })
        try await source.connectViaRelay(to: PeerEndpoint(
            publicKey: targetID.publicKey,
            host: "relay",
            port: 0
        ))
        await carrier.setEndpointWritabilityForTesting(targetID, writable: false)

        let result = await source.sendMessage(
            to: targetID,
            topic: "relay.stall",
            payload: Data([0xaa])
        )
        guard case .enqueued = result else {
            Issue.record("expected the relay packet to enqueue")
            await source.stop()
            await target.stop()
            await carrier.stop()
            return
        }
        #expect(try await TransportTestHarness.eventually {
            await carrier.relayRouteCountForTesting == 0
        })

        await carrier.setEndpointWritabilityForTesting(targetID, writable: true)
        await source.stop()
        await target.stop()
        await carrier.stop()
    }

    @Test("a relay reply from the wrong carrier cannot consume pending state")
    func relayReadyIsCarrierScoped() async throws {
        let node = Ivy(config: IvyConfig(
            publicKey: "relay-ready-scope",
            listenPort: 0,
            stunServers: [],
            healthConfig: PeerHealthConfig(enabled: false)))
        let expected = TransportTestHarness.key(
            TransportTestHarness.identity("relay-ready-expected"))
        let wrong = TransportTestHarness.key(
            TransportTestHarness.identity("relay-ready-wrong"))
        let target = TransportTestHarness.key(
            TransportTestHarness.identity("relay-ready-target"))
        let routeID = Data(repeating: 0x44, count: 32)
        let waiting = BoundedTestTask {
            await node.awaitRelayOpenForTesting(
                routeID: routeID,
                carrier: expected,
                target: target)
        }
        #expect(try await TransportTestHarness.eventually {
            await node.pendingRelayOpenCountForTesting == 1
        })

        await node.handleRelayControlForTesting(
            .relayReady(routeID: routeID, status: 0),
            from: wrong)
        #expect(await node.pendingRelayOpenCountForTesting == 1)

        await node.handleRelayControlForTesting(
            .relayReady(routeID: routeID, status: 1),
            from: expected)
        #expect(try await waiting.value(waitingFor: "carrier-scoped relay reply") == nil)
        #expect(await node.pendingRelayOpenCountForTesting == 0)
    }

    @Test("manual disconnect cannot advance to another carrier")
    func disconnectStopsCarrierFailover() async throws {
        let firstIdentity = TransportTestHarness.identity("relay-stop-first")
        let secondIdentity = TransportTestHarness.identity("relay-stop-second")
        let targetIdentity = TransportTestHarness.identity("relay-stop-target")
        let firstLoopback = try await TestLoopback.open()
        let secondLoopback = try await TestLoopback.open()
        let loopbacks = [firstLoopback, secondLoopback]
        let endpoints = [
            TransportTestHarness.endpoint(
                firstIdentity,
                port: firstLoopback.port),
            TransportTestHarness.endpoint(
                secondIdentity,
                port: secondLoopback.port),
        ]
        let node = Ivy(config: IvyConfig(
            publicKey: "relay-stop-node",
            listenPort: 0,
            stunServers: [],
            healthConfig: PeerHealthConfig(enabled: false),
            carriers: endpoints))
        for (index, endpoint) in endpoints.enumerated() {
            try await node.seedConnectedEndpointForTesting(
                endpoint,
                connection: PeerConnection(endpoint: endpoint, stream: NIOTransportConnection(channel: loopbacks[index].client)),
                role: .carrier,
                marker: UInt8(index + 1))
        }
        let target = TransportTestHarness.key(targetIdentity).peerID
        let connecting = Task {
            try? await node.connectViaRelay(to: PeerEndpoint(
                publicKey: target.publicKey,
                host: "relay",
                port: 0))
        }
        #expect(try await TransportTestHarness.eventually {
            await node.pendingRelayOpenCountForTesting == 1
        })

        await node.disconnect(target)
        _ = await connecting.value

        let ordered = zip(endpoints, loopbacks).sorted {
            (try! PeerKey($0.0.publicKey)) < (try! PeerKey($1.0.publicKey))
        }
        #expect(try await TransportTestHarness.eventually {
            ordered[0].1.sink.byteCount > 0
        })
        #expect(ordered[1].1.sink.byteCount == 0)
        #expect(await node.pendingRelayOpenCountForTesting == 0)
        for loopback in loopbacks { await loopback.close() }
    }

    @Test("task cancellation retires a pending relay open")
    func cancellationRetiresRelayOpen() async throws {
        let carrierIdentity = TransportTestHarness.identity("relay-cancel-carrier")
        let targetIdentity = TransportTestHarness.identity("relay-cancel-target")
        let loopback = try await TestLoopback.open()
        let endpoint = TransportTestHarness.endpoint(
            carrierIdentity,
            port: loopback.port)
        let node = Ivy(config: IvyConfig(
            publicKey: "relay-cancel-node",
            listenPort: 0,
            stunServers: [],
            healthConfig: PeerHealthConfig(enabled: false),
            carriers: [endpoint]))
        try await node.seedConnectedEndpointForTesting(
            endpoint,
            connection: PeerConnection(endpoint: endpoint, stream: NIOTransportConnection(channel: loopback.client)),
            role: .carrier,
            marker: 1)
        let connecting = Task {
            try? await node.connectViaRelay(to: PeerEndpoint(
                publicKey: TransportTestHarness.key(targetIdentity).hex,
                host: "relay",
                port: 0))
        }
        #expect(try await TransportTestHarness.eventually {
            await node.pendingRelayOpenCountForTesting == 1
        })

        connecting.cancel()
        let completion = BoundedTestTask {
            _ = await connecting.value
            return true
        }
        #expect(try await completion.value(waitingFor: "cancelled relay open"))
        #expect(await node.pendingRelayOpenCountForTesting == 0)
        #expect(try await TransportTestHarness.eventually {
            loopback.sink.hasRelayClose
        })

        await node.disconnect(TransportTestHarness.key(carrierIdentity).peerID)
        await loopback.close()
    }

    @Test("relay close wins if it arrives before the ready continuation resumes")
    func relayCloseWinsReadyResumeRace() async throws {
        let node = Ivy(config: IvyConfig(
            publicKey: "relay-ready-close-race",
            listenPort: 0,
            stunServers: [],
            healthConfig: PeerHealthConfig(enabled: false)))
        let carrier = TransportTestHarness.key(
            TransportTestHarness.identity("relay-ready-close-carrier"))
        let target = TransportTestHarness.key(
            TransportTestHarness.identity("relay-ready-close-target"))
        let routeID = Data(repeating: 0x45, count: 32)
        let waiting = BoundedTestTask {
            await node.awaitRelayOpenForTesting(
                routeID: routeID,
                carrier: carrier,
                target: target)
        }
        #expect(try await TransportTestHarness.eventually {
            await node.pendingRelayOpenCountForTesting == 1
        })

        await node.handleRelayControlForTesting(
            .relayReady(routeID: routeID, status: 0),
            from: carrier)
        #expect(try await waiting.value(waitingFor: "successful relay ready") == routeID)
        await node.handleRelayControlForTesting(
            .relayClose(routeID: routeID),
            from: carrier)

        let opened = await node.openInstalledRouteConnectionForTesting(
            endpoint: PeerEndpoint(publicKey: target.hex, host: "relay", port: 0),
            target: target,
            routeID: routeID,
            carrier: carrier)
        #expect(!opened)
        #expect(await node.routeConnectionCountForTesting == 0)
    }

    @Test("late route frames are idempotent after route retirement")
    func lateRouteFramesAreNoOps() async throws {
        let carrierIdentity = TransportTestHarness.identity("relay-late-carrier")
        let endpointIdentity = TransportTestHarness.identity("relay-late-endpoint")
        let carrierPort = TransportTestHarness.nextPort()
        let carrier = Ivy(config: TransportTestHarness.config(
            carrierIdentity,
            port: carrierPort,
            relayEnabled: true,
            requestTimeout: .seconds(5)))
        let endpoint = Ivy(config: TransportTestHarness.config(
            endpointIdentity,
            port: TransportTestHarness.nextPort()))
        let endpointID = TransportTestHarness.key(endpointIdentity).peerID
        let carrierID = TransportTestHarness.key(carrierIdentity).peerID
        let retiredRoute = Data(repeating: 0x71, count: 32)
        let recorder = TransportTestRecorder()
        await carrier.setTestDelegate(recorder)

        try await carrier.start()
        try await endpoint.start()
        try await endpoint.connect(to: TransportTestHarness.endpoint(
            carrierIdentity,
            port: carrierPort))
        #expect(try await TransportTestHarness.eventually {
            await carrier.hasEndpointSession(endpointID)
        })

        #expect(await endpoint.sendAuthenticatedMessageForTesting(
            .relayAccept(routeID: retiredRoute, status: 0),
            to: carrierID))
        #expect(await endpoint.sendAuthenticatedMessageForTesting(
            .relayPacket(routeID: retiredRoute, opaqueEndpointRecord: Data([1])),
            to: carrierID))
        #expect(await endpoint.sendAuthenticatedMessageForTesting(
            .peerMessage(topic: "after-late-route", payload: Data()),
            to: carrierID))
        #expect(try await TransportTestHarness.eventually {
            recorder.receivedMessage(
                topic: "after-late-route",
                payload: Data(),
                from: endpointID)
        })
        #expect(await carrier.hasEndpointSession(endpointID))

        #expect(await endpoint.sendAuthenticatedMessageForTesting(
            .relayPacket(routeID: Ivy.directRouteBinding, opaqueEndpointRecord: Data([1])),
            to: carrierID))
        try await recorder.waitForDisconnect(endpointID)

        await endpoint.stop()
        await carrier.stop()
    }

    @Test("configured carrier cannot accept in the wrong route direction")
    func configuredCarrierCannotBypassRouteOwnership() async throws {
        let nodeIdentity = TransportTestHarness.identity("relay-owner-node")
        let carrierIdentity = TransportTestHarness.identity("relay-owner-carrier")
        let nodePort = TransportTestHarness.nextPort()
        let carrierPort = TransportTestHarness.nextPort()
        let carrierEndpoint = TransportTestHarness.endpoint(
            carrierIdentity,
            port: carrierPort)
        let node = Ivy(config: TransportTestHarness.config(
            nodeIdentity,
            port: nodePort,
            carriers: [carrierEndpoint],
            relayEnabled: true))
        let carrier = Ivy(config: TransportTestHarness.config(
            carrierIdentity,
            port: carrierPort))
        let carrierKey = TransportTestHarness.key(carrierIdentity)
        let target = TransportTestHarness.key(
            TransportTestHarness.identity("relay-owner-target"))
        let recorder = TransportTestRecorder()
        let routeID = Data(repeating: 0x72, count: 32)
        await node.setTestDelegate(recorder)

        try await carrier.start()
        try await node.start()
        try await recorder.waitForConnect(carrierKey.peerID)
        await node.bindRelayRouteForTesting(
            routeID: routeID,
            source: carrierKey,
            target: target)

        #expect(await carrier.sendAuthenticatedMessageForTesting(
            .relayAccept(routeID: routeID, status: 0),
            to: TransportTestHarness.key(nodeIdentity).peerID))
        try await recorder.waitForDisconnect(carrierKey.peerID)

        await node.stop()
        await carrier.stop()
    }

    @Test("pending relay opens reserve route capacity")
    func pendingRelayOpenReservesCapacity() async throws {
        let carrierIdentity = TransportTestHarness.identity("relay-reserved-carrier")
        let carrier = TransportTestHarness.key(carrierIdentity)
        let source = TransportTestHarness.key(
            TransportTestHarness.identity("relay-reserved-source"))
        let loopback = try await TestLoopback.open()
        let carrierEndpoint = TransportTestHarness.endpoint(
            carrierIdentity,
            port: loopback.port)
        let node = Ivy(config: IvyConfig(
            publicKey: "relay-reserved-node",
            listenPort: 0,
            stunServers: [],
            healthConfig: PeerHealthConfig(enabled: false),
            carriers: [carrierEndpoint]))
        try await node.seedConnectedEndpointForTesting(
            carrierEndpoint,
            connection: PeerConnection(endpoint: carrierEndpoint, stream: NIOTransportConnection(channel: loopback.client)),
            role: .carrier,
            marker: 1)
        for marker in 1..<Ivy.maxRelayRoutes {
            let fillerCarrier = TransportTestHarness.key(
                TransportTestHarness.identity("relay-global-filler-\((marker - 1) / 7)"))
            await node.bindInstalledRouteForTesting(
                routeID: Data(repeating: UInt8(marker), count: 32),
                carrier: fillerCarrier,
                remote: source)
        }
        let pendingRoute = Data(repeating: 0xfe, count: 32)
        let pending = BoundedTestTask {
            await node.awaitRelayOpenForTesting(
                routeID: pendingRoute,
                carrier: carrier,
                target: source)
        }
        #expect(try await TransportTestHarness.eventually {
            await node.pendingRelayOpenCountForTesting == 1
        })

        await node.handleRelayControlForTesting(
            .relayOffer(routeID: Data(repeating: 0xfd, count: 32), sourceKey: source),
            from: carrier)
        #expect(await node.installedRouteCountForTesting == Ivy.maxRelayRoutes - 1)

        await node.bindInstalledRouteForTesting(
            routeID: Data(repeating: 0xfc, count: 32),
            carrier: TransportTestHarness.key(
                TransportTestHarness.identity("relay-global-final-filler")),
            remote: source)
        await node.handleRelayControlForTesting(
            .relayReady(routeID: pendingRoute, status: 0),
            from: carrier)
        #expect(try await pending.value(waitingFor: "capacity-rejected relay ready") == nil)
        #expect(try await TransportTestHarness.eventually { loopback.sink.hasRelayClose })

        await node.disconnect(carrier.peerID)
        await loopback.close()
    }

    @Test("pending relay opens reserve per-carrier capacity")
    func pendingRelayOpenReservesCarrierCapacity() async throws {
        let node = Ivy(config: IvyConfig(publicKey: "relay-carrier-reserved", listenPort: 0))
        let carrier = TransportTestHarness.key(
            TransportTestHarness.identity("relay-carrier-reserved-carrier"))
        let source = TransportTestHarness.key(
            TransportTestHarness.identity("relay-carrier-reserved-source"))
        for marker in 1..<Ivy.maxRelayRoutesPerPeer {
            await node.bindInstalledRouteForTesting(
                routeID: Data(repeating: UInt8(marker), count: 32),
                carrier: carrier,
                remote: source)
        }
        let pendingRoute = Data(repeating: 0x81, count: 32)
        let pending = BoundedTestTask {
            await node.awaitRelayOpenForTesting(
                routeID: pendingRoute,
                carrier: carrier,
                target: source)
        }
        #expect(try await TransportTestHarness.eventually {
            await node.pendingRelayOpenCountForTesting == 1
        })

        await node.handleRelayControlForTesting(
            .relayOffer(routeID: Data(repeating: 0x82, count: 32), sourceKey: source),
            from: carrier)
        #expect(await node.installedRouteCountForTesting == Ivy.maxRelayRoutesPerPeer - 1)
        await node.handleRelayControlForTesting(
            .relayReady(routeID: pendingRoute, status: 1),
            from: carrier)
        #expect(try await pending.value(waitingFor: "rejected reserved carrier route") == nil)
    }

    @Test("carrier retry rechecks global route capacity")
    func carrierRetryRechecksGlobalCapacity() async throws {
        let firstIdentity = TransportTestHarness.identity("relay-recheck-first")
        let secondIdentity = TransportTestHarness.identity("relay-recheck-second")
        let target = TransportTestHarness.key(
            TransportTestHarness.identity("relay-recheck-target"))
        let firstLoopback = try await TestLoopback.open()
        let secondLoopback = try await TestLoopback.open()
        let endpoints = [
            TransportTestHarness.endpoint(firstIdentity, port: firstLoopback.port),
            TransportTestHarness.endpoint(secondIdentity, port: secondLoopback.port),
        ]
        let loopbacks = [firstLoopback, secondLoopback]
        let node = Ivy(config: IvyConfig(
            publicKey: "relay-capacity-recheck",
            listenPort: 0,
            stunServers: [],
            healthConfig: PeerHealthConfig(enabled: false),
            carriers: endpoints))
        for (index, endpoint) in endpoints.enumerated() {
            try await node.seedConnectedEndpointForTesting(
                endpoint,
                connection: PeerConnection(endpoint: endpoint, stream: NIOTransportConnection(channel: loopbacks[index].client)),
                role: .carrier,
                marker: UInt8(index + 1))
        }
        for marker in 1..<Ivy.maxRelayRoutes {
            await node.bindInstalledRouteForTesting(
                routeID: Data(repeating: UInt8(marker), count: 32),
                carrier: TransportTestHarness.key(
                    TransportTestHarness.identity("relay-recheck-filler-\(marker)")),
                remote: target)
        }
        let ordered = zip(endpoints, loopbacks).sorted {
            (try! PeerKey($0.0.publicKey)) < (try! PeerKey($1.0.publicKey))
        }
        let connecting = BoundedTestTask {
            do {
                try await node.connectViaRelay(to: PeerEndpoint(
                    publicKey: target.hex,
                    host: "relay",
                    port: 0))
                return true
            } catch {
                return false
            }
        }
        #expect(try await TransportTestHarness.eventually {
            await node.pendingRelayOpenCountForTesting == 1
                && ordered[0].1.sink.byteCount > 0
        })

        await node.bindInstalledRouteForTesting(
            routeID: Data(repeating: 0xf0, count: 32),
            carrier: TransportTestHarness.key(
                TransportTestHarness.identity("relay-recheck-final-filler")),
            remote: target)
        guard let firstCarrier = try? PeerKey(ordered[0].0.publicKey) else {
            Issue.record("invalid test carrier")
            return
        }
        let pendingRoute = try #require(await node.pendingRelayRouteForTesting)
        await node.handleRelayControlForTesting(
            .relayReady(routeID: pendingRoute, status: 1),
            from: firstCarrier)

        #expect(try await !connecting.value(waitingFor: "capacity-rejected carrier retry"))
        #expect(!ordered[0].1.sink.hasRelayClose)
        #expect(ordered[1].1.sink.byteCount == 0)
        for endpoint in endpoints { await node.disconnect(try! PeerKey(endpoint.publicKey).peerID) }
        for loopback in loopbacks { await loopback.close() }
    }

    @Test("a relayed initiator cannot bypass the global connection cap")
    func relayedInitiatorObeysConnectionCapacity() async throws {
        let node = Ivy(config: IvyConfig(
            publicKey: "relay-initiator-cap",
            listenPort: 0,
            stunServers: [],
            healthConfig: PeerHealthConfig(enabled: false),
            maxConnections: 1,
            maxConnectionsPerNetgroup: 1))
        let existing = PeerEndpoint(
            publicKey: deterministicTestPeerKey("relay-cap-existing"),
            host: "127.0.0.1",
            port: 4001)
        try await node.seedConnectedEndpointForTesting(
            existing,
            marker: 1)

        let carrier = TransportTestHarness.key(
            TransportTestHarness.identity("relay-cap-carrier"))
        let target = TransportTestHarness.key(
            TransportTestHarness.identity("relay-cap-target"))
        let routeID = Data(repeating: 0x46, count: 32)
        let waiting = BoundedTestTask {
            await node.awaitRelayOpenForTesting(
                routeID: routeID,
                carrier: carrier,
                target: target)
        }
        #expect(try await TransportTestHarness.eventually {
            await node.pendingRelayOpenCountForTesting == 1
        })
        await node.handleRelayControlForTesting(
            .relayReady(routeID: routeID, status: 0),
            from: carrier)
        #expect(try await waiting.value(waitingFor: "capacity relay ready") == routeID)

        #expect(!(await node.openInstalledRouteConnectionForTesting(
            endpoint: PeerEndpoint(publicKey: target.hex, host: "relay", port: 0),
            target: target,
            routeID: routeID,
            carrier: carrier)))
        #expect(await node.routeConnectionCountForTesting == 0)
        await node.stop()
    }

    @Test("direct address alternatives precede relay fallback")
    func directAlternativesPrecedeRelay() async throws {
        let carrierIdentity = TransportTestHarness.identity("direct-first-carrier")
        let sourceIdentity = TransportTestHarness.identity("direct-first-source")
        let targetIdentity = TransportTestHarness.identity("direct-first-target")
        let carrierPort = TransportTestHarness.nextPort()
        let sourcePort = TransportTestHarness.nextPort()
        let targetPort = TransportTestHarness.nextPort()
        let carrierEndpoint = TransportTestHarness.endpoint(
            carrierIdentity,
            port: carrierPort)
        let targetEndpoint = TransportTestHarness.endpoint(targetIdentity, port: targetPort)
        let targetID = TransportTestHarness.key(targetIdentity).peerID
        let carrier = Ivy(config: TransportTestHarness.config(
            carrierIdentity,
            port: carrierPort,
            relayEnabled: true))
        let source = Ivy(config: TransportTestHarness.config(
            sourceIdentity,
            port: sourcePort,
            carriers: [carrierEndpoint]))
        let target = Ivy(config: TransportTestHarness.config(
            targetIdentity,
            port: targetPort))
        let sourceRecorder = TransportTestRecorder()
        await source.setTestDelegate(sourceRecorder)

        try await carrier.start()
        try await target.start()
        try await source.start()
        try await target.connect(to: carrierEndpoint)
        #expect(try await TransportTestHarness.eventually {
            await carrier.peerConnectionCount == 2
        })

        let dead = PeerEndpoint(
            publicKey: targetID.publicKey,
            host: "127.0.0.1",
            port: TransportTestHarness.nextPort())
        await source.connectToProviderEndpoints(
            [dead, targetEndpoint],
            generation: await source.runGeneration)

        #expect(sourceRecorder.authenticatedPeers.first {
            $0.key.peerID == targetID
        }?.route == .direct)

        await source.stop()
        await target.stop()
        await carrier.stop()
    }

    @Test("A configured carrier forwards peer messages and multi-frame Volumes")
    func configuredCarrierRelay() async throws {
        let carrierIdentity = TransportTestHarness.identity("relay-carrier")
        let sourceIdentity = TransportTestHarness.identity("relay-source")
        let targetIdentity = TransportTestHarness.identity("relay-target")
        let carrierPort = TransportTestHarness.nextPort()
        let sourcePort = TransportTestHarness.nextPort()
        let targetPort = TransportTestHarness.nextPort()
        let carrierEndpoint = TransportTestHarness.endpoint(carrierIdentity, port: carrierPort)
        let targetID = TransportTestHarness.key(targetIdentity).peerID
        let sourceID = TransportTestHarness.key(sourceIdentity).peerID
        let carrierKey = TransportTestHarness.key(carrierIdentity)
        let carrier = Ivy(config: TransportTestHarness.config(
            carrierIdentity,
            port: carrierPort,
            relayEnabled: true))
        let source = Ivy(config: TransportTestHarness.config(
            sourceIdentity,
            port: sourcePort,
            carriers: [carrierEndpoint],
            mode: .pinned(peer: targetID.publicKey),
            requestTimeout: .seconds(5)))
        let target = Ivy(config: TransportTestHarness.config(
            targetIdentity,
            port: targetPort,
            requestTimeout: .seconds(5)))
        let sourceRecorder = TransportTestRecorder()
        let targetRecorder = TransportTestRecorder()
        await source.setTestDelegate(sourceRecorder)
        await target.setTestDelegate(targetRecorder)
        let volumeBytes = Data(
            repeating: 0xa5,
            count: Int(IvyConfig.defaultProtocolMaxFrameSize) + 1
        )
        await target.setContentSource(RelayVolumeSource(entries: [
            ContentEntry(cid: "relay-root", data: volumeBytes),
        ]))

        try await carrier.start()
        try await target.start()
        try await source.start()
        try await target.connect(to: carrierEndpoint)
        #expect(try await TransportTestHarness.eventually {
            let carrierCount = await carrier.peerConnectionCount
            return carrierCount == 2 && sourceRecorder.authenticatedPeers.contains {
                $0.key == carrierKey && $0.role == .carrier
            } && targetRecorder.authenticatedPeers.contains {
                $0.key == carrierKey && $0.role == .endpoint
            }
        })
        #expect(await source.peerConnectionCount == 0)

        try await source.connectViaRelay(to: PeerEndpoint(
            publicKey: targetID.publicKey,
            host: "relay",
            port: 0))

        let payload = Data("relayed node state".utf8)
        let result = await source.sendMessage(
            to: targetID,
            topic: "node.state",
            payload: payload)
        guard case .enqueued(let endpoint, let route) = result,
              case .relayed(let authenticatedCarrier, let routeID) = route else {
            Issue.record("expected an enqueued relayed message")
            await source.stop()
            await target.stop()
            await carrier.stop()
            return
        }

        #expect(endpoint == targetID)
        #expect(authenticatedCarrier == carrierKey)
        #expect(try await TransportTestHarness.eventually {
            targetRecorder.authenticatedPeers.contains { $0.key.peerID == sourceID }
                && targetRecorder.receivedMessage(
                    topic: "node.state",
                    payload: payload,
                    from: sourceID)
        })
        guard case .relayed(let targetCarrier, let targetRouteID)? =
                targetRecorder.authenticatedPeers.first(where: { $0.key.peerID == sourceID })?.route else {
            Issue.record("target did not authenticate the relayed source")
            await source.stop()
            await target.stop()
            await carrier.stop()
            return
        }
        #expect(targetCarrier == carrierKey)
        #expect(targetRouteID == routeID)
        let messagePeer = try #require(targetRecorder.receivedPeer(
            topic: "node.state",
            payload: payload))
        #expect(messagePeer.key.peerID == sourceID)
        #expect(messagePeer.role == .endpoint)
        #expect(messagePeer.route == .relayed(carrier: carrierKey, routeID: routeID))

        let tooLargeForRelay = Data(
            repeating: 0xaa,
            count: Int(IvyConfig.defaultProtocolMaxFrameSize) - 180)
        #expect(await source.sendMessage(
            to: targetID,
            topic: "node.large",
            payload: tooLargeForRelay) == .locallyRejected)

        let afterRejection = Data("still sequenced".utf8)
        let afterResult = await source.sendMessage(
            to: targetID,
            topic: "node.after-rejection",
            payload: afterRejection)
        guard case .enqueued = afterResult else {
            Issue.record("relayed session did not survive local rejection")
            await source.stop()
            await target.stop()
            await carrier.stop()
            return
        }
        #expect(try await TransportTestHarness.eventually {
            targetRecorder.receivedMessage(
                topic: "node.after-rejection",
                payload: afterRejection,
                from: sourceID)
        })

        let targetPeer = try #require(
            sourceRecorder.authenticatedPeers.first { $0.key.peerID == targetID }
        )
        #expect(await source.fetchVolume(
            rootCID: "relay-root",
            from: targetPeer
        ) == AttributedVolumeResponse(
            rootCID: "relay-root",
            entries: ["relay-root": volumeBytes],
            servedBy: targetID
        ))

        await target.stop()
        #expect(try await TransportTestHarness.eventually {
            await source.peerConnectionCount == 0
        })

        await source.stop()
        await carrier.stop()
    }

    @Test("relay admission failure closes the route promptly")
    func relayAdmissionFailureClosesRoute() async throws {
        let carrierIdentity = TransportTestHarness.identity("relay-full-carrier")
        let sourceIdentity = TransportTestHarness.identity("relay-full-source")
        let targetIdentity = TransportTestHarness.identity("relay-full-target")
        let carrierPort = TransportTestHarness.nextPort()
        let sourcePort = TransportTestHarness.nextPort()
        let targetPort = TransportTestHarness.nextPort()
        let carrierEndpoint = TransportTestHarness.endpoint(carrierIdentity, port: carrierPort)
        let targetEndpoint = TransportTestHarness.endpoint(targetIdentity, port: targetPort)
        let carrierID = TransportTestHarness.key(carrierIdentity).peerID
        let carrier = Ivy(config: TransportTestHarness.config(
            carrierIdentity,
            port: carrierPort,
            relayEnabled: true))
        let source = Ivy(config: TransportTestHarness.config(
            sourceIdentity,
            port: sourcePort,
            carriers: [carrierEndpoint],
            mode: .pinned(peer: targetEndpoint.publicKey),
            relayTimeout: .seconds(10)))
        let target = Ivy(config: TransportTestHarness.config(
            targetIdentity,
            port: targetPort,
            maxConnections: 1))
        let sourceRecorder = TransportTestRecorder()
        await source.setTestDelegate(sourceRecorder)

        try await carrier.start()
        try await target.start()
        try await source.start()
        try await target.connect(to: carrierEndpoint)
        #expect(try await TransportTestHarness.eventually {
            await carrier.peerConnectionCount == 2
        })
        try await sourceRecorder.waitForConnect(carrierID)

        let started = ContinuousClock.now
        await #expect(throws: (any Error).self) {
            try await source.connectViaRelay(to: targetEndpoint)
        }
        #expect(ContinuousClock.now - started < .seconds(5))
        #expect(await target.peerConnectionCount == 1)
        #expect(sourceRecorder.isConnected(carrierID))

        #expect(await source.sendAuthenticatedMessageForTesting(
            .relayClose(routeID: Data(repeating: 0xaa, count: 32)),
            to: carrierID))
        try await Task.sleep(for: .milliseconds(50))
        #expect(sourceRecorder.isConnected(carrierID))

        await source.stop()
        await target.stop()
        await carrier.stop()
    }
}
