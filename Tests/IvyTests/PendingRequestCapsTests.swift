import Foundation
import Testing
@testable import Ivy
import Tally

private extension Ivy {
    func makeWireOperationIDAfterWrap(avoiding inUse: Set<UInt64>) -> UInt64 {
        nextWireOperationID = .max
        return makeWireOperationID(avoiding: inUse)
    }

    func pendingContentSnapshot() -> (requests: Int, waiters: Int) {
        (
            pendingContentRequests.count,
            pendingContentRequests.count
        )
    }

    func pendingProviderSnapshot(rootCID: String) -> (requestID: UInt64?, waiters: Int) {
        guard let pending = pendingProviderQueries[rootCID] else { return (nil, 0) }
        return (pending.requestID, pending.continuations.count)
    }

    func storedProviderExpiry(rootCID: String, peer: PeerID) -> UInt64? {
        providerHints[rootCID]?.first { $0.peer == peer }?.expiresAt
    }

    func seedProviderLookupTarget(_ endpoint: PeerEndpoint) {
        router.addPeer(PeerID(publicKey: endpoint.publicKey), endpoint: endpoint)
    }
}

@Suite("Pending content request caps")
struct PendingRequestCapsTests {
    private func cappedConfig(maxPending: Int, maxWaiters: Int) -> IvyConfig {
        IvyConfig(
            publicKey: "capped-node",
            listenPort: 0,
            bootstrapPeers: [],
            requestTimeout: .seconds(1),
            healthConfig: PeerHealthConfig(
                keepaliveInterval: .seconds(999),
                staleTimeout: .seconds(999),
                maxMissedPongs: 99,
                enabled: false
            ),
            maxPendingRequests: maxPending,
            maxWaitersPerRequest: maxWaiters,
            externalAddress: ("10.0.0.10", 4001)
        )
    }

    private func waitForSnapshot(
        _ expected: (requests: Int, waiters: Int),
        on node: Ivy
    ) async -> Bool {
        for _ in 0..<100 {
            let current = await node.pendingContentSnapshot()
            if current == expected { return true }
            try? await Task.sleep(for: .milliseconds(5))
        }
        return false
    }

    @Test("wire operation IDs skip zero and live IDs after wrap")
    func wireOperationIDWrapsWithoutCollision() async {
        let node = Ivy(config: cappedConfig(maxPending: 2, maxWaiters: 2))

        #expect(await node.makeWireOperationIDAfterWrap(avoiding: [1]) == 2)
    }

    @Test("distinct selections stop at the global cap")
    func globalCap() async {
        let node = Ivy(config: cappedConfig(maxPending: 2, maxWaiters: 8))
        let peer = PeerID(publicKey: deterministicTestPeerKey("silent-global-peer"))
        await node.setContentRequestEnqueueHookForTesting { _ in true }
        let first = Task {
            await node.fetchContent(ContentRequestKey(rootCID: "root-a", cids: []), from: [peer])
        }
        #expect(await waitForSnapshot((1, 1), on: node))
        let second = Task {
            await node.fetchContent(ContentRequestKey(rootCID: "root-b", cids: []), from: [peer])
        }
        #expect(await waitForSnapshot((2, 2), on: node))

        let start = ContinuousClock.now
        let rejected = await node.fetchContent(
            ContentRequestKey(rootCID: "root-c", cids: []),
            from: [peer]
        )

        #expect(rejected.entries.isEmpty)
        #expect(rejected.servedBy == nil)
        #expect(ContinuousClock.now - start < .milliseconds(200))
        let snapshot = await node.pendingContentSnapshot()
        #expect(snapshot.requests == 2)
        #expect(snapshot.waiters == 2)

        await node.cleanupAllPending()
        _ = await first.value
        _ = await second.value
    }

    @Test("wire requests have one owner and stop at the global cap")
    func wireRequestOwnership() async {
        let node = Ivy(config: cappedConfig(maxPending: 2, maxWaiters: 2))
        let peer = PeerID(publicKey: deterministicTestPeerKey("silent-coalescing-peer"))
        await node.setContentRequestEnqueueHookForTesting { _ in true }
        let firstKey = ContentRequestKey(
            rootCID: "root",
            cids: ["child-b", "root", "child-a", "child-b"]
        )
        let equivalentKey = ContentRequestKey(
            rootCID: "root",
            cids: ["child-a", "child-b"]
        )

        let first = Task { await node.fetchContent(firstKey, from: [peer]) }
        #expect(await waitForSnapshot((1, 1), on: node))
        let second = Task { await node.fetchContent(equivalentKey, from: [peer]) }
        #expect(await waitForSnapshot((2, 2), on: node))

        let start = ContinuousClock.now
        let rejected = await node.fetchContent(equivalentKey, from: [peer])

        #expect(firstKey == equivalentKey)
        #expect(rejected.entries.isEmpty)
        #expect(ContinuousClock.now - start < .milliseconds(200))
        let snapshot = await node.pendingContentSnapshot()
        #expect(snapshot.requests == 2)
        #expect(snapshot.waiters == 2)

        await node.cleanupAllPending()
        _ = await first.value
        _ = await second.value
    }

    @Test("provider queries coalesce, correlate, and aggregate bounded waiters")
    func providerQueryAggregation() async throws {
        let node = Ivy(config: cappedConfig(maxPending: 8, maxWaiters: 2))
        let peers = (0..<2).map {
            PeerID(publicKey: deterministicTestPeerKey("provider-query-\($0)"))
        }
        let endpoints = peers.enumerated().map { index, peer in
            PeerEndpoint(publicKey: peer.publicKey, host: "1.1.1.\(index + 1)", port: UInt16(4100 + index))
        }
        let targets = zip(peers, endpoints).map { peer, endpoint in
            Router.BucketEntry(
                id: peer,
                hash: Router.hash(peer.publicKey),
                endpoint: endpoint)
        }
        #expect(await node.queryProviders(rootCID: "unreachable", targets: targets).isEmpty)
        #expect(await node.pendingProviderSnapshot(rootCID: "unreachable").requestID == nil)
        var loopbacks: [TestLoopback] = []
        for (index, endpoint) in endpoints.enumerated() {
            let loopback = try await TestLoopback.open()
            loopbacks.append(loopback)
            try await node.seedConnectedEndpointForTesting(
                endpoint,
                connection: PeerConnection(endpoint: endpoint, stream: NIOTransportConnection(channel: loopback.client)),
                marker: UInt8(index + 1))
        }

        let first = Task { await node.queryProviders(rootCID: "root", targets: targets) }
        #expect(try await TransportTestHarness.eventually {
            await node.pendingProviderSnapshot(rootCID: "root").waiters == 1
        })
        let second = Task { await node.queryProviders(rootCID: "root", targets: targets) }
        #expect(try await TransportTestHarness.eventually {
            await node.pendingProviderSnapshot(rootCID: "root").waiters == 2
        })
        #expect(await node.queryProviders(rootCID: "root", targets: targets).isEmpty)

        guard let requestID = await node.pendingProviderSnapshot(rootCID: "root").requestID else {
            Issue.record("Expected one coalesced provider query")
            return
        }
        let expiry = await node.nowUnix() + 60
        await node.handleProvidersResponse(
            rootCID: "root",
            requestID: requestID &+ 1,
            records: [ProviderRecord(endpoint: endpoints[0], expiresAt: expiry)],
            from: peers[0])
        #expect(await node.pendingProviderSnapshot(rootCID: "root").waiters == 2)

        await node.handleProvidersResponse(
            rootCID: "root",
            requestID: requestID,
            records: [ProviderRecord(endpoint: endpoints[0], expiresAt: expiry)],
            from: peers[0])
        #expect(await node.pendingProviderSnapshot(rootCID: "root").requestID == requestID)
        await node.handleProvidersResponse(
            rootCID: "root",
            requestID: requestID,
            records: [ProviderRecord(endpoint: endpoints[1], expiresAt: expiry)],
            from: peers[1])

        #expect(Set(await first.value) == Set(endpoints))
        #expect(Set(await second.value) == Set(endpoints))
        #expect(await node.pendingProviderSnapshot(rootCID: "root").requestID == nil)
        #expect(await node.storedProviderExpiry(rootCID: "root", peer: peers[0]) == expiry)
        await node.stop()
        for loopback in loopbacks { await loopback.close() }
    }

    @Test("cancelling provider discovery promptly releases the public fetch slot")
    func publicFetchProviderCancellation() async throws {
        let node = Ivy(config: IvyConfig(
            publicKey: "provider-cancellation-node",
            listenPort: 0,
            requestTimeout: .seconds(5),
            stunServers: [],
            healthConfig: PeerHealthConfig(enabled: false),
            maxPendingRequests: 1
        ))
        let peer = PeerID(publicKey: deterministicTestPeerKey("silent-provider-peer"))
        let endpoint = PeerEndpoint(
            publicKey: peer.publicKey,
            host: "127.0.0.1",
            port: TransportTestHarness.nextPort()
        )
        let loopback = try await TestLoopback.open()
        try await node.start()
        try await node.seedConnectedEndpointForTesting(
            endpoint,
            connection: PeerConnection(endpoint: endpoint, stream: NIOTransportConnection(channel: loopback.client)),
            marker: 1
        )
        await node.seedProviderLookupTarget(endpoint)

        let fetch = Task { await node.fetchContent(rootCID: "cancelled-root") }
        #expect(try await TransportTestHarness.eventually {
            await node.pendingProviderSnapshot(rootCID: "cancelled-root").requestID != nil
        })
        fetch.cancel()
        #expect(await fetch.value == .empty)
        #expect(try await TransportTestHarness.eventually {
            let provider = await node.pendingProviderSnapshot(rootCID: "cancelled-root")
            let active = await node.activeFetchCountForTesting
            return provider.requestID == nil && active == 0
        })

        let replacement = Task { await node.fetchContent(rootCID: "replacement-root") }
        #expect(try await TransportTestHarness.eventually {
            await node.pendingProviderSnapshot(rootCID: "replacement-root").requestID != nil
        })
        replacement.cancel()
        #expect(await replacement.value == .empty)

        await node.stop()
        await loopback.close()
    }

}
