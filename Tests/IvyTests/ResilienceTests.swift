import Foundation
import NIOCore
import NIOEmbedded
import Testing
@testable import Ivy
import Tally

@Suite("Live transport bounds")
struct ResilienceTests {
    @Test("application records obey the protocol frame cap")
    func frameCap() {
        let message = Message.peerMessage(
            topic: "state",
            payload: Data(repeating: 0xAB, count: 128))

        #expect(message.serialize(maxFrameSize: 64).isEmpty)

        let encoded = message.serialize(maxFrameSize: 256)
        guard case .peerMessage(let topic, let payload)? =
                Message.deserialize(encoded, maxDataPayload: 256) else {
            Issue.record("bounded peer message did not round-trip")
            return
        }
        #expect(topic == "state")
        #expect(payload == Data(repeating: 0xAB, count: 128))
    }

    @Test("message parser rejects oversized bounded fields")
    func parserBounds() {
        let longTopic = String(
            repeating: "x",
            count: Int(MessageLimits.maxStringLength) + 1)
        #expect(Message.peerMessage(topic: longTopic, payload: Data()).serialize().isEmpty)

        var malformed = Data()
        malformed.appendUInt8(26)
        malformed.appendUInt64(1)
        malformed.appendUInt16(4)
        malformed.append(Data("root".utf8))
        malformed.appendUInt16(MessageLimits.maxContentCIDCount + 1)
        #expect(Message.deserialize(malformed) == nil)
    }

    @Test("relayed inbound queue overflow preserves order and closes the connection")
    func inboundQueue() async throws {
        let budget = InboundByteBudget(limit: PeerConnection.maxInboundBufferedRecords + 1)
        let carrier = try PeerKey(deterministicTestPeerKey("relayed-inbound-queue"))
        let connection = PeerConnection(
            endpoint: PeerEndpoint(publicKey: "", host: "relay", port: 0),
            routeID: Data(repeating: 1, count: 32),
            carrier: carrier,
            inboundByteBudget: budget)

        for value in 0..<connection.inboundBufferLimit {
            #expect(connection.feedRecord(Data([UInt8(value)])))
        }
        #expect(budget.currentUsage == connection.inboundBufferLimit)
        #expect(!connection.feedRecord(Data([0xff])))
        #expect(!connection.isLive)

        var received: [UInt8] = []
        for await record in connection.records {
            if let byte = record.bytes.first { received.append(byte) }
        }

        #expect(received.count == connection.inboundBufferLimit)
        #expect(received.first == 0)
        #expect(received.last == UInt8(connection.inboundBufferLimit - 1))
        #expect(budget.currentUsage == 0)
    }

    @Test("outbound backpressure waits for recovery and distinguishes closure")
    func outboundBackpressure() async throws {
        let loopback = try await TestLoopback.open()
        defer { Task { await loopback.close() } }
        let connection = PeerConnection(
            endpoint: PeerEndpoint(
                publicKey: "",
                host: "127.0.0.1",
                port: loopback.port
            ),
            stream: NIOTransportConnection(channel: loopback.client))

        connection.channelWritabilityChanged(isWritable: false)
        #expect(connection.sendSerializedRecord(Data([1, 2, 3])) == .backpressured)
        #expect(loopback.sink.byteCount == 0)

        let writable = Task { await connection.waitUntilWritable() }
        connection.channelWritabilityChanged(isWritable: true)
        #expect(await writable.value)
        #expect(connection.sendSerializedRecord(Data([1, 2, 3])) == .sent)
        try await TestSynchronization.wait(for: "writable loopback send") {
            loopback.sink.byteCount > 0
        }

        connection.channelWritabilityChanged(isWritable: false)
        let closed = Task { await connection.waitUntilWritable() }
        connection.cancel()
        #expect(!(await closed.value))
        #expect(connection.sendSerializedRecord(Data([4])) == .notConnected)
        await loopback.close()
    }

    @Test("Ivy exposes live transport backpressure without advancing the session")
    func ivyBackpressureResult() async throws {
        let local = deterministicTestSigningKey("outbound-local")
        let remote = try PeerKey(deterministicTestPeerKey("outbound-remote"))
        let endpoint = PeerEndpoint(publicKey: remote.hex, host: "127.0.0.1", port: 4001)
        let loopback = try await TestLoopback.open()
        let connection = PeerConnection(endpoint: endpoint, stream: NIOTransportConnection(channel: loopback.client))
        let ivy = Ivy(config: IvyConfig(signingKey: local, stunServers: []))
        try await ivy.seedConnectedEndpointForTesting(endpoint, connection: connection, marker: 1)

        connection.channelWritabilityChanged(isWritable: false)
        #expect(await ivy.sendMessage(
            to: remote.peerID,
            topic: "state",
            payload: Data()) == .backpressured)

        let writable = Task { await ivy.waitUntilWritable(to: remote.peerID) }
        connection.channelWritabilityChanged(isWritable: true)
        #expect(await writable.value)
        #expect(await ivy.sendMessage(
            to: remote.peerID,
            topic: "state",
            payload: Data()) == .enqueued(endpoint: remote.peerID, route: .direct))

        connection.cancel()
        #expect(!(await ivy.waitUntilWritable(to: remote.peerID)))
        await loopback.close()
    }

    @Test("a burst beyond Tally's per-peer request capacity is never locally rejected")
    func outboundBurstIsNotLocallyRejected() async throws {
        let local = deterministicTestSigningKey("burst-local")
        let remote = try PeerKey(deterministicTestPeerKey("burst-remote"))
        let endpoint = PeerEndpoint(publicKey: remote.hex, host: "127.0.0.1", port: 4001)
        let loopback = try await TestLoopback.open()
        let connection = PeerConnection(endpoint: endpoint, stream: NIOTransportConnection(channel: loopback.client))
        let ivy = Ivy(config: IvyConfig(
            signingKey: local,
            tallyConfig: TallyConfig(
                perPeerRequestCapacity: 1,
                perPeerRequestRefillPerSecond: 0
            ),
            stunServers: []))
        try await ivy.seedConnectedEndpointForTesting(endpoint, connection: connection, marker: 1)

        for _ in 0..<100 {
            #expect(await ivy.sendMessage(
                to: remote.peerID,
                topic: "state",
                payload: Data()) == .enqueued(endpoint: remote.peerID, route: .direct))
        }

        connection.cancel()
        await loopback.close()
    }

    @Test("a content response waits out a backpressured connection")
    func contentResponseWaitsForWritability() async throws {
        let local = deterministicTestSigningKey("reply-wait-local")
        let remote = try PeerKey(deterministicTestPeerKey("reply-wait-remote"))
        let endpoint = PeerEndpoint(publicKey: remote.hex, host: "127.0.0.1", port: 4001)
        let loopback = try await TestLoopback.open()
        let connection = PeerConnection(endpoint: endpoint, stream: NIOTransportConnection(channel: loopback.client))
        let ivy = Ivy(config: IvyConfig(signingKey: local, stunServers: []))
        try await ivy.seedConnectedEndpointForTesting(endpoint, connection: connection, marker: 1)
        let content = Data(repeating: 7, count: 1_000)
        await ivy.setContentSource(TransportTestContentSource(["root": content]))

        connection.channelWritabilityChanged(isWritable: false)
        let serving = Task {
            await ivy.handleContentRequest(
                requestID: 1,
                rootCID: "root",
                cids: [],
                from: remote.peerID)
        }
        try await Task.sleep(for: .milliseconds(100))
        #expect(await ivy.tally.metrics.totalBytesSent == 0)

        connection.channelWritabilityChanged(isWritable: true)
        await serving.value
        #expect(await ivy.tally.metrics.totalBytesSent > content.count)

        connection.cancel()
        await loopback.close()
    }

    @Test("relayed queues share one inbound byte budget")
    func relayedQueueBudget() async throws {
        let budget = InboundByteBudget(limit: 2)
        let carrier = try PeerKey(deterministicTestPeerKey("shared-budget-carrier"))
        let first = PeerConnection(
            endpoint: PeerEndpoint(publicKey: "", host: "relay", port: 0),
            routeID: Data(repeating: 1, count: 32),
            carrier: carrier,
            inboundByteBudget: budget)
        let second = PeerConnection(
            endpoint: PeerEndpoint(publicKey: "", host: "relay", port: 0),
            routeID: Data(repeating: 2, count: 32),
            carrier: carrier,
            inboundByteBudget: budget)

        #expect(first.feedRecord(Data([1, 2])))
        #expect(!second.feedRecord(Data([3])))
        #expect(budget.currentUsage == 2)
        for await _ in first.records { break }
        #expect(budget.currentUsage == 0)
    }
}
