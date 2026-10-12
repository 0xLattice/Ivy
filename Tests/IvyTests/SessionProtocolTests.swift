import Crypto
import Foundation
import NIOEmbedded
import Testing
@testable import Ivy

@Suite("Ivy v9 session protocol")
struct SessionProtocolTests {
    private func identity(_ byte: UInt8) -> Curve25519.Signing.PrivateKey {
        try! Curve25519.Signing.PrivateKey(rawRepresentation: Data(repeating: byte, count: 32))
    }

    private func peerKey(_ identity: Curve25519.Signing.PrivateKey) -> PeerKey {
        try! PeerKey(rawRepresentation: identity.publicKey.rawRepresentation)
    }

    private func transcript() throws -> (
        SignedSessionHelloInitiator,
        SignedSessionHelloResponder,
        SessionID,
        Curve25519.Signing.PrivateKey,
        Curve25519.Signing.PrivateKey
    ) {
        let initiator = identity(1)
        let responder = identity(2)
        let helloI = SessionHelloInitiator(
            routeBinding: Data(repeating: 0x33, count: 32),
            initiator: peerKey(initiator),
            responder: peerKey(responder),
            nonce: Data(repeating: 0x11, count: 32),
            metadata: PeerMetadata(listenAddresses: [
                ListenAddress(host: "a.example", port: 4001),
            ]).encode()!)
        let signedI = try SignedSessionHelloInitiator.sign(helloI, with: initiator)
        let helloR = SessionHelloResponder(
            routeBinding: helloI.routeBinding,
            responder: helloI.responder,
            initiator: helloI.initiator,
            initiatorNonce: helloI.nonce,
            responderNonce: Data(repeating: 0x22, count: 32),
            metadata: PeerMetadata(listenAddresses: [
                ListenAddress(host: "r.example", port: 5001),
            ]).encode()!)
        let signedR = try SignedSessionHelloResponder.sign(helloR, with: responder)
        return (signedI, signedR, try SessionID(initiator: signedI, responder: signedR), initiator, responder)
    }

    @Test("frozen v9 session vectors")
    func frozenV9Vectors() throws {
        let route = Data(repeating: 0x11, count: 32)
        let initiatorIdentity = identity(1)
        let responderIdentity = identity(2)
        let initiator = peerKey(initiatorIdentity)
        let responder = peerKey(responderIdentity)
        let metadata = Data([0, 0])
        let helloI = SessionHelloInitiator(
            routeBinding: route,
            initiator: initiator,
            responder: responder,
            nonce: Data(repeating: 0x44, count: 32),
            metadata: metadata)
        let signedI = SignedSessionHelloInitiator(
            hello: helloI,
            signature: try #require(Data(hexString:
                "f08acddddd05639166b5d5b106c1892482eab8d5809b91e52af7cf98e6b0e6b34be2895d6ec8a25a0d8ad36f77a392e40d2979977c51eb164fb3d03d0de61c08")))

        let helloR = SessionHelloResponder(
            routeBinding: route,
            responder: responder,
            initiator: initiator,
            initiatorNonce: Data(repeating: 0x44, count: 32),
            responderNonce: Data(repeating: 0x66, count: 32),
            metadata: metadata)
        let signedR = SignedSessionHelloResponder(
            hello: helloR,
            signature: try #require(Data(hexString:
                "b0a8eff2c26e765dbc08e2688cc1adb58e5419ea8cfc34e412a00dd638324c99d133fdaa46a424de0032fb3fd68264b1fe2614414e58852b1b4f66df91ed1809")))
        let sessionID = try SessionID(initiator: signedI, responder: signedR)
        let finish = SessionFinish(
            sessionID: sessionID,
            sender: initiator,
            receiver: responder,
            signature: try #require(Data(hexString:
                "02d5f2ed6b4ba1cb8b5e1691be1bc38a855c5098152eda591b48118793acf3f46781f4c12d16e5bad2f857cfa9273df000dbb7d0034f5a58c51a6e78c900bd07")))
        let dataRecord = SessionDataRecord(
            sessionID: sessionID,
            sequence: 1,
            payload: Data([0xaa, 0xbb]),
            signature: try #require(Data(hexString:
                "a48a8036da2e5655b4e36f126de51a37ab46ce1fca193b5ca094b3524703e7c4a321cf5859c375297ef800ec76e01496c3484bcfdca0bc1d58bcb62f2efb7306")))

        let vectors = [
            SessionWireRecord.helloInitiator(signedI).serialize(),
            SessionWireRecord.helloResponder(signedR).serialize(),
            sessionID.bytes,
            SessionWireRecord.finish(finish).serialize(),
            SessionWireRecord.data(dataRecord).serialize(),
        ]
        let expectedHex = [
            "495659090100000088000911111111111111111111111111111111111111111111111111111111111111118a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b3944444444444444444444444444444444444444444444444444444444444444444000000020000f08acddddd05639166b5d5b106c1892482eab8d5809b91e52af7cf98e6b0e6b34be2895d6ec8a25a0d8ad36f77a392e40d2979977c51eb164fb3d03d0de61c08",
            "4956590902000000a8000911111111111111111111111111111111111111111111111111111111111111118139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b3948a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c44444444444444444444444444444444444444444444444444444444444444446666666666666666666666666666666666666666666666666666666666666666000000020000b0a8eff2c26e765dbc08e2688cc1adb58e5419ea8cfc34e412a00dd638324c99d133fdaa46a424de0032fb3fd68264b1fe2614414e58852b1b4f66df91ed1809",
            "590f18273722558b37b755b4c0d1786c992673392f3d8359d17a93519da9ccbd",
            "4956590903590f18273722558b37b755b4c0d1786c992673392f3d8359d17a93519da9ccbd8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b39402d5f2ed6b4ba1cb8b5e1691be1bc38a855c5098152eda591b48118793acf3f46781f4c12d16e5bad2f857cfa9273df000dbb7d0034f5a58c51a6e78c900bd07",
            "4956590904590f18273722558b37b755b4c0d1786c992673392f3d8359d17a93519da9ccbd000000000000000100000002aabba48a8036da2e5655b4e36f126de51a37ab46ce1fca193b5ca094b3524703e7c4a321cf5859c375297ef800ec76e01496c3484bcfdca0bc1d58bcb62f2efb7306",
        ]
        for (vector, hex) in zip(vectors, expectedHex) {
            let actual = vector.map { String(format: "%02x", $0) }.joined()
            #expect(actual == hex)
        }

        #expect(signedI.isValid())
        #expect(signedR.isValid())
        #expect(finish.isValid())
        #expect(dataRecord.isValid(sender: initiator, receiver: responder))

        var legacyWire = vectors[0]
        legacyWire[legacyWire.startIndex + 3] = 0x08
        #expect(throws: (any Error).self) {
            try SessionWireRecord.deserialize(legacyWire)
        }
    }

    @Test("metadata contains only canonical listen addresses")
    func canonicalMetadata() throws {
        let a = ListenAddress(host: "a.example", port: 4001)
        let z = ListenAddress(host: "z.example", port: 4002)
        let metadata = PeerMetadata(listenAddresses: [z, a, z])
        let encoded = try #require(metadata.encode())

        #expect(metadata.listenAddresses == [a, z])
        #expect(try PeerMetadata.decodeCanonical(encoded) == metadata)
    }

    @Test("metadata advertises a non-default frame size and omits the default")
    func frameSizeNegotiation() throws {
        let addr = ListenAddress(host: "a.example", port: 4001)

        // The default frame size is OMITTED, so metadata is byte-identical to a
        // legacy peer's — the canonical handshake check stays backward-compatible.
        let dflt = try #require(PeerMetadata(listenAddresses: [addr]).encode())
        let explicit = try #require(PeerMetadata(
            listenAddresses: [addr],
            maxFrameSize: IvyConfig.defaultProtocolMaxFrameSize).encode())
        #expect(dflt == explicit)
        #expect(try PeerMetadata.decodeCanonical(dflt).maxFrameSize
            == IvyConfig.defaultProtocolMaxFrameSize)

        // A non-default frame size round-trips and costs exactly a trailing UInt32.
        let customEncoded = try #require(PeerMetadata(
            listenAddresses: [addr], maxFrameSize: 8 * 1024 * 1024).encode())
        #expect(customEncoded.count == dflt.count + 4)
        #expect(try PeerMetadata.decodeCanonical(customEncoded).maxFrameSize == 8 * 1024 * 1024)

        // Redundantly encoding the default value is non-canonical → rejected.
        var redundant = dflt
        redundant.appendUInt32(IvyConfig.defaultProtocolMaxFrameSize)
        #expect(throws: SessionProtocolError.self) {
            try PeerMetadata.decodeCanonical(redundant)
        }
    }

    @Test("signed responder hello and initiator finish authenticate one transcript")
    func handshake() throws {
        let (helloI, helloR, sessionID, initiatorIdentity, responderIdentity) = try transcript()
        let initiator = peerKey(initiatorIdentity)
        let responder = peerKey(responderIdentity)
        let finish = try SessionFinish.sign(
            sessionID: sessionID,
            sender: initiator,
            receiver: responder,
            with: initiatorIdentity)

        #expect(helloI.isValid())
        #expect(helloR.isValid())
        #expect(finish.isValid())
        #expect(try SessionID(initiator: helloI, responder: helloR) == sessionID)

        let otherSession = try SessionID(bytes: Data(repeating: 0xaa, count: 32))
        #expect(!SessionFinish(
            sessionID: otherSession,
            sender: finish.sender,
            receiver: finish.receiver,
            signature: finish.signature).isValid())
        #expect(!SessionFinish(
            sessionID: finish.sessionID,
            sender: responder,
            receiver: initiator,
            signature: finish.signature).isValid())

        let records: [SessionWireRecord] = [
            .helloInitiator(helloI),
            .helloResponder(helloR),
            .finish(finish),
        ]
        for record in records {
            #expect(try SessionWireRecord.deserialize(record.serialize()) == record)
        }
    }

    @Test("hello signatures bind identity and metadata")
    func helloTampering() throws {
        let (signed, _, _, _, wrongIdentity) = try transcript()
        var signature = signed.signature
        signature[0] ^= 1
        #expect(!SignedSessionHelloInitiator(hello: signed.hello, signature: signature).isValid())
        let signedByWrongIdentity = try SignedSessionHelloInitiator.sign(signed.hello, with: wrongIdentity)
        #expect(!signedByWrongIdentity.isValid())

        var metadata = signed.hello.metadata
        metadata[metadata.startIndex] ^= 1
        let changed = SessionHelloInitiator(
            routeBinding: signed.hello.routeBinding,
            initiator: signed.hello.initiator,
            responder: signed.hello.responder,
            nonce: signed.hello.nonce,
            metadata: metadata)
        #expect(!SignedSessionHelloInitiator(hello: changed, signature: signed.signature).isValid())
    }

    @Test("signed data is transcript-bound and strictly sequenced")
    func signedData() throws {
        let (_, _, sessionID, initiatorIdentity, responderIdentity) = try transcript()
        let initiator = peerKey(initiatorIdentity)
        let responder = peerKey(responderIdentity)
        let record = try SessionDataRecord.sign(
            sessionID: sessionID,
            sender: initiator,
            receiver: responder,
            sequence: 9,
            payload: Data("payload".utf8),
            with: initiatorIdentity)

        #expect(record.isValid(sender: initiator, receiver: responder))
        #expect(!record.isValid(sender: responder, receiver: initiator))
        #expect(
            try SessionWireRecord.deserialize(SessionWireRecord.data(record).serialize())
                == SessionWireRecord.data(record))

        var receive = SessionSequenceState()
        let first = receive.acceptIncoming(1)
        let gap = receive.acceptIncoming(9)
        let replay = receive.acceptIncoming(9)
        let earlier = receive.acceptIncoming(2)
        #expect(first)
        #expect(gap)
        #expect(!replay)
        #expect(!earlier)
        #expect(!receive.canAcceptIncoming(9))
        #expect(receive.canAcceptIncoming(10))

        var send = SessionSequenceState(nextToSend: UInt64.max)
        let last = send.takeNextOutgoing()
        let exhausted = send.takeNextOutgoing()
        #expect(last == UInt64.max)
        #expect(exhausted == nil)
    }

    @Test("direct handshake rejects a mismatched route binding")
    func directRouteBindingMismatch() async throws {
        let localIdentity = identity(1)
        let remoteIdentity = identity(2)
        let local = peerKey(localIdentity)
        let remote = peerKey(remoteIdentity)
        let ivy = Ivy(config: IvyConfig(signingKey: localIdentity, stunServers: []))
        let channel = EmbeddedChannel()
        defer { _ = try? channel.finish() }
        let connection = PeerConnection(
            endpoint: PeerEndpoint(publicKey: remote.hex, host: "127.0.0.1", port: 4001),
            stream: NIOTransportConnection(channel: channel),
            inboundByteBudget: InboundByteBudget(limit: IvyConfig.defaultMaxInboundBufferedBytes))
        let metadata = try #require(PeerMetadata().encode())
        let matching = SessionHelloInitiator(
            routeBinding: Ivy.directRouteBinding,
            initiator: remote,
            responder: local,
            nonce: Data(repeating: 1, count: 32),
            metadata: metadata)
        let mismatched = SessionHelloInitiator(
            routeBinding: Data(repeating: 1, count: 32),
            initiator: remote,
            responder: local,
            nonce: matching.nonce,
            metadata: metadata)

        let acceptsMatching = await ivy.acceptsInboundHello(matching, on: connection)
        let acceptsMismatched = await ivy.acceptsInboundHello(mismatched, on: connection)
        #expect(acceptsMatching)
        #expect(!acceptsMismatched)
    }

    @Test("duplicate sessions prefer the smaller session ID")
    func preferredSessionID() throws {
        let smaller = try SessionID(bytes: Data(repeating: 1, count: 32))
        let larger = try SessionID(bytes: Data(repeating: 2, count: 32))

        #expect(Ivy.preferredSessionID(larger, smaller) == smaller)
        #expect(Ivy.preferredSessionID(smaller, larger) == smaller)
    }

    @Test("application frames are not session records")
    func rejectsApplicationFrame() {
        #expect(throws: (any Error).self) {
            try SessionWireRecord.deserialize(Message.ping(nonce: 1).serialize())
        }
    }

    @Test("protocol violations require endpoint-authenticated evidence")
    func violationAttribution() {
        let peer = peerKey(identity(3))

        #expect(Ivy.attributedPeer(peer, direct: true, evidence: .unverified) == nil)
        #expect(Ivy.attributedPeer(peer, direct: false, evidence: .unverified) == nil)
        #expect(Ivy.attributedPeer(peer, direct: true, evidence: .signedTransport) == peer)
        #expect(Ivy.attributedPeer(peer, direct: false, evidence: .signedTransport) == nil)
        #expect(Ivy.attributedPeer(peer, direct: true, evidence: .signedPayload) == peer)
        #expect(Ivy.attributedPeer(peer, direct: false, evidence: .signedPayload) == peer)
    }
}
