import Foundation
import NIOCore
import NIOFoundationCompat
import NIOPosix

/// A `TransportConnection` over a NIO channel, and the channel handler that
/// feeds it.
///
/// The channel must run with `autoRead` off: `requestBytes()` is the channel's
/// only source of `read()`, so the socket is read exactly as far as the
/// session layer has asked for.
final class NIOTransportConnection: TransportConnection, ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer

    private let channel: Channel
    private let lock = NSLock()
    private var sink: (any TransportConnectionSink)?
    private var closed = false
    /// Bytes read but not yet delivered. Event loop only.
    private var pending: ByteBuffer?
    private var requested = false

    init(channel: Channel) {
        self.channel = channel
    }

    static func dial(
        host: String,
        port: UInt16,
        group: EventLoopGroup
    ) async throws -> NIOTransportConnection {
        try await ClientBootstrap(group: group)
            .connectTimeout(.seconds(5))
            .channelOption(ChannelOptions.autoRead, value: false)
            .connect(host: host, port: Int(port)) { channel in
                channel.eventLoop.makeCompletedFuture {
                    let connection = NIOTransportConnection(channel: channel)
                    try channel.pipeline.syncOperations.addHandler(connection)
                    return connection
                }
            }
    }

    var observedHost: String? { channel.remoteAddress?.ipAddress }
    var localHost: String? { channel.localAddress?.ipAddress }
    var isActive: Bool { channel.isActive }
    var isWritable: Bool { channel.isWritable }

    func attach(_ sink: any TransportConnectionSink) {
        let alreadyClosed = lock.withLock { () -> Bool in
            guard !closed else { return true }
            self.sink = sink
            return false
        }
        if alreadyClosed { sink.transportDidClose() }
    }

    func requestBytes() {
        if channel.eventLoop.inEventLoop {
            deliverOrRead()
        } else {
            channel.eventLoop.execute { self.deliverOrRead() }
        }
    }

    func send(_ bytes: Data) {
        var buffer = channel.allocator.buffer(capacity: bytes.count)
        buffer.writeBytes(bytes)
        channel.writeAndFlush(buffer, promise: nil)
    }

    func close() {
        channel.close(promise: nil)
    }

    private func deliverOrRead() {
        guard pending == nil else {
            deliverPending()
            return
        }
        requested = true
        // A read issued before the channel is active is never registered.
        if channel.isActive { channel.read() }
    }

    private func deliverPending() {
        guard var buffer = pending else { return }
        pending = nil
        requested = false
        guard let bytes = buffer.readData(length: buffer.readableBytes) else { return }
        lock.withLock { sink }?.transportDidReceive(bytes)
    }

    func channelActive(context: ChannelHandlerContext) {
        if requested { context.read() }
        context.fireChannelActive()
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var incoming = unwrapInboundIn(data)
        if pending == nil {
            pending = incoming
        } else {
            pending!.writeBuffer(&incoming)
        }
    }

    func channelReadComplete(context: ChannelHandlerContext) {
        // A closing socket is drained whether or not a read was asked for;
        // those bytes wait for the next request.
        guard requested else { return }
        guard pending != nil else {
            context.read()
            return
        }
        deliverPending()
    }

    func channelWritabilityChanged(context: ChannelHandlerContext) {
        lock.withLock { sink }?.transportWritabilityChanged(isWritable: context.channel.isWritable)
        context.fireChannelWritabilityChanged()
    }

    func channelInactive(context: ChannelHandlerContext) {
        pending = nil
        let sink = lock.withLock { () -> (any TransportConnectionSink)? in
            closed = true
            defer { self.sink = nil }
            return self.sink
        }
        sink?.transportDidClose()
        context.fireChannelInactive()
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        context.close(promise: nil)
    }
}

/// Admits an accepted TCP connection before anything is read from it, then
/// hands its stream to `Ivy.accept(_:admission:)`.
final class InboundConnectionAcceptor: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer

    weak var ivy: Ivy?
    private let admissionGate: InboundAdmissionGate
    private let connection: NIOTransportConnection
    private var accepted = false

    init(
        ivy: Ivy,
        admissionGate: InboundAdmissionGate,
        connection: NIOTransportConnection
    ) {
        self.ivy = ivy
        self.admissionGate = admissionGate
        self.connection = connection
    }

    func channelActive(context: ChannelHandlerContext) {
        guard !accepted, let ivy else {
            context.close(promise: nil)
            return
        }
        guard let lease = admissionGate.reserve(observedHost: connection.observedHost) else {
            context.close(promise: nil)
            return
        }
        accepted = true
        ivy.accept(connection, admission: lease)
        context.fireChannelActive()
    }
}
