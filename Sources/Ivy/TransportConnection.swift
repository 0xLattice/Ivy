import Foundation

/// Receives everything a `TransportConnection` produces. Calls arrive one at a
/// time, in stream order.
public protocol TransportConnectionSink: AnyObject, Sendable {
    /// The bytes one `requestBytes()` asked for, in stream order: never empty,
    /// and no more than one read of the stream's own. Ivy holds a delivery
    /// unreserved until it is decoded, so that read size is what bounds it.
    func transportDidReceive(_ bytes: Data)
    func transportWritabilityChanged(isWritable: Bool)
    /// The stream ended, whichever side closed it. Reported exactly once;
    /// nothing follows.
    func transportDidClose()
}

/// An ordered, reliable byte stream to one peer.
///
/// Ivy turns the stream into bounded records attributed to a peer key:
/// framing, byte budgets, admission, the handshake and sessions all live above
/// this protocol and are the same for every stream. Whoever established the
/// stream hands it to `Ivy.accept(_:admission:)` or `Ivy.connect(to:over:)`.
public protocol TransportConnection: AnyObject, Sendable {
    /// Address the peer was observed at, which netgroup admission keys on. A
    /// stream must report one: Ivy refuses a stream without it.
    var observedHost: String? { get }
    /// Local address the stream is bound to, if it has one.
    var localHost: String? { get }
    var isActive: Bool { get }
    var isWritable: Bool { get }

    /// Installs the sink. The stream holds it until it has reported its close
    /// and drops it then: the connection and its stream hold each other until
    /// it does. A stream that already closed reports that at once.
    func attach(_ sink: any TransportConnectionSink)

    /// Asks for the next bytes. Each call permits one `transportDidReceive`,
    /// and nothing is delivered that was not asked for, so a consumer that
    /// stops asking stops the peer instead of filling a buffer. The delivery
    /// may happen before this call returns.
    func requestBytes()

    /// Sends already-framed bytes in order. Bytes sent while the stream is not
    /// writable are still queued; `isWritable` is the signal to stop.
    func send(_ bytes: Data)

    /// Closes the stream. May be called more than once; the sink is told
    /// through `transportDidClose()` exactly once.
    func close()
}
