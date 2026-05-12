import Darwin

/// Holds a TCP connection managed by the NAT table.
final class NATEntry {
    public var connection: TCPConnection
    public let createdAt: UInt64
    public var lastActivity: UInt64
    /// Whether this connection was created from an inbound (port-forward) accept.
    public let isInbound: Bool

    public init(connection: TCPConnection, isInbound: Bool = false) {
        self.connection = connection
        let now = UInt64(Darwin.time(nil))
        self.createdAt = now
        self.lastActivity = now
        self.isInbound = isInbound
    }
}
