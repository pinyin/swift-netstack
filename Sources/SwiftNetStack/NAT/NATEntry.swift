import Darwin

/// Holds a TCP connection managed by the NAT table.
struct NATEntry {
    public var connection: TCPConnection
    public let createdAt: UInt64
    /// Whether this connection was created from an inbound (port-forward) accept.
    public let isInbound: Bool

    public init(connection: TCPConnection, isInbound: Bool = false) {
        self.connection = connection
        self.createdAt = UInt64(Darwin.time(nil))
        self.isInbound = isInbound
    }
}
