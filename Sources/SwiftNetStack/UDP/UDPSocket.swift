/// Protocol for UDP socket implementations.
///
/// Each registered socket handles datagrams addressed to its port.
/// Sockets produce outbound frames by appending to `replies`.
public protocol UDPSocket {
    func handleDatagram(
        payload: PacketBuffer,
        srcIP: IPv4Address,
        dstIP: IPv4Address,
        srcPort: UInt16,
        dstPort: UInt16,
        srcMAC: MACAddress,
        endpointID: Int,
        hostMAC: MACAddress,
        replies: inout [(endpointID: Int, packet: PacketBuffer)],
        round: RoundContext
    )
}

/// Port → socket registry.
///
/// Simple mutable value type passed via `inout`, following the `ARPMapping` pattern.
public struct UDPSocketTable {
    private var sockets: [UInt16: any UDPSocket] = [:]

    public init() {}

    public mutating func register(port: UInt16, socket: any UDPSocket) {
        sockets[port] = socket
    }

    public mutating func unregister(port: UInt16) {
        sockets[port] = nil
    }

    public func lookup(port: UInt16) -> (any UDPSocket)? {
        sockets[port]
    }
}
