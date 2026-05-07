/// Protocol for socket handler implementations.
///
/// Each registered handler processes transport-layer data addressed to its port.
/// Handlers produce outbound frames by appending to `replies`.
public protocol SocketHandler {
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

/// Port → handler registry.
///
/// Simple mutable value type passed via `inout`, following the `ARPMapping` pattern.
public struct SocketRegistry {
    private var handlers: [UInt16: any SocketHandler] = [:]

    public init() {}

    public mutating func register(port: UInt16, handler: any SocketHandler) {
        handlers[port] = handler
    }

    public mutating func unregister(port: UInt16) {
        handlers[port] = nil
    }

    public func lookup(port: UInt16) -> (any SocketHandler)? {
        handlers[port]
    }
}
