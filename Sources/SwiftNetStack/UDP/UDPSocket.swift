/// Protocol for socket handler implementations (SoA-compatible).
///
/// Each registered handler processes transport-layer data addressed to its port.
/// Handlers write outbound frames directly into IOBuffer.output and track them
/// via OutBatch.
public protocol SocketHandler {
    /// SoA-compatible handler. Implementations write headers to IOBuffer.output
    /// and add entries to `outBatch` for sending.
    func handleDatagram(
        payloadPtr: UnsafeMutableRawPointer,
        payloadLen: Int,
        srcIP: IPv4Address,
        dstIP: IPv4Address,
        srcPort: UInt16,
        dstPort: UInt16,
        srcMAC: MACAddress,
        endpointID: Int,
        hostMAC: MACAddress,
        outBatch: OutBatch,
        io: IOBuffer
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
