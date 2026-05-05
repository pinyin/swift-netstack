/// Northbound endpoint ID for TUN-originated packets.
public let northboundEndpointID = -1

/// Transport abstraction over I/O system calls.
///
/// Real implementation: PollingTransport (poll + read + non-blocking sendmsg)
/// Test implementation: InMemoryTransport (pre-filled inputs, captured outputs)
public protocol Transport {
    /// Read frames from all interfaces. Each frame tagged with endpointID.
    /// Production: poll() blocks → read() all ready fds until EAGAIN → return.
    mutating func readPackets(round: RoundContext) -> [(endpointID: Int, packet: PacketBuffer)]

    /// Write frames to corresponding interfaces. Non-blocking.
    /// Production: sendmsg with MSG_DONTWAIT. EAGAIN → internal pending, retry next round.
    mutating func writePackets(_ packets: [(endpointID: Int, packet: PacketBuffer)])
}

// MARK: - InMemoryTransport (testing)

/// Pure in-memory transport. Zero system calls. Inputs pre-filled, outputs captured.
public struct InMemoryTransport: Transport {
    public var inputs: [(endpointID: Int, packet: PacketBuffer)] = []
    public private(set) var outputs: [(endpointID: Int, packet: PacketBuffer)] = []

    public var outputEndpoints: Set<Int> {
        Set(outputs.map(\.endpointID))
    }

    public init(inputs: [(endpointID: Int, packet: PacketBuffer)] = []) {
        self.inputs = inputs
    }

    public mutating func readPackets(round: RoundContext) -> [(endpointID: Int, packet: PacketBuffer)] {
        return inputs
    }

    public mutating func writePackets(_ packets: [(endpointID: Int, packet: PacketBuffer)]) {
        outputs.append(contentsOf: packets)
    }
}
