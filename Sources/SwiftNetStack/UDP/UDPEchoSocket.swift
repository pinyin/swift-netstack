/// UDP echo server: swaps src↔dst ports and IPs, sends payload back verbatim.
///
/// RFC 862 compliant — simplest valid UDP socket, useful for testing
/// the UDP datapath end-to-end.
public struct UDPEchoSocket: UDPSocket {
    public init() {}

    public func handleDatagram(
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
    ) {
        guard let reply = buildUDPFrame(
            hostMAC: hostMAC,
            dstMAC: srcMAC,
            srcIP: dstIP,
            dstIP: srcIP,
            srcPort: dstPort,
            dstPort: srcPort,
            payload: payload,
            round: round
        ) else { return }
        replies.append((endpointID, reply))
    }
}
