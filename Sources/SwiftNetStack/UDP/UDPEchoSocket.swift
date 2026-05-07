/// UDP echo server: swaps src↔dst ports and IPs, sends payload back verbatim.
///
/// RFC 862 compliant — simplest valid UDP socket, useful for testing
/// the UDP datapath end-to-end.
///
/// `localIPs`: set of IP addresses this host owns. When non-empty, the echo
/// only replies to datagrams addressed to one of these IPs, preventing
/// UDP reflection amplification attacks. When empty (test convenience),
/// no dstIP filtering is performed. **Production callers must always provide
/// `localIPs` to prevent UDP reflection amplification.**
public struct UDPEchoSocket: SocketHandler {
    public let localIPs: Set<IPv4Address>

    public init(localIPs: Set<IPv4Address> = []) {
        self.localIPs = localIPs
    }

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
        // Reject datagrams not addressed to a local IP
        if !localIPs.isEmpty && !localIPs.contains(dstIP) { return }

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
