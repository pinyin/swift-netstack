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
    ) {
        // Reject datagrams not addressed to a local IP
        if !localIPs.isEmpty && !localIPs.contains(dstIP) { return }

        let frameLen = 14 + 20 + 8 + payloadLen
        // Echo swaps src↔dst: reply from dstIP:dstPort to srcIP:srcPort
        guard let ofs = buildUDPFrame(
            io: io, dstMAC: srcMAC, srcMAC: hostMAC,
            srcIP: dstIP, dstIP: srcIP,
            srcPort: dstPort, dstPort: srcPort,
            payloadPtr: UnsafeRawPointer(payloadPtr), payloadLen: payloadLen
        ) else { return }

        let idx = outBatch.count
        guard idx < outBatch.maxFrames else { return }
        outBatch.hdrOfs[idx] = ofs
        outBatch.hdrLen[idx] = frameLen
        outBatch.payOfs[idx] = -1
        outBatch.payLen[idx] = 0
        outBatch.epIDs[idx] = endpointID
        outBatch.payBase[idx] = nil
        outBatch.count += 1
    }
}
