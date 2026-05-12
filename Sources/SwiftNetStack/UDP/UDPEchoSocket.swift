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

        let udpTotalLen = 8 + payloadLen
        let ipTotalLen = 20 + udpTotalLen
        let hdrLen = 14 + 20 + 8  // 42 bytes

        guard let ptr = io.allocOutput(hdrLen) else { return }
        let ofs = ptr - io.output.baseAddress!

        // Ethernet header
        srcMAC.write(to: ptr)                                        // dst = original sender
        hostMAC.write(to: ptr.advanced(by: 6))                       // src = us
        writeUInt16BE(EtherType.ipv4.rawValue, to: ptr.advanced(by: 12))

        // IPv4 header
        let ipPtr = ptr.advanced(by: ethHeaderLen)
        writeIPv4Header(to: ipPtr, totalLength: UInt16(ipTotalLen), protocol: .udp,
                        srcIP: dstIP, dstIP: srcIP)

        // UDP header
        let udpPtr = ipPtr.advanced(by: ipv4HeaderLen)
        writeUInt16BE(dstPort, to: udpPtr)
        writeUInt16BE(srcPort, to: udpPtr.advanced(by: 2))
        writeUInt16BE(UInt16(udpTotalLen), to: udpPtr.advanced(by: 4))
        writeUInt16BE(0, to: udpPtr.advanced(by: 6))  // checksum placeholder

        // UDP checksum — src/dst are swapped for echo reply
        var ckSum = computePseudoHeaderSum(srcIP: dstIP, dstIP: srcIP,
                                            protocol: IPProtocol.udp.rawValue, totalLen: udpTotalLen)
        ckSum = checksumAdd(ckSum, udpPtr, 8)
        ckSum = checksumAdd(ckSum, UnsafeRawPointer(payloadPtr), payloadLen)
        let ck = finalizeChecksum(ckSum)
        writeUInt16BE(ck == 0 ? 0xFFFF : ck, to: udpPtr.advanced(by: 6))

        let idx = outBatch.count
        guard idx < outBatch.maxFrames else { return }
        outBatch.hdrOfs[idx] = ofs
        outBatch.hdrLen[idx] = hdrLen
        outBatch.payOfs[idx] = payloadPtr - io.input.baseAddress!  // offset within input
        outBatch.payLen[idx] = payloadLen
        outBatch.epIDs[idx] = endpointID
        outBatch.payBase[idx] = nil  // use io.input
        outBatch.count += 1
    }
}
