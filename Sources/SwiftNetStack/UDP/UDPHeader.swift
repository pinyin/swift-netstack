// MARK: - UDP pseudo-header checksum (RFC 768)

/// Compute the UDP checksum from a contiguous UDP header+payload in memory.
///
/// The caller must ensure `udpData` points to `udpLen` bytes of contiguous
/// UDP header + payload.
///
/// Returns 0xFFFF instead of 0 to distinguish "computed zero" from "unused"
/// (RFC 768 §1).
func computeUDPChecksum(
    pseudoSrcAddr: IPv4Address,
    pseudoDstAddr: IPv4Address,
    udpData: UnsafeRawPointer,
    udpLen: Int
) -> UInt16 {
    var sum = computePseudoHeaderSum(srcIP: pseudoSrcAddr, dstIP: pseudoDstAddr,
                                     protocol: IPProtocol.udp.rawValue, totalLen: udpLen)
    sum = checksumAdd(sum, udpData, udpLen)
    let ck = finalizeChecksum(sum)
    return ck == 0 ? 0xFFFF : ck
}

// MARK: - Unified UDP frame builder

/// Build a complete Ethernet+IPv4+UDP+payload frame into IOBuffer.output.
/// Returns the output offset, or nil if output buffer is full.
///
/// Used by DHCP server, DNS server, NAT UDP, and UDP echo — all four
/// previously had near-identical inline copies of this logic.
func buildUDPFrame(
    io: IOBuffer,
    dstMAC: MACAddress, srcMAC: MACAddress,
    srcIP: IPv4Address, dstIP: IPv4Address,
    srcPort: UInt16, dstPort: UInt16,
    payloadPtr: UnsafeRawPointer, payloadLen: Int
) -> Int? {
    let udpTotalLen = 8 + payloadLen
    let ipTotalLen = 20 + udpTotalLen
    let frameLen = 14 + ipTotalLen

    guard let ptr = io.allocOutput(frameLen) else { return nil }
    let ofs = ptr - io.output.baseAddress!

    // Ethernet
    dstMAC.write(to: ptr)
    srcMAC.write(to: ptr.advanced(by: 6))
    writeUInt16BE(EtherType.ipv4.rawValue, to: ptr.advanced(by: 12))

    // IPv4
    let ipPtr = ptr.advanced(by: ethHeaderLen)
    writeIPv4Header(to: ipPtr, totalLength: UInt16(ipTotalLen), protocol: .udp,
                    srcIP: srcIP, dstIP: dstIP)

    // UDP header
    let udpPtr = ipPtr.advanced(by: ipv4HeaderLen)
    writeUInt16BE(srcPort, to: udpPtr)
    writeUInt16BE(dstPort, to: udpPtr.advanced(by: 2))
    writeUInt16BE(UInt16(udpTotalLen), to: udpPtr.advanced(by: 4))
    writeUInt16BE(0, to: udpPtr.advanced(by: 6))

    // Payload
    if payloadLen > 0 {
        udpPtr.advanced(by: 8).copyMemory(from: payloadPtr, byteCount: payloadLen)
    }

    // UDP checksum
    let ck = computeUDPChecksum(
        pseudoSrcAddr: srcIP, pseudoDstAddr: dstIP,
        udpData: udpPtr, udpLen: udpTotalLen
    )
    writeUInt16BE(ck, to: udpPtr.advanced(by: 6))

    return ofs
}
