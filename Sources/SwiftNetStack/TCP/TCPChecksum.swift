/// Compute the TCP checksum over pseudo-header + contiguous TCP segment.
///
/// Same 12-byte pseudo-header structure as UDP (RFC 768), but with IPProtocol.tcp (6).
/// Unlike UDP, TCP checksum is mandatory — zero after computation means valid,
/// never "unused".
func computeTCPChecksum(
    pseudoSrcAddr: IPv4Address,
    pseudoDstAddr: IPv4Address,
    tcpData: UnsafeRawPointer,
    tcpLen: Int
) -> UInt16 {
    // Stack-allocated pseudo-header: srcIP(4) + dstIP(4) + zero(1) + proto(1) + len(2) = 12 bytes
    var sum = computePseudoHeaderSum(srcIP: pseudoSrcAddr, dstIP: pseudoDstAddr,
                                     protocol: IPProtocol.tcp.rawValue, totalLen: tcpLen)
    sum = checksumAdd(sum, tcpData, tcpLen)
    return finalizeChecksum(sum)
}
