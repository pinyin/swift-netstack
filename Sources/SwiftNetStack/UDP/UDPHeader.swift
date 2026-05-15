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
