/// Compute the TCP checksum over pseudo-header + TCP segment.
///
/// Same 12-byte pseudo-header structure as UDP (RFC 768), but with IPProtocol.tcp (6).
/// Unlike UDP, TCP checksum is mandatory — zero after computation means valid,
/// never "unused".
///
/// Returns 0 if the computed checksum is valid.
func computeTCPChecksum(
    pseudoSrcAddr: IPv4Address,
    pseudoDstAddr: IPv4Address,
    tcpData: UnsafeRawPointer,
    tcpLen: Int
) -> UInt16 {
    // Stack-allocated pseudo-header: srcIP(4) + dstIP(4) + zero(1) + proto(1) + len(2) = 12 bytes
    var pseudo: [UInt8] = [
        0, 0, 0, 0,  0, 0, 0, 0,  0, IPProtocol.tcp.rawValue, UInt8(tcpLen >> 8), UInt8(tcpLen & 0xFF),
    ]
    pseudoSrcAddr.write(to: &pseudo)
    pseudo.withUnsafeMutableBytes { buf in
        pseudoDstAddr.write(to: buf.baseAddress!.advanced(by: 4))
    }

    var sum = pseudoSum(pseudo)
    sum = checksumAdd(sum, tcpData, tcpLen)
    return finalizeChecksum(sum)
}

/// Compute TCP checksum using scatter-gather: header in contiguous memory,
/// payload accessed via PacketBuffer views without copying.
///
/// Avoids the O(N) payload copy that a full pullUp would incur. Used by
/// the parse (ingress) path; the egress path uses the same scatter-gather
/// pattern inline in buildTCPFrame.
func computeTCPChecksumSG(
    pseudoSrcAddr: IPv4Address,
    pseudoDstAddr: IPv4Address,
    tcpHeader: UnsafeRawPointer,
    headerLen: Int,
    payloadViews: [PacketBuffer.View],
    tcpLen: Int
) -> UInt16 {
    var pseudo: [UInt8] = [
        0, 0, 0, 0,  0, 0, 0, 0,  0, IPProtocol.tcp.rawValue, UInt8(tcpLen >> 8), UInt8(tcpLen & 0xFF),
    ]
    pseudoSrcAddr.write(to: &pseudo)
    pseudo.withUnsafeMutableBytes { buf in
        pseudoDstAddr.write(to: buf.baseAddress!.advanced(by: 4))
    }
    var sum = pseudoSum(pseudo)
    sum = checksumAdd(sum, tcpHeader, headerLen)
    sum = checksumAddViews(sum, payloadViews)
    return finalizeChecksum(sum)
}
