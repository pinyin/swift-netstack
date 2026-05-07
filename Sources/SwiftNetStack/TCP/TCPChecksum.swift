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
    var buf = [UInt8](repeating: 0, count: 12 + tcpLen)
    var ipOut = [UInt8](repeating: 0, count: 4)
    pseudoSrcAddr.write(to: &ipOut); buf[0...3] = ipOut[0...3]
    pseudoDstAddr.write(to: &ipOut); buf[4...7] = ipOut[0...3]
    buf[9] = IPProtocol.tcp.rawValue
    buf[10] = UInt8(tcpLen >> 8)
    buf[11] = UInt8(tcpLen & 0xFF)
    buf.withUnsafeMutableBytes { dst in
        dst.baseAddress!.advanced(by: 12).copyMemory(from: tcpData, byteCount: tcpLen)
    }
    return buf.withUnsafeBytes { internetChecksum($0) }
}
