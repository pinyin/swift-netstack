import Darwin

/// Build a complete Ethernet + IPv4 + TCP outbound frame.
///
/// Follows the same pattern as `buildUDPFrame`: allocate from `round`, write raw
/// bytes via pointer arithmetic, compute IP header checksum and TCP checksum.
func buildTCPFrame(
    hostMAC: MACAddress,
    dstMAC: MACAddress,
    srcIP: IPv4Address,
    dstIP: IPv4Address,
    srcPort: UInt16,
    dstPort: UInt16,
    seqNumber: UInt32,
    ackNumber: UInt32,
    flags: TCPFlags,
    window: UInt16,
    payload: PacketBuffer?,
    round: RoundContext
) -> PacketBuffer? {
    let tcpHeaderLen = 20  // fixed header, no options in our frames
    let payloadLen = payload?.totalLength ?? 0
    let tcpTotalLen = tcpHeaderLen + payloadLen
    let ipTotalLen = ipv4HeaderLen + tcpTotalLen
    let frameLen = ethHeaderLen + ipTotalLen

    var frame = round.allocate(capacity: frameLen, headroom: 0)
    guard let ptr = frame.appendPointer(count: frameLen) else { return nil }

    // Ethernet header (14 bytes)
    dstMAC.write(to: ptr)
    hostMAC.write(to: ptr.advanced(by: 6))
    writeUInt16BE(EtherType.ipv4.rawValue, to: ptr.advanced(by: 12))

    // IPv4 header (20 bytes) at offset 14
    let ipPtr = ptr.advanced(by: ethHeaderLen)
    writeIPv4Header(to: ipPtr, totalLength: UInt16(ipTotalLen), protocol: .tcp,
                    srcIP: srcIP, dstIP: dstIP)

    // TCP header (20 bytes) at offset 34
    let tcpPtr = ipPtr.advanced(by: ipv4HeaderLen)
    writeUInt16BE(srcPort, to: tcpPtr)
    writeUInt16BE(dstPort, to: tcpPtr.advanced(by: 2))
    writeUInt32BE(seqNumber, to: tcpPtr.advanced(by: 4))
    writeUInt32BE(ackNumber, to: tcpPtr.advanced(by: 8))
    // data offset (5) + reserved (0) → high nibble = 5
    tcpPtr.advanced(by: 12).storeBytes(of: UInt8(0x50), as: UInt8.self)
    // flags byte
    tcpPtr.advanced(by: 13).storeBytes(of: flags.rawValue, as: UInt8.self)
    writeUInt16BE(window, to: tcpPtr.advanced(by: 14))
    writeUInt16BE(0, to: tcpPtr.advanced(by: 16))   // checksum placeholder
    writeUInt16BE(0, to: tcpPtr.advanced(by: 18))   // urgent pointer

    // TCP payload
    if let payload = payload, payloadLen > 0 {
        payload.withUnsafeReadableBytes { payloadBuf in
            tcpPtr.advanced(by: tcpHeaderLen).copyMemory(from: payloadBuf.baseAddress!, byteCount: payloadLen)
        }
    }

    // TCP checksum (pseudo-header + TCP header + payload)
    let ck = computeTCPChecksum(
        pseudoSrcAddr: srcIP, pseudoDstAddr: dstIP,
        tcpData: tcpPtr, tcpLen: tcpTotalLen
    )
    writeUInt16BE(ck, to: tcpPtr.advanced(by: 16))

    return frame
}
