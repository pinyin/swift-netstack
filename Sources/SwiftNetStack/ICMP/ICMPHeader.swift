import Darwin

let icmpHeaderLen = 8

/// Write Ethernet+IPv4+ICMP Echo Reply headers into IOBuffer.output.
/// Returns the output offset, or -1 if the output buffer is full.
/// The caller tracks the payload separately via OutBatch (zero-copy from IOBuffer.input).
///
/// The ICMP checksum covers header + payload per RFC 792.  The payload's
/// one's complement sum is pre-computed during parse and stored in
/// ICMPEchoParsedFrame.payloadSum, so the build phase only folds the 8-byte
/// header into it — zero payload touch in the hot path.
public func buildICMPEchoReplyHeader(
    io: IOBuffer,
    hostMAC: MACAddress,
    dstMAC: MACAddress,
    srcIP: IPv4Address,
    dstIP: IPv4Address,
    identifier: UInt16,
    sequenceNumber: UInt16,
    payloadLen: Int,
    payloadSum: UInt32 = 0
) -> Int {
    let icmpTotalLen = 8 + payloadLen
    let ipTotalLen = 20 + icmpTotalLen
    let hdrLen = 14 + 20 + 8  // Ethernet + IPv4 + ICMP = 42 bytes
    guard let ptr = io.allocOutput(hdrLen) else { return -1 }
    let ofs = ptr - io.output.baseAddress!

    // Ethernet
    dstMAC.write(to: ptr)
    hostMAC.write(to: ptr.advanced(by: 6))
    writeUInt16BE(EtherType.ipv4.rawValue, to: ptr.advanced(by: 12))

    // IPv4
    let ipPtr = ptr.advanced(by: ethHeaderLen)
    writeIPv4Header(to: ipPtr, totalLength: UInt16(ipTotalLen), protocol: .icmp,
                    srcIP: srcIP, dstIP: dstIP)

    // ICMP echo reply
    let icmpPtr = ipPtr.advanced(by: ipv4HeaderLen)
    icmpPtr.storeBytes(of: UInt8(0), as: UInt8.self)           // type = echo reply
    icmpPtr.advanced(by: 1).storeBytes(of: UInt8(0), as: UInt8.self)  // code = 0
    writeUInt16BE(0, to: icmpPtr.advanced(by: 2))              // checksum placeholder
    writeUInt16BE(identifier, to: icmpPtr.advanced(by: 4))
    writeUInt16BE(sequenceNumber, to: icmpPtr.advanced(by: 6))

    // RFC 792 checksum: fold pre-computed payload sum with 8-byte header.
    // Addition is commutative, so processing header-last is equivalent to
    // checksumming the full message in one pass. Zero additional payload touch.
    let sum = checksumAdd(payloadSum, UnsafeRawPointer(icmpPtr), 8)
    writeUInt16BE(finalizeChecksum(sum), to: icmpPtr.advanced(by: 2))

    return ofs
}

/// Write Ethernet+IPv4+ICMP Unreachable headers into IOBuffer.output.
/// Returns the output offset, or -1 if full.
/// The original IP packet data is referenced from IOBuffer.input (zero-copy).
///
/// - Parameters:
///   - code: ICMP code — 2 (Protocol Unreachable, default), 3 (Port Unreachable), or 4 (Fragmentation Needed).
///   - type: ICMP type — 3 (Destination Unreachable, default) or 11 (Time Exceeded).
///   - payloadPtr: Pointer to the original IP packet data to include in the ICMP payload (first 28 bytes by RFC 792).
///   - payloadLen: Length of the original IP packet excerpt to be appended after the ICMP header (default 28).
public func buildICMPUnreachableHeader(
    io: IOBuffer,
    hostMAC: MACAddress,
    clientMAC: MACAddress,
    gatewayIP: IPv4Address,
    clientIP: IPv4Address,
    code: UInt8 = 2,
    type: UInt8 = 3,
    payloadPtr: UnsafeRawPointer? = nil,
    payloadLen: Int = 28
) -> Int {
    let hdrLen = 14 + 20 + 8  // Ethernet + IPv4 + ICMP header
    guard let ptr = io.allocOutput(hdrLen) else { return -1 }
    let ofs = ptr - io.output.baseAddress!

    // Ethernet
    clientMAC.write(to: ptr)
    hostMAC.write(to: ptr.advanced(by: 6))
    writeUInt16BE(EtherType.ipv4.rawValue, to: ptr.advanced(by: 12))

    // IPv4: totalLength matches actual ICMP message size
    let ipPtr = ptr.advanced(by: ethHeaderLen)
    let ipTotalLen = 20 + 8 + payloadLen
    writeIPv4Header(to: ipPtr, totalLength: UInt16(ipTotalLen), protocol: .icmp,
                    srcIP: gatewayIP, dstIP: clientIP)

    // ICMP header
    let icmpPtr = ipPtr.advanced(by: ipv4HeaderLen)
    icmpPtr.storeBytes(of: type, as: UInt8.self)
    icmpPtr.advanced(by: 1).storeBytes(of: code, as: UInt8.self)
    writeUInt16BE(0, to: icmpPtr.advanced(by: 2))  // placeholder
    writeUInt32BE(0, to: icmpPtr.advanced(by: 4))

    // Compute ICMP checksum over header + payload.
    var sum = checksumAdd(0, UnsafeRawPointer(icmpPtr), 8)
    if let pptr = payloadPtr, payloadLen > 0 {
        sum = checksumAdd(sum, pptr, payloadLen)
    }
    writeUInt16BE(finalizeChecksum(sum), to: icmpPtr.advanced(by: 2))

    return ofs
}
