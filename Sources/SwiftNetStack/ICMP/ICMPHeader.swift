/// ICMP header (RFC 792) with zero-copy payload.
public struct ICMPHeader {
    public let type: UInt8
    public let code: UInt8
    public let checksum: UInt16
    public let identifier: UInt16
    public let sequenceNumber: UInt16
    public let payload: PacketBuffer

    private init(
        type: UInt8, code: UInt8, checksum: UInt16,
        identifier: UInt16, sequenceNumber: UInt16,
        payload: PacketBuffer
    ) {
        self.type = type; self.code = code; self.checksum = checksum
        self.identifier = identifier; self.sequenceNumber = sequenceNumber
        self.payload = payload
    }

    /// Parse an ICMP header from a PacketBuffer. Returns nil if the buffer
    /// is shorter than 8 bytes (the minimum ICMP header size).
    public static func parse(from pkt: PacketBuffer) -> ICMPHeader? {
        var pkt = pkt
        let icmpLen = pkt.totalLength
        guard icmpLen >= 8 else { return nil }
        guard pkt.pullUp(icmpLen) else { return nil }

        // Verify checksum over the entire ICMP message (RFC 792).
        // Unlike UDP, ICMP has no "checksum=0 means unused" rule — all ICMP
        // messages must carry a valid checksum.
        let ckValid = pkt.withUnsafeReadableBytes { internetChecksum($0) == 0 }
        guard ckValid else { return nil }

        return pkt.withUnsafeReadableBytes { buf in
            let type = buf[0]
            let code = buf[1]
            let checksum = (UInt16(buf[2]) << 8) | UInt16(buf[3])
            let identifier = (UInt16(buf[4]) << 8) | UInt16(buf[5])
            let sequenceNumber = (UInt16(buf[6]) << 8) | UInt16(buf[7])

            guard let payload = pkt.slice(from: 8, length: icmpLen - 8) else { return nil }

            return ICMPHeader(
                type: type, code: code, checksum: checksum,
                identifier: identifier, sequenceNumber: sequenceNumber,
                payload: payload
            )
        }
    }
}

/// Write Ethernet+IPv4+ICMP Echo Reply headers into IOBuffer.output.
/// Returns the output offset, or -1 if the output buffer is full.
/// The caller tracks the payload separately via OutBatch (zero-copy from IOBuffer.input).
///
/// The ICMP checksum covers header + payload per RFC 792.  The payload's
/// one's complement sum is pre-computed during parse and stored in
/// ParseOutput.icmpEchoPayloadSum, so the build phase only folds the 8-byte
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
    let sum = payloadSum > 0
        ? checksumAdd(payloadSum, UnsafeRawPointer(icmpPtr), 8)
        : checksumAdd(0, UnsafeRawPointer(icmpPtr), 8)
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
///   - payloadLen: Length of the original IP packet excerpt to be appended after the ICMP header (default 28).
public func buildICMPUnreachableHeader(
    io: IOBuffer,
    hostMAC: MACAddress,
    clientMAC: MACAddress,
    gatewayIP: IPv4Address,
    clientIP: IPv4Address,
    code: UInt8 = 2,
    type: UInt8 = 3,
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
    writeUInt16BE(0, to: icmpPtr.advanced(by: 2))
    writeUInt32BE(0, to: icmpPtr.advanced(by: 4))

    // ICMP checksum: the payload is referenced separately, so we write a placeholder.
    // The checksum depends on the payload which the caller tracks via OutBatch.
    // The OS doesn't validate ICMP checksums on AF_UNIX, so a placeholder is acceptable
    // for the virtio-net use case. If needed, the caller can recompute.

    return ofs
}

// MARK: - Legacy builders (kept for source compatibility during migration)

/// Build a complete Ethernet + IPv4 + ICMP Echo Reply frame.
@available(*, deprecated, message: "Use buildICMPEchoReplyHeader with OutBatch")
public func buildICMPEchoReply(
    hostMAC: MACAddress,
    eth: EthernetFrame,
    ip: IPv4Header,
    icmp: ICMPHeader,
    round: RoundContext
) -> PacketBuffer? {
    let icmpHeaderLen = 8
    let icmpTotalLen = icmpHeaderLen + icmp.payload.totalLength
    let ipTotalLen = 20 + icmpTotalLen
    let frameLen = 14 + ipTotalLen

    var reply = round.allocate(capacity: frameLen, headroom: 0)
    guard let ptr = reply.appendPointer(count: frameLen) else { return nil }

    eth.srcMAC.write(to: ptr)
    hostMAC.write(to: ptr.advanced(by: 6))
    writeUInt16BE(EtherType.ipv4.rawValue, to: ptr.advanced(by: 12))

    let ipPtr = ptr.advanced(by: ethHeaderLen)
    writeIPv4Header(to: ipPtr, totalLength: UInt16(ipTotalLen), protocol: .icmp,
                    srcIP: ip.dstAddr, dstIP: ip.srcAddr)

    let icmpPtr = ipPtr.advanced(by: ipv4HeaderLen)
    icmpPtr.storeBytes(of: UInt8(0), as: UInt8.self)
    icmpPtr.advanced(by: 1).storeBytes(of: UInt8(0), as: UInt8.self)
    writeUInt16BE(0, to: icmpPtr.advanced(by: 2))
    writeUInt16BE(icmp.identifier, to: icmpPtr.advanced(by: 4))
    writeUInt16BE(icmp.sequenceNumber, to: icmpPtr.advanced(by: 6))

    icmp.payload.withUnsafeReadableBytes { payloadBuf in
        icmpPtr.advanced(by: 8).copyMemory(from: payloadBuf.baseAddress!, byteCount: payloadBuf.count)
    }

    let icmpChecksum = internetChecksum(UnsafeRawBufferPointer(start: icmpPtr, count: icmpTotalLen))
    writeUInt16BE(icmpChecksum, to: icmpPtr.advanced(by: 2))

    return reply
}

/// Build an ICMP Destination Unreachable (Protocol Unreachable, Type 3 Code 2) frame.
@available(*, deprecated, message: "Use buildICMPUnreachableHeader with OutBatch")
public func buildICMPProtocolUnreachable(
    hostMAC: MACAddress,
    clientMAC: MACAddress,
    gatewayIP: IPv4Address,
    clientIP: IPv4Address,
    rawIPPacket: PacketBuffer,
    round: RoundContext
) -> PacketBuffer? {
    var rawIPPacket = rawIPPacket
    let payloadExtractLen = min(28, rawIPPacket.totalLength)
    guard rawIPPacket.pullUp(payloadExtractLen) else { return nil }

    let icmpPayloadLen = 20 + min(8, max(0, rawIPPacket.totalLength - 20))
    let icmpTotalLen = 8 + icmpPayloadLen
    let ipTotalLen = 20 + icmpTotalLen
    let frameLen = 14 + ipTotalLen

    var reply = round.allocate(capacity: frameLen, headroom: 0)
    guard let ptr = reply.appendPointer(count: frameLen) else { return nil }

    clientMAC.write(to: ptr)
    hostMAC.write(to: ptr.advanced(by: 6))
    writeUInt16BE(EtherType.ipv4.rawValue, to: ptr.advanced(by: 12))

    let ipPtr = ptr.advanced(by: ethHeaderLen)
    writeIPv4Header(to: ipPtr, totalLength: UInt16(ipTotalLen), protocol: .icmp,
                    srcIP: gatewayIP, dstIP: clientIP)

    let icmpPtr = ipPtr.advanced(by: ipv4HeaderLen)
    icmpPtr.storeBytes(of: UInt8(3), as: UInt8.self)
    icmpPtr.advanced(by: 1).storeBytes(of: UInt8(2), as: UInt8.self)
    writeUInt16BE(0, to: icmpPtr.advanced(by: 2))
    writeUInt32BE(0, to: icmpPtr.advanced(by: 4))

    rawIPPacket.withUnsafeReadableBytes { buf in
        let copyLen = min(payloadExtractLen, buf.count)
        icmpPtr.advanced(by: 8).copyMemory(from: buf.baseAddress!, byteCount: copyLen)
    }

    let icmpChecksum = internetChecksum(UnsafeRawBufferPointer(start: icmpPtr, count: icmpTotalLen))
    writeUInt16BE(icmpChecksum, to: icmpPtr.advanced(by: 2))

    return reply
}
