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

/// Build a complete Ethernet + IPv4 + ICMP Echo Reply frame.
///
/// Follows the ARP reply pattern: construct the full L2 frame from scratch
/// using round.allocate + raw pointer writes. The reply swaps src↔dst at
/// both L2 and L3, changes ICMP type from 8→0, and recalculates both the
/// ICMP checksum (covers header+payload) and IP header checksum.
///
/// Returns nil if allocation fails.
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

    // Ethernet header (14 bytes)
    eth.srcMAC.write(to: ptr)                                 // dst = original sender
    hostMAC.write(to: ptr.advanced(by: 6))                     // src = us
    writeUInt16BE(EtherType.ipv4.rawValue, to: ptr.advanced(by: 12))

    // IPv4 header (20 bytes) at offset 14
    let ipPtr = ptr.advanced(by: ethHeaderLen)
    writeIPv4Header(to: ipPtr, totalLength: UInt16(ipTotalLen), protocol: .icmp,
                    srcIP: ip.dstAddr, dstIP: ip.srcAddr)

    // ICMP header (8 bytes)
    let icmpPtr = ipPtr.advanced(by: ipv4HeaderLen)
    icmpPtr.storeBytes(of: UInt8(0), as: UInt8.self)          // type = echo reply
    icmpPtr.advanced(by: 1).storeBytes(of: UInt8(0), as: UInt8.self) // code = 0
    // Zero checksum field before computing — chunk may contain stale bytes
    writeUInt16BE(0, to: icmpPtr.advanced(by: 2))
    writeUInt16BE(icmp.identifier, to: icmpPtr.advanced(by: 4))
    writeUInt16BE(icmp.sequenceNumber, to: icmpPtr.advanced(by: 6))

    // ICMP payload (copy from request)
    icmp.payload.withUnsafeReadableBytes { payloadBuf in
        icmpPtr.advanced(by: 8).copyMemory(from: payloadBuf.baseAddress!, byteCount: payloadBuf.count)
    }

    // ICMP checksum (RFC 792, over ICMP header + payload)
    let icmpChecksum = internetChecksum(UnsafeRawBufferPointer(start: icmpPtr, count: icmpTotalLen))
    writeUInt16BE(icmpChecksum, to: icmpPtr.advanced(by: 2))

    return reply
}

/// Build an ICMP Destination Unreachable (Protocol Unreachable, Type 3 Code 2) frame
/// in response to an IPv4 packet with an unsupported transport protocol (e.g., TCP).
///
/// RFC 792: the ICMP payload contains the original IP header + first 8 bytes of the
/// original IP payload. This helps the sender identify which packet triggered the error.
///
/// `rawIPPacket`: the full original IPv4 datagram (eth.payload, starting at byte 0 of IP header).
public func buildICMPProtocolUnreachable(
    hostMAC: MACAddress,
    clientMAC: MACAddress,
    gatewayIP: IPv4Address,
    clientIP: IPv4Address,
    rawIPPacket: PacketBuffer,
    round: RoundContext
) -> PacketBuffer? {
    // Extract first 20 bytes (IP header) + 8 bytes (transport header) from original
    var rawIPPacket = rawIPPacket
    let payloadExtractLen = min(28, rawIPPacket.totalLength)
    guard rawIPPacket.pullUp(payloadExtractLen) else { return nil }

    let icmpPayloadLen = 20 + min(8, max(0, rawIPPacket.totalLength - 20))
    let icmpTotalLen = 8 + icmpPayloadLen
    let ipTotalLen = 20 + icmpTotalLen
    let frameLen = 14 + ipTotalLen

    var reply = round.allocate(capacity: frameLen, headroom: 0)
    guard let ptr = reply.appendPointer(count: frameLen) else { return nil }

    // Ethernet header (14 bytes)
    clientMAC.write(to: ptr)
    hostMAC.write(to: ptr.advanced(by: 6))
    writeUInt16BE(EtherType.ipv4.rawValue, to: ptr.advanced(by: 12))

    // IPv4 header (20 bytes) at offset 14
    let ipPtr = ptr.advanced(by: ethHeaderLen)
    writeIPv4Header(to: ipPtr, totalLength: UInt16(ipTotalLen), protocol: .icmp,
                    srcIP: gatewayIP, dstIP: clientIP)

    // ICMP header (8 bytes): Type 3, Code 2
    let icmpPtr = ipPtr.advanced(by: ipv4HeaderLen)
    icmpPtr.storeBytes(of: UInt8(3), as: UInt8.self)          // type = Destination Unreachable
    icmpPtr.advanced(by: 1).storeBytes(of: UInt8(2), as: UInt8.self) // code = Protocol Unreachable
    writeUInt16BE(0, to: icmpPtr.advanced(by: 2))             // checksum placeholder
    writeUInt32BE(0, to: icmpPtr.advanced(by: 4))             // unused (must be zero)

    // ICMP payload: original IP header + first 8 bytes of original transport data
    rawIPPacket.withUnsafeReadableBytes { buf in
        let copyLen = min(payloadExtractLen, buf.count)
        icmpPtr.advanced(by: 8).copyMemory(from: buf.baseAddress!, byteCount: copyLen)
    }

    // ICMP checksum
    let icmpChecksum = internetChecksum(UnsafeRawBufferPointer(start: icmpPtr, count: icmpTotalLen))
    writeUInt16BE(icmpChecksum, to: icmpPtr.advanced(by: 2))

    return reply
}
