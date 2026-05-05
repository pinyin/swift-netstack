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
        guard pkt.totalLength >= 8 else { return nil }
        guard pkt.pullUp(8) else { return nil }

        return pkt.withUnsafeReadableBytes { buf in
            let type = buf[0]
            let code = buf[1]
            let checksum = (UInt16(buf[2]) << 8) | UInt16(buf[3])
            let identifier = (UInt16(buf[4]) << 8) | UInt16(buf[5])
            let sequenceNumber = (UInt16(buf[6]) << 8) | UInt16(buf[7])

            let payload = pkt.slice(from: 8, length: pkt.totalLength - 8)

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
    ourMAC: MACAddress,
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
    ourMAC.write(to: ptr.advanced(by: 6))                     // src = us
    writeUInt16BE(EtherType.ipv4.rawValue, to: ptr.advanced(by: 12))

    // IPv4 header (20 bytes)
    let ipPtr = ptr.advanced(by: 14)
    ipPtr.storeBytes(of: UInt8(0x45), as: UInt8.self)         // version=4, IHL=5
    ipPtr.advanced(by: 1).storeBytes(of: UInt8(0), as: UInt8.self) // DSCP+ECN
    writeUInt16BE(UInt16(ipTotalLen), to: ipPtr.advanced(by: 2))    // total length
    writeUInt16BE(0, to: ipPtr.advanced(by: 4))               // identification
    writeUInt16BE(0x4000, to: ipPtr.advanced(by: 6))          // flags=DF, offset=0
    ipPtr.advanced(by: 8).storeBytes(of: UInt8(64), as: UInt8.self) // TTL
    ipPtr.advanced(by: 9).storeBytes(of: IPProtocol.icmp.rawValue, as: UInt8.self)
    // checksum at offset 10-11 — computed below after we have all fields
    ip.dstAddr.write(to: ipPtr.advanced(by: 12))              // src = original dst
    ip.srcAddr.write(to: ipPtr.advanced(by: 16))              // dst = original src

    // IP header checksum (RFC 791, over the 20-byte header)
    let ipChecksum = internetChecksum(UnsafeRawBufferPointer(start: ipPtr, count: 20))
    writeUInt16BE(ipChecksum, to: ipPtr.advanced(by: 10))

    // ICMP header (8 bytes)
    let icmpPtr = ipPtr.advanced(by: 20)
    icmpPtr.storeBytes(of: UInt8(0), as: UInt8.self)          // type = echo reply
    icmpPtr.advanced(by: 1).storeBytes(of: UInt8(0), as: UInt8.self) // code = 0
    // checksum at offset 2-3 — computed below (zero for now)
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
