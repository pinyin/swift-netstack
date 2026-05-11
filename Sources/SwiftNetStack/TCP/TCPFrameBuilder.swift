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
    let headerOnlyLen = ethHeaderLen + ipv4HeaderLen + tcpHeaderLen
    let frameLen = headerOnlyLen + (payloadLen > 0 ? 0 : payloadLen)  // single buffer only for no-payload

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

    // TCP checksum (pseudo-header + TCP header + payload)
    if let payload = payload, payloadLen > 0 {
        // Scatter-gather: compute checksum across header + all payload views
        var pseudo: [UInt8] = [
            0, 0, 0, 0,  0, 0, 0, 0,  0, IPProtocol.tcp.rawValue,
            UInt8(tcpTotalLen >> 8), UInt8(tcpTotalLen & 0xFF),
        ]
        srcIP.write(to: &pseudo)
        pseudo.withUnsafeMutableBytes { buf in
            dstIP.write(to: buf.baseAddress!.advanced(by: 4))
        }
        var ckSum = pseudoSum(pseudo)
        ckSum = checksumAdd(ckSum, tcpPtr, tcpHeaderLen)
        ckSum = checksumAddViews(ckSum, payload._views)
        let ck = finalizeChecksum(ckSum)
        writeUInt16BE(ck, to: tcpPtr.advanced(by: 16))
        // Zero-copy: attach payload views to the header buffer
        frame.appendView(payload)
    } else {
        let ck = computeTCPChecksum(
            pseudoSrcAddr: srcIP, pseudoDstAddr: dstIP,
            tcpData: tcpPtr, tcpLen: tcpTotalLen
        )
        writeUInt16BE(ck, to: tcpPtr.advanced(by: 16))
    }

    return frame
}

// MARK: - ACK frame template

/// Build a 54-byte ACK template containing all static Ethernet+IPv4+TCP fields.
/// The returned byte array is suitable for storage in TCPConnection.ackTemplate.
/// Only seq (offset 38), ack (offset 42), and checksum (offset 50) are dynamic.
func makeAckTemplate(
    hostMAC: MACAddress,
    vmMAC: MACAddress,
    srcIP: IPv4Address,
    dstIP: IPv4Address,
    srcPort: UInt16,
    dstPort: UInt16,
    window: UInt16
) -> [UInt8] {
    var t = [UInt8](repeating: 0, count: 54)

    // Ethernet header (14 bytes)
    vmMAC.write(to: &t)                                       // dstMAC     0..<6
    hostMAC.write(to: &t[6])                                  // srcMAC     6..<12
    writeUInt16BE(EtherType.ipv4.rawValue, to: &t[12])        // EtherType 12..<14

    // IPv4 header (20 bytes) at offset 14
    let ipPtr = 14
    writeIPv4Header(to: &t[ipPtr], totalLength: 40, protocol: .tcp,
                    srcIP: srcIP, dstIP: dstIP)

    // TCP header (20 bytes) at offset 34
    let tcpPtr = 34
    writeUInt16BE(srcPort, to: &t[tcpPtr])                    // srcPort   34..<36
    writeUInt16BE(dstPort, to: &t[tcpPtr + 2])                // dstPort   36..<38
    // seq (38..<42), ack (42..<46) — zero placeholder, overwritten each send
    t[tcpPtr + 12] = 0x50                                     // dataOffset 46
    t[tcpPtr + 13] = TCPFlags.ack.rawValue                    // flags      47
    writeUInt16BE(window, to: &t[tcpPtr + 14])                // window    48..<50
    // checksum (50..<52), urgent (52..<54) — zero placeholder

    return t
}

/// Build a pure ACK frame from a pre-built template, overwriting only
/// seq, ack, and TCP checksum. This replaces the full `buildTCPFrame` path
/// for ACK-only segments and saves ~15 field writes per ACK.
///
/// If `checksum` is provided (from incremental computation), it is used directly
/// instead of computing the full checksum from scratch.
/// `outCK` is always set to the final checksum written to the frame.
func buildTCPAckFrame(
    template: [UInt8],
    seq: UInt32,
    ack: UInt32,
    srcIP: IPv4Address,
    dstIP: IPv4Address,
    round: RoundContext,
    checksum: UInt16? = nil,
    outCK: inout UInt16
) -> PacketBuffer? {
    var frame = round.allocate(capacity: 54, headroom: 0)
    guard let ptr = frame.appendPointer(count: 54) else { return nil }

    // Copy entire 54-byte template
    template.withUnsafeBytes { tBuf in
        ptr.copyMemory(from: tBuf.baseAddress!, byteCount: 54)
    }

    // Overwrite sequence number (offset 38) and acknowledgment number (offset 42)
    writeUInt32BE(seq, to: ptr.advanced(by: 38))
    writeUInt32BE(ack, to: ptr.advanced(by: 42))

    // Compute TCP checksum (incremental or full)
    let ck: UInt16
    if let precomputed = checksum {
        ck = precomputed
    } else {
        ck = computeTCPChecksum(
            pseudoSrcAddr: srcIP,
            pseudoDstAddr: dstIP,
            tcpData: ptr.advanced(by: 34), tcpLen: 20
        )
    }
    outCK = ck
    writeUInt16BE(ck, to: ptr.advanced(by: 50))

    return frame
}

/// Compute the full TCP checksum for a template-based ACK with given seq/ack.
/// Used in DEBUG builds to verify the incremental checksum result.
#if DEBUG
func computeACKFullChecksum(
    tmpl: [UInt8], seq: UInt32, ack: UInt32,
    srcIP: IPv4Address, dstIP: IPv4Address
) -> UInt16 {
    var hdr = [UInt8](repeating: 0, count: 20)
    // Copy TCP header portion of the template (offset 34..<54)
    tmpl.withUnsafeBytes { tBuf in
        hdr.withUnsafeMutableBytes { hBuf in
            hBuf.baseAddress!.copyMemory(from: tBuf.baseAddress!.advanced(by: 34), byteCount: 20)
        }
    }
    // Overwrite seq (offset 4 in TCP header) and ack (offset 8)
    writeUInt32BE(seq, to: &hdr[4])
    writeUInt32BE(ack, to: &hdr[8])
    // Checksum bytes at offset 16 are zero from template
    return hdr.withUnsafeBytes { buf in
        computeTCPChecksum(pseudoSrcAddr: srcIP, pseudoDstAddr: dstIP,
                           tcpData: buf.baseAddress!, tcpLen: 20)
    }
}
#endif

// MARK: - RFC 1146 incremental TCP checksum

/// Compute an updated TCP checksum for a pure ACK frame using the delta method
/// defined in RFC 1146. Only seq and ack fields changed from the previous ACK.
///
/// - Parameters:
///   - oldCK: Checksum of the previous ACK frame
///   - oldSeq: Sequence number of the previous ACK frame
///   - newSeq: New sequence number
///   - oldAck: Acknowledgment number of the previous ACK frame
///   - newAck: New acknowledgment number
/// - Returns: Updated one's-complement checksum
func computeIncrementalTCPChecksum(
    oldCK: UInt16, oldSeq: UInt32, newSeq: UInt32,
    oldAck: UInt32, newAck: UInt32
) -> UInt16 {
    // Start with the original one's-complement sum (~checksum)
    var sum: UInt32 = UInt32(~oldCK)

    // Remove old seq (2 words: high 16 bits, low 16 bits)
    let oldSeqHi = UInt16(oldSeq >> 16)
    let oldSeqLo = UInt16(oldSeq & 0xFFFF)
    sum &+= UInt32(~oldSeqHi)
    sum &+= UInt32(~oldSeqLo)

    // Remove old ack (2 words)
    let oldAckHi = UInt16(oldAck >> 16)
    let oldAckLo = UInt16(oldAck & 0xFFFF)
    sum &+= UInt32(~oldAckHi)
    sum &+= UInt32(~oldAckLo)

    // Add new seq (2 words)
    sum &+= UInt32(newSeq >> 16)
    sum &+= UInt32(newSeq & 0xFFFF)

    // Add new ack (2 words)
    sum &+= UInt32(newAck >> 16)
    sum &+= UInt32(newAck & 0xFFFF)

    return finalizeChecksum(sum)
}
