import Darwin

// MARK: - Build TCP frame into IOBuffer

/// Write a complete Ethernet+IPv4+TCP header into an IOBuffer output slot.
/// Returns the slot offset, or -1 if output buffer is full.
/// On success, the header is written to `io.output + offset` and caller must
/// track the payload reference separately using OutBatch.
public func buildTCPHeader(
    io: IOBuffer,
    hostMAC: MACAddress, dstMAC: MACAddress,
    srcIP: IPv4Address, dstIP: IPv4Address,
    srcPort: UInt16, dstPort: UInt16,
    seqNumber: UInt32, ackNumber: UInt32,
    flags: TCPFlags, window: UInt16
) -> Int {
    let hdrLen = 54  // Ethernet(14) + IPv4(20) + TCP(20)
    guard let ptr = io.allocOutput(hdrLen) else { return -1 }
    let ofs = ptr - io.output.baseAddress!

    // Ethernet
    dstMAC.write(to: ptr)
    hostMAC.write(to: ptr.advanced(by: 6))
    writeUInt16BE(EtherType.ipv4.rawValue, to: ptr.advanced(by: 12))

    // IPv4 — totalLength = 20 (IP hdr) + 20 (TCP hdr) + payloadLen
    // Payload length is written separately by caller after building the header.
    // We write totalLength as 40 (just headers) — caller adjusts if needed.
    let ipPtr = ptr.advanced(by: ethHeaderLen)
    writeIPv4Header(to: ipPtr, totalLength: 40, protocol: .tcp,
                    srcIP: srcIP, dstIP: dstIP)

    // TCP
    let tcpPtr = ipPtr.advanced(by: ipv4HeaderLen)
    writeUInt16BE(srcPort, to: tcpPtr)
    writeUInt16BE(dstPort, to: tcpPtr.advanced(by: 2))
    writeUInt32BE(seqNumber, to: tcpPtr.advanced(by: 4))
    writeUInt32BE(ackNumber, to: tcpPtr.advanced(by: 8))
    tcpPtr.advanced(by: 12).storeBytes(of: UInt8(0x50), as: UInt8.self)
    tcpPtr.advanced(by: 13).storeBytes(of: flags.rawValue, as: UInt8.self)
    writeUInt16BE(window, to: tcpPtr.advanced(by: 14))
    // Zero checksum and urgent pointer — allocOutput does NOT zero memory,
    // so stale data from a previous round would corrupt the checksum.
    writeUInt16BE(0, to: tcpPtr.advanced(by: 16))
    writeUInt16BE(0, to: tcpPtr.advanced(by: 18))

    return ofs
}

/// Write Ethernet+IPv4+TCP header with variable-length TCP options.
/// Returns the slot offset, or -1 if output buffer is full.
/// Used for SYN/SYN-ACK frames that carry TCP options (MSS, WSCALE, etc.).
public func buildTCPHeaderWithOptions(
    io: IOBuffer,
    hostMAC: MACAddress, dstMAC: MACAddress,
    srcIP: IPv4Address, dstIP: IPv4Address,
    srcPort: UInt16, dstPort: UInt16,
    seqNumber: UInt32, ackNumber: UInt32,
    flags: TCPFlags, window: UInt16,
    options: [UInt8]
) -> Int {
    let tcpHdrLen = 20 + options.count
    let frameHdrLen = 14 + 20 + tcpHdrLen  // Ethernet + IPv4 + TCP
    guard let ptr = io.allocOutput(frameHdrLen) else { return -1 }
    let ofs = ptr - io.output.baseAddress!

    // Ethernet
    dstMAC.write(to: ptr)
    hostMAC.write(to: ptr.advanced(by: 6))
    writeUInt16BE(EtherType.ipv4.rawValue, to: ptr.advanced(by: 12))

    // IPv4
    let ipPtr = ptr.advanced(by: ethHeaderLen)
    let ipTotal = UInt16(20 + tcpHdrLen)
    writeIPv4Header(to: ipPtr, totalLength: ipTotal, protocol: .tcp,
                    srcIP: srcIP, dstIP: dstIP)

    // TCP base header (20 bytes)
    let tcpPtr = ipPtr.advanced(by: ipv4HeaderLen)
    writeUInt16BE(srcPort, to: tcpPtr)
    writeUInt16BE(dstPort, to: tcpPtr.advanced(by: 2))
    writeUInt32BE(seqNumber, to: tcpPtr.advanced(by: 4))
    writeUInt32BE(ackNumber, to: tcpPtr.advanced(by: 8))
    let dataOff = UInt8(tcpHdrLen / 4) << 4
    tcpPtr.advanced(by: 12).storeBytes(of: dataOff, as: UInt8.self)
    tcpPtr.advanced(by: 13).storeBytes(of: flags.rawValue, as: UInt8.self)
    writeUInt16BE(window, to: tcpPtr.advanced(by: 14))
    writeUInt16BE(0, to: tcpPtr.advanced(by: 16))  // checksum (zeroed)
    writeUInt16BE(0, to: tcpPtr.advanced(by: 18))  // urgent

    // TCP options
    options.withUnsafeBytes { optBuf in
        tcpPtr.advanced(by: 20).copyMemory(from: optBuf.baseAddress!, byteCount: options.count)
    }

    return ofs
}

/// Compute TCP checksum for a frame with variable-length TCP header.
public func finalizeTCPChecksumEx(
    io: IOBuffer, hdrOfs: Int,
    srcIP: IPv4Address, dstIP: IPv4Address,
    tcpHdrLen: Int,
    payloadPtr: UnsafeRawPointer?, payloadLen: Int
) {
    let tcpPtr = io.output.baseAddress!.advanced(by: hdrOfs + ethHeaderLen + ipv4HeaderLen)
    let tcpTotalLen = tcpHdrLen + payloadLen

    var ckSum = computePseudoHeaderSum(srcIP: srcIP, dstIP: dstIP,
                                        protocol: IPProtocol.tcp.rawValue, totalLen: tcpTotalLen)
    ckSum = checksumAdd(ckSum, tcpPtr, tcpHdrLen)
    if let pp = payloadPtr, payloadLen > 0 {
        ckSum = checksumAdd(ckSum, pp, payloadLen)
    }
    let ck = finalizeChecksum(ckSum)
    writeUInt16BE(ck, to: tcpPtr.advanced(by: 16))
}

/// Compute and write TCP checksum for a frame built by buildTCPHeader.
/// `hdrOfs` is the offset returned by buildTCPHeader.
/// `payloadPtr` and `payloadLen` describe the TCP payload (may be 0/nil for pure ACK).
public func finalizeTCPChecksum(
    io: IOBuffer, hdrOfs: Int,
    srcIP: IPv4Address, dstIP: IPv4Address,
    payloadPtr: UnsafeRawPointer?, payloadLen: Int
) {
    let tcpPtr = io.output.baseAddress!.advanced(by: hdrOfs + ethHeaderLen + ipv4HeaderLen)
    let tcpHdrLen = 20
    let tcpTotalLen = tcpHdrLen + payloadLen

    // Pseudo-header
    var ckSum = computePseudoHeaderSum(srcIP: srcIP, dstIP: dstIP,
                                        protocol: IPProtocol.tcp.rawValue, totalLen: tcpTotalLen)
    ckSum = checksumAdd(ckSum, tcpPtr, tcpHdrLen)
    if let pp = payloadPtr, payloadLen > 0 {
        ckSum = checksumAdd(ckSum, pp, payloadLen)
    }
    let ck = finalizeChecksum(ckSum)
    writeUInt16BE(ck, to: tcpPtr.advanced(by: 16))

    // Update IPv4 totalLength if payload present
    if payloadLen > 0 {
        let ipPtr = io.output.baseAddress!.advanced(by: hdrOfs + ethHeaderLen)
        let ipTotal = UInt16(ipv4HeaderLen + tcpTotalLen)
        writeUInt16BE(ipTotal, to: ipPtr.advanced(by: 2))
        // Recompute IPv4 checksum — totalLength changed, so the checksum
        // computed by writeIPv4Header is now stale.
        finalizeIPv4Checksum(io: io, hdrOfs: hdrOfs)
    }
}

/// Write IPv4 header checksum for a frame built by buildTCPHeader.
/// Must zero the checksum field first because writeIPv4Header already wrote
/// a non-zero checksum (for totalLength=40) into the field, and
/// internetChecksum includes the field's current value in its computation.
public func finalizeIPv4Checksum(io: IOBuffer, hdrOfs: Int) {
    let ipPtr = io.output.baseAddress!.advanced(by: hdrOfs + ethHeaderLen)
    let ipHdrLen = 20
    writeUInt16BE(0, to: ipPtr.advanced(by: 10))
    let ck = internetChecksum(UnsafeRawBufferPointer(start: ipPtr, count: ipHdrLen))
    writeUInt16BE(ck, to: ipPtr.advanced(by: 10))
}

// MARK: - ACK frame via template (high-throughput path)

/// Build a pure ACK frame from a template, overwriting seq/ack/checksum.
/// Writes header into IOBuffer.output. Returns the output offset, or -1 if full.
/// `outCK` receives the final checksum (for caching).
public func writeAckFromTemplate(
    io: IOBuffer,
    template: [UInt8],
    seq: UInt32, ack: UInt32,
    srcIP: IPv4Address, dstIP: IPv4Address,
    window: UInt16,
    checksum: UInt16?,  // precomputed incremental checksum, or nil
    outCK: inout UInt16
) -> Int {
    guard let ptr = io.allocOutput(54) else { return -1 }
    let ofs = ptr - io.output.baseAddress!

    // Copy 54-byte template
    template.withUnsafeBytes { tBuf in
        ptr.copyMemory(from: tBuf.baseAddress!, byteCount: 54)
    }

    // Overwrite dynamic fields
    writeUInt32BE(seq, to: ptr.advanced(by: 38))
    writeUInt32BE(ack, to: ptr.advanced(by: 42))
    if window != 65535 {
        writeUInt16BE(window, to: ptr.advanced(by: 48))
    }

    let ck: UInt16
    if let precomputed = checksum {
        ck = precomputed
    } else {
        ck = computeTCPChecksum(
            pseudoSrcAddr: srcIP, pseudoDstAddr: dstIP,
            tcpData: ptr.advanced(by: 34), tcpLen: 20
        )
    }
    outCK = ck
    writeUInt16BE(ck, to: ptr.advanced(by: 50))

    return ofs
}

// MARK: - ACK template construction

/// Build a 54-byte ACK template (Ethernet+IPv4+TCP headers, static fields only).
/// Returns a [UInt8] suitable for caching in TCPConnection.ackTemplate.
public func makeAckTemplate(
    hostMAC: MACAddress, vmMAC: MACAddress,
    srcIP: IPv4Address, dstIP: IPv4Address,
    srcPort: UInt16, dstPort: UInt16,
    window: UInt16
) -> [UInt8] {
    var t = [UInt8](repeating: 0, count: 54)

    // Ethernet
    vmMAC.write(to: &t)
    hostMAC.write(to: &t[6])
    writeUInt16BE(EtherType.ipv4.rawValue, to: &t[12])

    // IPv4
    let ipPtr = 14
    writeIPv4Header(to: &t[ipPtr], totalLength: 40, protocol: .tcp,
                    srcIP: srcIP, dstIP: dstIP)

    // TCP
    let tcpPtr = 34
    writeUInt16BE(srcPort, to: &t[tcpPtr])
    writeUInt16BE(dstPort, to: &t[tcpPtr + 2])
    // seq (38..<42), ack (42..<46) — zero placeholder
    t[tcpPtr + 12] = 0x50
    t[tcpPtr + 13] = TCPFlags.ack.rawValue
    writeUInt16BE(window, to: &t[tcpPtr + 14])
    // checksum (50..<52), urgent (52..<54) — zero

    return t
}

#if DEBUG
func computeACKFullChecksum(
    tmpl: [UInt8], seq: UInt32, ack: UInt32,
    srcIP: IPv4Address, dstIP: IPv4Address
) -> UInt16 {
    var hdr = [UInt8](repeating: 0, count: 20)
    tmpl.withUnsafeBytes { tBuf in
        hdr.withUnsafeMutableBytes { hBuf in
            hBuf.baseAddress!.copyMemory(from: tBuf.baseAddress!.advanced(by: 34), byteCount: 20)
        }
    }
    writeUInt32BE(seq, to: &hdr[4])
    writeUInt32BE(ack, to: &hdr[8])
    return hdr.withUnsafeBytes { buf in
        computeTCPChecksum(pseudoSrcAddr: srcIP, pseudoDstAddr: dstIP,
                           tcpData: buf.baseAddress!, tcpLen: 20)
    }
}
#endif

// MARK: - RFC 7323 TSopt option builder

/// Build 12-byte TSopt option: NOP+NOP+kind=8+len=10+TSval+TSecr.
/// One allocation per handshake — not in the hot path.
public func buildTSoptOption(tsval: UInt32, tsecr: UInt32) -> [UInt8] {
    var opt = [UInt8](repeating: 0, count: 12)
    opt[0] = 1; opt[1] = 1   // NOP, NOP
    opt[2] = 8; opt[3] = 10  // TSopt kind, len
    writeUInt32BE(tsval, to: &opt[4])
    writeUInt32BE(tsecr, to: &opt[8])
    return opt
}

// MARK: - Extended ACK template (66-byte, with TSopt)

/// Build a 66-byte ACK template (Ethernet+IPv4+TCP+NOP+NOP+TSopt).
/// TCP header = 32 bytes (20 base + 12 options). Data offset = 8.
public func makeAckTemplateWithTSopt(
    hostMAC: MACAddress, vmMAC: MACAddress,
    srcIP: IPv4Address, dstIP: IPv4Address,
    srcPort: UInt16, dstPort: UInt16,
    window: UInt16
) -> [UInt8] {
    var t = [UInt8](repeating: 0, count: 66)

    // Ethernet
    vmMAC.write(to: &t)
    hostMAC.write(to: &t[6])
    writeUInt16BE(EtherType.ipv4.rawValue, to: &t[12])

    // IPv4 — totalLength = 20 + 32 = 52
    writeIPv4Header(to: &t[14], totalLength: 52, protocol: .tcp,
                    srcIP: srcIP, dstIP: dstIP)

    // TCP base header (20 bytes at offset 34)
    let tcpOfs = 34
    writeUInt16BE(srcPort, to: &t[tcpOfs])
    writeUInt16BE(dstPort, to: &t[tcpOfs + 2])
    // seq(38-41), ack(42-45) — zero placeholder
    t[tcpOfs + 12] = 0x80  // data offset = 8 (32/4)
    t[tcpOfs + 13] = TCPFlags.ack.rawValue
    writeUInt16BE(window, to: &t[tcpOfs + 14])
    // checksum(50-51), urgent(52-53) — zero

    // TCP options: NOP+NOP+TSopt(8,10,TSval,Tsecr) = 12 bytes at offset 54
    t[54] = 1; t[55] = 1    // NOP, NOP
    t[56] = 8; t[57] = 10   // TSopt kind, len
    // TSval(58-61), TSecr(62-65) — zero placeholder

    return t
}

/// Write ACK from 66-byte TSopt template. Always uses full checksum
/// (TSval changes every ACK, making incremental checksum pointless).
/// Returns output offset, writes final checksum to `outCK`.
public func writeAckFromTemplateExt(
    io: IOBuffer,
    template: [UInt8],
    seq: UInt32, ack: UInt32,
    srcIP: IPv4Address, dstIP: IPv4Address,
    window: UInt16,
    tsval: UInt32, tsecr: UInt32,
    outCK: inout UInt16
) -> Int {
    guard let ptr = io.allocOutput(66) else { return -1 }
    let ofs = ptr - io.output.baseAddress!

    template.withUnsafeBytes { tBuf in
        ptr.copyMemory(from: tBuf.baseAddress!, byteCount: 66)
    }

    // Overwrite dynamic fields
    writeUInt32BE(seq, to: ptr.advanced(by: 38))
    writeUInt32BE(ack, to: ptr.advanced(by: 42))
    if window != 65535 {
        writeUInt16BE(window, to: ptr.advanced(by: 48))
    }
    writeUInt32BE(tsval, to: ptr.advanced(by: 58))
    writeUInt32BE(tsecr, to: ptr.advanced(by: 62))

    // Full checksum over 32-byte TCP header
    writeUInt16BE(0, to: ptr.advanced(by: 50))
    let ck = computeTCPChecksum(
        pseudoSrcAddr: srcIP, pseudoDstAddr: dstIP,
        tcpData: ptr.advanced(by: 34), tcpLen: 32
    )
    outCK = ck
    writeUInt16BE(ck, to: ptr.advanced(by: 50))

    return ofs
}

// MARK: - RFC 1146 incremental TCP checksum

func computeIncrementalTCPChecksum(
    oldCK: UInt16, oldSeq: UInt32, newSeq: UInt32,
    oldAck: UInt32, newAck: UInt32
) -> UInt16 {
    // Use UInt64 to avoid losing carries from multiple &+= operations.
    var sum: UInt64 = UInt64(~oldCK)
    sum &+= UInt64(~(oldSeq >> 16))
    sum &+= UInt64(~(oldSeq & 0xFFFF))
    sum &+= UInt64(~(oldAck >> 16))
    sum &+= UInt64(~(oldAck & 0xFFFF))
    sum &+= UInt64(newSeq >> 16)
    sum &+= UInt64(newSeq & 0xFFFF)
    sum &+= UInt64(newAck >> 16)
    sum &+= UInt64(newAck & 0xFFFF)
    // Fold 64-bit sum down to 16-bit
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16)
    }
    return ~UInt16(sum & 0xFFFF)
}
