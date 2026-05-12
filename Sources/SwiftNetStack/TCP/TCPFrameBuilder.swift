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

    var pseudo: [UInt8] = [
        0, 0, 0, 0,  0, 0, 0, 0,  0, IPProtocol.tcp.rawValue,
        UInt8(tcpTotalLen >> 8), UInt8(tcpTotalLen & 0xFF),
    ]
    srcIP.write(to: &pseudo)
    pseudo.withUnsafeMutableBytes { buf in
        dstIP.write(to: buf.baseAddress!.advanced(by: 4))
    }

    var ckSum = pseudoSum(pseudo)
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
    var pseudo: [UInt8] = [
        0, 0, 0, 0,  0, 0, 0, 0,  0, IPProtocol.tcp.rawValue,
        UInt8(tcpTotalLen >> 8), UInt8(tcpTotalLen & 0xFF),
    ]
    srcIP.write(to: &pseudo)
    pseudo.withUnsafeMutableBytes { buf in
        dstIP.write(to: buf.baseAddress!.advanced(by: 4))
    }

    var ckSum = pseudoSum(pseudo)
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
