/// UDP header (RFC 768) with zero-copy payload.
public struct UDPHeader {
    public let srcPort: UInt16
    public let dstPort: UInt16
    public let length: UInt16        // total bytes: header(8) + payload
    public let checksum: UInt16      // pseudo-header checksum; 0 = unused (IPv4)
    public let payload: PacketBuffer
    public let pseudoSrcAddr: IPv4Address
    public let pseudoDstAddr: IPv4Address
    private let _checksumValid: Bool

    private init(
        srcPort: UInt16, dstPort: UInt16, length: UInt16,
        checksum: UInt16, payload: PacketBuffer,
        pseudoSrcAddr: IPv4Address, pseudoDstAddr: IPv4Address,
        checksumValid: Bool
    ) {
        self.srcPort = srcPort; self.dstPort = dstPort
        self.length = length; self.checksum = checksum
        self.payload = payload
        self.pseudoSrcAddr = pseudoSrcAddr; self.pseudoDstAddr = pseudoDstAddr
        self._checksumValid = checksumValid
    }

    /// Parse a UDP header from a PacketBuffer.
    /// Returns nil if the buffer is shorter than 8 bytes.
    public static func parse(
        from pkt: PacketBuffer,
        pseudoSrcAddr: IPv4Address,
        pseudoDstAddr: IPv4Address
    ) -> UDPHeader? {
        var pkt = pkt
        let tl = pkt.totalLength
        guard tl >= 8 else {
            return nil
        }
        guard pkt.pullUp(8) else {
            return nil
        }

        return pkt.withUnsafeReadableBytes { buf in
            let srcPort  = (UInt16(buf[0]) << 8) | UInt16(buf[1])
            let dstPort  = (UInt16(buf[2]) << 8) | UInt16(buf[3])
            let length   = (UInt16(buf[4]) << 8) | UInt16(buf[5])
            let checksum = (UInt16(buf[6]) << 8) | UInt16(buf[7])

            guard Int(length) >= 8 else {
                return nil
            }
            // Trim to declared length so payload boundary and pseudo-header
            // checksum both respect the UDP length field (not physical buffer).
            let udpLen = min(Int(length), pkt.totalLength)
            let ckPkt: PacketBuffer
            if udpLen < pkt.totalLength {
                guard let t = pkt.slice(from: 0, length: udpLen) else {
                    return nil
                }
                ckPkt = t
            } else {
                ckPkt = pkt
            }
            guard let payload = ckPkt.slice(from: 8, length: udpLen - 8) else {
                return nil
            }

            // RFC 768: checksum 0 means unused (IPv4). Non-zero: verify.
            let valid: Bool
            if checksum == 0 {
                valid = true
            } else if let ck = udpChecksum(
                pseudoSrcAddr: pseudoSrcAddr,
                pseudoDstAddr: pseudoDstAddr,
                udpPayload: ckPkt
            ) {
                valid = (ck == 0xFFFF)
            } else {
                valid = false
            }

            return UDPHeader(
                srcPort: srcPort, dstPort: dstPort, length: length,
                checksum: checksum, payload: payload,
                pseudoSrcAddr: pseudoSrcAddr, pseudoDstAddr: pseudoDstAddr,
                checksumValid: valid
            )
        }
    }

    public func verifyChecksum() -> Bool { _checksumValid }
}

// MARK: - UDP pseudo-header checksum (RFC 768)

/// Compute the UDP checksum from a contiguous UDP header+payload in memory.
///
/// Low-level helper used by both parse-time (`udpChecksum`) and build-time
/// (`buildUDPFrame`, `buildDHCPFrame`) paths. The caller must ensure `udpData`
/// points to `udpLen` bytes of contiguous UDP header + payload.
///
/// Returns 0xFFFF instead of 0 to distinguish "computed zero" from "unused"
/// (RFC 768 §1).
func computeUDPChecksum(
    pseudoSrcAddr: IPv4Address,
    pseudoDstAddr: IPv4Address,
    udpData: UnsafeRawPointer,
    udpLen: Int
) -> UInt16 {
    // pseudo-header: srcIP(4) + dstIP(4) + zero(1) + protocol(1) + udpLength(2) = 12
    var buf = [UInt8](repeating: 0, count: 12 + udpLen)
    var ipOut = [UInt8](repeating: 0, count: 4)
    pseudoSrcAddr.write(to: &ipOut); buf[0...3] = ipOut[0...3]
    pseudoDstAddr.write(to: &ipOut); buf[4...7] = ipOut[0...3]
    buf[9] = IPProtocol.udp.rawValue
    buf[10] = UInt8(udpLen >> 8)
    buf[11] = UInt8(udpLen & 0xFF)
    buf.withUnsafeMutableBytes { dst in
        dst.baseAddress!.advanced(by: 12).copyMemory(from: udpData, byteCount: udpLen)
    }
    let ck = buf.withUnsafeBytes { internetChecksum($0) }
    return ck == 0 ? 0xFFFF : ck
}

/// Compute the UDP checksum over pseudo-header + UDP header + payload.
/// Returns nil if the payload cannot be made contiguous.
/// Returns 0xFFFF instead of 0 to distinguish "computed zero" from "unused" (RFC 768 §1).
public func udpChecksum(
    pseudoSrcAddr: IPv4Address,
    pseudoDstAddr: IPv4Address,
    udpPayload: PacketBuffer
) -> UInt16? {
    var pkt = udpPayload
    let udpLen = UInt16(udpPayload.totalLength)
    guard pkt.pullUp(udpPayload.totalLength) else { return nil }

    return pkt.withUnsafeReadableBytes { udpBuf in
        computeUDPChecksum(
            pseudoSrcAddr: pseudoSrcAddr,
            pseudoDstAddr: pseudoDstAddr,
            udpData: udpBuf.baseAddress!,
            udpLen: Int(udpLen)
        )
    }
}

// MARK: - Build UDP frame

/// Build a complete Ethernet + IPv4 + UDP + payload outbound frame.
///
/// Follows `buildICMPEchoReply`: allocates from `round`, writes raw bytes,
/// computes IP header checksum and UDP pseudo-header checksum.
public func buildUDPFrame(
    hostMAC: MACAddress,
    dstMAC: MACAddress,
    srcIP: IPv4Address,
    dstIP: IPv4Address,
    srcPort: UInt16,
    dstPort: UInt16,
    payload: PacketBuffer,
    round: RoundContext
) -> PacketBuffer? {
    let udpHeaderLen = 8
    let udpTotalLen = udpHeaderLen + payload.totalLength
    let ipTotalLen = 20 + udpTotalLen
    let frameLen = 14 + ipTotalLen

    var frame = round.allocate(capacity: frameLen, headroom: 0)
    guard let ptr = frame.appendPointer(count: frameLen) else { return nil }

    // Ethernet header (14 bytes)
    dstMAC.write(to: ptr)                                        // dst
    hostMAC.write(to: ptr.advanced(by: 6))                       // src
    writeUInt16BE(EtherType.ipv4.rawValue, to: ptr.advanced(by: 12))

    // IPv4 header (20 bytes) at offset 14
    let ipPtr = ptr.advanced(by: ethHeaderLen)
    writeIPv4Header(to: ipPtr, totalLength: UInt16(ipTotalLen), protocol: .udp,
                    srcIP: srcIP, dstIP: dstIP)

    // UDP header (8 bytes) at offset 34
    let udpPtr = ipPtr.advanced(by: ipv4HeaderLen)
    writeUInt16BE(srcPort, to: udpPtr)
    writeUInt16BE(dstPort, to: udpPtr.advanced(by: 2))
    writeUInt16BE(UInt16(udpTotalLen), to: udpPtr.advanced(by: 4))
    writeUInt16BE(0, to: udpPtr.advanced(by: 6))                 // zero checksum

    // UDP payload
    payload.withUnsafeReadableBytes { payloadBuf in
        udpPtr.advanced(by: udpHeaderLen).copyMemory(from: payloadBuf.baseAddress!, byteCount: payloadBuf.count)
    }

    // UDP pseudo-header checksum (RFC 768)
    let ck = computeUDPChecksum(
        pseudoSrcAddr: srcIP, pseudoDstAddr: dstIP,
        udpData: udpPtr, udpLen: udpTotalLen
    )
    writeUInt16BE(ck, to: udpPtr.advanced(by: 6))

    return frame
}
