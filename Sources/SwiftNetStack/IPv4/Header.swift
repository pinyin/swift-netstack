/// Parsed IPv4 header. The payload is a zero-copy slice after the IP header.
public struct IPv4Header {
    public let version: UInt8
    public let ihl: UInt8
    public let totalLength: UInt16
    public let identification: UInt16
    public let flags: UInt8
    public let fragmentOffset: UInt16
    public let ttl: UInt8
    public let `protocol`: IPProtocol
    public let checksum: UInt16
    public let srcAddr: IPv4Address
    public let dstAddr: IPv4Address
    public let payload: PacketBuffer

    private init(
        version: UInt8, ihl: UInt8, totalLength: UInt16, identification: UInt16,
        flags: UInt8, fragmentOffset: UInt16, ttl: UInt8, protocol: IPProtocol,
        checksum: UInt16, srcAddr: IPv4Address, dstAddr: IPv4Address,
        payload: PacketBuffer
    ) {
        self.version = version; self.ihl = ihl; self.totalLength = totalLength
        self.identification = identification; self.flags = flags
        self.fragmentOffset = fragmentOffset; self.ttl = ttl
        self.protocol = `protocol`; self.checksum = checksum
        self.srcAddr = srcAddr; self.dstAddr = dstAddr
        self.payload = payload
    }

    /// Parse an IPv4 header from a PacketBuffer. Returns nil on validation failure.
    public static func parse(from pkt: PacketBuffer) -> IPv4Header? {
        guard pkt.totalLength >= 20 else { return nil }

        return pkt.withUnsafeReadableBytes { buf -> IPv4Header? in
            let versionIHL = buf[0]
            let version = versionIHL >> 4
            let ihl = versionIHL & 0x0F
            guard version == 4, ihl >= 5 else { return nil }

            let headerLen = Int(ihl) * 4
            guard pkt.totalLength >= headerLen else { return nil }

            let totalLength = (UInt16(buf[2]) << 8) | UInt16(buf[3])
            let identification = (UInt16(buf[4]) << 8) | UInt16(buf[5])
            let flagsFrag = (UInt16(buf[6]) << 8) | UInt16(buf[7])
            let flags = UInt8(flagsFrag >> 13)
            let fragmentOffset = flagsFrag & 0x1FFF
            let ttl = buf[8]
            let rawProtocol = buf[9]
            let checksum = (UInt16(buf[10]) << 8) | UInt16(buf[11])

            guard let proto = IPProtocol(rawValue: rawProtocol) else { return nil }

            let srcAddr = IPv4Address(UnsafeRawBufferPointer(rebasing: buf[12..<16]))
            let dstAddr = IPv4Address(UnsafeRawBufferPointer(rebasing: buf[16..<20]))

            let payload = pkt.slice(from: headerLen, length: pkt.totalLength - headerLen)

            return IPv4Header(
                version: version, ihl: ihl, totalLength: totalLength,
                identification: identification, flags: flags,
                fragmentOffset: fragmentOffset, ttl: ttl, protocol: proto,
                checksum: checksum, srcAddr: srcAddr, dstAddr: dstAddr,
                payload: payload
            )
        }
    }

    /// RFC 791 internet checksum over the IP header (not payload).
    /// Returns true if the header checksum is valid.
    public func verifyChecksum() -> Bool {
        var sum: UInt32 = 0

        let verIHL = UInt16((version << 4) | ihl)
        sum += UInt32(verIHL << 8)  // DSCP/ECN = 0 for checksum
        sum += UInt32(totalLength)
        sum += UInt32(identification)
        sum += UInt32((UInt16(flags) << 13) | fragmentOffset)
        sum += UInt32((UInt16(ttl) << 8) | UInt16(`protocol`.rawValue))
        // checksum field is zero when computing
        sum += UInt32(srcAddr.addr >> 16)
        sum += UInt32(srcAddr.addr & 0xFFFF)
        sum += UInt32(dstAddr.addr >> 16)
        sum += UInt32(dstAddr.addr & 0xFFFF)

        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16)
        }
        return UInt16(~sum & 0xFFFF) == checksum
    }
}

// MARK: - Internet checksum utility

/// RFC 791 internet checksum over an UnsafeRawBufferPointer.
/// Returns the one's complement of the one's complement sum.
public func internetChecksum(_ buf: UnsafeRawBufferPointer) -> UInt16 {
    var sum: UInt32 = 0
    var i = 0
    let count = buf.count
    while i + 1 < count {
        sum += UInt32((UInt16(buf[i]) << 8) | UInt16(buf[i + 1]))
        i += 2
    }
    if i < count {
        sum += UInt32(buf[i]) << 8
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16)
    }
    return ~UInt16(sum & 0xFFFF)
}
