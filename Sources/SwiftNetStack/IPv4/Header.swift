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
        payload: PacketBuffer, checksumValid: Bool
    ) {
        self.version = version; self.ihl = ihl; self.totalLength = totalLength
        self.identification = identification; self.flags = flags
        self.fragmentOffset = fragmentOffset; self.ttl = ttl
        self.protocol = `protocol`; self.checksum = checksum
        self.srcAddr = srcAddr; self.dstAddr = dstAddr
        self.payload = payload
        self._checksumValid = checksumValid
    }

    /// Parse an IPv4 header from a PacketBuffer. Returns nil on validation failure.
    public static func parse(from pkt: PacketBuffer) -> IPv4Header? {
        var pkt = pkt
        guard pkt.totalLength >= 20 else { return nil }
        // Pull up the maximum header size (60 bytes) to ensure single-view access
        // regardless of IHL value. The common case (IHL=5, 20 bytes) is a fast-path
        // no-op when the first view already covers it.
        let maxHeaderLen = Swift.min(60, pkt.totalLength)
        guard pkt.pullUp(maxHeaderLen) else { return nil }

        return pkt.withUnsafeReadableBytes { buf -> IPv4Header? in
            let versionIHL = buf[0]
            let version = versionIHL >> 4
            let ihl = versionIHL & 0x0F
            guard version == 4, ihl >= 5 else { return nil }

            let headerLen = Int(ihl) * 4
            guard pkt.totalLength >= headerLen else { return nil }
            // IP options (IHL > 5) are parsed for header size and checksum validation
            // but not exposed to upper layers. Strict Source Route, Record Route, and
            // Timestamp options are silently ignored — acceptable for a prototype that
            // does not forward packets between interfaces.

            let totalLength = (UInt16(buf[2]) << 8) | UInt16(buf[3])
            let identification = (UInt16(buf[4]) << 8) | UInt16(buf[5])
            let flagsFrag = (UInt16(buf[6]) << 8) | UInt16(buf[7])
            // RFC 791 §3.2.1.3: reserved bit (bit 15 of flagsFrag) must be 0
            guard flagsFrag & 0x8000 == 0 else { return nil }
            let flags = UInt8(flagsFrag >> 13)
            let fragmentOffset = flagsFrag & 0x1FFF
            let ttl = buf[8]
            let rawProtocol = buf[9]
            let checksum = (UInt16(buf[10]) << 8) | UInt16(buf[11])

            guard let proto = IPProtocol(rawValue: rawProtocol) else { return nil }

            let srcAddr = IPv4Address(UnsafeRawBufferPointer(rebasing: buf[12..<16]))
            let dstAddr = IPv4Address(UnsafeRawBufferPointer(rebasing: buf[16..<20]))

            let declaredPayloadLen = Int(totalLength) - headerLen
            let availablePayloadLen = pkt.totalLength - headerLen
            let payloadLen = min(declaredPayloadLen, availablePayloadLen)
            guard payloadLen >= 0, let payload = pkt.slice(from: headerLen, length: payloadLen) else { return nil }

            // Compute checksum from raw bytes covering IHL*4 bytes (includes options)
            let headerBuf = UnsafeRawBufferPointer(start: buf.baseAddress!, count: headerLen)
            let checksumValid = internetChecksum(headerBuf) == 0

            return IPv4Header(
                version: version, ihl: ihl, totalLength: totalLength,
                identification: identification, flags: flags,
                fragmentOffset: fragmentOffset, ttl: ttl, protocol: proto,
                checksum: checksum, srcAddr: srcAddr, dstAddr: dstAddr,
                payload: payload, checksumValid: checksumValid
            )
        }
    }

    /// RFC 791 internet checksum over the IP header (not payload).
    /// Returns true if the header checksum is valid.
    /// Computed during parse from raw bytes covering IHL*4 bytes (including options).
    public func verifyChecksum() -> Bool {
        return _checksumValid
    }
    private let _checksumValid: Bool
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

// MARK: - Checksum helpers for two-pass computation

/// Compute pseudo-header checksum sum directly from IP addresses — zero allocation.
/// IPv4 addresses are stored in network byte order, so extracting 16-bit words is
/// simple bit manipulation.
public func computePseudoHeaderSum(
    srcIP: IPv4Address, dstIP: IPv4Address,
    protocol: UInt8, totalLen: Int
) -> UInt32 {
    var sum: UInt64 = 0
    let s = srcIP.addr
    sum &+= UInt64((s >> 16) & 0xFFFF)
    sum &+= UInt64(s & 0xFFFF)
    let d = dstIP.addr
    sum &+= UInt64((d >> 16) & 0xFFFF)
    sum &+= UInt64(d & 0xFFFF)
    sum &+= UInt64(`protocol`)
    sum &+= UInt64(UInt16(totalLen))
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16)
    }
    return UInt32(sum & 0xFFFF)
}

/// Add bytes to an existing 16-bit checksum accumulator.
func checksumAdd(_ sum: UInt32, _ ptr: UnsafeRawPointer, _ count: Int) -> UInt32 {
    var s = sum
    var i = 0
    let p = ptr.assumingMemoryBound(to: UInt8.self)
    while i + 1 < count {
        s += UInt32((UInt16(p[i]) << 8) | UInt16(p[i + 1]))
        i += 2
    }
    if i < count {
        s += UInt32(p[i]) << 8
    }
    return s
}

/// Add bytes from multiple non-contiguous views to an existing checksum accumulator.
/// Correctly carries pending odd bytes across view boundaries, matching the behavior
/// of a single contiguous checksum pass.
func checksumAddViews(_ initialSum: UInt32, _ views: [PacketBuffer.View]) -> UInt32 {
    var s = initialSum
    var pendingOdd: UInt8? = nil
    for view in views where view.length > 0 {
        let p = view.storage.data.advanced(by: view.offset).assumingMemoryBound(to: UInt8.self)
        var i = 0
        if let odd = pendingOdd {
            s += UInt32((UInt16(odd) << 8) | UInt16(p[0]))
            pendingOdd = nil
            i = 1
        }
        while i + 1 < view.length {
            s += UInt32((UInt16(p[i]) << 8) | UInt16(p[i + 1]))
            i += 2
        }
        if i < view.length {
            pendingOdd = p[i]
        }
    }
    if let odd = pendingOdd {
        s += UInt32(odd) << 8
    }
    return s
}

/// Fold carries and return one's complement.
func finalizeChecksum(_ sum: UInt32) -> UInt16 {
    var s = sum
    while s >> 16 != 0 {
        s = (s & 0xFFFF) + (s >> 16)
    }
    return ~UInt16(s & 0xFFFF)
}
