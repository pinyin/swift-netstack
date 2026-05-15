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

/// Fold carries and return one's complement.
func finalizeChecksum(_ sum: UInt32) -> UInt16 {
    var s = sum
    while s >> 16 != 0 {
        s = (s & 0xFFFF) + (s >> 16)
    }
    return ~UInt16(s & 0xFFFF)
}
