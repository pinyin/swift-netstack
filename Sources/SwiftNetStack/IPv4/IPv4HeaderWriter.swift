/// Write a standard 20-byte IPv4 header at the given pointer and compute its checksum.
///
/// Writes version=4, IHL=5, DSCP+ECN=0, totalLength, identification, flags+offset,
/// TTL, protocol, zero checksum placeholder, srcIP, dstIP — then computes the
/// one's-complement internet checksum (RFC 791) over the 20-byte header and writes
/// it to bytes 10-11.
///
/// Parameters use sensible defaults so callers only override what they change:
/// - identification: 0 (unfragmented — DF=1 is set by default)
/// - ttl: 64
/// - flags: 0x4000 (DF=1, fragment offset=0)
func writeIPv4Header(
    to ipPtr: UnsafeMutableRawPointer,
    totalLength: UInt16,
    `protocol`: IPProtocol,
    srcIP: IPv4Address,
    dstIP: IPv4Address,
    identification: UInt16 = 0,
    ttl: UInt8 = 64,
    flags: UInt16 = 0x4000
) {
    ipPtr.storeBytes(of: UInt8(0x45), as: UInt8.self)            // version=4, IHL=5
    ipPtr.advanced(by: 1).storeBytes(of: UInt8(0), as: UInt8.self) // DSCP+ECN=0
    writeUInt16BE(totalLength, to: ipPtr.advanced(by: 2))
    writeUInt16BE(identification, to: ipPtr.advanced(by: 4))
    writeUInt16BE(flags, to: ipPtr.advanced(by: 6))
    ipPtr.advanced(by: 8).storeBytes(of: ttl, as: UInt8.self)
    ipPtr.advanced(by: 9).storeBytes(of: `protocol`.rawValue, as: UInt8.self)
    writeUInt16BE(0, to: ipPtr.advanced(by: 10))                // checksum placeholder
    srcIP.write(to: ipPtr.advanced(by: 12))
    dstIP.write(to: ipPtr.advanced(by: 16))
    let cksum = internetChecksum(UnsafeRawBufferPointer(start: ipPtr, count: 20))
    writeUInt16BE(cksum, to: ipPtr.advanced(by: 10))
}

// MARK: - Frame layout constants

let ethHeaderLen = 14
let ipv4HeaderLen = 20
let udpHeaderLen = 8

/// Decrement the TTL field of an in-place IPv4 header and update its checksum.
/// Returns true if forwarding may continue (TTL was > 1). Returns false if the
/// TTL reached 0 — the caller should generate ICMP Time Exceeded and drop the packet.
///
/// Uses incremental checksum (RFC 1624): HC' = HC + ~((oldTTL - newTTL) << 8).
/// This avoids recomputing the entire 20-byte checksum in the hot path.
public func decrementTTL(at ipPtr: UnsafeMutableRawPointer) -> Bool {
    let ttl = ipPtr.load(fromByteOffset: 8, as: UInt8.self)
    guard ttl > 1 else {
        ipPtr.storeBytes(of: UInt8(0), toByteOffset: 8, as: UInt8.self)
        // TTL=1 → 0: add 0x0100 to checksum (one's complement)
        // Derivation: new_checksum = ~(~old_checksum - 0x0100) = old_checksum + 0x0100
        let oldCK = UInt32(readUInt16BE(ipPtr, 10))
        var newCK = oldCK &+ 0x0100
        newCK = (newCK & 0xFFFF) &+ (newCK >> 16)
        newCK = (newCK & 0xFFFF) &+ (newCK >> 16)
        writeUInt16BE(UInt16(newCK & 0xFFFF), to: ipPtr.advanced(by: 10))
        return false
    }
    ipPtr.storeBytes(of: ttl &- 1, toByteOffset: 8, as: UInt8.self)
    // RFC 1624 incremental: HC' = ~(~HC - 0x0100) = HC + 0x0100
    let oldCK = UInt32(readUInt16BE(ipPtr, 10))
    var newCK = oldCK &+ 0x0100
    newCK = (newCK & 0xFFFF) &+ (newCK >> 16)
    newCK = (newCK & 0xFFFF) &+ (newCK >> 16)
    writeUInt16BE(UInt16(newCK & 0xFFFF), to: ipPtr.advanced(by: 10))
    return true
}
