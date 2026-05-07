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
