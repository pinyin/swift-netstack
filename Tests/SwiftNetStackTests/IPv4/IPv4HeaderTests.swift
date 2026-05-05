import Testing
@testable import SwiftNetStack

@Suite(.serialized)
struct IPv4HeaderTests {

    // MARK: - IPv4Address

    @Test func ipv4AddressEquality() {
        let a = IPv4Address(192, 168, 1, 1)
        let b = IPv4Address(192, 168, 1, 1)
        let c = IPv4Address(10, 0, 0, 1)
        #expect(a == b)
        #expect(a != c)
    }

    @Test func ipv4AddressDescription() {
        let ip = IPv4Address(10, 0, 0, 1)
        #expect(ip.description == "10.0.0.1")
        let ip2 = IPv4Address(255, 255, 255, 255)
        #expect(ip2.description == "255.255.255.255")
    }

    @Test func ipv4AddressFromBuffer() {
        let bytes: [UInt8] = [0xC0, 0xA8, 0x01, 0x01]  // 192.168.1.1
        let ip = bytes.withUnsafeBytes { IPv4Address($0) }
        #expect(ip.description == "192.168.1.1")
    }

    @Test func ipv4AddressWriteAndReadRoundTrip() {
        let ip = IPv4Address(172, 16, 0, 1)
        var buf = [UInt8](repeating: 0, count: 4)
        buf.withUnsafeMutableBytes { ip.write(to: $0.baseAddress!) }
        let restored = buf.withUnsafeBytes { IPv4Address($0) }
        #expect(restored == ip)
    }

    // MARK: - IPv4Header.parse

    func makeIPv4HeaderBytes(
        totalLength: UInt16 = 20,
        protocol: UInt8 = 6,  // TCP
        src: IPv4Address = IPv4Address(192, 168, 1, 1),
        dst: IPv4Address = IPv4Address(10, 0, 0, 1)
    ) -> [UInt8] {
        var bytes: [UInt8] = Array(repeating: 0, count: 20)
        bytes[0] = 0x45  // version=4, ihl=5
        bytes[1] = 0x00  // DSCP/ECN
        bytes[2] = UInt8(totalLength >> 8)
        bytes[3] = UInt8(totalLength & 0xFF)
        // identification = 0
        // flags + fragment = 0
        bytes[8] = 64  // TTL
        bytes[9] = `protocol`
        // checksum at 10-11 (computed later)
        // src at 12-15
        src.write(to: &bytes[12])
        // dst at 16-19
        dst.write(to: &bytes[16])

        // Compute checksum
        let cksum = bytes.withUnsafeBytes { internetChecksum($0) }
        bytes[10] = UInt8(cksum >> 8)
        bytes[11] = UInt8(cksum & 0xFF)
        return bytes
    }

    @Test func parseValidIPv4Header() {
        let headerBytes = makeIPv4HeaderBytes()
        let pkt = PacketBuffer.from(bytes: headerBytes)

        let ip = IPv4Header.parse(from: pkt)
        #expect(ip != nil)
        #expect(ip?.version == 4)
        #expect(ip?.ihl == 5)
        #expect(ip?.totalLength == 20)
        #expect(ip?.ttl == 64)
        #expect(ip?.protocol == .tcp)
        #expect(ip?.srcAddr.description == "192.168.1.1")
        #expect(ip?.dstAddr.description == "10.0.0.1")
    }

    @Test func parseWithPayloadSlice() {
        var bytes = makeIPv4HeaderBytes(totalLength: 30)
        bytes.append(contentsOf: [UInt8](repeating: 0xAA, count: 10))  // payload
        let pkt = PacketBuffer.from(bytes: bytes)

        let ip = IPv4Header.parse(from: pkt)
        #expect(ip != nil)
        #expect(ip?.payload.totalLength == 10)
    }

    @Test func parseTooShort() {
        let pkt = PacketBuffer.from(bytes: [UInt8](repeating: 0, count: 10))
        #expect(IPv4Header.parse(from: pkt) == nil)
    }

    @Test func parseBadVersion() {
        var bytes = makeIPv4HeaderBytes()
        bytes[0] = 0x65  // version=6
        let pkt = PacketBuffer.from(bytes: bytes)
        #expect(IPv4Header.parse(from: pkt) == nil)
    }

    @Test func parseBadIHL() {
        var bytes = makeIPv4HeaderBytes()
        bytes[0] = 0x44  // ihl=4 (too small)
        let pkt = PacketBuffer.from(bytes: bytes)
        #expect(IPv4Header.parse(from: pkt) == nil)
    }

    @Test func parseUnknownProtocol() {
        var bytes = makeIPv4HeaderBytes(protocol: 99)  // unknown
        // Recompute checksum
        bytes[10] = 0; bytes[11] = 0
        let cksum = bytes.withUnsafeBytes { internetChecksum($0) }
        bytes[10] = UInt8(cksum >> 8)
        bytes[11] = UInt8(cksum & 0xFF)

        let pkt = PacketBuffer.from(bytes: bytes)
        #expect(IPv4Header.parse(from: pkt) == nil)
    }

    // MARK: - Checksum

    @Test func verifyChecksumValid() {
        let headerBytes = makeIPv4HeaderBytes()
        let pkt = PacketBuffer.from(bytes: headerBytes)
        let ip = IPv4Header.parse(from: pkt)
        #expect(ip != nil)
        #expect(ip?.verifyChecksum() == true)
    }

    @Test func verifyChecksumInvalid() {
        var headerBytes = makeIPv4HeaderBytes()
        // Corrupt the TTL byte
        headerBytes[8] = 128
        let pkt = PacketBuffer.from(bytes: headerBytes)
        let ip = IPv4Header.parse(from: pkt)
        #expect(ip != nil)
        #expect(ip?.verifyChecksum() == false)
    }

    // MARK: - internetChecksum utility

    @Test func checksumOfEmpty() {
        let buf: [UInt8] = []
        let c = buf.withUnsafeBytes { internetChecksum($0) }
        #expect(c == 0xFFFF)
    }

    @Test func checksumOfAllZeros() {
        let buf = [UInt8](repeating: 0, count: 20)
        let c = buf.withUnsafeBytes { internetChecksum($0) }
        #expect(c == 0xFFFF)
    }
}
