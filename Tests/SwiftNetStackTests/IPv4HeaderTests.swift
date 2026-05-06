import Testing
@testable import SwiftNetStack

/// Tests for IPv4Header.parse and verifyChecksum.
@Suite(.serialized)
struct IPv4HeaderTests {

    // Helper: build an IPv4 header PacketBuffer with correct checksum
    func makeIPv4Header(proto: IPProtocol, src: IPv4Address = IPv4Address(10, 0, 0, 1),
                        dst: IPv4Address = IPv4Address(192, 168, 1, 1),
                        totalLen: UInt16 = 20) -> PacketBuffer {
        var bytes = [UInt8](repeating: 0, count: Int(totalLen))
        bytes[0] = 0x45  // v4, ihl=5
        bytes[2] = UInt8(totalLen >> 8)
        bytes[3] = UInt8(totalLen & 0xFF)
        bytes[8] = 64  // TTL
        bytes[9] = proto.rawValue
        var buf4 = [UInt8](repeating: 0, count: 4)
        src.write(to: &buf4); bytes.replaceSubrange(12..<16, with: buf4)
        dst.write(to: &buf4); bytes.replaceSubrange(16..<20, with: buf4)
        let cksum = bytes.withUnsafeBytes { internetChecksum($0) }
        bytes[10] = UInt8(cksum >> 8)
        bytes[11] = UInt8(cksum & 0xFF)
        let s = Storage.allocate(capacity: bytes.count)
        bytes.withUnsafeBytes { s.data.copyMemory(from: $0.baseAddress!, byteCount: bytes.count) }
        return PacketBuffer(storage: s, offset: 0, length: bytes.count)
    }

    // MARK: - Parse

    @Test func parseValidIPv4Header() {
        let pkt = makeIPv4Header(proto: .tcp)
        guard let ip = IPv4Header.parse(from: pkt) else {
            Issue.record("parse returned nil")
            return
        }
        #expect(ip.version == 4)
        #expect(ip.ihl == 5)
        #expect(ip.protocol == .tcp)
        #expect(ip.ttl == 64)
        #expect(ip.srcAddr == IPv4Address(10, 0, 0, 1))
        #expect(ip.dstAddr == IPv4Address(192, 168, 1, 1))
    }

    @Test func parseICMPHeader() {
        let pkt = makeIPv4Header(proto: .icmp)
        guard let ip = IPv4Header.parse(from: pkt) else { return }
        #expect(ip.protocol == .icmp)
    }

    @Test func parseUDPHeader() {
        let pkt = makeIPv4Header(proto: .udp, totalLen: 28)
        guard let ip = IPv4Header.parse(from: pkt) else { return }
        #expect(ip.protocol == .udp)
        #expect(ip.totalLength == 28)
    }

    @Test func parseTooShort() {
        let s = Storage.allocate(capacity: 19)
        let pkt = PacketBuffer(storage: s, offset: 0, length: 19)
        #expect(IPv4Header.parse(from: pkt) == nil)
    }

    @Test func parseBadVersion() {
        var bytes = [UInt8](repeating: 0, count: 20)
        bytes[0] = 0x65  // version=6, ihl=5
        bytes[9] = IPProtocol.tcp.rawValue
        let s = Storage.allocate(capacity: 20)
        bytes.withUnsafeBytes { s.data.copyMemory(from: $0.baseAddress!, byteCount: 20) }
        let pkt = PacketBuffer(storage: s, offset: 0, length: 20)
        #expect(IPv4Header.parse(from: pkt) == nil)
    }

    @Test func parseBadIHL() {
        var bytes = [UInt8](repeating: 0, count: 20)
        bytes[0] = 0x44  // version=4, ihl=4 (< 5 minimum)
        bytes[9] = IPProtocol.tcp.rawValue
        let s = Storage.allocate(capacity: 20)
        bytes.withUnsafeBytes { s.data.copyMemory(from: $0.baseAddress!, byteCount: 20) }
        let pkt = PacketBuffer(storage: s, offset: 0, length: 20)
        #expect(IPv4Header.parse(from: pkt) == nil)
    }

    @Test func parseUnknownProtocol() {
        var bytes = [UInt8](repeating: 0, count: 20)
        bytes[0] = 0x45
        bytes[9] = 99  // invalid protocol number
        let cksum = bytes.withUnsafeBytes { internetChecksum($0) }
        bytes[10] = UInt8(cksum >> 8); bytes[11] = UInt8(cksum & 0xFF)
        let s = Storage.allocate(capacity: 20)
        bytes.withUnsafeBytes { s.data.copyMemory(from: $0.baseAddress!, byteCount: 20) }
        let pkt = PacketBuffer(storage: s, offset: 0, length: 20)
        #expect(IPv4Header.parse(from: pkt) == nil)
    }

    // MARK: - Payload slice

    @Test func payloadIsZeroCopySlice() {
        let payloadData: [UInt8] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
        var bytes = [UInt8](repeating: 0, count: 28)
        bytes[0] = 0x45
        bytes[2] = 0x00; bytes[3] = 28
        bytes[8] = 64; bytes[9] = 1  // ICMP
        IPv4Address(10, 0, 0, 1).write(to: &bytes[12])
        IPv4Address(192, 168, 1, 1).write(to: &bytes[16])
        bytes.replaceSubrange(20..<28, with: payloadData)
        let cksum = bytes[0..<20].withUnsafeBytes { internetChecksum($0) }
        bytes[10] = UInt8(cksum >> 8); bytes[11] = UInt8(cksum & 0xFF)

        let s = Storage.allocate(capacity: 28)
        bytes.withUnsafeBytes { s.data.copyMemory(from: $0.baseAddress!, byteCount: 28) }
        let pkt = PacketBuffer(storage: s, offset: 0, length: 28)

        guard let ip = IPv4Header.parse(from: pkt) else { return }
        #expect(ip.payload.totalLength == 8)
        ip.payload.withUnsafeReadableBytes { buf in
            #expect(Array(buf) == payloadData)
        }
    }

    // MARK: - Checksum verification

    @Test func verifyChecksumValid() {
        let pkt = makeIPv4Header(proto: .tcp)
        guard let ip = IPv4Header.parse(from: pkt) else { return }
        #expect(ip.verifyChecksum())
    }

    @Test func verifyChecksumInvalid() {
        var bytes = [UInt8](repeating: 0, count: 20)
        bytes[0] = 0x45; bytes[8] = 64; bytes[9] = IPProtocol.tcp.rawValue
        IPv4Address(10, 0, 0, 1).write(to: &bytes[12])
        IPv4Address(192, 168, 1, 1).write(to: &bytes[16])
        let cksum = bytes.withUnsafeBytes { internetChecksum($0) }
        bytes[10] = UInt8(cksum >> 8); bytes[11] = UInt8(cksum & 0xFF)
        // Corrupt TTL
        bytes[8] = 0xFF
        let s = Storage.allocate(capacity: 20)
        bytes.withUnsafeBytes { s.data.copyMemory(from: $0.baseAddress!, byteCount: 20) }
        let pkt = PacketBuffer(storage: s, offset: 0, length: 20)
        guard let ip = IPv4Header.parse(from: pkt) else { return }
        #expect(!ip.verifyChecksum())
    }

    // MARK: - C1 regression: payload trimmed to IP totalLength

    /// Verifies that IPv4Header.parse respects the IP header's `totalLength`
    /// field when computing the payload slice, excluding Ethernet padding bytes.
    @Test func ipPayloadTrimmedToDeclaredTotalLength() {
        let declaredTotalLength: UInt16 = 28   // 20 header + 8 real payload
        let physicalBufLen = 40                 // includes 12 bytes padding
        let expectedPayloadLen = Int(declaredTotalLength) - 20  // 8

        var bytes = [UInt8](repeating: 0, count: physicalBufLen)
        bytes[0] = 0x45
        bytes[2] = UInt8(declaredTotalLength >> 8)
        bytes[3] = UInt8(declaredTotalLength & 0xFF)
        bytes[8] = 64; bytes[9] = IPProtocol.udp.rawValue
        IPv4Address(10, 0, 0, 1).write(to: &bytes[12])
        IPv4Address(192, 168, 1, 1).write(to: &bytes[16])
        for i in 20..<28 { bytes[i] = UInt8(i - 20) }       // real payload
        for i in 28..<40 { bytes[i] = 0xFF }                 // padding
        let cksum = bytes[0..<20].withUnsafeBytes { internetChecksum($0) }
        bytes[10] = UInt8(cksum >> 8); bytes[11] = UInt8(cksum & 0xFF)

        let s = Storage.allocate(capacity: physicalBufLen)
        bytes.withUnsafeBytes { s.data.copyMemory(from: $0.baseAddress!, byteCount: physicalBufLen) }
        let pkt = PacketBuffer(storage: s, offset: 0, length: physicalBufLen)

        guard let ip = IPv4Header.parse(from: pkt) else {
            Issue.record("parse returned nil")
            return
        }

        #expect(ip.totalLength == declaredTotalLength)
        #expect(ip.payload.totalLength == expectedPayloadLen)
        ip.payload.withUnsafeReadableBytes { buf in
            let payloadBytes = Array(buf)
            #expect(payloadBytes.count == expectedPayloadLen)
            #expect(!payloadBytes.contains(0xFF))
        }
    }

    // MARK: - Field accessors

    @Test func fieldAccessors() {
        let pkt = makeIPv4Header(proto: .tcp)
        guard let ip = IPv4Header.parse(from: pkt) else { return }
        #expect(ip.version == 4)
        #expect(ip.ihl == 5)
        #expect(ip.flags == 0)
        #expect(ip.fragmentOffset == 0)
        #expect(ip.totalLength == 20)
        #expect(ip.identification == 0)
        #expect(ip.checksum != 0)
    }
}
