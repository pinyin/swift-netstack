import Testing
@testable import SwiftNetStack

@Suite(.serialized)
struct ClassifierTests {

    let hostMAC = MACAddress(0x00, 0x11, 0x22, 0x33, 0x44, 0x55)

    // MARK: - Empty input

    @Test func emptyInputProducesEmptyResult() {
        let result = classifyFrames([], hostMAC: hostMAC)
        #expect(result.totalCount == 0)
        #expect(result.arp.isEmpty)
        #expect(result.ipv4ICMP.isEmpty)
        #expect(result.ipv4TCP.isEmpty)
        #expect(result.ipv4UDP.isEmpty)
        #expect(result.unknown.isEmpty)
    }

    // MARK: - Ethernet parse failures

    @Test func badEthernetFrameGoesToUnknown() {
        let s = Storage.allocate(capacity: 13)
        let pkt = PacketBuffer(storage: s, offset: 0, length: 13)

        let result = classifyFrames([pkt], hostMAC: hostMAC)
        #expect(result.totalCount == 1)
        #expect(result.unknown.count == 1)
    }

    // MARK: - MAC filtering

    @Test func nonMatchingMACGoesToUnknown() {
        let otherMAC = MACAddress(0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA)
        let frame = makeEthernetFrame(dst: otherMAC, src: MACAddress(0x12, 0x22, 0x33, 0x44, 0x55, 0x66), type: .ipv4)

        let result = classifyFrames([frame], hostMAC: hostMAC)
        #expect(result.unknown.count == 1)
    }

    @Test func broadcastMACIsAccepted() {
        let frame = makeEthernetFrame(dst: .broadcast, src: MACAddress(0x12, 0x22, 0x33, 0x44, 0x55, 0x66), type: .arp, payload: validARPPayload())

        let result = classifyFrames([frame], hostMAC: hostMAC)
        #expect(result.arp.count == 1)
    }

    // MARK: - ARP classification

    @Test func arpFrameClassifiedCorrectly() {
        let frame = makeEthernetFrame(dst: hostMAC, src: MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF), type: .arp, payload: validARPPayload())

        let result = classifyFrames([frame], hostMAC: hostMAC)
        #expect(result.arp.count == 1)
        #expect(result.totalCount == 1)
    }

    @Test func badARPParseGoesToUnknown() {
        var badARP = [UInt8](repeating: 0, count: 28)
        badARP[0] = 0x00; badARP[1] = 0x02  // bad htype
        badARP[2] = 0x08; badARP[3] = 0x00
        badARP[4] = 6; badARP[5] = 4
        badARP[7] = 1
        let frame = makeEthernetFrame(dst: hostMAC, src: MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF), type: .arp, payload: badARP)

        let result = classifyFrames([frame], hostMAC: hostMAC)
        #expect(result.arp.isEmpty)
        #expect(result.unknown.count == 1)
    }

    // MARK: - IPv4 classification

    @Test func ipv4ICMPClassifiedCorrectly() {
        let ipPayload = makeIPv4Payload(proto: .icmp, src: IPv4Address(10, 0, 0, 1), dst: IPv4Address(192, 168, 1, 1))
        let frame = makeEthernetFrame(dst: hostMAC, src: MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF), type: .ipv4, payload: ipPayload)

        let result = classifyFrames([frame], hostMAC: hostMAC)
        #expect(result.ipv4ICMP.count == 1)
    }

    @Test func ipv4TCPClassifiedCorrectly() {
        let ipPayload = makeIPv4Payload(proto: .tcp, src: IPv4Address(10, 0, 0, 1), dst: IPv4Address(192, 168, 1, 1))
        let frame = makeEthernetFrame(dst: hostMAC, src: MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF), type: .ipv4, payload: ipPayload)

        let result = classifyFrames([frame], hostMAC: hostMAC)
        #expect(result.ipv4TCP.count == 1)
    }

    @Test func ipv4UDPClassifiedCorrectly() {
        let ipPayload = makeIPv4Payload(proto: .udp, src: IPv4Address(10, 0, 0, 1), dst: IPv4Address(192, 168, 1, 1))
        let frame = makeEthernetFrame(dst: hostMAC, src: MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF), type: .ipv4, payload: ipPayload)

        let result = classifyFrames([frame], hostMAC: hostMAC)
        #expect(result.ipv4UDP.count == 1)
    }

    @Test func ipv4WithBadChecksumGoesToUnknown() {
        var bytes = [UInt8](repeating: 0, count: 20)
        bytes[0] = 0x45
        bytes[9] = IPProtocol.tcp.rawValue
        IPv4Address(10, 0, 0, 1).write(to: &bytes[12])
        IPv4Address(192, 168, 1, 1).write(to: &bytes[16])
        // Compute valid checksum, then corrupt the TTL to break it
        let cksum = bytes.withUnsafeBytes { internetChecksum($0) }
        bytes[10] = UInt8(cksum >> 8)
        bytes[11] = UInt8(cksum & 0xFF)
        bytes[8] = 0xFF  // corrupt TTL after checksum calculation

        let frame = makeEthernetFrame(dst: hostMAC, src: MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF), type: .ipv4, payload: bytes)

        let result = classifyFrames([frame], hostMAC: hostMAC)
        #expect(result.ipv4TCP.isEmpty)
        #expect(result.unknown.count == 1)
    }

    @Test func badIPv4ParseGoesToUnknown() {
        var bytes = [UInt8](repeating: 0, count: 20)
        bytes[0] = 0x65  // version=6, should fail
        bytes[9] = IPProtocol.tcp.rawValue

        let frame = makeEthernetFrame(dst: hostMAC, src: MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF), type: .ipv4, payload: bytes)

        let result = classifyFrames([frame], hostMAC: hostMAC)
        #expect(result.ipv4TCP.isEmpty)
        #expect(result.unknown.count == 1)
    }

    // MARK: - Mixed traffic

    @Test func mixedTrafficClassifiedCorrectly() {
        let arpFrame = makeEthernetFrame(dst: hostMAC, src: MACAddress(0x12, 0x22, 0x33, 0x44, 0x55, 0x01), type: .arp, payload: validARPPayload())
        let icmpFrame = makeEthernetFrame(dst: hostMAC, src: MACAddress(0x12, 0x22, 0x33, 0x44, 0x55, 0x02), type: .ipv4, payload: makeIPv4Payload(proto: .icmp))
        let tcpFrame = makeEthernetFrame(dst: hostMAC, src: MACAddress(0x12, 0x22, 0x33, 0x44, 0x55, 0x03), type: .ipv4, payload: makeIPv4Payload(proto: .tcp))
        let udpFrame = makeEthernetFrame(dst: hostMAC, src: MACAddress(0x12, 0x22, 0x33, 0x44, 0x55, 0x04), type: .ipv4, payload: makeIPv4Payload(proto: .udp))

        // A frame for a different MAC
        let otherFrame = makeEthernetFrame(dst: MACAddress(0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA), src: MACAddress(0x12, 0x22, 0x33, 0x44, 0x55, 0x05), type: .ipv4, payload: makeIPv4Payload(proto: .tcp))

        let result = classifyFrames([arpFrame, icmpFrame, tcpFrame, udpFrame, otherFrame], hostMAC: hostMAC)

        #expect(result.arp.count == 1)
        #expect(result.ipv4ICMP.count == 1)
        #expect(result.ipv4TCP.count == 1)
        #expect(result.ipv4UDP.count == 1)
        #expect(result.unknown.count == 1)
        #expect(result.totalCount == 5)
    }

    // MARK: - totalCount

    @Test func totalCountSumsAllCategories() {
        var result = ClassifiedFrames()
        #expect(result.totalCount == 0)

        let s = Storage.allocate(capacity: 13)
        result.unknown.append(PacketBuffer(storage: s, offset: 0, length: 13))
        #expect(result.totalCount == 1)
    }

    // MARK: - Helpers

    private func makeEthernetFrame(dst: MACAddress, src: MACAddress, type: EtherType, payload: [UInt8] = []) -> PacketBuffer {
        var bytes: [UInt8] = []
        var buf6 = [UInt8](repeating: 0, count: 6)
        dst.write(to: &buf6); bytes.append(contentsOf: buf6)
        src.write(to: &buf6); bytes.append(contentsOf: buf6)
        let etRaw = type.rawValue
        bytes.append(UInt8(etRaw >> 8))
        bytes.append(UInt8(etRaw & 0xFF))
        bytes.append(contentsOf: payload)
        let s = Storage.allocate(capacity: bytes.count)
        bytes.withUnsafeBytes { s.data.copyMemory(from: $0.baseAddress!, byteCount: bytes.count) }
        return PacketBuffer(storage: s, offset: 0, length: bytes.count)
    }

    private func validARPPayload() -> [UInt8] {
        var bytes = [UInt8](repeating: 0, count: 28)
        bytes[0] = 0x00; bytes[1] = 0x01  // htype = Ethernet
        bytes[2] = 0x08; bytes[3] = 0x00  // ptype = IPv4
        bytes[4] = 6; bytes[5] = 4
        bytes[6] = 0x00; bytes[7] = 0x01  // request
        var buf6 = [UInt8](repeating: 0, count: 6)
        MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF).write(to: &buf6)
        bytes.replaceSubrange(8..<14, with: buf6)
        bytes.replaceSubrange(18..<24, with: buf6)
        var buf4 = [UInt8](repeating: 0, count: 4)
        IPv4Address(10, 0, 0, 1).write(to: &buf4); bytes.replaceSubrange(14..<18, with: buf4)
        IPv4Address(10, 0, 0, 2).write(to: &buf4); bytes.replaceSubrange(24..<28, with: buf4)
        return bytes
    }

    private func makeIPv4Payload(proto: IPProtocol,
                                  src: IPv4Address = IPv4Address(10, 0, 0, 1),
                                  dst: IPv4Address = IPv4Address(192, 168, 1, 1)) -> [UInt8] {
        var bytes = [UInt8](repeating: 0, count: 20)
        bytes[0] = 0x45
        bytes[8] = 64
        bytes[9] = proto.rawValue
        var buf4 = [UInt8](repeating: 0, count: 4)
        src.write(to: &buf4); bytes.replaceSubrange(12..<16, with: buf4)
        dst.write(to: &buf4); bytes.replaceSubrange(16..<20, with: buf4)
        let cksum = bytes.withUnsafeBytes { internetChecksum($0) }
        bytes[10] = UInt8(cksum >> 8)
        bytes[11] = UInt8(cksum & 0xFF)
        return bytes
    }
}
