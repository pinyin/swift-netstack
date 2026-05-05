import Testing
@testable import SwiftNetStack

@Suite(.serialized)
struct EthernetFrameTests {

    // MARK: - MACAddress

    @Test func macAddressEquality() {
        let a = MACAddress(0x00, 0x11, 0x22, 0x33, 0x44, 0x55)
        let b = MACAddress(0x00, 0x11, 0x22, 0x33, 0x44, 0x55)
        let c = MACAddress(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF)
        #expect(a == b)
        #expect(a != c)
        #expect(MACAddress.broadcast == c)
    }

    @Test func macAddressDescription() {
        let mac = MACAddress(0x00, 0x11, 0x22, 0x33, 0x44, 0x55)
        #expect(mac.description == "00:11:22:33:44:55")
    }

    @Test func macAddressFromBuffer() {
        let bytes: [UInt8] = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]
        let mac = bytes.withUnsafeBytes { MACAddress($0) }
        #expect(mac.description == "aa:bb:cc:dd:ee:ff")
    }

    @Test func macAddressWriteAndReadRoundTrip() {
        let mac = MACAddress(0x11, 0x22, 0x33, 0x44, 0x55, 0x66)
        var buf = [UInt8](repeating: 0, count: 6)
        buf.withUnsafeMutableBytes { mac.write(to: $0.baseAddress!) }
        let restored = buf.withUnsafeBytes { MACAddress($0) }
        #expect(restored == mac)
    }

    // MARK: - EthernetFrame.parse

    @Test func parseValidFrame() {
        let pkt = PacketBuffer.from(bytes: [
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  // dst = broadcast
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55,  // src
            0x08, 0x00,                              // EtherType = IPv4
            0x01, 0x02, 0x03, 0x04,              // payload
        ])

        let eth = EthernetFrame.parse(from: pkt)
        #expect(eth != nil)
        #expect(eth?.dstMAC == .broadcast)
        #expect(eth?.srcMAC == MACAddress(0x00, 0x11, 0x22, 0x33, 0x44, 0x55))
        #expect(eth?.etherType == .ipv4)
        #expect(eth?.payload.totalLength == 4)
    }

    @Test func parseARPEtherType() {
        let pkt = PacketBuffer.from(bytes: [
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
            0x08, 0x06,  // ARP
        ])
        let eth = EthernetFrame.parse(from: pkt)
        #expect(eth?.etherType == .arp)
    }

    @Test func parseFrameTooShort() {
        let pkt = PacketBuffer.from(bytes: [UInt8](repeating: 0, count: 10))
        #expect(EthernetFrame.parse(from: pkt) == nil)
    }

    @Test func parseUnknownEtherType() {
        let pkt = PacketBuffer.from(bytes: [
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
            0x88, 0xB5,  // Unknown EtherType
        ])
        #expect(EthernetFrame.parse(from: pkt) == nil)
    }
}
