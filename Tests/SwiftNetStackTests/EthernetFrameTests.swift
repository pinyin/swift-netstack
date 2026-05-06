import Testing
@testable import SwiftNetStack

/// Tests for EthernetFrame.parse: the public entry point for L2 parsing.
@Suite(.serialized)
struct EthernetFrameTests {

    // Helper: build a raw Ethernet frame in a PacketBuffer
    func makeFrame(dst: MACAddress, src: MACAddress, type: EtherType, payload: [UInt8] = []) -> PacketBuffer {
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

    @Test func parseValidFrame() {
        let dst = MACAddress(0x00, 0x11, 0x22, 0x33, 0x44, 0x55)
        let src = MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF)
        let pkt = makeFrame(dst: dst, src: src, type: .ipv4, payload: [0x01, 0x02])

        guard let eth = EthernetFrame.parse(from: pkt) else {
            Issue.record("parse returned nil for valid frame")
            return
        }
        #expect(eth.dstMAC == dst)
        #expect(eth.srcMAC == src)
        #expect(eth.etherType == .ipv4)
        #expect(eth.payload.totalLength == 2)
    }

    @Test func parseARPFrame() {
        let pkt = makeFrame(dst: .broadcast, src: MACAddress(0x12, 0x22, 0x33, 0x44, 0x55, 0x66), type: .arp)
        guard let eth = EthernetFrame.parse(from: pkt) else {
            Issue.record("parse returned nil")
            return
        }
        #expect(eth.etherType == .arp)
    }

    @Test func parseFrameTooShort() {
        let s = Storage.allocate(capacity: 13)
        let pkt = PacketBuffer(storage: s, offset: 0, length: 13)
        #expect(EthernetFrame.parse(from: pkt) == nil)
    }

    @Test func parseUnknownEtherType() {
        // EtherType 0x86DD (IPv6) is not in our EtherType enum
        var bytes: [UInt8] = []
        var buf6 = [UInt8](repeating: 0, count: 6)
        MACAddress.broadcast.write(to: &buf6); bytes.append(contentsOf: buf6)
        MACAddress.zero.write(to: &buf6); bytes.append(contentsOf: buf6)
        bytes.append(0x86); bytes.append(0xDD)  // IPv6
        bytes.append(0x00)

        let s = Storage.allocate(capacity: bytes.count)
        bytes.withUnsafeBytes { s.data.copyMemory(from: $0.baseAddress!, byteCount: bytes.count) }
        let pkt = PacketBuffer(storage: s, offset: 0, length: bytes.count)

        #expect(EthernetFrame.parse(from: pkt) == nil)
    }
}
