import Testing
@testable import SwiftNetStack

/// Tests for ARPFrame.parse.
@Suite(.serialized)
struct ARPFrameTests {

    func makeARP(op: ARPOperation, senderMAC: MACAddress, senderIP: IPv4Address,
                 targetMAC: MACAddress, targetIP: IPv4Address) -> PacketBuffer {
        var bytes = [UInt8](repeating: 0, count: 28)
        bytes[0] = 0x00; bytes[1] = 0x01  // htype = Ethernet
        bytes[2] = 0x08; bytes[3] = 0x00  // ptype = IPv4
        bytes[4] = 6; bytes[5] = 4
        bytes[6] = UInt8(op.rawValue >> 8)
        bytes[7] = UInt8(op.rawValue & 0xFF)
        var buf6 = [UInt8](repeating: 0, count: 6)
        var buf4 = [UInt8](repeating: 0, count: 4)
        senderMAC.write(to: &buf6); bytes.replaceSubrange(8..<14, with: buf6)
        senderIP.write(to: &buf4); bytes.replaceSubrange(14..<18, with: buf4)
        targetMAC.write(to: &buf6); bytes.replaceSubrange(18..<24, with: buf6)
        targetIP.write(to: &buf4); bytes.replaceSubrange(24..<28, with: buf4)
        let s = Storage.allocate(capacity: 28)
        bytes.withUnsafeBytes { s.data.copyMemory(from: $0.baseAddress!, byteCount: 28) }
        return PacketBuffer(storage: s, offset: 0, length: 28)
    }

    @Test func parseARPRequest() {
        let smac = MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF)
        let sip = IPv4Address(192, 168, 1, 100)
        let tip = IPv4Address(192, 168, 1, 1)
        let pkt = makeARP(op: .request, senderMAC: smac, senderIP: sip, targetMAC: .zero, targetIP: tip)

        guard let arp = ARPFrame.parse(from: pkt) else {
            Issue.record("parse returned nil")
            return
        }
        #expect(arp.hardwareType == 1)
        #expect(arp.protocolType == 0x0800)
        #expect(arp.hardwareSize == 6)
        #expect(arp.protocolSize == 4)
        #expect(arp.operation == .request)
        #expect(arp.senderMAC == smac)
        #expect(arp.senderIP == sip)
        #expect(arp.targetMAC == .zero)
        #expect(arp.targetIP == tip)
    }

    @Test func parseARPReply() {
        let smac = MACAddress(0x00, 0x11, 0x22, 0x33, 0x44, 0x55)
        let sip = IPv4Address(192, 168, 1, 1)
        let tmac = MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF)
        let tip = IPv4Address(192, 168, 1, 100)
        let pkt = makeARP(op: .reply, senderMAC: smac, senderIP: sip, targetMAC: tmac, targetIP: tip)

        guard let arp = ARPFrame.parse(from: pkt) else {
            Issue.record("parse returned nil")
            return
        }
        #expect(arp.operation == .reply)
        #expect(arp.senderMAC == smac)
        #expect(arp.senderIP == sip)
        #expect(arp.targetMAC == tmac)
        #expect(arp.targetIP == tip)
    }

    @Test func parseTooShort() {
        let s = Storage.allocate(capacity: 27)
        let pkt = PacketBuffer(storage: s, offset: 0, length: 27)
        #expect(ARPFrame.parse(from: pkt) == nil)
    }

    @Test func parseNonARPEtherType() {
        var bytes = [UInt8](repeating: 0, count: 28)
        bytes[0] = 0x00; bytes[1] = 0x01
        bytes[2] = 0x86; bytes[3] = 0xDD  // IPv6 protocol type
        bytes[4] = 6; bytes[5] = 4
        bytes[7] = 1
        let s = Storage.allocate(capacity: 28)
        bytes.withUnsafeBytes { s.data.copyMemory(from: $0.baseAddress!, byteCount: 28) }
        let pkt = PacketBuffer(storage: s, offset: 0, length: 28)
        #expect(ARPFrame.parse(from: pkt) == nil)
    }

    @Test func parseBadHardwareType() {
        var bytes = [UInt8](repeating: 0, count: 28)
        bytes[0] = 0x00; bytes[1] = 0x02  // htype = experimental
        bytes[2] = 0x08; bytes[3] = 0x00
        bytes[4] = 6; bytes[5] = 4
        bytes[7] = 1
        let s = Storage.allocate(capacity: 28)
        bytes.withUnsafeBytes { s.data.copyMemory(from: $0.baseAddress!, byteCount: 28) }
        let pkt = PacketBuffer(storage: s, offset: 0, length: 28)
        #expect(ARPFrame.parse(from: pkt) == nil)
    }
}
