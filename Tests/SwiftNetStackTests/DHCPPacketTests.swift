import Testing
@testable import SwiftNetStack

/// Tests for DHCPPacket.parse.
@Suite(.serialized)
struct DHCPPacketTests {

    func makeDHCPBytes(op: UInt8 = 1, xid: UInt32, chaddr: MACAddress,
                       msgType: DHCPMessageType, options: [(UInt8, [UInt8])] = []) -> [UInt8] {
        var bytes = [UInt8](repeating: 0, count: 247)
        bytes[0] = op
        bytes[4] = UInt8((xid >> 24) & 0xFF)
        bytes[5] = UInt8((xid >> 16) & 0xFF)
        bytes[6] = UInt8((xid >> 8) & 0xFF)
        bytes[7] = UInt8(xid & 0xFF)
        var buf6 = [UInt8](repeating: 0, count: 6)
        chaddr.write(to: &buf6); bytes.replaceSubrange(28..<34, with: buf6)
        // Magic cookie
        bytes[240] = 99; bytes[241] = 130; bytes[242] = 83; bytes[243] = 99
        // Option 53 (required)
        bytes[244] = 53; bytes[245] = 1; bytes[246] = msgType.rawValue

        // Append additional options after the base
        var optIdx = 247
        for (code, value) in options {
            if optIdx + 2 + value.count > bytes.count {
                bytes.append(contentsOf: [UInt8](repeating: 0, count: optIdx + 2 + value.count - bytes.count))
            }
            bytes[optIdx] = code
            bytes[optIdx + 1] = UInt8(value.count)
            bytes.replaceSubrange((optIdx + 2)..<(optIdx + 2 + value.count), with: value)
            optIdx += 2 + value.count
        }
        // End option
        if optIdx >= bytes.count { bytes.append(0) }
        bytes[optIdx] = 255
        return bytes
    }

    @Test func parseDiscover() {
        let chaddr = MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF)
        let bytes = makeDHCPBytes(xid: 42, chaddr: chaddr, msgType: .discover)
        let s = Storage.allocate(capacity: bytes.count)
        bytes.withUnsafeBytes { s.data.copyMemory(from: $0.baseAddress!, byteCount: bytes.count) }
        let pkt = PacketBuffer(storage: s, offset: 0, length: bytes.count)

        guard let dhcp = DHCPPacket.parse(from: pkt) else {
            Issue.record("parse returned nil")
            return
        }
        #expect(dhcp.messageType == .discover)
        #expect(dhcp.xid == 42)
        #expect(dhcp.chaddr == chaddr)
    }

    @Test func parseRequest() {
        let chaddr = MACAddress(0x12, 0x22, 0x33, 0x44, 0x55, 0x66)
        let reqIP = IPv4Address(100, 64, 1, 50)
        let srvID = IPv4Address(100, 64, 1, 1)
        var ip4 = [UInt8](repeating: 0, count: 4)
        reqIP.write(to: &ip4)
        var gw4 = [UInt8](repeating: 0, count: 4)
        srvID.write(to: &gw4)

        let bytes = makeDHCPBytes(xid: 99, chaddr: chaddr, msgType: .request, options: [
            (50, ip4),   // requested IP
            (54, gw4),   // server identifier
        ])
        let s = Storage.allocate(capacity: bytes.count)
        bytes.withUnsafeBytes { s.data.copyMemory(from: $0.baseAddress!, byteCount: bytes.count) }
        let pkt = PacketBuffer(storage: s, offset: 0, length: bytes.count)

        guard let dhcp = DHCPPacket.parse(from: pkt) else { return }
        #expect(dhcp.messageType == .request)
        #expect(dhcp.requestedIP == reqIP)
        #expect(dhcp.serverIdentifier == srvID)
    }

    @Test func parseRelease() {
        let chaddr = MACAddress(0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01)
        let bytes = makeDHCPBytes(xid: 7, chaddr: chaddr, msgType: .release)
        let s = Storage.allocate(capacity: bytes.count)
        bytes.withUnsafeBytes { s.data.copyMemory(from: $0.baseAddress!, byteCount: bytes.count) }
        let pkt = PacketBuffer(storage: s, offset: 0, length: bytes.count)

        guard let dhcp = DHCPPacket.parse(from: pkt) else { return }
        #expect(dhcp.messageType == .release)
    }

    @Test func parseTooShort() {
        let s = Storage.allocate(capacity: 240)
        let pkt = PacketBuffer(storage: s, offset: 0, length: 240)
        #expect(DHCPPacket.parse(from: pkt) == nil)
    }

    @Test func parseBadMagicCookie() {
        var bytes = [UInt8](repeating: 0, count: 247)
        bytes[0] = 1; bytes[9] = 1  // hlen=1
        // Magic cookie = 0,0,0,0 (bad)
        bytes[244] = 53; bytes[245] = 1; bytes[246] = 1  // valid option after bad cookie
        let s = Storage.allocate(capacity: 247)
        bytes.withUnsafeBytes { s.data.copyMemory(from: $0.baseAddress!, byteCount: 247) }
        let pkt = PacketBuffer(storage: s, offset: 0, length: 247)
        #expect(DHCPPacket.parse(from: pkt) == nil)
    }
}
