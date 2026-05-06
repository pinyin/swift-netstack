import Testing
@testable import SwiftNetStack

/// Tests for DHCPPacket.parse.
@Suite(.serialized)
struct DHCPPacketTests {

    func makeDHCPBytes(op: UInt8 = 1, xid: UInt32, chaddr: MACAddress,
                       msgType: DHCPMessageType, options: [(UInt8, [UInt8])] = []) -> [UInt8] {
        var bytes = [UInt8](repeating: 0, count: 247)
        bytes[0] = op
        bytes[1] = 1   // htype = Ethernet
        bytes[2] = 6   // hlen = MAC address length
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

    // MARK: - Audit issue #1: DHCP Pad option (RFC 2132 §3.1)

    /// AUDIT #1 REPRODUCTION: DHCP Pad option (code 0) causes the option scanner
    /// to `break` instead of `continue`, terminating the scan before reaching
    /// option 53 (message type). A valid DHCP packet with Pad bytes is incorrectly rejected.
    ///
    /// RFC 2132 §3.1: "The pad option may be used to align subsequent options on
    /// word boundaries." The scanner MUST skip Pad (i += 1; continue), not terminate.
    ///
    /// EXPECTED: parse succeeds, returns DHCPPacket with messageType == .discover
    /// ACTUAL:   parse returns nil (BUG)
    @Test func padOptionShouldNotBreakParsing() {
        let chaddr = MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF)
        var bytes = [UInt8](repeating: 0, count: 249)
        bytes[0] = 1  // BOOTREQUEST
        bytes[1] = 1  // htype = Ethernet
        bytes[2] = 6  // hlen = MAC address length
        var buf6 = [UInt8](repeating: 0, count: 6)
        chaddr.write(to: &buf6); bytes.replaceSubrange(28..<34, with: buf6)
        bytes[240] = 99; bytes[241] = 130; bytes[242] = 83; bytes[243] = 99

        // Single Pad byte before option 53 — per RFC 2132 §3.1, skip and continue.
        bytes[244] = 0     // Pad
        bytes[245] = 53; bytes[246] = 1; bytes[247] = DHCPMessageType.discover.rawValue
        bytes[248] = 255   // End

        let s = Storage.allocate(capacity: 249)
        bytes.withUnsafeBytes { s.data.copyMemory(from: $0.baseAddress!, byteCount: 249) }
        let pkt = PacketBuffer(storage: s, offset: 0, length: 249)

        let result = DHCPPacket.parse(from: pkt)
        #expect(result != nil,
            "AUDIT #1 FAIL: DHCP Pad option causes valid packet to be rejected")
        #expect(result?.messageType == .discover,
            "AUDIT #1 FAIL: message type should be discover")
    }

    /// AUDIT #1 REPRODUCTION variant: multiple Pad bytes interleaved.
    @Test func multiplePadOptionsShouldNotBreakParsing() {
        let chaddr = MACAddress(0x12, 0x22, 0x33, 0x44, 0x55, 0x66)
        var bytes = [UInt8](repeating: 0, count: 251)
        bytes[0] = 1
        bytes[1] = 1  // htype = Ethernet
        bytes[2] = 6  // hlen = MAC address length
        var buf6 = [UInt8](repeating: 0, count: 6)
        chaddr.write(to: &buf6); bytes.replaceSubrange(28..<34, with: buf6)
        bytes[240] = 99; bytes[241] = 130; bytes[242] = 83; bytes[243] = 99

        // Two Pad bytes before option 53 — common when aligning to word boundaries.
        bytes[244] = 0     // Pad
        bytes[245] = 0     // Pad
        bytes[246] = 53; bytes[247] = 1; bytes[248] = DHCPMessageType.request.rawValue
        bytes[249] = 50; bytes[250] = 0  // option 50 with zero-length (no End needed)

        let s = Storage.allocate(capacity: 251)
        bytes.withUnsafeBytes { s.data.copyMemory(from: $0.baseAddress!, byteCount: 251) }
        let pkt = PacketBuffer(storage: s, offset: 0, length: 251)

        let result = DHCPPacket.parse(from: pkt)
        #expect(result != nil,
            "AUDIT #1 FAIL: Multiple Pad options cause valid DHCP packet to be rejected")
        #expect(result?.messageType == .request,
            "AUDIT #1 FAIL: message type should be request")
    }

    @Test func parseBadMagicCookie() {
        var bytes = [UInt8](repeating: 0, count: 247)
        bytes[0] = 1; bytes[1] = 1; bytes[2] = 6  // htype=Ethernet, hlen=MAC addr
        // Magic cookie = 0,0,0,0 (bad)
        bytes[244] = 53; bytes[245] = 1; bytes[246] = 1  // valid option after bad cookie
        let s = Storage.allocate(capacity: 247)
        bytes.withUnsafeBytes { s.data.copyMemory(from: $0.baseAddress!, byteCount: 247) }
        let pkt = PacketBuffer(storage: s, offset: 0, length: 247)
        #expect(DHCPPacket.parse(from: pkt) == nil)
    }

    // MARK: - AUDIT #2: ciaddr not parsed

    /// Verifies fix for audit finding #2: `DHCPPacket` now parses the `ciaddr`
    /// field (BOOTP header offset 12-15). RFC 2131 requires RELEASE to use
    /// ciaddr to identify the IP being released.
    @Test func ciaddrParsedFromReleasePacket() {
        let chaddr = MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF)
        let expectedCIAddr = IPv4Address(100, 64, 1, 20)

        var bytes = makeDHCPBytes(op: 1, xid: 99, chaddr: chaddr, msgType: .release)
        expectedCIAddr.write(to: &bytes[12])

        let s = Storage.allocate(capacity: bytes.count)
        bytes.withUnsafeBytes { s.data.copyMemory(from: $0.baseAddress!, byteCount: bytes.count) }
        let pkt = PacketBuffer(storage: s, offset: 0, length: bytes.count)

        guard let dhcp = DHCPPacket.parse(from: pkt) else {
            Issue.record("failed to parse valid RELEASE packet")
            return
        }
        #expect(dhcp.ciaddr == expectedCIAddr,
            "ciaddr should be parsed from BOOTP header bytes 12-15")
    }

    // MARK: - AUDIT #7: htype/hlen validation (RFC 2131 §2)

    /// Verifies fix: DHCP packets with non-Ethernet hardware type (htype != 1)
    /// are rejected. Without this check, IEEE 802.11 frames (htype=6, hlen=8)
    /// would read only 6 bytes of an 8-byte hardware address.
    @Test func nonEthernetHardwareTypeRejected() {
        let chaddr = MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF)
        var bytes = makeDHCPBytes(xid: 1, chaddr: chaddr, msgType: .discover)
        bytes[1] = 6  // htype = IEEE 802.11 (not Ethernet)
        let s = Storage.allocate(capacity: bytes.count)
        bytes.withUnsafeBytes { s.data.copyMemory(from: $0.baseAddress!, byteCount: bytes.count) }
        let pkt = PacketBuffer(storage: s, offset: 0, length: bytes.count)
        #expect(DHCPPacket.parse(from: pkt) == nil,
            "DHCP packet with htype=6 (non-Ethernet) should be rejected")
    }

    @Test func wrongHardwareAddressLengthRejected() {
        let chaddr = MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF)
        var bytes = makeDHCPBytes(xid: 1, chaddr: chaddr, msgType: .discover)
        bytes[2] = 8  // hlen = 8 (not 6 for Ethernet MAC)
        let s = Storage.allocate(capacity: bytes.count)
        bytes.withUnsafeBytes { s.data.copyMemory(from: $0.baseAddress!, byteCount: bytes.count) }
        let pkt = PacketBuffer(storage: s, offset: 0, length: bytes.count)
        #expect(DHCPPacket.parse(from: pkt) == nil,
            "DHCP packet with hlen=8 (non-MAC) should be rejected")
    }
}
