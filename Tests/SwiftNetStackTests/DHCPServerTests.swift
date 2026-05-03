import Foundation
import Testing
@testable import SwiftNetStack

// MARK: - DHCP Helpers

func buildDHCPDiscover(txID: UInt32, mac: MACAddr) -> [UInt8] {
    var buf = [UInt8](repeating: 0, count: 300)
    buf[0] = 1 // BOOTREQUEST
    buf[1] = 1 // Ethernet
    buf[2] = 6 // MAC length
    buf[4] = UInt8(txID >> 24); buf[5] = UInt8(txID >> 16 & 0xFF)
    buf[6] = UInt8(txID >> 8 & 0xFF); buf[7] = UInt8(txID & 0xFF)
    buf[10] = 0x80 // broadcast flag

    buf[28] = mac.b0; buf[29] = mac.b1; buf[30] = mac.b2
    buf[31] = mac.b3; buf[32] = mac.b4; buf[33] = mac.b5

    // Magic cookie
    buf[236] = 0x63; buf[237] = 0x82; buf[238] = 0x53; buf[239] = 0x63
    var offset = 240
    offset = writeOption(&buf, offset: offset, optType: optMessageType, val: [msgDiscover])
    offset = writeOption(&buf, offset: offset, optType: 55, val: [1, 3, 6]) // parameter request list
    buf[offset] = optEnd

    return Array(buf[..<(offset + 1)])
}

func buildDHCPRequest(txID: UInt32, mac: MACAddr, reqIP: UInt32, serverIP: UInt32) -> [UInt8] {
    var buf = [UInt8](repeating: 0, count: 300)
    buf[0] = 1; buf[1] = 1; buf[2] = 6
    buf[4] = UInt8(txID >> 24); buf[5] = UInt8(txID >> 16 & 0xFF)
    buf[6] = UInt8(txID >> 8 & 0xFF); buf[7] = UInt8(txID & 0xFF)
    buf[10] = 0x80

    buf[28] = mac.b0; buf[29] = mac.b1; buf[30] = mac.b2
    buf[31] = mac.b3; buf[32] = mac.b4; buf[33] = mac.b5

    buf[236] = 0x63; buf[237] = 0x82; buf[238] = 0x53; buf[239] = 0x63
    var offset = 240
    offset = writeOption(&buf, offset: offset, optType: optMessageType, val: [msgRequest])
    offset = writeOption(&buf, offset: offset, optType: optRequestedIP,
                         val: [UInt8(reqIP >> 24), UInt8(reqIP >> 16 & 0xFF),
                               UInt8(reqIP >> 8 & 0xFF), UInt8(reqIP & 0xFF)])
    offset = writeOption(&buf, offset: offset, optType: optServerIdentifier,
                         val: [UInt8(serverIP >> 24), UInt8(serverIP >> 16 & 0xFF),
                               UInt8(serverIP >> 8 & 0xFF), UInt8(serverIP & 0xFF)])
    buf[offset] = optEnd

    return Array(buf[..<(offset + 1)])
}

func buildDHCPRelease(txID: UInt32, mac: MACAddr) -> [UInt8] {
    var buf = [UInt8](repeating: 0, count: 300)
    buf[0] = 1; buf[1] = 1; buf[2] = 6
    buf[4] = UInt8(txID >> 24); buf[5] = UInt8(txID >> 16 & 0xFF)
    buf[6] = UInt8(txID >> 8 & 0xFF); buf[7] = UInt8(txID & 0xFF)

    buf[28] = mac.b0; buf[29] = mac.b1; buf[30] = mac.b2
    buf[31] = mac.b3; buf[32] = mac.b4; buf[33] = mac.b5

    buf[236] = 0x63; buf[237] = 0x82; buf[238] = 0x53; buf[239] = 0x63
    var offset = 240
    offset = writeOption(&buf, offset: offset, optType: optMessageType, val: [msgRelease])
    buf[offset] = optEnd

    return Array(buf[..<(offset + 1)])
}

// MARK: - Test DHCP Discover

@Test func testDHCPDiscover() {
    let cfg = DHCPServerConfig.defaultConfig()
    let srv = DHCPServer(cfg: cfg)
    let handler = srv.handler()

    let mac = MACAddr(0x02, 0x00, 0x00, 0x00, 0x00, 0x01)
    let dg = UDPDatagram(
        srcIP: 0, dstIP: ipToUInt32("255.255.255.255"),
        srcPort: clientPort, dstPort: serverPort,
        payload: buildDHCPDiscover(txID: 0x12345678, mac: mac)
    )

    let responses = handler(dg)
    #expect(responses.count == 1, "expected 1 response, got \(responses.count)")

    let offer = responses[0]
    #expect(offer.dstPort == clientPort, "expected DstPort 68, got \(offer.dstPort)")
    #expect(offer.srcPort == serverPort, "expected SrcPort 67, got \(offer.srcPort)")

    // Check DHCP message type = OFFER
    let msgType = srv.getOption(offer.payload, optType: optMessageType)
    #expect(msgType != nil && msgType!.count == 1 && msgType![0] == msgOffer,
            "expected DHCPOFFER, got \(String(describing: msgType))")

    // Check yiaddr is non-zero
    let yiaddr = UInt32(offer.payload[16]) << 24 | UInt32(offer.payload[17]) << 16 |
                 UInt32(offer.payload[18]) << 8 | UInt32(offer.payload[19])
    #expect(yiaddr != 0, "expected non-zero yiaddr")

    // Verify subnet mask option
    let subnetOpt = srv.getOption(offer.payload, optType: optSubnetMask)
    #expect(subnetOpt != nil && subnetOpt!.count == 4, "expected subnet mask option")

    // Verify router option
    let routerOpt = srv.getOption(offer.payload, optType: optRouter)
    #expect(routerOpt != nil && routerOpt!.count == 4, "expected router option")

    // Verify DNS option
    let dnsOpt = srv.getOption(offer.payload, optType: optDNSServer)
    #expect(dnsOpt != nil && dnsOpt!.count == 4, "expected DNS option")

    // Verify server identifier
    let srvID = srv.getOption(offer.payload, optType: optServerIdentifier)
    #expect(srvID != nil && srvID!.count == 4, "expected server identifier option")
}

// MARK: - Test DHCP Request → Ack

@Test func testDHCPRequestAck() {
    let cfg = DHCPServerConfig.defaultConfig()
    let srv = DHCPServer(cfg: cfg)
    let handler = srv.handler()

    let mac = MACAddr(0x02, 0x00, 0x00, 0x00, 0x00, 0x02)

    // First DISCOVER
    let discover = UDPDatagram(
        srcIP: 0, dstIP: ipToUInt32("255.255.255.255"),
        srcPort: clientPort, dstPort: serverPort,
        payload: buildDHCPDiscover(txID: 0xAAAA, mac: mac)
    )
    let responses = handler(discover)
    #expect(responses.count == 1, "expected 1 DISCOVER response, got \(responses.count)")

    let yiaddr = UInt32(responses[0].payload[16]) << 24 | UInt32(responses[0].payload[17]) << 16 |
                 UInt32(responses[0].payload[18]) << 8 | UInt32(responses[0].payload[19])

    // Now REQUEST the same IP
    let request = UDPDatagram(
        srcIP: 0, dstIP: ipToUInt32("255.255.255.255"),
        srcPort: clientPort, dstPort: serverPort,
        payload: buildDHCPRequest(txID: 0xAAAA, mac: mac, reqIP: yiaddr,
                                   serverIP: ipToUInt32("192.168.65.1"))
    )
    let responses2 = handler(request)
    #expect(responses2.count == 1, "expected 1 REQUEST response, got \(responses2.count)")

    let ack = responses2[0]
    let msgType = srv.getOption(ack.payload, optType: optMessageType)
    #expect(msgType != nil && msgType!.count == 1 && msgType![0] == msgAck,
            "expected DHCPACK, got \(String(describing: msgType))")
}

// MARK: - Test DHCP Request → Nak (wrong server)

@Test func testDHCPRequestNak() {
    let cfg = DHCPServerConfig.defaultConfig()
    let srv = DHCPServer(cfg: cfg)
    let handler = srv.handler()

    // Request an IP that was never offered (from a different MAC)
    let mac = MACAddr(0x02, 0x00, 0x00, 0x00, 0x00, 0x99)
    let request = UDPDatagram(
        srcIP: 0, dstIP: ipToUInt32("255.255.255.255"),
        srcPort: clientPort, dstPort: serverPort,
        payload: buildDHCPRequest(txID: 0xBBBB, mac: mac,
                                   reqIP: ipToUInt32("192.168.65.2"),
                                   serverIP: ipToUInt32("192.168.65.1"))
    )
    let responses = handler(request)
    #expect(responses.count == 1, "expected 1 response (NAK), got \(responses.count)")

    let nak = responses[0]
    let msgType = srv.getOption(nak.payload, optType: optMessageType)
    #expect(msgType != nil && msgType!.count == 1 && msgType![0] == msgNak,
            "expected DHCPNAK, got \(String(describing: msgType))")
}

// MARK: - Test DHCP Release

@Test func testDHCPRelease() {
    let cfg = DHCPServerConfig.defaultConfig()
    let srv = DHCPServer(cfg: cfg)
    let handler = srv.handler()

    let mac = MACAddr(0x02, 0x00, 0x00, 0x00, 0x00, 0x03)

    // Allocate
    let discover = UDPDatagram(
        srcIP: 0, dstIP: ipToUInt32("255.255.255.255"),
        srcPort: clientPort, dstPort: serverPort,
        payload: buildDHCPDiscover(txID: 0xBBBB, mac: mac)
    )
    _ = handler(discover)

    // Release
    let release = UDPDatagram(
        srcIP: 0, dstIP: ipToUInt32("255.255.255.255"),
        srcPort: clientPort, dstPort: serverPort,
        payload: buildDHCPRelease(txID: 0xBBBB, mac: mac)
    )
    let responses = handler(release)
    #expect(responses.isEmpty, "expected no response for RELEASE")

    // New DISCOVER from same MAC should get an IP (released pool slot)
    let responses2 = handler(discover)
    #expect(responses2.count == 1, "expected response after release, got \(responses2.count)")
}

// MARK: - Test DHCP IP Pool

@Test func testDHCPIPPoolsAllocation() {
    let cfg = DHCPServerConfig.defaultConfig()
    let srv = DHCPServer(cfg: cfg)

    // Allocate for 3 different MACs
    let mac1 = MACAddr(0x02, 0x00, 0x00, 0x00, 0x00, 0x01)
    let mac2 = MACAddr(0x02, 0x00, 0x00, 0x00, 0x00, 0x02)
    let mac3 = MACAddr(0x02, 0x00, 0x00, 0x00, 0x00, 0x03)

    let ip1 = srv.allocateIP(mac1)
    let ip2 = srv.allocateIP(mac2)
    let ip3 = srv.allocateIP(mac3)

    #expect(ip1 != nil && ip2 != nil && ip3 != nil, "should allocate 3 IPs")
    #expect(ip1 != ip2 && ip2 != ip3 && ip1 != ip3, "IPs should be unique")

    // Same MAC gets same IP
    #expect(srv.allocateIP(mac1) == ip1, "same MAC should get same IP")

    // Release and reallocate
    srv.releaseLease(mac1)
    let mac4 = MACAddr(0x02, 0x00, 0x00, 0x00, 0x00, 0x04)
    let ip4 = srv.allocateIP(mac4)
    #expect(ip4 == ip1, "released IP should be reused, expected \(ip1!), got \(ip4!)")
}

// MARK: - Test DHCP onLease callback

@Test func testDHCPOnLeaseCallback() {
    let cfg = DHCPServerConfig.defaultConfig()
    let srv = DHCPServer(cfg: cfg)
    let handler = srv.handler()

    let mac = MACAddr(0x02, 0x00, 0x00, 0x00, 0x00, 0x05)
    var callbackIP: UInt32?
    var callbackMAC: MACAddr?

    srv.onLease = { ip, macAddr in
        callbackIP = ip
        callbackMAC = macAddr
    }

    // Discover
    let discover = UDPDatagram(
        srcIP: 0, dstIP: ipToUInt32("255.255.255.255"),
        srcPort: clientPort, dstPort: serverPort,
        payload: buildDHCPDiscover(txID: 0xCCCC, mac: mac)
    )
    let responses = handler(discover)
    let yiaddr = UInt32(responses[0].payload[16]) << 24 | UInt32(responses[0].payload[17]) << 16 |
                 UInt32(responses[0].payload[18]) << 8 | UInt32(responses[0].payload[19])

    // Request (ACK triggers onLease)
    let request = UDPDatagram(
        srcIP: 0, dstIP: ipToUInt32("255.255.255.255"),
        srcPort: clientPort, dstPort: serverPort,
        payload: buildDHCPRequest(txID: 0xCCCC, mac: mac, reqIP: yiaddr,
                                   serverIP: ipToUInt32("192.168.65.1"))
    )
    _ = handler(request)

    #expect(callbackIP == yiaddr, "onLease callback IP mismatch")
    #expect(callbackMAC == mac, "onLease callback MAC mismatch")
}

// MARK: - Test DHCP Invalid Packets

@Test func testDHCPInvalidPackets() {
    let cfg = DHCPServerConfig.defaultConfig()
    let srv = DHCPServer(cfg: cfg)
    let handler = srv.handler()

    // Too short
    let short = UDPDatagram(
        srcIP: 0, dstIP: 0, srcPort: clientPort, dstPort: serverPort,
        payload: [UInt8](repeating: 0, count: 100)
    )
    #expect(handler(short).isEmpty, "should ignore short packet")

    // Not a request (op code != 1)
    var badOp = [UInt8](repeating: 0, count: 300)
    badOp[0] = 2 // REPLY
    badOp[236] = 0x63; badOp[237] = 0x82; badOp[238] = 0x53; badOp[239] = 0x63
    badOp[240] = optEnd
    let badReq = UDPDatagram(
        srcIP: 0, dstIP: 0, srcPort: clientPort, dstPort: serverPort,
        payload: Array(badOp[..<241])
    )
    #expect(handler(badReq).isEmpty, "should ignore non-request op code")

    // Unknown message type
    var unknownType = [UInt8](repeating: 0, count: 300)
    unknownType[0] = 1
    unknownType[236] = 0x63; unknownType[237] = 0x82; unknownType[238] = 0x53; unknownType[239] = 0x63
    var off = 240
    off = writeOption(&unknownType, offset: off, optType: optMessageType, val: [UInt8(99)])
    unknownType[off] = optEnd
    let unk = UDPDatagram(
        srcIP: 0, dstIP: 0, srcPort: clientPort, dstPort: serverPort,
        payload: Array(unknownType[..<(off + 1)])
    )
    #expect(handler(unk).isEmpty, "should ignore unknown message type")
}

// MARK: - Test DHCP Option Parsing

@Test func testDHCPGetOption() {
    let cfg = DHCPServerConfig.defaultConfig()
    let srv = DHCPServer(cfg: cfg)

    // Build a minimal packet with a specific option
    var buf = [UInt8](repeating: 0, count: 300)
    buf[0] = 2 // REPLY
    buf[236] = 0x63; buf[237] = 0x82; buf[238] = 0x53; buf[239] = 0x63
    var offset = 240
    offset = writeOption(&buf, offset: offset, optType: optRouter, val: [192, 168, 1, 1])
    offset = writeOption(&buf, offset: offset, optType: optSubnetMask, val: [255, 255, 255, 0])
    buf[offset] = optEnd

    let routerOpt = srv.getOption(Array(buf[..<(offset + 1)]), optType: optRouter)
    #expect(routerOpt == [192, 168, 1, 1], "router option mismatch")

    let subnetOpt = srv.getOption(Array(buf[..<(offset + 1)]), optType: optSubnetMask)
    #expect(subnetOpt == [255, 255, 255, 0], "subnet mask mismatch")

    // Non-existent option → nil
    let nonexistent = srv.getOption(Array(buf[..<(offset + 1)]), optType: optDNSServer)
    #expect(nonexistent == nil, "should return nil for missing option")
}

// MARK: - Test DHCP Pool Exhaustion

@Test func testDHCPPoolExhaustion() {
    var cfg = DHCPServerConfig.defaultConfig()
    cfg.poolSize = 2
    let srv = DHCPServer(cfg: cfg)

    let mac1 = MACAddr(0x02, 0x00, 0x00, 0x00, 0x00, 0x01)
    let mac2 = MACAddr(0x02, 0x00, 0x00, 0x00, 0x00, 0x02)
    let mac3 = MACAddr(0x02, 0x00, 0x00, 0x00, 0x00, 0x03)

    #expect(srv.allocateIP(mac1) != nil)
    #expect(srv.allocateIP(mac2) != nil)
    #expect(srv.allocateIP(mac3) == nil, "should return nil when pool is exhausted")
}
