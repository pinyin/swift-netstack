import Foundation
import Testing
@testable import SwiftNetStack

// MARK: - IPv4 Packet Parse

@Test func testIPv4PacketParseBasic() {
    let header = buildIPv4Header(totalLen: 40, proto: protocolTCP,
                                  src: ipToUInt32("192.168.1.1"), dst: ipToUInt32("10.0.0.1"))
    let payload: [UInt8] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                             0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
                             0x11, 0x12, 0x13, 0x14]
    let data = header + payload
    let parsed = IPv4Packet.parse(data)

    #expect(parsed != nil, "parse returned nil")
    #expect(parsed!.version == 4)
    #expect(parsed!.ihl == 20)
    #expect(parsed!.totalLen == 40)
    #expect(parsed!.protocol == protocolTCP)
    #expect(parsed!.srcIP == ipToUInt32("192.168.1.1"))
    #expect(parsed!.dstIP == ipToUInt32("10.0.0.1"))
    #expect(parsed!.payload.count == 20)
    #expect(parsed!.payload == payload)
}

// MARK: - IPv4 Packet Serialize Roundtrip

@Test func testIPv4PacketRoundtrip() {
    let payload: [UInt8] = Array(repeating: 0xAB, count: 32)
    let src = ipToUInt32("172.16.0.1")
    let dst = ipToUInt32("8.8.8.8")

    let original = IPv4Packet(
        version: 4, ihl: 20, tos: 0,
        totalLen: UInt16(20 + payload.count), id: 0x1234,
        flags: 0, fragOffset: 0,
        ttl: 64, protocol: protocolUDP,
        checksum: 0, srcIP: src, dstIP: dst,
        payload: payload
    )

    let data = original.serialize()
    let parsed = IPv4Packet.parse(data)

    #expect(parsed != nil)
    #expect(parsed!.version == 4)
    #expect(parsed!.ihl == 20)
    #expect(parsed!.protocol == protocolUDP)
    #expect(parsed!.srcIP == src)
    #expect(parsed!.dstIP == dst)
    #expect(parsed!.payload == payload)
    #expect(parsed!.id == 0x1234)
    #expect(parsed!.ttl == 64)
}

// MARK: - IPv4 Parse Too Short

@Test func testIPv4PacketParseTooShort() {
    let data = [UInt8](repeating: 0, count: 10)
    #expect(IPv4Packet.parse(data) == nil, "should return nil for data < 20 bytes")
}

// MARK: - IPv4 Parse Invalid IHL

@Test func testIPv4PacketParseInvalidIHL() {
    var data = [UInt8](repeating: 0, count: 22)
    data[0] = 0x4F // IHL=15*4=60, but data.count=22 → IHL > data.count
    #expect(IPv4Packet.parse(data) == nil, "should return nil when IHL exceeds data length")
}

// MARK: - IPv4 isForUs

@Test func testIPv4IsForUs() {
    let ourIP = ipToUInt32("192.168.65.1")
    let pkt1 = IPv4Packet(
        version: 4, ihl: 20, tos: 0, totalLen: 20, id: 0,
        flags: 0, fragOffset: 0, ttl: 64, protocol: protocolTCP,
        checksum: 0, srcIP: ipToUInt32("10.0.0.1"), dstIP: ourIP, payload: []
    )
    #expect(pkt1.isForUs(ourIP), "packet addressed to our IP should match")

    let pkt2 = IPv4Packet(
        version: 4, ihl: 20, tos: 0, totalLen: 20, id: 0,
        flags: 0, fragOffset: 0, ttl: 64, protocol: protocolTCP,
        checksum: 0, srcIP: ipToUInt32("10.0.0.1"), dstIP: ipToUInt32("8.8.8.8"), payload: []
    )
    #expect(!pkt2.isForUs(ourIP), "packet to external IP should not match")

    // Broadcast
    let pkt3 = IPv4Packet(
        version: 4, ihl: 20, tos: 0, totalLen: 20, id: 0,
        flags: 0, fragOffset: 0, ttl: 64, protocol: protocolUDP,
        checksum: 0, srcIP: ipToUInt32("10.0.0.1"), dstIP: 0xFFFFFFFF, payload: []
    )
    #expect(pkt3.isForUs(ourIP), "broadcast packet should be 'for us'")
}

// MARK: - IPv4 isFragmented

@Test func testIPv4IsFragmented() {
    let unfragmented = IPv4Packet(
        version: 4, ihl: 20, tos: 0, totalLen: 20, id: 0,
        flags: 0, fragOffset: 0, ttl: 64, protocol: protocolTCP,
        checksum: 0, srcIP: 0, dstIP: 0, payload: []
    )
    #expect(!unfragmented.isFragmented(), "unfragmented packet should return false")

    let fragmented = IPv4Packet(
        version: 4, ihl: 20, tos: 0, totalLen: 20, id: 0,
        flags: 0, fragOffset: 100, ttl: 64, protocol: protocolTCP,
        checksum: 0, srcIP: 0, dstIP: 0, payload: []
    )
    #expect(fragmented.isFragmented(), "fragmented packet should return true")

    let moreFragments = IPv4Packet(
        version: 4, ihl: 20, tos: 0, totalLen: 20, id: 0,
        flags: 0x01, fragOffset: 0, ttl: 64, protocol: protocolTCP,
        checksum: 0, srcIP: 0, dstIP: 0, payload: []
    )
    #expect(moreFragments.isFragmented(), "MF flag set should be fragmented")
}

// MARK: - IPv4 Serialize Computes Checksum

@Test func testIPv4SerializeComputesChecksum() {
    let pkt = IPv4Packet(
        version: 4, ihl: 20, tos: 0,
        totalLen: 20, id: 0xABCD,
        flags: 0, fragOffset: 0,
        ttl: 64, protocol: protocolTCP,
        checksum: 0,
        srcIP: ipToUInt32("192.168.1.1"),
        dstIP: ipToUInt32("192.168.1.2"),
        payload: []
    )
    let data = pkt.serialize()
    let checksum = UInt16(data[10]) << 8 | UInt16(data[11])
    #expect(checksum != 0, "checksum should be non-zero")

    // Insert computed checksum into header and verify
    var toVerify = data
    // Checksum is already computed, verify it
    #expect(ipChecksum(Array(toVerify[0..<20])) == 0, "checksum verification failed")
}

// MARK: - ICMP Packet Parse

@Test func testICMPPacketParse() {
    let payload: [UInt8] = [0x01, 0x02, 0x03, 0x04]
    let icmp = ICMPPacket(type: 8, code: 0, checksum: 0, restHdr: 0x12340001, payload: payload)
    let data = icmp.serialize()

    let parsed = ICMPPacket.parse(data)
    #expect(parsed != nil)
    #expect(parsed!.type == 8)
    #expect(parsed!.code == 0)
    #expect(parsed!.restHdr == 0x12340001)
    #expect(parsed!.payload == payload)
}

// MARK: - ICMP Packet Parse Too Short

@Test func testICMPPacketParseTooShort() {
    let data = [UInt8](repeating: 0, count: 4)
    #expect(ICMPPacket.parse(data) == nil, "should return nil for data < 8 bytes")
}

// MARK: - ICMP Roundtrip

@Test func testICMPPacketRoundtrip() {
    let payload: [UInt8] = Array(repeating: 0xAA, count: 56)
    let original = ICMPPacket(type: 0, code: 0, checksum: 0, restHdr: 0x56780001, payload: payload)
    let data = original.serialize()
    let parsed = ICMPPacket.parse(data)

    #expect(parsed != nil)
    #expect(parsed!.type == 0)
    #expect(parsed!.code == 0)
    #expect(parsed!.restHdr == 0x56780001)
    #expect(parsed!.payload == payload)
}

// MARK: - Build Echo Reply

@Test func testBuildEchoReply() {
    let payload: [UInt8] = [0xDE, 0xAD, 0xBE, 0xEF]
    let req = ICMPPacket(type: 8, code: 0, checksum: 0, restHdr: 0xABCD0001, payload: payload)
    let reply = buildEchoReply(req)

    #expect(reply.type == 0, "echo reply type should be 0")
    #expect(reply.code == 0)
    #expect(reply.restHdr == req.restHdr, "restHdr should be preserved")
    #expect(reply.payload == req.payload, "payload should be preserved")
}

// MARK: - ICMP Parse Handles Various Types

@Test func testICMPPacketParseVariousTypes() {
    // Echo Request (type 8)
    let req = ICMPPacket(type: 8, code: 0, checksum: 0, restHdr: 0, payload: [])
    #expect(ICMPPacket.parse(req.serialize())?.type == 8)

    // Echo Reply (type 0)
    let reply = ICMPPacket(type: 0, code: 0, checksum: 0, restHdr: 0, payload: [])
    #expect(ICMPPacket.parse(reply.serialize())?.type == 0)

    // Destination Unreachable (type 3)
    let unreach = ICMPPacket(type: 3, code: 1, checksum: 0, restHdr: 0, payload: [])
    let parsed = ICMPPacket.parse(unreach.serialize())
    #expect(parsed?.type == 3)
    #expect(parsed?.code == 1)
}

// MARK: - ICMP Checksum Validation

@Test func testICMPChecksumValidation() {
    let payload: [UInt8] = Array(0..<48)
    let icmp = ICMPPacket(type: 8, code: 0, checksum: 0, restHdr: 0x11112222, payload: payload)
    let data = icmp.serialize()

    // Serialize computes checksum, verify it
    let cs = ipChecksum(data)
    #expect(cs == 0, "ICMP checksum validation failed: got \(String(cs, radix: 16))")
}

// MARK: - IPv4 Packet With Options

@Test func testIPv4PacketWithOptions() {
    // IHL > 5 means options present
    let options: [UInt8] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
    var header = [UInt8](repeating: 0, count: 28) // IHL=7, 28 bytes
    header[0] = 0x47 // version=4, IHL=7
    header[2] = 0x00; header[3] = UInt8(28 + 10) // totalLen = 38
    header[8] = 64 // ttl
    header[9] = protocolTCP
    for i in 0..<options.count { header[20 + i] = options[i] }
    // Set IPs
    let srcIP = ipToUInt32("10.0.0.1")
    let dstIP = ipToUInt32("10.0.0.2")
    header[12] = UInt8(srcIP >> 24); header[13] = UInt8(srcIP >> 16 & 0xFF)
    header[14] = UInt8(srcIP >> 8 & 0xFF); header[15] = UInt8(srcIP & 0xFF)
    header[16] = UInt8(dstIP >> 24); header[17] = UInt8(dstIP >> 16 & 0xFF)
    header[18] = UInt8(dstIP >> 8 & 0xFF); header[19] = UInt8(dstIP & 0xFF)

    let payload: [UInt8] = Array(0..<10)
    let data = header + payload

    let parsed = IPv4Packet.parse(data)
    #expect(parsed != nil)
    #expect(parsed!.ihl == 28)
    #expect(parsed!.payload == payload)
    #expect(parsed!.srcIP == srcIP)
}

// MARK: - IPv4 TotalLen Truncation

@Test func testIPv4TotalLenTruncation() {
    // totalLen larger than actual data should be truncated
    var header = [UInt8](repeating: 0, count: 20)
    header[0] = 0x45 // version=4, IHL=5
    header[2] = 0xFF; header[3] = 0xFF // totalLen=65535 (much larger than data)
    header[8] = 64; header[9] = protocolTCP
    let srcIP = ipToUInt32("10.0.0.1")
    let dstIP = ipToUInt32("10.0.0.2")
    header[12] = UInt8(srcIP >> 24); header[13] = UInt8(srcIP >> 16 & 0xFF)
    header[14] = UInt8(srcIP >> 8 & 0xFF); header[15] = UInt8(srcIP & 0xFF)
    header[16] = UInt8(dstIP >> 24); header[17] = UInt8(dstIP >> 16 & 0xFF)
    header[18] = UInt8(dstIP >> 8 & 0xFF); header[19] = UInt8(dstIP & 0xFF)

    let payload: [UInt8] = [0x42, 0x42]
    let data = header + payload

    let parsed = IPv4Packet.parse(data)
    #expect(parsed != nil)
    #expect(parsed!.totalLen == UInt16(data.count)) // totalLen truncated
    #expect(parsed!.payload.count == 2)
}
