import Foundation
import Testing
@testable import SwiftNetStack

// MARK: - Frame Parse/Serialize Roundtrip

@Test func testParseFrame() {
    let dstMAC = Data([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF])
    let srcMAC = Data([0x02, 0x00, 0x00, 0x00, 0x00, 0x01])
    let payload = [UInt8](repeating: 0, count: 28)

    let frame = Frame(dstMAC: dstMAC, srcMAC: srcMAC, etherType: etherTypeARP, payload: Data(payload))

    let data = frame.serialize()
    let parsed = Frame.parse(data)

    #expect(parsed != nil, "ParseFrame returned nil")
    #expect(parsed!.etherType == etherTypeARP, "expected ARP, got \(String(parsed!.etherType, radix: 16))")
    #expect(parsed!.dstMAC == dstMAC, "DstMAC mismatch")
    #expect(parsed!.srcMAC == srcMAC, "SrcMAC mismatch")
}

@Test func testParseFrameIPv4() {
    let dstMAC = Data([0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xee])
    let srcMAC = Data([0x02, 0x00, 0x00, 0x00, 0x00, 0x01])
    let payload: [UInt8] = [0x45, 0x00, 0x00, 0x28] // start of IPv4 header

    let frame = Frame(dstMAC: dstMAC, srcMAC: srcMAC, etherType: etherTypeIPv4, payload: Data(payload))
    let data = frame.serialize()
    let parsed = Frame.parse(data)

    #expect(parsed != nil)
    #expect(parsed!.etherType == etherTypeIPv4)
    #expect(parsed!.payload.count == payload.count)
}

@Test func testParseFrameTooShort() {
    let short = [UInt8](repeating: 0, count: 10)
    #expect(Frame.parse(short) == nil, "should return nil for short data")
}

// MARK: - ARP Parse/Serialize Roundtrip

@Test func testParseARPRequest() {
    let senderMAC = Data([0x02, 0x00, 0x00, 0x00, 0x00, 0x01])
    let senderIP = Data([192, 168, 65, 2])
    let targetIP = Data([192, 168, 65, 1])
    let targetMAC = Data([0, 0, 0, 0, 0, 0])

    let arp = ARPPacket(
        hardwareType: 1, protocolType: 0x0800,
        hardwareLen: 6, protocolLen: 4,
        operation: arpRequest,
        senderMAC: senderMAC, senderIP: senderIP,
        targetMAC: targetMAC, targetIP: targetIP
    )

    let data = arp.serialize()
    let parsed = ARPPacket.parse(data)

    #expect(parsed != nil, "ParseARP returned nil")
    #expect(parsed!.operation == arpRequest, "expected ARPRequest")
    #expect(parsed!.senderIP == senderIP, "SenderIP mismatch")
    #expect(parsed!.targetIP == targetIP, "TargetIP mismatch")
    #expect(parsed!.senderMAC == senderMAC, "SenderMAC mismatch")
}

@Test func testBuildARPReply() {
    let gatewayMAC = Data([0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xee])
    let gatewayIP = Data([192, 168, 65, 1])
    let senderMAC = Data([0x02, 0x00, 0x00, 0x00, 0x00, 0x01])
    let senderIP = Data([192, 168, 65, 2])

    let reply = buildARPReply(senderMAC: gatewayMAC, senderIP: gatewayIP,
                               targetMAC: senderMAC, targetIP: senderIP)

    #expect(reply.operation == arpReply, "expected ARPReply")
    #expect(reply.senderIP == gatewayIP, "SenderIP should be gateway IP")
    #expect(reply.targetIP == senderIP, "TargetIP should be sender IP")
    #expect(reply.senderMAC == gatewayMAC, "SenderMAC should be gateway MAC")
    #expect(reply.targetMAC == senderMAC, "TargetMAC should be sender MAC")
}

@Test func testARPRoundtrip() {
    let mac = Data([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
    let ip = Data([10, 0, 0, 1])

    let original = ARPPacket(
        hardwareType: 1, protocolType: 0x0800,
        hardwareLen: 6, protocolLen: 4,
        operation: arpRequest,
        senderMAC: mac, senderIP: ip,
        targetMAC: zeroMAC, targetIP: ip
    )

    let data = original.serialize()
    let parsed = ARPPacket.parse(data)

    #expect(parsed != nil)
    #expect(parsed!.hardwareType == original.hardwareType)
    #expect(parsed!.protocolType == original.protocolType)
    #expect(parsed!.operation == original.operation)
    #expect(parsed!.senderMAC == original.senderMAC)
    #expect(parsed!.senderIP == original.senderIP)
}

@Test func testParseARPTooShort() {
    let short = [UInt8](repeating: 0, count: 20)
    #expect(ARPPacket.parse(short) == nil, "should return nil for short data")
}

// MARK: - MAC String Formatting

@Test func testMACString() {
    let mac = Data([0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xee])
    #expect(macStr(mac) == "5a:94:ef:e4:0c:ee")
}

@Test func testMACStringShort() {
    let mac = Data([0x02, 0x00])
    #expect(macStr(mac) == "02:00")
}

// MARK: - Frame Description

@Test func testFrameDescription() {
    let frame = Frame(dstMAC: Data([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]),
                      srcMAC: Data([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]),
                      etherType: etherTypeARP,
                      payload: Data(repeating: 0, count: 28))
    let desc = frame.description
    #expect(desc.contains("0x806"))
    #expect(desc.contains("ff:ff:ff:ff:ff:ff"))
}

// MARK: - IPv4 Parse/Serialize Roundtrip

func buildIPv4Header(version: UInt8 = 4, ihl: UInt8 = 5, tos: UInt8 = 0,
                     totalLen: UInt16, id: UInt16 = 0x1234, flags: UInt8 = 0,
                     ttl: UInt8 = 64, proto: UInt8, src: UInt32, dst: UInt32) -> [UInt8] {
    var buf = [UInt8](repeating: 0, count: Int(ihl) * 4)
    buf[0] = (version << 4) | ihl
    buf[1] = tos
    buf[2] = UInt8(totalLen >> 8)
    buf[3] = UInt8(totalLen & 0xFF)
    buf[4] = UInt8(id >> 8)
    buf[5] = UInt8(id & 0xFF)
    buf[6] = (flags << 5)
    buf[7] = 0 // fragment offset
    buf[8] = ttl
    buf[9] = proto
    // checksum at 10-11, leave as 0
    buf[12] = UInt8(src >> 24); buf[13] = UInt8(src >> 16 & 0xFF)
    buf[14] = UInt8(src >> 8 & 0xFF); buf[15] = UInt8(src & 0xFF)
    buf[16] = UInt8(dst >> 24); buf[17] = UInt8(dst >> 16 & 0xFF)
    buf[18] = UInt8(dst >> 8 & 0xFF); buf[19] = UInt8(dst & 0xFF)
    return buf
}

@Test func testIPChecksumComputation() {
    // Known test data: IPv4 header bytes
    let data: [UInt8] = [
        0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00,
        0x40, 0x11, 0x00, 0x00, 0xc0, 0xa8, 0x00, 0x01,
        0xc0, 0xa8, 0x00, 0xc7,
    ]
    let cs = ipChecksum(data)
    #expect(cs != 0, "checksum should not be zero")

    // Verify by inserting the checksum
    var withChecksum = data
    withChecksum[10] = UInt8(cs >> 8)
    withChecksum[11] = UInt8(cs & 0xFF)
    let verified = ipChecksum(withChecksum)
    #expect(verified == 0, "checksum verification failed: got \(String(verified, radix: 16))")
}

@Test func testIPChecksumAllZeros() {
    let zeros = [UInt8](repeating: 0, count: 20)
    let cs = ipChecksum(zeros)
    // All zeros should give 0xFFFF (which is the ones' complement of 0)
    #expect(cs == 0xFFFF, "checksum of all zeros should be 0xFFFF")
}

// MARK: - Ones' Complement Sum

@Test func testOnesComplementSumBasic() {
    let data: [UInt8] = [0x00, 0x01, 0x00, 0x02]
    let cs = onesComplementSum(data)
    // Sum = 0x0001 + 0x0002 = 0x0003, ones' complement = 0xFFFC
    #expect(cs == 0xFFFC, "got \(String(cs, radix: 16))")
}

@Test func testOnesComplementSumOddLength() {
    let data: [UInt8] = [0x00, 0x01, 0x00] // odd length, last byte padded with 0
    let cs = onesComplementSum(data)
    // Sum = 0x0001 + 0x0000 = 0x0001, ones' complement = 0xFFFE
    #expect(cs == 0xFFFE, "got \(String(cs, radix: 16))")
}

// MARK: - ICMP Echo Request Build

@Test func testBuildICMPEchoRequest() {
    let payload = [UInt8]([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07])
    let req = buildICMPEchoRequest(id: 0x1234, seq: 0x0001, payload: payload)

    #expect(req.count == 8 + payload.count)
    #expect(req[0] == 8, "type should be Echo Request (8)")
    #expect(req[1] == 0, "code should be 0")
    // id at offset 4-5
    #expect(req[4] == 0x12 && req[5] == 0x34, "id mismatch")
    // seq at offset 6-7
    #expect(req[6] == 0x00 && req[7] == 0x01, "seq mismatch")
    // payload
    #expect(Array(req[8...]) == payload)
}

@Test func testBuildICMPReplyData() {
    let payload = [UInt8]([0x10, 0x20, 0x30])
    let reply = buildICMPReplyData(id: 0xABCD, seq: 0x0002, payload: payload)

    #expect(reply[0] == 0, "type should be Echo Reply (0)")
    #expect(reply[1] == 0, "code should be 0")
    #expect(reply[4] == 0xAB && reply[5] == 0xCD)
    #expect(reply[6] == 0x00 && reply[7] == 0x02)
}

// MARK: - IP to UInt32 roundtrip

@Test func testIPConversionRoundtrip() {
    let ips = ["0.0.0.0", "255.255.255.255", "192.168.65.1",
                "10.0.0.1", "172.16.0.1", "8.8.8.8"]
    for ip in ips {
        #expect(ipString(ipToUInt32(ip)) == ip, "roundtrip failed for \(ip)")
    }
}

@Test func testIPConversionInvalid() {
    #expect(ipToUInt32("not.an.ip") == 0)
    #expect(ipToUInt32("1.2.3") == 0)
    #expect(ipToUInt32("1.2.3.4.5") == 0)
}
