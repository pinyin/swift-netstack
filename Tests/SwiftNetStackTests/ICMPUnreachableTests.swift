import Testing
@testable import SwiftNetStack
import Darwin

// MARK: - ICMP Unreachable Code Parameter

@Test func buildICMPUnreachableHeader_writesCode3ForPortUnreachable() {
    let io = IOBuffer(maxFrames: 4, mtu: 2048)
    let hostMAC = MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF)
    let clientMAC = MACAddress(0x11, 0x22, 0x33, 0x44, 0x55, 0x66)
    let gwIP = IPv4Address(10, 0, 0, 1)
    let clientIP = IPv4Address(10, 0, 0, 2)

    let ofs = buildICMPUnreachableHeader(
        io: io, hostMAC: hostMAC, clientMAC: clientMAC,
        gatewayIP: gwIP, clientIP: clientIP, code: 3)
    #expect(ofs >= 0)
    let icmpPtr = io.output.baseAddress!.advanced(by: ofs + ethHeaderLen + ipv4HeaderLen)
    let buf = UnsafeRawBufferPointer(start: icmpPtr, count: 8)
    #expect(buf[0] == 3, "Type == 3 (Destination Unreachable)")
    #expect(buf[1] == 3, "Code == 3 (Port Unreachable)")
}

@Test func buildICMPUnreachableHeader_code2ForProtocolUnreachable() {
    let io = IOBuffer(maxFrames: 4, mtu: 2048)
    let hostMAC = MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF)
    let clientMAC = MACAddress(0x11, 0x22, 0x33, 0x44, 0x55, 0x66)
    let gwIP = IPv4Address(10, 0, 0, 1)
    let clientIP = IPv4Address(10, 0, 0, 2)

    let ofs = buildICMPUnreachableHeader(
        io: io, hostMAC: hostMAC, clientMAC: clientMAC,
        gatewayIP: gwIP, clientIP: clientIP, code: 2)
    #expect(ofs >= 0)
    let icmpPtr = io.output.baseAddress!.advanced(by: ofs + ethHeaderLen + ipv4HeaderLen)
    let buf = UnsafeRawBufferPointer(start: icmpPtr, count: 8)
    #expect(buf[0] == 3, "Type == 3 (Destination Unreachable)")
    #expect(buf[1] == 2, "Code == 2 (Protocol Unreachable)")
}

@Test func buildICMPUnreachableHeader_defaultCodeIs2() {
    // Backward compat: calling without code parameter should still produce Code 2
    let io = IOBuffer(maxFrames: 4, mtu: 2048)
    let hostMAC = MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF)
    let clientMAC = MACAddress(0x11, 0x22, 0x33, 0x44, 0x55, 0x66)
    let gwIP = IPv4Address(10, 0, 0, 1)
    let clientIP = IPv4Address(10, 0, 0, 2)

    let ofs = buildICMPUnreachableHeader(
        io: io, hostMAC: hostMAC, clientMAC: clientMAC,
        gatewayIP: gwIP, clientIP: clientIP)
    #expect(ofs >= 0)
    let icmpPtr = io.output.baseAddress!.advanced(by: ofs + ethHeaderLen + ipv4HeaderLen)
    let buf = UnsafeRawBufferPointer(start: icmpPtr, count: 8)
    #expect(buf[1] == 2, "Default code == 2 (Protocol Unreachable)")
}
