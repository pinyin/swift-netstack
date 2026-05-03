import Foundation
import Testing
@testable import SwiftNetStack

// MARK: - UDP Header Parse

@Test func testUDPHeaderParse() {
    let data: [UInt8] = [
        0x12, 0x34, // srcPort 4660
        0x00, 0x50, // dstPort 80
        0x00, 0x20, // length 32
        0x00, 0x00, // checksum 0
    ]
    let hdr = UDPHeader.parse(data)
    #expect(hdr != nil, "parse returned nil")
    #expect(hdr!.srcPort == 4660)
    #expect(hdr!.dstPort == 80)
    #expect(hdr!.length == 32)
    #expect(hdr!.checksum == 0)
}

// MARK: - UDP Header Parse Too Short

@Test func testUDPHeaderParseTooShort() {
    let data = [UInt8](repeating: 0, count: 4)
    #expect(UDPHeader.parse(data) == nil, "should return nil for data < 8 bytes")
}

// MARK: - ParseUDP

@Test func testParseUDP() {
    let payload: [UInt8] = [0x48, 0x65, 0x6C, 0x6C, 0x6F]
    let hdr: [UInt8] = [
        0x04, 0xD2, // srcPort 1234
        0x00, 0x35, // dstPort 53
        0x00, UInt8(8 + payload.count), // length
        0x00, 0x00, // checksum
    ]
    let data = hdr + payload

    let (parsed, pd) = parseUDP(data)!
    #expect(parsed.srcPort == 1234)
    #expect(parsed.dstPort == 53)
    #expect(parsed.length == UInt16(8 + payload.count))
    #expect(pd == Data(payload), "payload mismatch")
}

// MARK: - ParseUDP Truncated Length

@Test func testParseUDPTruncatedLength() {
    // length field says 100, but only 8 bytes of payload exist
    let data: [UInt8] = [
        0x04, 0xD2, 0x00, 0x35,
        0x00, 0x64, // length=100
        0x00, 0x00,
        0x01, 0x02, 0x03,
    ]
    let (_, payload) = parseUDP(data)!
    // Payload should be truncated to actual available data
    #expect(payload.count == 3, "payload should be truncated to available data, got \(payload.count)")
}

// MARK: - ParseUDP Underflow Length

@Test func testParseUDPUnderflowLength() {
    // length field < 8 (claims only 4 bytes of UDP header)
    let data: [UInt8] = [
        0x04, 0xD2, 0x00, 0x35,
        0x00, 0x04, // length=4 (less than header size)
        0x00, 0x00,
        0x01, 0x02,
    ]
    let (_, payload) = parseUDP(data)!
    #expect(payload.isEmpty, "payload should be empty when length < 8")
}

// MARK: - BuildDatagram

@Test func testBuildDatagram() {
    let payload: [UInt8] = [0x01, 0x02, 0x03]
    let data = buildDatagram(srcPort: 53, dstPort: 12345, payload: Data(payload))

    #expect(data.count == 8 + payload.count)
    #expect(data[0] == 0x00 && data[1] == 0x35) // srcPort=53
    #expect(data[2] == 0x30 && data[3] == 0x39) // dstPort=12345
    #expect(data[4] == 0x00 && data[5] == UInt8(8 + payload.count)) // length
    #expect(Array(data[8...]) == payload)
}

// MARK: - BuildDatagram Empty Payload

@Test func testBuildDatagramEmptyPayload() {
    let data = buildDatagram(srcPort: 67, dstPort: 68, payload: Data())
    #expect(data.count == 8)
    #expect(data[0] == 0x00 && data[1] == 0x43) // srcPort=67
    #expect(data[4] == 0x00 && data[5] == 0x08) // length=8
}

// MARK: - UDPMux Dispatch

@Test func testUDPMuxDispatch() {
    let mux = UDPMux()

    var called = false
    mux.register(port: 80) { dg in
        called = true
        #expect(dg.dstPort == 80)
        return [UDPDatagram(srcIP: dg.dstIP, dstIP: dg.srcIP,
                            srcPort: dg.dstPort, dstPort: dg.srcPort,
                            payload: Data("response".utf8))]
    }

    let dg = UDPDatagram(
        srcIP: ipToUInt32("192.168.65.2"), dstIP: ipToUInt32("192.168.65.1"),
        srcPort: 12345, dstPort: 80,
        payload: Data("request".utf8)
    )

    mux.deliver(dg)
    #expect(called, "handler should have been called")

    let responses = mux.consumeOutputs()
    #expect(responses.count == 1)
    #expect(responses[0].srcPort == 80)
    #expect(responses[0].dstPort == 12345)
}

// MARK: - UDPMux No Handler

@Test func testUDPMuxNoHandler() {
    let mux = UDPMux()

    let dg = UDPDatagram(
        srcIP: ipToUInt32("192.168.65.2"), dstIP: ipToUInt32("192.168.65.1"),
        srcPort: 12345, dstPort: 9999,
        payload: Data("drop".utf8)
    )

    mux.deliver(dg)
    let responses = mux.consumeOutputs()
    #expect(responses.isEmpty, "unregistered port should produce no output")
}

// MARK: - UDPMux Multiple Handlers

@Test func testUDPMuxMultipleHandlers() {
    let mux = UDPMux()

    mux.register(port: 53) { dg in
        return [UDPDatagram(srcIP: dg.dstIP, dstIP: dg.srcIP,
                            srcPort: 53, dstPort: dg.srcPort,
                            payload: Data("dns-resp".utf8))]
    }
    mux.register(port: 67) { dg in
        return [UDPDatagram(srcIP: dg.dstIP, dstIP: dg.srcIP,
                            srcPort: 67, dstPort: dg.srcPort,
                            payload: Data("dhcp-resp".utf8))]
    }

    mux.deliver(UDPDatagram(srcIP: ipToUInt32("192.168.65.2"), dstIP: ipToUInt32("192.168.65.1"),
                             srcPort: 12345, dstPort: 53, payload: Data("dns".utf8)))
    mux.deliver(UDPDatagram(srcIP: ipToUInt32("192.168.65.2"), dstIP: ipToUInt32("192.168.65.1"),
                             srcPort: 12346, dstPort: 67, payload: Data("dhcp".utf8)))

    let responses = mux.consumeOutputs()
    #expect(responses.count == 2)
}

// MARK: - UDPMux Consume Clears

@Test func testUDPMuxConsumeClears() {
    let mux = UDPMux()

    mux.register(port: 80) { dg in
        return [UDPDatagram(srcIP: dg.dstIP, dstIP: dg.srcIP,
                            srcPort: 80, dstPort: dg.srcPort, payload: Data())]
    }

    mux.deliver(UDPDatagram(srcIP: 0, dstIP: 0, srcPort: 0, dstPort: 80, payload: Data()))
    let first = mux.consumeOutputs()
    #expect(first.count == 1)
    let second = mux.consumeOutputs()
    #expect(second.isEmpty, "second consume should be empty")
}

// MARK: - ARP Resolver

@Test func testARPResolverLookup() {
    let arp = ARPResolver()
    let ip = ipToUInt32("192.168.65.2")
    #expect(arp.lookup(ip: ip) == nil, "unset IP should return nil")
}

@Test func testARPResolverSetAndLookup() {
    let arp = ARPResolver()
    let ip = ipToUInt32("192.168.65.2")
    let mac = Data([0x02, 0x00, 0x00, 0x00, 0x00, 0x01])

    arp.set(ip: ip, mac: mac)
    #expect(arp.lookup(ip: ip) == mac)
}

@Test func testARPResolverOverwrite() {
    let arp = ARPResolver()
    let ip = ipToUInt32("192.168.65.2")
    let mac1 = Data([0x02, 0x00, 0x00, 0x00, 0x00, 0x01])
    let mac2 = Data([0x02, 0x00, 0x00, 0x00, 0x00, 0x02])

    arp.set(ip: ip, mac: mac1)
    arp.set(ip: ip, mac: mac2)
    #expect(arp.lookup(ip: ip) == mac2, "overwrite should update MAC")
}

@Test func testARPResolverMultipleIPs() {
    let arp = ARPResolver()
    let ip1 = ipToUInt32("192.168.65.2")
    let ip2 = ipToUInt32("192.168.65.3")
    let mac1 = Data([0x02, 0x00, 0x00, 0x00, 0x00, 0x01])
    let mac2 = Data([0x02, 0x00, 0x00, 0x00, 0x00, 0x02])

    arp.set(ip: ip1, mac: mac1)
    arp.set(ip: ip2, mac: mac2)

    #expect(arp.lookup(ip: ip1) == mac1)
    #expect(arp.lookup(ip: ip2) == mac2)
}

@Test func testARPResolverMACTruncation() {
    let arp = ARPResolver()
    let ip = ipToUInt32("10.0.0.1")
    let longMAC = Data([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])

    arp.set(ip: ip, mac: longMAC)
    let stored = arp.lookup(ip: ip)
    #expect(stored != nil)
    #expect(stored!.count == 6, "MAC should be truncated to 6 bytes")
    #expect(stored! == Data([0x01, 0x02, 0x03, 0x04, 0x05, 0x06]))
}
