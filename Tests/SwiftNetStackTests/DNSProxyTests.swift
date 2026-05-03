import Foundation
import Testing
@testable import SwiftNetStack

// MARK: - DNS Helpers

func makeTestDNSQuery(_ domain: String) -> [UInt8] {
    var buf = [UInt8](repeating: 0, count: 512)

    // Header
    buf[0] = 0x00; buf[1] = 0x01 // ID
    buf[2] = 0x01; buf[3] = 0x00 // flags: standard query
    buf[4] = 0x00; buf[5] = 0x01 // QDCOUNT=1

    // Question section starts at offset 12
    var offset = 12
    let parts = domain.split(separator: ".")
    for part in parts {
        buf[offset] = UInt8(part.count)
        offset += 1
        for ch in part.utf8 {
            buf[offset] = ch
            offset += 1
        }
    }
    buf[offset] = 0 // terminator
    offset += 1
    buf[offset] = 0x00; buf[offset + 1] = 0x01 // QTYPE=A
    buf[offset + 2] = 0x00; buf[offset + 3] = 0x01 // QCLASS=IN
    offset += 4

    return Array(buf[..<offset])
}

// Creates a DNSProxy with an empty upstream for immediate SERVFAIL generation.
// Uses a non-empty init string to avoid readSystemDNS(), then clears it.
func makeServfailProxy() -> DNSProxy {
    let proxy = DNSProxy(listenIP: ipToUInt32("192.168.65.1"), upstreamAddr: "127.0.0.1:9")
    proxy.set(upstream: "")
    return proxy
}

// MARK: - Test DNS Servfail

@Test func testDNSServfailWithNoUpstream() {
    let proxy = makeServfailProxy()

    let query = makeTestDNSQuery("example.com")
    let dg = UDPDatagram(
        srcIP: ipToUInt32("192.168.65.2"),
        dstIP: ipToUInt32("192.168.65.1"),
        srcPort: 12345, dstPort: dnsPort,
        payload: Data(query)
    )

    let handler = proxy.handler()
    let responses = handler(dg)
    // With empty upstream, enqueue generates SERVFAIL immediately and appends to ready.
    // The handler returns the result of enqueue, which returns [] (async pattern),
    // but SERVFAIL is placed directly in ready.
    // Poll/consumeResponses picks up the ready response.
    proxy.poll()
    let ready = proxy.consumeResponses()
    #expect(ready.count == 1, "expected 1 response (SERVFAIL), got \(ready.count)")
}

// MARK: - Test DNS Set Upstream

@Test func testDNSSetUpstream() {
    let proxy = DNSProxy(listenIP: ipToUInt32("192.168.65.1"), upstreamAddr: "127.0.0.1:9")
    let initial = proxy.upstream
    proxy.set(upstream: "8.8.8.8:53")
    #expect(proxy.upstream == "8.8.8.8:53")
    proxy.set(upstream: initial)
}

// MARK: - Test DNS Read System DNS

@Test func testDNSReadSystemDNS() {
    let upstream = DNSProxy.readSystemDNS()
    // Should either find a nameserver or return empty string
    #expect(upstream.isEmpty || upstream.contains(":53"),
            "expected empty or 'addr:53', got \(upstream)")
}

// MARK: - Test DNS Servfail Format

@Test func testDNSServfailResponseFormat() {
    let query = makeTestDNSQuery("example.com")
    let dg = UDPDatagram(
        srcIP: ipToUInt32("192.168.65.2"),
        dstIP: ipToUInt32("192.168.65.1"),
        srcPort: 12345, dstPort: dnsPort,
        payload: Data(query)
    )

    let proxy = makeServfailProxy()
    let handler = proxy.handler()
    _ = handler(dg)
    proxy.poll()
    let ready = proxy.consumeResponses()

    guard let resp = ready.first else {
        fatalError("no SERVFAIL response")
    }

    let payload = resp.payload
    #expect(payload.count >= 12, "response too short")

    // QR bit should be set (response)
    #expect((payload[2] & 0x80) != 0, "QR bit not set")

    // RCODE should be SERVFAIL (2)
    let rcode = payload[3] & 0x0F
    #expect(rcode == 2, "expected RCODE=SERVFAIL(2), got \(rcode)")
}

// MARK: - Test DNS Multiple Queries

@Test func testDNSMultipleQueries() {
    let proxy = makeServfailProxy()

    let query1 = makeTestDNSQuery("example.com")
    let query2 = makeTestDNSQuery("test.local")

    let dg1 = UDPDatagram(
        srcIP: ipToUInt32("192.168.65.2"), dstIP: ipToUInt32("192.168.65.1"),
        srcPort: 12345, dstPort: dnsPort, payload: Data(query1)
    )
    let dg2 = UDPDatagram(
        srcIP: ipToUInt32("192.168.65.2"), dstIP: ipToUInt32("192.168.65.1"),
        srcPort: 12346, dstPort: dnsPort, payload: Data(query2)
    )

    let handler = proxy.handler()
    _ = handler(dg1)
    _ = handler(dg2)

    proxy.poll()
    let ready = proxy.consumeResponses()
    #expect(ready.count == 2, "expected 2 responses, got \(ready.count)")
}

// MARK: - Test DNS No Crash Empty Query

@Test func testDNSNoCrashEmptyQuery() {
    let proxy = makeServfailProxy()
    let dg = UDPDatagram(
        srcIP: ipToUInt32("192.168.65.2"), dstIP: ipToUInt32("192.168.65.1"),
        srcPort: 12345, dstPort: dnsPort, payload: Data()
    )

    let handler = proxy.handler()
    _ = handler(dg)
    proxy.poll()
    let ready = proxy.consumeResponses()
    // Short payload (< 4 bytes) → servfail returns nil → no response
    #expect(ready.isEmpty, "short payload should produce no response (can't build SERVFAIL)")
}

// MARK: - Test DNS Consume Clears Queue

@Test func testDNSConsumeClearsQueue() {
    let proxy = makeServfailProxy()

    let dg = UDPDatagram(
        srcIP: ipToUInt32("192.168.65.2"), dstIP: ipToUInt32("192.168.65.1"),
        srcPort: 12345, dstPort: dnsPort,
        payload: Data(makeTestDNSQuery("example.com"))
    )

    let handler = proxy.handler()
    _ = handler(dg)
    proxy.poll()

    let first = proxy.consumeResponses()
    #expect(first.count == 1)

    let second = proxy.consumeResponses()
    #expect(second.isEmpty, "second consume should be empty")
}
