import Foundation
import Testing
@testable import SwiftNetStack

// MARK: - Test UDP NAT Intercept New Datagram

@Test func testUDPNATInterceptNewDatagram() {
    let table = UDPNATTable()

    let srcIP = ipToUInt32("192.168.65.2")
    let dstIP = ipToUInt32("8.8.8.8")
    let dg = UDPDatagram(
        srcIP: srcIP, dstIP: dstIP,
        srcPort: 12345, dstPort: 53,
        payload: Data("test-dns-query".utf8)
    )

    let handled = table.intercept(dg)
    // Even with failed connect (no actual host), intercept should return true (handled)
    #expect(handled, "Intercept should return true for external UDP datagram")

    // Note: socket creation may fail in test environment (no real network),
    // but the entry should still be tracked
}

// MARK: - Test UDP NAT Multiple Intercepts Same Flow

@Test func testUDPNATInterceptSameFlow() {
    let table = UDPNATTable()

    let srcIP = ipToUInt32("192.168.65.2")
    let dstIP = ipToUInt32("1.1.1.1")

    let dg1 = UDPDatagram(
        srcIP: srcIP, dstIP: dstIP,
        srcPort: 12345, dstPort: 53,
        payload: Data("query-1".utf8)
    )
    let dg2 = UDPDatagram(
        srcIP: srcIP, dstIP: dstIP,
        srcPort: 12345, dstPort: 53,
        payload: Data("query-2".utf8)
    )

    table.intercept(dg1)
    table.intercept(dg2)

    let key = UDPNATKey(srcIP: srcIP, dstIP: dstIP, srcPort: 12345, dstPort: 53)
    if let entry = table.entries[key] {
        #expect(entry.egressQ.count == 2, "expected 2 egress datagrams, got \(entry.egressQ.count)")
    }
}

// MARK: - Test UDP NAT Different Destinations

@Test func testUDPNATDifferentDestinations() {
    let table = UDPNATTable()

    let srcIP = ipToUInt32("192.168.65.2")
    let dg1 = UDPDatagram(
        srcIP: srcIP, dstIP: ipToUInt32("8.8.8.8"),
        srcPort: 12345, dstPort: 53,
        payload: Data("query-1".utf8)
    )
    let dg2 = UDPDatagram(
        srcIP: srcIP, dstIP: ipToUInt32("1.1.1.1"),
        srcPort: 12345, dstPort: 53,
        payload: Data("query-2".utf8)
    )

    table.intercept(dg1)
    table.intercept(dg2)

    #expect(table.count() == 2, "expected 2 entries (different destinations), got \(table.count())")
}

// MARK: - Test UDP NAT Same Src Different Ports

@Test func testUDPNATDifferentSrcPorts() {
    let table = UDPNATTable()

    let srcIP = ipToUInt32("192.168.65.2")
    let dstIP = ipToUInt32("8.8.8.8")
    let dg1 = UDPDatagram(
        srcIP: srcIP, dstIP: dstIP,
        srcPort: 12345, dstPort: 53,
        payload: Data("query-1".utf8)
    )
    let dg2 = UDPDatagram(
        srcIP: srcIP, dstIP: dstIP,
        srcPort: 12346, dstPort: 53,
        payload: Data("query-2".utf8)
    )

    table.intercept(dg1)
    table.intercept(dg2)

    #expect(table.count() == 2, "expected 2 entries (different src ports), got \(table.count())")
}

// MARK: - Test UDP NAT Flush Egress

@Test func testUDPNATFlushEgress() {
    let table = UDPNATTable()

    let srcIP = ipToUInt32("192.168.65.2")
    let dstIP = ipToUInt32("8.8.8.8")
    let dg = UDPDatagram(
        srcIP: srcIP, dstIP: dstIP,
        srcPort: 12345, dstPort: 53,
        payload: Data("test".utf8)
    )

    table.intercept(dg)

    // FlushEgress should not panic even if host socket write fails
    table.flushEgress()

    let key = UDPNATKey(srcIP: srcIP, dstIP: dstIP, srcPort: 12345, dstPort: 53)
    if let entry = table.entries[key] {
        #expect(entry.egressQ.isEmpty, "expected empty egress queue after flush, got \(entry.egressQ.count)")
    }
}

// MARK: - Test UDP NAT Cleanup

@Test func testUDPNATCleanup() {
    let table = UDPNATTable()

    let srcIP = ipToUInt32("192.168.65.2")
    let dstIP = ipToUInt32("8.8.8.8")
    let dg = UDPDatagram(
        srcIP: srcIP, dstIP: dstIP,
        srcPort: 12345, dstPort: 53,
        payload: Data("test".utf8)
    )
    table.intercept(dg)

    #expect(table.count() == 1)

    // Advance past idle timeout (90s)
    table.cleanup(now: Date().addingTimeInterval(100))

    #expect(table.count() == 0, "expected 0 entries after idle timeout, got \(table.count())")
}

// MARK: - Test UDP NAT Keep Active Entry

@Test func testUDPNATKeepActiveEntry() {
    let table = UDPNATTable()

    let srcIP = ipToUInt32("192.168.65.2")
    let dstIP = ipToUInt32("8.8.8.8")
    let dg = UDPDatagram(
        srcIP: srcIP, dstIP: dstIP,
        srcPort: 12345, dstPort: 53,
        payload: Data("test".utf8)
    )
    table.intercept(dg)

    table.cleanup(now: Date()) // cleanup at current time

    #expect(table.count() == 1, "expected 1 active entry, got \(table.count())")
}

// MARK: - Test UDP NAT Deliver to VM

@Test func testUDPNATDeliverToVM() {
    let table = UDPNATTable()

    // Manually set up an entry with ingress data
    let srcIP = ipToUInt32("192.168.65.2")
    let dstIP = ipToUInt32("8.8.8.8")
    let key = UDPNATKey(srcIP: srcIP, dstIP: dstIP, srcPort: 12345, dstPort: 53)
    let entry = UDPNATEntry(key: key)
    entry.ingressQ = [
        UDPDatagram(
            srcIP: dstIP, dstIP: srcIP,
            srcPort: 53, dstPort: 12345,
            payload: Data("dns-response".utf8)
        )
    ]
    table.entries[key] = entry

    let delivered = table.deliverToVM()
    #expect(delivered.count == 1, "expected 1 delivered datagram, got \(delivered.count)")
    #expect(delivered[0].srcPort == 53 && delivered[0].dstPort == 12345,
            "expected ports (53, 12345), got (\(delivered[0].srcPort), \(delivered[0].dstPort))")

    // After delivery, ingress queue should be cleared
    #expect(entry.ingressQ.isEmpty, "expected empty ingress queue after delivery")
}

// MARK: - Test UDP NAT Key Equality

@Test func testUDPNATKeyEquality() {
    let k1 = UDPNATKey(srcIP: 0x0A000001, dstIP: 0x08080808, srcPort: 12345, dstPort: 53)
    let k2 = UDPNATKey(srcIP: 0x0A000001, dstIP: 0x08080808, srcPort: 12345, dstPort: 53)
    let k3 = UDPNATKey(srcIP: 0x0A000001, dstIP: 0x08080808, srcPort: 12346, dstPort: 53)

    #expect(k1 == k2, "same keys should be equal")
    #expect(k1 != k3, "different ports should be different keys")
    #expect(k1.hashValue == k2.hashValue, "same keys should have same hash")
}

// MARK: - Test UDP NAT Max Payload

@Test func testUDPNATMaxPayload() {
    let entry = UDPNATEntry(key: UDPNATKey(srcIP: 0, dstIP: 0, srcPort: 0, dstPort: 0))
    #expect(entry.maxPayload == 65507, "max UDP payload should be 65507")
}
