import Foundation
import Testing
@testable import SwiftNetStack

// MARK: - NAT Helpers

func fakeNATTCPSegment(srcIP: UInt32, dstIP: UInt32, srcPort: UInt16, dstPort: UInt16,
                        seq: UInt32, ack: UInt32, flags: UInt8, payload: [UInt8] = []) -> TCPSegment {
    let tuple = Tuple(srcIP: srcIP, dstIP: dstIP, srcPort: srcPort, dstPort: dstPort)
    let raw = buildSegment(tuple: tuple, seq: seq, ack: ack, flags: flags, window: 65535, wscale: 0, payload: payload)
    let header = TCPHeader(
        srcPort: srcPort, dstPort: dstPort,
        seqNum: seq, ackNum: ack,
        dataOffset: 20, flags: flags,
        windowSize: 65535, checksum: 0, urgentPtr: 0
    )
    return TCPSegment(header: header, payload: payload, tuple: tuple, raw: raw)
}

// MARK: - Test NAT Intercept New SYN

@Test func testNATInterceptNewSYN() {
    let nt = NATTable()
    let cfg = makeConfig(gatewayIP: ipToUInt32("192.168.65.1"))
    let ts = TCPState(cfg: cfg)

    let vmIP = ipToUInt32("192.168.65.2")
    let extIP = ipToUInt32("93.184.216.34") // example.com

    let synSeg = fakeNATTCPSegment(srcIP: vmIP, dstIP: extIP,
                                    srcPort: 12345, dstPort: 80,
                                    seq: 1000, ack: 0, flags: TCPFlag.syn)

    let handled = nt.intercept(synSeg, tcpState: ts)
    #expect(handled, "expected SYN to be handled by NAT")
    #expect(nt.count() == 1, "expected 1 NAT entry, got \(nt.count())")

    // TCP connection created
    #expect(ts.connectionCount() == 1, "expected 1 TCP connection, got \(ts.connectionCount())")

    // Pending dial
    #expect(nt.pendingDials.count == 1, "expected 1 pending dial, got \(nt.pendingDials.count)")
}

// MARK: - Test NAT Intercept Existing Connection

@Test func testNATInterceptExistingConn() {
    let nt = NATTable()
    let cfg = makeConfig(gatewayIP: ipToUInt32("192.168.65.1"))
    let ts = TCPState(cfg: cfg)

    let vmIP = ipToUInt32("192.168.65.2")
    let extIP = ipToUInt32("93.184.216.34")

    // First SYN creates entry
    let syn = fakeNATTCPSegment(srcIP: vmIP, dstIP: extIP,
                                 srcPort: 12345, dstPort: 80,
                                 seq: 1000, ack: 0, flags: TCPFlag.syn)
    _ = nt.intercept(syn, tcpState: ts)

    // ACK for the same flow goes to existing entry
    let ack = fakeNATTCPSegment(srcIP: vmIP, dstIP: extIP,
                                 srcPort: 12345, dstPort: 80,
                                 seq: 1001, ack: 1, flags: TCPFlag.ack)
    let handled = nt.intercept(ack, tcpState: ts)
    #expect(handled, "expected ACK to be handled by NAT")
    #expect(nt.count() == 1, "expected still 1 NAT entry, got \(nt.count())")

    // Check segment was added to VM connection's pendingSegs
    var foundSeg = false
    for entry in nt.entries.values {
        if let conn = entry.vmConn, !conn.pendingSegs.isEmpty {
            foundSeg = true
            break
        }
    }
    #expect(foundSeg, "expected pending segment on VM conn")
}

// MARK: - Test NAT Non-SYN Ignored

@Test func testNATNonSYNIgnored() {
    let nt = NATTable()
    let cfg = makeConfig(gatewayIP: ipToUInt32("192.168.65.1"))
    let ts = TCPState(cfg: cfg)

    let vmIP = ipToUInt32("192.168.65.2")
    let extIP = ipToUInt32("93.184.216.34")

    // Non-SYN to unknown destination → ignored
    let ack = fakeNATTCPSegment(srcIP: vmIP, dstIP: extIP,
                                 srcPort: 12345, dstPort: 80,
                                 seq: 1001, ack: 0, flags: TCPFlag.ack)
    let handled = nt.intercept(ack, tcpState: ts)
    #expect(!handled, "expected non-SYN to be ignored for unknown connection")
    #expect(nt.count() == 0, "expected 0 entries, got \(nt.count())")
}

// MARK: - Test NAT Cleanup

@Test func testNATCleanup() {
    let nt = NATTable()
    let cfg = makeConfig(gatewayIP: ipToUInt32("192.168.65.1"))
    let ts = TCPState(cfg: cfg)

    let vmIP = ipToUInt32("192.168.65.2")
    let extIP = ipToUInt32("93.184.216.34")

    let syn = fakeNATTCPSegment(srcIP: vmIP, dstIP: extIP,
                                 srcPort: 12345, dstPort: 80,
                                 seq: 1000, ack: 0, flags: TCPFlag.syn)
    _ = nt.intercept(syn, tcpState: ts)

    // Mark entries as closed on both sides
    for entry in nt.entries.values {
        entry.hostClosed = true
        entry.vmClosed = true
    }
    nt.cleanup()

    #expect(nt.count() == 0, "expected 0 entries after cleanup, got \(nt.count())")
}

// MARK: - Test NAT SYNACK Not Intercepted

@Test func testNATSYNACKNotIntercepted() {
    let nt = NATTable()
    let cfg = makeConfig(gatewayIP: ipToUInt32("192.168.65.1"))
    let ts = TCPState(cfg: cfg)

    let vmIP = ipToUInt32("192.168.65.2")
    let extIP = ipToUInt32("93.184.216.34")

    // SYN-ACK (from external to VM) should NOT be intercepted as new entry
    let synAck = fakeNATTCPSegment(srcIP: extIP, dstIP: vmIP,
                                    srcPort: 80, dstPort: 12345,
                                    seq: 5000, ack: 1001,
                                    flags: TCPFlag.syn | TCPFlag.ack)
    let handled = nt.intercept(synAck, tcpState: ts)
    // It has SYN but also ACK, so !isACK() is false → not intercepted as new
    #expect(!handled, "SYN-ACK should not create NAT entry")
}

// MARK: - Test NAT No Crash on Multiple Polls

@Test func testNATNoCrashOnMultiplePolls() {
    let nt = NATTable()
    let cfg = makeConfig(gatewayIP: ipToUInt32("192.168.65.1"))
    let ts = TCPState(cfg: cfg)

    let vmIP = ipToUInt32("192.168.65.2")
    let extIP = ipToUInt32("1.1.1.1")

    let syn = fakeNATTCPSegment(srcIP: vmIP, dstIP: extIP,
                                 srcPort: 12345, dstPort: 53,
                                 seq: 1000, ack: 0, flags: TCPFlag.syn)
    _ = nt.intercept(syn, tcpState: ts)

    // Multiple polls should not crash
    for _ in 0..<5 {
        nt.poll()
    }
    #expect(nt.count() == 1, "entries should survive benign poll calls")
}
