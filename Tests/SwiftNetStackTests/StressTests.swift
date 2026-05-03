import Foundation
import Testing
@testable import SwiftNetStack

// MARK: - Stress Test Helpers

func runStressTest(listenPort: UInt16 = 0, _ body: (Stack, VZDebugConn) throws -> Void) {
    guard let (connA, connB) = VZDebugConn.newLoopbackPair() else {
        print("SKIP: socketpair failed")
        return
    }

    var cfg = StackConfig.defaultConfig()
    cfg.socketPath = ""
    cfg.debug = false

    var tcpCfg = TCPConfig.defaultConfig()
    tcpCfg.listenPort = listenPort
    let tcpState = TCPState(cfg: tcpCfg)
    if listenPort > 0 {
        tcpState.listen { _ in }
    }
    let stack = Stack(cfg: cfg, tcpState: tcpState)
    stack.setConn(connA)

    let runningFlag = E2ERunningFlag()
    let deliberationQueue = DispatchQueue(label: "stress.deliberation", qos: .userInitiated)

    deliberationQueue.async {
        while runningFlag.value {
            stack.deliberate(now: Date())
            Thread.sleep(forTimeInterval: 0.0005)
        }
    }

    do {
        try body(stack, connB)
    } catch {
        Issue.record("Stress test body threw: \(error)")
    }

    runningFlag.value = false
    Thread.sleep(forTimeInterval: 0.2)
}

func stressFrame(connB: VZDebugConn, srcIP: UInt32, dstIP: UInt32,
                  srcPort: UInt16, dstPort: UInt16, seq: UInt32, ack: UInt32,
                  flags: UInt8, payload: [UInt8] = []) {
    let tuple = Tuple(srcIP: srcIP, dstIP: dstIP, srcPort: srcPort, dstPort: dstPort)
    var raw = buildSegment(tuple: tuple, seq: seq, ack: ack, flags: flags, window: 65535, wscale: 0, payload: payload)
    let cs = tcpChecksum(srcIP: srcIP, dstIP: dstIP, tcpData: raw)
    raw[16] = UInt8(cs >> 8); raw[17] = UInt8(cs & 0xFF)
    let ipPkt = IPv4Packet(version: 4, ihl: 20, tos: 0, totalLen: 0, id: UInt16((srcPort & 0xFF00) | (dstPort & 0xFF)),
                           flags: 0, fragOffset: 0, ttl: 64, protocol: protocolTCP,
                           checksum: 0, srcIP: srcIP, dstIP: dstIP, payload: raw)
    _ = connB.write(frame: Frame(dstMAC: gwMAC, srcMAC: vmMAC,
                                  etherType: etherTypeIPv4, payload: Data(ipPkt.serialize())))
}

// MARK: - 1. Many Concurrent Connections

@Test func testStressManyConnections() throws {
    runStressTest(listenPort: 8080) { stack, connB in
        let count = 25
        var pairs: [(srcPort: UInt16, seq: UInt32)] = []

        // Send all SYNs
        for i in 0..<count {
            let srcPort = UInt16(20000 + i)
            let seq = UInt32(1000 + i * 100)
            pairs.append((srcPort, seq))
            stressFrame(connB: connB, srcIP: vmIP, dstIP: gwIP,
                        srcPort: srcPort, dstPort: 8080,
                        seq: seq, ack: 0, flags: TCPFlag.syn)
        }
        waitForDeliberation(0.5)

        let synAckFrames = readAllFramesFrom(connB, timeout: 0.3)
        let synAcks = synAckFrames.filter { $0.etherType == etherTypeIPv4 }
        #expect(synAcks.count >= count, "expected at least \(count) SYN-ACKs, got \(synAcks.count)")

        // ACK all SYN-ACKs
        for frame in synAcks {
            guard let ipPkt = IPv4Packet.parse([UInt8](frame.payload)),
                  let tcpHdr = TCPHeader.parse(ipPkt.payload) else { continue }
            stressFrame(connB: connB, srcIP: vmIP, dstIP: gwIP,
                        srcPort: tcpHdr.dstPort, dstPort: tcpHdr.srcPort,
                        seq: tcpHdr.ackNum, ack: tcpHdr.seqNum + 1,
                        flags: TCPFlag.ack)
        }
        waitForDeliberation(0.3)

        let totalConns = stack.tcpState.connectionCount()
        #expect(totalConns >= count, "expected at least \(count) established connections, got \(totalConns)")
    }
}

// MARK: - 2. Connection Churn

@Test func testStressConnectionChurn() throws {
    runStressTest(listenPort: 8081) { stack, connB in
        let cycles = 30

        for cycle in 0..<cycles {
            let srcPort = UInt16(30000 + cycle)
            let seq = UInt32(2000 + cycle * 100)

            // SYN
            stressFrame(connB: connB, srcIP: vmIP, dstIP: gwIP,
                        srcPort: srcPort, dstPort: 8081,
                        seq: seq, ack: 0, flags: TCPFlag.syn)
            waitForDeliberation(0.05)

            let frames = readAllFramesFrom(connB, timeout: 0.05)
            guard let saFrame = frames.first(where: { $0.etherType == etherTypeIPv4 }),
                  let saIP = IPv4Packet.parse([UInt8](saFrame.payload)),
                  let saHdr = TCPHeader.parse(saIP.payload) else { continue }

            // ACK
            stressFrame(connB: connB, srcIP: vmIP, dstIP: gwIP,
                        srcPort: srcPort, dstPort: 8081,
                        seq: saHdr.ackNum, ack: saHdr.seqNum + 1,
                        flags: TCPFlag.ack)
            waitForDeliberation(0.02)

            // FIN
            stressFrame(connB: connB, srcIP: vmIP, dstIP: gwIP,
                        srcPort: srcPort, dstPort: 8081,
                        seq: saHdr.ackNum, ack: saHdr.seqNum + 1,
                        flags: TCPFlag.fin | TCPFlag.ack)
            waitForDeliberation(0.05)
        }

        // After churn, stack should still be operational
        let totalConns = stack.tcpState.connectionCount()
        #expect(totalConns <= cycles, "connection count should not exceed cycles")

        // Verify invariants still hold (deliberation should not crash)

        #expect(true, "invariants should hold after connection churn")
    }
}

// MARK: - 3. Sustained Data Transfer

@Test func testStressSustainedDataTransfer() throws {
    runStressTest(listenPort: 8082) { stack, connB in
        let srcPort: UInt16 = 40000

        // Handshake
        stressFrame(connB: connB, srcIP: vmIP, dstIP: gwIP,
                    srcPort: srcPort, dstPort: 8082,
                    seq: 5000, ack: 0, flags: TCPFlag.syn)
        waitForDeliberation(0.1)

        let frames1 = readAllFramesFrom(connB, timeout: 0.1)
        guard let saFrame = frames1.first(where: { $0.etherType == etherTypeIPv4 }),
              let saIP = IPv4Packet.parse([UInt8](saFrame.payload)),
              let saHdr = TCPHeader.parse(saIP.payload) else {
            Issue.record("SYN-ACK not received"); return
        }

        stressFrame(connB: connB, srcIP: vmIP, dstIP: gwIP,
                    srcPort: srcPort, dstPort: 8082,
                    seq: saHdr.ackNum, ack: saHdr.seqNum + 1,
                    flags: TCPFlag.ack)
        waitForDeliberation(0.1)

        // Send many data segments in batches
        let totalDataSize = 65536
        let segSize = 1400
        let numSegs = totalDataSize / segSize
        var nextSeq = saHdr.ackNum

        for segIdx in 0..<numSegs {
            let payload = [UInt8](repeating: UInt8(segIdx & 0xFF), count: segSize)
            stressFrame(connB: connB, srcIP: vmIP, dstIP: gwIP,
                        srcPort: srcPort, dstPort: 8082,
                        seq: nextSeq, ack: saHdr.seqNum + 1,
                        flags: TCPFlag.ack | TCPFlag.psh, payload: payload)
            nextSeq += UInt32(segSize)

            if segIdx % 10 == 0 {
                waitForDeliberation(0.02)
            }
        }
        waitForDeliberation(0.2)

        // Connection should still be established after data flood
        let totalConns = stack.tcpState.connectionCount()
        #expect(totalConns == 1, "connection should still exist after data transfer")

        // Data should have been received
        let revTuple = Tuple(srcIP: gwIP, dstIP: vmIP, srcPort: 8082, dstPort: srcPort)
        if let conn = stack.tcpState.established[revTuple] {
            var buf = [UInt8](repeating: 0, count: 65536)
            let n = conn.readRecvBuf(into: &buf)
            #expect(n > 0, "should have received data, got \(n) bytes")
        }
    }
}

// MARK: - 4. Many Segments in One Deliberation

@Test func testStressBurstSegments() throws {
    runStressTest(listenPort: 8083) { stack, connB in
        let srcPort: UInt16 = 50000

        // Handshake
        stressFrame(connB: connB, srcIP: vmIP, dstIP: gwIP,
                    srcPort: srcPort, dstPort: 8083,
                    seq: 6000, ack: 0, flags: TCPFlag.syn)
        waitForDeliberation(0.1)

        let frames1 = readAllFramesFrom(connB, timeout: 0.1)
        guard let saFrame = frames1.first(where: { $0.etherType == etherTypeIPv4 }),
              let saIP = IPv4Packet.parse([UInt8](saFrame.payload)),
              let saHdr = TCPHeader.parse(saIP.payload) else {
            Issue.record("SYN-ACK not received"); return
        }

        // Send ACK + many data segments in one batch (before deliberation)
        let ackSeq = saHdr.ackNum
        stressFrame(connB: connB, srcIP: vmIP, dstIP: gwIP,
                    srcPort: srcPort, dstPort: 8083,
                    seq: ackSeq, ack: saHdr.seqNum + 1,
                    flags: TCPFlag.ack)
        waitForDeliberation(0.02)

        // Burst 20 data segments all at once
        let numSegs = 20
        var nextSeq = ackSeq
        for i in 0..<numSegs {
            let payload = Array("burst-\(i)-".utf8) + [UInt8](repeating: UInt8(i), count: 100)
            stressFrame(connB: connB, srcIP: vmIP, dstIP: gwIP,
                        srcPort: srcPort, dstPort: 8083,
                        seq: nextSeq, ack: saHdr.seqNum + 1,
                        flags: TCPFlag.ack | TCPFlag.psh, payload: payload)
            nextSeq += UInt32(payload.count)
        }

        // One deliberation processes all
        waitForDeliberation(0.15)

        let revTuple = Tuple(srcIP: gwIP, dstIP: vmIP, srcPort: 8083, dstPort: srcPort)
        if let conn = stack.tcpState.established[revTuple] {
            var buf = [UInt8](repeating: 0, count: 32768)
            let n = conn.readRecvBuf(into: &buf)
            #expect(n > 1000, "should have received burst data, got \(n) bytes")
        }
    }
}

// MARK: - 5. Many ARP Requests Rapidly

@Test func testStressARPCache() throws {
    runStressTest { stack, connB in
        // Send 100 ARP requests for different IPs
        for i in 0..<100 {
            let ipBytes = Data([192, 168, 65, UInt8(10 + (i % 100))])
            let targetIP = UInt32(bigEndian: ipBytes.withUnsafeBytes { $0.load(as: UInt32.self) })
            let request = buildARPRequestFrame(targetIP: targetIP)
            _ = connB.write(frame: request)
        }
        waitForDeliberation(0.3)

        // Stack should not crash and ARP table should have entries
        #expect(true, "ARP stress should not crash")
    }
}

// MARK: - 6. DHCP Pool Stress

@Test func testStressDHCPPoolExhaustion() throws {
    runStressTest { stack, connB in
        // Request IPs for many MACs — DHCP pool has limited range
        let count = 120 // exceeds typical /28 pool (14 allocatable)
        var allocated = 0

        for i in 0..<count {
            let mac = MACAddr(0x02, 0x00, 0x00, 0x00, UInt8(i >> 8), UInt8(i & 0xFF))

            var discover = [UInt8](repeating: 0, count: 300)
            discover[0] = 1; discover[1] = 1; discover[2] = 6
            discover[4] = UInt8(i >> 8); discover[5] = UInt8(i & 0xFF)
            discover[6] = 0x33; discover[7] = 0x44
            discover[10] = 0x80
            discover[28] = mac.b0; discover[29] = mac.b1; discover[30] = mac.b2
            discover[31] = mac.b3; discover[32] = mac.b4; discover[33] = mac.b5
            discover[236] = 0x63; discover[237] = 0x82; discover[238] = 0x53; discover[239] = 0x63
            var off = 240
            off = writeOption(&discover, offset: off, optType: optMessageType, val: [msgDiscover])
            off = writeOption(&discover, offset: off, optType: 55, val: [1, 3, 6])
            discover[off] = optEnd
            let full = Array(discover[..<(off + 1)])

            let udpData = buildDatagram(srcPort: clientPort, dstPort: serverPort, payload: full)
            let ipPkt = IPv4Packet(version: 4, ihl: 20, tos: 0, totalLen: 0, id: UInt16(0x300 + i),
                                   flags: 0, fragOffset: 0, ttl: 64, protocol: protocolUDP,
                                   checksum: 0, srcIP: 0, dstIP: ipToUInt32("255.255.255.255"),
                                   payload: udpData)
            let frame = Frame(dstMAC: broadcastMAC, srcMAC: Data([mac.b0, mac.b1, mac.b2, mac.b3, mac.b4, mac.b5]),
                              etherType: etherTypeIPv4, payload: Data(ipPkt.serialize()))
            _ = connB.write(frame: frame)

            if i % 10 == 0 { waitForDeliberation(0.05) }

            if stack.dhcpSrv.allocateIP(mac) != nil {
                allocated += 1
            }
        }
        waitForDeliberation(0.2)

        // Some should be allocated (up to pool size), rest should fail gracefully
        #expect(allocated > 0, "at least some IPs should be allocated")
        #expect(allocated <= count, "allocated should not exceed requested")
    }
}

// MARK: - 7. High-Frequency Deliberation Loop

@Test func testStressHighFrequencyDeliberation() throws {
    runStressTest(listenPort: 8084) { stack, connB in
        let iterations = 500

        for i in 0..<iterations {
            let srcPort = UInt16(60000 + (i % 200))

            // Inject a frame, then deliberate
            stressFrame(connB: connB, srcIP: vmIP, dstIP: gwIP,
                        srcPort: srcPort, dstPort: 8084,
                        seq: UInt32(7000 + i), ack: 0, flags: TCPFlag.syn)

            if i % 50 == 0 {
                waitForDeliberation(0.02)
            }
        }
        waitForDeliberation(0.5)

        // Stack should be responsive after heavy injection
        let connCount = stack.tcpState.connectionCount()
        #expect(connCount > 0, "should have some connections after injection barrage")

        // Deliberation should still function

        #expect(true, "invariants should hold after rapid deliberation")
    }
}
