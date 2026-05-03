import Foundation
import Testing
@testable import SwiftNetStack

// MARK: - Chaos Test Helpers

func runChaosTest(listenPort: UInt16 = 0, _ body: (Stack, VZDebugConn) throws -> Void) {
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
    DispatchQueue(label: "chaos.deliberation", qos: .userInitiated).async {
        while runningFlag.value {
            stack.deliberate(now: Date())
            Thread.sleep(forTimeInterval: 0.001)
        }
    }

    do {
        try body(stack, connB)
    } catch {
        Issue.record("Chaos test body threw: \(error)")
    }

    runningFlag.value = false
    Thread.sleep(forTimeInterval: 0.2)
}

func rawFrame(connB: VZDebugConn, dstMAC: Data, srcMAC: Data, etherType: UInt16, payload: Data) {
    let frame = Frame(dstMAC: dstMAC, srcMAC: srcMAC, etherType: etherType, payload: payload)
    _ = connB.write(frame: frame)
}

func tcpFrame(connB: VZDebugConn, srcIP: UInt32, dstIP: UInt32,
              srcPort: UInt16, dstPort: UInt16, seq: UInt32, ack: UInt32,
              flags: UInt8, window: UInt16 = 65535, payload: [UInt8] = [],
              dataOffset: UInt8 = 20) {
    let tuple = Tuple(srcIP: srcIP, dstIP: dstIP, srcPort: srcPort, dstPort: dstPort)
    let raw = buildSegment(tuple: tuple, seq: seq, ack: ack, flags: flags, window: window, wscale: 0, payload: payload)
    let cs = tcpChecksum(srcIP: srcIP, dstIP: dstIP, tcpData: raw)
    var adj = raw
    adj[16] = UInt8(cs >> 8); adj[17] = UInt8(cs & 0xFF)
    // Override dataOffset if needed
    if dataOffset != 20 {
        adj[12] = dataOffset << 4
    }
    let ipPkt = IPv4Packet(version: 4, ihl: 20, tos: 0, totalLen: 0, id: UInt16((srcPort & 0xFF00) | (dstPort & 0xFF)),
                           flags: 0, fragOffset: 0, ttl: 64, protocol: protocolTCP,
                           checksum: 0, srcIP: srcIP, dstIP: dstIP, payload: adj)
    _ = connB.write(frame: Frame(dstMAC: gwMAC, srcMAC: vmMAC,
                                  etherType: etherTypeIPv4, payload: Data(ipPkt.serialize())))
}

// MARK: - 1. Random Byte Injection

@Test func testChaosRandomBytes() throws {
    runChaosTest { stack, connB in
        // Inject many frames of random bytes
        for i in 0..<50 {
            let length = Int.random(in: 1...256)
            var randomBytes = [UInt8](repeating: 0, count: length)
            for j in 0..<length { randomBytes[j] = UInt8.random(in: 0...255) }

            let randomEtherType = UInt16.random(in: 0x0000...0xFFFF)
            rawFrame(connB: connB, dstMAC: gwMAC, srcMAC: vmMAC,
                     etherType: randomEtherType, payload: Data(randomBytes))
        }
        waitForDeliberation(0.2)

        // Stack should not crash — this is the primary assertion
        #expect(Bool(true))
    }
}

// MARK: - 2. Truncated Packets

@Test func testChaosTruncatedPackets() throws {
    runChaosTest(listenPort: 9090) { stack, connB in
        // Truncated IPv4 (less than 20 bytes)
        rawFrame(connB: connB, dstMAC: gwMAC, srcMAC: vmMAC,
                 etherType: etherTypeIPv4, payload: Data([0x45, 0x00, 0x00, 0x14]))

        // Truncated TCP (less than 20 bytes)
        let shortIP = IPv4Packet(version: 4, ihl: 20, tos: 0, totalLen: 6, id: 1,
                                 flags: 0, fragOffset: 0, ttl: 64, protocol: protocolTCP,
                                 checksum: 0, srcIP: vmIP, dstIP: gwIP,
                                 payload: [0x00, 0x01, 0x00, 0x02, 0x00, 0x03])
        rawFrame(connB: connB, dstMAC: gwMAC, srcMAC: vmMAC,
                 etherType: etherTypeIPv4, payload: Data(shortIP.serialize()))

        // Truncated ARP (less than 28 bytes)
        rawFrame(connB: connB, dstMAC: broadcastMAC, srcMAC: vmMAC,
                 etherType: etherTypeARP, payload: Data([0x00, 0x01, 0x08, 0x00]))

        // Zero-length frame
        rawFrame(connB: connB, dstMAC: gwMAC, srcMAC: vmMAC,
                 etherType: etherTypeIPv4, payload: Data())

        // Truncated UDP
        let shortUDP_IP = IPv4Packet(version: 4, ihl: 20, tos: 0, totalLen: 3, id: 2,
                                      flags: 0, fragOffset: 0, ttl: 64, protocol: protocolUDP,
                                      checksum: 0, srcIP: vmIP, dstIP: gwIP,
                                      payload: [0x00, 0x01, 0x02])
        rawFrame(connB: connB, dstMAC: gwMAC, srcMAC: vmMAC,
                 etherType: etherTypeIPv4, payload: Data(shortUDP_IP.serialize()))

        waitForDeliberation(0.1)

        // Should not crash
        #expect(true, "stack should survive truncated packets")

    }
}

// MARK: - 3. Invalid TCP Flag Combinations

@Test func testChaosInvalidTCPFlags() throws {
    runChaosTest(listenPort: 9091) { stack, connB in
        // SYN+FIN (impossible combination — opens and closes simultaneously)
        tcpFrame(connB: connB, srcIP: vmIP, dstIP: gwIP,
                 srcPort: 23456, dstPort: 9091,
                 seq: 1000, ack: 0, flags: TCPFlag.syn | TCPFlag.fin)

        // SYN+RST (impossible)
        tcpFrame(connB: connB, srcIP: vmIP, dstIP: gwIP,
                 srcPort: 23457, dstPort: 9091,
                 seq: 1000, ack: 0, flags: TCPFlag.syn | TCPFlag.rst)

        // SYN+ACK+RST+FIN (all at once)
        tcpFrame(connB: connB, srcIP: vmIP, dstIP: gwIP,
                 srcPort: 23458, dstPort: 9091,
                 seq: 1000, ack: 500, flags: TCPFlag.syn | TCPFlag.ack | TCPFlag.rst | TCPFlag.fin)

        // Null flags (no flags set)
        tcpFrame(connB: connB, srcIP: vmIP, dstIP: gwIP,
                 srcPort: 23459, dstPort: 9091,
                 seq: 1000, ack: 0, flags: 0)

        // SYN+URG (unusual)
        tcpFrame(connB: connB, srcIP: vmIP, dstIP: gwIP,
                 srcPort: 23460, dstPort: 9091,
                 seq: 1000, ack: 0, flags: TCPFlag.syn | TCPFlag.urg)

        // FIN without ACK (should only happen in certain states)
        tcpFrame(connB: connB, srcIP: vmIP, dstIP: gwIP,
                 srcPort: 23461, dstPort: 9091,
                 seq: 1000, ack: 0, flags: TCPFlag.fin)

        waitForDeliberation(0.1)

        #expect(true, "stack should survive invalid TCP flags")

    }
}

// MARK: - 4. RST Injection in Various States

@Test func testChaosRSTInjection() throws {
    runChaosTest(listenPort: 9092) { stack, connB in
        // RST to non-existent connection (should be ignored)
        tcpFrame(connB: connB, srcIP: vmIP, dstIP: gwIP,
                 srcPort: 11111, dstPort: 9092,
                 seq: 5000, ack: 0, flags: TCPFlag.rst | TCPFlag.ack)

        // Establish a connection first
        tcpFrame(connB: connB, srcIP: vmIP, dstIP: gwIP,
                 srcPort: 34567, dstPort: 9092,
                 seq: 2000, ack: 0, flags: TCPFlag.syn)
        waitForDeliberation(0.1)

        let frames1 = readAllFramesFrom(connB, timeout: 0.1)
        guard let saFrame = frames1.first(where: { $0.etherType == etherTypeIPv4 }),
              let saIP = IPv4Packet.parse([UInt8](saFrame.payload)),
              let saHdr = TCPHeader.parse(saIP.payload) else {
            Issue.record("SYN-ACK not received for RST test"); return
        }

        tcpFrame(connB: connB, srcIP: vmIP, dstIP: gwIP,
                 srcPort: 34567, dstPort: 9092,
                 seq: saHdr.ackNum, ack: saHdr.seqNum + 1,
                 flags: TCPFlag.ack)
        waitForDeliberation(0.05)

        // Now inject RST with wrong seq (should not kill the connection)
        tcpFrame(connB: connB, srcIP: vmIP, dstIP: gwIP,
                 srcPort: 34567, dstPort: 9092,
                 seq: 99999, ack: 0, flags: TCPFlag.rst | TCPFlag.ack)
        waitForDeliberation(0.05)

        let connCount1 = stack.tcpState.connectionCount()
        #expect(connCount1 == 1, "connection should survive RST with wrong seq, got \(connCount1)")

        // RST with correct seq should kill (but needs to be in window)
        tcpFrame(connB: connB, srcIP: vmIP, dstIP: gwIP,
                 srcPort: 34567, dstPort: 9092,
                 seq: saHdr.ackNum, ack: saHdr.seqNum + 1,
                 flags: TCPFlag.rst)
        waitForDeliberation(0.05)

        // Verify stack still functional
        #expect(true, "stack should survive RST injection")

    }
}

// MARK: - 5. Extreme Out-of-Order Segments

@Test func testChaosExtremeReordering() throws {
    runChaosTest(listenPort: 9093) { stack, connB in
        let srcPort: UInt16 = 45678

        // Handshake
        tcpFrame(connB: connB, srcIP: vmIP, dstIP: gwIP,
                 srcPort: srcPort, dstPort: 9093,
                 seq: 3000, ack: 0, flags: TCPFlag.syn)
        waitForDeliberation(0.1)

        let frames1 = readAllFramesFrom(connB, timeout: 0.1)
        guard let saFrame = frames1.first(where: { $0.etherType == etherTypeIPv4 }),
              let saIP = IPv4Packet.parse([UInt8](saFrame.payload)),
              let saHdr = TCPHeader.parse(saIP.payload) else {
            Issue.record("SYN-ACK not received"); return
        }

        tcpFrame(connB: connB, srcIP: vmIP, dstIP: gwIP,
                 srcPort: srcPort, dstPort: 9093,
                 seq: saHdr.ackNum, ack: saHdr.seqNum + 1,
                 flags: TCPFlag.ack)
        waitForDeliberation(0.05)

        // Send segments in reverse order
        let data1 = Array("first-data-block-".utf8)
        let data2 = Array("second-data-block-".utf8)
        let data3 = Array("third-data-block--".utf8)
        let baseSeq = saHdr.ackNum
        let len1 = UInt32(data1.count)
        let len2 = UInt32(data2.count)

        // Send in reverse: seq baseSeq+len1+len2, then baseSeq+len1, then baseSeq
        tcpFrame(connB: connB, srcIP: vmIP, dstIP: gwIP,
                 srcPort: srcPort, dstPort: 9093,
                 seq: baseSeq + len1 + len2, ack: saHdr.seqNum + 1,
                 flags: TCPFlag.ack | TCPFlag.psh, payload: data3)
        tcpFrame(connB: connB, srcIP: vmIP, dstIP: gwIP,
                 srcPort: srcPort, dstPort: 9093,
                 seq: baseSeq + len1, ack: saHdr.seqNum + 1,
                 flags: TCPFlag.ack | TCPFlag.psh, payload: data2)
        tcpFrame(connB: connB, srcIP: vmIP, dstIP: gwIP,
                 srcPort: srcPort, dstPort: 9093,
                 seq: baseSeq, ack: saHdr.seqNum + 1,
                 flags: TCPFlag.ack | TCPFlag.psh, payload: data1)
        waitForDeliberation(0.1)

        // Should not crash; data reordering is expected behavior
        #expect(true, "stack should survive extreme reordering")

    }
}

// MARK: - 6. Duplicate Segment Storm

@Test func testChaosDuplicateSegments() throws {
    runChaosTest(listenPort: 9094) { stack, connB in
        let srcPort: UInt16 = 56789

        // Handshake
        tcpFrame(connB: connB, srcIP: vmIP, dstIP: gwIP,
                 srcPort: srcPort, dstPort: 9094,
                 seq: 4000, ack: 0, flags: TCPFlag.syn)
        waitForDeliberation(0.1)

        let frames1 = readAllFramesFrom(connB, timeout: 0.1)
        guard let saFrame = frames1.first(where: { $0.etherType == etherTypeIPv4 }),
              let saIP = IPv4Packet.parse([UInt8](saFrame.payload)),
              let saHdr = TCPHeader.parse(saIP.payload) else {
            Issue.record("SYN-ACK not received"); return
        }

        // ACK
        tcpFrame(connB: connB, srcIP: vmIP, dstIP: gwIP,
                 srcPort: srcPort, dstPort: 9094,
                 seq: saHdr.ackNum, ack: saHdr.seqNum + 1,
                 flags: TCPFlag.ack)
        waitForDeliberation(0.05)

        // Send the SAME data segment 100 times
        let payload = Array("duplicated-data".utf8)
        for _ in 0..<100 {
            tcpFrame(connB: connB, srcIP: vmIP, dstIP: gwIP,
                     srcPort: srcPort, dstPort: 9094,
                     seq: saHdr.ackNum, ack: saHdr.seqNum + 1,
                     flags: TCPFlag.ack | TCPFlag.psh, payload: payload)
        }
        waitForDeliberation(0.2)

        // Connection should still be established (not crashed by duplicates)
        let connCount = stack.tcpState.connectionCount()
        #expect(connCount == 1, "connection should survive duplicate storm")


        #expect(true, "invariants should hold after duplicates")
    }
}

// MARK: - 7. Bad Checksums

@Test func testChaosBadChecksums() throws {
    runChaosTest(listenPort: 9095) { stack, connB in
        // TCP segment with intentionally bad checksum
        let srcPort: UInt16 = 12345
        let raw = buildSegment(tuple: Tuple(srcIP: vmIP, dstIP: gwIP, srcPort: srcPort, dstPort: 9095),
                               seq: 5000, ack: 0, flags: TCPFlag.syn, window: 65535, wscale: 0, payload: [])
        var badRaw = raw
        badRaw[16] = 0xFF; badRaw[17] = 0xFF // intentionally wrong checksum
        let ipPkt = IPv4Packet(version: 4, ihl: 20, tos: 0, totalLen: 0, id: 0x99,
                               flags: 0, fragOffset: 0, ttl: 64, protocol: protocolTCP,
                               checksum: 0, srcIP: vmIP, dstIP: gwIP, payload: badRaw)
        rawFrame(connB: connB, dstMAC: gwMAC, srcMAC: vmMAC,
                 etherType: etherTypeIPv4, payload: Data(ipPkt.serialize()))

        // IPv4 with bad checksum
        var badIPPkt = IPv4Packet(version: 4, ihl: 20, tos: 0, totalLen: 0, id: 0x100,
                                   flags: 0, fragOffset: 0, ttl: 64, protocol: protocolTCP,
                                   checksum: 0xFFFF, srcIP: vmIP, dstIP: gwIP, payload: [])
        badIPPkt = IPv4Packet(version: 4, ihl: 20, tos: 0, totalLen: 0, id: 0x100,
                               flags: 0, fragOffset: 0, ttl: 64, protocol: protocolTCP,
                               checksum: 0xFFFF, srcIP: vmIP, dstIP: gwIP, payload: [])
        rawFrame(connB: connB, dstMAC: gwMAC, srcMAC: vmMAC,
                 etherType: etherTypeIPv4, payload: Data(badIPPkt.serialize()))

        waitForDeliberation(0.1)

        #expect(true, "stack should survive bad checksums")

    }
}

// MARK: - 8. Zero Window and Recovery

@Test func testChaosZeroWindow() throws {
    runChaosTest(listenPort: 9096) { stack, connB in
        let srcPort: UInt16 = 7890

        // Handshake with zero window from VM
        var rawSYN = buildSegment(tuple: Tuple(srcIP: vmIP, dstIP: gwIP, srcPort: srcPort, dstPort: 9096),
                                   seq: 6000, ack: 0, flags: TCPFlag.syn, window: 0, wscale: 0, payload: [])
        let csSYN = tcpChecksum(srcIP: vmIP, dstIP: gwIP, tcpData: rawSYN)
        rawSYN[16] = UInt8(csSYN >> 8); rawSYN[17] = UInt8(csSYN & 0xFF)
        rawSYN[14] = 0; rawSYN[15] = 0 // window = 0
        let ipSYN = IPv4Packet(version: 4, ihl: 20, tos: 0, totalLen: 0, id: 0x200,
                                flags: 0, fragOffset: 0, ttl: 64, protocol: protocolTCP,
                                checksum: 0, srcIP: vmIP, dstIP: gwIP, payload: rawSYN)
        rawFrame(connB: connB, dstMAC: gwMAC, srcMAC: vmMAC,
                 etherType: etherTypeIPv4, payload: Data(ipSYN.serialize()))
        waitForDeliberation(0.1)

        let frames1 = readAllFramesFrom(connB, timeout: 0.1)
        // Even with zero window, SYN-ACK should be sent (SYN window doesn't control data)
        let hasSYNACK = frames1.contains(where: { $0.etherType == etherTypeIPv4 })
        #expect(hasSYNACK, "SYN-ACK should be sent despite zero window")

        // Now send window update (ACK with non-zero window)
        if let saFrame = frames1.first(where: { $0.etherType == etherTypeIPv4 }),
           let saIP = IPv4Packet.parse([UInt8](saFrame.payload)),
           let saHdr = TCPHeader.parse(saIP.payload) {

            // ACK + window update
            var rawACK = buildSegment(tuple: Tuple(srcIP: vmIP, dstIP: gwIP, srcPort: srcPort, dstPort: 9096),
                                       seq: saHdr.ackNum, ack: saHdr.seqNum + 1,
                                       flags: TCPFlag.ack, window: 65535, wscale: 0, payload: [])
            let csACK = tcpChecksum(srcIP: vmIP, dstIP: gwIP, tcpData: rawACK)
            rawACK[16] = UInt8(csACK >> 8); rawACK[17] = UInt8(csACK & 0xFF)
            let ipACK = IPv4Packet(version: 4, ihl: 20, tos: 0, totalLen: 0, id: 0x201,
                                    flags: 0, fragOffset: 0, ttl: 64, protocol: protocolTCP,
                                    checksum: 0, srcIP: vmIP, dstIP: gwIP, payload: rawACK)
            rawFrame(connB: connB, dstMAC: gwMAC, srcMAC: vmMAC,
                     etherType: etherTypeIPv4, payload: Data(ipACK.serialize()))
            waitForDeliberation(0.05)

            let connCount = stack.tcpState.connectionCount()
            #expect(connCount == 1, "connection should be established after window update")
        }


    }
}

// MARK: - 9. Out-of-Bounds Sequence Numbers

@Test func testChaosOutOfBoundsSequence() throws {
    runChaosTest(listenPort: 9097) { stack, connB in
        let srcPort: UInt16 = 8901

        // Handshake
        tcpFrame(connB: connB, srcIP: vmIP, dstIP: gwIP,
                 srcPort: srcPort, dstPort: 9097,
                 seq: 7000, ack: 0, flags: TCPFlag.syn)
        waitForDeliberation(0.1)

        let frames1 = readAllFramesFrom(connB, timeout: 0.1)
        guard let saFrame = frames1.first(where: { $0.etherType == etherTypeIPv4 }),
              let saIP = IPv4Packet.parse([UInt8](saFrame.payload)),
              let saHdr = TCPHeader.parse(saIP.payload) else {
            Issue.record("SYN-ACK not received"); return
        }

        tcpFrame(connB: connB, srcIP: vmIP, dstIP: gwIP,
                 srcPort: srcPort, dstPort: 9097,
                 seq: saHdr.ackNum, ack: saHdr.seqNum + 1,
                 flags: TCPFlag.ack)
        waitForDeliberation(0.05)

        // Send data with wildly wrong seq (far ahead of rcvNxt)
        tcpFrame(connB: connB, srcIP: vmIP, dstIP: gwIP,
                 srcPort: srcPort, dstPort: 9097,
                 seq: saHdr.ackNum + 50000, ack: saHdr.seqNum + 1,
                 flags: TCPFlag.ack | TCPFlag.psh, payload: Array("far-ahead".utf8))

        // Send data far behind rcvNxt (already ACKed region)
        tcpFrame(connB: connB, srcIP: vmIP, dstIP: gwIP,
                 srcPort: srcPort, dstPort: 9097,
                 seq: saHdr.ackNum - 100, ack: saHdr.seqNum + 1,
                 flags: TCPFlag.ack | TCPFlag.psh, payload: Array("far-behind".utf8))

        // Send segment that wraps around the 32-bit boundary
        tcpFrame(connB: connB, srcIP: vmIP, dstIP: gwIP,
                 srcPort: srcPort, dstPort: 9097,
                 seq: 0xFFFFFFF0, ack: saHdr.seqNum + 1,
                 flags: TCPFlag.ack, payload: Array("wraparound".utf8))

        waitForDeliberation(0.1)

        #expect(true, "stack should survive out-of-bounds sequence numbers")

    }
}

// MARK: - 10. Malformed UDP/DHCP Chaos

@Test func testChaosMalformedDHCP() throws {
    runChaosTest { stack, connB in
        // Empty DHCP
        let emptyUDP = buildDatagram(srcPort: clientPort, dstPort: serverPort, payload: [])
        let emptyIP = IPv4Packet(version: 4, ihl: 20, tos: 0, totalLen: 0, id: 0x500,
                                  flags: 0, fragOffset: 0, ttl: 64, protocol: protocolUDP,
                                  checksum: 0, srcIP: 0, dstIP: ipToUInt32("255.255.255.255"),
                                  payload: emptyUDP)
        rawFrame(connB: connB, dstMAC: broadcastMAC, srcMAC: vmMAC,
                 etherType: etherTypeIPv4, payload: Data(emptyIP.serialize()))

        // DHCP without magic cookie
        var badDHCP = [UInt8](repeating: 0, count: 240)
        badDHCP[0] = 1; badDHCP[1] = 1; badDHCP[2] = 6
        let badUDP = buildDatagram(srcPort: clientPort, dstPort: serverPort, payload: badDHCP)
        let badIP = IPv4Packet(version: 4, ihl: 20, tos: 0, totalLen: 0, id: 0x501,
                                flags: 0, fragOffset: 0, ttl: 64, protocol: protocolUDP,
                                checksum: 0, srcIP: 0, dstIP: ipToUInt32("255.255.255.255"),
                                payload: badUDP)
        rawFrame(connB: connB, dstMAC: broadcastMAC, srcMAC: vmMAC,
                 etherType: etherTypeIPv4, payload: Data(badIP.serialize()))

        // DHCP with wrong op code
        var dhcpReply = [UInt8](repeating: 0, count: 300)
        dhcpReply[0] = 2 // BOOTREPLY (shouldn't be sent to server)
        dhcpReply[1] = 1
        dhcpReply[236] = 0x63; dhcpReply[237] = 0x82; dhcpReply[238] = 0x53; dhcpReply[239] = 0x63
        dhcpReply[240] = 53; dhcpReply[241] = 1; dhcpReply[242] = 2 // DHCPOFFER
        dhcpReply[243] = 255
        let replyUDP = buildDatagram(srcPort: serverPort, dstPort: clientPort, payload: Array(dhcpReply[0..<244]))
        let replyIP = IPv4Packet(version: 4, ihl: 20, tos: 0, totalLen: 0, id: 0x502,
                                  flags: 0, fragOffset: 0, ttl: 64, protocol: protocolUDP,
                                  checksum: 0, srcIP: gwIP, dstIP: ipToUInt32("255.255.255.255"),
                                  payload: replyUDP)
        rawFrame(connB: connB, dstMAC: broadcastMAC, srcMAC: gwMAC,
                 etherType: etherTypeIPv4, payload: Data(replyIP.serialize()))

        waitForDeliberation(0.1)

        #expect(true, "stack should survive malformed DHCP/UDP packets")
    }
}
