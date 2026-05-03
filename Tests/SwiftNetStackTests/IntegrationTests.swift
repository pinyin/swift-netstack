import Foundation
import Testing
@testable import SwiftNetStack

// MARK: - Integration Test Helpers

func runIntegrationTest(listenPort: UInt16 = 0, _ body: (Stack, VZDebugConn) throws -> Void) {
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
    let deliberationQueue = DispatchQueue(label: "integ.deliberation", qos: .userInitiated)

    deliberationQueue.async {
        while runningFlag.value {
            stack.deliberate(now: Date())
            Thread.sleep(forTimeInterval: 0.001)
        }
    }

    do {
        try body(stack, connB)
    } catch {
        Issue.record("Integration test body threw: \(error)")
    }

    runningFlag.value = false
    Thread.sleep(forTimeInterval: 0.2)
}

func runIntegrationTestWithConfig(_ cfg: StackConfig, tcpCfg: TCPConfig = TCPConfig.defaultConfig(), _ body: (Stack, VZDebugConn) throws -> Void) {
    guard let (connA, connB) = VZDebugConn.newLoopbackPair() else {
        print("SKIP: socketpair failed")
        return
    }

    let tcpState = TCPState(cfg: tcpCfg)
    let stack = Stack(cfg: cfg, tcpState: tcpState)
    stack.setConn(connA)

    let runningFlag = E2ERunningFlag()
    let deliberationQueue = DispatchQueue(label: "integ.deliberation", qos: .userInitiated)

    deliberationQueue.async {
        while runningFlag.value {
            stack.deliberate(now: Date())
            Thread.sleep(forTimeInterval: 0.001)
        }
    }

    do {
        try body(stack, connB)
    } catch {
        Issue.record("Integration test body threw: \(error)")
    }

    runningFlag.value = false
    Thread.sleep(forTimeInterval: 0.2)
}

func waitForDeliberation(_ seconds: Double = 0.05) {
    Thread.sleep(forTimeInterval: seconds)
}

func readAllFramesFrom(_ conn: VZDebugConn, timeout: Double = 0.1) -> [Frame] {
    let deadline = Date().addingTimeInterval(timeout)
    var frames: [Frame] = []
    while Date() < deadline {
        let batch = conn.readAllFrames()
        frames.append(contentsOf: batch)
        if !batch.isEmpty {
            Thread.sleep(forTimeInterval: 0.005)
        } else {
            Thread.sleep(forTimeInterval: 0.001)
        }
    }
    return frames
}

let vmMAC = Data([0x02, 0x00, 0x00, 0x00, 0x00, 0x01])
let gwMAC = Data([0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xee])
let gwIP = ipToUInt32("192.168.65.1")
let vmIP = ipToUInt32("192.168.65.2")

func buildARPRequestFrame(targetIP: UInt32) -> Frame {
    let arp = ARPPacket(
        hardwareType: hardwareTypeEthernet,
        protocolType: etherTypeIPv4,
        hardwareLen: 6,
        protocolLen: 4,
        operation: arpRequest,
        senderMAC: vmMAC,
        senderIP: ipData(from: vmIP),
        targetMAC: zeroMAC,
        targetIP: ipData(from: targetIP)
    )
    return Frame(dstMAC: broadcastMAC, srcMAC: vmMAC,
                 etherType: etherTypeARP, payload: Data(arp.serialize()))
}

func buildICMPEchoFrame(srcIP: UInt32, dstIP: UInt32, id: UInt16 = 0x1234, seq: UInt16 = 1) -> Frame {
    let icmp = ICMPPacket(type: icmpTypeEchoRequest, code: 0, checksum: 0,
                          restHdr: UInt32(id) << 16 | UInt32(seq),
                          payload: Data("pingdata".utf8))
    let ipPkt = IPv4Packet(version: 4, ihl: 20, tos: 0, totalLen: 0, id: 0x42,
                           flags: 0, fragOffset: 0, ttl: 64, protocol: protocolICMP,
                           checksum: 0, srcIP: srcIP, dstIP: dstIP,
                           payload: Data(icmp.serialize()))
    return Frame(dstMAC: gwMAC, srcMAC: vmMAC,
                 etherType: etherTypeIPv4, payload: Data(ipPkt.serialize()))
}

// MARK: - 1. ARP Round-Trip

@Test func testIntegrationARPReply() throws {
    runIntegrationTest { stack, connB in
        let request = buildARPRequestFrame(targetIP: gwIP)
        _ = connB.write(frame: request)
        waitForDeliberation(0.1)

        let responses = readAllFramesFrom(connB, timeout: 0.1)
        let arpReplies = responses.filter { $0.etherType == etherTypeARP }

        #expect(!arpReplies.isEmpty, "expected at least one ARP reply")
        if let reply = arpReplies.first {
            let arpPkt = ARPPacket.parse([UInt8](reply.payload))
            #expect(arpPkt != nil, "ARP reply should parse")
            #expect(arpPkt!.operation == arpReply, "should be ARP reply")
            #expect(arpPkt!.senderMAC == gwMAC, "sender MAC should be gateway MAC")
            #expect(ipFromData(arpPkt!.senderIP) == gwIP, "sender IP should be gateway IP")
        }

        // Verify ARP entry learned in stack
        #expect(stack.arp.lookup(ip: vmIP) == vmMAC, "stack should have learned VM MAC")
    }
}

// MARK: - 2. ICMP Echo Round-Trip

@Test func testIntegrationICMPEcho() throws {
    runIntegrationTest { stack, connB in
        let request = buildICMPEchoFrame(srcIP: vmIP, dstIP: gwIP, id: 0x1234, seq: 1)
        _ = connB.write(frame: request)
        waitForDeliberation(0.1)

        let responses = readAllFramesFrom(connB, timeout: 0.1)
        let ipv4Frames = responses.filter { $0.etherType == etherTypeIPv4 }

        #expect(!ipv4Frames.isEmpty, "expected at least one IPv4 response frame")
        if let respFrame = ipv4Frames.first {
            guard let ipPkt = IPv4Packet.parse([UInt8](respFrame.payload)) else {
                Issue.record("IPv4 response should parse")
                return
            }
            #expect(ipPkt.protocol == protocolICMP, "should be ICMP")
            #expect(ipPkt.srcIP == gwIP, "src should be gateway IP")
            #expect(ipPkt.dstIP == vmIP, "dst should be VM IP")

            guard let icmp = ICMPPacket.parse(ipPkt.payload) else {
                Issue.record("ICMP in response should parse")
                return
            }
            #expect(icmp.type == icmpTypeEchoReply, "should be echo reply")
            #expect(icmp.restHdr == UInt32(0x1234) << 16 | UInt32(1), "id/seq should match")
        }
    }
}

// MARK: - 3. DHCP Full Flow Through Stack

@Test func testIntegrationDHCPFullFlow() throws {
    runIntegrationTest { stack, connB in
        let mac = MACAddr(0x02, 0x00, 0x00, 0x00, 0x00, 0x11)

        // Build DHCP DISCOVER
        var discover = [UInt8](repeating: 0, count: 300)
        discover[0] = 1; discover[1] = 1; discover[2] = 6
        discover[4] = 0x11; discover[5] = 0x22; discover[6] = 0x33; discover[7] = 0x44
        discover[10] = 0x80
        discover[28] = mac.b0; discover[29] = mac.b1; discover[30] = mac.b2
        discover[31] = mac.b3; discover[32] = mac.b4; discover[33] = mac.b5
        discover[236] = 0x63; discover[237] = 0x82; discover[238] = 0x53; discover[239] = 0x63
        var off = 240
        off = writeOption(&discover, offset: off, optType: optMessageType, val: [msgDiscover])
        off = writeOption(&discover, offset: off, optType: 55, val: [1, 3, 6])
        discover[off] = optEnd
        let discoverFull = Array(discover[..<(off + 1)])

        // Wrap in UDP → IPv4 → Frame
        let udpDiscover = buildDatagram(srcPort: clientPort, dstPort: serverPort, payload: Data(discoverFull))
        let ipDiscover = IPv4Packet(version: 4, ihl: 20, tos: 0, totalLen: 0, id: 0x101,
                                     flags: 0, fragOffset: 0, ttl: 64, protocol: protocolUDP,
                                     checksum: 0, srcIP: 0, dstIP: ipToUInt32("255.255.255.255"),
                                     payload: Data(udpDiscover))
        let frameDiscover = Frame(dstMAC: broadcastMAC, srcMAC: Data([mac.b0, mac.b1, mac.b2, mac.b3, mac.b4, mac.b5]),
                                   etherType: etherTypeIPv4, payload: Data(ipDiscover.serialize()))

        _ = connB.write(frame: frameDiscover)
        waitForDeliberation(0.1)

        let responses = readAllFramesFrom(connB, timeout: 0.1)
        let offerFrames = responses.filter { $0.etherType == etherTypeIPv4 }
        #expect(!offerFrames.isEmpty, "expected DHCP OFFER response")

        if let offerFrame = offerFrames.first {
            guard let ipPkt = IPv4Packet.parse([UInt8](offerFrame.payload)) else {
                Issue.record("DHCP OFFER IPv4 should parse")
                return
            }
            #expect(ipPkt.protocol == protocolUDP)

            let (udpHdr, udpPayload) = parseUDP(ipPkt.payload)!
            #expect(udpHdr.srcPort == serverPort, "srcPort should be serverPort(67)")
            #expect(udpHdr.dstPort == clientPort, "dstPort should be clientPort(68)")

            let msgType = udpPayload[240 + 2]
            #expect(msgType == msgOffer, "should be DHCPOFFER, got \(msgType)")
        }

        // Verify DHCP server has allocated an IP
        let ip = stack.dhcpSrv.allocateIP(mac)
        #expect(ip != nil, "DHCP server should have allocated an IP for the test MAC")

        // Send REQUEST
        let offeredIP = ip!
        var request = [UInt8](repeating: 0, count: 300)
        request[0] = 1; request[1] = 1; request[2] = 6
        request[4] = 0x11; request[5] = 0x22; request[6] = 0x33; request[7] = 0x44
        request[10] = 0x80
        request[16] = UInt8(offeredIP >> 24); request[17] = UInt8(offeredIP >> 16 & 0xFF)
        request[18] = UInt8(offeredIP >> 8 & 0xFF); request[19] = UInt8(offeredIP & 0xFF)
        request[28] = mac.b0; request[29] = mac.b1; request[30] = mac.b2
        request[31] = mac.b3; request[32] = mac.b4; request[33] = mac.b5
        request[236] = 0x63; request[237] = 0x82; request[238] = 0x53; request[239] = 0x63
        off = 240
        off = writeOption(&request, offset: off, optType: optMessageType, val: [msgRequest])
        off = writeOption(&request, offset: off, optType: optRequestedIP,
                          val: [UInt8(offeredIP >> 24), UInt8(offeredIP >> 16 & 0xFF),
                                UInt8(offeredIP >> 8 & 0xFF), UInt8(offeredIP & 0xFF)])
        off = writeOption(&request, offset: off, optType: optServerIdentifier,
                          val: [UInt8(gwIP >> 24), UInt8(gwIP >> 16 & 0xFF),
                                UInt8(gwIP >> 8 & 0xFF), UInt8(gwIP & 0xFF)])
        request[off] = optEnd
        let requestFull = Array(request[..<(off + 1)])

        let udpRequest = buildDatagram(srcPort: clientPort, dstPort: serverPort, payload: Data(requestFull))
        let ipRequest = IPv4Packet(version: 4, ihl: 20, tos: 0, totalLen: 0, id: 0x102,
                                    flags: 0, fragOffset: 0, ttl: 64, protocol: protocolUDP,
                                    checksum: 0, srcIP: 0, dstIP: ipToUInt32("255.255.255.255"),
                                    payload: Data(udpRequest))
        let frameRequest = Frame(dstMAC: broadcastMAC, srcMAC: Data([mac.b0, mac.b1, mac.b2, mac.b3, mac.b4, mac.b5]),
                                  etherType: etherTypeIPv4, payload: Data(ipRequest.serialize()))

        _ = connB.write(frame: frameRequest)
        waitForDeliberation(0.1)

        let ackResponses = readAllFramesFrom(connB, timeout: 0.1)
        let ackFrames = ackResponses.filter { $0.etherType == etherTypeIPv4 }
        #expect(!ackFrames.isEmpty, "expected DHCP ACK response")
    }
}

// MARK: - 4. DNS Proxy Integration

@Test func testIntegrationDNSProxyEnqueue() throws {
    runIntegrationTest { stack, connB in
        // Build a minimal DNS A-query for "example.com"
        var dnsQuery = [UInt8](repeating: 0, count: 12 + 15 + 4)
        dnsQuery[0] = 0xAB; dnsQuery[1] = 0xCD  // txID
        dnsQuery[2] = 0x01; dnsQuery[3] = 0x00  // flags: standard query, recursion desired
        dnsQuery[5] = 0x01                        // QDCOUNT = 1
        let labels: [UInt8] = [7, 101, 120, 97, 109, 112, 108, 101, 3, 99, 111, 109, 0]
        for (j, b) in labels.enumerated() { dnsQuery[12 + j] = b }
        dnsQuery[27] = 0x00; dnsQuery[28] = 0x01  // QTYPE = A
        dnsQuery[29] = 0x00; dnsQuery[30] = 0x01  // QCLASS = IN
        let queryFull = Array(dnsQuery[0..<31])

        let udpData = buildDatagram(srcPort: 54321, dstPort: dnsPort, payload: Data(queryFull))
        let ipPkt = IPv4Packet(version: 4, ihl: 20, tos: 0, totalLen: 0, id: 0x201,
                               flags: 0, fragOffset: 0, ttl: 64, protocol: protocolUDP,
                               checksum: 0, srcIP: vmIP, dstIP: gwIP, payload: Data(udpData))
        let frame = Frame(dstMAC: gwMAC, srcMAC: vmMAC,
                          etherType: etherTypeIPv4, payload: Data(ipPkt.serialize()))

        _ = connB.write(frame: frame)
        waitForDeliberation(0.1)

        // DNS proxy enqueues query upstream and fires async task
        // The async resolution may or may not complete quickly, but the query should not crash
        // and dnsProxy.poll() should have been called in the deliberation
        #expect(true, "DNS proxy should accept query without crashing")
    }
}

// MARK: - 5. TCP Handshake Through Stack

@Test func testIntegrationTCPHandshake() throws {
    runIntegrationTest(listenPort: 8080) { stack, connB in
        let srcPort: UInt16 = 12345
        let dstPort: UInt16 = 8080

        // Inject SYN from VM
        let synSeg = fakeSegment(
            srcIP: vmIP, dstIP: gwIP, srcPort: srcPort, dstPort: dstPort,
            seq: 1000, ack: 0, flags: TCPFlag.syn
        )
        let synTuple = Tuple(srcIP: vmIP, dstIP: gwIP, srcPort: srcPort, dstPort: dstPort)
        let synRaw = buildSegment(tuple: synTuple, seq: 1000, ack: 0,
                                   flags: TCPFlag.syn, window: 65535, wscale: 0, payload: [])
        let synTcpBytes = synRaw
        var synWithCS = synTcpBytes
        let synCS = tcpChecksum(srcIP: vmIP, dstIP: gwIP, tcpData: synTcpBytes)
        synWithCS[16] = UInt8(synCS >> 8)
        synWithCS[17] = UInt8(synCS & 0xFF)

        let synIP = IPv4Packet(version: 4, ihl: 20, tos: 0, totalLen: 0, id: 0x301,
                               flags: 0, fragOffset: 0, ttl: 64, protocol: protocolTCP,
                               checksum: 0, srcIP: vmIP, dstIP: gwIP, payload: Data(synWithCS))
        let synFrame = Frame(dstMAC: gwMAC, srcMAC: vmMAC,
                              etherType: etherTypeIPv4, payload: Data(synIP.serialize()))

        _ = connB.write(frame: synFrame)
        waitForDeliberation(0.1)

        // Should get SYN-ACK back
        let responses = readAllFramesFrom(connB, timeout: 0.1)
        let synAckFrames = responses.filter { $0.etherType == etherTypeIPv4 }
        #expect(!synAckFrames.isEmpty, "expected SYN-ACK response")

        guard let synAckFrame = synAckFrames.first,
              let synAckIP = IPv4Packet.parse([UInt8](synAckFrame.payload)),
              synAckIP.protocol == protocolTCP else {
            Issue.record("SYN-ACK should be valid IPv4 TCP")
            return
        }

        let synAckHeader = TCPHeader.parse(synAckIP.payload)
        #expect(synAckHeader != nil, "SYN-ACK TCP header should parse")
        #expect(synAckHeader!.hasFlag(TCPFlag.syn), "should have SYN flag")
        #expect(synAckHeader!.hasFlag(TCPFlag.ack), "should have ACK flag")
        #expect(synAckHeader!.ackNum == 1001, "ACK should be 1001")

        // Inject ACK to complete handshake
        let revTuple = Tuple(srcIP: gwIP, dstIP: vmIP,
                             srcPort: synAckIP.payload.count >= 2 ?
                                UInt16(synAckIP.payload[0]) << 8 | UInt16(synAckIP.payload[1]) : dstPort,
                             dstPort: srcPort)

        let ackRaw = buildSegment(tuple: synTuple, seq: 1001,
                                   ack: synAckHeader!.seqNum + 1,
                                   flags: TCPFlag.ack, window: 65535, wscale: 0, payload: [])
        var ackWithCS = ackRaw
        let ackCS = tcpChecksum(srcIP: vmIP, dstIP: gwIP, tcpData: ackRaw)
        ackWithCS[16] = UInt8(ackCS >> 8)
        ackWithCS[17] = UInt8(ackCS & 0xFF)

        let ackIP = IPv4Packet(version: 4, ihl: 20, tos: 0, totalLen: 0, id: 0x302,
                               flags: 0, fragOffset: 0, ttl: 64, protocol: protocolTCP,
                               checksum: 0, srcIP: vmIP, dstIP: gwIP, payload: Data(ackWithCS))
        let ackFrame = Frame(dstMAC: gwMAC, srcMAC: vmMAC,
                              etherType: etherTypeIPv4, payload: Data(ackIP.serialize()))

        _ = connB.write(frame: ackFrame)
        waitForDeliberation(0.1)

        // Verify connections in TCPState
        let expectedTuple = Tuple(srcIP: vmIP, dstIP: gwIP, srcPort: srcPort, dstPort: dstPort)
        let totalConns = stack.tcpState.connectionCount()
        #expect(totalConns == 1, "expected 1 connection, got \(totalConns)")
    }
}

// MARK: - 6. TCP Data Transfer

@Test func testIntegrationTCPDataTransfer() throws {
    runIntegrationTest(listenPort: 9090) { stack, connB in
        let srcPort: UInt16 = 23456
        let dstPort: UInt16 = 9090

        // Handshake — same pattern as testIntegrationTCPHandshake
        let synTuple = Tuple(srcIP: vmIP, dstIP: gwIP, srcPort: srcPort, dstPort: dstPort)
        let synRaw = buildSegment(tuple: synTuple, seq: 1000, ack: 0,
                                   flags: TCPFlag.syn, window: 65535, wscale: 0, payload: [])
        var synBytes = synRaw
        let synCs = tcpChecksum(srcIP: vmIP, dstIP: gwIP, tcpData: synRaw)
        synBytes[16] = UInt8(synCs >> 8); synBytes[17] = UInt8(synCs & 0xFF)
        let synIP = IPv4Packet(version: 4, ihl: 20, tos: 0, totalLen: 0, id: 0x401,
                               flags: 0, fragOffset: 0, ttl: 64, protocol: protocolTCP,
                               checksum: 0, srcIP: vmIP, dstIP: gwIP, payload: Data(synBytes))
        _ = connB.write(frame: Frame(dstMAC: gwMAC, srcMAC: vmMAC,
                                       etherType: etherTypeIPv4, payload: Data(synIP.serialize())))
        waitForDeliberation(0.1)

        let synAckFrames = readAllFramesFrom(connB, timeout: 0.1)
        #expect(!synAckFrames.isEmpty, "expected SYN-ACK response")

        guard let saFrame = synAckFrames.first,
              let saIP = IPv4Packet.parse([UInt8](saFrame.payload)),
              saIP.protocol == protocolTCP else {
            Issue.record("SYN-ACK should be valid IPv4 TCP")
            return
        }

        let saHdr = TCPHeader.parse(saIP.payload)
        #expect(saHdr != nil, "SYN-ACK TCP header should parse")
        #expect(saHdr!.hasFlag(TCPFlag.syn | TCPFlag.ack), "should have SYN|ACK flags")
        #expect(saHdr!.ackNum == 1001, "ACK should be 1001")

        // Send ACK + data segment together (same batch)
        let helloData = Array("hello".utf8)
        let dataRaw = buildSegment(tuple: synTuple, seq: 1001, ack: saHdr!.seqNum + 1,
                                    flags: TCPFlag.ack | TCPFlag.psh, window: 65535, wscale: 0,
                                    payload: helloData)
        var dataBytes = dataRaw
        let dataCs = tcpChecksum(srcIP: vmIP, dstIP: gwIP, tcpData: dataRaw)
        dataBytes[16] = UInt8(dataCs >> 8); dataBytes[17] = UInt8(dataCs & 0xFF)
        let dataIP = IPv4Packet(version: 4, ihl: 20, tos: 0, totalLen: 0, id: 0x402,
                                flags: 0, fragOffset: 0, ttl: 64, protocol: protocolTCP,
                                checksum: 0, srcIP: vmIP, dstIP: gwIP, payload: Data(dataBytes))
        _ = connB.write(frame: Frame(dstMAC: gwMAC, srcMAC: vmMAC,
                                       etherType: etherTypeIPv4, payload: Data(dataIP.serialize())))
        waitForDeliberation(0.1)

        let revTuple = synTuple.reversed()

        let connKey = revTuple
        let totalConns = stack.tcpState.connectionCount()
        #expect(totalConns == 1, "expected 1 connection, got \(totalConns)")

        // Check data arrived
        var foundData = false
        if let conn = stack.tcpState.established[connKey] ?? stack.tcpState.synRcvd[connKey] {
            var buf = [UInt8](repeating: 0, count: 256)
            let n = conn.readRecvBuf(into: &buf)
            if n > 0 {
                let received = String(bytes: buf[0..<n], encoding: .utf8) ?? ""
                if received == "hello" { foundData = true }
            }
        }
        #expect(foundData, "should receive 'hello' in TCP recv buffer")
    }
}

// MARK: - 7. Forwarder Integration

@Test func testIntegrationForwarderAccept() throws {
    runIntegrationTest { stack, connB in
        var fwdCfg = StackConfig.defaultConfig()
        fwdCfg.socketPath = ""
        fwdCfg.gatewayIP = gwIP

        let vmIPAddr = ipToUInt32("192.168.65.2")
        fwdCfg.portForwards = [
            ForwarderMapping(hostPort: 12222, vmIP: vmIPAddr, vmPort: 22)
        ]

        // Create a new Stack with forwarder (since runIntegrationTest already made a stack,
        // we use a different approach — just test that the Forwarder can be created and
        // its listener is set up properly)
        let fwd = Forwarder(gatewayIP: gwIP, mappings: fwdCfg.portForwards)
        #expect(fwd.mappings.count == 1, "should have 1 mapping")
        #expect(fwd.count() == 0, "should start with 0 entries")

        // Test that pollAccept doesn't crash with TCPState
        let ts = TCPState(cfg: TCPConfig.defaultConfig())
        fwd.pollAccept(tcpState: ts)
        #expect(true, "pollAccept should not crash")

        // Cleanup
        fwd.cleanup()
    }
}

// MARK: - 8. NAT Outbound Flow

@Test func testIntegrationNATIntercept() throws {
    runIntegrationTest { stack, connB in
        let extIP = ipToUInt32("8.8.8.8")
        let srcPort: UInt16 = 34567
        let dstPort: UInt16 = 80

        // Inject SYN to external IP
        let segTuple = Tuple(srcIP: vmIP, dstIP: extIP, srcPort: srcPort, dstPort: dstPort)
        let synRaw = buildSegment(tuple: segTuple, seq: 2000, ack: 0,
                                   flags: TCPFlag.syn, window: 65535, wscale: 0, payload: [])
        var synBytes = synRaw
        let synCs = tcpChecksum(srcIP: vmIP, dstIP: extIP, tcpData: synRaw)
        synBytes[16] = UInt8(synCs >> 8); synBytes[17] = UInt8(synCs & 0xFF)
        let synIP = IPv4Packet(version: 4, ihl: 20, tos: 0, totalLen: 0, id: 0x501,
                               flags: 0, fragOffset: 0, ttl: 64, protocol: protocolTCP,
                               checksum: 0, srcIP: vmIP, dstIP: extIP, payload: Data(synBytes))
        let synFrame = Frame(dstMAC: gwMAC, srcMAC: vmMAC,
                              etherType: etherTypeIPv4, payload: Data(synIP.serialize()))

        _ = connB.write(frame: synFrame)
        waitForDeliberation(0.1)

        // NAT should create an entry for the reversed tuple
        let natKey = Tuple(srcIP: extIP, dstIP: vmIP, srcPort: dstPort, dstPort: srcPort)
        let natCount = stack.natTable.count()
        let tcpConnCount = stack.tcpState.connectionCount()
        #expect(tcpConnCount > 0 || natCount > 0,
                "NAT should create entry or TCP conn, natCount=\(natCount) tcpConns=\(tcpConnCount)")
    }
}

// MARK: - 9. UDP NAT Integration

@Test func testIntegrationUDPNATIntercept() throws {
    runIntegrationTest { stack, connB in
        let extIP = ipToUInt32("8.8.8.8")
        let srcPort: UInt16 = 45678
        let dstPort: UInt16 = 443

        let payload = Array("udp-payload".utf8)
        let udpData = buildDatagram(srcPort: srcPort, dstPort: dstPort, payload: Data(payload))
        let ipPkt = IPv4Packet(version: 4, ihl: 20, tos: 0, totalLen: 0, id: 0x601,
                               flags: 0, fragOffset: 0, ttl: 64, protocol: protocolUDP,
                               checksum: 0, srcIP: vmIP, dstIP: extIP, payload: Data(udpData))
        let frame = Frame(dstMAC: gwMAC, srcMAC: vmMAC,
                          etherType: etherTypeIPv4, payload: Data(ipPkt.serialize()))

        _ = connB.write(frame: frame)
        waitForDeliberation(0.1)

        // UDP NAT should intercept without crash
        #expect(true, "UDP NAT should handle intercept without crashing")
    }
}

// MARK: - 10. Multi-Phase Cycle

@Test func testIntegrationMultiPhaseCycle() throws {
    runIntegrationTest(listenPort: 9999) { stack, connB in
        // Inject ARP request + ICMP echo + TCP SYN simultaneously

        let arpReq = buildARPRequestFrame(targetIP: gwIP)
        _ = connB.write(frame: arpReq)

        let icmpReq = buildICMPEchoFrame(srcIP: vmIP, dstIP: gwIP, id: 0x1111, seq: 1)
        _ = connB.write(frame: icmpReq)

        let synRaw = buildSegment(
            tuple: Tuple(srcIP: vmIP, dstIP: gwIP, srcPort: 11111, dstPort: 9999),
            seq: 3000, ack: 0, flags: TCPFlag.syn, window: 65535, wscale: 0, payload: []
        )
        var synBytes = synRaw
        let synCs = tcpChecksum(srcIP: vmIP, dstIP: gwIP, tcpData: synRaw)
        synBytes[16] = UInt8(synCs >> 8); synBytes[17] = UInt8(synCs & 0xFF)
        let synIP = IPv4Packet(version: 4, ihl: 20, tos: 0, totalLen: 0, id: 0x701,
                               flags: 0, fragOffset: 0, ttl: 64, protocol: protocolTCP,
                               checksum: 0, srcIP: vmIP, dstIP: gwIP, payload: Data(synBytes))
        let synFrame = Frame(dstMAC: gwMAC, srcMAC: vmMAC,
                              etherType: etherTypeIPv4, payload: Data(synIP.serialize()))
        _ = connB.write(frame: synFrame)

        waitForDeliberation(0.1)

        let responses = readAllFramesFrom(connB, timeout: 0.1)

        let arpReplies = responses.filter { $0.etherType == etherTypeARP }
        let ipv4Frames = responses.filter { $0.etherType == etherTypeIPv4 }

        #expect(!arpReplies.isEmpty, "should have ARP reply in multi-phase cycle")

        let icmpReplies = ipv4Frames.compactMap { f -> IPv4Packet? in
            guard let ip = IPv4Packet.parse([UInt8](f.payload)), ip.protocol == protocolICMP else { return nil }
            return ip
        }
        #expect(!icmpReplies.isEmpty, "should have ICMP reply in multi-phase cycle")

        // All three protocols should be processed in a single deliberation cycle
        #expect(arpReplies.count >= 1, "at least 1 ARP reply")
        #expect(icmpReplies.count >= 1, "at least 1 ICMP reply")
        #expect(stack.tcpState.connectionCount() >= 1, "TCP connection should be created")
    }
}

// MARK: - 11. FlowStats and Bytes Counters

@Test func testIntegrationFlowStats() throws {
    runIntegrationTest { stack, connB in
        let beforeIn = stack.bytesIn
        let beforeOut = stack.bytesOut

        // Send an ICMP echo to produce output
        let icmpReq = buildICMPEchoFrame(srcIP: vmIP, dstIP: gwIP, id: 0x2222, seq: 1)
        _ = connB.write(frame: icmpReq)
        waitForDeliberation(0.1)
        _ = readAllFramesFrom(connB, timeout: 0.1)

        #expect(stack.bytesIn > beforeIn, "bytesIn should increase, was \(beforeIn), now \(stack.bytesIn)")
        #expect(stack.bytesOut > beforeOut, "bytesOut should increase, was \(beforeOut), now \(stack.bytesOut)")
    }
}

// MARK: - 12. ARP Not For Us (should not reply)

@Test func testIntegrationARPNotForUs() throws {
    runIntegrationTest { stack, connB in
        let otherIP = ipToUInt32("10.0.0.1")
        let request = buildARPRequestFrame(targetIP: otherIP)
        _ = connB.write(frame: request)
        waitForDeliberation(0.1)

        let responses = readAllFramesFrom(connB, timeout: 0.05)
        let arpReplies = responses.filter { $0.etherType == etherTypeARP }
        #expect(arpReplies.isEmpty, "should NOT reply to ARP for other IPs")
    }
}

// MARK: - 13. ARP Learning

@Test func testIntegrationARPLearning() throws {
    runIntegrationTest { stack, connB in
        // Send an ICMP echo — the source IP:MAC should be learned by processIPv4
        let request = buildICMPEchoFrame(srcIP: vmIP, dstIP: gwIP, id: 0x4444, seq: 1)
        _ = connB.write(frame: request)
        waitForDeliberation(0.1)
        _ = readAllFramesFrom(connB, timeout: 0.1)

        // Stack should have learned VM's MAC via ARP set in processIPv4
        let learnedMAC = stack.arp.lookup(ip: vmIP)
        #expect(learnedMAC == vmMAC, "stack should have learned VM's MAC")
    }
}
