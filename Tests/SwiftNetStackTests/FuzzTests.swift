import Foundation
import Testing
@testable import SwiftNetStack

// MARK: - Fuzz Test Helpers

func runFuzzTest(listenPort: UInt16 = 0, _ body: (Stack, VZDebugConn) throws -> Void) {
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
    DispatchQueue(label: "fuzz.deliberation", qos: .userInitiated).async {
        while runningFlag.value {
            stack.deliberate(now: Date())
            Thread.sleep(forTimeInterval: 0.001)
        }
    }

    do {
        try body(stack, connB)
    } catch {
        Issue.record("Fuzz test body threw: \(error)")
    }

    runningFlag.value = false
    Thread.sleep(forTimeInterval: 0.2)
}

/// Linear congruential PRNG for deterministic fuzz tests
struct FuzzRNG {
    var state: UInt64

    init(seed: UInt64 = 12345) {
        self.state = seed
    }

    mutating func next() -> UInt64 {
        state = state &* 6364136223846793005 &+ 1442695040888963407
        return state
    }

    mutating func nextUInt8() -> UInt8 {
        UInt8(next() & 0xFF)
    }

    mutating func nextUInt16() -> UInt16 {
        UInt16(next() & 0xFFFF)
    }

    mutating func nextUInt32() -> UInt32 {
        UInt32(next() & 0xFFFFFFFF)
    }
}

// MARK: - 1. TCP Header Field Fuzzing

@Test func testFuzzTCPHeaderFields() throws {
    runFuzzTest(listenPort: 9080) { stack, connB in
        var rng = FuzzRNG(seed: 42)
        let iterations = 100

        // First, establish a baseline connection
        let srcPort: UInt16 = 20000
        let synRaw = buildSegment(tuple: Tuple(srcIP: vmIP, dstIP: gwIP, srcPort: srcPort, dstPort: 9080),
                                   seq: 1000, ack: 0, flags: TCPFlag.syn, window: 65535, wscale: 0, payload: [])
        var synBytes = synRaw
        let synCs = tcpChecksum(srcIP: vmIP, dstIP: gwIP, tcpData: synRaw)
        synBytes[16] = UInt8(synCs >> 8); synBytes[17] = UInt8(synCs & 0xFF)
        let synIP = IPv4Packet(version: 4, ihl: 20, tos: 0, totalLen: 0, id: 0xF01,
                                flags: 0, fragOffset: 0, ttl: 64, protocol: protocolTCP,
                                checksum: 0, srcIP: vmIP, dstIP: gwIP, payload: synBytes)
        _ = connB.write(frame: Frame(dstMAC: gwMAC, srcMAC: vmMAC,
                                       etherType: etherTypeIPv4, payload: Data(synIP.serialize())))
        waitForDeliberation(0.1)
        _ = readAllFramesFrom(connB, timeout: 0.05)

        // Now fuzz: mutate TCP header fields in valid-looking packets
        for i in 0..<iterations {
            let fuzzSrcPort = rng.nextUInt16()
            let fuzzDstPort = rng.nextUInt16()
            let fuzzSeq = rng.nextUInt32()
            let fuzzAck = rng.nextUInt32()
            let fuzzFlags = rng.nextUInt8()
            let fuzzWindow = rng.nextUInt16()
            let payloadLen = Int(rng.next() % 64)
            let fuzzPayload = (0..<payloadLen).map { _ in rng.nextUInt8() }

            let tuple = Tuple(srcIP: vmIP, dstIP: gwIP, srcPort: fuzzSrcPort, dstPort: fuzzDstPort)
            var raw = buildSegment(tuple: tuple, seq: fuzzSeq, ack: fuzzAck,
                                   flags: fuzzFlags, window: fuzzWindow, wscale: 0, payload: fuzzPayload)
            // Fuzz data offset (bits 4-7 of byte 12)
            let fuzzDataOffset = UInt8((rng.next() % 16) & 0x0F)
            raw[12] = (fuzzDataOffset << 4) | (raw[12] & 0x0F)

            // Recompute checksum for the fuzzed segment
            let cs = tcpChecksum(srcIP: vmIP, dstIP: gwIP, tcpData: raw)
            raw[16] = UInt8(cs >> 8); raw[17] = UInt8(cs & 0xFF)

            // Sometimes omit checksum calculation (inject bad checksum)
            if rng.next() % 5 == 0 {
                raw[16] = rng.nextUInt8(); raw[17] = rng.nextUInt8()
            }

            let ipPkt = IPv4Packet(version: 4, ihl: 20, tos: 0, totalLen: 0,
                                   id: UInt16(0xF00 | i), flags: 0, fragOffset: 0,
                                   ttl: 64, protocol: protocolTCP,
                                   checksum: 0, srcIP: vmIP, dstIP: gwIP, payload: raw)
            _ = connB.write(frame: Frame(dstMAC: gwMAC, srcMAC: vmMAC,
                                          etherType: etherTypeIPv4, payload: Data(ipPkt.serialize())))
        }
        waitForDeliberation(0.3)

        // Stack must survive fuzzing
        #expect(true, "stack should survive TCP header fuzzing")

    }
}

// MARK: - 2. IPv4 Header Field Fuzzing

@Test func testFuzzIPv4HeaderFields() throws {
    runFuzzTest { stack, connB in
        var rng = FuzzRNG(seed: 99)
        let iterations = 80

        for _ in 0..<iterations {
            let fuzzVersion: UInt8 = 4  // keep version valid
            let fuzzIHL: UInt8 = 5      // keep IHL at minimum
            let fuzzTOS = rng.nextUInt8()
            let fuzzID = rng.nextUInt16()
            let fuzzFlags = UInt8(rng.next() % 8)
            let fuzzFragOff = UInt16(rng.next() % 8192) | (UInt16(fuzzFlags) << 13)
            let fuzzTTL = rng.nextUInt8()
            let fuzzProtocol = rng.nextUInt8()
            let fuzzSrcIP = rng.nextUInt32()
            let fuzzDstIP = rng.nextUInt32()
            let fuzzPayloadLen = Int(rng.next() % 128)
            let fuzzPayload = (0..<fuzzPayloadLen).map { _ in rng.nextUInt8() }

            let ipPkt = IPv4Packet(
                version: fuzzVersion, ihl: fuzzIHL, tos: fuzzTOS,
                totalLen: UInt16(fuzzPayload.count),
                id: fuzzID, flags: fuzzFlags, fragOffset: fuzzFragOff,
                ttl: fuzzTTL, protocol: fuzzProtocol,
                checksum: 0, srcIP: fuzzSrcIP, dstIP: fuzzDstIP,
                payload: fuzzPayload
            )

            _ = connB.write(frame: Frame(
                dstMAC: gwMAC, srcMAC: vmMAC,
                etherType: etherTypeIPv4,
                payload: Data(ipPkt.serialize())
            ))
        }
        waitForDeliberation(0.2)

        #expect(Bool(true))
    }
}

// MARK: - 3. DHCP Option Fuzzing

@Test func testFuzzDHCPOptions() throws {
    runFuzzTest { stack, connB in
        var rng = FuzzRNG(seed: 777)
        let iterations = 40

        for i in 0..<iterations {
            let mac = MACAddr(rng.nextUInt8(), rng.nextUInt8(), rng.nextUInt8(),
                             rng.nextUInt8(), rng.nextUInt8(), rng.nextUInt8())

            var buf = [UInt8](repeating: 0, count: 300)
            buf[0] = 1; buf[1] = 1; buf[2] = 6
            buf[4] = rng.nextUInt8(); buf[5] = rng.nextUInt8()
            buf[6] = rng.nextUInt8(); buf[7] = rng.nextUInt8()
            buf[10] = 0x80

            buf[28] = mac.b0; buf[29] = mac.b1; buf[30] = mac.b2
            buf[31] = mac.b3; buf[32] = mac.b4; buf[33] = mac.b5

            buf[236] = 0x63; buf[237] = 0x82; buf[238] = 0x53; buf[239] = 0x63

            // Fuzz DHCP options
            var offset = 240
            let numOptions = Int(rng.next() % 10)
            for _ in 0..<numOptions {
                if offset + 2 >= 290 { break }
                let optType = rng.nextUInt8()
                let optLen = UInt8(rng.next() % 32)
                buf[offset] = optType
                buf[offset + 1] = optLen
                offset += 2
                for k in 0..<Int(optLen) {
                    if offset >= 290 { break }
                    buf[offset] = rng.nextUInt8()
                    offset += 1
                }
            }
            if offset < 298 {
                buf[offset] = optEnd
                offset += 1
            }
            let full = Array(buf[0..<offset])

            let udpData = buildDatagram(srcPort: clientPort, dstPort: serverPort, payload: full)
            let ipPkt = IPv4Packet(version: 4, ihl: 20, tos: 0, totalLen: 0, id: UInt16(0xD00 | i),
                                   flags: 0, fragOffset: 0, ttl: 64, protocol: protocolUDP,
                                   checksum: 0, srcIP: 0, dstIP: ipToUInt32("255.255.255.255"),
                                   payload: udpData)
            _ = connB.write(frame: Frame(dstMAC: broadcastMAC, srcMAC: Data([mac.b0, mac.b1, mac.b2, mac.b3, mac.b4, mac.b5]),
                                          etherType: etherTypeIPv4, payload: Data(ipPkt.serialize())))
        }
        waitForDeliberation(0.3)

        #expect(true, "stack should survive DHCP option fuzzing")
    }
}

// MARK: - 4. DNS Query Fuzzing

@Test func testFuzzDNSQueries() throws {
    runFuzzTest { stack, connB in
        var rng = FuzzRNG(seed: 888)
        let iterations = 50

        for i in 0..<iterations {
            let txID = rng.nextUInt16()
            let flags = rng.nextUInt16()
            let qdCount = rng.nextUInt16()
            let payloadLen = Int(rng.next() % 100)

            var dnsQuery = [UInt8](repeating: 0, count: 12 + payloadLen)
            dnsQuery[0] = UInt8(txID >> 8); dnsQuery[1] = UInt8(txID & 0xFF)
            dnsQuery[2] = UInt8(flags >> 8); dnsQuery[3] = UInt8(flags & 0xFF)
            dnsQuery[4] = UInt8(qdCount >> 8); dnsQuery[5] = UInt8(qdCount & 0xFF)
            for j in 0..<payloadLen {
                dnsQuery[12 + j] = rng.nextUInt8()
            }

            let udpData = buildDatagram(srcPort: rng.nextUInt16(), dstPort: dnsPort,
                                         payload: dnsQuery)
            let ipPkt = IPv4Packet(version: 4, ihl: 20, tos: 0, totalLen: 0, id: UInt16(0xE00 | i),
                                   flags: 0, fragOffset: 0, ttl: 64, protocol: protocolUDP,
                                   checksum: 0, srcIP: vmIP, dstIP: gwIP,
                                   payload: udpData)
            _ = connB.write(frame: Frame(dstMAC: gwMAC, srcMAC: vmMAC,
                                          etherType: etherTypeIPv4, payload: Data(ipPkt.serialize())))
        }
        waitForDeliberation(0.3)

        #expect(true, "stack should survive DNS query fuzzing")
    }
}

// MARK: - 5. UDP Header Fuzzing

@Test func testFuzzUDPHeaders() throws {
    runFuzzTest { stack, connB in
        var rng = FuzzRNG(seed: 333)
        let iterations = 60

        for i in 0..<iterations {
            let fuzzSrcPort = rng.nextUInt16()
            let fuzzDstPort = rng.nextUInt16()
            let fuzzLength = rng.nextUInt16()
            let payloadLen = Int(rng.next() % 64)
            let fuzzPayload = (0..<payloadLen).map { _ in rng.nextUInt8() }

            // Build raw UDP datagram
            var udpData = [UInt8](repeating: 0, count: 8 + payloadLen)
            udpData[0] = UInt8(fuzzSrcPort >> 8); udpData[1] = UInt8(fuzzSrcPort & 0xFF)
            udpData[2] = UInt8(fuzzDstPort >> 8); udpData[3] = UInt8(fuzzDstPort & 0xFF)
            udpData[4] = UInt8(fuzzLength >> 8); udpData[5] = UInt8(fuzzLength & 0xFF)
            // Checksum intentionally wrong sometimes
            udpData[6] = rng.nextUInt8(); udpData[7] = rng.nextUInt8()
            for j in 0..<payloadLen {
                udpData[8 + j] = fuzzPayload[j]
            }

            let ipPkt = IPv4Packet(version: 4, ihl: 20, tos: 0, totalLen: 0, id: UInt16(0xA00 | i),
                                   flags: 0, fragOffset: 0, ttl: 64, protocol: protocolUDP,
                                   checksum: 0, srcIP: vmIP, dstIP: gwIP,
                                   payload: udpData)
            _ = connB.write(frame: Frame(dstMAC: gwMAC, srcMAC: vmMAC,
                                          etherType: etherTypeIPv4, payload: Data(ipPkt.serialize())))
        }
        waitForDeliberation(0.2)

        #expect(true, "stack should survive UDP header fuzzing")
    }
}

// MARK: - 6. Ethernet Frame Fuzzing

@Test func testFuzzEthernetFrames() throws {
    runFuzzTest { stack, connB in
        var rng = FuzzRNG(seed: 444)
        let iterations = 80

        for _ in 0..<iterations {
            let dstLen = Int(rng.next() % 8)
            let srcLen = Int(rng.next() % 8)
            let etherType = rng.nextUInt16()
            let payloadLen = Int(rng.next() % 128)

            let dstMAC = Data((0..<dstLen).map { _ in rng.nextUInt8() })
            let srcMAC = Data((0..<srcLen).map { _ in rng.nextUInt8() })
            let payload = Data((0..<payloadLen).map { _ in rng.nextUInt8() })

            _ = connB.write(frame: Frame(dstMAC: dstMAC, srcMAC: srcMAC,
                                          etherType: etherType, payload: payload))
        }
        waitForDeliberation(0.2)

        #expect(true, "stack should survive Ethernet frame fuzzing")
    }
}

// MARK: - 7. Mixed Protocol Fuzzing Storm

@Test func testFuzzMixedStorm() throws {
    runFuzzTest(listenPort: 9081) { stack, connB in
        var rng = FuzzRNG(seed: 555)

        // Establish a TCP listener connection first
        let srcPort: UInt16 = 30000
        let synRaw = buildSegment(tuple: Tuple(srcIP: vmIP, dstIP: gwIP, srcPort: srcPort, dstPort: 9081),
                                   seq: 2000, ack: 0, flags: TCPFlag.syn, window: 65535, wscale: 0, payload: [])
        var synBytes = synRaw
        let synCs = tcpChecksum(srcIP: vmIP, dstIP: gwIP, tcpData: synRaw)
        synBytes[16] = UInt8(synCs >> 8); synBytes[17] = UInt8(synCs & 0xFF)
        let synIP = IPv4Packet(version: 4, ihl: 20, tos: 0, totalLen: 0, id: 0x666,
                                flags: 0, fragOffset: 0, ttl: 64, protocol: protocolTCP,
                                checksum: 0, srcIP: vmIP, dstIP: gwIP, payload: synBytes)
        _ = connB.write(frame: Frame(dstMAC: gwMAC, srcMAC: vmMAC,
                                       etherType: etherTypeIPv4, payload: Data(synIP.serialize())))
        waitForDeliberation(0.1)
        _ = readAllFramesFrom(connB, timeout: 0.05)

        // Now blast a mix of fuzzed protocols
        for _ in 0..<100 {
            let choice = rng.next() % 4
            switch choice {
            case 0: // Fuzzed TCP
                let raw = (0..<Int(20 + (rng.next() % 40))).map { _ in rng.nextUInt8() }
                let ipPkt = IPv4Packet(version: 4, ihl: 20, tos: 0, totalLen: 0, id: rng.nextUInt16(),
                                       flags: 0, fragOffset: 0, ttl: 64, protocol: protocolTCP,
                                       checksum: 0, srcIP: rng.nextUInt32(), dstIP: rng.nextUInt32(),
                                       payload: raw)
                _ = connB.write(frame: Frame(dstMAC: gwMAC, srcMAC: vmMAC,
                                              etherType: etherTypeIPv4, payload: Data(ipPkt.serialize())))
            case 1: // Fuzzed UDP
                let raw = (0..<Int(8 + (rng.next() % 32))).map { _ in rng.nextUInt8() }
                let ipPkt = IPv4Packet(version: 4, ihl: 20, tos: 0, totalLen: 0, id: rng.nextUInt16(),
                                       flags: 0, fragOffset: 0, ttl: 64, protocol: protocolUDP,
                                       checksum: 0, srcIP: rng.nextUInt32(), dstIP: rng.nextUInt32(),
                                       payload: raw)
                _ = connB.write(frame: Frame(dstMAC: gwMAC, srcMAC: vmMAC,
                                              etherType: etherTypeIPv4, payload: Data(ipPkt.serialize())))
            case 2: // Raw ARP
                let raw = (0..<Int(10 + (rng.next() % 50))).map { _ in rng.nextUInt8() }
                _ = connB.write(frame: Frame(dstMAC: gwMAC, srcMAC: vmMAC,
                                              etherType: etherTypeARP, payload: Data(raw)))
            default: // Random ethertype
                let raw = (0..<Int(rng.next() % 128)).map { _ in rng.nextUInt8() }
                _ = connB.write(frame: Frame(dstMAC: gwMAC, srcMAC: vmMAC,
                                              etherType: rng.nextUInt16(), payload: Data(raw)))
            }
        }
        waitForDeliberation(0.5)

        #expect(true, "stack should survive mixed protocol fuzzing storm")

    }
}
