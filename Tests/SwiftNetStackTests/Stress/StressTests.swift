import Testing
import Darwin
import Foundation
@testable import SwiftNetStack

@Suite(.serialized)
struct StressTests {

    let hostMAC = MACAddress(0x00, 0x11, 0x22, 0x33, 0x44, 0x55)
    let subnet = IPv4Subnet(network: IPv4Address(100, 64, 1, 0), prefixLength: 24)
    let gateway = IPv4Address(100, 64, 1, 1)
    let vmMAC = MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF)
    let vmIP = IPv4Address(100, 64, 1, 50)

    private func makeEndpoint(id: Int = 1) -> VMEndpoint {
        VMEndpoint(id: id, fd: Int32(id + 100), subnet: subnet, gateway: gateway, mtu: 1500)
    }

    private func runBDPSingleRound(inputs: [(endpointID: Int, packet: PacketBuffer)],
                                    arpMapping: inout ARPMapping,
                                    dhcpServer: inout DHCPServer,
                                    dnsServer: DNSServer = DNSServer(hosts: [:]),
                                    natTable: inout NATTable) -> [(endpointID: Int, packet: PacketBuffer)] {
        var transport: any Transport = InMemoryTransport(inputs: inputs)
        let round = RoundContext()
        var registry = SocketRegistry()
        var reasm = IPFragmentReassembler()
        var dns = dnsServer

        bdpRound(transport: &transport, arpMapping: &arpMapping, dhcpServer: &dhcpServer,
                 dnsServer: &dns, socketRegistry: &registry,
                 ipFragmentReassembler: &reasm, natTable: &natTable, round: round)
        return (transport as! InMemoryTransport).outputs
    }

    // MARK: - High volume single batch

    @Test func batch200MixedFramesSingleRound() {
        let ep = makeEndpoint()
        let clientMAC = MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF)
        let clientIP = IPv4Address(100, 64, 1, 50)

        var arpMapping = ARPMapping(hostMAC: hostMAC, endpoints: [ep])
        arpMapping.add(ip: clientIP, mac: clientMAC, endpointID: 1)
        var dhcpServer = DHCPServer(endpoints: [ep])
        var natTable = NATTable()

        let arpCount = 50, icmpCount = 50, dhcpCount = 50, dnsCount = 50
        var inputs: [(Int, PacketBuffer)] = []

        // ARP
        for i in 0..<arpCount {
            let mac = MACAddress(0xA0, 0x00, 0x00, 0x00, 0x00, UInt8(i))
            let ip = IPv4Address(100, 64, 1, UInt8(10 + i))
            inputs.append((1, makeEthernetFrame(
                dst: .broadcast, src: mac, type: .arp,
                payload: makeARPPayload(op: .request, senderMAC: mac, senderIP: ip,
                                        targetMAC: .zero, targetIP: gateway))))
        }

        // ICMP
        for i in 0..<icmpCount {
            inputs.append((1, makeICMPEchoFrame(
                dstMAC: hostMAC, clientMAC: clientMAC, clientIP: clientIP,
                dstIP: gateway, id: UInt16(i + 1), seq: 1)))
        }

        // DHCP
        for i in 0..<dhcpCount {
            let mac = MACAddress(0xB0, 0x00, 0x00, 0x00, 0x00, UInt8(i))
            let dhcpPayload = makeDHCPPacketBytes(op: 1, xid: UInt32(1000 + i), chaddr: mac, msgType: .discover)
            inputs.append((1, makeDHCPFrame(dstMAC: hostMAC, clientMAC: mac, dhcpPayload: dhcpPayload)))
        }

        // DNS (hosts-file hits)
        let dnsServer = DNSServer(hosts: ["hosted.local": IPv4Address(10, 0, 0, 1)])
        for i in 0..<dnsCount {
            var dnsBytes: [UInt8] = []
            dnsBytes.append(0x00); dnsBytes.append(UInt8(i + 1))
            dnsBytes.append(0x01); dnsBytes.append(0x00)
            dnsBytes.append(0x00); dnsBytes.append(0x01)
            dnsBytes.append(0x00); dnsBytes.append(0x00)
            dnsBytes.append(0x00); dnsBytes.append(0x00)
            dnsBytes.append(0x00); dnsBytes.append(0x00)
            // "hosted.local"
            dnsBytes.append(6)
            dnsBytes.append(contentsOf: "hosted".utf8)
            dnsBytes.append(5)
            dnsBytes.append(contentsOf: "local".utf8)
            dnsBytes.append(0)
            dnsBytes.append(0x00); dnsBytes.append(0x01)
            dnsBytes.append(0x00); dnsBytes.append(0x01)
            inputs.append((1, makeUDPFrame(dstMAC: hostMAC, clientMAC: clientMAC,
                                            srcIP: clientIP, dstIP: gateway,
                                            srcPort: UInt16(30000 + i), dstPort: 53, payload: dnsBytes)))
        }

        let outputs = runBDPSingleRound(inputs: inputs, arpMapping: &arpMapping,
                                         dhcpServer: &dhcpServer, dnsServer: dnsServer, natTable: &natTable)
        #expect(outputs.count == 200)

        // Classify outputs
        var arpReplies = 0, icmpReplies = 0, dhcpReplies = 0, dnsReplies = 0
        for out in outputs {
            guard let eth = EthernetFrame.parse(from: out.packet) else { continue }
            switch eth.etherType {
            case .arp: arpReplies += 1
            case .ipv4:
                guard let ip = IPv4Header.parse(from: eth.payload) else { continue }
                switch ip.protocol {
                case .icmp: icmpReplies += 1
                case .udp:
                    if let udp = UDPHeader.parse(from: ip.payload,
                                                  pseudoSrcAddr: ip.srcAddr,
                                                  pseudoDstAddr: ip.dstAddr) {
                        if udp.srcPort == 67 { dhcpReplies += 1 }
                        else if udp.srcPort == 53 { dnsReplies += 1 }
                    }
                case .tcp: break
                }
            @unknown default: break
            }
        }
        #expect(arpReplies == arpCount)
        #expect(icmpReplies == icmpCount)
        // DHCP count may be less if pool exhausted (/24 = 254 addresses, we're using 50)
        #expect(dhcpReplies == dhcpCount, "got \(dhcpReplies) DHCP replies")
        #expect(dnsReplies == dnsCount)
    }

    // MARK: - Many endpoints

    @Test func manyEndpoints8VMARPStress() {
        let eps = (0..<8).map { i in
            VMEndpoint(id: i + 1, fd: Int32(i + 101),
                       subnet: IPv4Subnet(network: IPv4Address(100, 64, UInt8(i + 1), 0), prefixLength: 24),
                       gateway: IPv4Address(100, 64, UInt8(i + 1), 1),
                       mtu: 1500)
        }

        var arpMapping = ARPMapping(hostMAC: hostMAC, endpoints: eps)
        var dhcpServer = DHCPServer(endpoints: eps)
        var natTable = NATTable()

        var inputs: [(Int, PacketBuffer)] = []
        for ep in eps {
            let mac = MACAddress(0xE0, 0x00, 0x00, 0x00, UInt8(ep.id), 0x01)
            let ip = IPv4Address(100, 64, UInt8(ep.id), 50)
            inputs.append((ep.id, makeEthernetFrame(
                dst: .broadcast, src: mac, type: .arp,
                payload: makeARPPayload(op: .request, senderMAC: mac, senderIP: ip,
                                        targetMAC: .zero, targetIP: ep.gateway))))
        }

        let outputs = runBDPSingleRound(inputs: inputs, arpMapping: &arpMapping,
                                         dhcpServer: &dhcpServer, natTable: &natTable)
        #expect(outputs.count == 8)

        // Each reply goes to the correct endpoint
        for out in outputs {
            #expect(out.endpointID >= 1 && out.endpointID <= 8)
            guard let eth = EthernetFrame.parse(from: out.packet),
                  let arp = ARPFrame.parse(from: eth.payload) else {
                Issue.record("output on endpoint \(out.endpointID) is not valid ARP")
                continue
            }
            #expect(arp.operation == .reply)
            #expect(arp.senderMAC == hostMAC)
            // targetIP should be on the correct subnet
            let oct0 = UInt8((arp.targetIP.addr >> 24) & 0xFF)
            let oct1 = UInt8((arp.targetIP.addr >> 16) & 0xFF)
            let oct2 = UInt8((arp.targetIP.addr >> 8) & 0xFF)
            #expect(oct0 == 100)
            #expect(oct1 == 64)
            #expect(oct2 == UInt8(out.endpointID))
        }
    }

    // MARK: - DHCP pool stress

    @Test func rapidDHCPDiscover100Clients() {
        let ep = makeEndpoint()
        var arpMapping = ARPMapping(hostMAC: hostMAC, endpoints: [ep])
        // /24 subnet → ~254 available addresses, 100 should be fine
        var dhcpServer = DHCPServer(endpoints: [ep])
        var natTable = NATTable()

        var inputs: [(Int, PacketBuffer)] = []
        for i in 0..<100 {
            let mac = MACAddress(0xBA, 0x00, 0x00, 0x00, UInt8(i >> 8), UInt8(i & 0xFF))
            let dhcpPayload = makeDHCPPacketBytes(op: 1, xid: UInt32(5000 + i), chaddr: mac, msgType: .discover)
            inputs.append((1, makeDHCPFrame(dstMAC: hostMAC, clientMAC: mac, dhcpPayload: dhcpPayload)))
        }

        let outputs = runBDPSingleRound(inputs: inputs, arpMapping: &arpMapping,
                                         dhcpServer: &dhcpServer, natTable: &natTable)
        #expect(outputs.count == 100)

        // Verify all are DHCP OFFERs with unique yiaddr values
        var offeredIPs = Set<UInt32>()
        for out in outputs {
            guard let dhcp = extractDHCPFromReply(out.packet) else {
                Issue.record("output is not valid DHCP")
                continue
            }
            #expect(dhcp.messageType == .offer)
            let raw = out.packet.withUnsafeReadableBytes { buf in
                (UInt32(buf[58]) << 24) | (UInt32(buf[59]) << 16) | (UInt32(buf[60]) << 8) | UInt32(buf[61])
            }
            offeredIPs.insert(raw)
        }
        #expect(offeredIPs.count == 100, "all 100 DHCP offers should have unique IPs, got \(offeredIPs.count)")
    }

    @Test func dhcpPoolExhaustionReturnsNil() {
        // Use a /30 subnet: 4 addresses total.
        // 10.0.0.0 = network, 10.0.0.1 = gateway, 10.0.0.2 = usable, 10.0.0.3 = broadcast.
        // Only 1 host address is available; the second discover gets no reply.
        let tinySubnet = IPv4Subnet(network: IPv4Address(10, 0, 0, 0), prefixLength: 30)
        let tinyGW = IPv4Address(10, 0, 0, 1)
        let ep = VMEndpoint(id: 1, fd: 101, subnet: tinySubnet, gateway: tinyGW, mtu: 1500)

        var arpMapping = ARPMapping(hostMAC: hostMAC, endpoints: [ep])
        var dhcpServer = DHCPServer(endpoints: [ep])
        var natTable = NATTable()

        var inputs: [(Int, PacketBuffer)] = []
        for i in 0..<2 {
            let mac = MACAddress(0xCA, 0x00, 0x00, 0x00, 0x00, UInt8(i))
            let dhcpPayload = makeDHCPPacketBytes(op: 1, xid: UInt32(6000 + i), chaddr: mac, msgType: .discover)
            inputs.append((1, makeDHCPFrame(dstMAC: hostMAC, clientMAC: mac, dhcpPayload: dhcpPayload)))
        }

        let outputs = runBDPSingleRound(inputs: inputs, arpMapping: &arpMapping,
                                         dhcpServer: &dhcpServer, natTable: &natTable)
        // Only 1 address available on /30 (excluding network, gateway, broadcast)
        #expect(outputs.count == 1, "only 1 address available on /30, got \(outputs.count)")
    }

    // MARK: - Empty batch

    @Test func emptyInputBatchReturnsZero() {
        let ep = makeEndpoint()
        var arpMapping = ARPMapping(hostMAC: hostMAC, endpoints: [ep])
        var dhcpServer = DHCPServer(endpoints: [ep])
        var natTable = NATTable()

        let outputs = runBDPSingleRound(inputs: [], arpMapping: &arpMapping,
                                         dhcpServer: &dhcpServer, natTable: &natTable)
        #expect(outputs.isEmpty)
    }

    @Test func emptyBatchRepeated1000TimesReturnsZero() {
        let ep = makeEndpoint()
        var arpMapping = ARPMapping(hostMAC: hostMAC, endpoints: [ep])
        var dhcpServer = DHCPServer(endpoints: [ep])
        var natTable = NATTable()

        for _ in 0..<1000 {
            let outputs = runBDPSingleRound(inputs: [], arpMapping: &arpMapping,
                                             dhcpServer: &dhcpServer, natTable: &natTable)
            #expect(outputs.isEmpty)
        }
    }

    // MARK: - IP fragment stress

    @Test func interleavedIPFragmentsReassembleCorrectly() {
        let ep = makeEndpoint()
        let clientMAC = MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF)
        let clientIP = IPv4Address(100, 64, 1, 50)

        var arpMapping = ARPMapping(hostMAC: hostMAC, endpoints: [ep])
        arpMapping.add(ip: clientIP, mac: clientMAC, endpointID: 1)
        var dhcpServer = DHCPServer(endpoints: [ep])
        var natTable = NATTable()

        /// Build an IP fragment header (20 bytes) with specified offset and MF flag.
        func makeFragHeader(id: UInt16, offset: UInt16, mf: Bool, totalLen: UInt16, payloadLen: UInt16) -> [UInt8] {
            var ip = [UInt8](repeating: 0, count: 20)
            ip[0] = 0x45
            ip[2] = UInt8(totalLen >> 8)
            ip[3] = UInt8(totalLen & 0xFF)
            ip[4] = UInt8(id >> 8)
            ip[5] = UInt8(id & 0xFF)
            let fragField: UInt16 = offset | (mf ? 0x2000 : 0x0000)
            ip[6] = UInt8(fragField >> 8)
            ip[7] = UInt8(fragField & 0xFF)
            ip[8] = 64
            ip[9] = IPProtocol.icmp.rawValue
            clientIP.write(to: &ip[12])
            gateway.write(to: &ip[16])
            let ck = ip.withUnsafeBytes { internetChecksum($0) }
            ip[10] = UInt8(ck >> 8)
            ip[11] = UInt8(ck & 0xFF)
            return ip
        }

        // Build two interleaved fragmented ICMP echo requests (id=0xA001 and id=0xA002)
        // Each fragment: 40 bytes of payload → ICMP header (8) + 32 bytes data
        let payload1a: [UInt8] = (0..<32).map { UInt8($0) }
        let payload1b: [UInt8] = (32..<64).map { UInt8($0) }
        let payload2a: [UInt8] = (64..<96).map { UInt8($0) }
        let payload2b: [UInt8] = (96..<128).map { UInt8($0) }

        // Build ICMP packets that will be fragmented
        let icmp1: [UInt8] = [8, 0, 0, 0, 0xA0, 0x01, 0x00, 0x01] + payload1a + payload1b  // 8 + 64 = 72 bytes
        let icmp2: [UInt8] = [8, 0, 0, 0, 0xA0, 0x02, 0x00, 0x01] + payload2a + payload2b

        // Compute ICMP checksums
        var icmp1ck = icmp1; let ck1 = icmp1.withUnsafeBytes { internetChecksum($0) }
        icmp1ck[2] = UInt8(ck1 >> 8); icmp1ck[3] = UInt8(ck1 & 0xFF)
        var icmp2ck = icmp2; let ck2 = icmp2.withUnsafeBytes { internetChecksum($0) }
        icmp2ck[2] = UInt8(ck2 >> 8); icmp2ck[3] = UInt8(ck2 & 0xFF)

        // Fragment datagram 1: first 40 bytes (offset 0, MF=1), last 32 bytes (offset 5, MF=0)
        let frag1aIp = makeFragHeader(id: 0xA001, offset: 0, mf: true, totalLen: UInt16(20 + 40), payloadLen: 40)
        let frag1bIp = makeFragHeader(id: 0xA001, offset: 5, mf: false, totalLen: UInt16(20 + 32), payloadLen: 32)

        // Fragment datagram 2: first 32 bytes (offset 0, MF=1), last 40 bytes (offset 4, MF=0)
        let frag2aIp = makeFragHeader(id: 0xA002, offset: 0, mf: true, totalLen: UInt16(20 + 32), payloadLen: 32)
        let frag2bIp = makeFragHeader(id: 0xA002, offset: 4, mf: false, totalLen: UInt16(20 + 40), payloadLen: 40)

        // Interleave: A1, B1, A2, B2
        let inputs: [(Int, PacketBuffer)] = [
            (1, makeEthernetFrame(dst: hostMAC, src: clientMAC, type: .ipv4, payload: frag1aIp + Array(icmp1ck[0..<40]))),
            (1, makeEthernetFrame(dst: hostMAC, src: clientMAC, type: .ipv4, payload: frag2aIp + Array(icmp2ck[0..<32]))),
            (1, makeEthernetFrame(dst: hostMAC, src: clientMAC, type: .ipv4, payload: frag1bIp + Array(icmp1ck[40..<72]))),
            (1, makeEthernetFrame(dst: hostMAC, src: clientMAC, type: .ipv4, payload: frag2bIp + Array(icmp2ck[32..<72]))),
        ]

        let outputs = runBDPSingleRound(inputs: inputs, arpMapping: &arpMapping,
                                         dhcpServer: &dhcpServer, natTable: &natTable)
        // Both reassembled datagrams → 2 ICMP echo replies
        #expect(outputs.count == 2)
        for out in outputs {
            guard let eth = EthernetFrame.parse(from: out.packet),
                  let ip = IPv4Header.parse(from: eth.payload),
                  let icmp = ICMPHeader.parse(from: ip.payload) else {
                Issue.record("output is not valid ICMP")
                continue
            }
            #expect(icmp.type == 0)  // echo reply
        }
    }

    // MARK: - High volume ICMP

    @Test func highVolume256ICMPEchoInOneBatch() {
        let ep = makeEndpoint()
        let clientMAC = MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF)
        let clientIP = IPv4Address(100, 64, 1, 50)

        var arpMapping = ARPMapping(hostMAC: hostMAC, endpoints: [ep])
        arpMapping.add(ip: clientIP, mac: clientMAC, endpointID: 1)
        var dhcpServer = DHCPServer(endpoints: [ep])
        var natTable = NATTable()

        let total = 256
        var inputs: [(Int, PacketBuffer)] = []
        for i in 0..<total {
            inputs.append((1, makeICMPEchoFrame(
                dstMAC: hostMAC, clientMAC: clientMAC, clientIP: clientIP,
                dstIP: gateway, id: UInt16(1 + i / 65536), seq: UInt16(i % 65536))))
        }

        let outputs = runBDPSingleRound(inputs: inputs, arpMapping: &arpMapping,
                                         dhcpServer: &dhcpServer, natTable: &natTable)
        #expect(outputs.count == total)
        for out in outputs {
            guard let eth = EthernetFrame.parse(from: out.packet),
                  let ip = IPv4Header.parse(from: eth.payload),
                  let icmp = ICMPHeader.parse(from: ip.payload) else {
                Issue.record("output is not valid ICMP")
                continue
            }
            #expect(icmp.type == 0)
            #expect(ip.verifyChecksum())
        }
    }

    // MARK: - Multi-round state consistency

    @Test func multiRoundARPStateConsistent() {
        let ep = makeEndpoint()
        let clientMAC = MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF)
        let clientIP = IPv4Address(100, 64, 1, 50)

        var arpMapping = ARPMapping(hostMAC: hostMAC, endpoints: [ep])
        var dhcpServer = DHCPServer(endpoints: [ep])
        var natTable = NATTable()

        // Round 1: ARP request. processARPRequest does NOT learn the sender —
        // we explicitly add the mapping to simulate a DHCP-learned entry.
        let arpFrame = makeEthernetFrame(
            dst: .broadcast, src: clientMAC, type: .arp,
            payload: makeARPPayload(op: .request, senderMAC: clientMAC, senderIP: clientIP,
                                    targetMAC: .zero, targetIP: gateway))
        _ = runBDPSingleRound(inputs: [(1, arpFrame)], arpMapping: &arpMapping,
                               dhcpServer: &dhcpServer, natTable: &natTable)
        arpMapping.add(ip: clientIP, mac: clientMAC, endpointID: 1)
        #expect(arpMapping.isKnown(clientIP))

        // Round 2: 100 ICMP echoes using the mapped IP
        var icmpInputs: [(Int, PacketBuffer)] = []
        for i in 0..<100 {
            icmpInputs.append((1, makeICMPEchoFrame(
                dstMAC: hostMAC, clientMAC: clientMAC, clientIP: clientIP,
                dstIP: gateway, id: UInt16(i + 1), seq: 1)))
        }
        let outputs = runBDPSingleRound(inputs: icmpInputs, arpMapping: &arpMapping,
                                         dhcpServer: &dhcpServer, natTable: &natTable)
        #expect(outputs.count == 100)

        // Round 3: mapping should still be known
        #expect(arpMapping.isKnown(clientIP))
    }

    // MARK: - E2E socketpair stress

    @Test func socketPairBatch50MixedFramesE2E() {
        var fds: [Int32] = [-1, -1]
        let rc = socketpair(AF_UNIX, SOCK_DGRAM, 0, &fds)
        guard rc == 0 else {
            Issue.record("socketpair failed: \(errno)")
            return
        }
        let hostFD = fds[0], guestFD = fds[1]
        defer { close(hostFD); close(guestFD) }

        let ep = VMEndpoint(id: 1, fd: hostFD, subnet: subnet, gateway: gateway)
        var loop = DeliberationLoop(endpoints: [ep], hostMAC: hostMAC)
        var transport: any Transport = PollingTransport(endpoints: [ep])

        let clientMAC = MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF)
        let clientIP = IPv4Address(100, 64, 1, 50)

        /// Write raw bytes to fd with 100ms poll timeout.
        func writeToFD(_ fd: Int32, _ bytes: [UInt8]) -> Bool {
            bytes.withUnsafeBytes { Darwin.write(fd, $0.baseAddress!, bytes.count) > 0 }
        }

        /// Read up to `maxLen` bytes from fd with a short timeout. Returns empty if timeout.
        func readFromFD(_ fd: Int32, maxLen: Int = 2048) -> [UInt8] {
            var pfd = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
            let rc = Darwin.poll(&pfd, 1, 100)
            guard rc > 0, pfd.revents & Int16(POLLIN) != 0 else { return [] }
            var buf = [UInt8](repeating: 0, count: maxLen)
            let n = Darwin.read(fd, &buf, maxLen)
            guard n > 0 else { return [] }
            return Array(buf[0..<n])
        }

        // Write 25 ARP + 25 ICMP in batches of 10 to avoid socket buffer overflow
        let batchSize = 10
        var totalReplies = 0

        // ARP batch
        for batchStart in stride(from: 0, to: 25, by: batchSize) {
            let end = min(batchStart + batchSize, 25)
            for i in batchStart..<end {
                let mac = MACAddress(0xF0, 0x00, 0x00, 0x00, 0x00, UInt8(i))
                let ip = IPv4Address(100, 64, 1, UInt8(100 + i))
                let arpFrame = makeEthernetFrameBytes(
                    dst: .broadcast, src: mac, type: .arp,
                    payload: makeARPPayload(op: .request, senderMAC: mac, senderIP: ip,
                                            targetMAC: .zero, targetIP: gateway))
                writeToFD(guestFD, arpFrame)
            }
            totalReplies += loop.runOneRound(transport: &transport)
            // Drain replies from guestFD
            for _ in batchStart..<end { _ = readFromFD(guestFD) }
        }

        // ICMP batch (ARP mapping already populated by previous rounds)
        for batchStart in stride(from: 0, to: 25, by: batchSize) {
            let end = min(batchStart + batchSize, 25)
            for i in batchStart..<end {
                let icmpFrame = makeICMPEchoFrameBytes(
                    dstMAC: hostMAC, clientMAC: clientMAC, clientIP: clientIP,
                    dstIP: gateway, id: UInt16(i + 1), seq: 1)
                writeToFD(guestFD, icmpFrame)
            }
            totalReplies += loop.runOneRound(transport: &transport)
            for _ in batchStart..<end { _ = readFromFD(guestFD) }
        }

        #expect(totalReplies == 50)
    }

    // MARK: - E2E socketpair TCP

    /// End-to-end TCP handshake + data transfer through socketpair +
    /// DeliberationLoop + PollingTransport. Each runOneRound call is
    /// preceded by a write to guestFD so the blocking poll always has
    /// data to read. Phase 11 (pollSockets) handles external→VM data
    /// within the same round.
    @Test func tcpDataTransferE2E() {
        guard let echo = TCPEchoServer.make() else {
            Issue.record("failed to start echo server"); return
        }

        var fds: [Int32] = [-1, -1]
        let rc = socketpair(AF_UNIX, SOCK_DGRAM, 0, &fds)
        guard rc == 0 else {
            Issue.record("socketpair failed: \(errno)"); return
        }
        let hostFD = fds[0], guestFD = fds[1]
        defer { close(hostFD); close(guestFD) }

        let ep = VMEndpoint(id: 1, fd: hostFD, subnet: subnet, gateway: gateway)
        var loop = DeliberationLoop(endpoints: [ep], hostMAC: hostMAC)
        var transport: any Transport = PollingTransport(endpoints: [ep])

        let dstIP = IPv4Address(127, 0, 0, 1)
        let srcPort: UInt16 = 22350

        // Helper: write bytes to guestFD
        func w(_ bytes: [UInt8]) {
            guard Darwin.write(guestFD, bytes, bytes.count) > 0 else {
                Issue.record("write failed")
                return
            }
        }

        // Helper: read available bytes from guestFD with short poll
        func r() -> [UInt8] {
            var pfd = pollfd(fd: guestFD, events: Int16(POLLIN), revents: 0)
            guard Darwin.poll(&pfd, 1, 50) > 0,
                  pfd.revents & Int16(POLLIN) != 0 else { return [] }
            var buf = [UInt8](repeating: 0, count: 4096)
            let n = Darwin.read(guestFD, &buf, 4096)
            return n > 0 ? Array(buf[0..<n]) : []
        }

        // ── SYN ──
        w(makeTCPFrame(dstMAC: hostMAC, srcMAC: vmMAC,
                       srcIP: vmIP, dstIP: dstIP,
                       srcPort: srcPort, dstPort: echo.port,
                       seq: 0, ack: 0, flags: .syn)
            .withUnsafeReadableBytes { Array($0) })

        let replyCount1 = loop.runOneRound(transport: &transport)
        #expect(replyCount1 >= 1, "expected SYN+ACK, got \(replyCount1)")

        let synAckRaw = r()
        guard !synAckRaw.isEmpty,
              let synAckEth = EthernetFrame.parse(from: packetFrom(synAckRaw)),
              let synAckIP = IPv4Header.parse(from: synAckEth.payload),
              let synAckTCP = TCPHeader.parse(from: synAckIP.payload,
                                              pseudoSrcAddr: synAckIP.srcAddr,
                                              pseudoDstAddr: synAckIP.dstAddr),
              synAckTCP.flags.isSynAck
        else { Issue.record("no SYN+ACK, got \(synAckRaw.count) bytes"); return }
        let natISN = synAckTCP.sequenceNumber

        // ── ACK (complete handshake) ──
        w(makeTCPFrame(dstMAC: hostMAC, srcMAC: vmMAC,
                       srcIP: vmIP, dstIP: dstIP,
                       srcPort: srcPort, dstPort: echo.port,
                       seq: 1, ack: natISN &+ 1, flags: .ack)
            .withUnsafeReadableBytes { Array($0) })
        _ = loop.runOneRound(transport: &transport)

        // ── Data (PSH+ACK with payload) ──
        let vmData: [UInt8] = (0..<256).map { UInt8($0 & 0xFF) }
        w(makeTCPFrame(dstMAC: hostMAC, srcMAC: vmMAC,
                       srcIP: vmIP, dstIP: dstIP,
                       srcPort: srcPort, dstPort: echo.port,
                       seq: 1, ack: natISN &+ 1,
                       flags: [.ack, .psh], payload: vmData)
            .withUnsafeReadableBytes { Array($0) })
        _ = loop.runOneRound(transport: &transport)

        // Drain echo reply. Because PollingTransport blocks on poll()
        // waiting for VM frames, we may need multiple rounds for Phase 11
        // (pollSockets) to pick up the async echo. Each round is triggered
        // by writing a harmless ARP request as a "keepalive" frame.
        var echoed: [UInt8] = []
        var attempts = 0
        while echoed.count < vmData.count, attempts < 30 {
            attempts += 1

            // Drain any data already on guestFD
            var raw = r()
            while !raw.isEmpty {
                if let eth = EthernetFrame.parse(from: packetFrom(raw)),
                   let ip = IPv4Header.parse(from: eth.payload),
                   let tcp = TCPHeader.parse(from: ip.payload,
                                             pseudoSrcAddr: ip.srcAddr,
                                             pseudoDstAddr: ip.dstAddr) {
                    let payload = tcp.payload.withUnsafeReadableBytes { Array($0) }
                    if !payload.isEmpty { echoed.append(contentsOf: payload) }
                }
                raw = r()
            }
            if echoed.count >= vmData.count { break }

            // Trigger another round: write a dummy ARP request so poll()
            // wakes up, giving Phase 11 another chance to read TCP socket data.
            w(makeEthernetFrameBytes(
                dst: .broadcast, src: vmMAC, type: .arp,
                payload: makeARPPayload(op: .request, senderMAC: vmMAC,
                                        senderIP: vmIP, targetMAC: .zero,
                                        targetIP: gateway)))
            _ = loop.runOneRound(transport: &transport)
            Thread.sleep(forTimeInterval: 0.01)
        }
        #expect(echoed == vmData, "echoed \(echoed.count) bytes, expected \(vmData.count)")

        // ── FIN ──
        w(makeTCPFrame(dstMAC: hostMAC, srcMAC: vmMAC,
                       srcIP: vmIP, dstIP: dstIP,
                       srcPort: srcPort, dstPort: echo.port,
                       seq: 1 &+ UInt32(vmData.count),
                       ack: natISN &+ 1 &+ UInt32(echoed.count),
                       flags: [.ack, .fin])
            .withUnsafeReadableBytes { Array($0) })
        _ = loop.runOneRound(transport: &transport)

        echo.waitDone()
    }
}
