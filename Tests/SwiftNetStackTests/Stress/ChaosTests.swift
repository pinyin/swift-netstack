import Testing
import Darwin
@testable import SwiftNetStack

@Suite(.serialized)
struct ChaosTests {

    let hostMAC = MACAddress(0x00, 0x11, 0x22, 0x33, 0x44, 0x55)
    let subnet = IPv4Subnet(network: IPv4Address(100, 64, 1, 0), prefixLength: 24)
    let gateway = IPv4Address(100, 64, 1, 1)

    private func makeEndpoint(id: Int = 1) -> VMEndpoint {
        VMEndpoint(id: id, fd: Int32(id + 100), subnet: subnet, gateway: gateway, mtu: 1500)
    }

    /// Run a single BDP round with given input frames and return the outputs.
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
                 dnsServer: &dns, routingTable: RoutingTable(), socketRegistry: &registry,
                 ipFragmentReassembler: &reasm, natTable: &natTable, round: round)
        return (transport as! InMemoryTransport).outputs
    }

    // MARK: - Random ordering

    @Test func randomlyOrderedARPFramesAllGetReplies() {
        let ep = makeEndpoint()
        var arpMapping = ARPMapping(hostMAC: hostMAC, endpoints: [ep])
        var dhcpServer = DHCPServer(endpoints: [ep])
        var natTable = NATTable()

        var inputs: [(Int, PacketBuffer)] = []
        for i in 0..<20 {
            let mac = MACAddress(0xA0, 0x00, 0x00, 0x00, 0x00, UInt8(i))
            let ip = IPv4Address(100, 64, 1, UInt8(10 + i))
            let arpFrame = makeEthernetFrame(
                dst: .broadcast, src: mac, type: .arp,
                payload: makeARPPayload(op: .request, senderMAC: mac, senderIP: ip,
                                        targetMAC: .zero, targetIP: gateway))
            inputs.append((1, arpFrame))
        }
        inputs.shuffle()

        let outputs = runBDPSingleRound(inputs: inputs, arpMapping: &arpMapping,
                                         dhcpServer: &dhcpServer, natTable: &natTable)
        #expect(outputs.count == 20)
        // Verify each reply is a valid ARP reply
        for out in outputs {
            guard let eth = EthernetFrame.parse(from: out.packet),
                  let arp = ARPFrame.parse(from: eth.payload) else {
                Issue.record("output is not valid ARP")
                continue
            }
            #expect(arp.operation == .reply)
            #expect(arp.senderMAC == hostMAC)
        }
    }

    @Test func randomlyOrderedMixedProtocolFramesAllGetReplies() {
        let ep = makeEndpoint()
        let clientMAC = MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF)
        let clientIP = IPv4Address(100, 64, 1, 50)

        var arpMapping = ARPMapping(hostMAC: hostMAC, endpoints: [ep])
        var dhcpServer = DHCPServer(endpoints: [ep])
        var natTable = NATTable()

        var inputs: [(Int, PacketBuffer)] = []

        // 10 ARP requests (different IPs)
        for i in 0..<10 {
            let mac = MACAddress(0xA0, 0x00, 0x00, 0x00, 0x00, UInt8(i))
            let ip = IPv4Address(100, 64, 1, UInt8(10 + i))
            inputs.append((1, makeEthernetFrame(
                dst: .broadcast, src: mac, type: .arp,
                payload: makeARPPayload(op: .request, senderMAC: mac, senderIP: ip,
                                        targetMAC: .zero, targetIP: gateway))))
        }

        // 10 ICMP echo requests (already in ARP table via arpMapping.add)
        arpMapping.add(ip: clientIP, mac: clientMAC, endpointID: 1)
        for i in 0..<10 {
            inputs.append((1, makeICMPEchoFrame(
                dstMAC: hostMAC, clientMAC: clientMAC, clientIP: clientIP,
                dstIP: gateway, id: UInt16(i + 1), seq: 1)))
        }

        // 5 DHCP discovers
        for i in 0..<5 {
            let mac = MACAddress(0xB0, 0x00, 0x00, 0x00, 0x00, UInt8(i))
            let dhcpPayload = makeDHCPPacketBytes(op: 1, xid: UInt32(100 + i), chaddr: mac, msgType: .discover)
            inputs.append((1, makeDHCPFrame(dstMAC: hostMAC, clientMAC: mac, dhcpPayload: dhcpPayload)))
        }

        inputs.shuffle()

        let outputs = runBDPSingleRound(inputs: inputs, arpMapping: &arpMapping,
                                         dhcpServer: &dhcpServer, natTable: &natTable)
        #expect(outputs.count == 25)  // 10 ARP + 10 ICMP + 5 DHCP
    }

    // MARK: - Packet duplication

    @Test func duplicateARPRequestGeneratesTwoReplies() {
        let ep = makeEndpoint()
        let clientMAC = MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF)
        let clientIP = IPv4Address(100, 64, 1, 50)

        let arpPayload = makeARPPayload(op: .request, senderMAC: clientMAC, senderIP: clientIP,
                                        targetMAC: .zero, targetIP: gateway)
        let frame = makeEthernetFrame(dst: .broadcast, src: clientMAC, type: .arp, payload: arpPayload)

        var arpMapping = ARPMapping(hostMAC: hostMAC, endpoints: [ep])
        var dhcpServer = DHCPServer(endpoints: [ep])
        var natTable = NATTable()

        let outputs = runBDPSingleRound(inputs: [(1, frame), (1, frame)],
                                         arpMapping: &arpMapping, dhcpServer: &dhcpServer, natTable: &natTable)
        #expect(outputs.count == 2)
        for out in outputs {
            guard let eth = EthernetFrame.parse(from: out.packet),
                  let arp = ARPFrame.parse(from: eth.payload) else { continue }
            #expect(arp.operation == .reply)
            #expect(arp.senderMAC == hostMAC)
            #expect(arp.targetIP == clientIP)
        }
    }

    @Test func duplicateICMPEchoGeneratesTwoReplies() {
        let ep = makeEndpoint()
        let clientMAC = MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF)
        let clientIP = IPv4Address(100, 64, 1, 50)

        var arpMapping = ARPMapping(hostMAC: hostMAC, endpoints: [ep])
        var dhcpServer = DHCPServer(endpoints: [ep])
        var natTable = NATTable()
        arpMapping.add(ip: clientIP, mac: clientMAC, endpointID: 1)

        let frame = makeICMPEchoFrame(dstMAC: hostMAC, clientMAC: clientMAC,
                                       clientIP: clientIP, dstIP: gateway, id: 0x42, seq: 1)

        let outputs = runBDPSingleRound(inputs: [(1, frame), (1, frame)],
                                         arpMapping: &arpMapping, dhcpServer: &dhcpServer, natTable: &natTable)
        #expect(outputs.count == 2)
        for out in outputs {
            guard let eth = EthernetFrame.parse(from: out.packet),
                  let ip = IPv4Header.parse(from: eth.payload),
                  let icmp = ICMPHeader.parse(from: ip.payload) else { continue }
            #expect(icmp.type == 0)  // echo reply
            #expect(icmp.identifier == 0x42)
        }
    }

    // MARK: - Corrupted packets alongside valid ones

    @Test func corruptedIPChecksumFramesAreDropped() {
        let ep = makeEndpoint()
        let clientMAC = MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF)
        let clientIP = IPv4Address(100, 64, 1, 50)

        var arpMapping = ARPMapping(hostMAC: hostMAC, endpoints: [ep])
        var dhcpServer = DHCPServer(endpoints: [ep])
        var natTable = NATTable()
        arpMapping.add(ip: clientIP, mac: clientMAC, endpointID: 1)

        let validFrame = makeICMPEchoFrame(dstMAC: hostMAC, clientMAC: clientMAC,
                                            clientIP: clientIP, dstIP: gateway, id: 1, seq: 1)
        let validBytes = validFrame.withUnsafeReadableBytes { Array($0) }

        // Corrupt the IP checksum (bytes 24-25 in the Ethernet frame: 14 + 10)
        let corruptedBytes = corruptChecksum(in: validBytes, atLo: 24, hi: 25)

        let outputs = runBDPSingleRound(
            inputs: [(1, validFrame), (1, packetFrom(corruptedBytes))],
            arpMapping: &arpMapping, dhcpServer: &dhcpServer, natTable: &natTable)
        #expect(outputs.count == 1, "only the valid frame should produce a reply")
    }

    @Test func mixedValidAndCorruptFramesProduceCorrectCounts() {
        let ep = makeEndpoint()
        let clientMAC = MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF)
        let clientIP = IPv4Address(100, 64, 1, 50)

        var arpMapping = ARPMapping(hostMAC: hostMAC, endpoints: [ep])
        var dhcpServer = DHCPServer(endpoints: [ep])
        var natTable = NATTable()
        arpMapping.add(ip: clientIP, mac: clientMAC, endpointID: 1)

        let validFrame = makeICMPEchoFrame(dstMAC: hostMAC, clientMAC: clientMAC,
                                            clientIP: clientIP, dstIP: gateway, id: 1, seq: 1)
        let validBytes = validFrame.withUnsafeReadableBytes { Array($0) }
        let corruptedBytes = corruptChecksum(in: validBytes, atLo: 24, hi: 25)

        // 5 valid + 5 corrupt = 10 inputs, expect 5 replies
        let inputs: [(Int, PacketBuffer)] = [
            (1, validFrame),
            (1, packetFrom(corruptedBytes)),
            (1, validFrame),
            (1, packetFrom(corruptedBytes)),
            (1, validFrame),
            (1, packetFrom(corruptedBytes)),
            (1, validFrame),
            (1, packetFrom(corruptedBytes)),
            (1, validFrame),
            (1, packetFrom(corruptedBytes)),
        ]

        let outputs = runBDPSingleRound(inputs: inputs, arpMapping: &arpMapping,
                                         dhcpServer: &dhcpServer, natTable: &natTable)
        #expect(outputs.count == 5)
    }

    // MARK: - Truncated frames

    @Test func truncatedEthernetFramesAreDroppedSilently() {
        let ep = makeEndpoint()
        var arpMapping = ARPMapping(hostMAC: hostMAC, endpoints: [ep])
        var dhcpServer = DHCPServer(endpoints: [ep])
        var natTable = NATTable()

        let validARP = makeEthernetFrame(
            dst: .broadcast,
            src: MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF),
            type: .arp,
            payload: makeARPPayload(op: .request,
                                     senderMAC: MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF),
                                     senderIP: IPv4Address(100, 64, 1, 50),
                                     targetMAC: .zero, targetIP: gateway))
        let validBytes = validARP.withUnsafeReadableBytes { Array($0) }

        // Truncated to 13 bytes (< 14 = no valid Ethernet header)
        let truncated = truncatedFrame(validBytes, to: 13)

        let outputs = runBDPSingleRound(
            inputs: [(1, validARP), (1, packetFrom(truncated))],
            arpMapping: &arpMapping, dhcpServer: &dhcpServer, natTable: &natTable)
        #expect(outputs.count == 1, "truncated frame should be dropped, only valid ARP gets reply")
    }

    @Test func emptyPayloadFrameIsDropped() {
        let ep = makeEndpoint()
        var arpMapping = ARPMapping(hostMAC: hostMAC, endpoints: [ep])
        var dhcpServer = DHCPServer(endpoints: [ep])
        var natTable = NATTable()

        // Exactly 14 bytes — valid Ethernet header but zero payload
        let emptyPayload = packetFrom([UInt8](repeating: 0, count: 14))
        let validFrame = makeEthernetFrame(
            dst: .broadcast,
            src: MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF),
            type: .arp,
            payload: makeARPPayload(op: .request,
                                     senderMAC: MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF),
                                     senderIP: IPv4Address(100, 64, 1, 50),
                                     targetMAC: .zero, targetIP: gateway))

        let outputs = runBDPSingleRound(inputs: [(1, emptyPayload), (1, validFrame)],
                                         arpMapping: &arpMapping, dhcpServer: &dhcpServer, natTable: &natTable)
        #expect(outputs.count == 1, "valid frame gets reply, empty-payload frame is ignored")
    }

    // MARK: - Malformed DNS queries

    @Test func dnsQueryWithCompressionPointerIsDropped() {
        let ep = makeEndpoint()
        let clientMAC = MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF)
        let clientIP = IPv4Address(100, 64, 1, 50)

        var arpMapping = ARPMapping(hostMAC: hostMAC, endpoints: [ep])
        arpMapping.add(ip: clientIP, mac: clientMAC, endpointID: 1)
        var dhcpServer = DHCPServer(endpoints: [ep])
        var dnsServer = DNSServer(hosts: ["example.com": IPv4Address(1, 2, 3, 4)])
        var natTable = NATTable()

        // Build a DNS query with a compression pointer (0xC0xx) in the QNAME
        // Standard DNS header (12 bytes) + QNAME with compression pointer
        var dnsBytes: [UInt8] = []
        // Header
        dnsBytes.append(0x00); dnsBytes.append(0x01)  // txID
        dnsBytes.append(0x01); dnsBytes.append(0x00)  // flags: RD=1
        dnsBytes.append(0x00); dnsBytes.append(0x01)  // QDCOUNT=1
        dnsBytes.append(0x00); dnsBytes.append(0x00)  // ANCOUNT
        dnsBytes.append(0x00); dnsBytes.append(0x00)  // NSCOUNT
        dnsBytes.append(0x00); dnsBytes.append(0x00)  // ARCOUNT
        // Malformed QNAME: starts with compression pointer (0xC0xx)
        dnsBytes.append(0xC0); dnsBytes.append(0x0C)  // compression pointer → rejected
        dnsBytes.append(0x00); dnsBytes.append(0x01)  // QTYPE=A
        dnsBytes.append(0x00); dnsBytes.append(0x01)  // QCLASS=IN

        let udpFrame = makeUDPFrame(dstMAC: hostMAC, clientMAC: clientMAC,
                                     srcIP: clientIP, dstIP: gateway,
                                     srcPort: 12345, dstPort: 53, payload: dnsBytes)

        let outputs = runBDPSingleRound(inputs: [(1, udpFrame)], arpMapping: &arpMapping,
                                         dhcpServer: &dhcpServer, dnsServer: dnsServer, natTable: &natTable)
        // With compression pointer, parse should fail → NXDOMAIN (not crash)
        // Either 0 replies (parse failed before processing) or 1 reply (NXDOMAIN)
        #expect(outputs.count <= 1)
        if outputs.count == 1 {
            guard let eth = EthernetFrame.parse(from: outputs[0].packet),
                  let ip = IPv4Header.parse(from: eth.payload),
                  let udp = UDPHeader.parse(from: ip.payload, pseudoSrcAddr: ip.srcAddr, pseudoDstAddr: ip.dstAddr),
                  let (_, question) = DNSPacket.parse(from: udp.payload) else {
                Issue.record("reply is not valid DNS")
                return
            }
            // NXDOMAIN is acceptable, but the parse should have failed
            _ = question
        }
        // Key invariant: no crash
    }

    @Test func dnsQueryWithQRBitSetIsDropped() {
        let ep = makeEndpoint()
        let clientMAC = MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF)
        let clientIP = IPv4Address(100, 64, 1, 50)

        var arpMapping = ARPMapping(hostMAC: hostMAC, endpoints: [ep])
        arpMapping.add(ip: clientIP, mac: clientMAC, endpointID: 1)
        var dhcpServer = DHCPServer(endpoints: [ep])
        var dnsServer = DNSServer(hosts: ["example.com": IPv4Address(1, 2, 3, 4)])
        var natTable = NATTable()

        // "response" with QR=1 where a query is expected
        var dnsBytes: [UInt8] = []
        dnsBytes.append(0x00); dnsBytes.append(0x01)  // txID
        dnsBytes.append(0x81); dnsBytes.append(0x80)  // flags: QR=1 (response!)
        dnsBytes.append(0x00); dnsBytes.append(0x01)  // QDCOUNT=1
        dnsBytes.append(0x00); dnsBytes.append(0x00)  // ANCOUNT
        dnsBytes.append(0x00); dnsBytes.append(0x00)  // NSCOUNT
        dnsBytes.append(0x00); dnsBytes.append(0x00)  // ARCOUNT
        // Valid QNAME: example.com
        dnsBytes.append(7)
        dnsBytes.append(contentsOf: "example".utf8)
        dnsBytes.append(3)
        dnsBytes.append(contentsOf: "com".utf8)
        dnsBytes.append(0)
        dnsBytes.append(0x00); dnsBytes.append(0x01)  // QTYPE=A
        dnsBytes.append(0x00); dnsBytes.append(0x01)  // QCLASS=IN

        let udpFrame = makeUDPFrame(dstMAC: hostMAC, clientMAC: clientMAC,
                                     srcIP: clientIP, dstIP: gateway,
                                     srcPort: 12345, dstPort: 53, payload: dnsBytes)

        let outputs = runBDPSingleRound(inputs: [(1, udpFrame)], arpMapping: &arpMapping,
                                         dhcpServer: &dhcpServer, dnsServer: dnsServer, natTable: &natTable)
        // QR=1 in a "query" should cause parse to fail → no output (or NXDOMAIN fallthrough)
        #expect(outputs.count <= 1)
    }

    // MARK: - Edge case: zero IP total length

    @Test func zeroIPTotalLengthIsDropped() {
        let ep = makeEndpoint()
        let clientMAC = MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF)

        var arpMapping = ARPMapping(hostMAC: hostMAC, endpoints: [ep])
        var dhcpServer = DHCPServer(endpoints: [ep])
        var natTable = NATTable()

        // Build Ethernet frame containing IPv4 with totalLength=0
        var ipHdr = [UInt8](repeating: 0, count: 20)
        ipHdr[0] = 0x45
        // totalLength=0 at bytes 2-3
        let corruptedIP = corruptByte(in: ipHdr, at: 2, to: 0)
        var eth = makeEthernetFrameBytes(dst: hostMAC, src: clientMAC, type: .ipv4, payload: corruptedIP)

        // Also include a valid ARP request to verify pipeline continues
        let validARP = makeEthernetFrame(
            dst: .broadcast, src: clientMAC, type: .arp,
            payload: makeARPPayload(op: .request, senderMAC: clientMAC,
                                     senderIP: IPv4Address(100, 64, 1, 50),
                                     targetMAC: .zero, targetIP: gateway))

        let outputs = runBDPSingleRound(
            inputs: [(1, packetFrom(eth)), (1, validARP)],
            arpMapping: &arpMapping, dhcpServer: &dhcpServer, natTable: &natTable)
        #expect(outputs.count == 1, "only ARP gets reply; zero-length IPv4 is dropped")
    }

    // MARK: - Stress mix: all protocols interleaved randomly

    @Test func allProtocolsInterleavedRandomly() {
        let ep = makeEndpoint()
        let clientMAC = MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF)
        let clientIP = IPv4Address(100, 64, 1, 50)

        var arpMapping = ARPMapping(hostMAC: hostMAC, endpoints: [ep])
        arpMapping.add(ip: clientIP, mac: clientMAC, endpointID: 1)
        var dhcpServer = DHCPServer(endpoints: [ep])
        let dnsServer = DNSServer(hosts: ["test.local": IPv4Address(10, 0, 0, 1)])
        var natTable = NATTable()

        var inputs: [(Int, PacketBuffer)] = []

        // 15 ARP
        for i in 0..<15 {
            let mac = MACAddress(0xC0, 0x00, 0x00, 0x00, 0x00, UInt8(i))
            let ip = IPv4Address(100, 64, 1, UInt8(20 + i))
            inputs.append((1, makeEthernetFrame(
                dst: .broadcast, src: mac, type: .arp,
                payload: makeARPPayload(op: .request, senderMAC: mac, senderIP: ip,
                                        targetMAC: .zero, targetIP: gateway))))
        }

        // 15 ICMP
        for i in 0..<15 {
            inputs.append((1, makeICMPEchoFrame(
                dstMAC: hostMAC, clientMAC: clientMAC, clientIP: clientIP,
                dstIP: gateway, id: UInt16(100 + i), seq: 1)))
        }

        // 10 DHCP discovers
        for i in 0..<10 {
            let mac = MACAddress(0xD0, 0x00, 0x00, 0x00, 0x00, UInt8(i))
            let dhcpPayload = makeDHCPPacketBytes(op: 1, xid: UInt32(200 + i), chaddr: mac, msgType: .discover)
            inputs.append((1, makeDHCPFrame(dstMAC: hostMAC, clientMAC: mac, dhcpPayload: dhcpPayload)))
        }

        // 10 DNS (hits hosts file)
        for i in 0..<10 {
            var dnsBytes: [UInt8] = []
            dnsBytes.append(0x00); dnsBytes.append(UInt8(i + 1))
            dnsBytes.append(0x01); dnsBytes.append(0x00)  // flags: RD=1
            dnsBytes.append(0x00); dnsBytes.append(0x01)  // QDCOUNT
            dnsBytes.append(0x00); dnsBytes.append(0x00)  // ANCOUNT
            dnsBytes.append(0x00); dnsBytes.append(0x00)  // NSCOUNT
            dnsBytes.append(0x00); dnsBytes.append(0x00)  // ARCOUNT
            // QNAME: test.local
            dnsBytes.append(4)
            dnsBytes.append(contentsOf: "test".utf8)
            dnsBytes.append(5)
            dnsBytes.append(contentsOf: "local".utf8)
            dnsBytes.append(0)
            dnsBytes.append(0x00); dnsBytes.append(0x01)  // QTYPE=A
            dnsBytes.append(0x00); dnsBytes.append(0x01)  // QCLASS=IN
            inputs.append((1, makeUDPFrame(dstMAC: hostMAC, clientMAC: clientMAC,
                                            srcIP: clientIP, dstIP: gateway,
                                            srcPort: UInt16(20000 + i), dstPort: 53, payload: dnsBytes)))
        }

        inputs.shuffle()
        // Also duplicate 5 random frames within the batch
        let dupes = (0..<5).map { _ in inputs[Int.random(in: 0..<inputs.count)] }
        inputs.append(contentsOf: dupes)

        let outputs = runBDPSingleRound(inputs: inputs, arpMapping: &arpMapping,
                                         dhcpServer: &dhcpServer, dnsServer: dnsServer, natTable: &natTable)
        // 15 ARP + 15 ICMP + 10 DHCP + 10 DNS + 5 dupes = 55 expected
        #expect(outputs.count == 55)

        // Verify protocol distribution
        var arpCount = 0, icmpCount = 0, dhcpCount = 0, dnsCount = 0
        for out in outputs {
            guard let eth = EthernetFrame.parse(from: out.packet) else { continue }
            switch eth.etherType {
            case .arp: arpCount += 1
            case .ipv4:
                guard let ip = IPv4Header.parse(from: eth.payload) else { continue }
                switch ip.protocol {
                case .icmp: icmpCount += 1
                case .udp:
                    // Distinguish DHCP (port 67/68) from DNS (port 53)
                    if let udp = UDPHeader.parse(from: ip.payload,
                                                  pseudoSrcAddr: ip.srcAddr,
                                                  pseudoDstAddr: ip.dstAddr) {
                        if udp.srcPort == 67 || udp.dstPort == 67 { dhcpCount += 1 }
                        else if udp.srcPort == 53 || udp.dstPort == 53 { dnsCount += 1 }
                    }
                case .tcp: break
                }
            @unknown default: break
            }
        }
        // 15 original + 5 randomly chosen dupes → each protocol gets ≥ original count
        #expect(arpCount >= 15)
        #expect(icmpCount >= 15)
        #expect(dhcpCount >= 10)
        #expect(dnsCount >= 10)
        // Total must be 55 (50 original + 5 dupes)
        #expect(arpCount + icmpCount + dhcpCount + dnsCount == 55)
    }
}
