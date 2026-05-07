import Testing
import Darwin
@testable import SwiftNetStack

@Suite(.serialized)
struct BDPRoundIntegrationTests {

    let hostMAC = MACAddress(0x00, 0x11, 0x22, 0x33, 0x44, 0x55)
    let subnet = IPv4Subnet(network: IPv4Address(100, 64, 1, 0), prefixLength: 24)
    let gateway = IPv4Address(100, 64, 1, 1)

    func makeEndpoint(id: Int = 1) -> VMEndpoint {
        VMEndpoint(id: id, fd: Int32(id + 100), subnet: subnet, gateway: gateway, mtu: 1500)
    }

    // MARK: - ARP proxy reply

    @Test func arpRequestForGatewayGeneratesProxyReply() {
        let ep = makeEndpoint()
        let clientMAC = MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF)
        let clientIP = IPv4Address(100, 64, 1, 50)

        // Build an ARP request asking for the gateway IP
        let arpFrame = makeEthernetFrame(
            dst: .broadcast,
            src: clientMAC,
            type: .arp,
            payload: makeARPPayload(op: .request, senderMAC: clientMAC, senderIP: clientIP, targetMAC: .zero, targetIP: gateway)
        )

        var transport: any Transport = InMemoryTransport(inputs: [(endpointID: 1, packet: arpFrame)])
        var arpMapping = ARPMapping(hostMAC: hostMAC, endpoints: [ep])
        var dhcpServer = DHCPServer(endpoints: [ep])
        let routingTable = RoutingTable()
        let round = RoundContext(); var registry = SocketRegistry(); var reasm = IPFragmentReassembler(); var natTable = NATTable(); var dnsServer = DNSServer(hosts: [:])

        bdpRound(transport: &transport, arpMapping: &arpMapping, dhcpServer: &dhcpServer, dnsServer: &dnsServer, routingTable: routingTable, socketRegistry: &registry, ipFragmentReassembler: &reasm, natTable: &natTable, round: round)

        #expect((transport as! InMemoryTransport).outputs.count == 1)
        guard (transport as! InMemoryTransport).outputs.count == 1 else { return }
        #expect((transport as! InMemoryTransport).outputs[0].endpointID == 1)

        // Verify the reply is a valid ARP reply
        let reply = (transport as! InMemoryTransport).outputs[0].packet
        guard let eth = EthernetFrame.parse(from: reply) else {
            Issue.record("reply is not valid Ethernet")
            return
        }
        #expect(eth.dstMAC == clientMAC)
        #expect(eth.srcMAC == hostMAC)
        #expect(eth.etherType == .arp)

        guard let arp = ARPFrame.parse(from: eth.payload) else {
            Issue.record("reply does not contain valid ARP")
            return
        }
        #expect(arp.operation == .reply)
        #expect(arp.senderMAC == hostMAC)
        #expect(arp.senderIP == gateway)
        #expect(arp.targetMAC == clientMAC)
        #expect(arp.targetIP == clientIP)
    }

    @Test func arpRequestForUnknownIPDoesNotGenerateReply() {
        let ep = makeEndpoint()
        let clientMAC = MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF)

        let arpFrame = makeEthernetFrame(
            dst: .broadcast,
            src: clientMAC,
            type: .arp,
            payload: makeARPPayload(op: .request, senderMAC: clientMAC, senderIP: IPv4Address(100, 64, 1, 50), targetMAC: .zero, targetIP: IPv4Address(100, 64, 1, 99))
        )

        var transport: any Transport = InMemoryTransport(inputs: [(endpointID: 1, packet: arpFrame)])
        var arpMapping = ARPMapping(hostMAC: hostMAC, endpoints: [ep])
        var dhcpServer = DHCPServer(endpoints: [ep])
        let round = RoundContext(); var registry = SocketRegistry(); var reasm = IPFragmentReassembler(); var natTable = NATTable(); var dnsServer = DNSServer(hosts: [:])

        bdpRound(transport: &transport, arpMapping: &arpMapping, dhcpServer: &dhcpServer, dnsServer: &dnsServer, routingTable: RoutingTable(), socketRegistry: &registry, ipFragmentReassembler: &reasm, natTable: &natTable, round: round)

        #expect((transport as! InMemoryTransport).outputs.isEmpty)
    }

    // MARK: - DHCP DISCOVER → OFFER

    @Test func dhcpDiscoverGeneratesOffer() {
        let ep = makeEndpoint()
        let clientMAC = MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF)

        // Build Ethernet/IPv4/UDP/DHCPDISCOVER
        let dhcpDiscover = makeDHCPPacketBytes(op: 1, xid: 42, chaddr: clientMAC, msgType: .discover)
        let frame = makeDHCPFrame(dstMAC: hostMAC, clientMAC:clientMAC, dhcpPayload: dhcpDiscover)

        var transport: any Transport = InMemoryTransport(inputs: [(endpointID: 1, packet: frame)])
        var arpMapping = ARPMapping(hostMAC: hostMAC, endpoints: [ep])
        var dhcpServer = DHCPServer(endpoints: [ep])
        let round = RoundContext(); var registry = SocketRegistry(); var reasm = IPFragmentReassembler(); var natTable = NATTable(); var dnsServer = DNSServer(hosts: [:])

        bdpRound(transport: &transport, arpMapping: &arpMapping, dhcpServer: &dhcpServer, dnsServer: &dnsServer, routingTable: RoutingTable(), socketRegistry: &registry, ipFragmentReassembler: &reasm, natTable: &natTable, round: round)

        #expect((transport as! InMemoryTransport).outputs.count == 1)
        guard (transport as! InMemoryTransport).outputs.count == 1 else { return }

        let reply = (transport as! InMemoryTransport).outputs[0].packet
        guard let dhcp = extractDHCPFromReply(reply) else {
            Issue.record("failed to parse DHCP OFFER from wrapped reply")
            return
        }
        #expect(dhcp.messageType == .offer)
        #expect(dhcp.xid == 42)
    }

    // MARK: - DHCP REQUEST → ACK

    @Test func dhcpRequestGeneratesAck() {
        let ep = makeEndpoint()
        let clientMAC = MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF)
        let requestedIP = IPv4Address(100, 64, 1, 50)

        let dhcpRequest = makeDHCPPacketBytes(op: 1, xid: 99, chaddr: clientMAC, msgType: .request, extraOptions: [
            (50, ipBytes(requestedIP)),
            (54, ipBytes(gateway)),
        ])
        let frame = makeDHCPFrame(dstMAC: hostMAC, clientMAC:clientMAC, dhcpPayload: dhcpRequest)

        var transport: any Transport = InMemoryTransport(inputs: [(endpointID: 1, packet: frame)])
        var arpMapping = ARPMapping(hostMAC: hostMAC, endpoints: [ep])
        var dhcpServer = DHCPServer(endpoints: [ep])
        let round = RoundContext(); var registry = SocketRegistry(); var reasm = IPFragmentReassembler(); var natTable = NATTable(); var dnsServer = DNSServer(hosts: [:])

        bdpRound(transport: &transport, arpMapping: &arpMapping, dhcpServer: &dhcpServer, dnsServer: &dnsServer, routingTable: RoutingTable(), socketRegistry: &registry, ipFragmentReassembler: &reasm, natTable: &natTable, round: round)

        #expect((transport as! InMemoryTransport).outputs.count == 1)
        guard (transport as! InMemoryTransport).outputs.count == 1 else { return }

        let reply = (transport as! InMemoryTransport).outputs[0].packet
        guard let dhcp = extractDHCPFromReply(reply) else {
            Issue.record("failed to parse DHCP ACK from wrapped reply")
            return
        }
        #expect(dhcp.messageType == .ack)
        #expect(dhcp.xid == 99)
    }

    // MARK: - DHCP updates ARPMapping

    @Test func dhcpRequestUpdatesARPMapping() {
        let ep = makeEndpoint()
        let clientMAC = MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF)
        let requestedIP = IPv4Address(100, 64, 1, 50)

        let dhcpRequest = makeDHCPPacketBytes(op: 1, xid: 1, chaddr: clientMAC, msgType: .request, extraOptions: [
            (50, ipBytes(requestedIP)),
            (54, ipBytes(gateway)),
        ])
        let frame = makeDHCPFrame(dstMAC: hostMAC, clientMAC:clientMAC, dhcpPayload: dhcpRequest)

        var transport: any Transport = InMemoryTransport(inputs: [(endpointID: 1, packet: frame)])
        var arpMapping = ARPMapping(hostMAC: hostMAC, endpoints: [ep])
        var dhcpServer = DHCPServer(endpoints: [ep])
        let round = RoundContext(); var registry = SocketRegistry(); var reasm = IPFragmentReassembler(); var natTable = NATTable(); var dnsServer = DNSServer(hosts: [:])

        #expect(!arpMapping.isKnown(requestedIP))
        bdpRound(transport: &transport, arpMapping: &arpMapping, dhcpServer: &dhcpServer, dnsServer: &dnsServer, routingTable: RoutingTable(), socketRegistry: &registry, ipFragmentReassembler: &reasm, natTable: &natTable, round: round)

        #expect(arpMapping.isKnown(requestedIP))
        #expect(arpMapping.lookup(ip: requestedIP) == clientMAC)
    }

    // MARK: - Cross-round state

    @Test func crossRoundStateLeasePersists() {
        let ep = makeEndpoint()
        let clientMAC = MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF)
        let requestedIP = IPv4Address(100, 64, 1, 50)

        var arpMapping = ARPMapping(hostMAC: hostMAC, endpoints: [ep])
        var dhcpServer = DHCPServer(endpoints: [ep])
        var registry = SocketRegistry()
        var reasm = IPFragmentReassembler()
        var natTable = NATTable(); var dnsServer = DNSServer(hosts: [:])

        // Round 1: REQUEST (allocate lease)
        let requestFrame = makeDHCPFrame(dstMAC: hostMAC, clientMAC:clientMAC, dhcpPayload: makeDHCPPacketBytes(op: 1, xid: 1, chaddr: clientMAC, msgType: .request, extraOptions: [
            (50, ipBytes(requestedIP)),
            (54, ipBytes(gateway)),
        ]))
        var transport1: any Transport = InMemoryTransport(inputs: [(endpointID: 1, packet: requestFrame)])
        let round1 = RoundContext()
        bdpRound(transport: &transport1, arpMapping: &arpMapping, dhcpServer: &dhcpServer, dnsServer: &dnsServer, routingTable: RoutingTable(), socketRegistry: &registry, ipFragmentReassembler: &reasm, natTable: &natTable, round: round1)

        #expect(arpMapping.isKnown(requestedIP))

        // Round 2: RELEASE
        let releaseFrame = makeDHCPFrame(dstMAC: hostMAC, clientMAC:clientMAC, dhcpPayload: makeDHCPPacketBytes(op: 1, xid: 2, chaddr: clientMAC, msgType: .release))
        var transport2: any Transport = InMemoryTransport(inputs: [(endpointID: 1, packet: releaseFrame)])
        let round2 = RoundContext()
        bdpRound(transport: &transport2, arpMapping: &arpMapping, dhcpServer: &dhcpServer, dnsServer: &dnsServer, routingTable: RoutingTable(), socketRegistry: &registry, ipFragmentReassembler: &reasm, natTable: &natTable, round: round2)

        #expect(!arpMapping.isKnown(requestedIP))

        // Round 3: DISCOVER should succeed (IP was reclaimed)
        let discoverFrame = makeDHCPFrame(dstMAC: hostMAC, clientMAC:MACAddress(0xBA, 0xCC, 0xDD, 0xEE, 0xFF, 0x00), dhcpPayload: makeDHCPPacketBytes(op: 1, xid: 3, chaddr: MACAddress(0xBA, 0xCC, 0xDD, 0xEE, 0xFF, 0x00), msgType: .discover))
        var transport3: any Transport = InMemoryTransport(inputs: [(endpointID: 1, packet: discoverFrame)])
        let round3 = RoundContext()
        bdpRound(transport: &transport3, arpMapping: &arpMapping, dhcpServer: &dhcpServer, dnsServer: &dnsServer, routingTable: RoutingTable(), socketRegistry: &registry, ipFragmentReassembler: &reasm, natTable: &natTable, round: round3)

        #expect(!(transport3 as! InMemoryTransport).outputs.isEmpty)
    }

    // MARK: - Mixed traffic

    @Test func mixedARPAndDHCPTraffic() {
        let ep = makeEndpoint()
        let clientMAC = MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF)
        let clientIP = IPv4Address(100, 64, 1, 50)

        // Frame 1: ARP request for gateway
        let arpFrame = makeEthernetFrame(
            dst: .broadcast,
            src: clientMAC,
            type: .arp,
            payload: makeARPPayload(op: .request, senderMAC: clientMAC, senderIP: clientIP, targetMAC: .zero, targetIP: gateway)
        )

        // Frame 2: DHCP DISCOVER
        let dhcpFrame = makeDHCPFrame(dstMAC: hostMAC, clientMAC:clientMAC, dhcpPayload: makeDHCPPacketBytes(op: 1, xid: 77, chaddr: clientMAC, msgType: .discover))

        var transport: any Transport = InMemoryTransport(inputs: [
            (endpointID: 1, packet: arpFrame),
            (endpointID: 1, packet: dhcpFrame),
        ])
        var arpMapping = ARPMapping(hostMAC: hostMAC, endpoints: [ep])
        var dhcpServer = DHCPServer(endpoints: [ep])
        let round = RoundContext(); var registry = SocketRegistry(); var reasm = IPFragmentReassembler(); var natTable = NATTable(); var dnsServer = DNSServer(hosts: [:])

        bdpRound(transport: &transport, arpMapping: &arpMapping, dhcpServer: &dhcpServer, dnsServer: &dnsServer, routingTable: RoutingTable(), socketRegistry: &registry, ipFragmentReassembler: &reasm, natTable: &natTable, round: round)

        // Should get 2 replies: ARP reply + DHCP OFFER
        #expect((transport as! InMemoryTransport).outputs.count == 2)
    }

    // MARK: - ICMP Echo Reply

    @Test func icmpEchoRequestGeneratesReply() {
        let ep = makeEndpoint()
        let clientMAC = MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF)
        let clientIP = IPv4Address(100, 64, 1, 50)

        let frame = makeICMPEchoFrame(dstMAC: hostMAC, clientMAC:clientMAC, clientIP: clientIP, dstIP: gateway, id: 0x1234, seq: 0x0001)

        var transport: any Transport = InMemoryTransport(inputs: [(endpointID: 1, packet: frame)])
        var arpMapping = ARPMapping(hostMAC: hostMAC, endpoints: [ep])
        var dhcpServer = DHCPServer(endpoints: [ep])
        let round = RoundContext(); var registry = SocketRegistry(); var reasm = IPFragmentReassembler(); var natTable = NATTable(); var dnsServer = DNSServer(hosts: [:])

        bdpRound(transport: &transport, arpMapping: &arpMapping, dhcpServer: &dhcpServer, dnsServer: &dnsServer, routingTable: RoutingTable(), socketRegistry: &registry, ipFragmentReassembler: &reasm, natTable: &natTable, round: round)

        #expect((transport as! InMemoryTransport).outputs.count == 1)
        guard (transport as! InMemoryTransport).outputs.count == 1 else { return }
        #expect((transport as! InMemoryTransport).outputs[0].endpointID == 1)

        let reply = (transport as! InMemoryTransport).outputs[0].packet
        guard let eth = EthernetFrame.parse(from: reply) else {
            Issue.record("reply is not valid Ethernet")
            return
        }
        #expect(eth.dstMAC == clientMAC)
        #expect(eth.srcMAC == hostMAC)
        #expect(eth.etherType == .ipv4)

        guard let ip = IPv4Header.parse(from: eth.payload) else {
            Issue.record("reply does not contain valid IPv4")
            return
        }
        #expect(ip.srcAddr == gateway)
        #expect(ip.dstAddr == clientIP)
        #expect(ip.protocol == .icmp)
        #expect(ip.verifyChecksum())

        guard let icmp = ICMPHeader.parse(from: ip.payload) else {
            Issue.record("reply does not contain valid ICMP")
            return
        }
        #expect(icmp.type == 0)
        #expect(icmp.code == 0)
        #expect(icmp.identifier == 0x1234)
        #expect(icmp.sequenceNumber == 0x0001)
    }

    // MARK: - Audit issue #5: DHCP reply missing UDP checksum

    /// AUDIT #5 REPRODUCTION: `buildDHCPFrame` constructs the UDP header for DHCP
    /// replies with checksum=0 (left as zero by `initializeMemory`). While RFC 768
    /// permits zero checksum for IPv4 UDP, this is not best practice — strict
    /// clients may reject it. Compare `buildUDPFrame` which correctly computes
    /// the UDP pseudo-header checksum.
    ///
    /// EXPECTED: DHCP reply UDP checksum is non-zero and valid
    /// ACTUAL:   checksum is 0 (BUG / suboptimal)
    @Test func dhcpReplyHasValidUDPChecksum() {
        let ep = makeEndpoint()
        let clientMAC = MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF)

        let dhcpDiscover = makeDHCPPacketBytes(op: 1, xid: 42, chaddr: clientMAC, msgType: .discover)
        let frame = makeDHCPFrame(dstMAC: hostMAC, clientMAC:clientMAC, dhcpPayload: dhcpDiscover)

        var transport: any Transport = InMemoryTransport(inputs: [(endpointID: 1, packet: frame)])
        var arpMapping = ARPMapping(hostMAC: hostMAC, endpoints: [ep])
        var dhcpServer = DHCPServer(endpoints: [ep])
        let round = RoundContext(); var registry = SocketRegistry(); var reasm = IPFragmentReassembler(); var natTable = NATTable(); var dnsServer = DNSServer(hosts: [:])

        bdpRound(transport: &transport, arpMapping: &arpMapping, dhcpServer: &dhcpServer, dnsServer: &dnsServer,
                 routingTable: RoutingTable(), socketRegistry: &registry,
                 ipFragmentReassembler: &reasm, natTable: &natTable, round: round)

        #expect((transport as! InMemoryTransport).outputs.count == 1)
        guard (transport as! InMemoryTransport).outputs.count == 1 else { return }

        let reply = (transport as! InMemoryTransport).outputs[0].packet
        guard let eth = EthernetFrame.parse(from: reply),
              eth.etherType == .ipv4,
              let ip = IPv4Header.parse(from: eth.payload),
              ip.protocol == .udp else {
            Issue.record("failed to parse DHCP reply wrapper")
            return
        }

        // Parse UDP header with pseudo-addresses to verify checksum
        guard let udp = UDPHeader.parse(
            from: ip.payload,
            pseudoSrcAddr: ip.srcAddr,
            pseudoDstAddr: ip.dstAddr
        ) else {
            Issue.record("failed to parse UDP header from DHCP reply")
            return
        }

        #expect(udp.srcPort == 67, "DHCP server port should be 67")
        #expect(udp.dstPort == 68, "DHCP client port should be 68")

        // RFC 768 allows checksum=0 for IPv4 UDP, but it's not best practice.
        // buildUDPFrame computes a real checksum; buildDHCPFrame should too.
        #expect(udp.checksum != 0,
            "AUDIT #5 FAIL: DHCP reply UDP checksum is 0 (unused); should compute real checksum")
        #expect(udp.verifyChecksum(),
            "AUDIT #5 FAIL: DHCP reply UDP checksum missing")
    }

    // MARK: - L2 forwarding

    @Test func unicastToKnownVMIsForwarded() {
        let ep1 = VMEndpoint(id: 1, fd: 101, subnet: subnet, gateway: gateway)
        let ep2 = VMEndpoint(id: 2, fd: 102, subnet: subnet, gateway: gateway)
        let mac1 = MACAddress(0xAA, 0x00, 0x00, 0x00, 0x00, 0x01)
        let mac2 = MACAddress(0xAA, 0x00, 0x00, 0x00, 0x00, 0x02)
        let ip1 = IPv4Address(100, 64, 1, 50)
        let ip2 = IPv4Address(100, 64, 1, 51)

        // Pre-populate ARP mapping: VM B's IP→MAC on endpoint 2
        var arpMapping = ARPMapping(hostMAC: hostMAC, endpoints: [ep1, ep2])
        arpMapping.add(ip: ip2, mac: mac2, endpointID: 2)

        // VM A sends ICMP echo to VM B's MAC (not hostMAC)
        let frame = makeICMPEchoFrame(dstMAC: hostMAC, clientMAC:mac1, clientIP: ip1, dstIP: ip2, id: 1, seq: 1)
        let l2Frame = makeEthernetFrame(
            dst: mac2, src: mac1, type: .ipv4,
            payload: extractEtherPayload(frame)
        )

        var transport: any Transport = InMemoryTransport(inputs: [(endpointID: 1, packet: l2Frame)])
        var dhcpServer = DHCPServer(endpoints: [ep1, ep2])
        let round = RoundContext(); var registry = SocketRegistry(); var reasm = IPFragmentReassembler(); var natTable = NATTable(); var dnsServer = DNSServer(hosts: [:])

        bdpRound(transport: &transport, arpMapping: &arpMapping, dhcpServer: &dhcpServer, dnsServer: &dnsServer, routingTable: RoutingTable(), socketRegistry: &registry, ipFragmentReassembler: &reasm, natTable: &natTable, round: round)

        let outputs = (transport as! InMemoryTransport).outputs
        #expect(outputs.count == 1)
        guard outputs.count == 1 else { return }
        #expect(outputs[0].endpointID == 2, "frame should be forwarded to VM B's endpoint")

        // The forwarded frame should be the original frame unchanged
        guard let eth = EthernetFrame.parse(from: outputs[0].packet) else {
            Issue.record("forwarded frame is not valid Ethernet")
            return
        }
        #expect(eth.dstMAC == mac2)
        #expect(eth.srcMAC == mac1)
    }

    @Test func unicastToUnknownMACIsDropped() {
        let ep1 = makeEndpoint(id: 1)
        let unknownMAC = MACAddress(0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00)
        let clientMAC = MACAddress(0xAA, 0x00, 0x00, 0x00, 0x00, 0x01)
        let clientIP = IPv4Address(100, 64, 1, 50)

        let frame = makeICMPEchoFrame(dstMAC: hostMAC, clientMAC:clientMAC, clientIP: clientIP, dstIP: gateway, id: 1, seq: 1)
        let l2Frame = makeEthernetFrame(
            dst: unknownMAC, src: clientMAC, type: .ipv4,
            payload: extractEtherPayload(frame)
        )

        var transport: any Transport = InMemoryTransport(inputs: [(endpointID: 1, packet: l2Frame)])
        var arpMapping = ARPMapping(hostMAC: hostMAC, endpoints: [ep1])
        var dhcpServer = DHCPServer(endpoints: [ep1])
        let round = RoundContext(); var registry = SocketRegistry(); var reasm = IPFragmentReassembler(); var natTable = NATTable(); var dnsServer = DNSServer(hosts: [:])

        bdpRound(transport: &transport, arpMapping: &arpMapping, dhcpServer: &dhcpServer, dnsServer: &dnsServer, routingTable: RoutingTable(), socketRegistry: &registry, ipFragmentReassembler: &reasm, natTable: &natTable, round: round)

        #expect((transport as! InMemoryTransport).outputs.isEmpty)
    }

    @Test func arpForPeerVMGeneratesProxyReply() {
        let ep1 = VMEndpoint(id: 1, fd: 101, subnet: subnet, gateway: gateway)
        let ep2 = VMEndpoint(id: 2, fd: 102, subnet: subnet, gateway: gateway)
        let mac1 = MACAddress(0xAA, 0x00, 0x00, 0x00, 0x00, 0x01)
        let mac2 = MACAddress(0xAA, 0x00, 0x00, 0x00, 0x00, 0x02)
        let ip2 = IPv4Address(100, 64, 1, 51)

        // Pre-populate: VM B's MAC is known
        var arpMapping = ARPMapping(hostMAC: hostMAC, endpoints: [ep1, ep2])
        arpMapping.add(ip: ip2, mac: mac2, endpointID: 2)

        // VM A ARPs for VM B's IP
        let arpFrame = makeEthernetFrame(
            dst: .broadcast, src: mac1, type: .arp,
            payload: makeARPPayload(op: .request, senderMAC: mac1, senderIP: IPv4Address(100, 64, 1, 50), targetMAC: .zero, targetIP: ip2)
        )

        var transport: any Transport = InMemoryTransport(inputs: [(endpointID: 1, packet: arpFrame)])
        var dhcpServer = DHCPServer(endpoints: [ep1, ep2])
        let round = RoundContext(); var registry = SocketRegistry(); var reasm = IPFragmentReassembler(); var natTable = NATTable(); var dnsServer = DNSServer(hosts: [:])

        bdpRound(transport: &transport, arpMapping: &arpMapping, dhcpServer: &dhcpServer, dnsServer: &dnsServer, routingTable: RoutingTable(), socketRegistry: &registry, ipFragmentReassembler: &reasm, natTable: &natTable, round: round)

        #expect((transport as! InMemoryTransport).outputs.count == 1)
        guard (transport as! InMemoryTransport).outputs.count == 1 else { return }

        let reply = (transport as! InMemoryTransport).outputs[0].packet
        guard let eth = EthernetFrame.parse(from: reply),
              let arp = ARPFrame.parse(from: eth.payload) else {
            Issue.record("reply is not valid ARP")
            return
        }
        #expect(arp.operation == .reply)
        #expect(arp.senderMAC == hostMAC)
        #expect(arp.senderIP == ip2)
        #expect(arp.targetMAC == mac1)
    }

    @Test func mixedForwardAndLocalTraffic() {
        let ep1 = VMEndpoint(id: 1, fd: 101, subnet: subnet, gateway: gateway)
        let ep2 = VMEndpoint(id: 2, fd: 102, subnet: subnet, gateway: gateway)
        let mac1 = MACAddress(0xAA, 0x00, 0x00, 0x00, 0x00, 0x01)
        let mac2 = MACAddress(0xAA, 0x00, 0x00, 0x00, 0x00, 0x02)
        let ip1 = IPv4Address(100, 64, 1, 50)
        let ip2 = IPv4Address(100, 64, 1, 51)

        // Pre-populate ARP: VM B known
        var arpMapping = ARPMapping(hostMAC: hostMAC, endpoints: [ep1, ep2])
        arpMapping.add(ip: ip2, mac: mac2, endpointID: 2)

        // Frame 1: VM A → hostMAC (ICMP echo, local processing)
        let localFrame = makeICMPEchoFrame(dstMAC: hostMAC, clientMAC:mac1, clientIP: ip1, dstIP: gateway, id: 1, seq: 1)

        // Frame 2: VM A → VM B MAC (forwarded)
        let forwardContent = makeICMPEchoFrame(dstMAC: hostMAC, clientMAC:mac1, clientIP: ip1, dstIP: ip2, id: 2, seq: 1)
        let forwardFrame = makeEthernetFrame(
            dst: mac2, src: mac1, type: .ipv4,
            payload: extractEtherPayload(forwardContent)
        )

        var transport: any Transport = InMemoryTransport(inputs: [
            (endpointID: 1, packet: localFrame),
            (endpointID: 1, packet: forwardFrame),
        ])
        var dhcpServer = DHCPServer(endpoints: [ep1, ep2])
        let round = RoundContext(); var registry = SocketRegistry(); var reasm = IPFragmentReassembler(); var natTable = NATTable(); var dnsServer = DNSServer(hosts: [:])

        bdpRound(transport: &transport, arpMapping: &arpMapping, dhcpServer: &dhcpServer, dnsServer: &dnsServer, routingTable: RoutingTable(), socketRegistry: &registry, ipFragmentReassembler: &reasm, natTable: &natTable, round: round)

        let outputs = (transport as! InMemoryTransport).outputs
        #expect(outputs.count == 2)

        var forwardedCount = 0, localCount = 0
        for out in outputs {
            if out.endpointID == 2 { forwardedCount += 1 }
            if out.endpointID == 1 { localCount += 1 }
        }
        #expect(forwardedCount == 1, "one frame should be forwarded to ep2")
        #expect(localCount == 1, "one frame should generate local reply on ep1")
    }

    // MARK: - Empty input

    @Test func emptyInputRoundReturnsFast() {
        var transport: any Transport = InMemoryTransport()
        var arpMapping = ARPMapping(hostMAC: hostMAC, endpoints: [makeEndpoint()])
        var dhcpServer = DHCPServer(endpoints: [makeEndpoint()])
        let round = RoundContext(); var registry = SocketRegistry(); var reasm = IPFragmentReassembler(); var natTable = NATTable(); var dnsServer = DNSServer(hosts: [:])

        bdpRound(transport: &transport, arpMapping: &arpMapping, dhcpServer: &dhcpServer, dnsServer: &dnsServer, routingTable: RoutingTable(), socketRegistry: &registry, ipFragmentReassembler: &reasm, natTable: &natTable, round: round)

        #expect((transport as! InMemoryTransport).outputs.isEmpty)
    }

    // MARK: - UDP echo

    @Test func udpEchoRequestGeneratesReply() {
        let ep = makeEndpoint()
        let clientMAC = MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF)
        let clientIP = IPv4Address(100, 64, 1, 50)

        let payload: [UInt8] = [0x70, 0x69, 0x6E, 0x67]
        let frame = makeUDPFrame(
            dstMAC: hostMAC, clientMAC: clientMAC,
            srcIP: clientIP, dstIP: gateway,
            srcPort: 1234, dstPort: 7,
            payload: payload
        )

        var transport: any Transport = InMemoryTransport(inputs: [(endpointID: 1, packet: frame)])
        var arpMapping = ARPMapping(hostMAC: hostMAC, endpoints: [ep])
        var dhcpServer = DHCPServer(endpoints: [ep])
        let round = RoundContext(); var registry = SocketRegistry(); var reasm = IPFragmentReassembler(); var natTable = NATTable(); var dnsServer = DNSServer(hosts: [:])
        registry.register(port: 7, handler: UDPEchoSocket())

        bdpRound(transport: &transport, arpMapping: &arpMapping, dhcpServer: &dhcpServer, dnsServer: &dnsServer, routingTable: RoutingTable(), socketRegistry: &registry, ipFragmentReassembler: &reasm, natTable: &natTable, round: round)

        #expect((transport as! InMemoryTransport).outputs.count == 1)
        guard (transport as! InMemoryTransport).outputs.count == 1 else { return }
        #expect((transport as! InMemoryTransport).outputs[0].endpointID == 1)

        let reply = (transport as! InMemoryTransport).outputs[0].packet
        guard let eth = EthernetFrame.parse(from: reply),
              let ip = IPv4Header.parse(from: eth.payload),
              let udp = UDPHeader.parse(from: ip.payload, pseudoSrcAddr: ip.srcAddr, pseudoDstAddr: ip.dstAddr) else {
            Issue.record("failed to parse UDP echo reply")
            return
        }
        #expect(eth.dstMAC == clientMAC)
        #expect(eth.srcMAC == hostMAC)
        #expect(ip.srcAddr == gateway)
        #expect(ip.dstAddr == clientIP)
        #expect(udp.srcPort == 7)
        #expect(udp.dstPort == 1234)
        #expect(udp.verifyChecksum())
        udp.payload.withUnsafeReadableBytes { buf in
            #expect([UInt8](buf) == payload)
        }
    }

    @Test func udpEchoPayloadPreserved() {
        let ep = makeEndpoint()
        let clientMAC = MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF)
        let clientIP = IPv4Address(100, 64, 1, 50)

        let payload: [UInt8] = Array(0..<255)
        let frame = makeUDPFrame(
            dstMAC: hostMAC, clientMAC: clientMAC,
            srcIP: clientIP, dstIP: gateway,
            srcPort: 9999, dstPort: 7,
            payload: payload
        )

        var transport: any Transport = InMemoryTransport(inputs: [(endpointID: 1, packet: frame)])
        var arpMapping = ARPMapping(hostMAC: hostMAC, endpoints: [ep])
        var dhcpServer = DHCPServer(endpoints: [ep])
        let round = RoundContext(); var registry = SocketRegistry(); var reasm = IPFragmentReassembler(); var natTable = NATTable(); var dnsServer = DNSServer(hosts: [:])
        registry.register(port: 7, handler: UDPEchoSocket())

        bdpRound(transport: &transport, arpMapping: &arpMapping, dhcpServer: &dhcpServer, dnsServer: &dnsServer, routingTable: RoutingTable(), socketRegistry: &registry, ipFragmentReassembler: &reasm, natTable: &natTable, round: round)

        guard (transport as! InMemoryTransport).outputs.count == 1,
              let eth = EthernetFrame.parse(from: (transport as! InMemoryTransport).outputs[0].packet),
              let ip = IPv4Header.parse(from: eth.payload),
              let udp = UDPHeader.parse(from: ip.payload, pseudoSrcAddr: ip.srcAddr, pseudoDstAddr: ip.dstAddr) else {
            Issue.record("failed to parse UDP echo reply")
            return
        }
        #expect(udp.payload.totalLength == 255)
        udp.payload.withUnsafeReadableBytes { buf in
            #expect([UInt8](buf) == payload)
        }
    }

    @Test func udpNonRegisteredPortIgnored() {
        let ep = makeEndpoint()
        let clientMAC = MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF)
        let clientIP = IPv4Address(100, 64, 1, 50)

        // Send to port 53 (no socket registered)
        let frame = makeUDPFrame(
            dstMAC: hostMAC, clientMAC: clientMAC,
            srcIP: clientIP, dstIP: gateway,
            srcPort: 1234, dstPort: 53,
            payload: [0xAA, 0xBB]
        )

        var transport: any Transport = InMemoryTransport(inputs: [(endpointID: 1, packet: frame)])
        var arpMapping = ARPMapping(hostMAC: hostMAC, endpoints: [ep])
        var dhcpServer = DHCPServer(endpoints: [ep])
        let round = RoundContext(); var registry = SocketRegistry(); var reasm = IPFragmentReassembler(); var natTable = NATTable(); var dnsServer = DNSServer(hosts: [:])
        // Register echo on port 7 only — port 53 has no socket
        registry.register(port: 7, handler: UDPEchoSocket())

        bdpRound(transport: &transport, arpMapping: &arpMapping, dhcpServer: &dhcpServer, dnsServer: &dnsServer, routingTable: RoutingTable(), socketRegistry: &registry, ipFragmentReassembler: &reasm, natTable: &natTable, round: round)

        #expect((transport as! InMemoryTransport).outputs.isEmpty)
    }

    @Test func mixedUDPAndICMPTraffic() {
        let ep = makeEndpoint()
        let clientMAC = MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF)
        let clientIP = IPv4Address(100, 64, 1, 50)

        // Frame 1: ICMP echo request
        let icmpFrame = makeICMPEchoFrame(dstMAC: hostMAC, clientMAC:clientMAC, clientIP: clientIP, dstIP: gateway, id: 0x42, seq: 0x01)

        // Frame 2: UDP echo request to port 7
        let udpFrame = makeUDPFrame(
            dstMAC: hostMAC, clientMAC: clientMAC,
            srcIP: clientIP, dstIP: gateway,
            srcPort: 5555, dstPort: 7,
            payload: [0x48, 0x65, 0x6C, 0x6C, 0x6F]
        )

        var transport: any Transport = InMemoryTransport(inputs: [
            (endpointID: 1, packet: icmpFrame),
            (endpointID: 1, packet: udpFrame),
        ])
        var arpMapping = ARPMapping(hostMAC: hostMAC, endpoints: [ep])
        var dhcpServer = DHCPServer(endpoints: [ep])
        let round = RoundContext(); var registry = SocketRegistry(); var reasm = IPFragmentReassembler(); var natTable = NATTable(); var dnsServer = DNSServer(hosts: [:])
        registry.register(port: 7, handler: UDPEchoSocket())

        bdpRound(transport: &transport, arpMapping: &arpMapping, dhcpServer: &dhcpServer, dnsServer: &dnsServer, routingTable: RoutingTable(), socketRegistry: &registry, ipFragmentReassembler: &reasm, natTable: &natTable, round: round)

        let outputs = (transport as! InMemoryTransport).outputs
        #expect(outputs.count == 2)

        var icmpReplies = 0, udpReplies = 0
        for out in outputs {
            guard let eth = EthernetFrame.parse(from: out.packet),
                  let ip = IPv4Header.parse(from: eth.payload) else { continue }
            if ip.protocol == .icmp { icmpReplies += 1 }
            if ip.protocol == .udp { udpReplies += 1 }
        }
        #expect(icmpReplies == 1, "expected 1 ICMP reply")
        #expect(udpReplies == 1, "expected 1 UDP reply")
    }

    // MARK: - TCP is now handled by the NAT stack

    /// With TCP+NAT support, a TCP SYN no longer generates ICMP Protocol Unreachable.
    /// The FSM processes the SYN and replies with SYN+ACK (the TCP handshake).
    /// If the connect to the external host fails immediately (e.g., ENETUNREACH),
    /// no reply is generated — but TCP is never silently dropped.
    @Test func tcpSYNReceivesTCPResponse() {
        let ep = makeEndpoint()
        let clientMAC = MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF)
        let clientIP = IPv4Address(100, 64, 1, 50)

        let frame = makeTCPSYNFrame(
            dstMAC: hostMAC, clientMAC: clientMAC,
            srcIP: clientIP, dstIP: gateway,
            srcPort: 12345, dstPort: 80
        )

        var transport: any Transport = InMemoryTransport(inputs: [(endpointID: 1, packet: frame)])
        var arpMapping = ARPMapping(hostMAC: hostMAC, endpoints: [ep])
        var dhcpServer = DHCPServer(endpoints: [ep])
        let round = RoundContext(); var registry = SocketRegistry(); var reasm = IPFragmentReassembler(); var natTable = NATTable(); var dnsServer = DNSServer(hosts: [:])

        bdpRound(transport: &transport, arpMapping: &arpMapping, dhcpServer: &dhcpServer, dnsServer: &dnsServer,
                 routingTable: RoutingTable(), socketRegistry: &registry,
                 ipFragmentReassembler: &reasm, natTable: &natTable, round: round)

        let outputs = (transport as! InMemoryTransport).outputs

        // TCP SYN should generate a TCP response (SYN+ACK), not ICMP unreachable.
        // If the connect syscall fails immediately, 0 replies is also acceptable
        // — the key invariant is that TCP is never silently dropped.
        for out in outputs {
            guard let eth = EthernetFrame.parse(from: out.packet),
                  let ip = IPv4Header.parse(from: eth.payload) else {
                Issue.record("reply is not valid Ethernet+IPv4")
                continue
            }
            #expect(ip.protocol == .tcp,
                "TCP SYN must receive TCP replies, not ICMP unreachable. Got protocol \(ip.protocol.rawValue)")

            if ip.protocol == .tcp, let tcp = TCPHeader.parse(
                from: ip.payload,
                pseudoSrcAddr: ip.srcAddr,
                pseudoDstAddr: ip.dstAddr
            ) {
                #expect(tcp.flags.isSyn && tcp.flags.isAck,
                    "expected SYN+ACK in response to SYN, got flags=\(tcp.flags.rawValue)")
                #expect(ip.dstAddr == clientIP)
                #expect(ip.srcAddr == gateway)
            }
        }
    }
}
