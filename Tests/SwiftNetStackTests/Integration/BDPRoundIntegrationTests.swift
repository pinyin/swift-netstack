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
        let round = RoundContext(); var udpTable = UDPSocketTable(); var reasm = IPFragmentReassembler()

        bdpRound(transport: &transport, arpMapping: &arpMapping, dhcpServer: &dhcpServer, routingTable: routingTable, udpSocketTable: &udpTable, ipFragmentReassembler: &reasm, round: round)

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
        let round = RoundContext(); var udpTable = UDPSocketTable(); var reasm = IPFragmentReassembler()

        bdpRound(transport: &transport, arpMapping: &arpMapping, dhcpServer: &dhcpServer, routingTable: RoutingTable(), udpSocketTable: &udpTable, ipFragmentReassembler: &reasm, round: round)

        #expect((transport as! InMemoryTransport).outputs.isEmpty)
    }

    // MARK: - DHCP DISCOVER → OFFER

    @Test func dhcpDiscoverGeneratesOffer() {
        let ep = makeEndpoint()
        let clientMAC = MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF)

        // Build Ethernet/IPv4/UDP/DHCPDISCOVER
        let dhcpDiscover = makeDHCPPacketBytes(op: 1, xid: 42, chaddr: clientMAC, msgType: .discover)
        let frame = makeDHCPFrame(clientMAC: clientMAC, dhcpPayload: dhcpDiscover)

        var transport: any Transport = InMemoryTransport(inputs: [(endpointID: 1, packet: frame)])
        var arpMapping = ARPMapping(hostMAC: hostMAC, endpoints: [ep])
        var dhcpServer = DHCPServer(endpoints: [ep])
        let round = RoundContext(); var udpTable = UDPSocketTable(); var reasm = IPFragmentReassembler()

        bdpRound(transport: &transport, arpMapping: &arpMapping, dhcpServer: &dhcpServer, routingTable: RoutingTable(), udpSocketTable: &udpTable, ipFragmentReassembler: &reasm, round: round)

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
        let frame = makeDHCPFrame(clientMAC: clientMAC, dhcpPayload: dhcpRequest)

        var transport: any Transport = InMemoryTransport(inputs: [(endpointID: 1, packet: frame)])
        var arpMapping = ARPMapping(hostMAC: hostMAC, endpoints: [ep])
        var dhcpServer = DHCPServer(endpoints: [ep])
        let round = RoundContext(); var udpTable = UDPSocketTable(); var reasm = IPFragmentReassembler()

        bdpRound(transport: &transport, arpMapping: &arpMapping, dhcpServer: &dhcpServer, routingTable: RoutingTable(), udpSocketTable: &udpTable, ipFragmentReassembler: &reasm, round: round)

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
        let frame = makeDHCPFrame(clientMAC: clientMAC, dhcpPayload: dhcpRequest)

        var transport: any Transport = InMemoryTransport(inputs: [(endpointID: 1, packet: frame)])
        var arpMapping = ARPMapping(hostMAC: hostMAC, endpoints: [ep])
        var dhcpServer = DHCPServer(endpoints: [ep])
        let round = RoundContext(); var udpTable = UDPSocketTable(); var reasm = IPFragmentReassembler()

        #expect(!arpMapping.isKnown(requestedIP))
        bdpRound(transport: &transport, arpMapping: &arpMapping, dhcpServer: &dhcpServer, routingTable: RoutingTable(), udpSocketTable: &udpTable, ipFragmentReassembler: &reasm, round: round)

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
        var udpTable = UDPSocketTable()
        var reasm = IPFragmentReassembler()

        // Round 1: REQUEST (allocate lease)
        let requestFrame = makeDHCPFrame(clientMAC: clientMAC, dhcpPayload: makeDHCPPacketBytes(op: 1, xid: 1, chaddr: clientMAC, msgType: .request, extraOptions: [
            (50, ipBytes(requestedIP)),
            (54, ipBytes(gateway)),
        ]))
        var transport1: any Transport = InMemoryTransport(inputs: [(endpointID: 1, packet: requestFrame)])
        let round1 = RoundContext()
        bdpRound(transport: &transport1, arpMapping: &arpMapping, dhcpServer: &dhcpServer, routingTable: RoutingTable(), udpSocketTable: &udpTable, ipFragmentReassembler: &reasm, round: round1)

        #expect(arpMapping.isKnown(requestedIP))

        // Round 2: RELEASE
        let releaseFrame = makeDHCPFrame(clientMAC: clientMAC, dhcpPayload: makeDHCPPacketBytes(op: 1, xid: 2, chaddr: clientMAC, msgType: .release))
        var transport2: any Transport = InMemoryTransport(inputs: [(endpointID: 1, packet: releaseFrame)])
        let round2 = RoundContext()
        bdpRound(transport: &transport2, arpMapping: &arpMapping, dhcpServer: &dhcpServer, routingTable: RoutingTable(), udpSocketTable: &udpTable, ipFragmentReassembler: &reasm, round: round2)

        #expect(!arpMapping.isKnown(requestedIP))

        // Round 3: DISCOVER should succeed (IP was reclaimed)
        let discoverFrame = makeDHCPFrame(clientMAC: MACAddress(0xBA, 0xCC, 0xDD, 0xEE, 0xFF, 0x00), dhcpPayload: makeDHCPPacketBytes(op: 1, xid: 3, chaddr: MACAddress(0xBA, 0xCC, 0xDD, 0xEE, 0xFF, 0x00), msgType: .discover))
        var transport3: any Transport = InMemoryTransport(inputs: [(endpointID: 1, packet: discoverFrame)])
        let round3 = RoundContext()
        bdpRound(transport: &transport3, arpMapping: &arpMapping, dhcpServer: &dhcpServer, routingTable: RoutingTable(), udpSocketTable: &udpTable, ipFragmentReassembler: &reasm, round: round3)

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
        let dhcpFrame = makeDHCPFrame(clientMAC: clientMAC, dhcpPayload: makeDHCPPacketBytes(op: 1, xid: 77, chaddr: clientMAC, msgType: .discover))

        var transport: any Transport = InMemoryTransport(inputs: [
            (endpointID: 1, packet: arpFrame),
            (endpointID: 1, packet: dhcpFrame),
        ])
        var arpMapping = ARPMapping(hostMAC: hostMAC, endpoints: [ep])
        var dhcpServer = DHCPServer(endpoints: [ep])
        let round = RoundContext(); var udpTable = UDPSocketTable(); var reasm = IPFragmentReassembler()

        bdpRound(transport: &transport, arpMapping: &arpMapping, dhcpServer: &dhcpServer, routingTable: RoutingTable(), udpSocketTable: &udpTable, ipFragmentReassembler: &reasm, round: round)

        // Should get 2 replies: ARP reply + DHCP OFFER
        #expect((transport as! InMemoryTransport).outputs.count == 2)
    }

    // MARK: - ICMP Echo Reply

    @Test func icmpEchoRequestGeneratesReply() {
        let ep = makeEndpoint()
        let clientMAC = MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF)
        let clientIP = IPv4Address(100, 64, 1, 50)

        let frame = makeICMPEchoFrame(clientMAC: clientMAC, clientIP: clientIP, dstIP: gateway, id: 0x1234, seq: 0x0001)

        var transport: any Transport = InMemoryTransport(inputs: [(endpointID: 1, packet: frame)])
        var arpMapping = ARPMapping(hostMAC: hostMAC, endpoints: [ep])
        var dhcpServer = DHCPServer(endpoints: [ep])
        let round = RoundContext(); var udpTable = UDPSocketTable(); var reasm = IPFragmentReassembler()

        bdpRound(transport: &transport, arpMapping: &arpMapping, dhcpServer: &dhcpServer, routingTable: RoutingTable(), udpSocketTable: &udpTable, ipFragmentReassembler: &reasm, round: round)

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
        let frame = makeDHCPFrame(clientMAC: clientMAC, dhcpPayload: dhcpDiscover)

        var transport: any Transport = InMemoryTransport(inputs: [(endpointID: 1, packet: frame)])
        var arpMapping = ARPMapping(hostMAC: hostMAC, endpoints: [ep])
        var dhcpServer = DHCPServer(endpoints: [ep])
        let round = RoundContext(); var udpTable = UDPSocketTable(); var reasm = IPFragmentReassembler()

        bdpRound(transport: &transport, arpMapping: &arpMapping, dhcpServer: &dhcpServer,
                 routingTable: RoutingTable(), udpSocketTable: &udpTable,
                 ipFragmentReassembler: &reasm, round: round)

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
        let frame = makeICMPEchoFrame(clientMAC: mac1, clientIP: ip1, dstIP: ip2, id: 1, seq: 1)
        let l2Frame = makeEthernetFrame(
            dst: mac2, src: mac1, type: .ipv4,
            payload: extractEtherPayload(frame)
        )

        var transport: any Transport = InMemoryTransport(inputs: [(endpointID: 1, packet: l2Frame)])
        var dhcpServer = DHCPServer(endpoints: [ep1, ep2])
        let round = RoundContext(); var udpTable = UDPSocketTable(); var reasm = IPFragmentReassembler()

        bdpRound(transport: &transport, arpMapping: &arpMapping, dhcpServer: &dhcpServer, routingTable: RoutingTable(), udpSocketTable: &udpTable, ipFragmentReassembler: &reasm, round: round)

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

        let frame = makeICMPEchoFrame(clientMAC: clientMAC, clientIP: clientIP, dstIP: gateway, id: 1, seq: 1)
        let l2Frame = makeEthernetFrame(
            dst: unknownMAC, src: clientMAC, type: .ipv4,
            payload: extractEtherPayload(frame)
        )

        var transport: any Transport = InMemoryTransport(inputs: [(endpointID: 1, packet: l2Frame)])
        var arpMapping = ARPMapping(hostMAC: hostMAC, endpoints: [ep1])
        var dhcpServer = DHCPServer(endpoints: [ep1])
        let round = RoundContext(); var udpTable = UDPSocketTable(); var reasm = IPFragmentReassembler()

        bdpRound(transport: &transport, arpMapping: &arpMapping, dhcpServer: &dhcpServer, routingTable: RoutingTable(), udpSocketTable: &udpTable, ipFragmentReassembler: &reasm, round: round)

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
        let round = RoundContext(); var udpTable = UDPSocketTable(); var reasm = IPFragmentReassembler()

        bdpRound(transport: &transport, arpMapping: &arpMapping, dhcpServer: &dhcpServer, routingTable: RoutingTable(), udpSocketTable: &udpTable, ipFragmentReassembler: &reasm, round: round)

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
        let localFrame = makeICMPEchoFrame(clientMAC: mac1, clientIP: ip1, dstIP: gateway, id: 1, seq: 1)

        // Frame 2: VM A → VM B MAC (forwarded)
        let forwardContent = makeICMPEchoFrame(clientMAC: mac1, clientIP: ip1, dstIP: ip2, id: 2, seq: 1)
        let forwardFrame = makeEthernetFrame(
            dst: mac2, src: mac1, type: .ipv4,
            payload: extractEtherPayload(forwardContent)
        )

        var transport: any Transport = InMemoryTransport(inputs: [
            (endpointID: 1, packet: localFrame),
            (endpointID: 1, packet: forwardFrame),
        ])
        var dhcpServer = DHCPServer(endpoints: [ep1, ep2])
        let round = RoundContext(); var udpTable = UDPSocketTable(); var reasm = IPFragmentReassembler()

        bdpRound(transport: &transport, arpMapping: &arpMapping, dhcpServer: &dhcpServer, routingTable: RoutingTable(), udpSocketTable: &udpTable, ipFragmentReassembler: &reasm, round: round)

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
        let round = RoundContext(); var udpTable = UDPSocketTable(); var reasm = IPFragmentReassembler()

        bdpRound(transport: &transport, arpMapping: &arpMapping, dhcpServer: &dhcpServer, routingTable: RoutingTable(), udpSocketTable: &udpTable, ipFragmentReassembler: &reasm, round: round)

        #expect((transport as! InMemoryTransport).outputs.isEmpty)
    }

    // MARK: - UDP echo

    @Test func udpEchoRequestGeneratesReply() {
        let ep = makeEndpoint()
        let clientMAC = MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF)
        let clientIP = IPv4Address(100, 64, 1, 50)

        let payload: [UInt8] = [0x70, 0x69, 0x6E, 0x67]
        let frame = makeUDPFrame(
            clientMAC: clientMAC,
            srcIP: clientIP, dstIP: gateway,
            srcPort: 1234, dstPort: 7,
            payload: payload
        )

        var transport: any Transport = InMemoryTransport(inputs: [(endpointID: 1, packet: frame)])
        var arpMapping = ARPMapping(hostMAC: hostMAC, endpoints: [ep])
        var dhcpServer = DHCPServer(endpoints: [ep])
        let round = RoundContext(); var udpTable = UDPSocketTable(); var reasm = IPFragmentReassembler()
        udpTable.register(port: 7, socket: UDPEchoSocket())

        bdpRound(transport: &transport, arpMapping: &arpMapping, dhcpServer: &dhcpServer, routingTable: RoutingTable(), udpSocketTable: &udpTable, ipFragmentReassembler: &reasm, round: round)

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
            clientMAC: clientMAC,
            srcIP: clientIP, dstIP: gateway,
            srcPort: 9999, dstPort: 7,
            payload: payload
        )

        var transport: any Transport = InMemoryTransport(inputs: [(endpointID: 1, packet: frame)])
        var arpMapping = ARPMapping(hostMAC: hostMAC, endpoints: [ep])
        var dhcpServer = DHCPServer(endpoints: [ep])
        let round = RoundContext(); var udpTable = UDPSocketTable(); var reasm = IPFragmentReassembler()
        udpTable.register(port: 7, socket: UDPEchoSocket())

        bdpRound(transport: &transport, arpMapping: &arpMapping, dhcpServer: &dhcpServer, routingTable: RoutingTable(), udpSocketTable: &udpTable, ipFragmentReassembler: &reasm, round: round)

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
            clientMAC: clientMAC,
            srcIP: clientIP, dstIP: gateway,
            srcPort: 1234, dstPort: 53,
            payload: [0xAA, 0xBB]
        )

        var transport: any Transport = InMemoryTransport(inputs: [(endpointID: 1, packet: frame)])
        var arpMapping = ARPMapping(hostMAC: hostMAC, endpoints: [ep])
        var dhcpServer = DHCPServer(endpoints: [ep])
        let round = RoundContext(); var udpTable = UDPSocketTable(); var reasm = IPFragmentReassembler()
        // Register echo on port 7 only — port 53 has no socket
        udpTable.register(port: 7, socket: UDPEchoSocket())

        bdpRound(transport: &transport, arpMapping: &arpMapping, dhcpServer: &dhcpServer, routingTable: RoutingTable(), udpSocketTable: &udpTable, ipFragmentReassembler: &reasm, round: round)

        #expect((transport as! InMemoryTransport).outputs.isEmpty)
    }

    @Test func mixedUDPAndICMPTraffic() {
        let ep = makeEndpoint()
        let clientMAC = MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF)
        let clientIP = IPv4Address(100, 64, 1, 50)

        // Frame 1: ICMP echo request
        let icmpFrame = makeICMPEchoFrame(clientMAC: clientMAC, clientIP: clientIP, dstIP: gateway, id: 0x42, seq: 0x01)

        // Frame 2: UDP echo request to port 7
        let udpFrame = makeUDPFrame(
            clientMAC: clientMAC,
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
        let round = RoundContext(); var udpTable = UDPSocketTable(); var reasm = IPFragmentReassembler()
        udpTable.register(port: 7, socket: UDPEchoSocket())

        bdpRound(transport: &transport, arpMapping: &arpMapping, dhcpServer: &dhcpServer, routingTable: RoutingTable(), udpSocketTable: &udpTable, ipFragmentReassembler: &reasm, round: round)

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

    // MARK: - Helpers

    /// Unwrap Ethernet → IPv4 → UDP → DHCP and parse the inner DHCP packet.
    private func extractDHCPFromReply(_ pkt: PacketBuffer) -> DHCPPacket? {
        guard let eth = EthernetFrame.parse(from: pkt),
              eth.etherType == .ipv4,
              let ip = IPv4Header.parse(from: eth.payload),
              ip.protocol == .udp else { return nil }
        // Skip UDP header (8 bytes)
        let udpPayload = ip.payload
        guard udpPayload.totalLength >= 8 else { return nil }
        guard let dhcpPayload = udpPayload.slice(from: 8, length: udpPayload.totalLength - 8) else { return nil }
        return DHCPPacket.parse(from: dhcpPayload)
    }

    private func makeEthernetFrame(dst: MACAddress, src: MACAddress, type: EtherType, payload: [UInt8]) -> PacketBuffer {
        var bytes: [UInt8] = []
        var buf6 = [UInt8](repeating: 0, count: 6)
        dst.write(to: &buf6); bytes.append(contentsOf: buf6)
        src.write(to: &buf6); bytes.append(contentsOf: buf6)
        let etRaw = type.rawValue
        bytes.append(UInt8(etRaw >> 8))
        bytes.append(UInt8(etRaw & 0xFF))
        bytes.append(contentsOf: payload)
        let s = Storage.allocate(capacity: bytes.count)
        bytes.withUnsafeBytes { s.data.copyMemory(from: $0.baseAddress!, byteCount: bytes.count) }
        return PacketBuffer(storage: s, offset: 0, length: bytes.count)
    }

    /// Extract the payload after the 14-byte Ethernet header as raw bytes.
    private func extractEtherPayload(_ pkt: PacketBuffer) -> [UInt8] {
        guard pkt.totalLength > 14 else { return [] }
        guard let payload = pkt.slice(from: 14, length: pkt.totalLength - 14) else { return [] }
        return payload.withUnsafeReadableBytes { Array($0) }
    }

    private func makeARPPayload(op: ARPOperation, senderMAC: MACAddress, senderIP: IPv4Address, targetMAC: MACAddress, targetIP: IPv4Address) -> [UInt8] {
        var bytes = [UInt8](repeating: 0, count: 28)
        bytes[0] = 0x00; bytes[1] = 0x01
        bytes[2] = 0x08; bytes[3] = 0x00
        bytes[4] = 6; bytes[5] = 4
        bytes[6] = UInt8(op.rawValue >> 8)
        bytes[7] = UInt8(op.rawValue & 0xFF)
        var buf6 = [UInt8](repeating: 0, count: 6)
        var buf4 = [UInt8](repeating: 0, count: 4)
        senderMAC.write(to: &buf6); bytes.replaceSubrange(8..<14, with: buf6)
        senderIP.write(to: &buf4); bytes.replaceSubrange(14..<18, with: buf4)
        targetMAC.write(to: &buf6); bytes.replaceSubrange(18..<24, with: buf6)
        targetIP.write(to: &buf4); bytes.replaceSubrange(24..<28, with: buf4)
        return bytes
    }

    private func ipBytes(_ ip: IPv4Address) -> [UInt8] {
        var buf = [UInt8](repeating: 0, count: 4)
        ip.write(to: &buf)
        return buf
    }

    /// Build a full Ethernet/IPv4/ICMP Echo Request frame.
    private func makeICMPEchoFrame(clientMAC: MACAddress, clientIP: IPv4Address, dstIP: IPv4Address, id: UInt16, seq: UInt16, payload: [UInt8] = [0x70, 0x69, 0x6E, 0x67]) -> PacketBuffer {
        let icmpLen = 8 + payload.count
        let ipTotalLen = 20 + icmpLen

        // ICMP header + payload
        var icmpBytes: [UInt8] = []
        icmpBytes.append(8); icmpBytes.append(0)  // type=8 (echo request), code=0
        icmpBytes.append(0); icmpBytes.append(0)  // checksum placeholder
        icmpBytes.append(UInt8(id >> 8)); icmpBytes.append(UInt8(id & 0xFF))
        icmpBytes.append(UInt8(seq >> 8)); icmpBytes.append(UInt8(seq & 0xFF))
        icmpBytes.append(contentsOf: payload)
        let icmpCksum = icmpBytes.withUnsafeBytes { internetChecksum($0) }
        icmpBytes[2] = UInt8(icmpCksum >> 8)
        icmpBytes[3] = UInt8(icmpCksum & 0xFF)

        // IPv4 header
        var ipBytes = [UInt8](repeating: 0, count: 20)
        ipBytes[0] = 0x45
        ipBytes[2] = UInt8(ipTotalLen >> 8)
        ipBytes[3] = UInt8(ipTotalLen & 0xFF)
        ipBytes[8] = 64
        ipBytes[9] = IPProtocol.icmp.rawValue
        clientIP.write(to: &ipBytes[12])
        dstIP.write(to: &ipBytes[16])
        let ipCksum = ipBytes.withUnsafeBytes { internetChecksum($0) }
        ipBytes[10] = UInt8(ipCksum >> 8)
        ipBytes[11] = UInt8(ipCksum & 0xFF)

        return makeEthernetFrame(
            dst: hostMAC,
            src: clientMAC,
            type: .ipv4,
            payload: ipBytes + icmpBytes
        )
    }

    /// Build a full Ethernet/IPv4/UDP/DHCP frame.
    private func makeDHCPFrame(clientMAC: MACAddress, dhcpPayload: [UInt8]) -> PacketBuffer {
        let udpLen = 8 + dhcpPayload.count
        let ipTotalLen = 20 + udpLen

        // IPv4 header
        var ipBytes = [UInt8](repeating: 0, count: 20)
        ipBytes[0] = 0x45
        ipBytes[2] = UInt8(ipTotalLen >> 8)
        ipBytes[3] = UInt8(ipTotalLen & 0xFF)
        ipBytes[8] = 64
        ipBytes[9] = IPProtocol.udp.rawValue
        IPv4Address(10, 0, 0, 50).write(to: &ipBytes[12])   // src
        IPv4Address(100, 64, 1, 1).write(to: &ipBytes[16])   // dst = gateway
        let ipCksum = ipBytes.withUnsafeBytes { internetChecksum($0) }
        ipBytes[10] = UInt8(ipCksum >> 8)
        ipBytes[11] = UInt8(ipCksum & 0xFF)

        // UDP header: srcPort=68 (client), dstPort=67 (server)
        var udpBytes = [UInt8](repeating: 0, count: 8)
        udpBytes[0] = 0x00; udpBytes[1] = 68   // src port 68
        udpBytes[2] = 0x00; udpBytes[3] = 67   // dst port 67
        udpBytes[4] = UInt8(udpLen >> 8)
        udpBytes[5] = UInt8(udpLen & 0xFF)
        // checksum = 0 (UDP checksum is optional for IPv4)

        return makeEthernetFrame(
            dst: hostMAC,
            src: clientMAC,
            type: .ipv4,
            payload: ipBytes + udpBytes + dhcpPayload
        )
    }

    /// Build a full Ethernet/IPv4/UDP frame with computed checksums.
    private func makeUDPFrame(
        clientMAC: MACAddress,
        srcIP: IPv4Address, dstIP: IPv4Address,
        srcPort: UInt16, dstPort: UInt16,
        payload: [UInt8]
    ) -> PacketBuffer {
        let udpLen = 8 + payload.count
        let ipTotalLen = 20 + udpLen

        // IPv4 header
        var ipBytes = [UInt8](repeating: 0, count: 20)
        ipBytes[0] = 0x45
        ipBytes[2] = UInt8(ipTotalLen >> 8)
        ipBytes[3] = UInt8(ipTotalLen & 0xFF)
        ipBytes[6] = 0x40; ipBytes[7] = 0x00  // DF flag
        ipBytes[8] = 64
        ipBytes[9] = IPProtocol.udp.rawValue
        srcIP.write(to: &ipBytes[12])
        dstIP.write(to: &ipBytes[16])
        let ipCksum = ipBytes.withUnsafeBytes { internetChecksum($0) }
        ipBytes[10] = UInt8(ipCksum >> 8)
        ipBytes[11] = UInt8(ipCksum & 0xFF)

        // UDP header: zero checksum for now, compute later
        var udpBytes: [UInt8] = []
        udpBytes.append(UInt8(srcPort >> 8))
        udpBytes.append(UInt8(srcPort & 0xFF))
        udpBytes.append(UInt8(dstPort >> 8))
        udpBytes.append(UInt8(dstPort & 0xFF))
        udpBytes.append(UInt8(udpLen >> 8))
        udpBytes.append(UInt8(udpLen & 0xFF))
        udpBytes.append(0); udpBytes.append(0)  // checksum
        udpBytes.append(contentsOf: payload)

        // Compute UDP checksum over pseudo-header
        var ckBuf = [UInt8](repeating: 0, count: 12 + udpLen)
        var ipOut = [UInt8](repeating: 0, count: 4)
        srcIP.write(to: &ipOut); ckBuf[0...3] = ipOut[0...3]
        dstIP.write(to: &ipOut); ckBuf[4...7] = ipOut[0...3]
        ckBuf[9] = IPProtocol.udp.rawValue
        ckBuf[10] = UInt8(udpLen >> 8)
        ckBuf[11] = UInt8(udpLen & 0xFF)
        for i in 0..<udpLen { ckBuf[12 + i] = udpBytes[i] }
        let ck = ckBuf.withUnsafeBytes { internetChecksum($0) }
        let finalCk = ck == 0 ? 0xFFFF : ck
        udpBytes[6] = UInt8(finalCk >> 8)
        udpBytes[7] = UInt8(finalCk & 0xFF)

        return makeEthernetFrame(
            dst: hostMAC,
            src: clientMAC,
            type: .ipv4,
            payload: ipBytes + udpBytes
        )
    }

    /// Build a raw DHCP packet (240-byte header + magic + options), suitable for DHCPPacket.parse.
    private func makeDHCPPacketBytes(op: UInt8, xid: UInt32, chaddr: MACAddress,
                                      msgType: DHCPMessageType,
                                      extraOptions: [(UInt8, [UInt8])] = []) -> [UInt8] {
        var bytes = [UInt8](repeating: 0, count: 247)
        bytes[0] = op
        bytes[4] = UInt8((xid >> 24) & 0xFF)
        bytes[5] = UInt8((xid >> 16) & 0xFF)
        bytes[6] = UInt8((xid >> 8) & 0xFF)
        bytes[7] = UInt8(xid & 0xFF)
        var buf6 = [UInt8](repeating: 0, count: 6)
        chaddr.write(to: &buf6); bytes.replaceSubrange(28..<34, with: buf6)
        // Magic cookie
        bytes[240] = 99; bytes[241] = 130; bytes[242] = 83; bytes[243] = 99
        // Option 53
        bytes[244] = 53; bytes[245] = 1; bytes[246] = msgType.rawValue

        var optIdx = 247
        for (code, value) in extraOptions {
            if optIdx + 2 + value.count > bytes.count {
                bytes.append(contentsOf: [UInt8](repeating: 0, count: optIdx + 2 + value.count - bytes.count))
            }
            bytes[optIdx] = code
            bytes[optIdx + 1] = UInt8(value.count)
            bytes.replaceSubrange((optIdx + 2)..<(optIdx + 2 + value.count), with: value)
            optIdx += 2 + value.count
        }
        if optIdx >= bytes.count { bytes.append(0) }
        bytes[optIdx] = 255
        return bytes
    }
}
