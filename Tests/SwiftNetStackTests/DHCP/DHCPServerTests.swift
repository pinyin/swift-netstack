import Testing
@testable import SwiftNetStack

@Suite(.serialized)
struct DHCPServerTests {

    // Helper: create a minimal endpoint with a small subnet for easy pool exhaustion testing
    private func makeEndpoint(id: Int, subnet: IPv4Subnet, gateway: IPv4Address) -> VMEndpoint {
        VMEndpoint(id: id, fd: Int32(id + 100), subnet: subnet, gateway: gateway, mtu: 1500)
    }

    // MARK: - DISCOVER → OFFER

    @Test func discoverGeneratesOffer() {
        let subnet = IPv4Subnet(network: IPv4Address(100, 64, 1, 0), prefixLength: 24)
        let gateway = IPv4Address(100, 64, 1, 1)
        let clientMAC = MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF)
        let ourMAC = MACAddress(0x00, 0x11, 0x22, 0x33, 0x44, 0x55)

        var dhcp = DHCPServer(endpoints: [makeEndpoint(id: 1, subnet: subnet, gateway: gateway)])
        var arp = ARPMapping(ourMAC: ourMAC, endpoints: [makeEndpoint(id: 1, subnet: subnet, gateway: gateway)])
        let round = RoundContext()

        let discover = DHCPPacket(op: 1, xid: 42, chaddr: clientMAC, messageType: .discover, requestedIP: nil, serverIdentifier: nil)
        let result = dhcp.process(packet: discover, srcMAC: clientMAC, endpointID: 1, arpMapping: &arp, round: round)

        #expect(result != nil)
        guard let (reply, endpointID) = result else { return }
        #expect(endpointID == 1)

        // Parse the reply back
        guard let parsed = DHCPPacket.parse(from: reply) else {
            Issue.record("failed to parse DHCP reply")
            return
        }
        #expect(parsed.op == 2)  // BOOTREPLY
        #expect(parsed.messageType == .offer)
        #expect(parsed.xid == 42)
        #expect(parsed.chaddr == clientMAC)
    }

    @Test func discoverWhenPoolExhaustedReturnsNil() {
        // Use /30 subnet: network .0, gateway .1, broadcast .3 → only .2 available
        let subnet = IPv4Subnet(network: IPv4Address(100, 64, 1, 0), prefixLength: 30)
        let gateway = IPv4Address(100, 64, 1, 1)
        let ourMAC = MACAddress(0x00, 0x11, 0x22, 0x33, 0x44, 0x55)

        var dhcp = DHCPServer(endpoints: [makeEndpoint(id: 1, subnet: subnet, gateway: gateway)])
        var arp = ARPMapping(ourMAC: ourMAC, endpoints: [makeEndpoint(id: 1, subnet: subnet, gateway: gateway)])
        let round = RoundContext()

        // First DISCOVER consumes the only available IP
        let d1 = DHCPPacket(op: 1, xid: 1, chaddr: MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01), messageType: .discover, requestedIP: nil, serverIdentifier: nil)
        #expect(dhcp.process(packet: d1, srcMAC: MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01), endpointID: 1, arpMapping: &arp, round: round) != nil)

        // Second DISCOVER has no pool left
        let d2 = DHCPPacket(op: 1, xid: 2, chaddr: MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x02), messageType: .discover, requestedIP: nil, serverIdentifier: nil)
        #expect(dhcp.process(packet: d2, srcMAC: MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x02), endpointID: 1, arpMapping: &arp, round: round) == nil)
    }

    // MARK: - REQUEST → ACK

    @Test func requestGeneratesAck() {
        let subnet = IPv4Subnet(network: IPv4Address(100, 64, 1, 0), prefixLength: 24)
        let gateway = IPv4Address(100, 64, 1, 1)
        let clientMAC = MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF)
        let requestedIP = IPv4Address(100, 64, 1, 50)
        let ourMAC = MACAddress(0x00, 0x11, 0x22, 0x33, 0x44, 0x55)

        var dhcp = DHCPServer(endpoints: [makeEndpoint(id: 1, subnet: subnet, gateway: gateway)])
        var arp = ARPMapping(ourMAC: ourMAC, endpoints: [makeEndpoint(id: 1, subnet: subnet, gateway: gateway)])
        let round = RoundContext()

        let request = DHCPPacket(op: 1, xid: 99, chaddr: clientMAC, messageType: .request,
                                  requestedIP: requestedIP, serverIdentifier: gateway)
        let result = dhcp.process(packet: request, srcMAC: clientMAC, endpointID: 1, arpMapping: &arp, round: round)

        #expect(result != nil)
        guard let (reply, endpointID) = result else { return }
        #expect(endpointID == 1)

        guard let parsed = DHCPPacket.parse(from: reply) else {
            Issue.record("failed to parse DHCP reply")
            return
        }
        #expect(parsed.messageType == .ack)
        #expect(parsed.xid == 99)
        #expect(parsed.chaddr == clientMAC)
    }

    @Test func requestUpdatesARPMapping() {
        let subnet = IPv4Subnet(network: IPv4Address(100, 64, 1, 0), prefixLength: 24)
        let gateway = IPv4Address(100, 64, 1, 1)
        let clientMAC = MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF)
        let requestedIP = IPv4Address(100, 64, 1, 50)
        let ourMAC = MACAddress(0x00, 0x11, 0x22, 0x33, 0x44, 0x55)

        var dhcp = DHCPServer(endpoints: [makeEndpoint(id: 1, subnet: subnet, gateway: gateway)])
        var arp = ARPMapping(ourMAC: ourMAC, endpoints: [makeEndpoint(id: 1, subnet: subnet, gateway: gateway)])
        let round = RoundContext()

        #expect(!arp.isKnown(requestedIP))

        let request = DHCPPacket(op: 1, xid: 1, chaddr: clientMAC, messageType: .request,
                                  requestedIP: requestedIP, serverIdentifier: gateway)
        _ = dhcp.process(packet: request, srcMAC: clientMAC, endpointID: 1, arpMapping: &arp, round: round)

        #expect(arp.isKnown(requestedIP))
        #expect(arp.lookup(ip: requestedIP) == clientMAC)
    }

    @Test func requestWithWrongServerIdentifierReturnsNil() {
        let subnet = IPv4Subnet(network: IPv4Address(100, 64, 1, 0), prefixLength: 24)
        let gateway = IPv4Address(100, 64, 1, 1)
        let clientMAC = MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF)
        let ourMAC = MACAddress(0x00, 0x11, 0x22, 0x33, 0x44, 0x55)
        let wrongServer = IPv4Address(192, 168, 1, 1)  // not in subnet → not ours

        var dhcp = DHCPServer(endpoints: [makeEndpoint(id: 1, subnet: subnet, gateway: gateway)])
        var arp = ARPMapping(ourMAC: ourMAC, endpoints: [makeEndpoint(id: 1, subnet: subnet, gateway: gateway)])
        let round = RoundContext()

        let request = DHCPPacket(op: 1, xid: 1, chaddr: clientMAC, messageType: .request,
                                  requestedIP: IPv4Address(100, 64, 1, 50),
                                  serverIdentifier: wrongServer)
        #expect(dhcp.process(packet: request, srcMAC: clientMAC, endpointID: 1, arpMapping: &arp, round: round) == nil)
    }

    @Test func requestWithoutRequestedIPReturnsNil() {
        let subnet = IPv4Subnet(network: IPv4Address(100, 64, 1, 0), prefixLength: 24)
        let gateway = IPv4Address(100, 64, 1, 1)
        let clientMAC = MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF)
        let ourMAC = MACAddress(0x00, 0x11, 0x22, 0x33, 0x44, 0x55)

        var dhcp = DHCPServer(endpoints: [makeEndpoint(id: 1, subnet: subnet, gateway: gateway)])
        var arp = ARPMapping(ourMAC: ourMAC, endpoints: [makeEndpoint(id: 1, subnet: subnet, gateway: gateway)])
        let round = RoundContext()

        let request = DHCPPacket(op: 1, xid: 1, chaddr: clientMAC, messageType: .request,
                                  requestedIP: nil, serverIdentifier: gateway)
        #expect(dhcp.process(packet: request, srcMAC: clientMAC, endpointID: 1, arpMapping: &arp, round: round) == nil)
    }

    // MARK: - RELEASE

    @Test func releaseReclaimsIP() {
        let subnet = IPv4Subnet(network: IPv4Address(100, 64, 1, 0), prefixLength: 30)
        let gateway = IPv4Address(100, 64, 1, 1)
        let clientMAC = MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF)
        let requestedIP = IPv4Address(100, 64, 1, 2)
        let ourMAC = MACAddress(0x00, 0x11, 0x22, 0x33, 0x44, 0x55)

        var dhcp = DHCPServer(endpoints: [makeEndpoint(id: 1, subnet: subnet, gateway: gateway)])
        var arp = ARPMapping(ourMAC: ourMAC, endpoints: [makeEndpoint(id: 1, subnet: subnet, gateway: gateway)])
        let round = RoundContext()

        // First, get a lease via REQUEST
        let request = DHCPPacket(op: 1, xid: 1, chaddr: clientMAC, messageType: .request,
                                  requestedIP: requestedIP, serverIdentifier: gateway)
        _ = dhcp.process(packet: request, srcMAC: clientMAC, endpointID: 1, arpMapping: &arp, round: round)
        #expect(arp.isKnown(requestedIP))

        // Now release it
        let release = DHCPPacket(op: 1, xid: 2, chaddr: clientMAC, messageType: .release,
                                  requestedIP: nil, serverIdentifier: nil)
        let result = dhcp.process(packet: release, srcMAC: clientMAC, endpointID: 1, arpMapping: &arp, round: round)
        #expect(result == nil)  // RELEASE has no response

        // ARP entry should be removed
        #expect(!arp.isKnown(requestedIP))

        // Should be able to DISCOVER again (IP was reclaimed)
        let discover = DHCPPacket(op: 1, xid: 3, chaddr: MACAddress(0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00), messageType: .discover, requestedIP: nil, serverIdentifier: nil)
        #expect(dhcp.process(packet: discover, srcMAC: MACAddress(0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00), endpointID: 1, arpMapping: &arp, round: round) != nil)
    }

    // MARK: - Edge cases

    @Test func unknownEndpointIDReturnsNil() {
        let subnet = IPv4Subnet(network: IPv4Address(100, 64, 1, 0), prefixLength: 24)
        let gateway = IPv4Address(100, 64, 1, 1)
        let ourMAC = MACAddress(0x00, 0x11, 0x22, 0x33, 0x44, 0x55)

        var dhcp = DHCPServer(endpoints: [makeEndpoint(id: 1, subnet: subnet, gateway: gateway)])
        var arp = ARPMapping(ourMAC: ourMAC, endpoints: [makeEndpoint(id: 1, subnet: subnet, gateway: gateway)])
        let round = RoundContext()

        let discover = DHCPPacket(op: 1, xid: 1, chaddr: MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF), messageType: .discover, requestedIP: nil, serverIdentifier: nil)
        #expect(dhcp.process(packet: discover, srcMAC: MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF), endpointID: 999, arpMapping: &arp, round: round) == nil)
    }

    @Test func unknownMessageTypeReturnsNil() {
        let subnet = IPv4Subnet(network: IPv4Address(100, 64, 1, 0), prefixLength: 24)
        let gateway = IPv4Address(100, 64, 1, 1)
        let ourMAC = MACAddress(0x00, 0x11, 0x22, 0x33, 0x44, 0x55)

        var dhcp = DHCPServer(endpoints: [makeEndpoint(id: 1, subnet: subnet, gateway: gateway)])
        var arp = ARPMapping(ourMAC: ourMAC, endpoints: [makeEndpoint(id: 1, subnet: subnet, gateway: gateway)])
        let round = RoundContext()

        // DECLINE has no handler
        let decline = DHCPPacket(op: 1, xid: 1, chaddr: MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF), messageType: .decline, requestedIP: nil, serverIdentifier: nil)
        #expect(dhcp.process(packet: decline, srcMAC: MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF), endpointID: 1, arpMapping: &arp, round: round) == nil)
    }

    // MARK: - Full flow: DISCOVER → REQUEST

    @Test func fullDiscoverThenRequestFlow() {
        let subnet = IPv4Subnet(network: IPv4Address(100, 64, 1, 0), prefixLength: 24)
        let gateway = IPv4Address(100, 64, 1, 1)
        let clientMAC = MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF)
        let ourMAC = MACAddress(0x00, 0x11, 0x22, 0x33, 0x44, 0x55)

        var dhcp = DHCPServer(endpoints: [makeEndpoint(id: 1, subnet: subnet, gateway: gateway)])
        var arp = ARPMapping(ourMAC: ourMAC, endpoints: [makeEndpoint(id: 1, subnet: subnet, gateway: gateway)])
        let round = RoundContext()

        // Step 1: DISCOVER
        let discover = DHCPPacket(op: 1, xid: 42, chaddr: clientMAC, messageType: .discover, requestedIP: nil, serverIdentifier: nil)
        guard let (offerPkt, _) = dhcp.process(packet: discover, srcMAC: clientMAC, endpointID: 1, arpMapping: &arp, round: round),
              let offer = DHCPPacket.parse(from: offerPkt) else {
            Issue.record("DISCOVER failed")
            return
        }
        #expect(offer.messageType == .offer)

        // Step 2: REQUEST for the offered IP (extracted from yiaddr field — we trust the server assigned one)
        let requestedIP = IPv4Address(100, 64, 1, 2)  // first available
        let request = DHCPPacket(op: 1, xid: 42, chaddr: clientMAC, messageType: .request,
                                  requestedIP: requestedIP, serverIdentifier: gateway)
        guard let (ackPkt, _) = dhcp.process(packet: request, srcMAC: clientMAC, endpointID: 1, arpMapping: &arp, round: round),
              let ack = DHCPPacket.parse(from: ackPkt) else {
            Issue.record("REQUEST failed")
            return
        }
        #expect(ack.messageType == .ack)
        #expect(arp.isKnown(requestedIP))
    }
}
