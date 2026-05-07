import Testing
@testable import SwiftNetStack

@Suite(.serialized)
struct DHCPServerTests {

    // Helper: create a minimal endpoint with a small subnet for easy pool exhaustion testing
    private func makeEndpoint(id: Int, subnet: IPv4Subnet, gateway: IPv4Address) -> VMEndpoint {
        VMEndpoint(id: id, fd: Int32(id + 100), subnet: subnet, gateway: gateway, mtu: 1500)
    }

    // Helper: extract DHCP payload from a full Ethernet frame (Ethernet + IPv4 + UDP + DHCP).
    private func parseDHCPFromFrame(_ frame: PacketBuffer) -> DHCPPacket? {
        guard let eth = EthernetFrame.parse(from: frame) else { return nil }
        guard let ip = IPv4Header.parse(from: eth.payload) else { return nil }
        guard let udp = UDPHeader.parse(from: ip.payload, pseudoSrcAddr: ip.srcAddr, pseudoDstAddr: ip.dstAddr) else { return nil }
        return DHCPPacket.parse(from: udp.payload)
    }

    // MARK: - DISCOVER → OFFER

    @Test func discoverGeneratesOffer() {
        let subnet = IPv4Subnet(network: IPv4Address(100, 64, 1, 0), prefixLength: 24)
        let gateway = IPv4Address(100, 64, 1, 1)
        let clientMAC = MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF)
        let hostMAC = MACAddress(0x00, 0x11, 0x22, 0x33, 0x44, 0x55)

        var dhcp = DHCPServer(endpoints: [makeEndpoint(id: 1, subnet: subnet, gateway: gateway)])
        var arp = ARPMapping(hostMAC: hostMAC, endpoints: [makeEndpoint(id: 1, subnet: subnet, gateway: gateway)])
        let round = RoundContext()

        let discover = DHCPPacket(op: 1, xid: 42, chaddr: clientMAC, messageType: .discover, requestedIP: nil, serverIdentifier: nil)
        let result = dhcp.process(packet: discover, srcMAC: clientMAC, endpointID: 1, hostMAC: hostMAC, arpMapping: &arp, round: round)

        #expect(result != nil)
        guard let (reply, endpointID) = result else { return }
        #expect(endpointID == 1)

        // Parse the Ethernet frame back to DHCP
        guard let parsed = parseDHCPFromFrame(reply) else {
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
        let hostMAC = MACAddress(0x00, 0x11, 0x22, 0x33, 0x44, 0x55)

        var dhcp = DHCPServer(endpoints: [makeEndpoint(id: 1, subnet: subnet, gateway: gateway)])
        var arp = ARPMapping(hostMAC: hostMAC, endpoints: [makeEndpoint(id: 1, subnet: subnet, gateway: gateway)])
        let round = RoundContext()

        // First DISCOVER consumes the only available IP
        let d1 = DHCPPacket(op: 1, xid: 1, chaddr: MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01), messageType: .discover, requestedIP: nil, serverIdentifier: nil)
        #expect(dhcp.process(packet: d1, srcMAC: MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01), endpointID: 1, hostMAC: hostMAC, arpMapping: &arp, round: round) != nil)

        // Second DISCOVER has no pool left
        let d2 = DHCPPacket(op: 1, xid: 2, chaddr: MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x02), messageType: .discover, requestedIP: nil, serverIdentifier: nil)
        #expect(dhcp.process(packet: d2, srcMAC: MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x02), endpointID: 1, hostMAC: hostMAC, arpMapping: &arp, round: round) == nil)
    }

    // MARK: - REQUEST → ACK

    @Test func requestGeneratesAck() {
        let subnet = IPv4Subnet(network: IPv4Address(100, 64, 1, 0), prefixLength: 24)
        let gateway = IPv4Address(100, 64, 1, 1)
        let clientMAC = MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF)
        let requestedIP = IPv4Address(100, 64, 1, 50)
        let hostMAC = MACAddress(0x00, 0x11, 0x22, 0x33, 0x44, 0x55)

        var dhcp = DHCPServer(endpoints: [makeEndpoint(id: 1, subnet: subnet, gateway: gateway)])
        var arp = ARPMapping(hostMAC: hostMAC, endpoints: [makeEndpoint(id: 1, subnet: subnet, gateway: gateway)])
        let round = RoundContext()

        let request = DHCPPacket(op: 1, xid: 99, chaddr: clientMAC, messageType: .request,
                                  requestedIP: requestedIP, serverIdentifier: gateway)
        let result = dhcp.process(packet: request, srcMAC: clientMAC, endpointID: 1, hostMAC: hostMAC, arpMapping: &arp, round: round)

        #expect(result != nil)
        guard let (reply, endpointID) = result else { return }
        #expect(endpointID == 1)

        guard let parsed = parseDHCPFromFrame(reply) else {
            Issue.record("failed to parse DHCP ACK")
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
        let hostMAC = MACAddress(0x00, 0x11, 0x22, 0x33, 0x44, 0x55)

        var dhcp = DHCPServer(endpoints: [makeEndpoint(id: 1, subnet: subnet, gateway: gateway)])
        var arp = ARPMapping(hostMAC: hostMAC, endpoints: [makeEndpoint(id: 1, subnet: subnet, gateway: gateway)])
        let round = RoundContext()

        #expect(!arp.isKnown(requestedIP))

        let request = DHCPPacket(op: 1, xid: 1, chaddr: clientMAC, messageType: .request,
                                  requestedIP: requestedIP, serverIdentifier: gateway)
        _ = dhcp.process(packet: request, srcMAC: clientMAC, endpointID: 1, hostMAC: hostMAC, arpMapping: &arp, round: round)

        #expect(arp.isKnown(requestedIP))
        #expect(arp.lookup(ip: requestedIP) == clientMAC)
    }

    @Test func requestWithWrongServerIdentifierReturnsNil() {
        let subnet = IPv4Subnet(network: IPv4Address(100, 64, 1, 0), prefixLength: 24)
        let gateway = IPv4Address(100, 64, 1, 1)
        let clientMAC = MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF)
        let hostMAC = MACAddress(0x00, 0x11, 0x22, 0x33, 0x44, 0x55)
        let wrongServer = IPv4Address(192, 168, 1, 1)  // not in subnet → not ours

        var dhcp = DHCPServer(endpoints: [makeEndpoint(id: 1, subnet: subnet, gateway: gateway)])
        var arp = ARPMapping(hostMAC: hostMAC, endpoints: [makeEndpoint(id: 1, subnet: subnet, gateway: gateway)])
        let round = RoundContext()

        let request = DHCPPacket(op: 1, xid: 1, chaddr: clientMAC, messageType: .request,
                                  requestedIP: IPv4Address(100, 64, 1, 50),
                                  serverIdentifier: wrongServer)
        #expect(dhcp.process(packet: request, srcMAC: clientMAC, endpointID: 1, hostMAC: hostMAC, arpMapping: &arp, round: round) == nil)
    }

    @Test func requestWithoutRequestedIPReturnsNil() {
        let subnet = IPv4Subnet(network: IPv4Address(100, 64, 1, 0), prefixLength: 24)
        let gateway = IPv4Address(100, 64, 1, 1)
        let clientMAC = MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF)
        let hostMAC = MACAddress(0x00, 0x11, 0x22, 0x33, 0x44, 0x55)

        var dhcp = DHCPServer(endpoints: [makeEndpoint(id: 1, subnet: subnet, gateway: gateway)])
        var arp = ARPMapping(hostMAC: hostMAC, endpoints: [makeEndpoint(id: 1, subnet: subnet, gateway: gateway)])
        let round = RoundContext()

        let request = DHCPPacket(op: 1, xid: 1, chaddr: clientMAC, messageType: .request,
                                  requestedIP: nil, serverIdentifier: gateway)
        #expect(dhcp.process(packet: request, srcMAC: clientMAC, endpointID: 1, hostMAC: hostMAC, arpMapping: &arp, round: round) == nil)
    }

    // MARK: - RELEASE

    @Test func releaseReclaimsIP() {
        let subnet = IPv4Subnet(network: IPv4Address(100, 64, 1, 0), prefixLength: 30)
        let gateway = IPv4Address(100, 64, 1, 1)
        let clientMAC = MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF)
        let requestedIP = IPv4Address(100, 64, 1, 2)
        let hostMAC = MACAddress(0x00, 0x11, 0x22, 0x33, 0x44, 0x55)

        var dhcp = DHCPServer(endpoints: [makeEndpoint(id: 1, subnet: subnet, gateway: gateway)])
        var arp = ARPMapping(hostMAC: hostMAC, endpoints: [makeEndpoint(id: 1, subnet: subnet, gateway: gateway)])
        let round = RoundContext()

        // First, get a lease via REQUEST
        let request = DHCPPacket(op: 1, xid: 1, chaddr: clientMAC, messageType: .request,
                                  requestedIP: requestedIP, serverIdentifier: gateway)
        _ = dhcp.process(packet: request, srcMAC: clientMAC, endpointID: 1, hostMAC: hostMAC, arpMapping: &arp, round: round)
        #expect(arp.isKnown(requestedIP))

        // Now release it
        let release = DHCPPacket(op: 1, xid: 2, chaddr: clientMAC, messageType: .release,
                                  requestedIP: nil, serverIdentifier: nil)
        let result = dhcp.process(packet: release, srcMAC: clientMAC, endpointID: 1, hostMAC: hostMAC, arpMapping: &arp, round: round)
        #expect(result == nil)  // RELEASE has no response

        // ARP entry should be removed
        #expect(!arp.isKnown(requestedIP))

        // Should be able to DISCOVER again (IP was reclaimed)
        let discover = DHCPPacket(op: 1, xid: 3, chaddr: MACAddress(0xBA, 0xCC, 0xDD, 0xEE, 0xFF, 0x00), messageType: .discover, requestedIP: nil, serverIdentifier: nil)
        #expect(dhcp.process(packet: discover, srcMAC: MACAddress(0xBA, 0xCC, 0xDD, 0xEE, 0xFF, 0x00), endpointID: 1, hostMAC: hostMAC, arpMapping: &arp, round: round) != nil)
    }

    // MARK: - AUDIT #2: RELEASE uses MAC lookup instead of ciaddr

    /// Reproduces audit finding #2: `handleRelease` uses `pool.ipForMAC(srcMAC)`
    /// to find the IP to release, instead of reading `ciaddr` from the DHCP packet
    /// (offset 12-15) as required by RFC 2131.
    ///
    /// When a single MAC holds multiple IPs (legal in DHCP), the wrong IP may be
    /// released. `ipForMAC` returns the first match from the leases dictionary,
    /// whose iteration order is non-deterministic.
    ///
    /// Additionally, `DHCPPacket` does not even parse the `ciaddr` field,
    /// so the RELEASE handler has no way to know which IP the client intends to free.
    @Test func releaseWithMultipleIPsReleasesWrongIP() {
        // /24 subnet: plenty of available IPs
        let subnet = IPv4Subnet(network: IPv4Address(100, 64, 1, 0), prefixLength: 24)
        let gateway = IPv4Address(100, 64, 1, 1)
        let clientMAC = MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF)
        let hostMAC = MACAddress(0x00, 0x11, 0x22, 0x33, 0x44, 0x55)
        let ip1 = IPv4Address(100, 64, 1, 10)
        let ip2 = IPv4Address(100, 64, 1, 20)

        var dhcp = DHCPServer(endpoints: [makeEndpoint(id: 1, subnet: subnet, gateway: gateway)])
        var arp = ARPMapping(hostMAC: hostMAC, endpoints: [makeEndpoint(id: 1, subnet: subnet, gateway: gateway)])
        let round = RoundContext()

        // MAC_A leases two IPs (same MAC, different IPs — legal per RFC 2131)
        let req1 = DHCPPacket(op: 1, xid: 1, chaddr: clientMAC, messageType: .request,
                               requestedIP: ip1, serverIdentifier: gateway)
        let r1 = dhcp.process(packet: req1, srcMAC: clientMAC, endpointID: 1, hostMAC: hostMAC, arpMapping: &arp, round: round)
        #expect(r1 != nil, "first REQUEST should get ACK")

        let req2 = DHCPPacket(op: 1, xid: 2, chaddr: clientMAC, messageType: .request,
                               requestedIP: ip2, serverIdentifier: gateway)
        let r2 = dhcp.process(packet: req2, srcMAC: clientMAC, endpointID: 1, hostMAC: hostMAC, arpMapping: &arp, round: round)
        #expect(r2 != nil, "second REQUEST should get ACK (same MAC, different IP)")

        #expect(arp.isKnown(ip1) && arp.isKnown(ip2), "both IPs should be leased before RELEASE")

        // Send RELEASE. handleRelease ignores ciaddr (offset 12-15 in BOOTP header)
        // and uses ipForMAC(srcMAC) which returns an arbitrary first match from leases dict.
        _ = dhcp.process(packet: DHCPPacket(op: 1, xid: 3, chaddr: clientMAC, messageType: .release,
                                             requestedIP: nil, serverIdentifier: nil),
                         srcMAC: clientMAC, endpointID: 1, hostMAC: hostMAC, arpMapping: &arp, round: round)

        // AUDIT #2: Only ONE IP is released — handleRelease calls ipForMAC once.
        // The RELEASE packet has no ciaddr field in DHCPPacket, so there's no way
        // to specify WHICH IP to release. A correct implementation would read ciaddr
        // from the raw BOOTP header (bytes 12-15) and release that specific IP.
        let remaining = [ip1, ip2].filter { arp.isKnown($0) }
        let released = 2 - remaining.count
        #expect(remaining.count == 1,
            "AUDIT #2 FAIL: expected exactly 1 IP released, got \(released) released, \(remaining.count) remaining — handleRelease picks arbitrary IP via ipForMAC")
    }

    // MARK: - Edge cases

    @Test func unknownEndpointIDReturnsNil() {
        let subnet = IPv4Subnet(network: IPv4Address(100, 64, 1, 0), prefixLength: 24)
        let gateway = IPv4Address(100, 64, 1, 1)
        let hostMAC = MACAddress(0x00, 0x11, 0x22, 0x33, 0x44, 0x55)

        var dhcp = DHCPServer(endpoints: [makeEndpoint(id: 1, subnet: subnet, gateway: gateway)])
        var arp = ARPMapping(hostMAC: hostMAC, endpoints: [makeEndpoint(id: 1, subnet: subnet, gateway: gateway)])
        let round = RoundContext()

        let discover = DHCPPacket(op: 1, xid: 1, chaddr: MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF), messageType: .discover, requestedIP: nil, serverIdentifier: nil)
        #expect(dhcp.process(packet: discover, srcMAC: MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF), endpointID: 999, hostMAC: hostMAC, arpMapping: &arp, round: round) == nil)
    }

    @Test func unknownMessageTypeReturnsNil() {
        let subnet = IPv4Subnet(network: IPv4Address(100, 64, 1, 0), prefixLength: 24)
        let gateway = IPv4Address(100, 64, 1, 1)
        let hostMAC = MACAddress(0x00, 0x11, 0x22, 0x33, 0x44, 0x55)

        var dhcp = DHCPServer(endpoints: [makeEndpoint(id: 1, subnet: subnet, gateway: gateway)])
        var arp = ARPMapping(hostMAC: hostMAC, endpoints: [makeEndpoint(id: 1, subnet: subnet, gateway: gateway)])
        let round = RoundContext()

        // DECLINE has no handler
        let decline = DHCPPacket(op: 1, xid: 1, chaddr: MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF), messageType: .decline, requestedIP: nil, serverIdentifier: nil)
        #expect(dhcp.process(packet: decline, srcMAC: MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF), endpointID: 1, hostMAC: hostMAC, arpMapping: &arp, round: round) == nil)
    }

    // MARK: - Pending offer expiration (CRITICAL: IP pool leak fix)

    @Test func discoverWithoutRequestReclaimsIPAfterTimeout() {
        // /30 subnet: network .0, gateway .1, broadcast .3 → only .2 available
        let subnet = IPv4Subnet(network: IPv4Address(100, 64, 1, 0), prefixLength: 30)
        let gateway = IPv4Address(100, 64, 1, 1)
        let hostMAC = MACAddress(0x00, 0x11, 0x22, 0x33, 0x44, 0x55)

        // offerTimeout: 0 means offers expire instantly
        var dhcp = DHCPServer(endpoints: [makeEndpoint(id: 1, subnet: subnet, gateway: gateway)], offerTimeout: 0)
        var arp = ARPMapping(hostMAC: hostMAC, endpoints: [makeEndpoint(id: 1, subnet: subnet, gateway: gateway)])
        let round = RoundContext()

        // First DISCOVER → OFFER (IP allocated as pending, expires immediately since timeout=0)
        let d1 = DHCPPacket(op: 1, xid: 1, chaddr: MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01),
                            messageType: .discover, requestedIP: nil, serverIdentifier: nil)
        let result1 = dhcp.process(packet: d1, srcMAC: MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01),
                                   endpointID: 1, hostMAC: hostMAC, arpMapping: &arp, round: round)
        #expect(result1 != nil)

        // Second DISCOVER should also succeed — the first offer expired and IP was reclaimed
        let d2 = DHCPPacket(op: 1, xid: 2, chaddr: MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x02),
                            messageType: .discover, requestedIP: nil, serverIdentifier: nil)
        let result2 = dhcp.process(packet: d2, srcMAC: MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x02),
                                   endpointID: 1, hostMAC: hostMAC, arpMapping: &arp, round: round)
        #expect(result2 != nil, "Second DISCOVER should succeed after pending offer expired — pool leak regression")
    }

    @Test func discoverConfirmedByRequestDoesNotLeak() {
        // Verify that a properly completed DISCOVER→REQUEST flow does NOT leak
        let subnet = IPv4Subnet(network: IPv4Address(100, 64, 1, 0), prefixLength: 30)
        let gateway = IPv4Address(100, 64, 1, 1)
        let hostMAC = MACAddress(0x00, 0x11, 0x22, 0x33, 0x44, 0x55)
        let clientMAC = MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01)
        let requestedIP = IPv4Address(100, 64, 1, 2)  // the only available IP in /30

        var dhcp = DHCPServer(endpoints: [makeEndpoint(id: 1, subnet: subnet, gateway: gateway)], offerTimeout: 0)
        var arp = ARPMapping(hostMAC: hostMAC, endpoints: [makeEndpoint(id: 1, subnet: subnet, gateway: gateway)])
        let round = RoundContext()

        // DISCOVER → OFFER (IP becomes pending)
        let discover = DHCPPacket(op: 1, xid: 1, chaddr: clientMAC,
                                   messageType: .discover, requestedIP: nil, serverIdentifier: nil)
        let offerResult = dhcp.process(packet: discover, srcMAC: clientMAC,
                                        endpointID: 1, hostMAC: hostMAC, arpMapping: &arp, round: round)
        #expect(offerResult != nil)

        // REQUEST → ACK (IP confirmed, removed from pending)
        let request = DHCPPacket(op: 1, xid: 2, chaddr: clientMAC, messageType: .request,
                                  requestedIP: requestedIP, serverIdentifier: gateway)
        let ackResult = dhcp.process(packet: request, srcMAC: clientMAC,
                                      endpointID: 1, hostMAC: hostMAC, arpMapping: &arp, round: round)
        #expect(ackResult != nil)

        // Now another DISCOVER should fail — the IP is legitimately leased, not pending
        let discover2 = DHCPPacket(op: 1, xid: 3, chaddr: MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x02),
                                    messageType: .discover, requestedIP: nil, serverIdentifier: nil)
        let exhaustedResult = dhcp.process(packet: discover2, srcMAC: MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x02),
                                           endpointID: 1, hostMAC: hostMAC, arpMapping: &arp, round: round)
        #expect(exhaustedResult == nil, "Pool should be exhausted after confirmed lease, not pending offer")
    }

    // MARK: - Full flow: DISCOVER → REQUEST

    // MARK: - AUDIT #1: DHCP address stealing via pendingOffer bypass

    /// Reproduces audit finding #1: `handleRequest` checks `pool.macForIP(requestedIP)`
    /// (which looks at confirmed leases) but NOT `pendingOffers`. A second MAC can
    /// REQUEST an IP that was offered to a different MAC and steal it.
    ///
    /// Expected: MAC_B's REQUEST for an IP offered to MAC_A should be rejected (nil or NAK).
    /// Actual:   MAC_B gets an ACK and the IP is stolen.
    @Test func requestForPendingOfferFromDifferentMACStealsIP() {
        // /30 subnet: only .2 available. offerTimeout: 60 so offer doesn't expire.
        let subnet = IPv4Subnet(network: IPv4Address(100, 64, 1, 0), prefixLength: 30)
        let gateway = IPv4Address(100, 64, 1, 1)
        let hostMAC = MACAddress(0x00, 0x11, 0x22, 0x33, 0x44, 0x55)
        let macA = MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01)
        let macB = MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x02)
        let targetIP = IPv4Address(100, 64, 1, 2)

        var dhcp = DHCPServer(endpoints: [makeEndpoint(id: 1, subnet: subnet, gateway: gateway)], offerTimeout: 60)
        var arp = ARPMapping(hostMAC: hostMAC, endpoints: [makeEndpoint(id: 1, subnet: subnet, gateway: gateway)])
        let round = RoundContext()

        // Step 1: MAC_A DISCOVER → OFFER. IP X goes to pendingOffers[macA].
        let discover = DHCPPacket(op: 1, xid: 1, chaddr: macA,
                                  messageType: .discover, requestedIP: nil, serverIdentifier: nil)
        let offerResult = dhcp.process(packet: discover, srcMAC: macA, endpointID: 1,
                                        hostMAC: hostMAC, arpMapping: &arp, round: round)
        #expect(offerResult != nil, "DISCOVER from MAC_A should get OFFER")

        // Step 2: MAC_B REQUEST for same IP — should be REJECTED (IP is offered to MAC_A).
        // BUG: macForIP only checks leases[], not pendingOffers[] → check passes → ACK.
        let request = DHCPPacket(op: 1, xid: 2, chaddr: macB, messageType: .request,
                                  requestedIP: targetIP, serverIdentifier: gateway)
        let ackResult = dhcp.process(packet: request, srcMAC: macB, endpointID: 1,
                                      hostMAC: hostMAC, arpMapping: &arp, round: round)

        #expect(ackResult == nil,
            "AUDIT #1 FAIL: MAC_B stole IP \(targetIP) that was offered to MAC_A — pendingOffer MAC not verified")
    }

    @Test func fullDiscoverThenRequestFlow() {
        let subnet = IPv4Subnet(network: IPv4Address(100, 64, 1, 0), prefixLength: 24)
        let gateway = IPv4Address(100, 64, 1, 1)
        let clientMAC = MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF)
        let hostMAC = MACAddress(0x00, 0x11, 0x22, 0x33, 0x44, 0x55)

        var dhcp = DHCPServer(endpoints: [makeEndpoint(id: 1, subnet: subnet, gateway: gateway)])
        var arp = ARPMapping(hostMAC: hostMAC, endpoints: [makeEndpoint(id: 1, subnet: subnet, gateway: gateway)])
        let round = RoundContext()

        // Step 1: DISCOVER
        let discover = DHCPPacket(op: 1, xid: 42, chaddr: clientMAC, messageType: .discover, requestedIP: nil, serverIdentifier: nil)
        guard let (offerPkt, _) = dhcp.process(packet: discover, srcMAC: clientMAC, endpointID: 1, hostMAC: hostMAC, arpMapping: &arp, round: round),
              let offer = parseDHCPFromFrame(offerPkt) else {
            Issue.record("DISCOVER failed")
            return
        }
        #expect(offer.messageType == .offer)

        // Step 2: REQUEST for the offered IP (extracted from yiaddr field — we trust the server assigned one)
        let requestedIP = IPv4Address(100, 64, 1, 2)  // first available
        let request = DHCPPacket(op: 1, xid: 42, chaddr: clientMAC, messageType: .request,
                                  requestedIP: requestedIP, serverIdentifier: gateway)
        guard let (ackPkt, _) = dhcp.process(packet: request, srcMAC: clientMAC, endpointID: 1, hostMAC: hostMAC, arpMapping: &arp, round: round),
              let ack = parseDHCPFromFrame(ackPkt) else {
            Issue.record("REQUEST failed")
            return
        }
        #expect(ack.messageType == .ack)
        #expect(arp.isKnown(requestedIP))
    }

    // MARK: - ISSUE-3: DHCP lease expiry

    /// Reproduces audit finding ISSUE-3: `DHCPPool.leases` stores IP→MAC mappings
    /// with no deadline. A confirmed lease (ACK'd) never expires — only an explicit
    /// RELEASE reclaims the IP. If a client crashes without sending RELEASE, the IP
    /// is permanently leaked from the pool.
    ///
    /// Fix: leases now track `(mac, deadline)` and `reapExpiredLeases()` is called
    /// before every allocation. With `leaseTime: 0`, a confirmed lease expires
    /// immediately and the IP is available for the next DISCOVER.
    @Test func confirmedLeaseExpiresAfterLeaseTime() {
        // /30 subnet: only .2 available. leaseTime: 0 = instant expiry.
        let subnet = IPv4Subnet(network: IPv4Address(100, 64, 1, 0), prefixLength: 30)
        let gateway = IPv4Address(100, 64, 1, 1)
        let hostMAC = MACAddress(0x00, 0x11, 0x22, 0x33, 0x44, 0x55)
        let macA = MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01)
        let macB = MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x02)
        let targetIP = IPv4Address(100, 64, 1, 2)

        var dhcp = DHCPServer(endpoints: [makeEndpoint(id: 1, subnet: subnet, gateway: gateway)],
                              offerTimeout: 60, leaseTime: 0)
        var arp = ARPMapping(hostMAC: hostMAC, endpoints: [makeEndpoint(id: 1, subnet: subnet, gateway: gateway)])
        let round = RoundContext()

        // Step 1: MAC_A gets a confirmed lease via REQUEST.
        let request = DHCPPacket(op: 1, xid: 1, chaddr: macA, messageType: .request,
                                  requestedIP: targetIP, serverIdentifier: gateway)
        let ackResult = dhcp.process(packet: request, srcMAC: macA, endpointID: 1,
                                      hostMAC: hostMAC, arpMapping: &arp, round: round)
        #expect(ackResult != nil, "REQUEST from MAC_A should get ACK")
        #expect(arp.isKnown(targetIP), "target IP should be leased to MAC_A")

        // Step 2: MAC_B DISCOVER — should succeed because MAC_A's lease expired
        // (leaseTime=0 means the lease deadline was set to now() and
        // reapExpiredLeases() reclaims it in the next allocation).
        let discover = DHCPPacket(op: 1, xid: 2, chaddr: macB,
                                  messageType: .discover, requestedIP: nil, serverIdentifier: nil)
        let offerResult = dhcp.process(packet: discover, srcMAC: macB, endpointID: 1,
                                        hostMAC: hostMAC, arpMapping: &arp, round: round)

        #expect(offerResult != nil,
            "ISSUE-3 FAIL: confirmed lease for \(targetIP) did not expire — IP permanently leaked, MAC_B DISCOVER returned nil")
    }
}
