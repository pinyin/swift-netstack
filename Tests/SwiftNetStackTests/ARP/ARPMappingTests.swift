import Testing
@testable import SwiftNetStack

@Suite(.serialized)
struct ARPMappingTests {

    // MARK: - Initialization

    @Test func initPrepopulatesGatewayEntries() {
        let ep1 = VMEndpoint(id: 1, fd: 10, subnet: IPv4Subnet(network: IPv4Address(100, 64, 1, 0), prefixLength: 24), gateway: IPv4Address(100, 64, 1, 1))
        let ep2 = VMEndpoint(id: 2, fd: 11, subnet: IPv4Subnet(network: IPv4Address(100, 64, 2, 0), prefixLength: 24), gateway: IPv4Address(100, 64, 2, 1))
        let hostMAC = MACAddress(0x00, 0x11, 0x22, 0x33, 0x44, 0x55)

        let mapping = ARPMapping(hostMAC: hostMAC, endpoints: [ep1, ep2])

        #expect(mapping.isKnown(IPv4Address(100, 64, 1, 1)))
        #expect(mapping.isKnown(IPv4Address(100, 64, 2, 1)))
        #expect(mapping.lookup(ip: IPv4Address(100, 64, 1, 1)) == hostMAC)
        #expect(mapping.lookup(ip: IPv4Address(100, 64, 2, 1)) == hostMAC)
    }

    @Test func initEmptyEndpointsProducesEmptyMapping() {
        let mapping = ARPMapping(hostMAC: MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF), endpoints: [])
        #expect(!mapping.isKnown(IPv4Address(10, 0, 0, 1)))
    }

    // MARK: - Lookup

    @Test func lookupReturnsNilForUnknown() {
        let ep = VMEndpoint(id: 1, fd: 10, subnet: IPv4Subnet(network: IPv4Address(10, 0, 0, 0), prefixLength: 24), gateway: IPv4Address(10, 0, 0, 1))
        let mapping = ARPMapping(hostMAC: MACAddress(0x00, 0x11, 0x22, 0x33, 0x44, 0x55), endpoints: [ep])

        #expect(mapping.lookup(ip: IPv4Address(192, 168, 1, 100)) == nil)
    }

    @Test func lookupReturnsMACForKnown() {
        let ep = VMEndpoint(id: 1, fd: 10, subnet: IPv4Subnet(network: IPv4Address(10, 0, 0, 0), prefixLength: 24), gateway: IPv4Address(10, 0, 0, 1))
        var mapping = ARPMapping(hostMAC: MACAddress(0x00, 0x11, 0x22, 0x33, 0x44, 0x55), endpoints: [ep])

        let ip = IPv4Address(10, 0, 0, 50)
        let mac = MACAddress(0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01)
        mapping.add(ip: ip, mac: mac, endpointID: 1)

        #expect(mapping.lookup(ip: ip) == mac)
    }

    // MARK: - isKnown

    @Test func isKnownTrueForGateway() {
        let ep = VMEndpoint(id: 1, fd: 10, subnet: IPv4Subnet(network: IPv4Address(10, 0, 0, 0), prefixLength: 24), gateway: IPv4Address(10, 0, 0, 1))
        let mapping = ARPMapping(hostMAC: MACAddress(0x00, 0x11, 0x22, 0x33, 0x44, 0x55), endpoints: [ep])

        #expect(mapping.isKnown(IPv4Address(10, 0, 0, 1)))
    }

    @Test func isKnownFalseForUnknown() {
        let ep = VMEndpoint(id: 1, fd: 10, subnet: IPv4Subnet(network: IPv4Address(10, 0, 0, 0), prefixLength: 24), gateway: IPv4Address(10, 0, 0, 1))
        let mapping = ARPMapping(hostMAC: MACAddress(0x00, 0x11, 0x22, 0x33, 0x44, 0x55), endpoints: [ep])

        #expect(!mapping.isKnown(IPv4Address(10, 0, 0, 99)))
    }

    // MARK: - Add

    @Test func addInsertsNewEntry() {
        let ep = VMEndpoint(id: 1, fd: 10, subnet: IPv4Subnet(network: IPv4Address(10, 0, 0, 0), prefixLength: 24), gateway: IPv4Address(10, 0, 0, 1))
        var mapping = ARPMapping(hostMAC: MACAddress(0x00, 0x11, 0x22, 0x33, 0x44, 0x55), endpoints: [ep])

        let ip = IPv4Address(10, 0, 0, 100)
        let mac = MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF)
        mapping.add(ip: ip, mac: mac, endpointID: 1)

        #expect(mapping.isKnown(ip))
        #expect(mapping.lookup(ip: ip) == mac)
    }

    @Test func addUpdatesExistingEntry() {
        let ep = VMEndpoint(id: 1, fd: 10, subnet: IPv4Subnet(network: IPv4Address(10, 0, 0, 0), prefixLength: 24), gateway: IPv4Address(10, 0, 0, 1))
        var mapping = ARPMapping(hostMAC: MACAddress(0x00, 0x11, 0x22, 0x33, 0x44, 0x55), endpoints: [ep])

        let ip = IPv4Address(10, 0, 0, 1)  // the gateway
        let oldMAC = mapping.lookup(ip: ip)
        #expect(oldMAC != nil)

        let newMAC = MACAddress(0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA)
        mapping.add(ip: ip, mac: newMAC, endpointID: 2)

        #expect(mapping.lookup(ip: ip) == newMAC)
    }

    // MARK: - Remove

    @Test func removeDeletesEntry() {
        let ep = VMEndpoint(id: 1, fd: 10, subnet: IPv4Subnet(network: IPv4Address(10, 0, 0, 0), prefixLength: 24), gateway: IPv4Address(10, 0, 0, 1))
        var mapping = ARPMapping(hostMAC: MACAddress(0x00, 0x11, 0x22, 0x33, 0x44, 0x55), endpoints: [ep])

        let ip = IPv4Address(10, 0, 0, 50)
        mapping.add(ip: ip, mac: MACAddress(0x12, 0x22, 0x33, 0x44, 0x55, 0x66), endpointID: 1)
        #expect(mapping.isKnown(ip))

        mapping.remove(ip: ip)
        #expect(!mapping.isKnown(ip))
    }

    @Test func removeUnknownIsNoop() {
        let ep = VMEndpoint(id: 1, fd: 10, subnet: IPv4Subnet(network: IPv4Address(10, 0, 0, 0), prefixLength: 24), gateway: IPv4Address(10, 0, 0, 1))
        var mapping = ARPMapping(hostMAC: MACAddress(0x00, 0x11, 0x22, 0x33, 0x44, 0x55), endpoints: [ep])

        let countBefore = mapping.lookup(ip: IPv4Address(10, 0, 0, 1)) != nil
        mapping.remove(ip: IPv4Address(192, 168, 1, 1))
        // Gateway entry should still exist
        #expect(mapping.isKnown(IPv4Address(10, 0, 0, 1)) == countBefore)
    }

    // MARK: - Proxy ARP

    @Test func processARPRequestReturnsNilForUnknownTarget() {
        let ep = VMEndpoint(id: 1, fd: 10, subnet: IPv4Subnet(network: IPv4Address(10, 0, 0, 0), prefixLength: 24), gateway: IPv4Address(10, 0, 0, 1))
        let mapping = ARPMapping(hostMAC: MACAddress(0x00, 0x11, 0x22, 0x33, 0x44, 0x55), endpoints: [ep])
        let round = RoundContext()

        // Build an ARP request for an unknown IP
        let smac = MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF)
        let sip = IPv4Address(10, 0, 0, 50)
        let tip = IPv4Address(10, 0, 0, 99)  // unknown
        let arpPkt = makeARPPacket(op: .request, senderMAC: smac, senderIP: sip, targetMAC: .zero, targetIP: tip)
        guard let arp = ARPFrame.parse(from: arpPkt) else {
            Issue.record("failed to parse ARP packet")
            return
        }

        #expect(mapping.processARPRequest(arp, round: round) == nil)
    }

    @Test func processARPRequestGeneratesReplyForKnownTarget() {
        let ep = VMEndpoint(id: 1, fd: 10, subnet: IPv4Subnet(network: IPv4Address(10, 0, 0, 0), prefixLength: 24), gateway: IPv4Address(10, 0, 0, 1))
        let hostMAC = MACAddress(0x00, 0x11, 0x22, 0x33, 0x44, 0x55)
        let mapping = ARPMapping(hostMAC: hostMAC, endpoints: [ep])
        let round = RoundContext()

        let smac = MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF)
        let sip = IPv4Address(10, 0, 0, 50)
        let tip = IPv4Address(10, 0, 0, 1)  // the gateway, known
        let arpPkt = makeARPPacket(op: .request, senderMAC: smac, senderIP: sip, targetMAC: .zero, targetIP: tip)
        guard let arp = ARPFrame.parse(from: arpPkt) else {
            Issue.record("failed to parse ARP packet")
            return
        }

        let reply = mapping.processARPRequest(arp, round: round)
        #expect(reply != nil)
        guard let reply = reply else { return }

        // Reply should be exactly 42 bytes (14 Ethernet + 28 ARP)
        #expect(reply.totalLength == 42)

        // Parse the reply to verify its contents
        guard let replyEth = EthernetFrame.parse(from: reply) else {
            Issue.record("failed to parse reply Ethernet frame")
            return
        }
        #expect(replyEth.dstMAC == smac)       // reply to requester
        #expect(replyEth.srcMAC == hostMAC)      // from us
        #expect(replyEth.etherType == .arp)

        guard let replyARP = ARPFrame.parse(from: replyEth.payload) else {
            Issue.record("failed to parse reply ARP frame")
            return
        }
        #expect(replyARP.operation == .reply)
        #expect(replyARP.senderMAC == hostMAC)
        #expect(replyARP.senderIP == tip)       // we claim to be the target
        #expect(replyARP.targetMAC == smac)
        #expect(replyARP.targetIP == sip)
    }

    // MARK: - Helpers

    private func makeARPPacket(op: ARPOperation, senderMAC: MACAddress, senderIP: IPv4Address,
                                targetMAC: MACAddress, targetIP: IPv4Address) -> PacketBuffer {
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
        let s = Storage.allocate(capacity: 28)
        bytes.withUnsafeBytes { s.data.copyMemory(from: $0.baseAddress!, byteCount: 28) }
        return PacketBuffer(storage: s, offset: 0, length: 28)
    }
}
