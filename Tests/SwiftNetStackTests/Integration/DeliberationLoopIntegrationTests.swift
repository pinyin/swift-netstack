import Testing
@testable import SwiftNetStack

@Suite(.serialized)
struct DeliberationLoopIntegrationTests {

    let hostMAC = MACAddress(0x00, 0x11, 0x22, 0x33, 0x44, 0x55)
    let subnet = IPv4Subnet(network: IPv4Address(100, 64, 1, 0), prefixLength: 24)
    let gateway = IPv4Address(100, 64, 1, 1)

    func makeEndpoint(id: Int = 1) -> VMEndpoint {
        VMEndpoint(id: id, fd: Int32(id + 100), subnet: subnet, gateway: gateway, mtu: 1500)
    }

    // MARK: - VM boot sequence

    @Test func vmBootSequenceAcrossRounds() {
        let ep = makeEndpoint()
        let clientMAC = MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF)
        let clientIP = IPv4Address(100, 64, 1, 50)

        var loop = DeliberationLoop(endpoints: [ep], hostMAC: hostMAC)

        // Round 1: DHCP DISCOVER → OFFER
        let discoverFrame = makeDHCPFrame(clientMAC: clientMAC, dstMAC: hostMAC,
            dhcpPayload: makeDHCPPacketBytes(op: 1, xid: 1, chaddr: clientMAC, msgType: .discover))
        var transport1: any Transport = InMemoryTransport(inputs: [(endpointID: 1, packet: discoverFrame)])
        let count1 = loop.runOneRound(transport: &transport1)
        #expect(count1 == 1)
        #expect(!(transport1 as! InMemoryTransport).outputs.isEmpty)

        // Round 2: DHCP REQUEST → ACK
        let requestFrame = makeDHCPFrame(clientMAC: clientMAC, dstMAC: hostMAC,
            dhcpPayload: makeDHCPPacketBytes(op: 1, xid: 2, chaddr: clientMAC, msgType: .request, extraOptions: [
                (50, ipBytes(clientIP)),
                (54, ipBytes(gateway)),
            ]))
        var transport2: any Transport = InMemoryTransport(inputs: [(endpointID: 1, packet: requestFrame)])
        let count2 = loop.runOneRound(transport: &transport2)
        #expect(count2 == 1)

        // After DHCP ACK, ARP mapping should know the client
        #expect(loop.arpMapping.isKnown(clientIP))

        // Round 3: ARP request for gateway → proxy reply
        let arpFrame = makeEthernetFrame(
            dst: .broadcast, src: clientMAC, type: .arp,
            payload: makeARPPayload(op: .request, senderMAC: clientMAC, senderIP: clientIP, targetMAC: .zero, targetIP: gateway)
        )
        var transport3: any Transport = InMemoryTransport(inputs: [(endpointID: 1, packet: arpFrame)])
        let count3 = loop.runOneRound(transport: &transport3)
        #expect(count3 == 1)

        // Round 4: ICMP echo request → reply
        let icmpFrame = makeICMPEchoFrame(clientMAC: clientMAC, clientIP: clientIP, dstIP: gateway, id: 0x42, seq: 0x0001)
        var transport4: any Transport = InMemoryTransport(inputs: [(endpointID: 1, packet: icmpFrame)])
        let count4 = loop.runOneRound(transport: &transport4)
        #expect(count4 == 1)
    }

    // MARK: - Multi-VM

    @Test func twoVMsGetDifferentReplies() {
        let ep1 = VMEndpoint(id: 1, fd: 101, subnet: subnet, gateway: gateway)
        let ep2 = VMEndpoint(id: 2, fd: 102, subnet: subnet, gateway: gateway)
        let mac1 = MACAddress(0xAA, 0x00, 0x00, 0x00, 0x00, 0x01)
        let mac2 = MACAddress(0xAA, 0x00, 0x00, 0x00, 0x00, 0x02)

        var loop = DeliberationLoop(endpoints: [ep1, ep2], hostMAC: hostMAC)

        // Both VMs send DHCP DISCOVER simultaneously
        let discover1 = makeDHCPFrame(clientMAC: mac1, dstMAC: hostMAC,
            dhcpPayload: makeDHCPPacketBytes(op: 1, xid: 1, chaddr: mac1, msgType: .discover))
        let discover2 = makeDHCPFrame(clientMAC: mac2, dstMAC: hostMAC,
            dhcpPayload: makeDHCPPacketBytes(op: 1, xid: 2, chaddr: mac2, msgType: .discover))
        var transport1: any Transport = InMemoryTransport(inputs: [
            (endpointID: 1, packet: discover1),
            (endpointID: 2, packet: discover2),
        ])
        loop.runOneRound(transport: &transport1)

        // Both should get OFFER replies, routed to the correct endpoint
        #expect((transport1 as! InMemoryTransport).outputs.count == 2)
        let epIDs = Set((transport1 as! InMemoryTransport).outputs.map(\.endpointID))
        #expect(epIDs == Set([1, 2]))
    }

    // MARK: - Multi-container (shared endpoint)

    @Test func twoContainersBehindOneVM() {
        let ep = makeEndpoint()
        let mac1 = MACAddress(0xAA, 0x00, 0x00, 0x00, 0x00, 0x01)
        let mac2 = MACAddress(0xAA, 0x00, 0x00, 0x00, 0x00, 0x02)
        let ip1 = IPv4Address(100, 64, 1, 50)
        let ip2 = IPv4Address(100, 64, 1, 51)

        var loop = DeliberationLoop(endpoints: [ep], hostMAC: hostMAC)

        // Two containers behind the same endpoint send ICMP echo
        let icmp1 = makeICMPEchoFrame(clientMAC: mac1, clientIP: ip1, dstIP: gateway, id: 1, seq: 1)
        let icmp2 = makeICMPEchoFrame(clientMAC: mac2, clientIP: ip2, dstIP: gateway, id: 2, seq: 1)
        var transport: any Transport = InMemoryTransport(inputs: [
            (endpointID: 1, packet: icmp1),
            (endpointID: 1, packet: icmp2),
        ])
        let count = loop.runOneRound(transport: &transport)
        #expect(count == 2)

        let outputs = (transport as! InMemoryTransport).outputs
        #expect(outputs.count == 2)

        // Each reply should be addressed to the correct container MAC
        var seenMAC1 = false, seenMAC2 = false
        for out in outputs {
            #expect(out.endpointID == 1)
            guard let eth = EthernetFrame.parse(from: out.packet) else {
                Issue.record("output is not valid Ethernet")
                continue
            }
            #expect(eth.etherType == .ipv4)
            if eth.dstMAC == mac1 { seenMAC1 = true }
            if eth.dstMAC == mac2 { seenMAC2 = true }
        }
        #expect(seenMAC1)
        #expect(seenMAC2)
    }

    // MARK: - Batch stress (verifies BDP phase batching)

    @Test func batchStress100MixedFrames() {
        let ep = makeEndpoint()

        let totalARP = 30
        let totalICMP = 30
        let totalDHCP = 40
        var inputs: [(endpointID: Int, packet: PacketBuffer)] = []

        for i in 0..<totalARP {
            let mac = MACAddress(0xA1, 0x00, 0x00, 0x00, 0x00, UInt8(i))
            let ip = IPv4Address(100, 64, 1, UInt8(10 + i))
            let frame = makeEthernetFrame(
                dst: .broadcast, src: mac, type: .arp,
                payload: makeARPPayload(op: .request, senderMAC: mac, senderIP: ip, targetMAC: .zero, targetIP: gateway)
            )
            inputs.append((endpointID: 1, packet: frame))
        }
        for i in 0..<totalICMP {
            let idx = UInt8(totalARP + i)
            let mac = MACAddress(0xA2, 0x00, 0x00, 0x00, 0x00, idx)
            let ip = IPv4Address(100, 64, 1, UInt8(50 + i))
            let frame = makeICMPEchoFrame(clientMAC: mac, clientIP: ip, dstIP: gateway, id: 0x42, seq: 0x0001)
            inputs.append((endpointID: 1, packet: frame))
        }
        for i in 0..<totalDHCP {
            let idx = UInt8(totalARP + totalICMP + i)
            let mac = MACAddress(0xA3, 0x00, 0x00, 0x00, 0x00, idx)
            let frame = makeDHCPFrame(clientMAC: mac, dstMAC: hostMAC,
                dhcpPayload: makeDHCPPacketBytes(op: 1, xid: UInt32(1000 + i), chaddr: mac, msgType: .discover))
            inputs.append((endpointID: 1, packet: frame))
        }

        var transport: any Transport = InMemoryTransport(inputs: inputs)
        var loop = DeliberationLoop(endpoints: [ep], hostMAC: hostMAC)
        let count = loop.runOneRound(transport: &transport)
        #expect(count == inputs.count)

        let outputs = (transport as! InMemoryTransport).outputs
        #expect(outputs.count == inputs.count)

        var arpReplies = 0, icmpReplies = 0, dhcpOffers = 0
        for out in outputs {
            guard let eth = EthernetFrame.parse(from: out.packet) else { continue }
            switch eth.etherType {
            case .arp: arpReplies += 1
            case .ipv4:
                guard let ip = IPv4Header.parse(from: eth.payload) else { continue }
                switch ip.protocol {
                case .icmp: icmpReplies += 1
                case .udp: dhcpOffers += 1
                case .tcp: break
                @unknown default: break
                }
            @unknown default: break
            }
        }
        #expect(arpReplies == totalARP)
        #expect(icmpReplies == totalICMP)
        #expect(dhcpOffers == totalDHCP)
    }

    // MARK: - Cross-round state

    @Test func leasePersistsAfterManyEmptyRounds() {
        let ep = makeEndpoint()
        let clientMAC = MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF)
        let clientIP = IPv4Address(100, 64, 1, 50)

        var loop = DeliberationLoop(endpoints: [ep], hostMAC: hostMAC)

        // Allocate lease
        let requestFrame = makeDHCPFrame(clientMAC: clientMAC, dstMAC: hostMAC,
            dhcpPayload: makeDHCPPacketBytes(op: 1, xid: 1, chaddr: clientMAC, msgType: .request, extraOptions: [
                (50, ipBytes(clientIP)),
                (54, ipBytes(gateway)),
            ]))
        var t1: any Transport = InMemoryTransport(inputs: [(endpointID: 1, packet: requestFrame)])
        loop.runOneRound(transport: &t1)
        #expect(loop.arpMapping.isKnown(clientIP))

        // Run several empty rounds — lease should persist
        for _ in 0..<5 {
            var t: any Transport = InMemoryTransport()
            loop.runOneRound(transport: &t)
        }
        #expect(loop.arpMapping.isKnown(clientIP))
    }

    // MARK: - Empty input

    @Test func emptyInputReturnsZero() {
        let ep = makeEndpoint()
        var loop = DeliberationLoop(endpoints: [ep], hostMAC: hostMAC)

        var transport: any Transport = InMemoryTransport()
        let count = loop.runOneRound(transport: &transport)
        #expect(count == 0)
    }

    // MARK: - Pool exhaustion

    @Test func poolExhaustionReturnsNilForDiscover() {
        // /30 subnet: only 2 usable IPs (network + broadcast + gateway consume 3, leaving 1)
        let smallSubnet = IPv4Subnet(network: IPv4Address(100, 64, 1, 0), prefixLength: 30)
        let smallGW = IPv4Address(100, 64, 1, 1)
        let ep = VMEndpoint(id: 1, fd: 101, subnet: smallSubnet, gateway: smallGW)

        var loop = DeliberationLoop(endpoints: [ep], hostMAC: hostMAC)

        // First VM gets the only available IP
        let mac1 = MACAddress(0xAA, 0x00, 0x00, 0x00, 0x00, 0x01)
        let request1 = makeDHCPFrame(clientMAC: mac1, dstMAC: hostMAC,
            dhcpPayload: makeDHCPPacketBytes(op: 1, xid: 1, chaddr: mac1, msgType: .request, extraOptions: [
                (50, ipBytes(IPv4Address(100, 64, 1, 2))),
                (54, ipBytes(smallGW)),
            ]))
        var t1: any Transport = InMemoryTransport(inputs: [(endpointID: 1, packet: request1)])
        loop.runOneRound(transport: &t1)

        // Second VM's DISCOVER should get no reply (pool exhausted)
        let mac2 = MACAddress(0xBB, 0x00, 0x00, 0x00, 0x00, 0x01)
        let discover2 = makeDHCPFrame(clientMAC: mac2, dstMAC: hostMAC,
            dhcpPayload: makeDHCPPacketBytes(op: 1, xid: 2, chaddr: mac2, msgType: .discover))
        var t2: any Transport = InMemoryTransport(inputs: [(endpointID: 1, packet: discover2)])
        let count2 = loop.runOneRound(transport: &t2)
        #expect(count2 == 0)
    }

    // MARK: - Helpers

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

    private func makeDHCPFrame(clientMAC: MACAddress, dstMAC: MACAddress, dhcpPayload: [UInt8]) -> PacketBuffer {
        let udpLen = 8 + dhcpPayload.count
        let ipTotalLen = 20 + udpLen

        var ipBytes = [UInt8](repeating: 0, count: 20)
        ipBytes[0] = 0x45
        ipBytes[2] = UInt8(ipTotalLen >> 8)
        ipBytes[3] = UInt8(ipTotalLen & 0xFF)
        ipBytes[8] = 64
        ipBytes[9] = IPProtocol.udp.rawValue
        IPv4Address(10, 0, 0, 50).write(to: &ipBytes[12])
        IPv4Address(100, 64, 1, 1).write(to: &ipBytes[16])
        let ipCksum = ipBytes.withUnsafeBytes { internetChecksum($0) }
        ipBytes[10] = UInt8(ipCksum >> 8)
        ipBytes[11] = UInt8(ipCksum & 0xFF)

        var udpBytes = [UInt8](repeating: 0, count: 8)
        udpBytes[0] = 0x00; udpBytes[1] = 68
        udpBytes[2] = 0x00; udpBytes[3] = 67
        udpBytes[4] = UInt8(udpLen >> 8)
        udpBytes[5] = UInt8(udpLen & 0xFF)

        return makeEthernetFrame(
            dst: dstMAC, src: clientMAC, type: .ipv4,
            payload: ipBytes + udpBytes + dhcpPayload
        )
    }

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
        bytes[240] = 99; bytes[241] = 130; bytes[242] = 83; bytes[243] = 99
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

    private func makeICMPEchoFrame(clientMAC: MACAddress, clientIP: IPv4Address, dstIP: IPv4Address, id: UInt16, seq: UInt16, payload: [UInt8] = [0x70, 0x69, 0x6E, 0x67]) -> PacketBuffer {
        let icmpLen = 8 + payload.count
        let ipTotalLen = 20 + icmpLen

        var icmpBytes: [UInt8] = []
        icmpBytes.append(8); icmpBytes.append(0)
        icmpBytes.append(0); icmpBytes.append(0)
        icmpBytes.append(UInt8(id >> 8)); icmpBytes.append(UInt8(id & 0xFF))
        icmpBytes.append(UInt8(seq >> 8)); icmpBytes.append(UInt8(seq & 0xFF))
        icmpBytes.append(contentsOf: payload)
        let icmpCksum = icmpBytes.withUnsafeBytes { internetChecksum($0) }
        icmpBytes[2] = UInt8(icmpCksum >> 8)
        icmpBytes[3] = UInt8(icmpCksum & 0xFF)

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
            dst: hostMAC, src: clientMAC, type: .ipv4,
            payload: ipBytes + icmpBytes
        )
    }
}
