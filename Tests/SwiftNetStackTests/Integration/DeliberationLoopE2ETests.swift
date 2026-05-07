import Testing
import Darwin
@testable import SwiftNetStack

@Suite(.serialized)
struct DeliberationLoopE2ETests {

    let hostMAC = MACAddress(0x00, 0x11, 0x22, 0x33, 0x44, 0x55)
    let subnet = IPv4Subnet(network: IPv4Address(100, 64, 1, 0), prefixLength: 24)
    let gateway = IPv4Address(100, 64, 1, 1)

    private func makeSocketPair() -> (hostFD: Int32, guestFD: Int32)? {
        var fds: [Int32] = [-1, -1]
        let rc = socketpair(AF_UNIX, SOCK_DGRAM, 0, &fds)
        guard rc == 0 else { return nil }
        return (fds[0], fds[1])
    }

    // Write raw bytes to fd. Returns bytes written.
    @discardableResult
    private func writeToFD(_ fd: Int32, _ bytes: [UInt8]) -> Int {
        bytes.withUnsafeBytes { Darwin.write(fd, $0.baseAddress!, bytes.count) }
    }

    // Read up to `maxLen` bytes from fd with a short timeout. Returns empty if timeout.
    private func readFromFD(_ fd: Int32, maxLen: Int = 2048) -> [UInt8] {
        var pfd = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
        let rc = Darwin.poll(&pfd, 1, 100)  // 100ms timeout
        guard rc > 0, pfd.revents & Int16(POLLIN) != 0 else { return [] }
        var buf = [UInt8](repeating: 0, count: maxLen)
        let n = Darwin.read(fd, &buf, maxLen)
        guard n > 0 else { return [] }
        return Array(buf[0..<n])
    }

    // MARK: - Single round ICMP

    @Test func icmpEchoE2E() {
        guard let (hostFD, guestFD) = makeSocketPair() else {
            Issue.record("socketpair failed: \(errno)")
            return
        }
        defer { close(hostFD); close(guestFD) }

        let ep = VMEndpoint(id: 1, fd: hostFD, subnet: subnet, gateway: gateway)
        var loop = DeliberationLoop(endpoints: [ep], hostMAC: hostMAC)
        var transport: any Transport = PollingTransport(endpoints: [ep])

        let clientMAC = MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF)
        let clientIP = IPv4Address(100, 64, 1, 50)

        // Write ICMP echo request via the socketpair (guest OS side)
        let icmpBytes = makeICMPEchoFrameBytes(dstMAC: hostMAC, clientMAC:clientMAC, clientIP: clientIP, dstIP: gateway, id: 0x42, seq: 1)
        writeToFD(guestFD, icmpBytes)

        let count = loop.runOneRound(transport: &transport)
        #expect(count == 1)

        // Read the reply from the guest side of the socketpair
        let reply = readFromFD(guestFD)
        #expect(!reply.isEmpty)
        guard !reply.isEmpty else { return }

        // Parse and verify
        let pkt = packetFrom(reply)
        guard let eth = EthernetFrame.parse(from: pkt) else {
            Issue.record("reply is not valid Ethernet")
            return
        }
        #expect(eth.dstMAC == clientMAC)
        #expect(eth.srcMAC == hostMAC)
        #expect(eth.etherType == .ipv4)

        guard let ip = IPv4Header.parse(from: eth.payload), ip.verifyChecksum() else {
            Issue.record("reply has invalid IPv4")
            return
        }
        #expect(ip.srcAddr == gateway)
        #expect(ip.dstAddr == clientIP)
        #expect(ip.protocol == .icmp)

        guard let icmp = ICMPHeader.parse(from: ip.payload) else {
            Issue.record("reply has invalid ICMP")
            return
        }
        #expect(icmp.type == 0)  // echo reply
        #expect(icmp.identifier == 0x42)
        #expect(icmp.sequenceNumber == 1)
    }

    // MARK: - Multi-round DHCP

    @Test func dhcpDiscoverOfferRequestAckE2E() {
        guard let (hostFD, guestFD) = makeSocketPair() else {
            Issue.record("socketpair failed: \(errno)")
            return
        }
        defer { close(hostFD); close(guestFD) }

        let ep = VMEndpoint(id: 1, fd: hostFD, subnet: subnet, gateway: gateway)
        var loop = DeliberationLoop(endpoints: [ep], hostMAC: hostMAC)
        var transport: any Transport = PollingTransport(endpoints: [ep])

        let clientMAC = MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF)

        // Round 1: DISCOVER → OFFER
        let discoverFrame = makeDHCPFrameBytes(dstMAC: hostMAC, clientMAC:clientMAC,
            dhcpPayload: makeDHCPPacketBytes(op: 1, xid: 0xABCD, chaddr: clientMAC, msgType: .discover))
        writeToFD(guestFD, discoverFrame)

        let count1 = loop.runOneRound(transport: &transport)
        #expect(count1 == 1)

        let offer = readFromFD(guestFD)
        #expect(!offer.isEmpty)
        guard !offer.isEmpty else { return }
        guard let offerDHCP = parseDHCPFromBytes(offer) else {
            Issue.record("OFFER is not valid DHCP")
            return
        }
        #expect(offerDHCP.messageType == .offer)
        #expect(offerDHCP.xid == 0xABCD)

        // Extract offered IP from DHCP payload (yiaddr at offset 16 in DHCP, which starts at byte 42)
        let offeredIP = IPv4Address(offer[58], offer[59], offer[60], offer[61])

        // Round 2: REQUEST → ACK
        let requestFrame = makeDHCPFrameBytes(dstMAC: hostMAC, clientMAC:clientMAC,
            dhcpPayload: makeDHCPPacketBytes(op: 1, xid: 0xABCE, chaddr: clientMAC, msgType: .request, extraOptions: [
                (50, ipBytes(offeredIP)),
                (54, ipBytes(gateway)),
            ]))
        writeToFD(guestFD, requestFrame)

        let count2 = loop.runOneRound(transport: &transport)
        #expect(count2 == 1)

        let ack = readFromFD(guestFD)
        #expect(!ack.isEmpty)
        guard !ack.isEmpty else { return }
        guard let ackDHCP = parseDHCPFromBytes(ack) else {
            Issue.record("ACK is not valid DHCP")
            return
        }
        #expect(ackDHCP.messageType == .ack)
        #expect(ackDHCP.xid == 0xABCE)

        // ARP mapping should now know the client
        #expect(loop.arpMapping.isKnown(offeredIP))
    }

    // MARK: - Mixed traffic

    @Test func mixedARPAndICMPE2E() {
        guard let (hostFD, guestFD) = makeSocketPair() else {
            Issue.record("socketpair failed: \(errno)")
            return
        }
        defer { close(hostFD); close(guestFD) }

        let ep = VMEndpoint(id: 1, fd: hostFD, subnet: subnet, gateway: gateway)
        var loop = DeliberationLoop(endpoints: [ep], hostMAC: hostMAC)
        var transport: any Transport = PollingTransport(endpoints: [ep])

        let clientMAC = MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF)
        let clientIP = IPv4Address(100, 64, 1, 50)

        // Write ARP request + ICMP echo request simultaneously
        let arpFrame = makeEthernetFrameBytes(
            dst: .broadcast, src: clientMAC, type: .arp,
            payload: makeARPPayload(op: .request, senderMAC: clientMAC, senderIP: clientIP, targetMAC: .zero, targetIP: gateway)
        )
        let icmpBytes = makeICMPEchoFrameBytes(dstMAC: hostMAC, clientMAC:clientMAC, clientIP: clientIP, dstIP: gateway, id: 1, seq: 1)
        writeToFD(guestFD, arpFrame)
        writeToFD(guestFD, icmpBytes)

        let count = loop.runOneRound(transport: &transport)
        #expect(count == 2)

        // Read both replies
        let reply1 = readFromFD(guestFD)
        let reply2 = readFromFD(guestFD)
        #expect(!reply1.isEmpty)
        #expect(!reply2.isEmpty)

        // One should be ARP, one should be ICMP
        var arpCount = 0, icmpCount = 0
        for reply in [reply1, reply2] {
            guard let eth = EthernetFrame.parse(from: packetFrom(reply)) else { continue }
            if eth.etherType == .arp { arpCount += 1 }
            if eth.etherType == .ipv4 { icmpCount += 1 }
        }
        #expect(arpCount == 1)
        #expect(icmpCount == 1)
    }

    // MARK: - Multi-guest (separate endpoints)

    @Test func twoGuestsEchoE2E() {
        guard let (hostFD1, guestFD1) = makeSocketPair(),
              let (hostFD2, guestFD2) = makeSocketPair() else {
            Issue.record("socketpair failed: \(errno)")
            return
        }
        defer { close(hostFD1); close(hostFD2); close(guestFD1); close(guestFD2) }

        let subnet1 = IPv4Subnet(network: IPv4Address(100, 64, 1, 0), prefixLength: 24)
        let gw1 = IPv4Address(100, 64, 1, 1)
        let subnet2 = IPv4Subnet(network: IPv4Address(100, 64, 2, 0), prefixLength: 24)
        let gw2 = IPv4Address(100, 64, 2, 1)

        let ep1 = VMEndpoint(id: 1, fd: hostFD1, subnet: subnet1, gateway: gw1)
        let ep2 = VMEndpoint(id: 2, fd: hostFD2, subnet: subnet2, gateway: gw2)

        var loop = DeliberationLoop(endpoints: [ep1, ep2], hostMAC: hostMAC)
        var transport: any Transport = PollingTransport(endpoints: [ep1, ep2])

        let mac1 = MACAddress(0xAA, 0x00, 0x00, 0x00, 0x00, 0x01)
        let mac2 = MACAddress(0xBA, 0x00, 0x00, 0x00, 0x00, 0x02)

        // Both guests send ICMP echo to their respective gateways
        let icmp1 = makeICMPEchoFrameBytes(dstMAC: hostMAC, clientMAC:mac1, clientIP: IPv4Address(100, 64, 1, 50), dstIP: gw1, id: 1, seq: 1)
        let icmp2 = makeICMPEchoFrameBytes(dstMAC: hostMAC, clientMAC:mac2, clientIP: IPv4Address(100, 64, 2, 50), dstIP: gw2, id: 2, seq: 1)
        writeToFD(guestFD1, icmp1)
        writeToFD(guestFD2, icmp2)

        let count = loop.runOneRound(transport: &transport)
        #expect(count == 2)

        let reply1 = readFromFD(guestFD1)
        let reply2 = readFromFD(guestFD2)
        #expect(!reply1.isEmpty)
        #expect(!reply2.isEmpty)

        // Each reply should be addressed to the correct guest MAC
        if let eth1 = EthernetFrame.parse(from: packetFrom(reply1)) {
            #expect(eth1.dstMAC == mac1)
            #expect(eth1.etherType == .ipv4)
        } else {
            Issue.record("reply1 is not valid Ethernet")
        }
        if let eth2 = EthernetFrame.parse(from: packetFrom(reply2)) {
            #expect(eth2.dstMAC == mac2)
            #expect(eth2.etherType == .ipv4)
        } else {
            Issue.record("reply2 is not valid Ethernet")
        }
    }

    // MARK: - Multi-container (shared endpoint)

    @Test func twoContainersBehindOneVME2E() {
        guard let (hostFD, guestFD) = makeSocketPair() else {
            Issue.record("socketpair failed: \(errno)")
            return
        }
        defer { close(hostFD); close(guestFD) }

        let ep = VMEndpoint(id: 1, fd: hostFD, subnet: subnet, gateway: gateway)
        var loop = DeliberationLoop(endpoints: [ep], hostMAC: hostMAC)
        var transport: any Transport = PollingTransport(endpoints: [ep])

        let mac1 = MACAddress(0xAA, 0x00, 0x00, 0x00, 0x00, 0x01)
        let ip1 = IPv4Address(100, 64, 1, 50)
        let mac2 = MACAddress(0xAA, 0x00, 0x00, 0x00, 0x00, 0x02)
        let ip2 = IPv4Address(100, 64, 1, 51)

        // Two containers behind the same VM endpoint send ICMP echo
        let icmp1 = makeICMPEchoFrameBytes(dstMAC: hostMAC, clientMAC:mac1, clientIP: ip1, dstIP: gateway, id: 1, seq: 1)
        let icmp2 = makeICMPEchoFrameBytes(dstMAC: hostMAC, clientMAC:mac2, clientIP: ip2, dstIP: gateway, id: 2, seq: 1)
        writeToFD(guestFD, icmp1)
        writeToFD(guestFD, icmp2)

        let count = loop.runOneRound(transport: &transport)
        #expect(count == 2)

        let reply1 = readFromFD(guestFD)
        let reply2 = readFromFD(guestFD)
        #expect(!reply1.isEmpty)
        #expect(!reply2.isEmpty)

        // Verify each reply reaches the correct container
        var seenMAC1 = false, seenMAC2 = false
        for reply in [reply1, reply2] {
            guard let eth = EthernetFrame.parse(from: packetFrom(reply)) else {
                Issue.record("reply is not valid Ethernet")
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

    @Test func batchStress100MixedFramesE2E() {
        guard let (hostFD, guestFD) = makeSocketPair() else {
            Issue.record("socketpair failed: \(errno)")
            return
        }
        defer { close(hostFD); close(guestFD) }

        let ep = VMEndpoint(id: 1, fd: hostFD, subnet: subnet, gateway: gateway)
        var loop = DeliberationLoop(endpoints: [ep], hostMAC: hostMAC)
        var transport: any Transport = PollingTransport(endpoints: [ep])

        let totalARP = 30
        let totalICMP = 30
        let totalDHCP = 40
        let totalFrames = totalARP + totalICMP + totalDHCP
        let batchSize = 10

        var arpReplies = 0, icmpReplies = 0, dhcpOffers = 0
        var totalReplies = 0

        /// Process one batch: write frames, one round drains all, then collect replies.
        func runBatch(frameCount: Int, buildFrame: (Int) -> [UInt8]) {
            // Write frames
            for i in 0..<frameCount {
                writeToFD(guestFD, buildFrame(i))
            }
            // One round drains all pending datagrams from hostFD (readPackets has drain loop)
            totalReplies += loop.runOneRound(transport: &transport)
            // Collect replies from guestFD to prevent buffer overflow
            for _ in 0..<frameCount {
                let reply = readFromFD(guestFD)
                guard !reply.isEmpty else { continue }
                guard let eth = EthernetFrame.parse(from: packetFrom(reply)) else { continue }
                switch eth.etherType {
                case .arp: arpReplies += 1
                case .ipv4:
                    guard let ip = IPv4Header.parse(from: eth.payload) else { continue }
                    switch ip.protocol {
                    case .icmp: icmpReplies += 1
                    case .udp:  dhcpOffers += 1
                    case .tcp: break
                    }
                @unknown default: break
                }
            }
        }

        // ARP batch
        for batchStart in stride(from: 0, to: totalARP, by: batchSize) {
            let end = min(batchStart + batchSize, totalARP)
            runBatch(frameCount: end - batchStart) { i in
                let idx = batchStart + i
                let mac = MACAddress(0xA0, 0x00, 0x00, 0x00, 0x00, UInt8(idx))
                let ip = IPv4Address(100, 64, 1, UInt8(10 + idx))
                return makeEthernetFrameBytes(
                    dst: .broadcast, src: mac, type: .arp,
                    payload: makeARPPayload(op: .request, senderMAC: mac, senderIP: ip, targetMAC: .zero, targetIP: gateway)
                )
            }
        }

        // ICMP batch
        for batchStart in stride(from: 0, to: totalICMP, by: batchSize) {
            let end = min(batchStart + batchSize, totalICMP)
            runBatch(frameCount: end - batchStart) { i in
                let idx = totalARP + batchStart + i
                let mac = MACAddress(0xA2, 0x00, 0x00, 0x00, 0x00, UInt8(idx))
                let ip = IPv4Address(100, 64, 1, UInt8(50 + batchStart + i))
                return makeICMPEchoFrameBytes(dstMAC: hostMAC, clientMAC:mac, clientIP: ip, dstIP: gateway, id: UInt16(idx + 1), seq: 1)
            }
        }

        // DHCP batch
        for batchStart in stride(from: 0, to: totalDHCP, by: batchSize) {
            let end = min(batchStart + batchSize, totalDHCP)
            runBatch(frameCount: end - batchStart) { i in
                let idx = totalARP + totalICMP + batchStart + i
                let mac = MACAddress(0xA2, 0x00, 0x00, 0x00, 0x00, UInt8(idx))
                return makeDHCPFrameBytes(dstMAC: hostMAC, clientMAC:mac,
                    dhcpPayload: makeDHCPPacketBytes(op: 1, xid: UInt32(1000 + batchStart + i), chaddr: mac, msgType: .discover))
            }
        }

        // Drain any remaining replies from guestFD (non-blocking poll, may timeout)
        for _ in 0..<totalFrames {
            let reply = readFromFD(guestFD)
            guard !reply.isEmpty else { continue }
            guard let eth = EthernetFrame.parse(from: packetFrom(reply)) else { continue }
            switch eth.etherType {
            case .arp: arpReplies += 1
            case .ipv4:
                guard let ip = IPv4Header.parse(from: eth.payload) else { continue }
                switch ip.protocol {
                case .icmp: icmpReplies += 1
                case .udp:  dhcpOffers += 1
                case .tcp: break
                }
            @unknown default: break
            }
        }

        #expect(totalReplies == totalFrames)
        #expect(arpReplies == totalARP)
        #expect(icmpReplies == totalICMP)
        #expect(dhcpOffers == totalDHCP)
    }

}