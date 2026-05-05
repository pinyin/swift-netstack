import Testing
import Darwin
@testable import SwiftNetStack

@Suite(.serialized)
struct DeliberationLoopE2ETests {

    let ourMAC = MACAddress(0x00, 0x11, 0x22, 0x33, 0x44, 0x55)
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
        var loop = DeliberationLoop(endpoints: [ep], ourMAC: ourMAC)
        var transport: any Transport = PollingTransport(endpoints: [ep])

        let clientMAC = MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF)
        let clientIP = IPv4Address(100, 64, 1, 50)

        // Write ICMP echo request via the socketpair (guest OS side)
        let icmpBytes = makeICMPEchoFrame(clientMAC: clientMAC, clientIP: clientIP, dstIP: gateway, id: 0x42, seq: 1)
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
        #expect(eth.srcMAC == ourMAC)
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
        var loop = DeliberationLoop(endpoints: [ep], ourMAC: ourMAC)
        var transport: any Transport = PollingTransport(endpoints: [ep])

        let clientMAC = MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF)

        // Round 1: DISCOVER → OFFER
        let discoverFrame = makeDHCPFrame(clientMAC: clientMAC,
            dhcpPayload: makeDHCPPacketBytes(op: 1, xid: 0xABCD, chaddr: clientMAC, msgType: .discover))
        writeToFD(guestFD, discoverFrame)

        let count1 = loop.runOneRound(transport: &transport)
        #expect(count1 == 1)

        let offer = readFromFD(guestFD)
        #expect(!offer.isEmpty)
        guard !offer.isEmpty else { return }
        guard let offerDHCP = DHCPPacket.parse(from: packetFrom(offer)) else {
            Issue.record("OFFER is not valid DHCP")
            return
        }
        #expect(offerDHCP.messageType == .offer)
        #expect(offerDHCP.xid == 0xABCD)

        // Extract offered IP from the raw packet (yiaddr at offset 16)
        let offeredIP = IPv4Address(offer[16], offer[17], offer[18], offer[19])

        // Round 2: REQUEST → ACK
        let requestFrame = makeDHCPFrame(clientMAC: clientMAC,
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
        guard let ackDHCP = DHCPPacket.parse(from: packetFrom(ack)) else {
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
        var loop = DeliberationLoop(endpoints: [ep], ourMAC: ourMAC)
        var transport: any Transport = PollingTransport(endpoints: [ep])

        let clientMAC = MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF)
        let clientIP = IPv4Address(100, 64, 1, 50)

        // Write ARP request + ICMP echo request simultaneously
        let arpFrame = makeEthernetFrameBytes(
            dst: .broadcast, src: clientMAC, type: .arp,
            payload: makeARPPayload(op: .request, senderMAC: clientMAC, senderIP: clientIP, targetMAC: .zero, targetIP: gateway)
        )
        let icmpBytes = makeICMPEchoFrame(clientMAC: clientMAC, clientIP: clientIP, dstIP: gateway, id: 1, seq: 1)
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

        var loop = DeliberationLoop(endpoints: [ep1, ep2], ourMAC: ourMAC)
        var transport: any Transport = PollingTransport(endpoints: [ep1, ep2])

        let mac1 = MACAddress(0xAA, 0x00, 0x00, 0x00, 0x00, 0x01)
        let mac2 = MACAddress(0xBB, 0x00, 0x00, 0x00, 0x00, 0x02)

        // Both guests send ICMP echo to their respective gateways
        let icmp1 = makeICMPEchoFrame(clientMAC: mac1, clientIP: IPv4Address(100, 64, 1, 50), dstIP: gw1, id: 1, seq: 1)
        let icmp2 = makeICMPEchoFrame(clientMAC: mac2, clientIP: IPv4Address(100, 64, 2, 50), dstIP: gw2, id: 2, seq: 1)
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
        var loop = DeliberationLoop(endpoints: [ep], ourMAC: ourMAC)
        var transport: any Transport = PollingTransport(endpoints: [ep])

        let mac1 = MACAddress(0xAA, 0x00, 0x00, 0x00, 0x00, 0x01)
        let ip1 = IPv4Address(100, 64, 1, 50)
        let mac2 = MACAddress(0xAA, 0x00, 0x00, 0x00, 0x00, 0x02)
        let ip2 = IPv4Address(100, 64, 1, 51)

        // Two containers behind the same VM endpoint send ICMP echo
        let icmp1 = makeICMPEchoFrame(clientMAC: mac1, clientIP: ip1, dstIP: gateway, id: 1, seq: 1)
        let icmp2 = makeICMPEchoFrame(clientMAC: mac2, clientIP: ip2, dstIP: gateway, id: 2, seq: 1)
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

    // MARK: - Helpers

    private func packetFrom(_ bytes: [UInt8]) -> PacketBuffer {
        let s = Storage.allocate(capacity: bytes.count)
        bytes.withUnsafeBytes { s.data.copyMemory(from: $0.baseAddress!, byteCount: bytes.count) }
        return PacketBuffer(storage: s, offset: 0, length: bytes.count)
    }

    private func ipBytes(_ ip: IPv4Address) -> [UInt8] {
        var buf = [UInt8](repeating: 0, count: 4)
        ip.write(to: &buf)
        return buf
    }

    private func makeEthernetFrameBytes(dst: MACAddress, src: MACAddress, type: EtherType, payload: [UInt8]) -> [UInt8] {
        var bytes: [UInt8] = []
        var buf6 = [UInt8](repeating: 0, count: 6)
        dst.write(to: &buf6); bytes.append(contentsOf: buf6)
        src.write(to: &buf6); bytes.append(contentsOf: buf6)
        let etRaw = type.rawValue
        bytes.append(UInt8(etRaw >> 8))
        bytes.append(UInt8(etRaw & 0xFF))
        bytes.append(contentsOf: payload)
        return bytes
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

    private func makeDHCPFrame(clientMAC: MACAddress, dhcpPayload: [UInt8]) -> [UInt8] {
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

        return makeEthernetFrameBytes(
            dst: ourMAC, src: clientMAC, type: .ipv4,
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

    private func makeICMPEchoFrame(clientMAC: MACAddress, clientIP: IPv4Address, dstIP: IPv4Address, id: UInt16, seq: UInt16, payload: [UInt8] = [0x70, 0x69, 0x6E, 0x67]) -> [UInt8] {
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

        var ipBytesArr = [UInt8](repeating: 0, count: 20)
        ipBytesArr[0] = 0x45
        ipBytesArr[2] = UInt8(ipTotalLen >> 8)
        ipBytesArr[3] = UInt8(ipTotalLen & 0xFF)
        ipBytesArr[8] = 64
        ipBytesArr[9] = IPProtocol.icmp.rawValue
        clientIP.write(to: &ipBytesArr[12])
        dstIP.write(to: &ipBytesArr[16])
        let ipCksum = ipBytesArr.withUnsafeBytes { internetChecksum($0) }
        ipBytesArr[10] = UInt8(ipCksum >> 8)
        ipBytesArr[11] = UInt8(ipCksum & 0xFF)

        return makeEthernetFrameBytes(
            dst: ourMAC, src: clientMAC, type: .ipv4,
            payload: ipBytesArr + icmpBytes
        )
    }
}