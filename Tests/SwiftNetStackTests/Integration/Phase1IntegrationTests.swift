import Testing
import Darwin
@testable import SwiftNetStack

@Suite(.serialized)
struct Phase1IntegrationTests {

    let ourMAC = MACAddress(0x00, 0x11, 0x22, 0x33, 0x44, 0x55)
    let ourIP = IPv4Address(192, 168, 1, 1)

    // MARK: - Helpers

    func makeEthernet(dst: MACAddress, src: MACAddress, type: EtherType, payload: [UInt8]) -> PacketBuffer {
        var bytes: [UInt8] = []
        var buf6 = [UInt8](repeating: 0, count: 6)
        dst.write(to: &buf6); bytes.append(contentsOf: buf6)
        src.write(to: &buf6); bytes.append(contentsOf: buf6)
        let etRaw = type.rawValue
        bytes.append(UInt8(etRaw >> 8))
        bytes.append(UInt8(etRaw & 0xFF))
        bytes.append(contentsOf: payload)
        return PacketBuffer.from(bytes: bytes)
    }

    func makeIPv4Header(proto: IPProtocol, src: IPv4Address = IPv4Address(10, 0, 0, 1),
                        dst: IPv4Address = IPv4Address(192, 168, 1, 1),
                        totalLen: UInt16 = 20) -> [UInt8] {
        var bytes = [UInt8](repeating: 0, count: 20)
        bytes[0] = 0x45  // v4, ihl=5
        bytes[2] = UInt8(totalLen >> 8)
        bytes[3] = UInt8(totalLen & 0xFF)
        bytes[8] = 64  // TTL
        bytes[9] = proto.rawValue
        var ipBuf = [UInt8](repeating: 0, count: 4)
        src.write(to: &ipBuf); bytes.replaceSubrange(12..<16, with: ipBuf)
        dst.write(to: &ipBuf); bytes.replaceSubrange(16..<20, with: ipBuf)
        let cksum = bytes.withUnsafeBytes { internetChecksum($0) }
        bytes[10] = UInt8(cksum >> 8)
        bytes[11] = UInt8(cksum & 0xFF)
        return bytes
    }

    func makeICMPEchoRequest() -> [UInt8] {
        var bytes = [UInt8](repeating: 0, count: 8)
        bytes[0] = 8   // type = echo request
        bytes[1] = 0   // code = 0
        // checksum at 2-3
        bytes[6] = 0x12; bytes[7] = 0x34  // id + seq
        let cksum = bytes.withUnsafeBytes { internetChecksum($0) }
        bytes[2] = UInt8(cksum >> 8)
        bytes[3] = UInt8(cksum & 0xFF)
        return bytes
    }

    func makeARPRequest(senderMAC: MACAddress, senderIP: IPv4Address, targetIP: IPv4Address) -> [UInt8] {
        var bytes = [UInt8](repeating: 0, count: 28)
        bytes[0] = 0x00; bytes[1] = 0x01  // htype = Ethernet
        bytes[2] = 0x08; bytes[3] = 0x00  // ptype = IPv4
        bytes[4] = 6; bytes[5] = 4
        bytes[6] = 0x00; bytes[7] = 0x01  // request
        var buf6 = [UInt8](repeating: 0, count: 6)
        var buf4 = [UInt8](repeating: 0, count: 4)
        senderMAC.write(to: &buf6); bytes.replaceSubrange(8..<14, with: buf6)
        senderIP.write(to: &buf4); bytes.replaceSubrange(14..<18, with: buf4)
        MACAddress.zero.write(to: &buf6); bytes.replaceSubrange(18..<24, with: buf6)
        targetIP.write(to: &buf4); bytes.replaceSubrange(24..<28, with: buf4)
        return bytes
    }

    // MARK: - Full parse chain: Ethernet → IPv4 → ICMP

    @Test func parseFullICMPEchoRequest() {
        let remoteMAC = MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF)
        let remoteIP = IPv4Address(10, 0, 0, 1)

        let icmpPayload = makeICMPEchoRequest()
        let ipBytes = makeIPv4Header(proto: .icmp, src: remoteIP, dst: ourIP, totalLen: 28)
        let ipWithPayload = ipBytes + icmpPayload
        let pkt = makeEthernet(dst: ourMAC, src: remoteMAC, type: .ipv4, payload: ipWithPayload)

        // Layer 2
        guard let eth = EthernetFrame.parse(from: pkt) else {
            Issue.record("Ethernet parse failed")
            return
        }
        #expect(eth.dstMAC == ourMAC)
        #expect(eth.srcMAC == remoteMAC)
        #expect(eth.etherType == .ipv4)

        // Layer 3
        guard let ip = IPv4Header.parse(from: eth.payload) else {
            Issue.record("IPv4 parse failed")
            return
        }
        #expect(ip.version == 4)
        #expect(ip.protocol == .icmp)
        #expect(ip.srcAddr == remoteIP)
        #expect(ip.dstAddr == ourIP)
        #expect(ip.verifyChecksum() == true)

        // ICMP payload
        #expect(ip.payload.totalLength == 8)

        ip.payload.withUnsafeReadableBytes { buf in
            #expect(buf[0] == 8)  // type = echo request
            #expect(buf[1] == 0)  // code = 0
        }
    }

    // MARK: - ARP round-trip

    @Test func arpRequestReplyRoundTrip() {
        let requesterMAC = MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF)
        let requesterIP = IPv4Address(192, 168, 1, 100)

        // Build and parse incoming ARP request
        let arpBytes = makeARPRequest(senderMAC: requesterMAC, senderIP: requesterIP, targetIP: ourIP)
        let inPkt = makeEthernet(dst: .broadcast, src: requesterMAC, type: .arp, payload: arpBytes)

        guard let inEth = EthernetFrame.parse(from: inPkt) else {
            Issue.record("Failed to parse incoming Ethernet frame")
            return
        }
        guard let inARP = ARPFrame.parse(from: inEth.payload) else {
            Issue.record("Failed to parse incoming ARP frame")
            return
        }
        #expect(inARP.operation == .request)
        #expect(inARP.targetIP == ourIP)

        // Generate reply
        let round = RoundContext()
        let replies = ARPHandler.process(
            requests: [inARP], ourMAC: ourMAC, ourIP: ourIP, round: round
        )
        #expect(replies.count == 1)

        // Verify reply
        let outPkt = replies[0]
        guard let outEth = EthernetFrame.parse(from: outPkt) else {
            Issue.record("Failed to parse reply Ethernet frame")
            round.endRound()
            return
        }
        #expect(outEth.dstMAC == requesterMAC)
        #expect(outEth.srcMAC == ourMAC)
        #expect(outEth.etherType == .arp)

        guard let outARP = ARPFrame.parse(from: outEth.payload) else {
            Issue.record("Failed to parse reply ARP frame")
            round.endRound()
            return
        }
        #expect(outARP.operation == .reply)
        #expect(outARP.senderMAC == ourMAC)
        #expect(outARP.senderIP == ourIP)
        #expect(outARP.targetMAC == requesterMAC)
        #expect(outARP.targetIP == requesterIP)

        round.endRound()
    }

    // MARK: - Batch classification end-to-end

    @Test func batchClassificationE2E() {
        let remoteMAC = MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF)
        let remoteIP = IPv4Address(10, 0, 0, 1)

        var frames: [PacketBuffer] = []

        // ARP request
        frames.append(makeEthernet(
            dst: .broadcast, src: remoteMAC, type: .arp,
            payload: makeARPRequest(senderMAC: remoteMAC, senderIP: remoteIP, targetIP: ourIP)
        ))

        // IPv4 ICMP
        let icmpPayload = makeICMPEchoRequest()
        let icmpIP = makeIPv4Header(proto: .icmp, src: remoteIP, dst: ourIP, totalLen: 28)
        frames.append(makeEthernet(dst: ourMAC, src: remoteMAC, type: .ipv4, payload: icmpIP + icmpPayload))

        // IPv4 TCP
        frames.append(makeEthernet(
            dst: ourMAC, src: remoteMAC, type: .ipv4,
            payload: makeIPv4Header(proto: .tcp, src: remoteIP, dst: ourIP)
        ))

        // IPv4 UDP
        frames.append(makeEthernet(
            dst: .broadcast, src: remoteMAC, type: .ipv4,
            payload: makeIPv4Header(proto: .udp, src: remoteIP, dst: ourIP)
        ))

        // Classify all in one pass
        let classified = classifyFrames(frames, ourMAC: ourMAC)
        #expect(classified.totalCount == 4)
        #expect(classified.arp.count == 1)
        #expect(classified.ipv4ICMP.count == 1)
        #expect(classified.ipv4TCP.count == 1)
        #expect(classified.ipv4UDP.count == 1)
        #expect(classified.unknown.isEmpty)
    }

    // MARK: - FrameReader integration

    @Test func frameReaderReadsFrames() {
        // Create a socket pair for testing
        var fds: [Int32] = [0, 0]
        let rc = socketpair(AF_UNIX, SOCK_STREAM, 0, &fds)
        #expect(rc == 0)
        defer { close(fds[0]); close(fds[1]) }

        // Write a frame to one end
        let remoteMAC = MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF)
        let frame = makeEthernet(
            dst: ourMAC, src: remoteMAC, type: .ipv4,
            payload: makeIPv4Header(proto: .tcp)
        )
        frame.withUnsafeReadableBytes { buf in
            let written = Darwin.write(fds[1], buf.baseAddress, buf.count)
            #expect(written == buf.count)
        }
        close(fds[1])  // close write end so read() sees EOF instead of blocking

        // Read from the other end
        let round = RoundContext()
        let reader = FrameReader(mtu: 1500)
        let frames = reader.readAllFrames(from: fds[0], round: round)
        #expect(frames.count == 1, "Should read one frame")
        #expect(frames[0].totalLength == frame.totalLength)
        round.endRound()
    }
}
