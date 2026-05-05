import Testing
@testable import SwiftNetStack

@Suite(.serialized)
struct ClassifierTests {

    let ourMAC = MACAddress(0x00, 0x11, 0x22, 0x33, 0x44, 0x55)

    // MARK: - Helpers

    func makeEthernet(dst: MACAddress, src: MACAddress, type: EtherType, payload: [UInt8]) -> PacketBuffer {
        var bytes: [UInt8] = []
        var dstBuf = [UInt8](repeating: 0, count: 6)
        var srcBuf = [UInt8](repeating: 0, count: 6)
        dstBuf.withUnsafeMutableBytes { dst.write(to: $0.baseAddress!) }
        srcBuf.withUnsafeMutableBytes { src.write(to: $0.baseAddress!) }
        bytes.append(contentsOf: dstBuf)
        bytes.append(contentsOf: srcBuf)
        let etRaw = type.rawValue
        bytes.append(UInt8(etRaw >> 8))
        bytes.append(UInt8(etRaw & 0xFF))
        bytes.append(contentsOf: payload)
        return PacketBuffer.from(bytes: bytes)
    }

    func makeIPv4Bytes(protocol: IPProtocol, src: IPv4Address = IPv4Address(10, 0, 0, 1), dst: IPv4Address = IPv4Address(192, 168, 1, 1)) -> [UInt8] {
        var bytes = [UInt8](repeating: 0, count: 20)
        bytes[0] = 0x45  // v4, ihl=5
        bytes[2] = 0x00; bytes[3] = 20  // totalLength
        bytes[8] = 64  // TTL
        bytes[9] = `protocol`.rawValue
        var srcBuf = [UInt8](repeating: 0, count: 4)
        var dstBuf = [UInt8](repeating: 0, count: 4)
        srcBuf.withUnsafeMutableBytes { src.write(to: $0.baseAddress!) }
        dstBuf.withUnsafeMutableBytes { dst.write(to: $0.baseAddress!) }
        bytes.replaceSubrange(12..<16, with: srcBuf)
        bytes.replaceSubrange(16..<20, with: dstBuf)

        // Checksum
        let cksum = bytes.withUnsafeBytes { internetChecksum($0) }
        bytes[10] = UInt8(cksum >> 8)
        bytes[11] = UInt8(cksum & 0xFF)
        return bytes
    }

    // MARK: - Classification

    @Test func classifyEmptyBatch() {
        let result = classifyFrames([], ourMAC: ourMAC)
        #expect(result.totalCount == 0)
    }

    @Test func classifyARPRequest() {
        // Build ARP request bytes targeting our IP
        let senderMAC = MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF)
        let senderIP = IPv4Address(192, 168, 1, 100)
        let targetIP = IPv4Address(192, 168, 1, 1)

        var arpBytes = [UInt8](repeating: 0, count: 28)
        arpBytes[0] = 0x00; arpBytes[1] = 0x01  // htype = Ethernet
        arpBytes[2] = 0x08; arpBytes[3] = 0x00  // ptype = IPv4
        arpBytes[4] = 6; arpBytes[5] = 4
        arpBytes[6] = 0x00; arpBytes[7] = 0x01  // request
        var macBuf = [UInt8](repeating: 0, count: 6)
        var ipBuf = [UInt8](repeating: 0, count: 4)
        senderMAC.write(to: &macBuf); arpBytes.replaceSubrange(8..<14, with: macBuf)
        senderIP.write(to: &ipBuf); arpBytes.replaceSubrange(14..<18, with: ipBuf)
        MACAddress.zero.write(to: &macBuf); arpBytes.replaceSubrange(18..<24, with: macBuf)
        targetIP.write(to: &ipBuf); arpBytes.replaceSubrange(24..<28, with: ipBuf)

        let pkt = makeEthernet(dst: ourMAC, src: senderMAC, type: .arp, payload: arpBytes)

        let result = classifyFrames([pkt], ourMAC: ourMAC)
        #expect(result.arp.count == 1)
        #expect(result.ipv4ICMP.isEmpty)
        #expect(result.unknown.isEmpty)
        #expect(result.totalCount == 1)
    }

    @Test func classifyIPv4ICMP() {
        let srcMAC = MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF)
        let ipBytes = makeIPv4Bytes(protocol: .icmp)
        let pkt = makeEthernet(dst: ourMAC, src: srcMAC, type: .ipv4, payload: ipBytes)

        let result = classifyFrames([pkt], ourMAC: ourMAC)
        #expect(result.arp.isEmpty)
        #expect(result.ipv4ICMP.count == 1)
        #expect(result.ipv4TCP.isEmpty)
        #expect(result.ipv4UDP.isEmpty)
        #expect(result.totalCount == 1)
    }

    @Test func classifyIPv4TCP() {
        let srcMAC = MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF)
        let ipBytes = makeIPv4Bytes(protocol: .tcp)
        let pkt = makeEthernet(dst: ourMAC, src: srcMAC, type: .ipv4, payload: ipBytes)

        let result = classifyFrames([pkt], ourMAC: ourMAC)
        #expect(result.ipv4TCP.count == 1)
        #expect(result.totalCount == 1)
    }

    @Test func classifyIPv4UDP() {
        let srcMAC = MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF)
        let ipBytes = makeIPv4Bytes(protocol: .udp)
        let pkt = makeEthernet(dst: ourMAC, src: srcMAC, type: .ipv4, payload: ipBytes)

        let result = classifyFrames([pkt], ourMAC: ourMAC)
        #expect(result.ipv4UDP.count == 1)
        #expect(result.totalCount == 1)
    }

    @Test func classifyIgnoresNonOurMAC() {
        let otherMAC = MACAddress(0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01)
        let srcMAC = MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF)
        let ipBytes = makeIPv4Bytes(protocol: .tcp)
        let pkt = makeEthernet(dst: otherMAC, src: srcMAC, type: .ipv4, payload: ipBytes)

        let result = classifyFrames([pkt], ourMAC: ourMAC)
        #expect(result.totalCount == 1)
        #expect(result.unknown.count == 1)
    }

    @Test func classifyBroadcastAccepted() {
        let srcMAC = MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF)
        let arpBytes: [UInt8] = {
            var bytes = [UInt8](repeating: 0, count: 28)
            bytes[0] = 0x00; bytes[1] = 0x01
            bytes[2] = 0x08; bytes[3] = 0x00
            bytes[4] = 6; bytes[5] = 4
            bytes[6] = 0x00; bytes[7] = 0x01
            return bytes
        }()

        let pkt = makeEthernet(dst: .broadcast, src: srcMAC, type: .arp, payload: arpBytes)

        let result = classifyFrames([pkt], ourMAC: ourMAC)
        #expect(result.arp.count == 1)
    }

    @Test func classifyUnknownEtherType() {
        let srcMAC = MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF)
        // EtherType=0x88B5 is unknown to our parser
        var bytes: [UInt8] = []
        var dstBuf = [UInt8](repeating: 0, count: 6)
        var srcBuf = [UInt8](repeating: 0, count: 6)
        ourMAC.write(to: &dstBuf); bytes.append(contentsOf: dstBuf)
        srcMAC.write(to: &srcBuf); bytes.append(contentsOf: srcBuf)
        bytes.append(0x88); bytes.append(0xB5)  // unknown EtherType
        bytes.append(0)  // 1 byte payload

        let pkt = PacketBuffer.from(bytes: bytes)

        let result = classifyFrames([pkt], ourMAC: ourMAC)
        #expect(result.totalCount == 1)
        #expect(result.unknown.count == 1)
    }

    @Test func classifyMixedBatch() {
        let srcMAC = MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF)

        let icmpPkt = makeEthernet(dst: ourMAC, src: srcMAC, type: .ipv4,
                                    payload: makeIPv4Bytes(protocol: .icmp))
        let tcpPkt = makeEthernet(dst: .broadcast, src: srcMAC, type: .ipv4,
                                   payload: makeIPv4Bytes(protocol: .tcp))
        let udpPkt = makeEthernet(dst: ourMAC, src: srcMAC, type: .ipv4,
                                   payload: makeIPv4Bytes(protocol: .udp))

        let result = classifyFrames([icmpPkt, tcpPkt, udpPkt], ourMAC: ourMAC)
        #expect(result.totalCount == 3)
        #expect(result.ipv4ICMP.count == 1)
        #expect(result.ipv4TCP.count == 1)
        #expect(result.ipv4UDP.count == 1)
    }
}
