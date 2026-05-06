import Testing
@testable import SwiftNetStack

@Suite(.serialized)
struct ICMPHeaderTests {

    let hostMAC = MACAddress(0x00, 0x11, 0x22, 0x33, 0x44, 0x55)
    let clientMAC = MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF)
    let srcIP = IPv4Address(10, 0, 0, 1)
    let dstIP = IPv4Address(10, 0, 0, 2)

    // MARK: - Parse tests

    @Test func parseEchoRequest() {
        let icmpBytes = makeICMPBytes(type: 8, code: 0, id: 0x1234, seq: 0x0001, payload: [0x70, 0x69, 0x6E, 0x67])
        let pkt = packetFrom(icmpBytes)

        let icmp = ICMPHeader.parse(from: pkt)
        #expect(icmp != nil)
        guard let icmp else { return }
        #expect(icmp.type == 8)
        #expect(icmp.code == 0)
        #expect(icmp.identifier == 0x1234)
        #expect(icmp.sequenceNumber == 0x0001)
    }

    @Test func parseEchoReply() {
        let icmpBytes = makeICMPBytes(type: 0, code: 0, id: 0x5678, seq: 0x0042, payload: [])
        let pkt = packetFrom(icmpBytes)

        let icmp = ICMPHeader.parse(from: pkt)
        #expect(icmp != nil)
        guard let icmp else { return }
        #expect(icmp.type == 0)
        #expect(icmp.code == 0)
        #expect(icmp.identifier == 0x5678)
        #expect(icmp.sequenceNumber == 0x0042)
    }

    @Test func parseNonEchoType() {
        // Destination Unreachable (type 3, code 1)
        let icmpBytes = makeICMPBytes(type: 3, code: 1, id: 0, seq: 0, payload: [])
        let pkt = packetFrom(icmpBytes)

        let icmp = ICMPHeader.parse(from: pkt)
        #expect(icmp != nil)
        guard let icmp else { return }
        #expect(icmp.type == 3)
        #expect(icmp.code == 1)
    }

    // MARK: - Audit issue #6: ICMP checksum not verified

    /// AUDIT #6 REPRODUCTION: ICMPHeader.parse accepts packets with deliberately
    /// wrong checksums. Unlike UDPHeader.parse which validates the checksum on
    /// parse, ICMPHeader.parse reads the checksum field but never verifies it.
    ///
    /// EXPECTED: parse returns nil (bad checksum → corrupt packet)
    /// ACTUAL:   parse succeeds (BUG)
    @Test func badChecksumShouldCauseParseFailure() {
        var bytes: [UInt8] = []
        bytes.append(8); bytes.append(0)          // type=echo request, code=0
        bytes.append(0x12); bytes.append(0x34)    // deliberately wrong checksum
        bytes.append(0); bytes.append(1)          // id=1
        bytes.append(0); bytes.append(1)          // seq=1
        bytes.append(contentsOf: [0x70, 0x69, 0x6E, 0x67])  // "ping"

        let pkt = packetFrom(bytes)
        let icmp = ICMPHeader.parse(from: pkt)
        #expect(icmp == nil,
            "AUDIT #6 FAIL: ICMP parse should reject packet with bad checksum 0x1234")
    }

    /// AUDIT #6 REPRODUCTION: zero checksum also accepted without verification.
    /// RFC 792 (unlike RFC 768 UDP) does not have a "checksum=0 means unused" rule
    /// for ICMP — all ICMP messages must have a valid checksum.
    ///
    /// EXPECTED: parse returns nil (zero checksum is invalid for ICMP)
    /// ACTUAL:   parse succeeds (BUG)
    @Test func zeroChecksumShouldCauseParseFailure() {
        var bytes: [UInt8] = []
        bytes.append(8); bytes.append(0)          // type=echo request, code=0
        bytes.append(0); bytes.append(0)          // zero checksum
        bytes.append(0x12); bytes.append(0x34)    // id=0x1234
        bytes.append(0x00); bytes.append(0x01)    // seq=1
        bytes.append(contentsOf: [0xAA, 0xBB])

        let pkt = packetFrom(bytes)
        let icmp = ICMPHeader.parse(from: pkt)
        #expect(icmp == nil,
            "AUDIT #6 FAIL: ICMP parse should reject packet with zero checksum")
    }

    @Test func bufferTooShortReturnsNil() {
        // ICMP needs at least 8 bytes
        let pkt = packetFrom([0x08, 0x00, 0x00, 0x00, 0x12, 0x34])
        #expect(ICMPHeader.parse(from: pkt) == nil)
    }

    @Test func payloadIsCorrectLength() {
        let payload: [UInt8] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
        let icmpBytes = makeICMPBytes(type: 8, code: 0, id: 1, seq: 1, payload: payload)
        let pkt = packetFrom(icmpBytes)

        let icmp = ICMPHeader.parse(from: pkt)
        #expect(icmp != nil)
        guard let icmp else { return }
        #expect(icmp.payload.totalLength == 10)
        icmp.payload.withUnsafeReadableBytes { buf in
            #expect(Array(buf) == payload)
        }
    }

    // MARK: - buildEchoReply tests

    @Test func buildEchoReplySetsCorrectTypeAndCode() {
        let (eth, ip, icmp) = makeEchoRequest()
        let round = RoundContext()

        let reply = buildICMPEchoReply(hostMAC: hostMAC, eth: eth, ip: ip, icmp: icmp, round: round)
        #expect(reply != nil)
        guard let reply else { return }

        // Parse back and verify ICMP fields
        guard let replyEth = EthernetFrame.parse(from: reply) else {
            Issue.record("reply is not valid Ethernet")
            return
        }
        guard let replyIP = IPv4Header.parse(from: replyEth.payload) else {
            Issue.record("reply does not contain valid IPv4")
            return
        }
        guard let replyICMP = ICMPHeader.parse(from: replyIP.payload) else {
            Issue.record("reply does not contain valid ICMP")
            return
        }

        #expect(replyICMP.type == 0)
        #expect(replyICMP.code == 0)
    }

    @Test func buildEchoReplyPreservesIdentifierAndSequence() {
        let (eth, ip, icmp) = makeEchoRequest(id: 0xABCD, seq: 0x0042)
        let round = RoundContext()

        let reply = buildICMPEchoReply(hostMAC: hostMAC, eth: eth, ip: ip, icmp: icmp, round: round)
        guard let reply else { return }
        guard let replyEth = EthernetFrame.parse(from: reply),
              let replyIP = IPv4Header.parse(from: replyEth.payload),
              let replyICMP = ICMPHeader.parse(from: replyIP.payload) else { return }

        #expect(replyICMP.identifier == 0xABCD)
        #expect(replyICMP.sequenceNumber == 0x0042)
    }

    @Test func buildEchoReplyPreservesPayload() {
        let payload: [UInt8] = [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE]
        let (eth, ip, icmp) = makeEchoRequest(payload: payload)
        let round = RoundContext()

        let reply = buildICMPEchoReply(hostMAC: hostMAC, eth: eth, ip: ip, icmp: icmp, round: round)
        guard let reply else { return }
        guard let replyEth = EthernetFrame.parse(from: reply),
              let replyIP = IPv4Header.parse(from: replyEth.payload),
              let replyICMP = ICMPHeader.parse(from: replyIP.payload) else { return }

        #expect(replyICMP.payload.totalLength == payload.count)
        replyICMP.payload.withUnsafeReadableBytes { buf in
            #expect(Array(buf) == payload)
        }
    }

    @Test func buildEchoReplySwapsMACAddresses() {
        let (eth, ip, icmp) = makeEchoRequest()
        let round = RoundContext()

        let reply = buildICMPEchoReply(hostMAC: hostMAC, eth: eth, ip: ip, icmp: icmp, round: round)
        guard let reply else { return }
        guard let replyEth = EthernetFrame.parse(from: reply) else { return }

        #expect(replyEth.dstMAC == clientMAC)
        #expect(replyEth.srcMAC == hostMAC)
    }

    @Test func buildEchoReplySwapsIPAddresses() {
        let (eth, ip, icmp) = makeEchoRequest()
        let round = RoundContext()

        let reply = buildICMPEchoReply(hostMAC: hostMAC, eth: eth, ip: ip, icmp: icmp, round: round)
        guard let reply else { return }
        guard let replyEth = EthernetFrame.parse(from: reply),
              let replyIP = IPv4Header.parse(from: replyEth.payload) else { return }

        #expect(replyIP.srcAddr == dstIP)
        #expect(replyIP.dstAddr == srcIP)
    }

    @Test func buildEchoReplyHasValidICMPChecksum() {
        let (eth, ip, icmp) = makeEchoRequest(payload: [1, 2, 3, 4, 5])
        let round = RoundContext()

        let reply = buildICMPEchoReply(hostMAC: hostMAC, eth: eth, ip: ip, icmp: icmp, round: round)
        guard let reply else { return }
        guard let replyEth = EthernetFrame.parse(from: reply),
              let replyIP = IPv4Header.parse(from: replyEth.payload),
              let replyICMP = ICMPHeader.parse(from: replyIP.payload) else { return }

        // Verify ICMP checksum by recomputing over the raw bytes
        let icmpLen = 8 + replyICMP.payload.totalLength
        var icmpBytes = replyIP.payload
        guard icmpBytes.pullUp(icmpLen) else {
            Issue.record("cannot pull up ICMP bytes")
            return
        }
        let valid = icmpBytes.withUnsafeReadableBytes { buf in
            let computed = internetChecksum(UnsafeRawBufferPointer(start: buf.baseAddress, count: icmpLen))
            return computed == 0
        }
        #expect(valid)
    }

    @Test func buildEchoReplyHasValidIPChecksum() {
        let (eth, ip, icmp) = makeEchoRequest()
        let round = RoundContext()

        let reply = buildICMPEchoReply(hostMAC: hostMAC, eth: eth, ip: ip, icmp: icmp, round: round)
        guard let reply else { return }
        guard let replyEth = EthernetFrame.parse(from: reply),
              let replyIP = IPv4Header.parse(from: replyEth.payload) else { return }

        #expect(replyIP.verifyChecksum())
    }

    // MARK: - Helpers

    /// Build raw ICMP bytes: 8-byte header + payload.
    private func makeICMPBytes(type: UInt8, code: UInt8, id: UInt16, seq: UInt16, payload: [UInt8]) -> [UInt8] {
        var bytes: [UInt8] = []
        bytes.append(type)
        bytes.append(code)
        bytes.append(0); bytes.append(0)  // checksum placeholder
        bytes.append(UInt8(id >> 8)); bytes.append(UInt8(id & 0xFF))
        bytes.append(UInt8(seq >> 8)); bytes.append(UInt8(seq & 0xFF))
        bytes.append(contentsOf: payload)

        // Compute checksum
        let cksum = bytes.withUnsafeBytes { internetChecksum($0) }
        bytes[2] = UInt8(cksum >> 8)
        bytes[3] = UInt8(cksum & 0xFF)
        return bytes
    }

    /// Wrap raw bytes in a PacketBuffer.
    private func packetFrom(_ bytes: [UInt8]) -> PacketBuffer {
        let storage = Storage.allocate(capacity: bytes.count)
        bytes.withUnsafeBytes { storage.data.copyMemory(from: $0.baseAddress!, byteCount: bytes.count) }
        return PacketBuffer(storage: storage, offset: 0, length: bytes.count)
    }

    /// Build raw IPv4 header bytes (20 bytes) with ICMP protocol.
    private func makeIPv4Bytes(totalLength: Int) -> [UInt8] {
        var bytes = [UInt8](repeating: 0, count: 20)
        bytes[0] = 0x45                          // version=4, IHL=5
        bytes[2] = UInt8(totalLength >> 8)
        bytes[3] = UInt8(totalLength & 0xFF)
        bytes[8] = 64                             // TTL
        bytes[9] = IPProtocol.icmp.rawValue       // protocol
        srcIP.write(to: &bytes[12])
        dstIP.write(to: &bytes[16])
        // checksum placeholder, computed below
        let cksum = bytes.withUnsafeBytes { internetChecksum($0) }
        bytes[10] = UInt8(cksum >> 8)
        bytes[11] = UInt8(cksum & 0xFF)
        return bytes
    }

    /// Build a complete Ethernet + IPv4 + ICMP echo request frame and parse it
    /// into the three structs needed by buildICMPEchoReply.
    private func makeEchoRequest(
        id: UInt16 = 0x1234,
        seq: UInt16 = 0x0001,
        payload: [UInt8] = [0x70, 0x69, 0x6E, 0x67]
    ) -> (EthernetFrame, IPv4Header, ICMPHeader) {
        let icmpBytes = makeICMPBytes(type: 8, code: 0, id: id, seq: seq, payload: payload)
        let ipTotalLen = 20 + icmpBytes.count
        let ipBytes = makeIPv4Bytes(totalLength: ipTotalLen)

        // Ethernet frame: dst=hostMAC, src=clientMAC, type=IPv4
        var ethBytes: [UInt8] = []
        var macBuf = [UInt8](repeating: 0, count: 6)
        hostMAC.write(to: &macBuf); ethBytes.append(contentsOf: macBuf)
        clientMAC.write(to: &macBuf); ethBytes.append(contentsOf: macBuf)
        ethBytes.append(0x08); ethBytes.append(0x00)  // EtherType IPv4
        ethBytes.append(contentsOf: ipBytes)
        ethBytes.append(contentsOf: icmpBytes)

        let pkt = packetFrom(ethBytes)

        guard let eth = EthernetFrame.parse(from: pkt) else {
            fatalError("test setup: failed to parse Ethernet")
        }
        guard let ip = IPv4Header.parse(from: eth.payload) else {
            fatalError("test setup: failed to parse IPv4")
        }
        guard let icmp = ICMPHeader.parse(from: ip.payload) else {
            fatalError("test setup: failed to parse ICMP")
        }
        return (eth, ip, icmp)
    }
}
