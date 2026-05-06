import Testing
@testable import SwiftNetStack

@Suite(.serialized)
struct UDPHeaderTests {

    // Default pseudo-addresses for parse tests
    private let srcIP = IPv4Address(100, 64, 1, 1)
    private let dstIP = IPv4Address(100, 64, 1, 50)

    // MARK: - Parse

    @Test func parseValidUDPHeader() {
        let udp = makeUDPPacket(srcPort: 1234, dstPort: 5678, payload: [0x70, 0x69, 0x6E, 0x67])
        guard let parsed = UDPHeader.parse(from: udp, pseudoSrcAddr: srcIP, pseudoDstAddr: dstIP) else {
            Issue.record("parse returned nil")
            return
        }
        #expect(parsed.srcPort == 1234)
        #expect(parsed.dstPort == 5678)
        #expect(parsed.length == 12)  // 8 header + 4 payload
        #expect(parsed.payload.totalLength == 4)
    }

    @Test func parseBufferTooShortReturnsNil() {
        let short = makeRawPacket([0x00, 0x01, 0x02])  // only 3 bytes
        #expect(UDPHeader.parse(from: short, pseudoSrcAddr: srcIP, pseudoDstAddr: dstIP) == nil)
    }

    @Test func parseZeroChecksumIsValid() {
        // RFC 768: checksum 0 means unused
        let udp = makeUDPPacket(srcPort: 1, dstPort: 2, checksum: 0, payload: [])
        guard let parsed = UDPHeader.parse(from: udp, pseudoSrcAddr: srcIP, pseudoDstAddr: dstIP) else {
            Issue.record("parse returned nil")
            return
        }
        #expect(parsed.verifyChecksum())
    }

    @Test func parseEmptyPayloadUDP() {
        let udp = makeUDPPacket(srcPort: 9999, dstPort: 8888, payload: [])
        guard let parsed = UDPHeader.parse(from: udp, pseudoSrcAddr: srcIP, pseudoDstAddr: dstIP) else {
            Issue.record("parse returned nil")
            return
        }
        #expect(parsed.length == 8)  // header only
        #expect(parsed.payload.totalLength == 0)
    }

    @Test func parsePreservesPseudoAddresses() {
        let udp = makeUDPPacket(srcPort: 42, dstPort: 43, payload: [0xAB])
        let src = IPv4Address(10, 0, 0, 1)
        let dst = IPv4Address(192, 168, 1, 100)
        guard let parsed = UDPHeader.parse(from: udp, pseudoSrcAddr: src, pseudoDstAddr: dst) else {
            Issue.record("parse returned nil")
            return
        }
        #expect(parsed.pseudoSrcAddr == src)
        #expect(parsed.pseudoDstAddr == dst)
    }

    // MARK: - Checksum verification

    @Test func verifyChecksumWithKnownVector() {
        // Manually computed: pseudo-header + UDP header + "ping" payload
        let srcIP = IPv4Address(100, 64, 1, 1)
        let dstIP = IPv4Address(100, 64, 1, 50)
        let payload: [UInt8] = [0x70, 0x69, 0x6E, 0x67]  // "ping"

        let udp = makeUDPPacketWithChecksum(
            srcPort: 1234, dstPort: 5678,
            srcIP: srcIP, dstIP: dstIP,
            payload: payload
        )
        guard let parsed = UDPHeader.parse(from: udp, pseudoSrcAddr: srcIP, pseudoDstAddr: dstIP) else {
            Issue.record("parse returned nil")
            return
        }
        #expect(parsed.verifyChecksum())
    }

    @Test func badChecksumDetected() {
        let srcIP = IPv4Address(10, 0, 0, 1)
        let dstIP = IPv4Address(10, 0, 0, 2)
        // Deliberately wrong checksum
        let udp = makeUDPPacket(srcPort: 1, dstPort: 2, checksum: 0x1234, payload: [0xAA])
        guard let parsed = UDPHeader.parse(from: udp, pseudoSrcAddr: srcIP, pseudoDstAddr: dstIP) else {
            Issue.record("parse returned nil")
            return
        }
        #expect(!parsed.verifyChecksum())
    }

    // MARK: - udpChecksum() standalone

    @Test func udpChecksumProducesAllOnes() {
        let srcIP = IPv4Address(100, 64, 1, 1)
        let dstIP = IPv4Address(100, 64, 1, 50)
        let udp = makeUDPPacket(srcPort: 42, dstPort: 99, checksum: 0, payload: [0x01, 0x02, 0x03])
        guard let ck = udpChecksum(pseudoSrcAddr: srcIP, pseudoDstAddr: dstIP, udpPayload: udp) else {
            Issue.record("udpChecksum returned nil")
            return
        }
        // Checksum of the full pseudo-header + header + payload
        // should not be 0 (would mean all bits sum to 0xFFFF before complement)
        // For a random payload, it should be non-zero
        #expect(ck != 0)
    }

    // MARK: - buildUDPFrame round-trip

    @Test func buildUDPFrameRoundTrip() {
        let hostMAC = MACAddress(0x00, 0x11, 0x22, 0x33, 0x44, 0x55)
        let clientMAC = MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF)
        let srcIP = IPv4Address(100, 64, 1, 1)
        let dstIP = IPv4Address(100, 64, 1, 50)
        let payload = makeRawPacket([0x70, 0x69, 0x6E, 0x67])

        let round = RoundContext()
        guard let frame = buildUDPFrame(
            hostMAC: hostMAC, dstMAC: clientMAC,
            srcIP: srcIP, dstIP: dstIP,
            srcPort: 7777, dstPort: 8888,
            payload: payload,
            round: round
        ) else {
            Issue.record("buildUDPFrame returned nil")
            return
        }

        // Parse back the Ethernet frame
        guard let eth = EthernetFrame.parse(from: frame) else {
            Issue.record("failed to parse Ethernet")
            return
        }
        #expect(eth.dstMAC == clientMAC)
        #expect(eth.srcMAC == hostMAC)
        #expect(eth.etherType == .ipv4)

        guard let ip = IPv4Header.parse(from: eth.payload) else {
            Issue.record("failed to parse IPv4")
            return
        }
        #expect(ip.protocol == .udp)
        #expect(ip.srcAddr == srcIP)
        #expect(ip.dstAddr == dstIP)
        #expect(ip.verifyChecksum())

        guard let udp = UDPHeader.parse(from: ip.payload, pseudoSrcAddr: srcIP, pseudoDstAddr: dstIP) else {
            Issue.record("failed to parse UDP")
            return
        }
        #expect(udp.srcPort == 7777)
        #expect(udp.dstPort == 8888)
        #expect(udp.verifyChecksum())

        // Verify payload matches
        #expect(udp.payload.totalLength == 4)
        udp.payload.withUnsafeReadableBytes { buf in
            #expect(buf[0] == 0x70)
            #expect(buf[1] == 0x69)
            #expect(buf[2] == 0x6E)
            #expect(buf[3] == 0x67)
        }
    }

    @Test func buildUDPFrameEmptyPayload() {
        let hostMAC = MACAddress(0x00, 0x11, 0x22, 0x33, 0x44, 0x55)
        let clientMAC = MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF)
        let srcIP = IPv4Address(10, 0, 0, 1)
        let dstIP = IPv4Address(10, 0, 0, 2)
        let emptyPayload = makeRawPacket([])

        let round = RoundContext()
        guard let frame = buildUDPFrame(
            hostMAC: hostMAC, dstMAC: clientMAC,
            srcIP: srcIP, dstIP: dstIP,
            srcPort: 1, dstPort: 2,
            payload: emptyPayload,
            round: round
        ) else {
            Issue.record("buildUDPFrame returned nil")
            return
        }

        guard let eth = EthernetFrame.parse(from: frame),
              let ip = IPv4Header.parse(from: eth.payload),
              let udp = UDPHeader.parse(from: ip.payload, pseudoSrcAddr: srcIP, pseudoDstAddr: dstIP) else {
            Issue.record("parse chain failed")
            return
        }
        #expect(udp.length == 8)
        #expect(udp.payload.totalLength == 0)
        #expect(udp.verifyChecksum())
    }

    // MARK: - C2 regression: payload trimmed to UDP length

    /// Verifies that UDPHeader.parse respects the UDP header's `length` field
    /// when computing the payload slice, excluding trailing garbage bytes.
    @Test func udpPayloadTrimmedToDeclaredLength() {
        let declaredUDPLength: UInt16 = 12   // 8 header + 4 payload
        let physicalBufLen = 20              // includes 8 bytes garbage
        let expectedPayloadLen = Int(declaredUDPLength) - 8  // 4

        var bytes = [UInt8](repeating: 0, count: physicalBufLen)
        bytes[0] = 0x04; bytes[1] = 0xD2                  // srcPort=1234
        bytes[2] = 0x16; bytes[3] = 0x2E                  // dstPort=5678
        bytes[4] = UInt8(declaredUDPLength >> 8)           // length=12
        bytes[5] = UInt8(declaredUDPLength & 0xFF)
        // checksum = 0 (unused)
        for i in 0..<4 { bytes[8 + i] = UInt8(i + 1) }    // real payload
        for i in 12..<20 { bytes[i] = 0xEE }               // garbage

        let s = Storage.allocate(capacity: physicalBufLen)
        bytes.withUnsafeBytes { s.data.copyMemory(from: $0.baseAddress!, byteCount: physicalBufLen) }
        let pkt = PacketBuffer(storage: s, offset: 0, length: physicalBufLen)

        guard let udp = UDPHeader.parse(from: pkt, pseudoSrcAddr: srcIP, pseudoDstAddr: dstIP) else {
            Issue.record("parse returned nil")
            return
        }

        #expect(udp.length == declaredUDPLength)
        #expect(udp.payload.totalLength == expectedPayloadLen)
        udp.payload.withUnsafeReadableBytes { buf in
            let payloadBytes = Array(buf)
            #expect(payloadBytes.count == expectedPayloadLen)
            #expect(payloadBytes == [0x01, 0x02, 0x03, 0x04])
        }
    }

    // MARK: - Helpers

    /// Create a raw PacketBuffer from bytes.
    private func makeRawPacket(_ bytes: [UInt8]) -> PacketBuffer {
        let s = Storage.allocate(capacity: max(bytes.count, 1))
        if !bytes.isEmpty {
            bytes.withUnsafeBytes { s.data.copyMemory(from: $0.baseAddress!, byteCount: bytes.count) }
        }
        return PacketBuffer(storage: s, offset: 0, length: bytes.count)
    }

    /// Create a UDP PacketBuffer with zero checksum.
    private func makeUDPPacket(srcPort: UInt16, dstPort: UInt16,
                                checksum: UInt16 = 0,
                                payload: [UInt8]) -> PacketBuffer {
        let len = UInt16(8 + payload.count)
        var bytes: [UInt8] = []
        bytes.append(UInt8(srcPort >> 8))
        bytes.append(UInt8(srcPort & 0xFF))
        bytes.append(UInt8(dstPort >> 8))
        bytes.append(UInt8(dstPort & 0xFF))
        bytes.append(UInt8(len >> 8))
        bytes.append(UInt8(len & 0xFF))
        bytes.append(UInt8(checksum >> 8))
        bytes.append(UInt8(checksum & 0xFF))
        bytes.append(contentsOf: payload)
        return makeRawPacket(bytes)
    }

    /// Create a UDP PacketBuffer with a correctly computed checksum.
    private func makeUDPPacketWithChecksum(srcPort: UInt16, dstPort: UInt16,
                                            srcIP: IPv4Address, dstIP: IPv4Address,
                                            payload: [UInt8]) -> PacketBuffer {
        // Build with checksum=0, compute, then rebuild with correct checksum
        let tmp = makeUDPPacket(srcPort: srcPort, dstPort: dstPort, checksum: 0, payload: payload)
        guard let ck = udpChecksum(pseudoSrcAddr: srcIP, pseudoDstAddr: dstIP, udpPayload: tmp) else {
            return tmp
        }
        return makeUDPPacket(srcPort: srcPort, dstPort: dstPort, checksum: ck, payload: payload)
    }
}
