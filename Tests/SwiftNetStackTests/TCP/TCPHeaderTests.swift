import Testing
@testable import SwiftNetStack

@Suite(.serialized)
struct TCPHeaderTests {

    // MARK: - Helpers

    /// Build raw TCP bytes with header + optional payload and valid checksum.
    private func makeTCPBytes(
        srcPort: UInt16 = 1234,
        dstPort: UInt16 = 80,
        seq: UInt32 = 1000,
        ack: UInt32 = 2000,
        dataOffset: UInt8 = 5,
        flags: TCPFlags = .ack,
        window: UInt16 = 65535,
        payload: [UInt8] = [],
        pseudoSrc: IPv4Address = IPv4Address(10, 0, 0, 1),
        pseudoDst: IPv4Address = IPv4Address(10, 0, 0, 2)
    ) -> [UInt8] {
        // Always allocate at least 20 bytes for the mandatory TCP header fields,
        // even when testing invalid/small dataOffset values.
        let minHdr = max(Int(dataOffset) * 4, 20)
        let tcpLen = minHdr + payload.count
        var bytes = [UInt8](repeating: 0, count: tcpLen)

        bytes[0] = UInt8(srcPort >> 8); bytes[1] = UInt8(srcPort & 0xFF)
        bytes[2] = UInt8(dstPort >> 8); bytes[3] = UInt8(dstPort & 0xFF)
        bytes[4] = UInt8((seq >> 24) & 0xFF); bytes[5] = UInt8((seq >> 16) & 0xFF)
        bytes[6] = UInt8((seq >> 8) & 0xFF); bytes[7] = UInt8(seq & 0xFF)
        bytes[8] = UInt8((ack >> 24) & 0xFF); bytes[9] = UInt8((ack >> 16) & 0xFF)
        bytes[10] = UInt8((ack >> 8) & 0xFF); bytes[11] = UInt8(ack & 0xFF)
        bytes[12] = (dataOffset << 4)
        bytes[13] = flags.rawValue
        bytes[14] = UInt8(window >> 8); bytes[15] = UInt8(window & 0xFF)
        // checksum at [16..<18], computed below
        // urgent at [18..<20]
        if !payload.isEmpty {
            for i in 0..<payload.count { bytes[minHdr + i] = payload[i] }
        }

        let ck = computeTCPChecksum(
            pseudoSrcAddr: pseudoSrc, pseudoDstAddr: pseudoDst,
            tcpData: &bytes, tcpLen: tcpLen
        )
        bytes[16] = UInt8(ck >> 8)
        bytes[17] = UInt8(ck & 0xFF)

        return bytes
    }

    private func packetBuffer(from bytes: [UInt8]) -> PacketBuffer {
        let s = Storage.allocate(capacity: bytes.count)
        bytes.withUnsafeBytes { s.data.copyMemory(from: $0.baseAddress!, byteCount: bytes.count) }
        return PacketBuffer(storage: s, offset: 0, length: bytes.count)
    }

    // MARK: - Basic parse

    @Test func parseValidMinimalHeader() {
        let bytes = makeTCPBytes()
        let pkt = packetBuffer(from: bytes)
        let hdr = TCPHeader.parse(from: pkt,
                                   pseudoSrcAddr: IPv4Address(10, 0, 0, 1),
                                   pseudoDstAddr: IPv4Address(10, 0, 0, 2))
        #expect(hdr != nil)
        #expect(hdr?.srcPort == 1234)
        #expect(hdr?.dstPort == 80)
        #expect(hdr?.sequenceNumber == 1000)
        #expect(hdr?.acknowledgmentNumber == 2000)
        #expect(hdr?.dataOffset == 5)
        #expect(hdr?.window == 65535)
    }

    @Test func parseHeaderWithPayload() {
        let payload: [UInt8] = [0x41, 0x42, 0x43, 0x44, 0x45]  // "ABCDE"
        let bytes = makeTCPBytes(payload: payload)
        let pkt = packetBuffer(from: bytes)
        let hdr = TCPHeader.parse(from: pkt,
                                   pseudoSrcAddr: IPv4Address(10, 0, 0, 1),
                                   pseudoDstAddr: IPv4Address(10, 0, 0, 2))
        #expect(hdr != nil)
        #expect(hdr?.payload.totalLength == 5)
    }

    @Test func parseHeaderTooShort() {
        var bytes = makeTCPBytes()
        bytes.removeLast() // truncate to 19 bytes (min is 20)
        let pkt = packetBuffer(from: bytes)
        let hdr = TCPHeader.parse(from: pkt,
                                   pseudoSrcAddr: IPv4Address(10, 0, 0, 1),
                                   pseudoDstAddr: IPv4Address(10, 0, 0, 2))
        #expect(hdr == nil)
    }

    @Test func parseInvalidDataOffset() {
        // dataOffset=4 is invalid (< 5)
        let bytes = makeTCPBytes(dataOffset: 4)
        let pkt = packetBuffer(from: bytes)
        let hdr = TCPHeader.parse(from: pkt,
                                   pseudoSrcAddr: IPv4Address(10, 0, 0, 1),
                                   pseudoDstAddr: IPv4Address(10, 0, 0, 2))
        #expect(hdr == nil)
    }

    @Test func parseDataOffset15() {
        // dataOffset=15 is the maximum valid value
        let bytes = makeTCPBytes(dataOffset: 15)
        let pkt = packetBuffer(from: bytes)
        let hdr = TCPHeader.parse(from: pkt,
                                   pseudoSrcAddr: IPv4Address(10, 0, 0, 1),
                                   pseudoDstAddr: IPv4Address(10, 0, 0, 2))
        #expect(hdr != nil)
        #expect(hdr?.dataOffset == 15)
        #expect(hdr?.headerLength == 60)
    }

    @Test func parseTooShortForDeclaredDataOffset() {
        // dataOffset=10 means 40-byte header, but we only provide 25 bytes
        let bytes = makeTCPBytes(dataOffset: 10)
        // Truncate to 25 bytes (less than the 40-byte header declared)
        let truncated = Array(bytes[0..<25])
        let pkt = packetBuffer(from: truncated)
        let hdr = TCPHeader.parse(from: pkt,
                                   pseudoSrcAddr: IPv4Address(10, 0, 0, 1),
                                   pseudoDstAddr: IPv4Address(10, 0, 0, 2))
        #expect(hdr == nil)
    }

    // MARK: - Checksum

    @Test func verifyChecksumOnValidHeader() {
        let bytes = makeTCPBytes()
        let pkt = packetBuffer(from: bytes)
        let hdr = TCPHeader.parse(from: pkt,
                                   pseudoSrcAddr: IPv4Address(10, 0, 0, 1),
                                   pseudoDstAddr: IPv4Address(10, 0, 0, 2))
        #expect(hdr?.verifyChecksum() == true)
    }

    @Test func checksumWithDifferentPseudoHeaderFails() {
        let bytes = makeTCPBytes(
            pseudoSrc: IPv4Address(10, 0, 0, 1),
            pseudoDst: IPv4Address(10, 0, 0, 2)
        )
        let pkt = packetBuffer(from: bytes)
        // Pass different pseudo addresses than what was used to compute the checksum
        let hdr = TCPHeader.parse(from: pkt,
                                   pseudoSrcAddr: IPv4Address(192, 168, 1, 1),
                                   pseudoDstAddr: IPv4Address(192, 168, 1, 2))
        #expect(hdr?.verifyChecksum() == false)
    }

    // MARK: - Flags

    @Test func synFlagRoundTrip() {
        let bytes = makeTCPBytes(flags: .syn)
        let pkt = packetBuffer(from: bytes)
        let hdr = TCPHeader.parse(from: pkt,
                                   pseudoSrcAddr: IPv4Address(10, 0, 0, 1),
                                   pseudoDstAddr: IPv4Address(10, 0, 0, 2))
        #expect(hdr?.flags.isSyn == true)
        #expect(hdr?.flags.isAck == false)
    }

    @Test func synAckFlagsRoundTrip() {
        let flags: TCPFlags = [.syn, .ack]
        let bytes = makeTCPBytes(flags: flags)
        let pkt = packetBuffer(from: bytes)
        let hdr = TCPHeader.parse(from: pkt,
                                   pseudoSrcAddr: IPv4Address(10, 0, 0, 1),
                                   pseudoDstAddr: IPv4Address(10, 0, 0, 2))
        #expect(hdr?.flags.isSynAck == true)
    }

    @Test func finFlagRoundTrip() {
        let flags: TCPFlags = [.fin, .ack]
        let bytes = makeTCPBytes(flags: flags)
        let pkt = packetBuffer(from: bytes)
        let hdr = TCPHeader.parse(from: pkt,
                                   pseudoSrcAddr: IPv4Address(10, 0, 0, 1),
                                   pseudoDstAddr: IPv4Address(10, 0, 0, 2))
        #expect(hdr?.flags.contains(.fin) == true)
        #expect(hdr?.flags.contains(.ack) == true)
    }

    @Test func rstFlagRoundTrip() {
        let bytes = makeTCPBytes(flags: .rst)
        let pkt = packetBuffer(from: bytes)
        let hdr = TCPHeader.parse(from: pkt,
                                   pseudoSrcAddr: IPv4Address(10, 0, 0, 1),
                                   pseudoDstAddr: IPv4Address(10, 0, 0, 2))
        #expect(hdr?.flags.isRst == true)
    }

    // MARK: - Window and urgent

    @Test func windowFieldParsedCorrectly() {
        let bytes = makeTCPBytes(window: 8192)
        let pkt = packetBuffer(from: bytes)
        let hdr = TCPHeader.parse(from: pkt,
                                   pseudoSrcAddr: IPv4Address(10, 0, 0, 1),
                                   pseudoDstAddr: IPv4Address(10, 0, 0, 2))
        #expect(hdr?.window == 8192)
    }

    @Test func sequenceNumberWraparound() {
        // Test with sequence number near UInt32.max
        let seq = UInt32.max &- 5
        let bytes = makeTCPBytes(seq: seq)
        let pkt = packetBuffer(from: bytes)
        let hdr = TCPHeader.parse(from: pkt,
                                   pseudoSrcAddr: IPv4Address(10, 0, 0, 1),
                                   pseudoDstAddr: IPv4Address(10, 0, 0, 2))
        #expect(hdr?.sequenceNumber == seq)
    }

    // MARK: - Pseudo address preservation

    @Test func parsePreservesPseudoAddresses() {
        let src = IPv4Address(192, 168, 1, 100)
        let dst = IPv4Address(10, 0, 0, 1)
        let bytes = makeTCPBytes(pseudoSrc: src, pseudoDst: dst)
        let pkt = packetBuffer(from: bytes)
        let hdr = TCPHeader.parse(from: pkt,
                                   pseudoSrcAddr: src,
                                   pseudoDstAddr: dst)
        #expect(hdr?.pseudoSrcAddr == src)
        #expect(hdr?.pseudoDstAddr == dst)
    }

    // MARK: - syntheticAck

    @Test func syntheticAckDefaultSeqIsZero() {
        let round = RoundContext()
        let pkt = round.allocate(capacity: 0, headroom: 0)
        let sa = TCPHeader.syntheticAck(
            ackNumber: 5000,
            pseudoSrcAddr: IPv4Address(10, 0, 0, 1),
            pseudoDstAddr: IPv4Address(10, 0, 0, 2),
            payload: pkt
        )
        #expect(sa.sequenceNumber == 0)
        #expect(sa.acknowledgmentNumber == 5000)
        #expect(sa.flags == .ack)
    }

    @Test func syntheticAckWithCustomSeq() {
        let round = RoundContext()
        let pkt = round.allocate(capacity: 0, headroom: 0)
        let sa = TCPHeader.syntheticAck(
            ackNumber: 5000,
            sequenceNumber: 3000,
            pseudoSrcAddr: IPv4Address(10, 0, 0, 1),
            pseudoDstAddr: IPv4Address(10, 0, 0, 2),
            payload: pkt
        )
        #expect(sa.sequenceNumber == 3000)
        #expect(sa.acknowledgmentNumber == 5000)
    }
}
