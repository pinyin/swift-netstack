import Testing
@testable import SwiftNetStack

@Suite(.serialized)
struct TCPStateMachineTests {

    // MARK: - Test helpers

    /// Build a minimal TCP header inside a PacketBuffer. The checksum is computed
    /// so that `TCPHeader.parse` returns a valid header.
    private func makeSegment(
        flags: TCPFlags,
        seq: UInt32,
        ack: UInt32,
        window: UInt16 = 65535,
        payload: [UInt8] = [],
        srcPort: UInt16 = 1234,
        dstPort: UInt16 = 80,
        pseudoSrc: IPv4Address = IPv4Address(10, 0, 0, 1),
        pseudoDst: IPv4Address = IPv4Address(10, 0, 0, 2)
    ) -> TCPHeader {
        let hdrLen = 20
        let tcpLen = hdrLen + payload.count
        var bytes = [UInt8](repeating: 0, count: tcpLen)

        bytes[0] = UInt8(srcPort >> 8); bytes[1] = UInt8(srcPort & 0xFF)
        bytes[2] = UInt8(dstPort >> 8); bytes[3] = UInt8(dstPort & 0xFF)
        bytes[4] = UInt8((seq >> 24) & 0xFF); bytes[5] = UInt8((seq >> 16) & 0xFF)
        bytes[6] = UInt8((seq >> 8) & 0xFF); bytes[7] = UInt8(seq & 0xFF)
        bytes[8] = UInt8((ack >> 24) & 0xFF); bytes[9] = UInt8((ack >> 16) & 0xFF)
        bytes[10] = UInt8((ack >> 8) & 0xFF); bytes[11] = UInt8(ack & 0xFF)
        bytes[12] = 0x50  // data offset = 5
        bytes[13] = flags.rawValue
        bytes[14] = UInt8(window >> 8); bytes[15] = UInt8(window & 0xFF)
        // checksum at [16..<18], computed below
        // urgent at [18..<20]
        if !payload.isEmpty {
            for i in 0..<payload.count { bytes[hdrLen + i] = payload[i] }
        }

        // Compute and insert TCP checksum
        let ck = computeTCPChecksum(
            pseudoSrcAddr: pseudoSrc,
            pseudoDstAddr: pseudoDst,
            tcpData: &bytes,
            tcpLen: tcpLen
        )
        bytes[16] = UInt8(ck >> 8)
        bytes[17] = UInt8(ck & 0xFF)

        let s = Storage.allocate(capacity: tcpLen)
        bytes.withUnsafeBytes { s.data.copyMemory(from: $0.baseAddress!, byteCount: tcpLen) }
        let pkt = PacketBuffer(storage: s, offset: 0, length: tcpLen)
        return TCPHeader.parse(from: pkt, pseudoSrcAddr: pseudoSrc, pseudoDstAddr: pseudoDst)!
    }

    private func makeSendSequence(nxt: UInt32 = 1000, una: UInt32 = 1000, wnd: UInt16 = 65535) -> SendSequence {
        SendSequence(nxt: nxt, una: una, wnd: wnd)
    }

    private func makeRecvSequence(nxt: UInt32 = 2000, initialSeq: UInt32 = 2000) -> RecvSequence {
        RecvSequence(nxt: nxt, initialSeq: initialSeq)
    }

    // MARK: - CLOSED

    @Test func closedStateRejectsAllSegments() {
        let seg = makeSegment(flags: .syn, seq: 100, ack: 0)
        var snd = makeSendSequence()
        var rcv = makeRecvSequence()

        let (state, toSend, data) = tcpProcess(
            state: .closed, segment: seg, snd: &snd, rcv: &rcv, appClose: false
        )

        #expect(state == .closed)
        #expect(toSend.isEmpty)
        #expect(data == nil)
    }

    @Test func rstResetsAnyStateToClosed() {
        let seg = makeSegment(flags: .rst, seq: 100, ack: 0)
        var snd = makeSendSequence()
        var rcv = makeRecvSequence()

        let (state, _, _) = tcpProcess(
            state: .established, segment: seg, snd: &snd, rcv: &rcv, appClose: false
        )

        #expect(state == .closed)
    }

    // MARK: - LISTEN → SYN_RECEIVED

    @Test func listenReceivesSynTransitionsToSynReceived() {
        let seg = makeSegment(flags: .syn, seq: 5000, ack: 0)
        var snd = makeSendSequence(nxt: 0, una: 0)
        var rcv = makeRecvSequence(nxt: 0, initialSeq: 0)

        let (state, toSend, data) = tcpProcess(
            state: .listen, segment: seg, snd: &snd, rcv: &rcv, appClose: false
        )

        #expect(state == .synReceived)
        #expect(toSend.count == 1)
        #expect(toSend[0].flags.isSynAck)
        #expect(data == nil)
    }

    @Test func listenRecordsPeerInitialSequence() {
        let seg = makeSegment(flags: .syn, seq: 5000, ack: 0)
        var snd = makeSendSequence(nxt: 0, una: 0)
        var rcv = makeRecvSequence(nxt: 0, initialSeq: 0)

        _ = tcpProcess(state: .listen, segment: seg, snd: &snd, rcv: &rcv, appClose: false)

        #expect(rcv.initialSeq == 5000)
        #expect(rcv.nxt == 5001)
    }

    @Test func listenGeneratesISNAndAdvancesSndNxt() {
        let seg = makeSegment(flags: .syn, seq: 5000, ack: 0)
        var snd = makeSendSequence(nxt: 0, una: 0)
        var rcv = makeRecvSequence(nxt: 0, initialSeq: 0)

        _ = tcpProcess(state: .listen, segment: seg, snd: &snd, rcv: &rcv, appClose: false)

        #expect(snd.una == snd.nxt &- 1) // una should be the ISN
    }

    @Test func listenSynAckSeqEqualsISN() {
        let seg = makeSegment(flags: .syn, seq: 5000, ack: 0)
        var snd = makeSendSequence(nxt: 0, una: 0)
        var rcv = makeRecvSequence(nxt: 0, initialSeq: 0)

        let (_, toSend, _) = tcpProcess(state: .listen, segment: seg, snd: &snd, rcv: &rcv, appClose: false)

        // SYN+ACK seq number must equal the ISN (saved in snd.una)
        #expect(toSend[0].seq == snd.una, "SYN+ACK seq \(toSend[0].seq) must equal ISN \(snd.una)")
    }

    @Test func listenIgnoredOnSynAckSegment() {
        let seg = makeSegment(flags: [.syn, .ack], seq: 5000, ack: 0)
        var snd = makeSendSequence(nxt: 0, una: 0)
        var rcv = makeRecvSequence(nxt: 0, initialSeq: 0)

        let (state, toSend, _) = tcpProcess(
            state: .listen, segment: seg, snd: &snd, rcv: &rcv, appClose: false
        )

        #expect(state == .listen)
        #expect(toSend.isEmpty)
    }

    @Test func listenIgnoresNonSynSegments() {
        let seg = makeSegment(flags: .ack, seq: 5000, ack: 0)
        var snd = makeSendSequence(nxt: 0, una: 0)
        var rcv = makeRecvSequence(nxt: 0, initialSeq: 0)

        let (state, toSend, _) = tcpProcess(
            state: .listen, segment: seg, snd: &snd, rcv: &rcv, appClose: false
        )

        #expect(state == .listen)
        #expect(toSend.isEmpty)
    }

    // MARK: - SYN_RECEIVED → ESTABLISHED

    @Test func synReceivedAckCompletesHandshake() {
        // SYN was already processed: snd.nxt = ISN+1, snd.una = ISN
        let isn: UInt32 = 1000
        var snd = makeSendSequence(nxt: isn &+ 1, una: isn)
        var rcv = makeRecvSequence(nxt: 5001, initialSeq: 5000)

        // ACK of our SYN (ack == snd.nxt == ISN+1)
        let seg = makeSegment(flags: .ack, seq: 5001, ack: isn &+ 1)
        let (state, toSend, _) = tcpProcess(
            state: .synReceived, segment: seg, snd: &snd, rcv: &rcv, appClose: false
        )

        #expect(state == .established)
        #expect(toSend.isEmpty)
        #expect(snd.una == isn &+ 1)
    }

    @Test func synReceivedWrongAckDoesNotCompleteHandshake() {
        let isn: UInt32 = 1000
        var snd = makeSendSequence(nxt: isn &+ 1, una: isn)
        var rcv = makeRecvSequence(nxt: 5001, initialSeq: 5000)

        let seg = makeSegment(flags: .ack, seq: 5001, ack: 999) // wrong ack
        let (state, _, _) = tcpProcess(
            state: .synReceived, segment: seg, snd: &snd, rcv: &rcv, appClose: false
        )

        #expect(state == .synReceived)
    }

    @Test func synReceivedNonAckSegmentIsIgnored() {
        let isn: UInt32 = 1000
        var snd = makeSendSequence(nxt: isn &+ 1, una: isn)
        var rcv = makeRecvSequence(nxt: 5001, initialSeq: 5000)

        let seg = makeSegment(flags: .syn, seq: 5001, ack: 0)
        let (state, toSend, _) = tcpProcess(
            state: .synReceived, segment: seg, snd: &snd, rcv: &rcv, appClose: false
        )

        #expect(state == .synReceived)
        #expect(toSend.isEmpty)
    }

    // MARK: - ESTABLISHED data transfer

    @Test func establishedInOrderDataIsAckedAndForwarded() {
        var snd = makeSendSequence(nxt: 1001, una: 1001)
        var rcv = makeRecvSequence(nxt: 5001, initialSeq: 5000)

        let data: [UInt8] = [0x48, 0x65, 0x6C, 0x6C, 0x6F] // "Hello"
        let seg = makeSegment(flags: .ack, seq: 5001, ack: 1001, payload: data)
        let (state, toSend, outData) = tcpProcess(
            state: .established, segment: seg, snd: &snd, rcv: &rcv, appClose: false
        )

        #expect(state == .established)
        #expect(toSend.count == 1)
        #expect(toSend[0].flags == .ack)
        #expect(toSend[0].ack == 5001 &+ UInt32(data.count))
        #expect(rcv.nxt == 5001 &+ UInt32(data.count))
        #expect(outData != nil)
    }

    @Test func establishedOutOfOrderDataTriggersDupAck() {
        var snd = makeSendSequence(nxt: 1001, una: 1001)
        var rcv = makeRecvSequence(nxt: 5001, initialSeq: 5000)

        // Segment with seq=5006 (skipping 5 bytes)
        let seg = makeSegment(flags: .ack, seq: 5006, ack: 1001, payload: [0x21])
        let (state, toSend, outData) = tcpProcess(
            state: .established, segment: seg, snd: &snd, rcv: &rcv, appClose: false
        )

        #expect(state == .established)
        #expect(toSend.count == 1)  // ACK only, no data
        #expect(toSend[0].flags == .ack)
        #expect(toSend[0].ack == 5001)  // re-ACK what we have
        #expect(outData == nil)  // no data forwarded
        #expect(rcv.nxt == 5001)  // nxt unchanged
    }

    @Test func establishedPureAckAdvancesSndUna() {
        var snd = makeSendSequence(nxt: 1500, una: 1001)
        var rcv = makeRecvSequence(nxt: 5001, initialSeq: 5000)

        // ACK up to 1200
        let seg = makeSegment(flags: .ack, seq: 5001, ack: 1200)
        let (state, toSend, _) = tcpProcess(
            state: .established, segment: seg, snd: &snd, rcv: &rcv, appClose: false
        )

        #expect(state == .established)
        #expect(toSend.isEmpty)
        #expect(snd.una == 1200)
    }

    @Test func establishedUpdatesPeerWindow() {
        var snd = makeSendSequence(nxt: 1001, una: 1001)
        var rcv = makeRecvSequence(nxt: 5001, initialSeq: 5000)

        let seg = makeSegment(flags: .ack, seq: 5001, ack: 1001, window: 8192)
        _ = tcpProcess(state: .established, segment: seg, snd: &snd, rcv: &rcv, appClose: false)

        #expect(snd.wnd == 8192)
    }

    // MARK: - ESTABLISHED → CLOSE_WAIT (peer FIN)

    @Test func establishedReceivesFinTransitionsToCloseWait() {
        var snd = makeSendSequence(nxt: 1001, una: 1001)
        var rcv = makeRecvSequence(nxt: 5001, initialSeq: 5000)

        let seg = makeSegment(flags: [.ack, .fin], seq: 5001, ack: 1001)
        let (state, toSend, _) = tcpProcess(
            state: .established, segment: seg, snd: &snd, rcv: &rcv, appClose: false
        )

        #expect(state == .closeWait)
        #expect(toSend.count == 1)
        #expect(toSend[0].flags == .ack)
        #expect(rcv.nxt == 5002)  // FIN consumes one sequence number
    }

    @Test func establishedDataPlusFinTransitionsToCloseWait() {
        var snd = makeSendSequence(nxt: 1001, una: 1001)
        var rcv = makeRecvSequence(nxt: 5001, initialSeq: 5000)

        let data: [UInt8] = [0x41, 0x42]
        let seg = makeSegment(flags: [.ack, .fin], seq: 5001, ack: 1001, payload: data)
        let (state, toSend, outData) = tcpProcess(
            state: .established, segment: seg, snd: &snd, rcv: &rcv, appClose: false
        )

        #expect(state == .closeWait)
        #expect(toSend.count == 2)
        #expect(rcv.nxt == 5001 &+ UInt32(data.count) &+ 1)  // data + FIN
        #expect(outData != nil)
    }

    // MARK: - ESTABLISHED → FIN_WAIT_1 (app close)

    @Test func establishedAppCloseSendsFin() {
        var snd = makeSendSequence(nxt: 1001, una: 1001)
        var rcv = makeRecvSequence(nxt: 5001, initialSeq: 5000)

        let seg = makeSegment(flags: .ack, seq: 5001, ack: 1001)
        let (state, toSend, _) = tcpProcess(
            state: .established, segment: seg, snd: &snd, rcv: &rcv, appClose: true
        )

        #expect(state == .finWait1)
        #expect(toSend.count == 1)
        #expect(toSend[0].flags.contains(.fin))
        #expect(toSend[0].flags.contains(.ack))
        #expect(snd.nxt == 1002)  // FIN consumes one sequence number
    }

    // MARK: - FIN_WAIT_1 → FIN_WAIT_2

    @Test func finWait1AckOfFinTransitionsToFinWait2() {
        // snd.nxt is advanced past our FIN (seq + 1 for FIN)
        var snd = makeSendSequence(nxt: 1002, una: 1001)
        var rcv = makeRecvSequence(nxt: 5001, initialSeq: 5000)

        let seg = makeSegment(flags: .ack, seq: 5001, ack: 1002)
        let (state, _, _) = tcpProcess(
            state: .finWait1, segment: seg, snd: &snd, rcv: &rcv, appClose: false
        )

        #expect(state == .finWait2)
    }

    // MARK: - FIN_WAIT_1 → CLOSED (simultaneous close)

    @Test func finWait1SimultaneousFinTransitionsToClosed() {
        var snd = makeSendSequence(nxt: 1002, una: 1001)
        var rcv = makeRecvSequence(nxt: 5001, initialSeq: 5000)

        let seg = makeSegment(flags: [.ack, .fin], seq: 5001, ack: 1002)
        let (state, toSend, _) = tcpProcess(
            state: .finWait1, segment: seg, snd: &snd, rcv: &rcv, appClose: false
        )

        #expect(state == .closed)
        #expect(toSend.count == 1)
        #expect(toSend[0].flags == .ack)
    }

    // MARK: - FIN_WAIT_2 → CLOSED

    @Test func finWait2ReceivesFinTransitionsToClosed() {
        var snd = makeSendSequence(nxt: 1002, una: 1001)
        var rcv = makeRecvSequence(nxt: 5001, initialSeq: 5000)

        let seg = makeSegment(flags: [.ack, .fin], seq: 5001, ack: 1002)
        let (state, toSend, _) = tcpProcess(
            state: .finWait2, segment: seg, snd: &snd, rcv: &rcv, appClose: false
        )

        #expect(state == .closed)
        #expect(toSend.count == 1)
        #expect(toSend[0].flags == .ack)
        #expect(rcv.nxt == 5002)
    }

    @Test func finWait2DataFollowedByFin() {
        var snd = makeSendSequence(nxt: 1002, una: 1001)
        var rcv = makeRecvSequence(nxt: 5001, initialSeq: 5000)

        let data: [UInt8] = [0x58]
        let seg = makeSegment(flags: [.ack, .fin], seq: 5001, ack: 1002, payload: data)
        let (state, toSend, outData) = tcpProcess(
            state: .finWait2, segment: seg, snd: &snd, rcv: &rcv, appClose: false
        )

        #expect(state == .closed)
        #expect(toSend.count == 1)
        #expect(outData != nil)
    }

    // MARK: - CLOSE_WAIT → LAST_ACK

    @Test func closeWaitAppCloseSendsFin() {
        var snd = makeSendSequence(nxt: 1001, una: 1001)
        var rcv = makeRecvSequence(nxt: 5002, initialSeq: 5000)

        let seg = makeSegment(flags: .ack, seq: 5002, ack: 1001)
        let (state, toSend, _) = tcpProcess(
            state: .closeWait, segment: seg, snd: &snd, rcv: &rcv, appClose: true
        )

        #expect(state == .lastAck)
        #expect(toSend.count == 1)
        #expect(toSend[0].flags.contains(.fin))
        #expect(snd.nxt == 1002)
    }

    @Test func closeWaitWithoutAppCloseStays() {
        var snd = makeSendSequence(nxt: 1001, una: 1001)
        var rcv = makeRecvSequence(nxt: 5002, initialSeq: 5000)

        let seg = makeSegment(flags: .ack, seq: 5002, ack: 1001)
        let (state, _, _) = tcpProcess(
            state: .closeWait, segment: seg, snd: &snd, rcv: &rcv, appClose: false
        )

        #expect(state == .closeWait)
    }

    // MARK: - LAST_ACK → CLOSED

    @Test func lastAckAcknowledgedTransitionsToClosed() {
        var snd = makeSendSequence(nxt: 1002, una: 1001)
        var rcv = makeRecvSequence(nxt: 5002, initialSeq: 5000)

        let seg = makeSegment(flags: .ack, seq: 5002, ack: 1002)
        let (state, _, _) = tcpProcess(
            state: .lastAck, segment: seg, snd: &snd, rcv: &rcv, appClose: false
        )

        #expect(state == .closed)
        #expect(snd.una == 1002)
    }

    @Test func lastAckWithoutAckStays() {
        var snd = makeSendSequence(nxt: 1002, una: 1001)
        var rcv = makeRecvSequence(nxt: 5002, initialSeq: 5000)

        let seg = makeSegment(flags: .syn, seq: 5002, ack: 0)
        let (state, _, _) = tcpProcess(
            state: .lastAck, segment: seg, snd: &snd, rcv: &rcv, appClose: false
        )

        #expect(state == .lastAck)
    }

    // MARK: - Sequence number tracking

    @Test func sendSequenceBytesInFlight() {
        let snd = SendSequence(nxt: 1500, una: 1000, wnd: 65535)
        #expect(snd.bytesInFlight == 500)
    }

    @Test func sendSequenceBytesInFlightZeroWhenAllAcked() {
        let snd = SendSequence(nxt: 1000, una: 1000, wnd: 65535)
        #expect(snd.bytesInFlight == 0)
    }

    @Test func isnIsNonZero() {
        let isn = tcpGenerateISN()
        #expect(isn != 0)
    }
}
