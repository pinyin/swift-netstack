import Testing
@testable import SwiftNetStack

// MARK: - closeWait pure ACK (regression: ACKs were silently dropped after peer FIN)

@Test func closeWait_pureAck_advances_snd_una() {
    var snd = SendSequence(nxt: 1000, una: 100, wnd: 65535)
    var rcv = RecvSequence(nxt: 500, initialSeq: 0)
    let seg = TCPSegmentInfo(seq: 500, ack: 500, flags: .ack, window: 2048)

    let (newState, toSend, _, dataLen) = tcpProcess(
        state: .closeWait, seg: seg,
        payloadPtr: nil, payloadLen: 0,
        snd: &snd, rcv: &rcv
    )

    // snd.una should advance from 100 → 500
    #expect(snd.una == 500, "closeWait pure ACK must advance snd.una")
    #expect(newState == .closeWait)
    #expect(toSend.isEmpty)
    #expect(dataLen == 0)
}

@Test func closeWait_pureAck_no_rewind() {
    var snd = SendSequence(nxt: 2000, una: 1500, wnd: 65535)
    var rcv = RecvSequence(nxt: 500, initialSeq: 0)

    // Old ACK for byte 1000 (before current snd.una=1500)
    let oldSeg = TCPSegmentInfo(seq: 500, ack: 1000, flags: .ack, window: 2048)

    let (_, _, _, _) = tcpProcess(
        state: .closeWait, seg: oldSeg,
        payloadPtr: nil, payloadLen: 0,
        snd: &snd, rcv: &rcv
    )

    // snd.una must NOT rewind from 1500 back to 1000
    #expect(snd.una == 1500, "closeWait must not rewind snd.una on old ACK")
}

// MARK: - finWait2 pure ACK (regression: missing handler)

@Test func finWait2_pureAck_advances_snd_una() {
    var snd = SendSequence(nxt: 1001, una: 100, wnd: 65535)
    var rcv = RecvSequence(nxt: 500, initialSeq: 0)
    let seg = TCPSegmentInfo(seq: 500, ack: 800, flags: .ack, window: 2048)

    let (newState, toSend, _, dataLen) = tcpProcess(
        state: .finWait2, seg: seg,
        payloadPtr: nil, payloadLen: 0,
        snd: &snd, rcv: &rcv
    )

    #expect(snd.una == 800, "finWait2 pure ACK must advance snd.una")
    #expect(newState == .finWait2)
    #expect(toSend.isEmpty)
    #expect(dataLen == 0)
}

// MARK: - established: ACK never rewinds snd.una

@Test func established_pureAck_never_rewinds_snd_una() {
    var snd = SendSequence(nxt: 5000, una: 3000, wnd: 65535)
    var rcv = RecvSequence(nxt: 100, initialSeq: 0)

    // A reordered old ACK arrives for byte 2000 (behind current una=3000)
    let oldSeg = TCPSegmentInfo(seq: 100, ack: 2000, flags: .ack, window: 2048)

    let (_, _, _, _) = tcpProcess(
        state: .established, seg: oldSeg,
        payloadPtr: nil, payloadLen: 0,
        snd: &snd, rcv: &rcv
    )

    #expect(snd.una == 3000, "established must not rewind snd.una on old/reordered ACK")
}

@Test func established_pureAck_advances_snd_una() {
    var snd = SendSequence(nxt: 5000, una: 3000, wnd: 65535)
    var rcv = RecvSequence(nxt: 100, initialSeq: 0)

    let seg = TCPSegmentInfo(seq: 100, ack: 4000, flags: .ack, window: 2048)

    let (_, _, _, _) = tcpProcess(
        state: .established, seg: seg,
        payloadPtr: nil, payloadLen: 0,
        snd: &snd, rcv: &rcv
    )

    #expect(snd.una == 4000, "established pure ACK must advance snd.una forward")
}

// MARK: - closeWait ACK with wraparound (32-bit sequence space)

@Test func closeWait_ack_advances_across_wraparound() {
    var snd = SendSequence(nxt: 1000, una: UInt32.max &- 100, wnd: 65535)
    var rcv = RecvSequence(nxt: 500, initialSeq: 0)

    // ACK wraps around past UInt32.max
    let seg = TCPSegmentInfo(seq: 500, ack: 50, flags: .ack, window: 2048)

    let (_, _, _, _) = tcpProcess(
        state: .closeWait, seg: seg,
        payloadPtr: nil, payloadLen: 0,
        snd: &snd, rcv: &rcv
    )

    // ack=50 is ahead of una=(max-100) in 32-bit wrap space
    #expect(snd.una == 50, "closeWait ACK must handle 32-bit wraparound correctly")
}

// MARK: - Basic state transition tests (moved from BDPDebug)

@Test func listen_syn_transitions_to_synReceived() {
    let seg = TCPSegmentInfo(seq: 2000, ack: 0, flags: .syn, window: 65535)
    var snd = SendSequence(nxt: 1000, una: 1000, wnd: 65535)
    var rcv = RecvSequence(nxt: 2000, initialSeq: 2000)

    let (newState, toSend, _, _) = _tcpProcessImpl(state: .listen, seg: seg, payloadPtr: nil, payloadLen: 0, snd: &snd, rcv: &rcv)

    #expect(newState == .synReceived)
    #expect(toSend.count == 1)
    #expect(toSend.first!.flags == [.syn, .ack])
}

@Test func listen_nonSyn_stays_in_listen() {
    let seg = TCPSegmentInfo(seq: 2000, ack: 0, flags: .ack, window: 65535)
    var snd = SendSequence(nxt: 1000, una: 1000, wnd: 65535)
    var rcv = RecvSequence(nxt: 2000, initialSeq: 2000)

    let (newState, toSend, _, _) = _tcpProcessImpl(state: .listen, seg: seg, payloadPtr: nil, payloadLen: 0, snd: &snd, rcv: &rcv)

    #expect(newState == .listen)
    #expect(toSend.isEmpty)
}

@Test func synReceived_matchingAck_transitions_to_established() {
    let seg = TCPSegmentInfo(seq: 2001, ack: 1001, flags: .ack, window: 65535)
    var snd = SendSequence(nxt: 1001, una: 1000, wnd: 65535)
    var rcv = RecvSequence(nxt: 2001, initialSeq: 2000)

    let (newState, _, _, _) = _tcpProcessImpl(state: .synReceived, seg: seg, payloadPtr: nil, payloadLen: 0, snd: &snd, rcv: &rcv)

    #expect(newState == .established)
}

@Test func synReceived_nonMatchingAck_stays_in_synReceived() {
    let seg = TCPSegmentInfo(seq: 2001, ack: 999, flags: .ack, window: 65535)
    var snd = SendSequence(nxt: 1001, una: 1000, wnd: 65535)
    var rcv = RecvSequence(nxt: 2001, initialSeq: 2000)

    let (newState, _, _, _) = _tcpProcessImpl(state: .synReceived, seg: seg, payloadPtr: nil, payloadLen: 0, snd: &snd, rcv: &rcv)

    #expect(newState == .synReceived)
}

@Test func established_fin_transitions_to_closeWait() {
    let seg = TCPSegmentInfo(seq: 2000, ack: 1000, flags: .fin, window: 65535)
    var snd = SendSequence(nxt: 1000, una: 1000, wnd: 65535)
    var rcv = RecvSequence(nxt: 2000, initialSeq: 2000)

    let (newState, toSend, _, _) = _tcpProcessImpl(state: .established, seg: seg, payloadPtr: nil, payloadLen: 0, snd: &snd, rcv: &rcv)

    #expect(newState == .closeWait)
    #expect(!toSend.isEmpty)
}

@Test func established_data_advances_rcv_nxt() {
    let dataBuf = UnsafeMutableRawBufferPointer.allocate(byteCount: 10, alignment: 8)
    dataBuf.initializeMemory(as: UInt8.self, repeating: 0x41)
    defer { dataBuf.deallocate() }
    let seg = TCPSegmentInfo(seq: 2000, ack: 1000, flags: .ack, window: 65535)
    var snd = SendSequence(nxt: 1000, una: 1000, wnd: 65535)
    var rcv = RecvSequence(nxt: 2000, initialSeq: 2000)

    let (newState, _, dataPtr, dataLen) = _tcpProcessImpl(state: .established, seg: seg, payloadPtr: UnsafeRawPointer(dataBuf.baseAddress!), payloadLen: 10, snd: &snd, rcv: &rcv)

    #expect(newState == .established)
    #expect(dataPtr != nil && dataLen == 10)
    #expect(rcv.nxt == 2010)
}

@Test func established_appClose_transitions_to_finWait1() {
    let seg = TCPSegmentInfo(seq: 2000, ack: 1000, flags: .ack, window: 65535)
    var snd = SendSequence(nxt: 1000, una: 1000, wnd: 65535)
    var rcv = RecvSequence(nxt: 2000, initialSeq: 2000)

    let (newState, toSend) = tcpAppClose(state: .established, snd: &snd, rcv: &rcv)

    #expect(newState == .finWait1)
    #expect(!toSend.isEmpty && toSend.first!.flags.isFin)
}

@Test func finWait1_ack_transitions_to_finWait2() {
    let seg = TCPSegmentInfo(seq: 2000, ack: 1001, flags: .ack, window: 65535)
    var snd = SendSequence(nxt: 1001, una: 1000, wnd: 65535)
    var rcv = RecvSequence(nxt: 2000, initialSeq: 2000)

    let (newState, _, _, _) = _tcpProcessImpl(state: .finWait1, seg: seg, payloadPtr: nil, payloadLen: 0, snd: &snd, rcv: &rcv)

    #expect(newState == .finWait2)
}

@Test func finWait2_fin_transitions_to_closed() {
    let seg = TCPSegmentInfo(seq: 2000, ack: 1000, flags: .fin, window: 65535)
    var snd = SendSequence(nxt: 1000, una: 1000, wnd: 65535)
    var rcv = RecvSequence(nxt: 2000, initialSeq: 2000)

    let (newState, _, _, _) = _tcpProcessImpl(state: .finWait2, seg: seg, payloadPtr: nil, payloadLen: 0, snd: &snd, rcv: &rcv)

    #expect(newState == .closed)
}

@Test func closeWait_appClose_transitions_to_lastAck() {
    var snd = SendSequence(nxt: 1000, una: 1000, wnd: 65535)
    var rcv = RecvSequence(nxt: 2000, initialSeq: 2000)

    let (newState, _) = tcpAppClose(state: .closeWait, snd: &snd, rcv: &rcv)

    #expect(newState == .lastAck)
}

@Test func lastAck_matchingAck_transitions_to_closed() {
    let seg = TCPSegmentInfo(seq: 2000, ack: 1001, flags: .ack, window: 65535)
    var snd = SendSequence(nxt: 1001, una: 1000, wnd: 65535)
    var rcv = RecvSequence(nxt: 2000, initialSeq: 2000)

    let (newState, _, _, _) = _tcpProcessImpl(state: .lastAck, seg: seg, payloadPtr: nil, payloadLen: 0, snd: &snd, rcv: &rcv)

    #expect(newState == .closed)
}

@Test func established_rst_transitions_to_closed() {
    let seg = TCPSegmentInfo(seq: 0, ack: 0, flags: .rst, window: 65535)
    var snd = SendSequence(nxt: 1000, una: 1000, wnd: 65535)
    var rcv = RecvSequence(nxt: 2000, initialSeq: 2000)

    let (newState, _, _, _) = _tcpProcessImpl(state: .established, seg: seg, payloadPtr: nil, payloadLen: 0, snd: &snd, rcv: &rcv)

    #expect(newState == .closed)
}

@Test func closed_syn_stays_closed() {
    let seg = TCPSegmentInfo(seq: 2000, ack: 0, flags: .syn, window: 65535)
    var snd = SendSequence(nxt: 1000, una: 1000, wnd: 65535)
    var rcv = RecvSequence(nxt: 2000, initialSeq: 2000)

    let (newState, _, _, _) = _tcpProcessImpl(state: .closed, seg: seg, payloadPtr: nil, payloadLen: 0, snd: &snd, rcv: &rcv)

    #expect(newState == .closed)
}
