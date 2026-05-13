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
        snd: &snd, rcv: &rcv, appClose: false
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
        snd: &snd, rcv: &rcv, appClose: false
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
        snd: &snd, rcv: &rcv, appClose: false
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
        snd: &snd, rcv: &rcv, appClose: false
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
        snd: &snd, rcv: &rcv, appClose: false
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
        snd: &snd, rcv: &rcv, appClose: false
    )

    // ack=50 is ahead of una=(max-100) in 32-bit wrap space
    #expect(snd.una == 50, "closeWait ACK must handle 32-bit wraparound correctly")
}
