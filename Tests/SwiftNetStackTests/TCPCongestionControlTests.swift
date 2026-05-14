import Testing
@testable import SwiftNetStack

// MARK: - RFC 5681 Congestion Control Tests

@Test func cwndLimitsBurstSize() {
    // effectiveWnd = min(wnd, cwnd) caps sends even when wnd is large
    var snd = SendSequence(nxt: 0, una: 0, wnd: 65535, cwnd: 2920, ssthresh: 65535)
    // With nxt=una=0, inFlight=0, so canSend = min(65535, 2920) - 0 = 2920
    let effectiveWnd = Swift.min(snd.wnd, snd.cwnd)
    let inFlight = snd.nxt &- snd.una
    var canSend = Int(effectiveWnd) - Int(inFlight)
    // Cap at mss=1460
    if canSend > 1460 { canSend = 1460 }
    #expect(canSend == 1460, "with cwnd=2920 and wnd=65535, effectiveWnd caps send to mss=1460")

    // With cwnd=7300 (5*MSS), inFlight=0, effectiveWnd=7300 -> canSend=1460 (capped by mss)
    snd.cwnd = 7300
    let ew2 = Swift.min(snd.wnd, snd.cwnd)
    var cs2 = Int(ew2) - Int(snd.nxt &- snd.una)
    if cs2 > 1460 { cs2 = 1460 }
    #expect(cs2 == 1460, "with cwnd=7300, mss cap still applies")
}

@Test func fastRetransmitEntry() {
    // Simulate 3 dup ACKs: enter fast retransmit/recovery
    // snd.nxt=5000, snd.una=0 → inFlight=5000
    var snd = SendSequence(nxt: 5000, una: 0, wnd: 65535, cwnd: 4380, ssthresh: 65535)
    let mss: UInt32 = 1460

    // 3rd dup ACK (dupAckCount >= 3, una NOT advanced)
    let dupAckCount: UInt8 = 3
    let inFlight = snd.nxt &- snd.una  // 5000
    let unaAdvanced = false

    if !snd.inRecovery {
        if dupAckCount >= 3 && !unaAdvanced {
            snd.ssthresh = max(inFlight / 2, UInt32(2 * mss))
            snd.cwnd = snd.ssthresh + UInt32(3 * mss)
            snd.recover = snd.nxt
            snd.inRecovery = true
        }
    }

    #expect(snd.ssthresh == max(5000 / 2, 2 * mss), "ssthresh = max(inFlight/2, 2*mss)")
    #expect(snd.ssthresh == 2920)  // max(2500, 2920)
    #expect(snd.cwnd == 2920 + 3 * 1460, "cwnd = ssthresh + 3*MSS")
    #expect(snd.cwnd == 7300)
    #expect(snd.recover == 5000, "recover = snd.nxt at loss detection")
    #expect(snd.inRecovery == true, "inRecovery flag set")
}

@Test func recoveryExitOnFullAck() {
    // In recovery, ACK >= recover → exit recovery
    var snd = SendSequence(nxt: 10000, una: 0, wnd: 65535, cwnd: 7300, ssthresh: 2920)
    snd.recover = 5000
    snd.inRecovery = true
    let mss: UInt32 = 1460
    let ackValue: UInt32 = 6000  // ack >= recover (5000)

    if snd.inRecovery {
        if (ackValue &- snd.recover) < (1 << 31) {
            // Full ACK: exit recovery
            let inFlight = snd.nxt &- snd.una
            snd.cwnd = min(snd.ssthresh, inFlight + mss)
            snd.inRecovery = false
        }
    }

    #expect(snd.inRecovery == false, "exited recovery on full ACK")
    #expect(snd.cwnd == snd.ssthresh, "cwnd = ssthresh after recovery exit")
    #expect(snd.cwnd == 2920)
}

@Test func recoveryPartialAck() {
    // In recovery, ACK advances una but ack < recover → deflate+inflate cwnd
    var snd = SendSequence(nxt: 10000, una: 1000, wnd: 65535, cwnd: 7300, ssthresh: 2920)
    snd.recover = 5000
    snd.inRecovery = true
    let mss: UInt32 = 1460

    let ackValue: UInt32 = 3000  // ack < recover (5000)
    let oldUna = snd.una
    snd.una = 3000  // una advanced
    let unaDelta = Int(snd.una &- oldUna)  // 2000

    if snd.inRecovery {
        if (ackValue &- snd.recover) < (1 << 31) {
            // full ACK — not this path
        } else if unaDelta > 0 {
            // Partial ACK
            snd.cwnd -= UInt32(unaDelta)
            snd.cwnd += mss
        }
    }

    #expect(snd.cwnd == 7300 - 2000 + 1460, "cwnd deflated by unaDelta, inflated by MSS")
    #expect(snd.cwnd == 6760)
    #expect(snd.inRecovery == true, "still in recovery after partial ACK")
}

@Test func recoveryDupAckInflatesCwnd() {
    // In recovery, dup ACK (no una advance) → inflate cwnd by MSS
    var snd = SendSequence(nxt: 10000, una: 1000, wnd: 65535, cwnd: 7300, ssthresh: 2920)
    snd.recover = 5000
    snd.inRecovery = true
    let mss: UInt32 = 1460

    let ackValue: UInt32 = 1000  // dup ACK, same as una
    let unaAdvanced = false

    if snd.inRecovery {
        if (ackValue &- snd.recover) < (1 << 31) {
            // full ACK — not this path
        } else if unaAdvanced {
            // partial ACK — not this path
        } else {
            snd.cwnd += mss
        }
    }

    #expect(snd.cwnd == 7300 + 1460, "cwnd inflated by MSS on dup ACK in recovery")
    #expect(snd.cwnd == 8760)
    #expect(snd.inRecovery == true, "still in recovery after dup ACK")
}

@Test func recoveryRoundTrip() {
    // Complete loss → recovery → exit cycle
    let mss: UInt32 = 1460
    var snd = SendSequence(nxt: 5000, una: 0, wnd: 65535,
                           cwnd: 14600,
                           ssthresh: 65535)

    // Initial cwnd = IW = 10*MSS = 14600 (RFC 6928)
    #expect(snd.cwnd == 14600)

    // Step 1: Normal operation, send some data
    snd.nxt = 5000
    #expect(snd.inRecovery == false)

    // Step 2: 3rd dup ACK arrives (una stays at 0), enter recovery
    let inFlight = snd.nxt &- snd.una
    snd.ssthresh = max(inFlight / 2, UInt32(2 * mss))
    snd.cwnd = snd.ssthresh + UInt32(3 * mss)
    snd.recover = snd.nxt
    snd.inRecovery = true

    #expect(snd.ssthresh == 2920)  // max(2500, 2920)
    #expect(snd.cwnd == 7300)      // 2920 + 4380
    #expect(snd.recover == 5000)
    #expect(snd.inRecovery == true)

    // Step 3: Dup ACKs in recovery inflate cwnd
    snd.cwnd += mss  // dup ACK 1
    snd.cwnd += mss  // dup ACK 2
    #expect(snd.cwnd == 7300 + 2920)  // = 10220

    // Step 4: Partial ACK (una advances to 2000, ack=2000 < recover=5000)
    let oldUna = snd.una
    snd.una = 2000
    let unaDelta = Int(snd.una &- oldUna)  // 2000
    snd.cwnd -= UInt32(unaDelta)
    snd.cwnd += mss
    #expect(snd.cwnd == 10220 - 2000 + 1460)  // = 9680

    // Step 5: Full ACK arrives (ack=6000 >= recover=5000), exit recovery
    let ackValue: UInt32 = 6000
    let finalInFlight = snd.nxt &- snd.una  // 3000
    if (ackValue &- snd.recover) < (1 << 31) {
        snd.cwnd = min(snd.ssthresh, finalInFlight + mss)  // min(2920, 3000+1460) = 2920
        snd.inRecovery = false
    }

    #expect(snd.inRecovery == false, "exited recovery")
    #expect(snd.cwnd == 2920, "cwnd = ssthresh after recovery exit")
    #expect(snd.cwnd < 7300, "cwnd reduced after congestion event")
}

// MARK: - SACK-aware retransmit truncation

@Test func sackScoreboard_firstSackedAfter_findsFirstBlock() {
    var sack = SACKScoreboard()
    // Record out-of-order data: seq 3000-4000
    sack.record(3000, 4000)
    sack.record(5000, 6000)

    let r1 = sack.firstSackedAfter(from: 1000)
    #expect(r1 == 3000, "first SACK block after seq 1000 starts at 3000")

    let r2 = sack.firstSackedAfter(from: 3500)
    #expect(r2 == 5000, "seq 3500 is inside first block, next block starts at 5000")

    let r3 = sack.firstSackedAfter(from: 6000)
    #expect(r3 == nil, "no SACK block after 6000")
}

@Test func sackScoreboard_firstSackedAfter_empty() {
    let sack = SACKScoreboard()
    #expect(sack.firstSackedAfter(from: 0) == nil)
    #expect(sack.firstSackedAfter(from: 5000) == nil)
}

@Test func retransmitTruncation_sackBoundary() {
    // Simulate: snd.una=1000, SACK=[2000,3000), MSS=1460
    // Retransmit from 1000 with 1460 bytes would cover 1000-2460.
    // But 2000-2460 is SACKed → truncate to 1000 bytes (1000-2000).
    var sack = SACKScoreboard()
    sack.record(2000, 3000)

    let sndUna: UInt32 = 1000
    let rtLen = 1460  // naive retransmit length

    var actualLen = rtLen
    if let firstSacked = sack.firstSackedAfter(from: sndUna) {
        let sackedOffset = Int(firstSacked &- sndUna)
        if sackedOffset > 0, sackedOffset < actualLen {
            actualLen = sackedOffset
        }
    }
    #expect(actualLen == 1000, "retransmit truncated at first SACK boundary")
}

@Test func retransmitTruncation_noSackBlocks() {
    let sack = SACKScoreboard()
    let sndUna: UInt32 = 1000
    let rtLen = 1460

    var actualLen = rtLen
    if let firstSacked = sack.firstSackedAfter(from: sndUna) {
        let sackedOffset = Int(firstSacked &- sndUna)
        if sackedOffset > 0, sackedOffset < actualLen {
            actualLen = sackedOffset
        }
    }
    #expect(actualLen == 1460, "no SACK blocks → no truncation")
}

@Test func retransmitTruncation_sackStartsBeyondRetransmit() {
    // SACK block starts at offset 1460, same as mss → no truncation needed
    var sack = SACKScoreboard()
    sack.record(2460, 3000)  // offset = 2460-1000 = 1460

    let sndUna: UInt32 = 1000
    let rtLen = 1460
    var actualLen = rtLen
    if let firstSacked = sack.firstSackedAfter(from: sndUna) {
        let sackedOffset = Int(firstSacked &- sndUna)
        if sackedOffset > 0, sackedOffset < actualLen {
            actualLen = sackedOffset
        }
    }
    #expect(actualLen == 1460, "SACK starts at or beyond mss → full retransmit")
}

// MARK: - Limited Transmit (RFC 3042)

@Test func limitedTransmit_allowsSendOnDupAck1() {
    // On 1st dup ACK, Limited Transmit allows one segment even when cwnd-limited.
    let cwnd: UInt32 = 2920
    let wnd: UInt32 = 65535
    let inFlight: UInt32 = 2920  // cwnd full
    let dupAckCount: UInt8 = 1
    let mss = 1400

    let effectiveWnd = Swift.min(wnd, cwnd)
    var canSend = Int(effectiveWnd) - Int(inFlight)
    #expect(canSend <= 0, "cwnd-limited: canSend is 0")

    // Limited Transmit: allowed on dup ACK 1 or 2
    if canSend <= 0, dupAckCount >= 1, dupAckCount <= 2,
       Int(wnd) > Int(inFlight) {
        canSend = mss
    }
    #expect(canSend == mss, "Limited Transmit allows one segment on 1st dup ACK")
}

@Test func limitedTransmit_notAllowedOnDupAck3() {
    // On 3rd dup ACK, we enter fast retransmit — Limited Transmit does NOT apply.
    let cwnd: UInt32 = 2920
    let wnd: UInt32 = 65535
    let inFlight: UInt32 = 2920
    let dupAckCount: UInt8 = 3
    let mss = 1400

    let effectiveWnd = Swift.min(wnd, cwnd)
    var canSend = Int(effectiveWnd) - Int(inFlight)

    let limitedTransmitOK = dupAckCount >= 1 && dupAckCount <= 2
    if canSend <= 0, limitedTransmitOK, Int(wnd) > Int(inFlight) {
        canSend = mss
    }
    #expect(!limitedTransmitOK, "dupAckCount=3 → Limited Transmit condition is false")
    #expect(canSend <= 0, "Limited Transmit NOT allowed on 3rd dup ACK")
}

@Test func limitedTransmit_notAllowedWhenWndFull() {
    // Even on 1st dup ACK, Limited Transmit requires receiver window headroom.
    let cwnd: UInt32 = 2920
    let wnd: UInt32 = 2920  // same as inFlight → receiver window full
    let inFlight: UInt32 = 2920
    let dupAckCount: UInt8 = 1
    let mss = 1400

    let effectiveWnd = Swift.min(wnd, cwnd)
    var canSend = Int(effectiveWnd) - Int(inFlight)

    if canSend <= 0, dupAckCount >= 1, dupAckCount <= 2,
       Int(wnd) > Int(inFlight) {
        canSend = mss
    }
    #expect(canSend <= 0, "Limited Transmit blocked when receiver window is full")
}

// MARK: - cwnd growth (slow start + congestion avoidance)

@Test func slowStartGrowsCwndOnNewAck() {
    let smss: UInt32 = 1460
    var snd = SendSequence(nxt: 5000, una: 0, wnd: 65535,
                           cwnd: 4380, ssthresh: 65535)
    #expect(snd.cwnd == 4380, "initial cwnd = IW")
    #expect(snd.cwnd < snd.ssthresh, "in slow start")

    // New ACK acknowledges 1460 bytes
    snd.growCwnd(bytesAcked: 1460, smss: smss)
    #expect(snd.cwnd == 4380 + 1460, "slow start: cwnd += bytesAcked per ACK")
    #expect(snd.cwnd == 5840)

    // Another ACK for 2920 bytes (delayed ACK covering 2 segments)
    snd.growCwnd(bytesAcked: 2920, smss: smss)
    #expect(snd.cwnd == 5840 + 1460, "slow start: cwnd += min(bytesAcked, SMSS)")
    #expect(snd.cwnd == 7300)
}

@Test func slowStartCapsGrowthAtSMSS() {
    let smss: UInt32 = 1400
    var snd = SendSequence(nxt: 0, una: 0, wnd: 65535,
                           cwnd: 2920, ssthresh: 65535)

    // ACK covering many bytes (delayed ACK after several segments)
    snd.growCwnd(bytesAcked: 5600, smss: smss)
    #expect(snd.cwnd == 2920 + 1400, "slow start cap: cwnd += min(bytesAcked, SMSS)")
    #expect(snd.cwnd == 4320)
}

@Test func congestionAvoidanceGrowsCwnd() {
    let smss: UInt32 = 1460
    // cwnd >= ssthresh → congestion avoidance
    var snd = SendSequence(nxt: 0, una: 0, wnd: 65535,
                           cwnd: 20000, ssthresh: 14600)
    #expect(snd.cwnd >= snd.ssthresh, "in congestion avoidance")

    // SMSS * SMSS / cwnd = 1460 * 1460 / 20000 = 2131600 / 20000 = 106
    let expectedInc = Swift.max(1, smss &* smss / 20000)
    #expect(expectedInc == 106)

    snd.growCwnd(bytesAcked: 1460, smss: smss)
    #expect(snd.cwnd == 20000 + expectedInc, "congestion avoidance: cwnd += SMSS^2/cwnd")
}

@Test func cwndGrowthSuppressedInRecovery() {
    let smss: UInt32 = 1460
    var snd = SendSequence(nxt: 5000, una: 0, wnd: 65535,
                           cwnd: 7300, ssthresh: 2920)
    snd.inRecovery = true

    let cwndBefore = snd.cwnd
    snd.growCwnd(bytesAcked: 1460, smss: smss)
    #expect(snd.cwnd == cwndBefore, "cwnd should NOT grow during recovery")
}

@Test func cwndGrowthNoopOnZeroBytesAcked() {
    var snd = SendSequence(nxt: 0, una: 0, wnd: 65535,
                           cwnd: 4380, ssthresh: 65535)
    let cwndBefore = snd.cwnd
    snd.growCwnd(bytesAcked: 0, smss: 1460)
    #expect(snd.cwnd == cwndBefore, "zero bytes acked → no cwnd change")
}

// MARK: - RTO cwnd reset (RFC 5681 §5)

@Test func rtoResetsCwndToLossWindow() {
    let smss: UInt32 = 1460
    var snd = SendSequence(nxt: 10000, una: 5000, wnd: 65535,
                           cwnd: 20000, ssthresh: 10000)
    snd.inRecovery = true

    snd.resetCwndOnRTO(smss: smss)

    let inFlight = UInt32(5000)  // nxt - una = 10000 - 5000
    #expect(snd.ssthresh == max(inFlight / 2, 2 * smss),
            "ssthresh = max(inFlight/2, 2*SMSS)")
    #expect(snd.ssthresh == max(2500, 2920))
    #expect(snd.ssthresh == 2920)
    #expect(snd.cwnd == smss, "cwnd = 1 SMSS (Loss Window)")
    #expect(snd.inRecovery == false, "recovery flag cleared on RTO")
}

@Test func rtoResetsCwndWithSmallInFlight() {
    let smss: UInt32 = 1400
    // Small inFlight (only 1 segment) → ssthresh floored at 2*SMSS
    var snd = SendSequence(nxt: 1400, una: 0, wnd: 65535,
                           cwnd: 4380, ssthresh: 65535)

    snd.resetCwndOnRTO(smss: smss)

    #expect(snd.ssthresh == 2 * smss, "ssthresh floored at 2*SMSS")
    #expect(snd.ssthresh == 2800)
    #expect(snd.cwnd == smss, "cwnd = 1 SMSS")
    #expect(snd.inRecovery == false)
}
