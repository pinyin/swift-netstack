import Testing
@testable import SwiftNetStack
import Darwin

/// Verify that incremental TCP checksum works correctly across multiple
/// rounds, catching the bug where lastACKChecksum is never updated after
/// the first ACK in buildAckFrame.

@Test func incrementalChecksum_twoRound_sameAsFull() {
    // Build template matching real usage
    let hostMAC = MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF)
    let vmMAC = MACAddress(0x00, 0x11, 0x22, 0x33, 0x44, 0x55)
    let srcIP = IPv4Address(192, 168, 3, 16)
    let dstIP = IPv4Address(100, 64, 1, 182)
    let tmpl = makeAckTemplate(
        hostMAC: hostMAC, vmMAC: vmMAC,
        srcIP: srcIP, dstIP: dstIP,
        srcPort: 7777, dstPort: 52300,
        window: 65535
    )

    // Round 1: seq=1000, ack=5000
    let ck1_full = computeACKFullChecksum(tmpl: tmpl, seq: 1000, ack: 5000,
                                          srcIP: srcIP, dstIP: dstIP)

    // Round 1→2: incremental from ck1
    let ck2_inc = computeIncrementalTCPChecksum(
        oldCK: ck1_full, oldSeq: 1000, newSeq: 1000,
        oldAck: 5000, newAck: 5536
    )
    let ck2_full = computeACKFullChecksum(tmpl: tmpl, seq: 1000, ack: 5536,
                                          srcIP: srcIP, dstIP: dstIP)
    #expect(ck2_inc == ck2_full, "Round 2: incremental must match full checksum")

    // Round 2→3: incremental from ck2 (correct behavior)
    let ck3_inc_correct = computeIncrementalTCPChecksum(
        oldCK: ck2_full, oldSeq: 1000, newSeq: 1000,
        oldAck: 5536, newAck: 6072
    )
    let ck3_full = computeACKFullChecksum(tmpl: tmpl, seq: 1000, ack: 6072,
                                          srcIP: srcIP, dstIP: dstIP)
    #expect(ck3_inc_correct == ck3_full, "Round 3 (correct): incremental must match full")

    // Round 1→3: incremental from stale ck1 (THE BUG)
    let ck3_inc_bug = computeIncrementalTCPChecksum(
        oldCK: ck1_full, oldSeq: 1000, newSeq: 1000,
        oldAck: 5536, newAck: 6072
    )
    #expect(ck3_inc_bug != ck3_full, "Round 3 (stale base): incremental from stale oldCK produces WRONG checksum")
}

@Test func incrementalChecksum_varyingSeqAndAck() {
    let hostMAC = MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF)
    let vmMAC = MACAddress(0x00, 0x11, 0x22, 0x33, 0x44, 0x55)
    let srcIP = IPv4Address(192, 168, 3, 16)
    let dstIP = IPv4Address(100, 64, 1, 182)
    let tmpl = makeAckTemplate(
        hostMAC: hostMAC, vmMAC: vmMAC,
        srcIP: srcIP, dstIP: dstIP,
        srcPort: 7777, dstPort: 52300,
        window: 65535
    )

    // Simulate a real sequence: seq stays constant (pure ACKs, no data),
    // ack advances as VM data is received.
    var currentCK = computeACKFullChecksum(tmpl: tmpl, seq: 4200, ack: 1000,
                                           srcIP: srcIP, dstIP: dstIP)
    var seq: UInt32 = 4200
    var ack: UInt32 = 1000

    // Advance ack 10 times, updating base checksum each time (CORRECT)
    for i in 1...10 {
        let newSeq = seq
        let newAck = ack + 536

        let incCK = computeIncrementalTCPChecksum(
            oldCK: currentCK, oldSeq: seq, newSeq: newSeq,
            oldAck: ack, newAck: newAck
        )
        let fullCK = computeACKFullChecksum(tmpl: tmpl, seq: newSeq, ack: newAck,
                                            srcIP: srcIP, dstIP: dstIP)
        #expect(incCK == fullCK, "Step \(i): incremental (correct base) must match full checksum")

        // Update for next round
        currentCK = fullCK  // <- THIS is the fix: update lastACKChecksum every time
        seq = newSeq
        ack = newAck
    }
}

@Test func incrementalChecksum_staleBase_producesWrongResult() {
    let hostMAC = MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF)
    let vmMAC = MACAddress(0x00, 0x11, 0x22, 0x33, 0x44, 0x55)
    let srcIP = IPv4Address(192, 168, 3, 16)
    let dstIP = IPv4Address(100, 64, 1, 182)
    let tmpl = makeAckTemplate(
        hostMAC: hostMAC, vmMAC: vmMAC,
        srcIP: srcIP, dstIP: dstIP,
        srcPort: 7777, dstPort: 52300,
        window: 65535
    )

    // First checksum (only ever computed once in the buggy code)
    let ck1 = computeACKFullChecksum(tmpl: tmpl, seq: 4200, ack: 1000,
                                     srcIP: srcIP, dstIP: dstIP)

    // Simulate the bug: base checksum (ck1) never updated
    let staleBase = ck1
    var oldSeq: UInt32 = 4200
    var oldAck: UInt32 = 1000

    var mismatchCount = 0
    for _ in 1...10 {
        let newSeq = oldSeq
        let newAck = oldAck + 536

        let incCK = computeIncrementalTCPChecksum(
            oldCK: staleBase,  // BUG: always uses ck1
            oldSeq: oldSeq, newSeq: newSeq,
            oldAck: oldAck, newAck: newAck
        )
        let fullCK = computeACKFullChecksum(tmpl: tmpl, seq: newSeq, ack: newAck,
                                            srcIP: srcIP, dstIP: dstIP)
        if incCK != fullCK {
            mismatchCount += 1
        }

        oldSeq = newSeq
        oldAck = newAck
    }

    #expect(mismatchCount > 0, "Stale base checksum should produce at least one mismatch")
}
