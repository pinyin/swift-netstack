import Foundation
import Testing
@testable import SwiftNetStack

// Helper: syncs the timer wheel's lastTick to the given tick so subsequent
// schedule + expire calls have a predictable scan range.
func syncTimerWheel(_ tw: TimerWheel, tick: Int64) {
    // expired() updates lastTick=currentTick only when currentTick > lastTick.
    // Advance by 1 to guarantee lastTick advances.
    _ = tw.expired(currentTick: tick + 1)
}

// MARK: - TimerWheel Schedule

@Test func testTimerWheelSchedule() {
    let tw = TimerWheel(slotSizeNs: 10_000_000, numSlots: 100)

    let t1 = Tuple(srcIP: 0x0A000001, dstIP: 0x08080808, srcPort: 12345, dstPort: 80)
    let t2 = Tuple(srcIP: 0x0A000001, dstIP: 0x08080808, srcPort: 12346, dstPort: 80)

    let now = Date()
    let tick = tw.advance(now: now)
    syncTimerWheel(tw, tick: tick)

    tw.schedule(tuple: t1, tick: tick + 50)
    tw.schedule(tuple: t2, tick: tick + 50)

    // Not expired at a tick before scheduled time
    let expired = tw.expired(currentTick: tick + 5)
    #expect(expired.isEmpty, "nothing should expire at tick+5")
}

// MARK: - TimerWheel Expired

@Test func testTimerWheelExpired() {
    let tw = TimerWheel(slotSizeNs: 10_000_000, numSlots: 100)
    let t1 = Tuple(srcIP: 0x0A000001, dstIP: 0x08080808, srcPort: 12345, dstPort: 80)

    let now = Date()
    let tick = tw.advance(now: now)
    syncTimerWheel(tw, tick: tick)

    tw.schedule(tuple: t1, tick: tick + 10)

    let expired = tw.expired(currentTick: tick + 20)
    #expect(expired.contains(t1), "tuple t1 should have expired")
}

// MARK: - TimerWheel Not Expired

@Test func testTimerWheelNotExpired() {
    let tw = TimerWheel(slotSizeNs: 10_000_000, numSlots: 100)
    let t1 = Tuple(srcIP: 0x0A000001, dstIP: 0x08080808, srcPort: 12345, dstPort: 80)

    let now = Date()
    let tick = tw.advance(now: now)
    syncTimerWheel(tw, tick: tick)

    tw.schedule(tuple: t1, tick: tick + 100)

    let expired = tw.expired(currentTick: tick + 20)
    #expect(expired.isEmpty, "should not expire prematurely")
}

// MARK: - TimerWheel Wrap Around Cursor

@Test func testTimerWheelWrapAroundCursor() {
    let tw = TimerWheel(slotSizeNs: 10_000_000, numSlots: 100)

    let now = Date()
    let tick = tw.advance(now: now)
    syncTimerWheel(tw, tick: tick)

    // Verify that expired() handles wrap-around of the internal cursor.
    // Schedule entries across a wide tick range to force multiple slot visits.
    var tuples: [Tuple] = []
    for i in stride(from: 5, through: 95, by: 10) {
        let t = Tuple(srcIP: 0x0A000001, dstIP: 0x08080808, srcPort: UInt16(i), dstPort: 80)
        tuples.append(t)
        tw.schedule(tuple: t, tick: tick + Int64(i))
    }

    // All should expire
    let expired = tw.expired(currentTick: tick + 100)
    #expect(expired.count == tuples.count, "all \(tuples.count) entries should expire, got \(expired.count)")
}

// MARK: - TimerWheel Multiple Advances

@Test func testTimerWheelMultipleAdvances() {
    let tw = TimerWheel(slotSizeNs: 10_000_000, numSlots: 100)
    let t1 = Tuple(srcIP: 0x0A000001, dstIP: 0x08080808, srcPort: 12345, dstPort: 80)

    let now = Date()
    let tick = tw.advance(now: now)
    syncTimerWheel(tw, tick: tick)

    tw.schedule(tuple: t1, tick: tick + 30)

    let r1 = tw.expired(currentTick: tick + 5)
    #expect(r1.isEmpty)

    let r2 = tw.expired(currentTick: tick + 15)
    #expect(r2.isEmpty)

    let r3 = tw.expired(currentTick: tick + 35)
    #expect(r3.contains(t1))
}

// MARK: - TimerWheel Empty

@Test func testTimerWheelEmpty() {
    let tw = TimerWheel(slotSizeNs: 10_000_000, numSlots: 100)
    let now = Date()
    let tick = tw.advance(now: now)
    syncTimerWheel(tw, tick: tick)
    let expired = tw.expired(currentTick: tick + 100)
    #expect(expired.isEmpty, "expired should be empty with no scheduled entries")
}

// MARK: - TimerWheel Advancing Backwards No-op

@Test func testTimerWheelAdvancingBackwards() {
    let tw = TimerWheel(slotSizeNs: 10_000_000, numSlots: 100)
    let t1 = Tuple(srcIP: 0x0A000001, dstIP: 0x08080808, srcPort: 12345, dstPort: 80)

    let now = Date()
    let tick = tw.advance(now: now)
    syncTimerWheel(tw, tick: tick)

    tw.schedule(tuple: t1, tick: tick + 30)

    let expired = tw.expired(currentTick: tick - 10)
    #expect(expired.isEmpty, "advancing backwards should produce no expired entries")
}

// MARK: - TimerWheel Same Slot Different Ticks

@Test func testTimerWheelSameSlotDifferentTicks() {
    let tw = TimerWheel(slotSizeNs: 10_000_000, numSlots: 100)

    let t1 = Tuple(srcIP: 0x0A000001, dstIP: 0x08080808, srcPort: 100, dstPort: 80)
    let t2 = Tuple(srcIP: 0x0A000001, dstIP: 0x08080808, srcPort: 200, dstPort: 80)

    let now = Date()
    let tick = tw.advance(now: now)
    syncTimerWheel(tw, tick: tick)

    // Same slot modulo 100, different absolute ticks
    tw.schedule(tuple: t1, tick: tick + 5)
    tw.schedule(tuple: t2, tick: tick + 105) // 105 mod 100 = 5, same slot

    let r1 = tw.expired(currentTick: tick + 50)
    #expect(r1.contains(t1), "t1 should expire (tick+5)")
    #expect(!r1.contains(t2), "t2 should not expire yet (tick+105)")

    let r2 = tw.expired(currentTick: tick + 110)
    #expect(r2.contains(t2), "t2 should expire after further advance")
}

// MARK: - TimerWheel advance helper

@Test func testTimerWheelAdvance() {
    let tw = TimerWheel(slotSizeNs: 10_000_000, numSlots: 100)
    let now = Date()
    let tick = tw.advance(now: now)
    let expected = Int64(now.timeIntervalSince1970 * 1e9) / 10_000_000
    #expect(tick == expected, "advance should compute correct tick")
}
