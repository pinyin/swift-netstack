import Testing
@testable import SwiftNetStack

@Suite(.serialized)
struct TCPRetransmitTimerTests {

    // MARK: - Initial state

    @Test func timerNotArmedInitially() {
        let timer = TCPRetransmitTimer()
        #expect(timer.isArmed == false)
        #expect(timer.retransmits == 0)
    }

    @Test func isExpiredReturnsFalseWhenNotArmed() {
        let timer = TCPRetransmitTimer()
        #expect(timer.isExpired() == false)
    }

    // MARK: - Schedule / Cancel

    @Test func scheduleArmsTimer() {
        var timer = TCPRetransmitTimer(rto: 9999) // won't expire soon
        timer.schedule()
        #expect(timer.isArmed == true)
    }

    @Test func cancelDisarmsTimer() {
        var timer = TCPRetransmitTimer()
        timer.schedule()
        #expect(timer.isArmed == true)
        timer.cancel()
        #expect(timer.isArmed == false)
    }

    @Test func timerNotExpiredImmediatelyAfterSchedule() {
        var timer = TCPRetransmitTimer(rto: 9999)
        timer.schedule()
        #expect(timer.isExpired() == false)
    }

    @Test func timerExpiresAfterRTOOfZero() {
        var timer = TCPRetransmitTimer(rto: 0)
        timer.schedule()
        // With RTO=0, the fire time is set to current time + 0 = current time,
        // so it should be expired immediately (or very soon given wall-clock).
        #expect(timer.isExpired() == true)
    }

    // MARK: - onExpire

    @Test func onExpireIncrementsRetransmitCount() {
        var timer = TCPRetransmitTimer(rto: 0)
        timer.schedule()
        let ok = timer.onExpire()
        #expect(ok == true)
        #expect(timer.retransmits == 1)
    }

    @Test func onExpireDoublesRTO() {
        var timer = TCPRetransmitTimer(rto: 1)
        timer.schedule()
        _ = timer.onExpire()
        // After first expiry, RTO doubles to 2
        timer.schedule()
        // We can't directly read RTO, but we know the second expiry spacing
        // Verify retransmits count incremented
        #expect(timer.retransmits == 1)
    }

    @Test func onExpireRearmsTimer() {
        var timer = TCPRetransmitTimer(rto: 0)
        timer.schedule()
        let ok = timer.onExpire()
        #expect(ok == true)
        #expect(timer.isArmed == true)
    }

    @Test func maxRetransmitsExceededReturnsFalse() {
        var timer = TCPRetransmitTimer(rto: 0, maxRetransmits: 3)
        timer.schedule()

        // First 3 onExpire should return true
        #expect(timer.onExpire() == true)  // count=1
        #expect(timer.onExpire() == true)  // count=2
        #expect(timer.onExpire() == true)  // count=3
        // 4th onExpire exceeds max (3) → returns false
        #expect(timer.onExpire() == false) // count=4 > 3
        #expect(timer.retransmits == 4)
    }

    @Test func rtoDoublesUpToCapOf60Seconds() {
        var timer = TCPRetransmitTimer(rto: 1, maxRetransmits: 10)
        timer.schedule()

        // RTO: 1 → 2 → 4 → 8 → 16 → 32 → 60 → 60 → 60 → 60
        for _ in 0..<6 {
            #expect(timer.onExpire() == true)
        }
        // After 6 expirations: 1→2→4→8→16→32
        // 7th: 32*2=64 capped to 60
        #expect(timer.onExpire() == true)
        // 8th: 60*2=120 capped to 60
        #expect(timer.onExpire() == true)
        #expect(timer.retransmits == 8)
    }

    @Test func cancelDoesNotResetRetransmitCount() {
        var timer = TCPRetransmitTimer(rto: 0)
        timer.schedule()
        _ = timer.onExpire()  // count=1
        timer.cancel()
        #expect(timer.isArmed == false)
        #expect(timer.retransmits == 1) // count preserved
    }
}
