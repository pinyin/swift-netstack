import Darwin

/// Per-connection retransmission timer with exponential backoff.
struct TCPRetransmitTimer {
    private var rto: UInt64            // current retransmit timeout (seconds)
    private var nextFireTime: UInt64?  // Darwin time when the timer fires
    private var retransmitCount: Int = 0
    private let maxRetransmits: Int

    init(rto: UInt64 = 1, maxRetransmits: Int = 5) {
        self.rto = rto
        self.maxRetransmits = maxRetransmits
    }

    /// Arm the timer. Call after sending a segment that requires acknowledgment.
    mutating func schedule() {
        nextFireTime = UInt64(Darwin.time(nil)) + rto
    }

    /// Cancel the timer. Call when the expected ACK arrives.
    mutating func cancel() {
        nextFireTime = nil
    }

    /// Returns true if the timer is armed and has expired.
    func isExpired() -> Bool {
        guard let fireTime = nextFireTime else { return false }
        return UInt64(Darwin.time(nil)) >= fireTime
    }

    /// Returns true if armed (not idle).
    var isArmed: Bool { nextFireTime != nil }

    /// Handle expiry: double RTO (cap 60s), increment retransmit count.
    /// Returns true if the segment should be retransmitted.
    mutating func onExpire() -> Bool {
        retransmitCount += 1
        if retransmitCount > maxRetransmits { return false }
        rto = min(rto * 2, 60)
        schedule()
        return true
    }

    /// Number of consecutive retransmissions so far.
    var retransmits: Int { retransmitCount }
}
