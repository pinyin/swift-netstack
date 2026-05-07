/// Per-endpoint rate limiting state for TCP connections.
///
/// Uses a token bucket for connection-rate limiting plus a simple counter
/// for concurrent-connection caps.  Both limits are checked in a single
/// `tryAcquire` call; a `release` call decrements the concurrent counter
/// when a connection is torn down.
struct EndpointRateState {
    /// Available tokens (fractional for smooth refill).
    var tokens: Double
    /// Timestamp (seconds) of the last token refill.
    var lastRefill: UInt64
    /// Currently active TCP connections for this endpoint.
    var concurrentCount: Int

    let maxTokens: Double
    let maxConcurrent: Int
    let refillRate: Double   // tokens per second

    init(
        maxTokens: Double = 100,
        maxConcurrent: Int = 256,
        refillRate: Double = 100
    ) {
        self.tokens = maxTokens
        self.lastRefill = 0
        self.concurrentCount = 0
        self.maxTokens = maxTokens
        self.maxConcurrent = maxConcurrent
        self.refillRate = refillRate
    }

    /// Attempt to acquire one token and one concurrent slot.
    /// Returns `true` if the connection is allowed.
    mutating func tryAcquire(now: UInt64) -> Bool {
        refill(now: now)

        guard tokens >= 1.0 else { return false }
        guard concurrentCount < maxConcurrent else { return false }

        tokens -= 1.0
        concurrentCount += 1
        return true
    }

    /// Release one concurrent slot (called on connection teardown).
    mutating func release() {
        if concurrentCount > 0 { concurrentCount -= 1 }
    }

    // MARK: - Private

    private mutating func refill(now: UInt64) {
        if lastRefill == 0 {
            lastRefill = now
            return
        }
        let elapsed = Double(now &- lastRefill)
        guard elapsed > 0 else { return }
        tokens = min(maxTokens, tokens + elapsed * refillRate)
        lastRefill = now
    }
}
