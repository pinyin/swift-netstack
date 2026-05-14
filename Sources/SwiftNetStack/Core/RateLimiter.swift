import Darwin

// MARK: - Generic sliding-window rate limiter

/// A sliding-window rate limiter keyed by a Hashable type.
/// Used for ARP reply rate limiting, DHCP DISCOVER rate limiting,
/// and ICMP error message rate limiting (RFC 1812 §4.3.2.8).
struct RateLimiter<Key: Hashable> {
    let window: UInt64       // window duration in seconds
    let maxRequests: Int     // max requests per window

    private var counters: [Key: (count: Int, windowStart: UInt64)] = [:]

    init(window: UInt64, maxRequests: Int) {
        self.window = window
        self.maxRequests = maxRequests
    }

    /// Returns true if the request is allowed, false if rate-limited.
    mutating func allow(_ key: Key) -> Bool {
        let now = Self.now()
        if let entry = counters[key] {
            if now - entry.windowStart < window {
                if entry.count >= maxRequests { return false }
                counters[key] = (entry.count + 1, entry.windowStart)
            } else {
                counters[key] = (1, now)
            }
        } else {
            counters[key] = (1, now)
        }
        return true
    }

    /// Remove entries whose window has expired. Call periodically to prevent
    /// unbounded memory growth from one-shot senders.
    mutating func pruneExpired() {
        let now = Self.now()
        counters = counters.filter { now - $0.value.windowStart < window }
    }

    var entryCount: Int { counters.count }

    private static func now() -> UInt64 {
        UInt64(Darwin.time(nil))
    }
}
