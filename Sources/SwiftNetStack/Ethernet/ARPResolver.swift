import Foundation

// ARP table: IP → MAC mapping with TTL-based expiration.
final class ARPResolver {
    private var table: [UInt32: Data] = [:]
    private var timestamps: [UInt32: Date] = [:]

    init() {}

    func lookup(ip: UInt32) -> Data? {
        table[ip]
    }

    func set(ip: UInt32, mac: Data) {
        table[ip] = Data(mac.prefix(6))
        timestamps[ip] = Date()
    }

    /// Remove entries older than 300 seconds (5 minutes).
    func cleanup(now: Date) {
        let cutoff = now.addingTimeInterval(-300)
        for (ip, ts) in timestamps {
            if ts < cutoff {
                table[ip] = nil
                timestamps[ip] = nil
            }
        }
    }
}
