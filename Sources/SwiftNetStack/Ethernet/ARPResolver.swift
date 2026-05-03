import Foundation

// ARP table: IP → MAC mapping.
final class ARPResolver {
    private var table: [UInt32: Data] = [:]

    init() {}

    func lookup(ip: UInt32) -> Data? {
        table[ip]
    }

    func set(ip: UInt32, mac: Data) {
        table[ip] = Data(mac.prefix(6))
    }
}
