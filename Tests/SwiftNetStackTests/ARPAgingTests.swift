import Testing
@testable import SwiftNetStack
import Darwin

// MARK: - ARP Entry Expiration (injectable time)

@Test func arpEntry_isExpired_respectsTimeout() {
    let ip = IPv4Address(10, 0, 0, 5)
    let mac = MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF)
    var entry = ARPEntry(ip: ip, mac: mac, endpointID: 0, createdAt: 1000)

    // Not expired at creation time
    #expect(!entry.isExpired(now: 1000, timeout: 3600))
    // Not expired just before timeout
    #expect(!entry.isExpired(now: 4599, timeout: 3600))
    // Expired just after timeout (1000 + 3600 = 4600)
    #expect(entry.isExpired(now: 4601, timeout: 3600))
}

@Test func arpEntry_isExpired_shortTimeout() {
    let ip = IPv4Address(10, 0, 0, 6)
    let mac = MACAddress(0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00)
    var entry = ARPEntry(ip: ip, mac: mac, endpointID: 1, createdAt: 0)

    #expect(!entry.isExpired(now: 29, timeout: 30))
    #expect(entry.isExpired(now: 31, timeout: 30))
}

@Test func arpEntry_defaultTimeoutIs3600() {
    let ip = IPv4Address(10, 0, 0, 7)
    let mac = MACAddress(0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11)
    var entry = ARPEntry(ip: ip, mac: mac, endpointID: 2, createdAt: 0)

    #expect(!entry.isExpired(now: 3599))
    #expect(entry.isExpired(now: 3601))
}

// MARK: - ARP Mapping reapExpired

@Test func arpMapping_reapExpired_removesStaleEntries() {
    var mapping = ARPMapping(hostMAC: MACAddress(0, 1, 2, 3, 4, 5), endpoints: [])
    let ip = IPv4Address(10, 0, 0, 8)
    let mac = MACAddress(0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11)
    mapping.add(ip: ip, mac: mac, endpointID: 0, createdAt: 0)
    #expect(mapping.isKnown(ip, now: 0, timeout: 3600), "entry known at t=0")

    mapping.reapExpired(now: 3601, timeout: 3600)
    #expect(!mapping.isKnown(ip, now: 3601, timeout: 3600), "entry reaped after expiry")
}

@Test func arpMapping_reapExpired_keepsFreshEntries() {
    var mapping = ARPMapping(hostMAC: MACAddress(0, 1, 2, 3, 4, 5), endpoints: [])
    let ip = IPv4Address(10, 0, 0, 9)
    let mac = MACAddress(0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22)
    mapping.add(ip: ip, mac: mac, endpointID: 0, createdAt: 1000)
    #expect(mapping.isKnown(ip, now: 1000, timeout: 3600), "entry known at t=1000")

    mapping.reapExpired(now: 2000, timeout: 3600)
    #expect(mapping.isKnown(ip, now: 2000, timeout: 3600), "fresh entry survives reaping")
}

@Test func arpMapping_lookup_returnsNilForExpiredEntry() {
    var mapping = ARPMapping(hostMAC: MACAddress(0, 1, 2, 3, 4, 5), endpoints: [])
    let ip = IPv4Address(10, 0, 0, 10)
    let mac = MACAddress(0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33)
    mapping.add(ip: ip, mac: mac, endpointID: 0, createdAt: 0)

    // Entry is expired but not yet reaped
    let result = mapping.lookup(ip: ip, now: 3601, timeout: 3600)
    #expect(result == nil, "expired entry returns nil from lookup")
}
