import Foundation
import Testing
@testable import SwiftNetStack

// MARK: - Test Forwarder Init

@Test func testForwarderNew() {
    let mappings = [
        ForwarderMapping(hostPort: 2222, vmIP: ipToUInt32("192.168.65.2"), vmPort: 22),
        ForwarderMapping(hostPort: 8080, vmIP: ipToUInt32("192.168.65.2"), vmPort: 80),
    ]

    let fwd = Forwarder(gatewayIP: ipToUInt32("192.168.65.1"), mappings: mappings)
    #expect(fwd.count() == 0, "expected 0 entries on init, got \(fwd.count())")
    #expect(fwd.mappings.count == 2, "expected 2 mappings, got \(fwd.mappings.count)")
    // Listeners may succeed or fail depending on permissions; count should be <= mappings
    #expect(fwd.listeners.count <= 2, "expected at most 2 listeners")
}

// MARK: - Test Forwarder Empty Mappings

@Test func testForwarderEmptyMappings() {
    let fwd = Forwarder(gatewayIP: ipToUInt32("192.168.65.1"), mappings: [])
    #expect(fwd.count() == 0)
    #expect(fwd.mappings.isEmpty)
    #expect(fwd.listeners.isEmpty)
}

// MARK: - Test Forwarder Cleanup

@Test func testForwarderCleanup() {
    let fwd = Forwarder(gatewayIP: ipToUInt32("192.168.65.1"), mappings: [])

    // Manually add an entry marked closed on both sides
    let entry = ForwarderEntry(vmAddr: "192.168.65.2:22")
    entry.hostClosed = true
    entry.vmClosed = true
    fwd.entries[5] = entry

    #expect(fwd.count() == 1, "expected 1 entry, got \(fwd.count())")

    fwd.cleanup()
    #expect(fwd.count() == 0, "expected 0 entries after cleanup, got \(fwd.count())")
}

// MARK: - Test Forwarder Cleanup Keeps Open Entry

@Test func testForwarderCleanupKeepsOpenEntry() {
    let fwd = Forwarder(gatewayIP: ipToUInt32("192.168.65.1"), mappings: [])

    let entry = ForwarderEntry(vmAddr: "192.168.65.2:22")
    entry.hostClosed = false
    entry.vmClosed = false
    fwd.entries[5] = entry

    #expect(fwd.count() == 1)
    fwd.cleanup()
    #expect(fwd.count() == 1, "open entry should survive cleanup")
}

// MARK: - Test Forwarder Cleanup Host Closed Only

@Test func testForwarderCleanupHostClosedOnly() {
    let fwd = Forwarder(gatewayIP: ipToUInt32("192.168.65.1"), mappings: [])

    let entry = ForwarderEntry(vmAddr: "192.168.65.2:22")
    entry.hostClosed = true
    entry.vmClosed = false
    fwd.entries[7] = entry

    #expect(fwd.count() == 1)
    fwd.cleanup()
    // Host closed but VM not closed → entry should survive
    #expect(fwd.count() == 1, "host-closed-only entry should survive cleanup")
}

// MARK: - Test Forwarder Poll No Crash

@Test func testForwarderPollNoCrash() {
    let fwd = Forwarder(gatewayIP: ipToUInt32("192.168.65.1"), mappings: [])
    // poll with no entries should not crash
    fwd.poll()
    #expect(fwd.count() == 0)
}

// MARK: - Test Forwarder ProxyVMToHost No Crash

@Test func testForwarderProxyVMToHostNoCrash() {
    let fwd = Forwarder(gatewayIP: ipToUInt32("192.168.65.1"), mappings: [])
    fwd.proxyVMToHost()
    #expect(fwd.count() == 0)
}

// MARK: - Test Forwarder PollAccept No Crash

@Test func testForwarderPollAcceptNoCrash() {
    let cfg = makeConfig(gatewayIP: ipToUInt32("192.168.65.1"))
    let ts = TCPState(cfg: cfg)

    let fwd = Forwarder(gatewayIP: ipToUInt32("192.168.65.1"), mappings: [])
    // pollAccept with empty mappings should not crash
    fwd.pollAccept(tcpState: ts)
    #expect(fwd.count() == 0)
}

// MARK: - Test Forwarder Entry Defaults

@Test func testForwarderEntryDefaults() {
    let entry = ForwarderEntry(vmAddr: "192.168.65.2:22")
    #expect(entry.hostFD == -1)
    #expect(entry.vmConn == nil)
    #expect(!entry.hostClosed)
    #expect(!entry.vmClosed)
    #expect(!entry.deferredClose)
    #expect(entry.vmAddr == "192.168.65.2:22")
}

// MARK: - Test Forwarder Mapping

@Test func testForwarderMappingFields() {
    let m = ForwarderMapping(hostPort: 2222, vmIP: ipToUInt32("192.168.65.2"), vmPort: 22)
    #expect(m.hostPort == 2222)
    #expect(m.vmIP == ipToUInt32("192.168.65.2"))
    #expect(m.vmPort == 22)
}

// MARK: - Test Forwarder Multiple Cleanup Cycles

@Test func testForwarderMultipleCleanupCycles() {
    let fwd = Forwarder(gatewayIP: ipToUInt32("192.168.65.1"), mappings: [])

    let entry = ForwarderEntry(vmAddr: "192.168.65.2:22")
    entry.hostClosed = true
    entry.vmClosed = true
    fwd.entries[1] = entry

    #expect(fwd.count() == 1)

    fwd.cleanup()
    #expect(fwd.count() == 0, "first cleanup should remove closed entry")

    // Second cleanup should not crash
    fwd.cleanup()
    #expect(fwd.count() == 0, "second cleanup should be a no-op")
}

// MARK: - Test Forwarder Mappings Persist After Operations

@Test func testForwarderMappingsPersist() {
    let mappings = [
        ForwarderMapping(hostPort: 2222, vmIP: ipToUInt32("192.168.65.2"), vmPort: 22),
    ]

    let fwd = Forwarder(gatewayIP: ipToUInt32("192.168.65.1"), mappings: mappings)

    fwd.poll()
    fwd.proxyVMToHost()
    fwd.cleanup()

    // Mappings should survive operations
    #expect(fwd.mappings.count == 1)
    #expect(fwd.mappings[2222]?.vmPort == 22)
}
