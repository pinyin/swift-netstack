import Testing
import Darwin
@testable import SwiftNetStack

@Suite(.serialized)
struct PollingTransportTests {

    private func makeSocketPair() -> (fd0: Int32, fd1: Int32)? {
        var fds: [Int32] = [-1, -1]
        let rc = socketpair(AF_UNIX, SOCK_DGRAM, 0, &fds)
        guard rc == 0 else { return nil }
        return (fds[0], fds[1])
    }

    // MARK: - Read datagrams

    @Test func readPacketsFromSingleEndpoint() {
        guard let (vmFD, ourFD) = makeSocketPair() else {
            Issue.record("socketpair failed: \(errno)")
            return
        }
        defer { close(vmFD); close(ourFD) }

        let ep = VMEndpoint(id: 1, fd: vmFD, subnet: IPv4Subnet(network: IPv4Address(100, 64, 1, 0), prefixLength: 24), gateway: IPv4Address(100, 64, 1, 1))

        // Write data BEFORE calling readPackets so poll() finds it
        let data: [UInt8] = Array(0..<64).map { UInt8($0) }
        data.withUnsafeBytes { _ = Darwin.write(ourFD, $0.baseAddress!, data.count) }

        // Create a separate fd for TUN (use another socketpair, just need a valid fd that won't have data)
        guard let (tunFD, _) = makeSocketPair() else {
            Issue.record("tun socketpair failed")
            return
        }
        defer { close(tunFD) }

        var transport = PollingTransport(endpoints: [ep], tunFD: tunFD)
        let round = RoundContext()
        let packets = transport.readPackets(round: round)

        #expect(packets.count == 1)
        guard packets.count == 1 else { return }
        #expect(packets[0].endpointID == 1)
        #expect(packets[0].packet.totalLength == 64)
    }

    // MARK: - Write+read round-trip

    @Test func writeThenReadRoundTrip() {
        guard let (vmFD, ourFD) = makeSocketPair() else {
            Issue.record("socketpair failed: \(errno)")
            return
        }
        defer { close(vmFD); close(ourFD) }

        let ep = VMEndpoint(id: 1, fd: vmFD, subnet: IPv4Subnet(network: IPv4Address(100, 64, 1, 0), prefixLength: 24), gateway: IPv4Address(100, 64, 1, 1))

        guard let (tunFD, _) = makeSocketPair() else {
            Issue.record("tun socketpair failed")
            return
        }
        defer { close(tunFD) }

        var transport = PollingTransport(endpoints: [ep], tunFD: tunFD)

        // Write a packet to endpoint 1 (goes to vmFD, which we read from ourFD)
        var pkt = PacketBuffer(capacity: 128)
        guard let ptr = pkt.appendPointer(count: 10) else { return }
        let sendData: [UInt8] = [0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05]
        sendData.withUnsafeBytes { ptr.copyMemory(from: $0.baseAddress!, byteCount: 10) }

        transport.writePackets([(endpointID: 1, packet: pkt)])

        // Read from the other end of the socketpair
        var recvBuf = [UInt8](repeating: 0, count: 128)
        let n = Darwin.read(ourFD, &recvBuf, 128)
        #expect(n == 10)
        #expect(Array(recvBuf[0..<10]) == sendData)
    }

    // MARK: - Multiple endpoints

    @Test func readFromMultipleEndpoints() {
        guard let (vmFD1, ourFD1) = makeSocketPair(),
              let (vmFD2, ourFD2) = makeSocketPair() else {
            Issue.record("socketpair failed: \(errno)")
            return
        }
        defer { close(vmFD1); close(vmFD2); close(ourFD1); close(ourFD2) }

        let ep1 = VMEndpoint(id: 1, fd: vmFD1, subnet: IPv4Subnet(network: IPv4Address(100, 64, 1, 0), prefixLength: 24), gateway: IPv4Address(100, 64, 1, 1))
        let ep2 = VMEndpoint(id: 2, fd: vmFD2, subnet: IPv4Subnet(network: IPv4Address(100, 64, 2, 0), prefixLength: 24), gateway: IPv4Address(100, 64, 2, 1))

        // Write data to both endpoints
        let data1: [UInt8] = [1, 2, 3]
        let data2: [UInt8] = [4, 5, 6, 7]
        data1.withUnsafeBytes { _ = Darwin.write(ourFD1, $0.baseAddress!, data1.count) }
        data2.withUnsafeBytes { _ = Darwin.write(ourFD2, $0.baseAddress!, data2.count) }

        guard let (tunFD, _) = makeSocketPair() else {
            Issue.record("tun socketpair failed")
            return
        }
        defer { close(tunFD) }

        var transport = PollingTransport(endpoints: [ep1, ep2], tunFD: tunFD)
        let round = RoundContext()
        let packets = transport.readPackets(round: round)

        #expect(packets.count == 2)
        let epIDs = Set(packets.map(\.endpointID))
        #expect(epIDs == Set([1, 2]))
    }

    // MARK: - Northbound (TUN)

    @Test func readFromTUN() {
        guard let (tunFD, ourTunFD) = makeSocketPair() else {
            Issue.record("socketpair failed: \(errno)")
            return
        }
        defer { close(ourTunFD) }

        // Create a VM endpoint that won't have data
        guard let (vmFD, _) = makeSocketPair() else {
            Issue.record("vm socketpair failed")
            close(tunFD)
            return
        }
        defer { close(vmFD) }

        let ep = VMEndpoint(id: 1, fd: vmFD, subnet: IPv4Subnet(network: IPv4Address(100, 64, 1, 0), prefixLength: 24), gateway: IPv4Address(100, 64, 1, 1))

        // Write to TUN fd
        let data: [UInt8] = Array(0..<32).map { UInt8($0) }
        data.withUnsafeBytes { _ = Darwin.write(ourTunFD, $0.baseAddress!, data.count) }

        var transport = PollingTransport(endpoints: [ep], tunFD: tunFD)
        let round = RoundContext()
        let packets = transport.readPackets(round: round)

        // Should find at least the TUN packet
        let tunPackets = packets.filter { $0.endpointID == northboundEndpointID }
        #expect(!tunPackets.isEmpty)
    }

    // MARK: - Purge dead fd

    @Test func deadFDIsPurged() {
        // Create a socketpair, then close the read end so poll() returns POLLNVAL
        guard let (vmFD, ourFD) = makeSocketPair() else {
            Issue.record("socketpair failed: \(errno)")
            return
        }
        close(vmFD)  // close the fd that PollingTransport will poll

        let ep = VMEndpoint(id: 1, fd: vmFD, subnet: IPv4Subnet(network: IPv4Address(100, 64, 1, 0), prefixLength: 24), gateway: IPv4Address(100, 64, 1, 1))

        // Write to TUN so poll() returns (otherwise it'd block on the dead fd with no events)
        guard let (tunFD, ourTunFD) = makeSocketPair() else {
            Issue.record("tun socketpair failed")
            close(ourFD)
            return
        }
        defer { close(ourFD); close(tunFD); close(ourTunFD) }

        let data: [UInt8] = [1]
        data.withUnsafeBytes { _ = Darwin.write(ourTunFD, $0.baseAddress!, data.count) }

        var transport = PollingTransport(endpoints: [ep], tunFD: tunFD)
        let round = RoundContext()
        let packets = transport.readPackets(round: round)

        // Should not crash — dead fd is silently removed
        // TUN packet should be read
        #expect(!packets.isEmpty)
    }

    // MARK: - readPackets budget

    @Test func packetBudgetIsRespected() {
        guard let (vmFD, ourFD) = makeSocketPair() else {
            Issue.record("socketpair failed: \(errno)")
            return
        }
        defer { close(vmFD); close(ourFD) }

        let ep = VMEndpoint(id: 1, fd: vmFD, subnet: IPv4Subnet(network: IPv4Address(100, 64, 1, 0), prefixLength: 24), gateway: IPv4Address(100, 64, 1, 1))

        // Write many small frames (kMaxPacketsPerRead = 256)
        let data: [UInt8] = [0xAA]
        for _ in 0..<300 {
            data.withUnsafeBytes { _ = Darwin.write(ourFD, $0.baseAddress!, data.count) }
        }

        guard let (tunFD, _) = makeSocketPair() else {
            Issue.record("tun socketpair failed")
            return
        }
        defer { close(tunFD) }

        var transport = PollingTransport(endpoints: [ep], tunFD: tunFD)
        let round = RoundContext()
        let packets = transport.readPackets(round: round)

        // Should be capped at 256
        #expect(packets.count <= 256)
        #expect(packets.count > 0)
    }
}
