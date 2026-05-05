import Testing
import Darwin
@testable import SwiftNetStack

@Suite(.serialized)
struct PollingTransportTests {

    private func makeSocketPair() -> (hostFD: Int32, guestFD: Int32)? {
        var fds: [Int32] = [-1, -1]
        let rc = socketpair(AF_UNIX, SOCK_DGRAM, 0, &fds)
        guard rc == 0 else { return nil }
        return (fds[0], fds[1])
    }

    // MARK: - Read datagrams

    @Test func readPacketsFromSingleEndpoint() {
        guard let (hostFD, guestFD) = makeSocketPair() else {
            Issue.record("socketpair failed: \(errno)")
            return
        }
        defer { close(hostFD); close(guestFD) }

        let ep = VMEndpoint(id: 1, fd: hostFD, subnet: IPv4Subnet(network: IPv4Address(100, 64, 1, 0), prefixLength: 24), gateway: IPv4Address(100, 64, 1, 1))

        let data: [UInt8] = Array(0..<64).map { UInt8($0) }
        data.withUnsafeBytes { _ = Darwin.write(guestFD, $0.baseAddress!, data.count) }

        var transport = PollingTransport(endpoints: [ep])
        let round = RoundContext()
        let packets = transport.readPackets(round: round)

        #expect(packets.count == 1)
        guard packets.count == 1 else { return }
        #expect(packets[0].endpointID == 1)
        #expect(packets[0].packet.totalLength == 64)
    }

    // MARK: - Write+read round-trip

    @Test func writeThenReadRoundTrip() {
        guard let (hostFD, guestFD) = makeSocketPair() else {
            Issue.record("socketpair failed: \(errno)")
            return
        }
        defer { close(hostFD); close(guestFD) }

        let ep = VMEndpoint(id: 1, fd: hostFD, subnet: IPv4Subnet(network: IPv4Address(100, 64, 1, 0), prefixLength: 24), gateway: IPv4Address(100, 64, 1, 1))

        var transport = PollingTransport(endpoints: [ep])

        var pkt = PacketBuffer(capacity: 128)
        guard let ptr = pkt.appendPointer(count: 10) else { return }
        let sendData: [UInt8] = [0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05]
        sendData.withUnsafeBytes { ptr.copyMemory(from: $0.baseAddress!, byteCount: 10) }

        transport.writePackets([(endpointID: 1, packet: pkt)])

        var recvBuf = [UInt8](repeating: 0, count: 128)
        let n = Darwin.read(guestFD, &recvBuf, 128)
        #expect(n == 10)
        #expect(Array(recvBuf[0..<10]) == sendData)
    }

    // MARK: - Multiple endpoints

    @Test func readFromMultipleEndpoints() {
        guard let (hostFD1, guestFD1) = makeSocketPair(),
              let (hostFD2, guestFD2) = makeSocketPair() else {
            Issue.record("socketpair failed: \(errno)")
            return
        }
        defer { close(hostFD1); close(hostFD2); close(guestFD1); close(guestFD2) }

        let ep1 = VMEndpoint(id: 1, fd: hostFD1, subnet: IPv4Subnet(network: IPv4Address(100, 64, 1, 0), prefixLength: 24), gateway: IPv4Address(100, 64, 1, 1))
        let ep2 = VMEndpoint(id: 2, fd: hostFD2, subnet: IPv4Subnet(network: IPv4Address(100, 64, 2, 0), prefixLength: 24), gateway: IPv4Address(100, 64, 2, 1))

        let data1: [UInt8] = [1, 2, 3]
        let data2: [UInt8] = [4, 5, 6, 7]
        data1.withUnsafeBytes { _ = Darwin.write(guestFD1, $0.baseAddress!, data1.count) }
        data2.withUnsafeBytes { _ = Darwin.write(guestFD2, $0.baseAddress!, data2.count) }

        var transport = PollingTransport(endpoints: [ep1, ep2])
        let round = RoundContext()
        let packets = transport.readPackets(round: round)

        #expect(packets.count == 2)
        let epIDs = Set(packets.map(\.endpointID))
        #expect(epIDs == Set([1, 2]))
    }

    // MARK: - Purge dead fd

    @Test func deadFDIsPurged() {
        guard let (hostFD, guestFD) = makeSocketPair() else {
            Issue.record("socketpair failed: \(errno)")
            return
        }
        close(hostFD)  // close the fd that PollingTransport will poll
        defer { close(guestFD) }

        let ep = VMEndpoint(id: 1, fd: hostFD, subnet: IPv4Subnet(network: IPv4Address(100, 64, 1, 0), prefixLength: 24), gateway: IPv4Address(100, 64, 1, 1))

        var transport = PollingTransport(endpoints: [ep])
        let round = RoundContext()
        let packets = transport.readPackets(round: round)

        // Dead fd should be purged without crashing. POLLNVAL causes
        // immediate poll() return; no packets are readable from a dead fd.
        #expect(packets.isEmpty)
    }

    // MARK: - readPackets budget

    @Test func packetBudgetIsRespected() {
        guard let (hostFD, guestFD) = makeSocketPair() else {
            Issue.record("socketpair failed: \(errno)")
            return
        }
        defer { close(hostFD); close(guestFD) }

        let ep = VMEndpoint(id: 1, fd: hostFD, subnet: IPv4Subnet(network: IPv4Address(100, 64, 1, 0), prefixLength: 24), gateway: IPv4Address(100, 64, 1, 1))

        // Write many small frames (kMaxPacketsPerRead = 256)
        let data: [UInt8] = [0xAA]
        for _ in 0..<300 {
            data.withUnsafeBytes { _ = Darwin.write(guestFD, $0.baseAddress!, data.count) }
        }

        var transport = PollingTransport(endpoints: [ep])
        let round = RoundContext()
        let packets = transport.readPackets(round: round)

        #expect(packets.count <= 256)
        #expect(packets.count > 0)
    }
}
