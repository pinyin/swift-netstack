import Testing
@testable import SwiftNetStack

@Suite(.serialized)
struct UDPSocketTests {

    // MARK: - UDPSocketTable

    @Test func registerAndLookup() {
        var table = UDPSocketTable()
        let echo = UDPEchoSocket()
        table.register(port: 7, socket: echo)
        #expect(table.lookup(port: 7) != nil)
    }

    @Test func lookupUnregisteredPortReturnsNil() {
        let table = UDPSocketTable()
        #expect(table.lookup(port: 9999) == nil)
    }

    @Test func unregisterRemovesSocket() {
        var table = UDPSocketTable()
        table.register(port: 7, socket: UDPEchoSocket())
        table.unregister(port: 7)
        #expect(table.lookup(port: 7) == nil)
    }

    @Test func unregisterNonexistentPortIsNoop() {
        var table = UDPSocketTable()
        table.unregister(port: 42)
        #expect(table.lookup(port: 42) == nil)
    }

    @Test func reregisterOverwritesSocket() {
        var table = UDPSocketTable()
        table.register(port: 7, socket: UDPEchoSocket())
        table.register(port: 7, socket: UDPEchoSocket())
        #expect(table.lookup(port: 7) != nil)
    }

    @Test func multiplePortsIndependent() {
        var table = UDPSocketTable()
        table.register(port: 7, socket: UDPEchoSocket())
        table.register(port: 53, socket: UDPEchoSocket())
        #expect(table.lookup(port: 7) != nil)
        #expect(table.lookup(port: 53) != nil)
        table.unregister(port: 7)
        #expect(table.lookup(port: 7) == nil)
        #expect(table.lookup(port: 53) != nil)
    }

    // MARK: - UDPEchoSocket

    @Test func echoSwapsPortsAndAddresses() {
        let hostMAC = MACAddress(0x00, 0x11, 0x22, 0x33, 0x44, 0x55)
        let clientMAC = MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF)
        let srcIP = IPv4Address(100, 64, 1, 1)
        let dstIP = IPv4Address(100, 64, 1, 50)

        let payload = makeRawPacket([0x70, 0x69, 0x6E, 0x67])
        var socket = UDPEchoSocket()
        var replies: [(endpointID: Int, packet: PacketBuffer)] = []
        let round = RoundContext()

        socket.handleDatagram(
            payload: payload,
            srcIP: srcIP, dstIP: dstIP,
            srcPort: 1234, dstPort: 7,
            srcMAC: clientMAC,
            endpointID: 1,
            hostMAC: hostMAC,
            replies: &replies,
            round: round
        )

        #expect(replies.count == 1)
        let (ep, frame) = replies[0]
        #expect(ep == 1)

        // Parse the reply frame and verify swapped ports/IPs
        guard let eth = EthernetFrame.parse(from: frame),
              let ip = IPv4Header.parse(from: eth.payload),
              let udp = UDPHeader.parse(from: ip.payload, pseudoSrcAddr: ip.srcAddr, pseudoDstAddr: ip.dstAddr) else {
            Issue.record("failed to parse echo reply")
            return
        }
        #expect(udp.srcPort == 7)
        #expect(udp.dstPort == 1234)
        #expect(ip.srcAddr == dstIP)
        #expect(ip.dstAddr == srcIP)
        #expect(eth.dstMAC == clientMAC)
        #expect(eth.srcMAC == hostMAC)
        #expect(udp.verifyChecksum())
    }

    @Test func echoPayloadPreserved() {
        let hostMAC = MACAddress(0x00, 0x11, 0x22, 0x33, 0x44, 0x55)
        let clientMAC = MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF)
        let srcIP = IPv4Address(10, 0, 0, 1)
        let dstIP = IPv4Address(10, 0, 0, 2)

        let data: [UInt8] = Array(0..<255)
        let payload = makeRawPacket(data)
        var socket = UDPEchoSocket()
        var replies: [(endpointID: Int, packet: PacketBuffer)] = []
        let round = RoundContext()

        socket.handleDatagram(
            payload: payload, srcIP: srcIP, dstIP: dstIP,
            srcPort: 5555, dstPort: 7,
            srcMAC: clientMAC, endpointID: 1,
            hostMAC: hostMAC,
            replies: &replies, round: round
        )

        guard let eth = EthernetFrame.parse(from: replies[0].packet),
              let ip = IPv4Header.parse(from: eth.payload),
              let udp = UDPHeader.parse(from: ip.payload, pseudoSrcAddr: ip.srcAddr, pseudoDstAddr: ip.dstAddr) else {
            Issue.record("failed to parse echo reply")
            return
        }
        #expect(udp.payload.totalLength == 255)
        udp.payload.withUnsafeReadableBytes { buf in
            let bytes = [UInt8](buf)
            #expect(bytes == data)
        }
    }

    @Test func echoEmptyPayload() {
        let hostMAC = MACAddress(0x00, 0x11, 0x22, 0x33, 0x44, 0x55)
        let clientMAC = MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF)
        let srcIP = IPv4Address(1, 1, 1, 1)
        let dstIP = IPv4Address(2, 2, 2, 2)

        let payload = makeRawPacket([])
        var socket = UDPEchoSocket()
        var replies: [(endpointID: Int, packet: PacketBuffer)] = []
        let round = RoundContext()

        socket.handleDatagram(
            payload: payload, srcIP: srcIP, dstIP: dstIP,
            srcPort: 9999, dstPort: 7,
            srcMAC: clientMAC, endpointID: 42,
            hostMAC: hostMAC,
            replies: &replies, round: round
        )

        guard let eth = EthernetFrame.parse(from: replies[0].packet),
              let ip = IPv4Header.parse(from: eth.payload),
              let udp = UDPHeader.parse(from: ip.payload, pseudoSrcAddr: ip.srcAddr, pseudoDstAddr: ip.dstAddr) else {
            Issue.record("failed to parse echo reply")
            return
        }
        #expect(udp.payload.totalLength == 0)
        #expect(udp.length == 8)
        #expect(udp.verifyChecksum())
    }

    // MARK: - Helpers

    private func makeRawPacket(_ bytes: [UInt8]) -> PacketBuffer {
        let s = Storage.allocate(capacity: max(bytes.count, 1))
        if !bytes.isEmpty {
            bytes.withUnsafeBytes { s.data.copyMemory(from: $0.baseAddress!, byteCount: bytes.count) }
        }
        return PacketBuffer(storage: s, offset: 0, length: bytes.count)
    }
}
