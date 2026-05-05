import Testing
@testable import SwiftNetStack

@Suite(.serialized)
struct ARPTests {

    // MARK: - Helpers

    func makeARPRequestBytes(
        senderMAC: MACAddress = MACAddress(0x00, 0x11, 0x22, 0x33, 0x44, 0x55),
        senderIP: IPv4Address = IPv4Address(192, 168, 1, 100),
        targetIP: IPv4Address = IPv4Address(192, 168, 1, 1)
    ) -> [UInt8] {
        var bytes = [UInt8](repeating: 0, count: 28)
        bytes[0] = 0x00; bytes[1] = 0x01  // hardware type = Ethernet
        bytes[2] = 0x08; bytes[3] = 0x00  // protocol type = IPv4
        bytes[4] = 6   // hardware size
        bytes[5] = 4   // protocol size
        bytes[6] = 0x00; bytes[7] = 0x01  // operation = request
        senderMAC.write(to: &bytes[8])
        senderIP.write(to: &bytes[14])
        MACAddress.zero.write(to: &bytes[18])  // target MAC = zero
        targetIP.write(to: &bytes[24])
        return bytes
    }

    // MARK: - ARPFrame.parse

    @Test func parseARPRequest() {
        let bytes = makeARPRequestBytes()
        let pkt = PacketBuffer.from(bytes: bytes)

        let arp = ARPFrame.parse(from: pkt)
        #expect(arp != nil)
        #expect(arp?.hardwareType == 1)
        #expect(arp?.protocolType == 0x0800)
        #expect(arp?.hardwareSize == 6)
        #expect(arp?.protocolSize == 4)
        #expect(arp?.operation == .request)
        #expect(arp?.senderMAC.description == "00:11:22:33:44:55")
        #expect(arp?.senderIP.description == "192.168.1.100")
        #expect(arp?.targetMAC == .zero)
        #expect(arp?.targetIP.description == "192.168.1.1")
    }

    @Test func parseARPReply() {
        var bytes = makeARPRequestBytes()
        bytes[7] = 0x02  // operation = reply
        let pkt = PacketBuffer.from(bytes: bytes)

        let arp = ARPFrame.parse(from: pkt)
        #expect(arp?.operation == .reply)
    }

    @Test func parseTooShort() {
        let pkt = PacketBuffer.from(bytes: [UInt8](repeating: 0, count: 20))
        #expect(ARPFrame.parse(from: pkt) == nil)
    }

    @Test func parseNonARPFields() {
        var bytes = makeARPRequestBytes()
        bytes[1] = 0x02  // non-Ethernet hardware type
        let pkt = PacketBuffer.from(bytes: bytes)
        #expect(ARPFrame.parse(from: pkt) == nil)
    }

    // MARK: - ARPHandler.process

    @Test func processARPRequestGeneratesReply() {
        let requesterMAC = MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF)
        let requesterIP = IPv4Address(192, 168, 1, 100)

        let bytes = makeARPRequestBytes(
            senderMAC: requesterMAC,
            senderIP: requesterIP,
            targetIP: IPv4Address(192, 168, 1, 1)
        )
        let pkt = PacketBuffer.from(bytes: bytes)
        let arp = ARPFrame.parse(from: pkt)
        #expect(arp != nil)

        let round = RoundContext()
        let ourMAC = MACAddress(0x00, 0x11, 0x22, 0x33, 0x44, 0x55)
        let ourIP = IPv4Address(192, 168, 1, 1)

        let replies = ARPHandler.process(
            requests: [arp!],
            ourMAC: ourMAC,
            ourIP: ourIP,
            round: round
        )
        #expect(replies.count == 1)

        // Parse the reply and verify fields
        let reply = replies[0]
        #expect(reply.totalLength == 42)  // 14 eth + 28 arp

        guard let replyEth = EthernetFrame.parse(from: reply) else {
            Issue.record("Failed to parse reply Ethernet frame")
            round.endRound()
            return
        }
        #expect(replyEth.dstMAC == requesterMAC)
        #expect(replyEth.srcMAC == ourMAC)
        #expect(replyEth.etherType == .arp)

        guard let replyARP = ARPFrame.parse(from: replyEth.payload) else {
            Issue.record("Failed to parse reply ARP frame")
            round.endRound()
            return
        }
        #expect(replyARP.operation == .reply)
        #expect(replyARP.senderMAC == ourMAC)
        #expect(replyARP.senderIP == ourIP)
        #expect(replyARP.targetMAC == requesterMAC)
        #expect(replyARP.targetIP == requesterIP)

        round.endRound()
    }

    @Test func processIgnoresNonMatchingIP() {
        let bytes = makeARPRequestBytes(
            targetIP: IPv4Address(10, 0, 0, 99)  // not our IP
        )
        let pkt = PacketBuffer.from(bytes: bytes)
        let arp = ARPFrame.parse(from: pkt)!

        let round = RoundContext()
        let replies = ARPHandler.process(
            requests: [arp],
            ourMAC: MACAddress(0x00, 0x11, 0x22, 0x33, 0x44, 0x55),
            ourIP: IPv4Address(192, 168, 1, 1),
            round: round
        )
        #expect(replies.isEmpty)
        round.endRound()
    }

    @Test func processIgnoresReplies() {
        var bytes = makeARPRequestBytes()
        bytes[7] = 0x02  // make it a reply
        let pkt = PacketBuffer.from(bytes: bytes)
        let arp = ARPFrame.parse(from: pkt)!

        let round = RoundContext()
        let replies = ARPHandler.process(
            requests: [arp],
            ourMAC: .zero,
            ourIP: .zero,
            round: round
        )
        #expect(replies.isEmpty)
        round.endRound()
    }
}
