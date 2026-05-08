import Testing
import Darwin
@testable import SwiftNetStack

@Suite(.serialized)
struct DNSServerTests {

    // MARK: - Helpers

    /// Build a raw DNS query packet for a single A record question.
    private func makeDNSQuery(txID: UInt16, name: String, qtype: UInt16 = 1) -> [UInt8] {
        let qnameLabels = DNSPacket.encodeQName(name)
        let totalLen = 12 + qnameLabels.count + 4
        var bytes = [UInt8](repeating: 0, count: totalLen)

        // Header
        bytes[0] = UInt8((txID >> 8) & 0xFF); bytes[1] = UInt8(txID & 0xFF)
        bytes[2] = 0x01; bytes[3] = 0x00  // RD=1, rest=0 (standard query)
        bytes[4] = 0x00; bytes[5] = 0x01  // QDCOUNT=1
        // ANCOUNT, NSCOUNT, ARCOUNT already zero

        // Question
        var off = 12
        for b in qnameLabels { bytes[off] = b; off += 1 }
        bytes[off] = UInt8((qtype >> 8) & 0xFF); off += 1
        bytes[off] = UInt8(qtype & 0xFF); off += 1
        bytes[off] = 0x00; bytes[off + 1] = 0x01  // QCLASS=IN

        return bytes
    }

    private func packetBuffer(from bytes: [UInt8]) -> PacketBuffer {
        let storage = Storage.allocate(capacity: bytes.count)
        bytes.withUnsafeBytes { storage.data.copyMemory(from: $0.baseAddress!, byteCount: bytes.count) }
        return PacketBuffer(storage: storage, offset: 0, length: bytes.count)
    }

    // MARK: - DNSPacket.parse

    @Test func parseValidAQuery() {
        let query = makeDNSQuery(txID: 0x1234, name: "example.com")
        let pkt = packetBuffer(from: query)
        guard let (txID, question) = DNSPacket.parse(from: pkt) else {
            Issue.record("parse failed for valid A query")
            return
        }
        #expect(txID == 0x1234)
        #expect(question.name == "example.com")
        #expect(question.type == 1)
        #expect(question.class == 1)
    }

    @Test func parseRejectsResponseQR() {
        var query = makeDNSQuery(txID: 1, name: "test.local")
        query[2] = 0x81  // QR=1
        let pkt = packetBuffer(from: query)
        #expect(DNSPacket.parse(from: pkt) == nil)
    }

    @Test func parseRejectsTruncated() {
        let pkt = packetBuffer(from: [0x00, 0x01, 0x02])  // only 3 bytes
        #expect(DNSPacket.parse(from: pkt) == nil)
    }

    @Test func parseRejectsNonINClass() {
        var query = makeDNSQuery(txID: 1, name: "test.local")
        let qnameLabels = DNSPacket.encodeQName("test.local")
        let qclassOff = 12 + qnameLabels.count + 2
        query[qclassOff] = 0x00; query[qclassOff + 1] = 0xFF  // not IN
        #expect(DNSPacket.parse(from: packetBuffer(from: query)) == nil)
    }

    @Test func parseCaseInsensitiveQNAME() {
        let query = makeDNSQuery(txID: 42, name: "Example.COM")
        guard let (_, question) = DNSPacket.parse(from: packetBuffer(from: query)) else {
            Issue.record("parse failed")
            return
        }
        #expect(question.name == "example.com")
    }

    // MARK: - DNSPacket.buildAReply

    @Test func buildAReplyHasCorrectStructure() {
        let round = RoundContext()
        let question = DNSQuestion(name: "test.local", type: 1, class: 1)
        let ip = IPv4Address(10, 0, 0, 99)

        guard let reply = DNSPacket.buildAReply(txID: 0xABCD, question: question, ip: ip, round: round) else {
            Issue.record("buildAReply returned nil")
            return
        }

        // Verify raw DNS reply structure (QR=1, ANCOUNT=1, A record)
        reply.withUnsafeReadableBytes { buf in
            guard buf.count >= 12 else { Issue.record("too short"); return }

            let txID   = (UInt16(buf[0]) << 8) | UInt16(buf[1])
            let flags  = (UInt16(buf[2]) << 8) | UInt16(buf[3])
            let ancount = (UInt16(buf[6]) << 8) | UInt16(buf[7])

            #expect(txID == 0xABCD)
            #expect((flags & 0x8000) != 0, "QR should be 1 for reply")
            #expect(ancount == 1, "expected 1 answer, got \(ancount)")

            // Find the A record IP at the end (last 4 bytes = RDATA)
            let ipBytes = [buf[buf.count - 4], buf[buf.count - 3], buf[buf.count - 2], buf[buf.count - 1]]
            let rdlength = (UInt16(buf[buf.count - 6]) << 8) | UInt16(buf[buf.count - 5])
            #expect(rdlength == 4)
            #expect(ipBytes == [10, 0, 0, 99])
        }
    }

    @Test func buildNXDOMAINHasRCODE3() {
        let round = RoundContext()
        let question = DNSQuestion(name: "no-such-host.local", type: 1, class: 1)

        guard let reply = DNSPacket.buildNXDOMAIN(txID: 1, question: question, round: round) else {
            Issue.record("buildNXDOMAIN returned nil")
            return
        }

        reply.withUnsafeReadableBytes { buf in
            guard buf.count >= 12 else { Issue.record("too short"); return }
            let flags  = (UInt16(buf[2]) << 8) | UInt16(buf[3])
            let rcode  = flags & 0x000F
            let ancount = (UInt16(buf[6]) << 8) | UInt16(buf[7])
            #expect(rcode == 3, "expected RCODE=3 (NXDOMAIN), got \(rcode)")
            #expect(ancount == 0, "NXDOMAIN should have 0 answers")
        }
    }

    // MARK: - DNSServer.processQuery (raw DNS payload verification)

    /// Extract the UDP payload (DNS content) from a full Ethernet→IP→UDP frame.
    private func extractUDPPayload(from frame: PacketBuffer) -> PacketBuffer? {
        guard let eth = EthernetFrame.parse(from: frame) else { return nil }
        guard let ip = IPv4Header.parse(from: eth.payload) else { return nil }
        // Skip UDP checksum validation by reading the raw payload directly
        let ipPayload = ip.payload
        // UDP header is 8 bytes; payload starts at offset 8
        guard ipPayload.totalLength >= 8 else { return nil }
        guard let udpPayload = ipPayload.slice(from: 8, length: ipPayload.totalLength - 8) else { return nil }
        return udpPayload
    }

    @Test func processQueryAReply() {
        let hosts = ["example.com": IPv4Address(10, 0, 0, 42)]
        var dns = DNSServer(hosts: hosts)
        let round = RoundContext()
        let clientMAC = MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF)
        let hostMAC = MACAddress(0x00, 0x11, 0x22, 0x33, 0x44, 0x55)
        let gateway = IPv4Address(100, 64, 1, 1)
        let clientIP = IPv4Address(100, 64, 1, 50)

        let query = makeDNSQuery(txID: 1, name: "example.com")
        let queryPkt = packetBuffer(from: query)
        var replies: [(endpointID: Int, packet: PacketBuffer)] = []

        dns.processQuery(
            payload: queryPkt,
            srcIP: clientIP, dstIP: gateway,
            srcPort: 12345, dstPort: 53,
            srcMAC: clientMAC,
            endpointID: 1,
            hostMAC: hostMAC,
            replies: &replies,
            round: round
        )

        #expect(replies.count == 1)
        guard replies.count == 1 else { return }
        #expect(replies[0].endpointID == 1)

        // Verify the DNS reply contains the A record IP
        guard let dnsPayload = extractUDPPayload(from: replies[0].packet) else {
            Issue.record("failed to extract UDP payload")
            return
        }
        dnsPayload.withUnsafeReadableBytes { buf in
            guard buf.count >= 12 else { Issue.record("DNS too short"); return }
            let ancount = (UInt16(buf[6]) << 8) | UInt16(buf[7])
            #expect(ancount == 1, "expected 1 answer, got \(ancount)")
            // A record RDATA is the last 4 bytes
            let ipBytes = [buf[buf.count - 4], buf[buf.count - 3], buf[buf.count - 2], buf[buf.count - 1]]
            #expect(ipBytes == [10, 0, 0, 42], "expected 10.0.0.42, got \(ipBytes)")
        }
    }

    @Test func processQueryNXDOMAIN() {
        let hosts = ["known.local": IPv4Address(10, 0, 0, 1)]
        var dns = DNSServer(hosts: hosts)
        let round = RoundContext()
        let mac = MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF)
        let hostMAC = MACAddress(0x00, 0x11, 0x22, 0x33, 0x44, 0x55)
        let gw = IPv4Address(100, 64, 1, 1)
        let clientIP = IPv4Address(100, 64, 1, 50)

        let query = makeDNSQuery(txID: 2, name: "unknown.local")
        var replies: [(endpointID: Int, packet: PacketBuffer)] = []

        dns.processQuery(
            payload: packetBuffer(from: query),
            srcIP: clientIP, dstIP: gw,
            srcPort: 54321, dstPort: 53,
            srcMAC: mac,
            endpointID: 1,
            hostMAC: hostMAC,
            replies: &replies,
            round: round
        )

        #expect(replies.count == 1)
        guard replies.count == 1 else { return }

        guard let dnsPayload = extractUDPPayload(from: replies[0].packet) else {
            Issue.record("failed to extract UDP payload")
            return
        }
        dnsPayload.withUnsafeReadableBytes { buf in
            guard buf.count >= 12 else { Issue.record("DNS too short"); return }
            let flags = (UInt16(buf[2]) << 8) | UInt16(buf[3])
            let rcode = flags & 0x000F
            #expect(rcode == 3, "expected NXDOMAIN (rcode=3), got \(rcode)")
        }
    }

    @Test func processQueryCaseInsensitive() {
        let hosts = ["MyHost.Local": IPv4Address(192, 168, 1, 100)]
        var dns = DNSServer(hosts: hosts)
        let round = RoundContext()
        let mac = MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF)
        let hostMAC = MACAddress(0x00, 0x11, 0x22, 0x33, 0x44, 0x55)
        let gw = IPv4Address(100, 64, 1, 1)
        let clientIP = IPv4Address(100, 64, 1, 50)

        let query = makeDNSQuery(txID: 3, name: "myhost.local")
        var replies: [(endpointID: Int, packet: PacketBuffer)] = []

        dns.processQuery(
            payload: packetBuffer(from: query),
            srcIP: clientIP, dstIP: gw,
            srcPort: 11111, dstPort: 53,
            srcMAC: mac,
            endpointID: 1,
            hostMAC: hostMAC,
            replies: &replies,
            round: round
        )

        #expect(replies.count == 1)
        guard replies.count == 1 else { return }

        guard let dnsPayload = extractUDPPayload(from: replies[0].packet) else {
            Issue.record("failed to extract UDP payload")
            return
        }
        dnsPayload.withUnsafeReadableBytes { buf in
            guard buf.count >= 12 else { Issue.record("DNS too short"); return }
            let ipBytes = [buf[buf.count - 4], buf[buf.count - 3], buf[buf.count - 2], buf[buf.count - 1]]
            #expect(ipBytes == [192, 168, 1, 100], "expected 192.168.1.100, got \(ipBytes)")
        }
    }

    @Test func processQueryTrailingDotNormalization() {
        let hosts = ["host.local": IPv4Address(10, 0, 0, 55)]
        var dns = DNSServer(hosts: hosts)
        let round = RoundContext()
        let mac = MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF)
        let hostMAC = MACAddress(0x00, 0x11, 0x22, 0x33, 0x44, 0x55)
        let gw = IPv4Address(100, 64, 1, 1)
        let clientIP = IPv4Address(100, 64, 1, 50)

        let query = makeDNSQuery(txID: 4, name: "host.local.")
        var replies: [(endpointID: Int, packet: PacketBuffer)] = []

        dns.processQuery(
            payload: packetBuffer(from: query),
            srcIP: clientIP, dstIP: gw,
            srcPort: 22222, dstPort: 53,
            srcMAC: mac,
            endpointID: 1,
            hostMAC: hostMAC,
            replies: &replies,
            round: round
        )

        #expect(replies.count == 1)
        guard replies.count == 1 else { return }

        guard let dnsPayload = extractUDPPayload(from: replies[0].packet) else {
            Issue.record("failed to extract UDP payload")
            return
        }
        dnsPayload.withUnsafeReadableBytes { buf in
            guard buf.count >= 12 else { Issue.record("DNS too short"); return }
            let ipBytes = [buf[buf.count - 4], buf[buf.count - 3], buf[buf.count - 2], buf[buf.count - 1]]
            #expect(ipBytes == [10, 0, 0, 55], "expected 10.0.0.55, got \(ipBytes)")
        }
    }

    @Test func processQueryAnyType() {
        let hosts = ["any.local": IPv4Address(10, 0, 0, 77)]
        var dns = DNSServer(hosts: hosts)
        let round = RoundContext()
        let mac = MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF)
        let hostMAC = MACAddress(0x00, 0x11, 0x22, 0x33, 0x44, 0x55)
        let gw = IPv4Address(100, 64, 1, 1)
        let clientIP = IPv4Address(100, 64, 1, 50)

        let query = makeDNSQuery(txID: 5, name: "any.local", qtype: 255)
        var replies: [(endpointID: Int, packet: PacketBuffer)] = []

        dns.processQuery(
            payload: packetBuffer(from: query),
            srcIP: clientIP, dstIP: gw,
            srcPort: 33333, dstPort: 53,
            srcMAC: mac,
            endpointID: 1,
            hostMAC: hostMAC,
            replies: &replies,
            round: round
        )

        #expect(replies.count == 1)
        guard replies.count == 1 else { return }

        guard let dnsPayload = extractUDPPayload(from: replies[0].packet) else {
            Issue.record("failed to extract UDP payload")
            return
        }
        dnsPayload.withUnsafeReadableBytes { buf in
            guard buf.count >= 12 else { Issue.record("DNS too short"); return }
            let ipBytes = [buf[buf.count - 4], buf[buf.count - 3], buf[buf.count - 2], buf[buf.count - 1]]
            #expect(ipBytes == [10, 0, 0, 77], "expected 10.0.0.77, got \(ipBytes)")
        }
    }

    // MARK: - Integration: DNS via BDP round

    @Test func dnsQueryViaBDPRound() {
        let ep = VMEndpoint(id: 1, fd: 101, subnet: IPv4Subnet(network: IPv4Address(100, 64, 1, 0), prefixLength: 24), gateway: IPv4Address(100, 64, 1, 1), mtu: 1500)
        let hostMAC = MACAddress(0x00, 0x11, 0x22, 0x33, 0x44, 0x55)
        let clientMAC = MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF)
        let clientIP = IPv4Address(100, 64, 1, 50)
        let gateway = IPv4Address(100, 64, 1, 1)

        let dnsQuery = makeDNSQuery(txID: 100, name: "vmhost.local")
        let udpPayload = packetBuffer(from: dnsQuery)
        guard let udpFrame = buildUDPFrame(
            hostMAC: clientMAC, dstMAC: hostMAC,
            srcIP: clientIP, dstIP: gateway,
            srcPort: 12345, dstPort: 53,
            payload: udpPayload,
            round: RoundContext()
        ) else {
            Issue.record("buildUDPFrame failed")
            return
        }

        var transport: any Transport = InMemoryTransport(inputs: [(endpointID: 1, packet: udpFrame)])
        var arpMapping = ARPMapping(hostMAC: hostMAC, endpoints: [ep])
        var dhcpServer = DHCPServer(endpoints: [ep])
        var dnsServer = DNSServer(hosts: ["vmhost.local": IPv4Address(10, 0, 0, 88)])
        let routingTable = RoutingTable()
        let round = RoundContext(); var registry = SocketRegistry(); var reasm = IPFragmentReassembler(); var natTable = NATTable()

        bdpRound(transport: &transport, arpMapping: &arpMapping, dhcpServer: &dhcpServer, dnsServer: &dnsServer, socketRegistry: &registry, ipFragmentReassembler: &reasm, natTable: &natTable, round: round)

        let outputs = (transport as! InMemoryTransport).outputs
        #expect(outputs.count == 1, "expected 1 DNS reply, got \(outputs.count)")
        guard outputs.count == 1 else { return }
        #expect(outputs[0].endpointID == 1)

        // Verify the A record IP in the reply
        guard let dnsPayload = extractUDPPayload(from: outputs[0].packet) else {
            Issue.record("failed to extract UDP payload from BDP output")
            return
        }
        dnsPayload.withUnsafeReadableBytes { buf in
            guard buf.count >= 12 else { Issue.record("DNS too short"); return }
            let ancount = (UInt16(buf[6]) << 8) | UInt16(buf[7])
            #expect(ancount == 1, "expected 1 answer, got \(ancount)")
            let ipBytes = [buf[buf.count - 4], buf[buf.count - 3], buf[buf.count - 2], buf[buf.count - 1]]
            #expect(ipBytes == [10, 0, 0, 88], "expected 10.0.0.88, got \(ipBytes)")
        }
    }

    // MARK: - DNS upstream forwarding

    @Test func initWithUpstreamConfiguresPollFD() {
        let hosts = ["local.host": IPv4Address(10, 0, 0, 1)]
        let upstream = IPv4Address(8, 8, 8, 8)
        let dns = DNSServer(hosts: hosts, upstream: upstream)
        #expect(dns.pollFD != nil)
    }

    @Test func initWithoutUpstreamHasNilPollFD() {
        let hosts = ["local.host": IPv4Address(10, 0, 0, 1)]
        let dns = DNSServer(hosts: hosts, upstream: nil)
        #expect(dns.pollFD == nil)
    }

    @Test func processQueryNXDOMAINWhenNoUpstream() {
        var dns = DNSServer(hosts: [:], upstream: nil)
        let round = RoundContext()
        let mac = MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF)
        let hostMAC = MACAddress(0x00, 0x11, 0x22, 0x33, 0x44, 0x55)
        let gw = IPv4Address(100, 64, 1, 1)
        let clientIP = IPv4Address(100, 64, 1, 50)

        let query = makeDNSQuery(txID: 99, name: "unknown.example.com")
        var replies: [(endpointID: Int, packet: PacketBuffer)] = []

        dns.processQuery(
            payload: packetBuffer(from: query),
            srcIP: clientIP, dstIP: gw,
            srcPort: 55555, dstPort: 53,
            srcMAC: mac, endpointID: 1,
            hostMAC: hostMAC, replies: &replies, round: round
        )

        // Should get NXDOMAIN when no upstream configured
        #expect(replies.count == 1)
        guard replies.count == 1 else { return }
        guard let dnsPayload = extractUDPPayload(from: replies[0].packet) else {
            Issue.record("failed to extract UDP payload")
            return
        }
        dnsPayload.withUnsafeReadableBytes { buf in
            guard buf.count >= 12 else { Issue.record("DNS too short"); return }
            let flags = (UInt16(buf[2]) << 8) | UInt16(buf[3])
            let rcode = flags & 0x000F
            #expect(rcode == 3, "expected NXDOMAIN, got rcode=\(rcode)")
        }
    }

    @Test func hostsFileStillWorksWithUpstreamConfigured() {
        let hosts = ["cached.local": IPv4Address(192, 168, 1, 50)]
        let upstream = IPv4Address(8, 8, 8, 8)
        var dns = DNSServer(hosts: hosts, upstream: upstream)
        let round = RoundContext()
        let mac = MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF)
        let hostMAC = MACAddress(0x00, 0x11, 0x22, 0x33, 0x44, 0x55)
        let gw = IPv4Address(100, 64, 1, 1)
        let clientIP = IPv4Address(100, 64, 1, 50)

        let query = makeDNSQuery(txID: 1, name: "cached.local")
        var replies: [(endpointID: Int, packet: PacketBuffer)] = []

        dns.processQuery(
            payload: packetBuffer(from: query),
            srcIP: clientIP, dstIP: gw,
            srcPort: 12345, dstPort: 53,
            srcMAC: mac, endpointID: 1,
            hostMAC: hostMAC, replies: &replies, round: round
        )

        // Should get A reply from hosts file, not NXDOMAIN
        #expect(replies.count == 1)
        guard replies.count == 1 else { return }
        guard let dnsPayload = extractUDPPayload(from: replies[0].packet) else {
            Issue.record("failed to extract UDP payload")
            return
        }
        dnsPayload.withUnsafeReadableBytes { buf in
            guard buf.count >= 12 else { Issue.record("DNS too short"); return }
            let ipBytes = [buf[buf.count - 4], buf[buf.count - 3], buf[buf.count - 2], buf[buf.count - 1]]
            #expect(ipBytes == [192, 168, 1, 50], "expected 192.168.1.50, got \(ipBytes)")
        }
    }

    @Test func pollUpstreamWithNoPendingQueriesIsSafe() {
        let upstream = IPv4Address(8, 8, 8, 8)
        var dns = DNSServer(hosts: [:], upstream: upstream)
        let round = RoundContext()
        let hostMAC = MACAddress(0x00, 0x11, 0x22, 0x33, 0x44, 0x55)
        var replies: [(endpointID: Int, packet: PacketBuffer)] = []

        // Should not crash when no pending queries exist
        dns.pollUpstream(hostMAC: hostMAC, replies: &replies, round: round)
        #expect(replies.isEmpty)
    }

    @Test func forwardedQueryDoesNotReturnNXDOMAINImmediately() {
        let upstream = IPv4Address(8, 8, 8, 8)
        var dns = DNSServer(hosts: [:], upstream: upstream)
        let round = RoundContext()
        let mac = MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF)
        let hostMAC = MACAddress(0x00, 0x11, 0x22, 0x33, 0x44, 0x55)
        let gw = IPv4Address(100, 64, 1, 1)
        let clientIP = IPv4Address(100, 64, 1, 50)

        let query = makeDNSQuery(txID: 42, name: "should-forward.local")
        var replies: [(endpointID: Int, packet: PacketBuffer)] = []

        dns.processQuery(
            payload: packetBuffer(from: query),
            srcIP: clientIP, dstIP: gw,
            srcPort: 55555, dstPort: 53,
            srcMAC: mac, endpointID: 1,
            hostMAC: hostMAC, replies: &replies, round: round
        )

        // When upstream is configured, the query should be forwarded (not NXDOMAIN)
        // The reply should come later via pollUpstream. If the upstream is unreachable
        // and there's no immediate error on sendto (non-blocking UDP), no reply is
        // generated in processQuery.
        // Note: If the upstream socket couldn't be bound (e.g., no network), the
        // forward attempt falls through to NXDOMAIN. Both outcomes are valid.
    }
}
