/// Static DNS server backed by a hosts file.
///
/// Queries matching a hostname in `hosts` receive an A-record reply.
/// All other queries receive NXDOMAIN.
///
/// Upstream forwarding is not yet implemented; the design leaves room for
/// a `private let upstreamFD: Int32?` and a `pendingQueries` dictionary
/// to be added later.
public struct DNSServer {
    private let hosts: [String: IPv4Address]

    /// Create a DNS server with the given hosts-file mappings.
    /// Keys are normalised at init (lowercased, trailing dot stripped).
    public init(hosts: [String: IPv4Address]) {
        var normalised: [String: IPv4Address] = [:]
        for (name, ip) in hosts {
            let key = DNSServer.normaliseHost(name)
            normalised[key] = ip
        }
        self.hosts = normalised
    }

    /// Process a single DNS query datagram.
    ///
    /// Called from BDP Phase 9a for every UDP datagram destined to port 53
    /// that is not a DHCP packet.
    public mutating func processQuery(
        payload: PacketBuffer,
        srcIP: IPv4Address,
        dstIP: IPv4Address,
        srcPort: UInt16,
        dstPort: UInt16,
        srcMAC: MACAddress,
        endpointID: Int,
        hostMAC: MACAddress,
        replies: inout [(endpointID: Int, packet: PacketBuffer)],
        round: RoundContext
    ) {
        guard let (txID, question) = DNSPacket.parse(from: payload) else { return }

        if question.type == 1 || question.type == 255 {  // A or ANY
            let normalised = DNSServer.normaliseHost(question.name)
            if let ip = hosts[normalised] {
                if let replyPayload = DNSPacket.buildAReply(
                    txID: txID, question: question, ip: ip, round: round
                ) {
                    if let frame = buildUDPFrame(
                        hostMAC: hostMAC, dstMAC: srcMAC,
                        srcIP: dstIP, dstIP: srcIP,
                        srcPort: dstPort, dstPort: srcPort,
                        payload: replyPayload, round: round
                    ) {
                        replies.append((endpointID, frame))
                    }
                }
                return
            }
        }

        // NXDOMAIN for anything we cannot resolve
        if let replyPayload = DNSPacket.buildNXDOMAIN(
            txID: txID, question: question, round: round
        ) {
            if let frame = buildUDPFrame(
                hostMAC: hostMAC, dstMAC: srcMAC,
                srcIP: dstIP, dstIP: srcIP,
                srcPort: dstPort, dstPort: srcPort,
                payload: replyPayload, round: round
            ) {
                replies.append((endpointID, frame))
            }
        }
    }

    // MARK: - Private

    private static func normaliseHost(_ name: String) -> String {
        let stripped = name.hasSuffix(".") ? String(name.dropLast()) : name
        return stripped.lowercased()
    }
}
