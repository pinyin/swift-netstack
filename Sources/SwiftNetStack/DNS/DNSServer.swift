import Darwin

/// Static DNS server backed by a hosts file, with optional upstream forwarding.
///
/// Queries matching a hostname in `hosts` receive an A-record reply.
/// When an upstream server is configured, queries that miss the hosts file
/// are forwarded upstream; responses are matched to pending queries by
/// transaction ID and relayed back to the VM.
public struct DNSServer {
    private let hosts: [String: IPv4Address]
    private var upstreamFD: Int32?
    private let upstreamAddr: sockaddr_in?
    private var pendingQueries: [UInt16: PendingQuery] = [:]
    private var nextTxID: UInt16 = 1

    /// Create a DNS server with the given hosts-file mappings and optional upstream.
    /// - Parameter hosts: hostname-to-IP mappings (keys are normalised at init).
    /// - Parameter upstream: upstream DNS server address. When nil, the first
    ///   nameserver from /etc/resolv.conf is used automatically.
    public init(hosts: [String: IPv4Address], upstream: IPv4Address? = nil) {
        var normalised: [String: IPv4Address] = [:]
        for (name, ip) in hosts {
            let key = DNSServer.normaliseHost(name)
            normalised[key] = ip
        }
        self.hosts = normalised

        let effectiveUpstream = upstream ?? DNSServer.detectSystemDNS()

        if let upstreamAddr = effectiveUpstream {
            let fd = socket(AF_INET, SOCK_DGRAM, 0)
            if fd >= 0 {
                setNonBlocking(fd)
                var bindAddr = sockaddr_in()
                bindAddr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
                bindAddr.sin_family = sa_family_t(AF_INET)
                bindAddr.sin_port = 0
                bindAddr.sin_addr.s_addr = INADDR_ANY.bigEndian
                let b = withUnsafePointer(to: &bindAddr) {
                    $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                        Darwin.bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
                    }
                }
                if b >= 0 {
                    self.upstreamFD = fd
                    var addr = sockaddr_in()
                    addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
                    addr.sin_family = sa_family_t(AF_INET)
                    addr.sin_port = UInt16(53).bigEndian
                    withUnsafeMutableBytes(of: &addr.sin_addr) { upstreamAddr.write(to: $0.baseAddress!) }
                    self.upstreamAddr = addr
                } else {
                    close(fd)
                    self.upstreamFD = nil
                    self.upstreamAddr = nil
                }
            } else {
                self.upstreamFD = nil
                self.upstreamAddr = nil
            }
        } else {
            self.upstreamFD = nil
            self.upstreamAddr = nil
        }
    }

    /// Read /etc/resolv.conf and return the first nameserver as an IPv4Address.
    private static func detectSystemDNS() -> IPv4Address? {
        guard let content = try? String(contentsOfFile: "/etc/resolv.conf", encoding: .utf8) else {
            return nil
        }
        for line in content.split(separator: "\n") {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            guard trimmed.hasPrefix("nameserver") else { continue }
            let parts = trimmed.split(separator: " ", omittingEmptySubsequences: true)
            guard parts.count >= 2 else { continue }
            let ipStr = String(parts[1])
            guard let ip = parseIPv4String(ipStr) else { continue }
            return ip
        }
        return nil
    }

    /// Parse "a.b.c.d" into an IPv4Address, or nil.
    private static func parseIPv4String(_ s: String) -> IPv4Address? {
        let parts = s.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4,
              let a = UInt8(parts[0]), let b = UInt8(parts[1]),
              let c = UInt8(parts[2]), let d = UInt8(parts[3]) else { return nil }
        return IPv4Address(a, b, c, d)
    }

    /// The upstream socket fd, if configured.
    public var pollFD: Int32? { upstreamFD }

    /// Register the upstream DNS socket with Transport for unified polling.
    public mutating func registerUpstreamFD(with transport: inout PollingTransport) {
        guard let fd = upstreamFD else { return }
        transport.registerFD(fd, events: Int16(POLLIN), kind: .rawDatagram)
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
        transport: inout PollingTransport,
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

        // Try upstream forwarding
        if let _ = upstreamFD, let _ = upstreamAddr {
            if forwardToUpstream(
                originalTxID: txID, question: question,
                srcIP: srcIP, dstIP: dstIP,
                srcPort: srcPort, dstPort: dstPort,
                srcMAC: srcMAC, endpointID: endpointID,
                transport: &transport,
                round: round
            ) {
                return  // pending — reply will come via pollUpstream
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

    // MARK: - Upstream poll (I/O + processing)

    /// Drain upstream DNS responses and immediately build VM reply frames.
    /// The upstream DNS socket fd, for inclusion in the unified transport poll.
    public var upstreamPollFD: Int32? { upstreamFD }

    /// Expire pending upstream queries older than 5 seconds, replying NXDOMAIN.
    public mutating func expireQueries(
        hostMAC: MACAddress,
        replies: inout [(endpointID: Int, packet: PacketBuffer)],
        round: RoundContext
    ) {
        let now = UInt64(Darwin.time(nil))
        let expiredKeys = pendingQueries.filter { now - $0.value.createdAt > 5 }.map { $0.key }
        for key in expiredKeys {
            guard let pending = pendingQueries.removeValue(forKey: key) else { continue }
            if let replyPayload = DNSPacket.buildNXDOMAIN(
                txID: pending.originalTxID, question: pending.question, round: round
            ) {
                if let frame = buildUDPFrame(
                    hostMAC: hostMAC, dstMAC: pending.srcMAC,
                    srcIP: pending.dstIP, dstIP: pending.srcIP,
                    srcPort: pending.dstPort, dstPort: pending.srcPort,
                    payload: replyPayload, round: round
                ) {
                    replies.append((pending.endpointID, frame))
                }
            }
        }
    }

    /// Process upstream DNS responses already read by Transport.
    /// Relays the upstream response to the VM with only the transaction ID
    /// swapped back to the original — the answer records (A, AAAA, CNAME,
    /// etc.) are forwarded as-is.
    public mutating func processUpstreamReady(
        data rawDatagramReads: [(fd: Int32, data: PacketBuffer)],
        hostMAC: MACAddress,
        replies: inout [(endpointID: Int, packet: PacketBuffer)],
        round: RoundContext
    ) {
        guard let fd = upstreamFD else { return }

        for (rfd, pkt) in rawDatagramReads where rfd == fd {
            guard let (rxID, _) = DNSPacket.parseResponse(from: pkt) else { continue }
            guard let pending = pendingQueries.removeValue(forKey: rxID) else { continue }

            guard let relayed = DNSPacket.relayResponse(pkt, originalTxID: pending.originalTxID,
                                                        round: round) else { continue }
            if let frame = buildUDPFrame(
                hostMAC: hostMAC, dstMAC: pending.srcMAC,
                srcIP: pending.dstIP, dstIP: pending.srcIP,
                srcPort: pending.dstPort, dstPort: pending.srcPort,
                payload: relayed, round: round
            ) {
                replies.append((pending.endpointID, frame))
            }
        }
    }

    // MARK: - Pending query tracking

    private struct PendingQuery {
        let originalTxID: UInt16
        let question: DNSQuestion
        let srcIP: IPv4Address
        let dstIP: IPv4Address
        let srcPort: UInt16
        let dstPort: UInt16
        let srcMAC: MACAddress
        let endpointID: Int
        let createdAt: UInt64
    }

    // MARK: - Upstream forwarding

    private mutating func forwardToUpstream(
        originalTxID: UInt16,
        question: DNSQuestion,
        srcIP: IPv4Address,
        dstIP: IPv4Address,
        srcPort: UInt16,
        dstPort: UInt16,
        srcMAC: MACAddress,
        endpointID: Int,
        transport: inout PollingTransport,
        round: RoundContext
    ) -> Bool {
        guard let fd = upstreamFD, let upstream = upstreamAddr else { return false }

        let ourTxID = nextTxID
        nextTxID = nextTxID &+ 1
        if nextTxID == 0 { nextTxID = 1 }

        pendingQueries[ourTxID] = PendingQuery(
            originalTxID: originalTxID,
            question: question,
            srcIP: srcIP, dstIP: dstIP,
            srcPort: srcPort, dstPort: dstPort,
            srcMAC: srcMAC, endpointID: endpointID,
            createdAt: UInt64(Darwin.time(nil))
        )

        // Rebuild the query with our transaction ID
        guard let queryPkt = DNSPacket.buildQuery(txID: ourTxID, question: question, round: round) else {
            pendingQueries.removeValue(forKey: ourTxID)
            return false
        }

        transport.writeDatagram(queryPkt, to: fd, addr: upstream)
        return true
    }

    // MARK: - Normalisation

    private static func normaliseHost(_ name: String) -> String {
        let stripped = name.hasSuffix(".") ? String(name.dropLast()) : name
        return stripped.lowercased()
    }
}

// MARK: - Helpers

private func makePacketBuffer(_ data: [UInt8], count: Int, round: RoundContext) -> PacketBuffer {
    var pkt = round.allocate(capacity: count, headroom: 0)
    guard let ptr = pkt.appendPointer(count: count) else { return pkt }
    data.withUnsafeBufferPointer { ptr.copyMemory(from: $0.baseAddress!, byteCount: count) }
    return pkt
}
