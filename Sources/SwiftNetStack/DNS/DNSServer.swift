import Darwin

/// Static DNS server backed by a hosts file, with optional upstream forwarding.
///
/// Queries matching a hostname in `hosts` receive an A-record reply.
/// When an upstream server is configured, queries that miss the hosts file
/// are forwarded upstream; responses are matched to pending queries by
/// transaction ID and relayed back to the VM.
public struct DNSServer {
    private let hosts: [String: IPv4Address]
    private let upstreamFD: Int32?
    private let upstreamAddr: sockaddr_in?
    private var pendingQueries: [UInt16: PendingQuery] = [:]
    private var nextTxID: UInt16 = 1
    private static let pendingTimeout: UInt64 = 10  // seconds

    /// Create a DNS server with the given hosts-file mappings and optional upstream.
    /// - Parameter hosts: hostname-to-IP mappings (keys are normalised at init).
    /// - Parameter upstream: upstream DNS server address, or nil for hosts-only mode.
    public init(hosts: [String: IPv4Address], upstream: IPv4Address? = nil) {
        var normalised: [String: IPv4Address] = [:]
        for (name, ip) in hosts {
            let key = DNSServer.normaliseHost(name)
            normalised[key] = ip
        }
        self.hosts = normalised

        if let upstream = upstream {
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
                    withUnsafeMutableBytes(of: &addr.sin_addr) { upstream.write(to: $0.baseAddress!) }
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

    /// The upstream socket fd, if configured. Exposed for BDP loop polling.
    public var pollFD: Int32? { upstreamFD }

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

        // Try upstream forwarding
        if let _ = upstreamFD, let _ = upstreamAddr {
            if forwardToUpstream(
                originalTxID: txID, question: question,
                srcIP: srcIP, dstIP: dstIP,
                srcPort: srcPort, dstPort: dstPort,
                srcMAC: srcMAC, endpointID: endpointID,
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

    /// Poll the upstream socket and process any responses.
    /// Called from the BDP loop after Phase 11 (NAT poll).
    public mutating func pollUpstream(
        hostMAC: MACAddress,
        replies: inout [(endpointID: Int, packet: PacketBuffer)],
        round: RoundContext
    ) {
        guard let fd = upstreamFD else { return }

        // Read all available responses
        var buf = [UInt8](repeating: 0, count: 2048)
        let now = UInt64(Darwin.time(nil))

        while true {
            let n = Darwin.recvfrom(fd, &buf, buf.count, 0, nil, nil)
            guard n >= 12 else { break }

            // Parse the response
            let pkt = makePacketBuffer(buf, count: n, round: round)
            guard let (rxID, question) = DNSPacket.parseResponse(from: pkt) else { continue }
            guard let pending = pendingQueries.removeValue(forKey: rxID) else { continue }

            // Reconstruct reply using the original transaction ID and deliver to VM
            let normalised = DNSServer.normaliseHost(question.name)
            if let ip = hosts[normalised] {
                if let replyPayload = DNSPacket.buildAReply(
                    txID: pending.originalTxID, question: pending.question, ip: ip, round: round
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
            } else if let ip = DNSPacket.extractFirstA(from: pkt) {
                if let replyPayload = DNSPacket.buildAReply(
                    txID: pending.originalTxID, question: pending.question, ip: ip, round: round
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
            } else {
                // Upstream returned no A record — NXDOMAIN
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

        // Cleanup expired pending queries
        var expired: [UInt16] = []
        for (txID, pq) in pendingQueries where now - pq.timestamp > DNSServer.pendingTimeout {
            expired.append(txID)
        }
        for txID in expired {
            pendingQueries.removeValue(forKey: txID)
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
        let timestamp: UInt64
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
            timestamp: UInt64(Darwin.time(nil))
        )

        // Rebuild the query with our transaction ID
        guard let queryPkt = DNSPacket.buildQuery(txID: ourTxID, question: question, round: round) else {
            pendingQueries.removeValue(forKey: ourTxID)
            return false
        }

        queryPkt.withUnsafeReadableBytes { buf in
            withUnsafePointer(to: upstream) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                    _ = Darwin.sendto(fd, buf.baseAddress!, buf.count, 0, sa, socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }
        }
        return true
    }

    // MARK: - Normalisation

    private static func normaliseHost(_ name: String) -> String {
        let stripped = name.hasSuffix(".") ? String(name.dropLast()) : name
        return stripped.lowercased()
    }
}

// MARK: - Helpers

private func setNonBlocking(_ fd: Int32) {
    let flags = fcntl(fd, F_GETFL, 0)
    if flags >= 0 { _ = fcntl(fd, F_SETFL, flags | O_NONBLOCK) }
}

private func makePacketBuffer(_ data: [UInt8], count: Int, round: RoundContext) -> PacketBuffer {
    var pkt = round.allocate(capacity: count, headroom: 0)
    guard let ptr = pkt.appendPointer(count: count) else { return pkt }
    data.withUnsafeBufferPointer { ptr.copyMemory(from: $0.baseAddress!, byteCount: count) }
    return pkt
}
