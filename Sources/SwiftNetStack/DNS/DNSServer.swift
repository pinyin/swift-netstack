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

    private static func parseIPv4String(_ s: String) -> IPv4Address? {
        let parts = s.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4,
              let a = UInt8(parts[0]), let b = UInt8(parts[1]),
              let c = UInt8(parts[2]), let d = UInt8(parts[3]) else { return nil }
        return IPv4Address(a, b, c, d)
    }

    // MARK: - Resolution

    /// Shared DNS resolution: parse query, check hosts file, return A-record reply.
    /// Returns nil when the hostname is not in the hosts file — caller decides
    /// whether to forward upstream or reply with NXDOMAIN.
    /// Zero-copy: works directly from raw pointer.
    private func resolveLocal(_ ptr: UnsafeRawPointer, _ len: Int) -> [UInt8]? {
        guard let (txID, question) = DNSPacket.parse(from: ptr, len: len) else { return nil }
        if question.type == 1 || question.type == 255 {
            let normalised = Self.normaliseHost(question.name)
            if let ip = hosts[normalised] {
                return DNSPacket.buildAReply(txID: txID, question: question, ip: ip)
            }
        }
        return nil
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
    /// Called from BDP Phase 10 for every UDP datagram destined to port 53.
    public mutating func processQuery(
        payloadPtr: UnsafeMutableRawPointer,
        payloadLen: Int,
        srcIP: IPv4Address,
        dstIP: IPv4Address,
        srcPort: UInt16,
        dstPort: UInt16,
        srcMAC: MACAddress,
        endpointID: Int,
        hostMAC: MACAddress,
        transport: inout PollingTransport,
        outBatch: OutBatch, io: IOBuffer
    ) {
        // Shared local resolution (hosts file lookup).
        if let reply = resolveLocal(payloadPtr, payloadLen) {
            buildUDPFrameInIO(hostMAC: hostMAC, dstMAC: srcMAC,
                              srcIP: dstIP, dstIP: srcIP,
                              srcPort: dstPort, dstPort: srcPort,
                              payload: reply, endpointID: endpointID,
                              io: io, outBatch: outBatch)
            return
        }

        // Hostname not in hosts — parse for upstream/NXDOMAIN.
        guard let (txID, question) = DNSPacket.parse(from: payloadPtr, len: payloadLen) else { return }

        // Try upstream forwarding
        if let _ = upstreamFD, let _ = upstreamAddr {
            if forwardToUpstream(
                originalTxID: txID, question: question,
                srcIP: srcIP, dstIP: dstIP,
                srcPort: srcPort, dstPort: dstPort,
                srcMAC: srcMAC, endpointID: endpointID,
                transport: &transport
            ) {
                return
            }
        }

        // NXDOMAIN for anything we cannot resolve
        let nxBytes = DNSPacket.buildNXDOMAIN(txID: txID, question: question)
        buildUDPFrameInIO(hostMAC: hostMAC, dstMAC: srcMAC,
                          srcIP: dstIP, dstIP: srcIP,
                          srcPort: dstPort, dstPort: srcPort,
                          payload: nxBytes, endpointID: endpointID,
                          io: io, outBatch: outBatch)
    }

    /// Expire pending upstream queries older than 5 seconds, replying NXDOMAIN.
    public mutating func expireQueries(
        hostMAC: MACAddress,
        outBatch: OutBatch, io: IOBuffer
    ) {
        let now = UInt64(Darwin.time(nil))
        let expiredKeys = pendingQueries.filter { now - $0.value.createdAt > 5 }.map { $0.key }
        for key in expiredKeys {
            guard let pending = pendingQueries.removeValue(forKey: key) else { continue }
            let nxBytes = DNSPacket.buildNXDOMAIN(txID: pending.originalTxID, question: pending.question)
            buildUDPFrameInIO(hostMAC: hostMAC, dstMAC: pending.srcMAC,
                              srcIP: pending.dstIP, dstIP: pending.srcIP,
                              srcPort: pending.dstPort, dstPort: pending.srcPort,
                              payload: nxBytes, endpointID: pending.endpointID,
                              io: io, outBatch: outBatch)
        }
    }

    /// Process upstream DNS responses already read by Transport.
    /// Relays the upstream response to the VM with only the transaction ID
    /// swapped back to the original.
    public mutating func processUpstreamReady(
        data rawDatagramReads: [(fd: Int32, data: [UInt8])],
        hostMAC: MACAddress,
        outBatch: OutBatch, io: IOBuffer
    ) {
        guard let fd = upstreamFD else { return }

        for (rfd, data) in rawDatagramReads where rfd == fd {
            guard let (rxID, _) = data.withUnsafeBytes({ buf in
                DNSPacket.parseResponse(from: buf.baseAddress!, len: data.count)
            }) else { continue }
            guard let pending = pendingQueries.removeValue(forKey: rxID) else { continue }

            let relayed = data.withUnsafeBytes { buf in
                DNSPacket.relayResponse(from: buf.baseAddress!, len: data.count,
                                        originalTxID: pending.originalTxID)
            }
            buildUDPFrameInIO(hostMAC: hostMAC, dstMAC: pending.srcMAC,
                              srcIP: pending.dstIP, dstIP: pending.srcIP,
                              srcPort: pending.dstPort, dstPort: pending.srcPort,
                              payload: relayed, endpointID: pending.endpointID,
                              io: io, outBatch: outBatch)
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
        transport: inout PollingTransport
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

        let queryBytes = DNSPacket.buildQuery(txID: ourTxID, question: question)
        queryBytes.withUnsafeBytes { buf in
            transport.writeDatagram(buf.baseAddress!, buf.count, to: fd, addr: upstream)
        }
        return true
    }

    // MARK: - Normalisation

    private static func normaliseHost(_ name: String) -> String {
        let stripped = name.hasSuffix(".") ? String(name.dropLast()) : name
        return stripped.lowercased()
    }
}

// MARK: - UDP frame builder (IOBuffer-based)

/// Build a complete Ethernet+IPv4+UDP+payload frame in IOBuffer.output and
/// add to outBatch. Used by DNSServer for all DNS reply paths.
private func buildUDPFrameInIO(
    hostMAC: MACAddress, dstMAC: MACAddress,
    srcIP: IPv4Address, dstIP: IPv4Address,
    srcPort: UInt16, dstPort: UInt16,
    payload: [UInt8], endpointID: Int,
    io: IOBuffer, outBatch: OutBatch
) {
    let udpTotalLen = 8 + payload.count
    let ipTotalLen = 20 + udpTotalLen
    let frameLen = 14 + ipTotalLen

    guard let ptr = io.allocOutput(frameLen) else { return }
    let ofs = ptr - io.output.baseAddress!

    // Ethernet
    dstMAC.write(to: ptr)
    hostMAC.write(to: ptr.advanced(by: 6))
    writeUInt16BE(EtherType.ipv4.rawValue, to: ptr.advanced(by: 12))

    // IPv4
    let ipPtr = ptr.advanced(by: ethHeaderLen)
    writeIPv4Header(to: ipPtr, totalLength: UInt16(ipTotalLen), protocol: .udp,
                    srcIP: srcIP, dstIP: dstIP)

    // UDP
    let udpPtr = ipPtr.advanced(by: ipv4HeaderLen)
    writeUInt16BE(srcPort, to: udpPtr)
    writeUInt16BE(dstPort, to: udpPtr.advanced(by: 2))
    writeUInt16BE(UInt16(udpTotalLen), to: udpPtr.advanced(by: 4))
    writeUInt16BE(0, to: udpPtr.advanced(by: 6))

    // Payload
    payload.withUnsafeBytes { buf in
        udpPtr.advanced(by: 8).copyMemory(from: buf.baseAddress!, byteCount: buf.count)
    }

    // UDP checksum
    let ck = computeUDPChecksum(
        pseudoSrcAddr: srcIP, pseudoDstAddr: dstIP,
        udpData: udpPtr, udpLen: udpTotalLen
    )
    writeUInt16BE(ck, to: udpPtr.advanced(by: 6))

    let idx = outBatch.count
    guard idx < outBatch.maxFrames else { return }
    outBatch.hdrOfs[idx] = ofs
    outBatch.hdrLen[idx] = frameLen
    outBatch.payOfs[idx] = -1
    outBatch.payLen[idx] = 0
    outBatch.epIDs[idx] = endpointID
    outBatch.payBase[idx] = nil
    outBatch.count += 1
}
