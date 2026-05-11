import Darwin

/// NAT connection tracker and TCP/UDP proxy.
///
/// Manages proxied connections with TCP/UDP symmetry:
/// - **processTCPRound** (Phase 11): all VM↔external TCP work in one method
/// - **processUDP** (Phase 9):  VM→external UDP via per-mapping sockets
/// - **processTransportResult** (Phase 12): external→VM for UDP, dead FDs, new accepts
///
/// Each NAT entry (TCP connection or UDP mapping) owns exactly one POSIX fd,
/// making the fd→key reverse lookup trivial and symmetric across protocols.
public struct NATTable {
    // Connection limits
    private let maxTCPConnections: Int = 256
    private let maxUDPMappings: Int = 256

    /// Skip cleanup scanning if last scan was less than 1 second ago.
    private var lastCleanupTime: UInt64 = 0

    /// Connections modified in this round (steps 2-4). Step 5 iterates only
    /// these instead of all tcpEntries, avoiding O(N) idle-connection scans.
    private var dirtyConnections: Set<NATKey> = []

    /// Optional pcap writer for external socket traffic (synthetic frames).
    /// Set before run() to capture VM↔external data for Wireshark analysis.
    public var externalPcap: PCAPWriter? = nil

#if DEBUG
    /// Current round number — set by processTCPRound, read by debugLog.
    private var debugRound: UInt64 = 0
#endif

    // TCP
    private var tcpEntries: [NATKey: NATEntry] = [:]
    private var tcpFdToKey: [Int32: NATKey] = [:]

    // UDP
    private var udpEntries: [NATKey: UDPNATMapping] = [:]
    private var udpFdToKey: [Int32: NATKey] = [:]

    // Listeners (TCP + UDP port forwards)
    private var tcpListeners: [(fd: Int32, entry: PortForwardEntry)] = []
    private var udpListeners: [(fd: Int32, entry: PortForwardEntry)] = []

    private var _nextID: UInt64 = 0

    public init(portForwards: [PortForwardEntry] = []) {
        tcpEntries.reserveCapacity(maxTCPConnections)
        tcpFdToKey.reserveCapacity(maxTCPConnections)
        udpEntries.reserveCapacity(maxUDPMappings)
        udpFdToKey.reserveCapacity(maxUDPMappings)
        dirtyConnections.reserveCapacity(maxTCPConnections)

        for pf in portForwards {
            switch pf.protocol {
            case .tcp:
                if let fd = createTCPListener(port: pf.hostPort) {
                    tcpListeners.append((fd, pf))
                }
            case .udp:
                if let fd = createUDPListener(port: pf.hostPort) {
                    udpListeners.append((fd, pf))
                }
            default:
                break
            }
        }
    }

    public var tcpCount: Int { tcpEntries.count }
    public var udpCount: Int { udpEntries.count }

    public var tcpListenerPorts: [UInt16] {
        tcpListeners.compactMap { listenerPort($0.fd) }
    }

    public var udpListenerPorts: [UInt16] {
        udpListeners.compactMap { listenerPort($0.fd) }
    }

    // MARK: - Dynamic port forwarding

    public var activePortForwards: [PortForwardEntry] {
        tcpListeners.map { $0.entry } + udpListeners.map { $0.entry }
    }

    @discardableResult
    public mutating func addPortForward(_ pf: PortForwardEntry) -> Bool {
        if pf.hostPort != 0 {
            let existingPorts = allListenerPorts()
            if existingPorts.contains(pf.hostPort) { return false }
        }
        switch pf.protocol {
        case .tcp:
            guard let fd = createTCPListener(port: pf.hostPort) else { return false }
            tcpListeners.append((fd, pf))
            return true
        case .udp:
            guard let fd = createUDPListener(port: pf.hostPort) else { return false }
            udpListeners.append((fd, pf))
            return true
        default:
            return false
        }
    }

    @discardableResult
    public mutating func removePortForward(hostPort: UInt16, protocol: IPProtocol) -> Bool {
        switch `protocol` {
        case .tcp:
            guard let idx = tcpListeners.firstIndex(where: { listenerPort($0.fd) == hostPort }) else { return false }
            close(tcpListeners[idx].fd)
            tcpListeners.remove(at: idx)
            return true
        case .udp:
            guard let idx = udpListeners.firstIndex(where: { listenerPort($0.fd) == hostPort }) else { return false }
            close(udpListeners[idx].fd)
            udpListeners.remove(at: idx)
            return true
        default:
            return false
        }
    }

    private func allListenerPorts() -> Set<UInt16> {
        var ports = Set<UInt16>()
        for listener in tcpListeners {
            if let p = listenerPort(listener.fd) { ports.insert(p) }
        }
        for listener in udpListeners {
            if let p = listenerPort(listener.fd) { ports.insert(p) }
        }
        return ports
    }

    private func listenerPort(_ fd: Int32) -> UInt16? {
        var addr = sockaddr_in()
        var len = socklen_t(MemoryLayout<sockaddr_in>.size)
        let ok = withUnsafeMutablePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                getsockname(fd, $0, &len)
            }
        }
        guard ok >= 0 else { return nil }
        return addr.sin_port.bigEndian
    }

    // MARK: - Phase 9: UDP processing (VM → external)

    public mutating func processUDP(
        eth: EthernetFrame,
        ip: IPv4Header,
        udp: UDPHeader,
        endpointID: Int,
        hostMAC: MACAddress,
        transport: inout PollingTransport,
        replies: inout [(endpointID: Int, packet: PacketBuffer)],
        round: RoundContext
    ) {
        let key = NATKey(vmIP: ip.srcAddr, vmPort: udp.srcPort, dstIP: ip.dstAddr, dstPort: udp.dstPort, protocol: .udp)

        if var mapping = udpEntries[key] {
            mapping.lastActivity = currentTime()
            udpEntries[key] = mapping
            sendUDP(fd: mapping.fd, data: udp.payload, dstIP: key.dstIP, dstPort: key.dstPort, transport: &transport)
            return
        }

        if udpEntries.count >= maxUDPMappings { return }

        let fd = socket(AF_INET, SOCK_DGRAM, 0)
        guard fd >= 0 else { return }
        setNonBlocking(fd)

        var bindAddr = sockaddr_in()
        bindAddr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        bindAddr.sin_family = sa_family_t(AF_INET)
        bindAddr.sin_port = 0
        bindAddr.sin_addr.s_addr = INADDR_ANY.bigEndian

        let bindOK = withUnsafePointer(to: &bindAddr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard bindOK >= 0 else { close(fd); return }

        let mapping = UDPNATMapping(
            key: key, fd: fd,
            vmMAC: eth.srcMAC, endpointID: endpointID,
            isInbound: false
        )
        udpEntries[key] = mapping
        udpFdToKey[fd] = key
        transport.registerFD(fd, events: Int16(POLLIN), kind: .datagram)

        sendUDP(fd: fd, data: udp.payload, dstIP: key.dstIP, dstPort: key.dstPort, transport: &transport)
    }

    // MARK: - Phase 11: Unified TCP processing (VM ↔ external)

    /// All VM↔external TCP processing for one BDP round.
    ///
    /// Replaces the old 4-phase design with a single method that processes each
    /// connection fully in one place — eliminating the "copy out, modify, manually
    /// track updated flag, write back" pattern that caused bugs.
    ///
    /// Internal ordering:
    ///   1. Complete non-blocking connects
    ///   2. Process VM→external segments
    ///   3. Process external→VM reads
    ///   4. Handle external hangups
    ///   5. Flush send queues and forward pending FIN immediately when the
    ///      external send queue is drained — FIN is a TCP signal like any
    ///      other; RFC 793 half-close allows the server to continue sending.
    public mutating func processTCPRound(
        vmSegments: [(ep: Int, eth: EthernetFrame, ip: IPv4Header, tcp: TCPHeader)],
        streamReads: [(fd: Int32, data: PacketBuffer)],
        streamHangup: [Int32],
        streamConnects: [Int32],
        transport: inout PollingTransport,
        hostMAC: MACAddress,
        arpMapping: ARPMapping,
        replies: inout [(endpointID: Int, packet: PacketBuffer)],
        round: RoundContext
    ) {
#if DEBUG
        debugRound = round.roundNumber
#endif

        // ── Step 1: Complete non-blocking connects ──
        for fd in streamConnects {
            guard let key = tcpFdToKey[fd], let entry = tcpEntries[key] else { continue }
            let st = entry.connection.state
            guard st == .listen || st == .synReceived else { continue }

            var addr = sockaddr_in()
            var addrLen = socklen_t(MemoryLayout<sockaddr_in>.size)
            let result = withUnsafeMutablePointer(to: &addr) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    getpeername(fd, $0, &addrLen)
                }
            }
            if result < 0 {
                if errno == ENOTCONN { continue }
                cleanupTCP(fd: fd, key: key, transport: &transport)
                continue
            }
            tcpEntries[key]?.connection.externalConnecting = false
            transport.registerFD(fd, events: Int16(POLLIN), kind: .stream)
        }

        // ── Step 2: Process VM→external segments ──
        for (ep, eth, ip, tcp) in vmSegments {
            let key = NATKey(vmIP: ip.srcAddr, vmPort: tcp.srcPort, dstIP: ip.dstAddr, dstPort: tcp.dstPort, protocol: .tcp)

            // New outbound connection
            if tcp.flags.isSyn, !tcp.flags.isAck {
                handleOutboundSYN(
                    key: key, eth: eth, ip: ip, tcp: tcp, endpointID: ep,
                    hostMAC: hostMAC, transport: &transport,
                    replies: &replies, round: round
                )
                dirtyConnections.insert(key)
                continue
            }

            // RST → cleanup
            if tcp.flags.isRst {
                if let entry = tcpEntries[key] {
                    cleanupTCP(fd: entry.connection.posixFD, key: key, transport: &transport)
                }
                continue
            }

            guard var entry = tcpEntries[key] else { continue }
            var conn = entry.connection
            entry.lastActivity = currentTime()

            // Check external connect completion (synReceived state)
            if conn.state == .synReceived {
                var addr = sockaddr_in()
                var addrLen = socklen_t(MemoryLayout<sockaddr_in>.size)
                let result = withUnsafeMutablePointer(to: &addr) {
                    $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                        getpeername(conn.posixFD, $0, &addrLen)
                    }
                }
                if result < 0 {
                    // connect still in progress — skip processing this round.
                    // The VM will retransmit if needed (RTO); on localhost the
                    // connect always completes before the ACK arrives so this
                    // gate is never hit in practice.
                    continue
                }
                if conn.externalConnecting {
                    conn.externalConnecting = false
                    transport.registerFD(conn.posixFD, events: Int16(POLLIN), kind: .stream)
                }
            }

            let oldState = conn.state
            let oldUna = conn.snd.una
            let (newState, toSend, dataToExternal) = tcpProcess(
                state: conn.state, segment: tcp, snd: &conn.snd, rcv: &conn.rcv, appClose: false
            )
            conn.state = newState
            let unaDelta = Int(conn.snd.una &- oldUna)
            if unaDelta > 0 { conn.ackSendBuf(delta: unaDelta) }
            // Resume external reads if backpressure cleared
            if conn.sendQueueBlocked, conn.totalQueuedBytes < TCPConnection.maxQueueBytes / 2 {
                conn.sendQueueBlocked = false
                transport.setFDEvents(conn.posixFD, events: Int16(POLLIN))
            }
            if oldState != newState {
                debugLog("[NAT-TCP-PROC] state \(oldState) → \(newState) for \(key.dstIP):\(key.dstPort), flags=\(tcp.flags.rawValue)\n")
            } else if toSend.isEmpty && (dataToExternal == nil || dataToExternal!.isEmpty) {
                // Segment didn't change state, produce a response, or carry data —
                // log the full segment details so we can see why it was rejected.
                debugLog("[NAT-TCP-REJ] C\(conn.connectionID) \(oldState) \(key.dstIP):\(key.dstPort) "
                    + "seq=\(tcp.sequenceNumber) ack=\(tcp.acknowledgmentNumber) "
                    + "flags=0x\(String(tcp.flags.rawValue, radix: 16)) "
                    + "wnd=\(tcp.window) dataLen=\(tcp.payload.totalLength) "
                    + "rcv.nxt=\(conn.rcv.nxt) snd.nxt=\(conn.snd.nxt) snd.una=\(conn.snd.una)\n")
            }
            if let data = dataToExternal, !data.isEmpty {
                debugLog("[NAT-TCP-PROC] buffering \(data.totalLength)B for external \(key.dstIP):\(key.dstPort)\n")
                conn.appendExternalSend(data)
            }

            if newState == .closeWait {
                conn.pendingExternalFin = true
            }
            for seg in toSend {
                if let frame = buildTCPFrame(
                    hostMAC: hostMAC, dstMAC: eth.srcMAC,
                    srcIP: ip.dstAddr, dstIP: ip.srcAddr,
                    srcPort: tcp.dstPort, dstPort: tcp.srcPort,
                    seqNumber: seg.seq, ackNumber: seg.ack,
                    flags: seg.flags, window: seg.window,
                    payload: nil, round: round
                ) {
                    replies.append((ep, frame))
                }
            }

            entry.connection = conn
            tcpEntries[key] = entry
            dirtyConnections.insert(key)

            if newState == .closed {
                cleanupTCP(fd: conn.posixFD, key: key, transport: &transport)
            }
        }

        // ── Step 3: Process external→VM reads ──
        for (fd, data) in streamReads {
            guard let key = tcpFdToKey[fd], var entry = tcpEntries[key] else { continue }
            let st = entry.connection.state
            guard st == .synReceived || st == .established || st == .finWait1 || st == .finWait2
                || st == .closeWait || st == .lastAck else { continue }
            if entry.connection.externalEOF { continue }

            debugLog("[NAT-TCP-RD] read \(data.totalLength)B external→VM for \(key.dstIP):\(key.dstPort), state=\(st)\n")
            entry.lastActivity = currentTime()
            let queued = entry.connection.writeSendBuf(data)
            if queued == 0, !entry.connection.sendQueueBlocked {
                entry.connection.sendQueueBlocked = true
                transport.setFDEvents(fd, events: 0)  // pause reads until queue drains
            }
            if let pw = self.externalPcap, queued > 0 {
                captureExternalPacket(pcap: pw, fd: fd, direction: .fromExternal,
                    conn: entry.connection, flags: [.ack, .psh], payload: data,
                    hostMAC: hostMAC, round: round)
            }
            tcpEntries[key] = entry
            dirtyConnections.insert(key)
        }

        // ── Step 4: Handle external hangups ──
        for fd in streamHangup {
            guard let key = tcpFdToKey[fd], var entry = tcpEntries[key] else { continue }
            let st = entry.connection.state
            if st == .listen || st == .synReceived {
                if entry.connection.totalQueuedBytes > 0 {
                    debugLog("[NAT-TCP-HUP] external EOF for \(key.dstIP):\(key.dstPort) (data queued in synReceived)\n")
                    entry.lastActivity = currentTime()
                    entry.connection.externalEOF = true
                    entry.connection.pendingExternalFin = false
                    tcpEntries[key] = entry
                    dirtyConnections.insert(key)
                    handleTCPExternalFIN(key: key, hostMAC: hostMAC, transport: &transport,
                                         replies: &replies, round: round)
                    continue
                }
                cleanupTCP(fd: entry.connection.posixFD, key: key, transport: &transport)
                continue
            }
            if entry.connection.externalEOF { continue }
            debugLog("[NAT-TCP-HUP] external EOF for \(key.dstIP):\(key.dstPort), state=\(st)\n")
            entry.lastActivity = currentTime()
            entry.connection.externalEOF = true
            entry.connection.pendingExternalFin = false
            tcpEntries[key] = entry
            dirtyConnections.insert(key)
            handleTCPExternalFIN(key: key, hostMAC: hostMAC, transport: &transport,
                                 replies: &replies, round: round)
        }

        // ── Step 5: Flush dirty connections (drain queues, forward FIN) ──
        for key in dirtyConnections {
            guard var entry = tcpEntries[key] else { continue }
            var conn = entry.connection
            guard conn.state == .established || conn.state == .closeWait
                  || conn.state == .finWait1 || conn.state == .finWait2
                  || conn.state == .lastAck else { continue }

            flushOneConnection(key: key, conn: &conn, hostMAC: hostMAC,
                               transport: &transport, replies: &replies, round: round)
            entry.connection = conn
            tcpEntries[key] = entry
        }
        dirtyConnections.removeAll(keepingCapacity: true)
    }

    // MARK: - Per-connection flush (send queues + FIN forwarding)

    /// Drain both send queues for one connection and handle pending FIN.
    /// Called from processTCPRound step 5 — no manual `updated` flag needed
    /// because the caller writes back unconditionally.
    private mutating func flushOneConnection(
        key: NATKey, conn: inout TCPConnection,
        hostMAC: MACAddress,
        transport: inout PollingTransport,
        replies: inout [(endpointID: Int, packet: PacketBuffer)],
        round: RoundContext
    ) {
        let mss = 1400

        // ── Drain sendQueue (external→VM) ──
        if conn.totalQueuedBytes > 0 {
            var segCount = 0
            let maxSegs = 64
            while segCount < maxSegs {
                let inFlight = conn.snd.nxt &- conn.snd.una
                var canSend = Int(conn.snd.wnd) - Int(inFlight)
                if canSend <= 0 { break }
                if canSend > mss { canSend = mss }
                guard let data = conn.peekSendData(max: canSend) else { break }
                debugLog("[NAT-TCP-FLUSH] flushing \(data.totalLength)B to VM \(conn.vmIP):\(conn.vmPort), state=\(conn.state), queued=\(conn.totalQueuedBytes)\n")
                let flags: TCPFlags = [.ack, .psh]
                if let frame = buildTCPFrame(
                    hostMAC: hostMAC, dstMAC: conn.vmMAC,
                    srcIP: conn.dstIP, dstIP: conn.vmIP,
                    srcPort: conn.dstPort, dstPort: conn.vmPort,
                    seqNumber: conn.snd.nxt, ackNumber: conn.rcv.nxt,
                    flags: flags, window: 65535,
                    payload: data, round: round
                ) {
                    replies.append((conn.endpointID, frame))
                    conn.snd.nxt = conn.snd.nxt &+ UInt32(data.totalLength)
                    conn.sendQueueSent += data.totalLength
                    segCount += 1
                } else {
                    break
                }
            }
        }

        // ── Drain externalSendQueue (VM→external) ──
        while conn.externalSendQueued > 0 {
            guard let chunk = conn.externalSendQueue.slice(
                from: 0, length: min(conn.externalSendQueued, 65536)
            ) else { break }
            let written = transport.writeStream(chunk, to: conn.posixFD)
            if written < 0 {
                if errno == EAGAIN { break }
                debugLog("[NAT-TCP-EXT] write to \(key.dstIP):\(key.dstPort) failed: errno=\(errno)\n")
                break
            }
            if written == 0 { break }
            debugLog("[NAT-TCP-EXT] flushed \(written)B to \(key.dstIP):\(key.dstPort)\n")
            if let pw = self.externalPcap, let payload = chunk.slice(from: 0, length: written) {
                captureExternalPacket(pcap: pw, fd: conn.posixFD, direction: .toExternal,
                    conn: conn, flags: [.ack, .psh], payload: payload,
                    hostMAC: hostMAC, round: round)
            }
            conn.drainExternalSend(written)
        }

        // ── Forward pending FIN once externalSendQueue is drained ──
        if conn.pendingExternalFin, conn.externalSendQueued == 0 {
            debugLog("[NAT-TCP-FIN] forwarding FIN to \(key.dstIP):\(key.dstPort)\n")
            shutdown(conn.posixFD, SHUT_WR)
            if let pw = self.externalPcap {
                captureExternalPacket(pcap: pw, fd: conn.posixFD, direction: .toExternal,
                    conn: conn, flags: [.fin, .ack], payload: nil,
                    hostMAC: hostMAC, round: round)
            }
            conn.pendingExternalFin = false
        }
    }

    // MARK: - External pcap capture (centralized helper)

    /// Capture a synthetic Ethernet frame representing external socket traffic.
    /// Uses `getsockname`/`getpeername` for real addresses so the pcap shows
    /// exactly what the kernel sent on the wire, not the VM's internal addresses.
    private func captureExternalPacket(
        pcap: PCAPWriter,
        fd: Int32,
        direction: ExternalDirection,
        conn: TCPConnection,
        flags: TCPFlags,
        payload: PacketBuffer?,
        hostMAC: MACAddress,
        round: RoundContext
    ) {
        var localAddr = sockaddr_in()
        var localLen = socklen_t(MemoryLayout<sockaddr_in>.size)
        let hasLocal = withUnsafeMutablePointer(to: &localAddr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                getsockname(fd, $0, &localLen)
            }
        } >= 0

        var remoteAddr = sockaddr_in()
        var remoteLen = socklen_t(MemoryLayout<sockaddr_in>.size)
        let hasRemote = withUnsafeMutablePointer(to: &remoteAddr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                getpeername(fd, $0, &remoteLen)
            }
        } >= 0

        let hostIP = hasLocal
            ? IPv4Address(addr: localAddr.sin_addr.s_addr.bigEndian)
            : conn.vmIP
        let hostPort = hasLocal
            ? localAddr.sin_port.bigEndian
            : conn.vmPort
        let serverIP = hasRemote
            ? IPv4Address(addr: remoteAddr.sin_addr.s_addr.bigEndian)
            : conn.dstIP
        let serverPort = hasRemote
            ? remoteAddr.sin_port.bigEndian
            : conn.dstPort

        let srcIP: IPv4Address
        let srcPort: UInt16
        let dstIP: IPv4Address
        let dstPort: UInt16

        switch direction {
        case .toExternal:
            srcIP = hostIP; srcPort = hostPort
            dstIP = serverIP; dstPort = serverPort
        case .fromExternal:
            srcIP = serverIP; srcPort = serverPort
            dstIP = hostIP; dstPort = hostPort
        }

        // Synthetic frames use seq=0 ack=0 — the real TCP sequence numbers
        // belong to the kernel's POSIX socket, not the NAT's FSM.
        if let frame = buildTCPFrame(
            hostMAC: hostMAC, dstMAC: hostMAC,
            srcIP: srcIP, dstIP: dstIP,
            srcPort: srcPort, dstPort: dstPort,
            seqNumber: 0, ackNumber: 0,
            flags: flags, window: 65535,
            payload: payload, round: round
        ) {
            pcap.write(packet: frame)
        }
    }

    private enum ExternalDirection {
        case toExternal
        case fromExternal
    }

    // MARK: - Phase 12: Non-TCP transport result processing

    /// Handle dead FDs, new accepts, and UDP reads from the transport result.
    /// TCP reads, hangups, and connects are handled by processTCPRound (Phase 11).
    public mutating func processTransportResult(
        _ result: TransportResult,
        transport: inout PollingTransport,
        hostMAC: MACAddress,
        arpMapping: ARPMapping,
        replies: inout [(endpointID: Int, packet: PacketBuffer)],
        round: RoundContext
    ) {
        let now = currentTime()
        if now - lastCleanupTime >= 1 {
            cleanupExpiredUDP(transport: &transport)
            cleanupExpiredTCP(transport: &transport)
            lastCleanupTime = now
        }

        // Dead FDs → cleanup
        for fd in result.deadFDs {
            if tcpListeners.contains(where: { $0.fd == fd }) {
                transport.unregisterFD(fd); close(fd)
                tcpListeners.removeAll { $0.fd == fd }
            } else if udpListeners.contains(where: { $0.fd == fd }) {
                transport.unregisterFD(fd); close(fd)
                udpListeners.removeAll { $0.fd == fd }
            } else if let key = tcpFdToKey[fd] {
                cleanupTCP(fd: fd, key: key, transport: &transport)
            } else if let key = udpFdToKey[fd] {
                cleanupUDP(fd: fd, key: key, transport: &transport)
            }
        }

        // Stream accepts → new inbound connections
        for (listenerFD, newFD, remoteAddr) in result.streamAccepts {
            pollTCPAccept(listenerFd: listenerFD, newFD: newFD, clientAddr: remoteAddr,
                          hostMAC: hostMAC, arpMapping: arpMapping,
                          transport: &transport, replies: &replies, round: round)
        }

        // Datagram reads → UDP data from external
        for (fd, data, from) in result.datagramReads {
            if udpListeners.contains(where: { $0.fd == fd }) {
                pollUDPAccept(fd: fd, data: data, from: from,
                              hostMAC: hostMAC, arpMapping: arpMapping,
                              replies: &replies, round: round)
            } else if let key = udpFdToKey[fd] {
                pollUDPReadable(key: key, data: data, hostMAC: hostMAC,
                                arpMapping: arpMapping, replies: &replies, round: round)
            }
        }
    }

    // MARK: - External FD registration (for unified poll)

    /// Register all existing NAT-controlled FDs with Transport.
    /// Called once before the main loop starts.
    public mutating func syncExternalFDs(with transport: inout PollingTransport) {
        for (fd, _) in tcpListeners { transport.registerFD(fd, events: Int16(POLLIN), kind: .stream) }
        for (fd, _) in udpListeners { transport.registerFD(fd, events: Int16(POLLIN), kind: .datagram) }
        for (_, entry) in tcpEntries {
            var events = Int16(POLLIN)
            if entry.connection.wantsPOLLOUT() { events |= Int16(POLLOUT) }
            transport.registerFD(entry.connection.posixFD, events: events, kind: .stream)
        }
        for (_, mapping) in udpEntries {
            transport.registerFD(mapping.fd, events: Int16(POLLIN), kind: .datagram)
        }
    }

    // MARK: ── Inbound connection accept ──

    private mutating func pollTCPAccept(
        listenerFd: Int32, newFD: Int32, clientAddr: sockaddr_in,
        hostMAC: MACAddress, arpMapping: ARPMapping, transport: inout PollingTransport,
        replies: inout [(endpointID: Int, packet: PacketBuffer)], round: RoundContext
    ) {
        guard tcpEntries.count < maxTCPConnections else { close(newFD); return }
        setNoDelay(newFD)

        guard let pf = findTCPListener(fd: listenerFd) else { close(newFD); return }
        let externalIP = IPv4Address(addr: clientAddr.sin_addr.s_addr.bigEndian)
        let externalPort = clientAddr.sin_port.bigEndian

        let key = NATKey(vmIP: pf.vmIP, vmPort: pf.vmPort, dstIP: externalIP, dstPort: externalPort, protocol: .tcp)
        guard let (vmMAC, vmEp) = lookupVM(ip: pf.vmIP, arpMapping: arpMapping) else { close(newFD); return }

        let isn = tcpGenerateISN()
        var conn = TCPConnection(
            connectionID: nextID(), posixFD: newFD, state: .synReceived,
            vmMAC: vmMAC, vmIP: pf.vmIP, vmPort: pf.vmPort,
            dstIP: externalIP, dstPort: externalPort, endpointID: vmEp
        )
        conn.snd.nxt = isn
        conn.snd.una = isn

        let synSeg = TCPSegmentToSend(flags: .syn, seq: isn, ack: 0, window: 65535, payload: nil)
        conn.snd.nxt = isn &+ 1

        tcpEntries[key] = NATEntry(connection: conn, isInbound: true)
        tcpFdToKey[newFD] = key
        transport.registerFD(newFD, events: Int16(POLLIN), kind: .stream)

        if let frame = buildTCPFrame(
            hostMAC: hostMAC, dstMAC: vmMAC,
            srcIP: externalIP, dstIP: pf.vmIP,
            srcPort: externalPort, dstPort: pf.vmPort,
            seqNumber: synSeg.seq, ackNumber: synSeg.ack,
            flags: synSeg.flags, window: synSeg.window,
            payload: nil, round: round
        ) {
            replies.append((vmEp, frame))
        }
    }

    // MARK: ── UDP accept / readable ──

    private mutating func pollUDPAccept(
        fd: Int32, data: PacketBuffer, from srcAddr: sockaddr_in,
        hostMAC: MACAddress, arpMapping: ARPMapping,
        replies: inout [(endpointID: Int, packet: PacketBuffer)], round: RoundContext
    ) {
        guard let pf = findUDPListener(fd: fd) else { return }
        let externalIP = IPv4Address(addr: srcAddr.sin_addr.s_addr.bigEndian)
        let externalPort = srcAddr.sin_port.bigEndian
        guard let (vmMAC, vmEp) = lookupVM(ip: pf.vmIP, arpMapping: arpMapping) else { return }

        guard let frame = buildUDPFrame(
            hostMAC: hostMAC, dstMAC: vmMAC,
            srcIP: externalIP, dstIP: pf.vmIP,
            srcPort: externalPort, dstPort: pf.vmPort,
            payload: data, round: round
        ) else { return }

        replies.append((vmEp, frame))
    }

    private mutating func pollUDPReadable(
        key: NATKey, data: PacketBuffer,
        hostMAC: MACAddress, arpMapping: ARPMapping,
        replies: inout [(endpointID: Int, packet: PacketBuffer)], round: RoundContext
    ) {
        guard var mapping = udpEntries[key] else { return }
        mapping.lastActivity = currentTime()
        udpEntries[key] = mapping

        guard let (vmMAC, vmEp) = lookupVM(ip: key.vmIP, arpMapping: arpMapping) else { return }
        guard let frame = buildUDPFrame(
            hostMAC: hostMAC, dstMAC: vmMAC,
            srcIP: key.dstIP, dstIP: key.vmIP,
            srcPort: key.dstPort, dstPort: key.vmPort,
            payload: data, round: round
        ) else { return }

        replies.append((vmEp, frame))
    }

    // MARK: ── TCP outbound SYN ──

    private mutating func handleOutboundSYN(
        key: NATKey, eth: EthernetFrame, ip: IPv4Header, tcp: TCPHeader,
        endpointID: Int, hostMAC: MACAddress,
        transport: inout PollingTransport,
        replies: inout [(endpointID: Int, packet: PacketBuffer)], round: RoundContext
    ) {
        if tcpEntries.count >= maxTCPConnections {
            if let rstFrame = buildTCPFrame(
                hostMAC: hostMAC, dstMAC: eth.srcMAC,
                srcIP: ip.dstAddr, dstIP: ip.srcAddr,
                srcPort: tcp.dstPort, dstPort: tcp.srcPort,
                seqNumber: 0, ackNumber: tcp.sequenceNumber &+ 1,
                flags: [.rst, .ack], window: 0,
                payload: nil, round: round
            ) {
                replies.append((endpointID, rstFrame))
            }
            return
        }
        debugLog("[NAT-TCP-OUT] outbound SYN to \(key.dstIP):\(key.dstPort) from VM \(key.vmIP):\(key.vmPort)\n")

        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { debugLog("[NAT-TCP-OUT] socket() failed for \(key.dstIP):\(key.dstPort)\n"); return }
        setNonBlocking(fd)
        setNoDelay(fd)

        let connectOK = withSockAddr(ip: key.dstIP, port: key.dstPort) { sa, saLen in
            Darwin.connect(fd, sa, saLen)
        }
        if connectOK < 0 && errno != EINPROGRESS {
            debugLog("[NAT-TCP-OUT] connect() to \(key.dstIP):\(key.dstPort) failed: errno=\(errno)\n")
            close(fd); return
        }
        debugLog("[NAT-TCP-OUT] connect() to \(key.dstIP):\(key.dstPort) OK (fd=\(fd), errno=\(errno))\n")

        var conn = TCPConnection(
            connectionID: nextID(), posixFD: fd, state: .listen,
            vmMAC: eth.srcMAC, vmIP: key.vmIP, vmPort: key.vmPort,
            dstIP: key.dstIP, dstPort: key.dstPort, endpointID: endpointID
        )
        conn.externalConnecting = true

        let (newState, toSend, _) = tcpProcess(
            state: .listen, segment: tcp, snd: &conn.snd, rcv: &conn.rcv, appClose: false
        )
        conn.state = newState
        debugLog("[NAT-TCP-OUT] TCP FSM: .listen → \(newState), isn=\(conn.snd.nxt)\n")

        var entry = NATEntry(connection: conn, isInbound: false)
        entry.lastActivity = currentTime()
        tcpEntries[key] = entry
        tcpFdToKey[fd] = key
        transport.registerFD(fd, events: Int16(POLLIN | POLLOUT), kind: .stream)

        for seg in toSend {
            if let frame = buildTCPFrame(
                hostMAC: hostMAC, dstMAC: eth.srcMAC,
                srcIP: ip.dstAddr, dstIP: ip.srcAddr,
                srcPort: tcp.dstPort, dstPort: tcp.srcPort,
                seqNumber: seg.seq, ackNumber: seg.ack,
                flags: seg.flags, window: seg.window,
                payload: nil, round: round
            ) {
                replies.append((endpointID, frame))
            }
        }
    }

    // MARK: ── TCP external FIN ──

    private mutating func handleTCPExternalFIN(
        key: NATKey, hostMAC: MACAddress, transport: inout PollingTransport,
        replies: inout [(endpointID: Int, packet: PacketBuffer)], round: RoundContext
    ) {
        guard var entry = tcpEntries[key] else { return }
        var conn = entry.connection

        var needsCleanup = false
        var cleanupFD: Int32 = 0

        // Flush sendQueue before sending FIN to VM
        let mss = 1400
        while conn.totalQueuedBytes > 0 {
            let inFlight = conn.snd.nxt &- conn.snd.una
            var canSend = Int(conn.snd.wnd) - Int(inFlight)
            if canSend <= 0 { break }
            if canSend > mss { canSend = mss }
            guard let data = conn.peekSendData(max: canSend) else { break }
            if let frame = buildTCPFrame(
                hostMAC: hostMAC, dstMAC: conn.vmMAC,
                srcIP: conn.dstIP, dstIP: conn.vmIP,
                srcPort: conn.dstPort, dstPort: conn.vmPort,
                seqNumber: conn.snd.nxt, ackNumber: conn.rcv.nxt,
                flags: [.ack, .psh], window: 65535,
                payload: data, round: round
            ) {
                replies.append((conn.endpointID, frame))
                conn.snd.nxt = conn.snd.nxt &+ UInt32(data.totalLength)
                conn.sendQueueSent += data.totalLength
            } else {
                break
            }
        }

        let emptyPkt = round.allocate(capacity: 0, headroom: 0)
        let dummy = TCPHeader.syntheticAck(
            ackNumber: conn.snd.una,
            sequenceNumber: conn.rcv.nxt,
            pseudoSrcAddr: conn.dstIP,
            pseudoDstAddr: conn.vmIP,
            payload: emptyPkt
        )
        let (newState, toSend, _) = tcpProcess(
            state: conn.state, segment: dummy, snd: &conn.snd, rcv: &conn.rcv, appClose: true
        )
        conn.state = newState

        for seg in toSend {
            if let frame = buildTCPFrame(
                hostMAC: hostMAC, dstMAC: conn.vmMAC,
                srcIP: conn.dstIP, dstIP: conn.vmIP,
                srcPort: conn.dstPort, dstPort: conn.vmPort,
                seqNumber: seg.seq, ackNumber: seg.ack,
                flags: seg.flags, window: seg.window,
                payload: nil, round: round
            ) {
                replies.append((conn.endpointID, frame))
            }
        }

        if newState == .closed {
            needsCleanup = true
            cleanupFD = conn.posixFD
        }

        entry.connection = conn
        tcpEntries[key] = entry

        if needsCleanup {
            cleanupTCP(fd: cleanupFD, key: key, transport: &transport)
        }
    }

    // MARK: ── Helpers ──

    private mutating func withTCPConnection(
        _ key: NATKey,
        _ body: (inout TCPConnection) -> Void
    ) {
        guard var entry = tcpEntries[key] else { return }
        body(&entry.connection)
        tcpEntries[key] = entry
    }

    private func lookupVM(ip: IPv4Address, arpMapping: ARPMapping) -> (MACAddress, Int)? {
        guard let mac = arpMapping.lookup(ip: ip),
              let ep = arpMapping.lookupEndpoint(mac: mac) else { return nil }
        return (mac, ep)
    }

    private func sendUDP(fd: Int32, data: PacketBuffer, dstIP: IPv4Address, dstPort: UInt16, transport: inout PollingTransport) {
        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = dstPort.bigEndian
        withUnsafeMutableBytes(of: &addr.sin_addr) { dstIP.write(to: $0.baseAddress!) }
        transport.writeDatagram(data, to: fd, addr: addr)
    }

    private mutating func cleanupTCP(fd: Int32, key: NATKey, transport: inout PollingTransport) {
        transport.unregisterFD(fd)
        close(fd)
        tcpFdToKey.removeValue(forKey: fd)
        tcpEntries.removeValue(forKey: key)
        dirtyConnections.remove(key)
    }

    private mutating func cleanupUDP(fd: Int32, key: NATKey, transport: inout PollingTransport) {
        transport.unregisterFD(fd)
        close(fd)
        udpFdToKey.removeValue(forKey: fd)
        udpEntries.removeValue(forKey: key)
    }

    private mutating func cleanupExpiredUDP(transport: inout PollingTransport) {
        let now = currentTime()
        let timeout: UInt64 = 30
        for (key, mapping) in udpEntries where now - mapping.lastActivity > timeout {
            cleanupUDP(fd: mapping.fd, key: key, transport: &transport)
        }
    }

    private mutating func cleanupExpiredTCP(transport: inout PollingTransport) {
        let now = currentTime()
        // Idle timeout: 5 minutes for established, 2 minutes for half-open/closed states.
        for (key, entry) in tcpEntries {
            let age = now - entry.lastActivity
            let tooOld: Bool
            let reason: String
            switch entry.connection.state {
            case .established:
                tooOld = age > 300
                reason = "established idle timeout"
            case .finWait1, .finWait2, .closeWait, .lastAck:
                tooOld = age > 120
                reason = "half-closed idle timeout"
            case .synReceived, .listen, .closed:
                tooOld = age > 60
                reason = "handshake idle timeout"
            }
            if tooOld {
            #if DEBUG
                debugSnapshotEntry(key: key, entry: entry, reason: reason)
            #endif
                cleanupTCP(fd: entry.connection.posixFD, key: key, transport: &transport)
            }
        }
    }

    private func findTCPListener(fd: Int32) -> PortForwardEntry? {
        tcpListeners.first(where: { $0.fd == fd })?.entry
    }

    private func findUDPListener(fd: Int32) -> PortForwardEntry? {
        udpListeners.first(where: { $0.fd == fd })?.entry
    }

    private mutating func nextID() -> UInt64 { _nextID += 1; return _nextID }
    private func currentTime() -> UInt64 { UInt64(Darwin.time(nil)) }
    private func debugLog(_ msg: @autoclosure () -> String) {
    #if DEBUG
    fputs("[R\(debugRound)] \(msg())", stderr)
    #endif
    }

#if DEBUG
    /// Dump one connection's full state to stderr.  Called before idle-timeout
    /// cleanup so there's a post-mortem record of what got pruned and why.
    private func debugSnapshotEntry(key: NATKey, entry: NATEntry, reason: String) {
        let c = entry.connection
        let age = currentTime() - entry.lastActivity
        fputs("""
            [R\(debugRound)] [NAT-TCP-TIMEOUT] \(reason) age=\(age)s
            [R\(debugRound)]   C\(c.connectionID) \(key.vmIP):\(key.vmPort)→\(key.dstIP):\(key.dstPort)
            [R\(debugRound)]   state=\(c.state)  snd.nxt=\(c.snd.nxt) snd.una=\(c.snd.una) snd.wnd=\(c.snd.wnd)
            [R\(debugRound)]   rcv.nxt=\(c.rcv.nxt)  rcv.initialSeq=\(c.rcv.initialSeq)
            [R\(debugRound)]   sendQueue: queued=\(c.totalQueuedBytes) sent=\(c.sendQueueSent) blocked=\(c.sendQueueBlocked)
            [R\(debugRound)]   extSendQueue: queued=\(c.externalSendQueued)  pendingFin=\(c.pendingExternalFin)
            [R\(debugRound)]   extEOF=\(c.externalEOF) extConnecting=\(c.externalConnecting)
            [R\(debugRound)]   fd=\(c.posixFD) endpoint=\(c.endpointID) inbound=\(entry.isInbound)
            [R\(debugRound)]   createdAt=\(entry.createdAt) lastActivity=\(entry.lastActivity)
            \n
            """, stderr)
    }
#endif
}

// MARK: - sockaddr helpers

private func withSockAddr<T>(ip: IPv4Address, port: UInt16, _ body: (UnsafePointer<sockaddr>, socklen_t) -> T) -> T {
    var addr = sockaddr_in()
    addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
    addr.sin_family = sa_family_t(AF_INET)
    addr.sin_port = port.bigEndian
    withUnsafeMutableBytes(of: &addr.sin_addr) { ip.write(to: $0.baseAddress!) }
    return withUnsafePointer(to: &addr) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { body($0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
}

// MARK: - Listener creation

private func createTCPListener(port: UInt16) -> Int32? {
    let fd = socket(AF_INET, SOCK_STREAM, 0)
    guard fd >= 0 else { return nil }
    var reuse: Int32 = 1
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, socklen_t(MemoryLayout<Int32>.size))
    return bindAndListen(fd: fd, port: port)
}

private func createUDPListener(port: UInt16) -> Int32? {
    let fd = socket(AF_INET, SOCK_DGRAM, 0)
    guard fd >= 0 else { return nil }
    var reuse: Int32 = 1
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, socklen_t(MemoryLayout<Int32>.size))
    return bindOnly(fd: fd, port: port)
}

private func bindAndListen(fd: Int32, port: UInt16) -> Int32? {
    var addr = sockaddr_in()
    addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
    addr.sin_family = sa_family_t(AF_INET)
    addr.sin_port = port.bigEndian
    addr.sin_addr.s_addr = INADDR_ANY

    let b = withUnsafePointer(to: &addr) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
    guard b >= 0 else { close(fd); return nil }
    guard Darwin.listen(fd, 16) >= 0 else { close(fd); return nil }
    setNonBlocking(fd)
    return fd
}

private func bindOnly(fd: Int32, port: UInt16) -> Int32? {
    var addr = sockaddr_in()
    addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
    addr.sin_family = sa_family_t(AF_INET)
    addr.sin_port = port.bigEndian
    addr.sin_addr.s_addr = INADDR_ANY

    let b = withUnsafePointer(to: &addr) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
    guard b >= 0 else { close(fd); return nil }
    setNonBlocking(fd)
    return fd
}

private func setNoDelay(_ fd: Int32) {
    var nodelay: Int32 = 1
    _ = setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &nodelay, socklen_t(MemoryLayout<Int32>.size))
}
