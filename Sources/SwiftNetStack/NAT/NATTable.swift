import Darwin

/// NAT connection tracker and TCP/UDP proxy.
///
/// Manages proxied connections with TCP/UDP symmetry:
/// - **processTCP** (Phase 10): VM→external TCP via FSM + POSIX sockets
/// - **processUDP** (Phase 9):  VM→external UDP via per-mapping sockets
/// - **pollSockets** (Phase 11): external→VM for both TCP and UDP
///
/// Each NAT entry (TCP connection or UDP mapping) owns exactly one POSIX fd,
/// making the fd→key reverse lookup trivial and symmetric across protocols.
public struct NATTable {
    // TCP
    private var tcpEntries: [NATKey: NATEntry] = [:]
    private var tcpFdToKey: [Int32: NATKey] = [:]

    // UDP
    private var udpEntries: [NATKey: UDPNATMapping] = [:]
    private var udpFdToKey: [Int32: NATKey] = [:]

    // Listeners (TCP + UDP port forwards)
    private var tcpListeners: [(fd: Int32, entry: PortForwardEntry)] = []
    private var udpListeners: [(fd: Int32, entry: PortForwardEntry)] = []

    // Rate limiting
    private var endpointRateState: [Int: EndpointRateState] = [:]

    private var _nextID: UInt64 = 0

    public init(portForwards: [PortForwardEntry] = []) {
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

    /// TCP port-forward listener ports (for tests to discover OS-assigned ports).
    public var tcpListenerPorts: [UInt16] {
        tcpListeners.compactMap { listener in
            var addr = sockaddr_in()
            var len = socklen_t(MemoryLayout<sockaddr_in>.size)
            let ok = withUnsafeMutablePointer(to: &addr) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    getsockname(listener.fd, $0, &len)
                }
            }
            guard ok >= 0 else { return nil }
            return addr.sin_port.bigEndian
        }
    }

    // MARK: - Phase 9: UDP processing (VM → external)

    /// Process a UDP datagram from a VM. Called when no SocketHandler matches.
    public mutating func processUDP(
        eth: EthernetFrame,
        ip: IPv4Header,
        udp: UDPHeader,
        endpointID: Int,
        hostMAC _: MACAddress,
        replies _: inout [(endpointID: Int, packet: PacketBuffer)],
        round _: RoundContext
    ) {
        let key = NATKey(vmIP: ip.srcAddr, vmPort: udp.srcPort, dstIP: ip.dstAddr, dstPort: udp.dstPort, protocol: .udp)

        if var mapping = udpEntries[key] {
            mapping.lastActivity = currentTime()
            udpEntries[key] = mapping
            sendUDP(fd: mapping.fd, data: udp.payload, dstIP: key.dstIP, dstPort: key.dstPort)
            return
        }

        // New outbound UDP mapping
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
            id: nextID(), key: key, fd: fd,
            vmMAC: eth.srcMAC, endpointID: endpointID,
            isInbound: false
        )
        udpEntries[key] = mapping
        udpFdToKey[fd] = key

        sendUDP(fd: fd, data: udp.payload, dstIP: key.dstIP, dstPort: key.dstPort)
    }

    // MARK: - Phase 10: TCP processing (VM → external)

    /// Process a TCP segment from a VM.
    public mutating func processTCP(
        eth: EthernetFrame,
        ip: IPv4Header,
        tcp: TCPHeader,
        endpointID: Int,
        hostMAC: MACAddress,
        replies: inout [(endpointID: Int, packet: PacketBuffer)],
        round: RoundContext
    ) {
        let key = NATKey(vmIP: ip.srcAddr, vmPort: tcp.srcPort, dstIP: ip.dstAddr, dstPort: tcp.dstPort, protocol: .tcp)

        // New outbound connection (VM SYN without ACK)
        if tcp.flags.isSyn, !tcp.flags.isAck {
            handleOutboundSYN(
                key: key, eth: eth, ip: ip, tcp: tcp, endpointID: endpointID,
                hostMAC: hostMAC, replies: &replies, round: round
            )
            return
        }

        // RST → cleanup
        if tcp.flags.isRst {
            if let entry = tcpEntries[key] {
                cleanupTCP(fd: entry.connection.posixFD, key: key)
            }
            return
        }

        guard var entry = tcpEntries[key] else { return }

        var conn = entry.connection
        let unaBefore = conn.snd.una
        let (newState, toSend, dataToExternal) = tcpProcess(
            state: conn.state,
            segment: tcp,
            snd: &conn.snd,
            rcv: &conn.rcv,
            appClose: false
        )
        conn.state = newState

        // Clean up acknowledged pending segments
        if conn.snd.una != unaBefore {
            cleanupPendingAcks(&conn)
        }

        // Write data to external socket
        if let data = dataToExternal, !data.isEmpty {
            let wn = writeToSocket(fd: conn.posixFD, data: data, conn: &conn)
            if wn < 0 && errno != EAGAIN {
                cleanupTCP(fd: conn.posixFD, key: key)
                return
            }
        }

        // VM initiated close: shutdown external socket write side so the
        // remote peer reads EOF and closes, which triggers cleanup.
        if newState == .closeWait {
            shutdown(conn.posixFD, SHUT_WR)
        }

        // Build reply frames
        for seg in toSend {
            if let frame = buildTCPFrame(
                hostMAC: hostMAC, dstMAC: eth.srcMAC,
                srcIP: ip.dstAddr, dstIP: ip.srcAddr,
                srcPort: tcp.dstPort, dstPort: tcp.srcPort,
                seqNumber: seg.seq, ackNumber: seg.ack,
                flags: seg.flags, window: seg.window,
                payload: makePayload(seg.payload, round: round),
                round: round
            ) {
                replies.append((endpointID, frame))
                if seg.flags.isSyn || seg.flags.isFin || (seg.payload?.count ?? 0) > 0 {
                    conn.retransmitTimer.schedule()
                    conn.pendingSegments.append(seg)
                }
            }
        }

        entry.connection = conn
        tcpEntries[key] = entry

        // Trigger deferred close if external EOF was waiting for pending data
        if conn.externalEOF && conn.pendingSegments.isEmpty {
            conn.externalEOF = false
            entry.connection = conn
            tcpEntries[key] = entry
            handleTCPExternalFIN(key: key, hostMAC: hostMAC, replies: &replies, round: round)
            return
        }

        if newState == .closed {
            cleanupTCP(fd: conn.posixFD, key: key)
        }
    }

    // MARK: - Phase 11: NAT socket poll (external → VM)

    /// Poll all managed sockets for incoming data or state changes.
    public mutating func pollSockets(
        hostMAC: MACAddress,
        arpMapping: ARPMapping,
        replies: inout [(endpointID: Int, packet: PacketBuffer)],
        round: RoundContext
    ) {
        // Collect all fds
        var fds: [Int32] = []
        var kinds: [PollKind] = []

        for (fd, _) in tcpListeners { fds.append(fd); kinds.append(.tcpListener) }
        for (fd, _) in udpListeners { fds.append(fd); kinds.append(.udpListener) }
        for (key, entry) in tcpEntries {
            fds.append(entry.connection.posixFD)
            kinds.append(.tcpSocket(key))
        }
        for (key, mapping) in udpEntries {
            fds.append(mapping.fd)
            kinds.append(.udpSocket(key))
        }

        guard !fds.isEmpty else { return }

        var pollfds: [pollfd] = []
        for i in 0..<fds.count {
            var pfd = pollfd()
            pfd.fd = fds[i]
            pfd.events = Int16(POLLIN)
            switch kinds[i] {
            case .tcpSocket(let key):
                if let entry = tcpEntries[key] {
                    let st = entry.connection.state
                    if st == .listen || st == .synReceived || !entry.connection.writeBuffer.isEmpty {
                        pfd.events |= Int16(POLLOUT)
                    }
                }
            default:
                break
            }
            pfd.revents = 0
            pollfds.append(pfd)
        }

        let ret = Darwin.poll(&pollfds, UInt32(pollfds.count), 0)
        guard ret > 0 else { return }

        for i in 0..<pollfds.count where pollfds[i].revents != 0 {
            let revents = pollfds[i].revents

            // POLLERR / POLLNVAL are hard errors — close immediately.
            if revents & (Int16(POLLERR) | Int16(POLLNVAL)) != 0 {
                switch kinds[i] {
                case .tcpListener: close(fds[i]); tcpListeners.removeAll { $0.fd == fds[i] }
                case .udpListener: close(fds[i]); udpListeners.removeAll { $0.fd == fds[i] }
                case .tcpSocket(let key):
                    handleTCPError(key: key, hostMAC: hostMAC, arpMapping: arpMapping, replies: &replies, round: round)
                case .udpSocket(let key):
                    cleanupUDP(fd: fds[i], key: key)
                }
                continue
            }

            // POLLHUP alone (without POLLIN) means the remote side closed
            // and there is no pending data to read — clean up.
            // When both POLLHUP and POLLIN are set there may still be an EOF
            // (read returns 0) that triggers a FIN toward the VM; fall through
            // to the normal POLLIN path below.
            if revents & Int16(POLLHUP) != 0 && revents & Int16(POLLIN) == 0 {
                switch kinds[i] {
                case .tcpListener: close(fds[i]); tcpListeners.removeAll { $0.fd == fds[i] }
                case .udpListener: close(fds[i]); udpListeners.removeAll { $0.fd == fds[i] }
                case .tcpSocket(let key):
                    handleTCPError(key: key, hostMAC: hostMAC, arpMapping: arpMapping, replies: &replies, round: round)
                case .udpSocket(let key):
                    cleanupUDP(fd: fds[i], key: key)
                }
                continue
            }

            switch kinds[i] {
            case .tcpListener:
                if revents & Int16(POLLIN) != 0 {
                    handleTCPAccept(fd: fds[i], hostMAC: hostMAC, arpMapping: arpMapping, replies: &replies, round: round)
                }
            case .udpListener:
                if revents & Int16(POLLIN) != 0 {
                    handleUDPAccept(fd: fds[i], pf: findUDPListener(fd: fds[i]), hostMAC: hostMAC, arpMapping: arpMapping, replies: &replies, round: round)
                }
            case .tcpSocket(let key):
                if revents & Int16(POLLOUT) != 0 {
                    handleTCPWritable(key: key, hostMAC: hostMAC, arpMapping: arpMapping, replies: &replies, round: round)
                }
                if revents & Int16(POLLIN) != 0 {
                    handleTCPReadable(key: key, hostMAC: hostMAC, arpMapping: arpMapping, replies: &replies, round: round)
                }
            case .udpSocket(let key):
                if revents & Int16(POLLIN) != 0 {
                    handleUDPReadable(key: key, hostMAC: hostMAC, arpMapping: arpMapping, replies: &replies, round: round)
                }
            }
        }

        // TCP retransmit timers
        checkTCPTimers(hostMAC: hostMAC, arpMapping: arpMapping, replies: &replies, round: round)
        // UDP timeout cleanup
        cleanupExpiredUDP(hostMAC: hostMAC, arpMapping: arpMapping, replies: &replies, round: round)
    }

    private enum PollKind {
        case tcpListener
        case udpListener
        case tcpSocket(NATKey)
        case udpSocket(NATKey)
    }

    // MARK: ── TCP outbound SYN ──

    private mutating func handleOutboundSYN(
        key: NATKey, eth: EthernetFrame, ip: IPv4Header, tcp: TCPHeader,
        endpointID: Int, hostMAC: MACAddress,
        replies: inout [(endpointID: Int, packet: PacketBuffer)], round: RoundContext
    ) {
        let now = UInt64(Darwin.time(nil))
        if !checkRateLimit(endpointID: endpointID, now: now) { return }

        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { return }
        setNonBlocking(fd)
        setNoDelay(fd)

        let connectOK = withSockAddr(ip: key.dstIP, port: key.dstPort) { sa, saLen in
            Darwin.connect(fd, sa, saLen)
        }
        if connectOK < 0 && errno != EINPROGRESS { close(fd); return }

        var conn = TCPConnection(
            connectionID: nextID(), posixFD: fd, state: .listen,
            vmMAC: eth.srcMAC, vmIP: key.vmIP, vmPort: key.vmPort,
            dstIP: key.dstIP, dstPort: key.dstPort, endpointID: endpointID
        )

        let (newState, toSend, _) = tcpProcess(
            state: .listen, segment: tcp, snd: &conn.snd, rcv: &conn.rcv, appClose: false
        )
        conn.state = newState

        tcpEntries[key] = NATEntry(connection: conn, isInbound: false)
        tcpFdToKey[fd] = key

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
                tcpEntries[key]?.connection.retransmitTimer.schedule()
                tcpEntries[key]?.connection.pendingSegments.append(seg)
            }
        }
    }

    // MARK: ── TCP accept (inbound) ──

    private mutating func handleTCPAccept(
        fd listenerFd: Int32, hostMAC: MACAddress, arpMapping: ARPMapping,
        replies: inout [(endpointID: Int, packet: PacketBuffer)], round: RoundContext
    ) {
        var clientAddr = sockaddr_in()
        var addrLen = socklen_t(MemoryLayout<sockaddr_in>.size)

        let newFd = withUnsafeMutablePointer(to: &clientAddr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.accept(listenerFd, $0, &addrLen) }
        }
        guard newFd >= 0 else { return }
        setNonBlocking(newFd)
        setNoDelay(newFd)

        guard let pf = findTCPListener(fd: listenerFd) else { close(newFd); return }
        let externalIP = IPv4Address(addr: clientAddr.sin_addr.s_addr.bigEndian)
        let externalPort = clientAddr.sin_port.bigEndian

        let key = NATKey(vmIP: pf.vmIP, vmPort: pf.vmPort, dstIP: externalIP, dstPort: externalPort, protocol: .tcp)

        guard let (vmMAC, vmEp) = lookupVM(ip: pf.vmIP, arpMapping: arpMapping) else { close(newFd); return }

        let now = UInt64(Darwin.time(nil))
        if !checkRateLimit(endpointID: vmEp, now: now) { close(newFd); return }

        let isn = tcpGenerateISN()
        var conn = TCPConnection(
            connectionID: nextID(), posixFD: newFd, state: .synReceived,
            vmMAC: vmMAC, vmIP: pf.vmIP, vmPort: pf.vmPort,
            dstIP: externalIP, dstPort: externalPort, endpointID: vmEp
        )
        conn.snd.nxt = isn
        conn.snd.una = isn

        let synSeg = TCPSegmentToSend(flags: .syn, seq: isn, ack: 0, window: 65535, payload: nil)
        conn.snd.nxt = isn &+ 1

        tcpEntries[key] = NATEntry(connection: conn, isInbound: true)
        tcpFdToKey[newFd] = key

        if let frame = buildTCPFrame(
            hostMAC: hostMAC, dstMAC: vmMAC,
            srcIP: externalIP, dstIP: pf.vmIP,
            srcPort: externalPort, dstPort: pf.vmPort,
            seqNumber: synSeg.seq, ackNumber: synSeg.ack,
            flags: synSeg.flags, window: synSeg.window,
            payload: nil, round: round
        ) {
            replies.append((vmEp, frame))
            tcpEntries[key]?.connection.retransmitTimer.schedule()
            tcpEntries[key]?.connection.pendingSegments.append(synSeg)
        }
    }

    // MARK: ── TCP writable ──

    private mutating func handleTCPWritable(
        key: NATKey, hostMAC: MACAddress, arpMapping: ARPMapping,
        replies: inout [(endpointID: Int, packet: PacketBuffer)], round: RoundContext
    ) {
        guard var entry = tcpEntries[key] else { return }
        let fd = entry.connection.posixFD

        // Check connect result for pending connections
        if entry.connection.state == .listen || entry.connection.state == .synReceived {
            var soError: Int32 = 0
            var soLen = socklen_t(MemoryLayout<Int32>.size)
            getsockopt(fd, SOL_SOCKET, SO_ERROR, &soError, &soLen)
            if soError != 0 {
                handleTCPError(key: key, hostMAC: hostMAC, arpMapping: arpMapping, replies: &replies, round: round)
                return
            }
        }

        // Flush write buffer
        if !entry.connection.writeBuffer.isEmpty {
            let data = entry.connection.writeBuffer
            let n = Darwin.write(fd, data, data.count)
            if n > 0 { entry.connection.writeBuffer.removeFirst(n) }
            else if n < 0 && errno != EAGAIN {
                handleTCPError(key: key, hostMAC: hostMAC, arpMapping: arpMapping, replies: &replies, round: round)
                return
            }
            tcpEntries[key] = entry
        }
    }

    // MARK: ── TCP readable ──

    private mutating func handleTCPReadable(
        key: NATKey, hostMAC: MACAddress, arpMapping: ARPMapping,
        replies: inout [(endpointID: Int, packet: PacketBuffer)], round: RoundContext
    ) {
        guard var entry = tcpEntries[key] else { return }
        var conn = entry.connection
        let st = conn.state
        guard st == .established || st == .finWait1 || st == .finWait2
            || st == .closeWait || st == .lastAck else { return }

        // Once the external side has closed its write half, stop reading.
        // POLLHUP persists across polls and would otherwise cause a tight
        // loop of read→0→externalEOF/handleExternalFIN on every iteration.
        if conn.externalEOF { return }

        var buf = [UInt8](repeating: 0, count: 65536)
        let n = Darwin.read(conn.posixFD, &buf, buf.count)

        if n > 0 {
            let data = Array(buf[0..<n])

            let seg = TCPSegmentToSend(flags: .ack, seq: conn.snd.nxt, ack: conn.rcv.nxt, window: 65535, payload: data)

            if let frame = buildTCPFrame(
                hostMAC: hostMAC, dstMAC: conn.vmMAC,
                srcIP: conn.dstIP, dstIP: conn.vmIP,
                srcPort: conn.dstPort, dstPort: conn.vmPort,
                seqNumber: seg.seq, ackNumber: seg.ack,
                flags: seg.flags, window: seg.window,
                payload: makePayload(data, round: round), round: round
            ) {
                replies.append((conn.endpointID, frame))
                conn.snd.nxt = conn.snd.nxt &+ UInt32(data.count)
                conn.retransmitTimer.schedule()
                conn.pendingSegments.append(seg)
            }

            entry.connection = conn
            tcpEntries[key] = entry
        } else if n == 0 {
            conn.externalEOF = true
            entry.connection = conn
            tcpEntries[key] = entry
            if conn.pendingSegments.isEmpty {
                handleTCPExternalFIN(key: key, hostMAC: hostMAC, replies: &replies, round: round)
            }
        }
    }

    // MARK: ── TCP external FIN ──

    private mutating func handleTCPExternalFIN(
        key: NATKey, hostMAC: MACAddress,
        replies: inout [(endpointID: Int, packet: PacketBuffer)], round: RoundContext
    ) {
        guard var entry = tcpEntries[key] else { return }
        var conn = entry.connection

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
                payload: makePayload(seg.payload, round: round), round: round
            ) {
                replies.append((conn.endpointID, frame))
                conn.retransmitTimer.schedule()
                conn.pendingSegments.append(seg)
            }
        }

        conn.externalEOF = false  // consumed; don't re-fire
        entry.connection = conn
        tcpEntries[key] = entry

        if newState == .closed {
            cleanupTCP(fd: conn.posixFD, key: key)
        }
    }

    // MARK: ── TCP error ──

    private mutating func handleTCPError(
        key: NATKey, hostMAC: MACAddress, arpMapping: ARPMapping,
        replies: inout [(endpointID: Int, packet: PacketBuffer)], round: RoundContext
    ) {
        guard let entry = tcpEntries[key] else { return }
        let conn = entry.connection

        if let frame = buildTCPFrame(
            hostMAC: hostMAC, dstMAC: conn.vmMAC,
            srcIP: conn.dstIP, dstIP: conn.vmIP,
            srcPort: conn.dstPort, dstPort: conn.vmPort,
            seqNumber: conn.snd.nxt, ackNumber: 0,
            flags: [.rst, .ack], window: 0, payload: nil, round: round
        ) {
            replies.append((conn.endpointID, frame))
        }
        cleanupTCP(fd: conn.posixFD, key: key)
    }

    // MARK: ── TCP retransmit timers ──

    private mutating func checkTCPTimers(
        hostMAC: MACAddress, arpMapping: ARPMapping,
        replies: inout [(endpointID: Int, packet: PacketBuffer)], round: RoundContext
    ) {
        var toCleanup: [NATKey] = []

        for (key, var entry) in tcpEntries {
            guard entry.connection.retransmitTimer.isArmed,
                  entry.connection.retransmitTimer.isExpired() else { continue }

            if entry.connection.retransmitTimer.onExpire(),
               let seg = entry.connection.pendingSegments.first {
                if let frame = buildTCPFrame(
                    hostMAC: hostMAC, dstMAC: entry.connection.vmMAC,
                    srcIP: entry.connection.dstIP, dstIP: entry.connection.vmIP,
                    srcPort: entry.connection.dstPort, dstPort: entry.connection.vmPort,
                    seqNumber: seg.seq, ackNumber: seg.ack,
                    flags: seg.flags, window: seg.window,
                    payload: makePayload(seg.payload, round: round), round: round
                ) {
                    replies.append((entry.connection.endpointID, frame))
                }
                tcpEntries[key] = entry
            } else {
                toCleanup.append(key)
            }
        }

        for key in toCleanup {
            if let entry = tcpEntries[key] { cleanupTCP(fd: entry.connection.posixFD, key: key) }
        }
    }

    // MARK: ── UDP readable ──

    private mutating func handleUDPReadable(
        key: NATKey, hostMAC: MACAddress, arpMapping: ARPMapping,
        replies: inout [(endpointID: Int, packet: PacketBuffer)], round: RoundContext
    ) {
        guard var mapping = udpEntries[key] else { return }

        var buf = [UInt8](repeating: 0, count: 65536)
        let n = Darwin.recvfrom(mapping.fd, &buf, buf.count, 0, nil, nil)

        guard n > 0 else { return }
        let data = Array(buf[0..<n])
        mapping.lastActivity = currentTime()
        udpEntries[key] = mapping

        guard let (vmMAC, vmEp) = lookupVM(ip: key.vmIP, arpMapping: arpMapping) else { return }

        guard let frame = buildUDPFrame(
            hostMAC: hostMAC, dstMAC: vmMAC,
            srcIP: key.dstIP, dstIP: key.vmIP,
            srcPort: key.dstPort, dstPort: key.vmPort,
            payload: makePayload(data, round: round)!,
            round: round
        ) else { return }

        replies.append((vmEp, frame))
    }

    // MARK: ── UDP accept (port forwarding) ──

    private mutating func handleUDPAccept(
        fd: Int32, pf: PortForwardEntry?, hostMAC: MACAddress, arpMapping: ARPMapping,
        replies: inout [(endpointID: Int, packet: PacketBuffer)], round: RoundContext
    ) {
        guard let pf = pf else { return }

        var buf = [UInt8](repeating: 0, count: 65536)
        var srcAddr = sockaddr_in()
        var srcLen = socklen_t(MemoryLayout<sockaddr_in>.size)

        let n = withUnsafeMutablePointer(to: &srcAddr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { saPtr in
                Darwin.recvfrom(fd, &buf, buf.count, 0, saPtr, &srcLen)
            }
        }
        guard n > 0 else { return }
        let data = Array(buf[0..<n])

        let externalIP = IPv4Address(addr: srcAddr.sin_addr.s_addr.bigEndian)
        let externalPort = srcAddr.sin_port.bigEndian

        guard let (vmMAC, vmEp) = lookupVM(ip: pf.vmIP, arpMapping: arpMapping) else { return }

        guard let frame = buildUDPFrame(
            hostMAC: hostMAC, dstMAC: vmMAC,
            srcIP: externalIP, dstIP: pf.vmIP,
            srcPort: externalPort, dstPort: pf.vmPort,
            payload: makePayload(data, round: round)!,
            round: round
        ) else { return }

        replies.append((vmEp, frame))
    }

    // MARK: ── UDP timeout cleanup ──

    private mutating func cleanupExpiredUDP(
        hostMAC _: MACAddress, arpMapping _: ARPMapping,
        replies _: inout [(endpointID: Int, packet: PacketBuffer)], round _: RoundContext
    ) {
        let now = currentTime()
        let timeout: UInt64 = 30
        var expired: [(Int32, NATKey)] = []

        for (key, mapping) in udpEntries where now - mapping.lastActivity > timeout {
            expired.append((mapping.fd, key))
        }
        for (fd, key) in expired {
            cleanupUDP(fd: fd, key: key)
        }
    }

    // MARK: ── Helpers ──

    /// Remove acknowledged segments from pendingSegments and cancel or re-arm
    /// the retransmit timer accordingly.
    private mutating func cleanupPendingAcks(_ conn: inout TCPConnection) {
        let una = conn.snd.una
        conn.pendingSegments.removeAll { seg in
            var segLen: UInt32 = UInt32(seg.payload?.count ?? 0)
            if seg.flags.isSyn { segLen = segLen &+ 1 }
            if seg.flags.isFin { segLen = segLen &+ 1 }
            // Acknowledged if seg.seq + segLen <= una (wraparound-safe)
            return !tcpSeqGreaterThan(seg.seq &+ segLen, una)
        }
        if conn.pendingSegments.isEmpty {
            conn.retransmitTimer.cancel()
        }
    }

    private func lookupVM(ip: IPv4Address, arpMapping: ARPMapping) -> (MACAddress, Int)? {
        guard let mac = arpMapping.lookup(ip: ip),
              let ep = arpMapping.lookupEndpoint(mac: mac) else { return nil }
        return (mac, ep)
    }

    private mutating func writeToSocket(fd: Int32, data: [UInt8], conn: inout TCPConnection) -> Int {
        let n = Darwin.write(fd, data, data.count)
        if n >= 0 {
            if n < data.count { conn.writeBuffer.append(contentsOf: data[n...]) }
            return n
        }
        if errno == EAGAIN { conn.writeBuffer.append(contentsOf: data); return 0 }
        return -1
    }

    private func sendUDP(fd: Int32, data: PacketBuffer, dstIP: IPv4Address, dstPort: UInt16) {
        data.withUnsafeReadableBytes { buf in
            withSockAddr(ip: dstIP, port: dstPort) { sa, saLen in
                _ = Darwin.sendto(fd, buf.baseAddress!, buf.count, 0, sa, saLen)
            }
        }
    }

    private mutating func cleanupTCP(fd: Int32, key: NATKey) {
        close(fd)
        tcpFdToKey.removeValue(forKey: fd)
        if let entry = tcpEntries.removeValue(forKey: key) {
            endpointRateState[entry.connection.endpointID]?.release()
        }
    }

    private mutating func cleanupUDP(fd: Int32, key: NATKey) {
        close(fd)
        udpFdToKey.removeValue(forKey: fd)
        udpEntries.removeValue(forKey: key)
    }

    private func findTCPListener(fd: Int32) -> PortForwardEntry? {
        tcpListeners.first(where: { $0.fd == fd })?.entry
    }

    private func findUDPListener(fd: Int32) -> PortForwardEntry? {
        udpListeners.first(where: { $0.fd == fd })?.entry
    }

    private mutating func nextID() -> UInt64 { _nextID += 1; return _nextID }
    private func currentTime() -> UInt64 { UInt64(Darwin.time(nil)) }

    // MARK: - Rate limiting

    private mutating func checkRateLimit(endpointID: Int, now: UInt64) -> Bool {
        var state = endpointRateState[endpointID] ?? EndpointRateState()
        let ok = state.tryAcquire(now: now)
        endpointRateState[endpointID] = state
        return ok
    }
}

// MARK: - Payload construction

private func makePayload(_ data: [UInt8]?, round: RoundContext) -> PacketBuffer? {
    guard let data = data, !data.isEmpty else { return nil }
    var pkt = round.allocate(capacity: data.count, headroom: 0)
    guard let ptr = pkt.appendPointer(count: data.count) else { return nil }
    data.withUnsafeBufferPointer { ptr.copyMemory(from: $0.baseAddress!, byteCount: data.count) }
    return pkt
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

private func setNonBlocking(_ fd: Int32) {
    let flags = fcntl(fd, F_GETFL, 0)
    if flags >= 0 { _ = fcntl(fd, F_SETFL, flags | O_NONBLOCK) }
}

private func setNoDelay(_ fd: Int32) {
    var nodelay: Int32 = 1
    _ = setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &nodelay, socklen_t(MemoryLayout<Int32>.size))
}
