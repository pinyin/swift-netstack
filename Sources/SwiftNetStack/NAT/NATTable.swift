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
    // Connection limits
    private let maxTCPConnections: Int = 256
    private let maxUDPMappings: Int = 256

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

    // MARK: - Phase 10: TCP processing (VM → external)

    public mutating func processTCP(
        eth: EthernetFrame,
        ip: IPv4Header,
        tcp: TCPHeader,
        endpointID: Int,
        hostMAC: MACAddress,
        transport: inout PollingTransport,
        replies: inout [(endpointID: Int, packet: PacketBuffer)],
        round: RoundContext
    ) {
        let key = NATKey(vmIP: ip.srcAddr, vmPort: tcp.srcPort, dstIP: ip.dstAddr, dstPort: tcp.dstPort, protocol: .tcp)

        if tcp.flags.isSyn, !tcp.flags.isAck {
            handleOutboundSYN(
                key: key, eth: eth, ip: ip, tcp: tcp, endpointID: endpointID,
                hostMAC: hostMAC, transport: &transport,
                replies: &replies, round: round
            )
            return
        }

        if tcp.flags.isRst {
            if let entry = tcpEntries[key] {
                cleanupTCP(fd: entry.connection.posixFD, key: key, transport: &transport)
            }
            return
        }

        guard var entry = tcpEntries[key] else { return }

        var conn = entry.connection

        // If we're waiting for the external connect() to complete, don't
        // process the VM's ACK yet — return without responding so the VM
        // retransmits.  Once the external handshake finishes, the retransmitted
        // ACK will be processed and data forwarding can begin.
        //
        // Use getpeername() rather than getsockopt(SO_ERROR): on macOS, SO_ERROR
        // returns 0 (no error) even while connect() is still in progress, which
        // would cause us to prematurely transition to established and silently
        // lose data written to a not-yet-connected socket (ENOTCONN).
        if conn.state == .synReceived {
            var addr = sockaddr_in()
            var addrLen = socklen_t(MemoryLayout<sockaddr_in>.size)
            let result = withUnsafeMutablePointer(to: &addr) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    getpeername(conn.posixFD, $0, &addrLen)
                }
            }
            if result < 0 {
                return
            }
        }

        let oldState = conn.state
        let oldUna = conn.snd.una
        let (newState, toSend, dataToExternal) = tcpProcess(
            state: conn.state,
            segment: tcp,
            snd: &conn.snd,
            rcv: &conn.rcv,
            appClose: false
        )
        conn.state = newState
        // Drain acknowledged data from sendBuf after FSM advanced snd.una
        let unaDelta = Int(conn.snd.una &- oldUna)
        if unaDelta > 0 {
            conn.ackSendBuf(delta: unaDelta)
        }
        if oldState != newState {
            debugLog("[NAT-TCP-PROC] state \(oldState) → \(newState) for \(key.dstIP):\(key.dstPort), flags=\(tcp.flags.rawValue)\n")
        }
        if let d = dataToExternal, !d.isEmpty {
            debugLog("[NAT-TCP-PROC] sending \(d.count)B to external \(key.dstIP):\(key.dstPort)\n")
        }

        if let data = dataToExternal, !data.isEmpty {
            var pkt = round.allocate(capacity: data.count, headroom: 0)
            if let ptr = pkt.appendPointer(count: data.count) {
                data.withUnsafeBufferPointer { ptr.copyMemory(from: $0.baseAddress!, byteCount: data.count) }
                transport.writeStream(pkt, to: conn.posixFD)
            }
        }

        // Do not forward the VM's FIN to the external server via shutdown(SHUT_WR)
        // immediately.  Instead, buffer it explicitly: wait for either (a) the
        // external server to respond with data, or (b) a timeout of maxFinWaitRounds.
        // This models gvproxy's behavior where gVisor's internal TCP stack buffers
        // the VM's data+FIN while the external connect() completes, creating a
        // natural delay between data delivery and FIN.
        if newState == .closeWait {
            conn.finWaitRounds = 1
            conn.externalResponded = false
        }
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
            }
        }

        entry.connection = conn
        tcpEntries[key] = entry

        if newState == .closed {
            cleanupTCP(fd: conn.posixFD, key: key, transport: &transport)
        }
    }

    // MARK: - Phase 11: Poll + process external I/O

    /// Poll all managed sockets and immediately build VM reply frames.
    /// Single unified phase — no intermediate queues.
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

    /// Consume data read by Transport and build VM reply frames.
    /// Transport has already performed all I/O — this method does pure
    /// protocol processing and uses Transport for writes.
    public mutating func processTransportResult(
        _ result: TransportResult,
        transport: inout PollingTransport,
        hostMAC: MACAddress,
        arpMapping: ARPMapping,
        replies: inout [(endpointID: Int, packet: PacketBuffer)],
        round: RoundContext
    ) {
        cleanupExpiredUDP(transport: &transport)

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

        // Stream connects completed
        for fd in result.streamConnects {
            pollTCPWritable(fd: fd, transport: &transport)
        }

        // Stream accepts → new inbound connections
        for (listenerFD, newFD, remoteAddr) in result.streamAccepts {
            pollTCPAccept(listenerFd: listenerFD, newFD: newFD, clientAddr: remoteAddr,
                          hostMAC: hostMAC, arpMapping: arpMapping,
                          transport: &transport, replies: &replies, round: round)
        }

        // Stream reads → TCP data from external
        for (fd, data) in result.streamReads {
            if let key = tcpFdToKey[fd] {
                pollTCPReadable(key: key, data: data, hostMAC: hostMAC,
                                replies: &replies, round: round)
            }
        }

        // Stream hangup → TCP half-close (or connect failure)
        for fd in result.streamHangup {
            if let key = tcpFdToKey[fd] {
                handleStreamHangup(key: key, hostMAC: hostMAC,
                                   transport: &transport,
                                   replies: &replies, round: round)
            } else if tcpListeners.contains(where: { $0.fd == fd }) {
                close(fd); tcpListeners.removeAll { $0.fd == fd }
            }
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

    // MARK: ── Poll handlers (I/O + frame building) ──

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

    private mutating func pollTCPWritable(fd: Int32, transport: inout PollingTransport) {
        guard let key = tcpFdToKey[fd], let entry = tcpEntries[key] else { return }
        let st = entry.connection.state
        guard st == .listen || st == .synReceived else { return }

        var addr = sockaddr_in()
        var addrLen = socklen_t(MemoryLayout<sockaddr_in>.size)
        let result = withUnsafeMutablePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                getpeername(fd, $0, &addrLen)
            }
        }
        if result < 0 {
            if errno == ENOTCONN { return }
            debugLog("[NAT-TCP-WR] connect failed for \(key.dstIP):\(key.dstPort): errno=\(errno)")
            cleanupTCP(fd: fd, key: key, transport: &transport)
            return
        }
        if var entry = tcpEntries[key] {
            entry.connection.externalConnecting = false
            tcpEntries[key] = entry
            // Re-register without POLLOUT now that connect is done
            transport.registerFD(fd, events: Int16(POLLIN), kind: .stream)
        }
        if st == .synReceived {
            debugLog("[NAT-TCP-WR] connect completed for \(key.dstIP):\(key.dstPort)")
        }
    }

    private mutating func pollTCPReadable(
        key: NATKey, data: PacketBuffer,
        hostMAC: MACAddress,
        replies: inout [(endpointID: Int, packet: PacketBuffer)], round: RoundContext
    ) {
        guard let entry = tcpEntries[key] else { return }
        let st = entry.connection.state
        guard st == .established || st == .finWait1 || st == .finWait2
            || st == .closeWait || st == .lastAck else { return }
        if entry.connection.externalEOF { return }

        // Write data into sendBuf. A subsequent flushTCPOutgoing phase sends
        // it with proper sequence numbers, window checking, and enables
        // retransmission when the VM doesn't ACK (timer → SND_NXT rollback).
        debugLog("[NAT-TCP-RD] read \(data.totalLength)B external→VM for \(key.dstIP):\(key.dstPort), state=\(st)\n")
        data.withUnsafeReadableBytes { ptr in
            withTCPConnection(key) { conn in
                conn.writeSendBuf(ptr: ptr.baseAddress!, count: data.totalLength)
                conn.externalResponded = true
            }
        }
    }

    // Maximum rounds to wait for external response before forwarding FIN anyway.
    // At ~10ms/round, 30 rounds ≈ 300ms — enough for a typical HTTP round-trip.
    private let maxFinWaitRounds: Int = 30

    // MARK: - Flush TCP sendBuf (external→VM)

    /// Drain sendBuf for all established TCP connections, building frames with
    /// proper sequence/window management and retransmission support.
    /// Also processes buffered FIN forwarding: when the VM has sent FIN
    /// (closeWait state), FIN is forwarded to the external socket only after
    /// the external server has responded with data, or a timeout expires.
    public mutating func flushTCPOutgoing(
        hostMAC: MACAddress,
        replies: inout [(endpointID: Int, packet: PacketBuffer)],
        round: RoundContext
    ) {
        let mss = 1400
        var newEntries: [(NATKey, NATEntry)] = []

        for (key, entry) in tcpEntries {
            var conn = entry.connection
            guard conn.state == .established || conn.state == .closeWait
                  || conn.state == .finWait1 || conn.state == .finWait2
                  || conn.state == .lastAck else { continue }

            var updated = false

            // Flush sendBuf data (external→VM)
            if conn.sendSize > 0 {
                var segCount = 0
                let maxSegs = 64

                while segCount < maxSegs {
                    let inFlight = conn.snd.nxt &- conn.snd.una
                    var canSend = Int(conn.snd.wnd) - Int(inFlight)
                    if canSend <= 0 { break }
                    if canSend > mss { canSend = mss }

                    let data = conn.peekSendData(max: canSend)
                    if data.isEmpty { break }

                    debugLog("[NAT-TCP-FLUSH] flushing \(data.count)B to VM \(conn.vmIP):\(conn.vmPort), state=\(conn.state), sendSize=\(conn.sendSize)\n")

                    let flags: TCPFlags = [.ack, .psh]
                    if let frame = buildTCPFrame(
                        hostMAC: hostMAC, dstMAC: conn.vmMAC,
                        srcIP: conn.dstIP, dstIP: conn.vmIP,
                        srcPort: conn.dstPort, dstPort: conn.vmPort,
                        seqNumber: conn.snd.nxt, ackNumber: conn.rcv.nxt,
                        flags: flags, window: 65535,
                        payload: makePayload(data, round: round), round: round
                    ) {
                        replies.append((conn.endpointID, frame))
                        conn.snd.nxt = conn.snd.nxt &+ UInt32(data.count)
                        segCount += 1
                        updated = true
                    } else {
                        break
                    }
                }
            }

            // Explicit FIN buffering: forward VM's FIN to external when
            // (a) the external server has already sent response data, or
            // (b) maxFinWaitRounds have elapsed with no response.
            if conn.finWaitRounds > 0 {
                if conn.externalResponded {
                    debugLog("[NAT-TCP-FIN] forwarding FIN to \(key.dstIP):\(key.dstPort) (external responded)\n")
                    shutdown(conn.posixFD, SHUT_WR)
                    conn.finWaitRounds = 0
                    updated = true
                } else if conn.finWaitRounds >= maxFinWaitRounds {
                    debugLog("[NAT-TCP-FIN] forwarding FIN to \(key.dstIP):\(key.dstPort) (timeout after \(conn.finWaitRounds) rounds)\n")
                    shutdown(conn.posixFD, SHUT_WR)
                    conn.finWaitRounds = 0
                    updated = true
                } else {
                    conn.finWaitRounds += 1
                    updated = true
                }
            }

            if updated {
                newEntries.append((key, NATEntry(connection: conn, isInbound: entry.isInbound)))
            }
        }

        for (key, entry) in newEntries {
            tcpEntries[key] = entry
        }
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

        tcpEntries[key] = NATEntry(connection: conn, isInbound: false)
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
        var needsCleanup = false
        var cleanupFD: Int32 = 0

        // Flush any remaining sendBuf data BEFORE sending FIN to VM.
        // This ensures correct TCP ordering: data frames arrive at the VM
        // before the FIN, so applications can read all data before seeing EOF.
        withTCPConnection(key) { conn in
            let mss = 1400
            while conn.sendSize > 0 {
                let inFlight = conn.snd.nxt &- conn.snd.una
                var canSend = Int(conn.snd.wnd) - Int(inFlight)
                if canSend <= 0 { break }
                if canSend > mss { canSend = mss }
                let data = conn.peekSendData(max: canSend)
                if data.isEmpty { break }
                if let frame = buildTCPFrame(
                    hostMAC: hostMAC, dstMAC: conn.vmMAC,
                    srcIP: conn.dstIP, dstIP: conn.vmIP,
                    srcPort: conn.dstPort, dstPort: conn.vmPort,
                    seqNumber: conn.snd.nxt, ackNumber: conn.rcv.nxt,
                    flags: [.ack, .psh], window: 65535,
                    payload: makePayload(data, round: round), round: round
                ) {
                    replies.append((conn.endpointID, frame))
                    conn.snd.nxt = conn.snd.nxt &+ UInt32(data.count)
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
                    payload: makePayload(seg.payload, round: round), round: round
                ) {
                    replies.append((conn.endpointID, frame))
                }
            }

            // Only cleanup on closed — lastAck must wait for VM's final ACK
            // so any remaining sendBuf data can be flushed and the connection
            // can complete the closing handshake.
            if newState == .closed {
                needsCleanup = true
                cleanupFD = conn.posixFD
            }
        }

        if needsCleanup {
            cleanupTCP(fd: cleanupFD, key: key, transport: &transport)
        }
    }

    // MARK: ── Stream hangup (external TCP EOF) ──

    private mutating func handleStreamHangup(
        key: NATKey, hostMAC: MACAddress, transport: inout PollingTransport,
        replies: inout [(endpointID: Int, packet: PacketBuffer)], round: RoundContext
    ) {
        guard let entry = tcpEntries[key] else { return }
        let st = entry.connection.state
        // If still connecting, hangup means connect failed
        if st == .listen || st == .synReceived {
            cleanupTCP(fd: entry.connection.posixFD, key: key, transport: &transport)
            return
        }
        // Established or later: peer closed — handle as EOF
        if entry.connection.externalEOF { return }
        debugLog("[NAT-TCP-HUP] external EOF for \(key.dstIP):\(key.dstPort), state=\(st)\n")
        withTCPConnection(key) { conn in
            conn.externalEOF = true
            conn.finWaitRounds = 0
        }
        handleTCPExternalFIN(key: key, hostMAC: hostMAC, transport: &transport, replies: &replies, round: round)
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
    fputs(msg(), stderr)
    #endif
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

private func setNoDelay(_ fd: Int32) {
    var nodelay: Int32 = 1
    _ = setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &nodelay, socklen_t(MemoryLayout<Int32>.size))
}
