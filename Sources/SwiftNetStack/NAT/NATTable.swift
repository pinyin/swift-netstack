import Darwin

/// Monotonic microseconds clock for timer-based operations.
/// Uses CLOCK_MONOTONIC for sub-millisecond precision without wall-clock jumps.
public func monotonicMicros() -> UInt64 {
    var ts = timespec()
    clock_gettime(CLOCK_MONOTONIC, &ts)
    return UInt64(ts.tv_sec) * 1_000_000 + UInt64(ts.tv_nsec) / 1_000
}

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
    public var externalPcap: PCAPWriter? = nil
    public var stats: NATStats

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
    private let mss: Int

    public init(portForwards: [PortForwardEntry] = [], mss: Int = 1400) {
        self.mss = mss
        self.stats = NATStats()
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
        srcMAC: MACAddress, srcIP: IPv4Address, dstIP: IPv4Address,
        srcPort: UInt16, dstPort: UInt16,
        payloadOfs: Int, payloadLen: Int,
        endpointID: Int,
        hostMAC: MACAddress,
        transport: inout PollingTransport,
        io: IOBuffer,
        nowSec: UInt64
    ) {
        let key = NATKey(vmIP: srcIP, vmPort: srcPort, dstIP: dstIP, dstPort: dstPort, protocol: .udp)

        if var mapping = udpEntries[key] {
            mapping.lastActivity = nowSec
            udpEntries[key] = mapping
            let data = [UInt8](UnsafeRawBufferPointer(start: io.inputBase.advanced(by: payloadOfs), count: payloadLen))
            sendUDP(fd: mapping.fd, data: data, dstIP: key.dstIP, dstPort: key.dstPort, transport: &transport)
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
            vmMAC: srcMAC, endpointID: endpointID,
            isInbound: false
        )
        udpEntries[key] = mapping
        udpFdToKey[fd] = key
        transport.registerFD(fd, events: Int16(POLLIN), kind: .datagram)

        let data = [UInt8](UnsafeRawBufferPointer(start: io.inputBase.advanced(by: payloadOfs), count: payloadLen))
        sendUDP(fd: fd, data: data, dstIP: key.dstIP, dstPort: key.dstPort, transport: &transport)
    }

    // MARK: - Delayed ACK (RFC 1122 timer-based coalescing)

    /// Returns the earliest monotonic-µs deadline among all pending delayed ACKs,
    /// or nil if no delayed ACKs are pending.
    public func nextDelayedACKDeadline() -> UInt64? {
        var earliest: UInt64?
        for entry in tcpEntries.values {
            guard entry.connection.pendingDelayedACK else { continue }
            let dl = entry.connection.delayedACKDeadline
            if earliest == nil || dl < earliest! { earliest = dl }
        }
        return earliest
    }

    /// Build a pure ACK frame into IOBuffer and add to outBatch.
    /// Uses the pre-built template and incremental checksum (RFC 1146) when available.
    /// Writes directly via transport — no outBatch intermediate.
    @discardableResult
    private mutating func buildAckFrame(
        conn: inout TCPConnection, seq: UInt32, ack: UInt32, window: UInt16,
        io: IOBuffer, transport: inout PollingTransport
    ) -> Bool {
        var outCK: UInt16 = 0
        let hdrOfs: Int

        if let tmpl = conn.ackTemplate {
            stats.ackTemplateUsed += 1
            let incCK: UInt16?
            if conn.ackChecksumValid && conn.lastACKWindow == window {
                incCK = computeIncrementalTCPChecksum(
                    oldCK: conn.lastACKChecksum,
                    oldSeq: conn.lastACKSeq, newSeq: seq,
                    oldAck: conn.lastACKAck, newAck: ack
                )
                stats.ackChecksumIncremental += 1
            } else {
                incCK = nil
                stats.ackChecksumFull += 1
            }
            hdrOfs = writeAckFromTemplate(io: io, template: tmpl, seq: seq, ack: ack,
                                          srcIP: conn.dstIP, dstIP: conn.vmIP,
                                          window: window, checksum: incCK, outCK: &outCK)
#if DEBUG
            if incCK != nil, hdrOfs >= 0 {
                let fullCK = computeACKFullChecksum(tmpl: tmpl, seq: seq, ack: ack,
                                                    srcIP: conn.dstIP, dstIP: conn.vmIP)
                assert(outCK == fullCK,
                       "Incremental checksum mismatch: inc=\(outCK) full=\(fullCK) oldCK=\(conn.lastACKChecksum) oldSeq=\(conn.lastACKSeq)→\(seq) oldAck=\(conn.lastACKAck)→\(ack)")
            }
#endif
        } else {
            stats.ackTemplateFallback += 1
            stats.ackChecksumFull += 1
            hdrOfs = buildTCPHeader(io: io, hostMAC: conn.hostMAC, dstMAC: conn.vmMAC,
                srcIP: conn.dstIP, dstIP: conn.vmIP,
                srcPort: conn.dstPort, dstPort: conn.vmPort,
                seqNumber: seq, ackNumber: ack, flags: .ack, window: window)
            if hdrOfs >= 0 {
                finalizeTCPChecksum(io: io, hdrOfs: hdrOfs,
                    srcIP: conn.dstIP, dstIP: conn.vmIP,
                    payloadPtr: nil, payloadLen: 0)
            }
        }

        guard hdrOfs >= 0 else { return false }

        conn.lastACKSeq = seq
        conn.lastACKAck = ack
        conn.lastACKWindow = window
        conn.ackChecksumValid = true
        if conn.ackTemplate != nil {
            conn.lastACKChecksum = outCK
        }

        if let pw = self.externalPcap {
            let hdrPtr = io.output.baseAddress!.advanced(by: hdrOfs)
            pw.writeRaw(framePtr: hdrPtr, len: 54)
        }
        return transport.writeSingleFrame(endpointID: conn.endpointID, io: io,
                                          hdrOfs: hdrOfs, hdrLen: 54,
                                          payPtr: nil, payLen: 0)
    }

    /// Flush expired delayed ACKs for all connections.
    private mutating func flushExpiredDelayedACKs(
        io: IOBuffer, transport: inout PollingTransport, nowUs: UInt64
    ) {
        for (key, var entry) in tcpEntries {
            guard entry.connection.pendingDelayedACK else { continue }
            guard entry.connection.delayedACKDeadline <= nowUs else { continue }
            if buildAckFrame(
                conn: &entry.connection, seq: entry.connection.delayedACKSeq,
                ack: entry.connection.delayedACKAck,
                window: entry.connection.delayedACKWindow,
                io: io, transport: &transport
            ) {
                stats.ackFlushedTimer += 1
            }
            entry.connection.pendingDelayedACK = false
            tcpEntries[key] = entry
        }
    }

    // MARK: - Helper: write a TCP output frame directly (no OutBatch)

    @discardableResult
    private func addTCPOutput(
        hdrOfs: Int, endpointID: Int, io: IOBuffer,
        transport: inout PollingTransport
    ) -> Bool {
        if let pw = self.externalPcap {
            let hdrPtr = io.output.baseAddress!.advanced(by: hdrOfs)
            pw.writeRaw(framePtr: hdrPtr, len: 54)
        }
        return transport.writeSingleFrame(endpointID: endpointID, io: io,
                                          hdrOfs: hdrOfs, hdrLen: 54,
                                          payPtr: nil, payLen: 0)
    }

    @discardableResult
    private func addTCPOutput(
        hdrOfs: Int, endpointID: Int, payPtr: UnsafeRawPointer, payLen: Int,
        io: IOBuffer, transport: inout PollingTransport
    ) -> Bool {
        if let pw = self.externalPcap {
            let hdrPtr = io.output.baseAddress!.advanced(by: hdrOfs)
            pw.writeRawSplit(hdr: hdrPtr, hdrLen: 54,
                             pay: UnsafeMutableRawPointer(mutating: payPtr), payLen: payLen)
        }
        return transport.writeSingleFrame(endpointID: endpointID, io: io,
                                          hdrOfs: hdrOfs, hdrLen: 54,
                                          payPtr: payPtr, payLen: payLen)
    }

    // MARK: - Phase 11: Unified TCP processing (VM ↔ external)

    /// Unified TCP processing — all VM↔external work in one method.
    public mutating func processTCPRound(
        out: ParseOutput,
        io: IOBuffer,
        streamReads: [(fd: Int32, data: [UInt8])],
        streamHangup: [Int32],
        streamConnects: [Int32],
        transport: inout PollingTransport,
        hostMAC: MACAddress,
        arpMapping: ARPMapping,
        nowSec: UInt64,
        nowUs: UInt64
    ) {
#if DEBUG
        // debug round tracking; caller can update via debugRound if desired
#endif

        // ── Step 0: Flush expired delayed ACKs ──
        let tAckFlush = cpuNanos()
        flushExpiredDelayedACKs(io: io, transport: &transport, nowUs: nowUs)
        stats.tcpAckFlushNs &+= cpuNanos() - tAckFlush

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

        // ── Step 1.5: Handle POLLOUT for established connections with queued VM→external data ──
        for fd in streamConnects {
            guard let key = tcpFdToKey[fd], let entry = tcpEntries[key] else { continue }
            let st = entry.connection.state
            guard st == .established || st == .closeWait || st == .finWait1
                  || st == .finWait2 || st == .lastAck else { continue }
            if entry.connection.externalSendQueued > 0 {
                dirtyConnections.insert(key)
            }
            if entry.connection.externalSendQueued == 0 {
                transport.setFDEvents(fd, events: Int16(POLLIN))
            }
        }

        // ── Step 2: Process VM→external segments ──
        let tFSM = cpuNanos()
        for i in 0..<out.tcpCount {
            let key = out.tcpKeys[i]
            let seg = out.tcpSegs[i]
            let ep = out.tcpEndpointIDs[i]
            let srcMAC = out.tcpSrcMACs[i]
            let payloadPtr: UnsafeRawPointer? = out.tcpPayloadLen[i] > 0
                ? UnsafeRawPointer(io.inputBase.advanced(by: out.tcpPayloadOfs[i])) : nil
            let payloadLen = out.tcpPayloadLen[i]

            // New outbound connection
            if seg.flags.isSyn, !seg.flags.isAck {
                handleOutboundSYN(
                    key: key, srcMAC: srcMAC, seg: seg,
                    payloadPtr: payloadPtr, payloadLen: payloadLen,
                    endpointID: ep,
                    hostMAC: hostMAC, transport: &transport,
                    io: io
                )
                dirtyConnections.insert(key)
                continue
            }

            // RST → cleanup
            if seg.flags.isRst {
                if let entry = tcpEntries[key] {
                    cleanupTCP(fd: entry.connection.posixFD, key: key, transport: &transport)
                }
                continue
            }

            guard var entry = tcpEntries[key] else { continue }
            entry.lastActivity = nowSec

            // Check external connect completion (synReceived state)
            if entry.connection.state == .synReceived {
                var addr = sockaddr_in()
                var addrLen = socklen_t(MemoryLayout<sockaddr_in>.size)
                let result = withUnsafeMutablePointer(to: &addr) {
                    $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                        getpeername(entry.connection.posixFD, $0, &addrLen)
                    }
                }
                if result < 0 { continue }
                if entry.connection.externalConnecting {
                    entry.connection.externalConnecting = false
                    transport.registerFD(entry.connection.posixFD, events: Int16(POLLIN), kind: .stream)
                }
            }

            let oldState = entry.connection.state
            let oldUna = entry.connection.snd.una
            let (newState, toSend, dataPtr, dataLen) = tcpProcess(
                state: entry.connection.state, seg: seg,
                payloadPtr: payloadPtr, payloadLen: payloadLen,
                snd: &entry.connection.snd, rcv: &entry.connection.rcv, appClose: false
            )
            entry.connection.state = newState
            if newState == .established && entry.connection.ackTemplate == nil {
                entry.connection.ackTemplate = makeAckTemplate(
                    hostMAC: entry.connection.hostMAC, vmMAC: entry.connection.vmMAC,
                    srcIP: entry.connection.dstIP, dstIP: entry.connection.vmIP,
                    srcPort: entry.connection.dstPort, dstPort: entry.connection.vmPort, window: 65535
                )
            }
            let unaDelta = Int(entry.connection.snd.una &- oldUna)
            if unaDelta > 0 { entry.connection.ackSendBuf(delta: unaDelta) }
            // Resume external reads if backpressure cleared
            if entry.connection.sendQueueBlocked, entry.connection.totalQueuedBytes < TCPConnection.maxQueueBytes / 2 {
                entry.connection.sendQueueBlocked = false
                transport.setFDEvents(entry.connection.posixFD, events: Int16(POLLIN))
            }
            if oldState != newState {
                debugLog("[NAT-TCP-PROC] state \(oldState) → \(newState) for \(key.dstIP):\(key.dstPort), flags=\(seg.flags.rawValue)\n")
            } else if toSend.isEmpty && dataLen == 0 {
                debugLog("[NAT-TCP-REJ] C\(entry.connection.connectionID) \(oldState) \(key.dstIP):\(key.dstPort) "
                    + "seq=\(seg.seq) ack=\(seg.ack) "
                    + "flags=0x\(String(seg.flags.rawValue, radix: 16)) "
                    + "wnd=\(seg.window) dataLen=\(payloadLen) "
                    + "rcv.nxt=\(entry.connection.rcv.nxt) snd.nxt=\(entry.connection.snd.nxt) snd.una=\(entry.connection.snd.una)\n")
            }
            if dataLen > 0, let ptr = dataPtr {
                debugLog("[NAT-TCP-PROC] buffering \(dataLen)B for external \(key.dstIP):\(key.dstPort)\n")
                entry.connection.appendExternalSend(ptr, dataLen)
            }

            if newState == .closeWait {
                entry.connection.pendingExternalFin = true
            }

            for segToSend in toSend {
                let isPureACK = segToSend.flags == .ack
                if isPureACK {
                    if entry.connection.pendingDelayedACK {
                        _ = buildAckFrame(
                            conn: &entry.connection, seq: entry.connection.delayedACKSeq,
                            ack: entry.connection.delayedACKAck,
                            window: entry.connection.delayedACKWindow,
                            io: io, transport: &transport
                        )
                        stats.ackFlushedImmediate += 1
                    }
                    stats.ackDeferred += 1
                    entry.connection.pendingDelayedACK = true
                    entry.connection.delayedACKDeadline = nowUs + 200
                    entry.connection.delayedACKSeq = segToSend.seq
                    entry.connection.delayedACKAck = segToSend.ack
                    entry.connection.delayedACKWindow = segToSend.window
                } else {
                    // Non-ACK segment — flush any pending delayed ACK first
                    if entry.connection.pendingDelayedACK {
                        _ = buildAckFrame(
                            conn: &entry.connection, seq: entry.connection.delayedACKSeq,
                            ack: entry.connection.delayedACKAck,
                            window: entry.connection.delayedACKWindow,
                            io: io, transport: &transport
                        )
                        stats.ackFlushedImmediate += 1
                        entry.connection.pendingDelayedACK = false
                    }
                    let hdrOfs = buildTCPHeader(
                        io: io, hostMAC: hostMAC, dstMAC: srcMAC,
                        srcIP: key.dstIP, dstIP: key.vmIP,
                        srcPort: key.dstPort, dstPort: key.vmPort,
                        seqNumber: segToSend.seq, ackNumber: segToSend.ack,
                        flags: segToSend.flags, window: segToSend.window)
                    if hdrOfs >= 0 {
                        finalizeTCPChecksum(io: io, hdrOfs: hdrOfs,
                            srcIP: key.dstIP, dstIP: key.vmIP,
                            payloadPtr: nil, payloadLen: 0)
                        _ = addTCPOutput(hdrOfs: hdrOfs, endpointID: ep, io: io, transport: &transport)
                    }
                }
            }

            tcpEntries[key] = entry
            dirtyConnections.insert(key)

            if newState == .closed {
                cleanupTCP(fd: entry.connection.posixFD, key: key, transport: &transport)
            }
        }

        stats.tcpFsmNs &+= cpuNanos() - tFSM

        // ── Step 3: Process external→VM reads ──
        let tExtR = cpuNanos()
        if !streamReads.isEmpty {
            debugLog("[NAT-TCP-RD-RAW] streamReads count=\(streamReads.count), fds=\(streamReads.map { $0.fd }), tcpFdToKey=\(tcpFdToKey.keys.sorted())\n")
        }
        for (fd, data) in streamReads {
            debugLog("[NAT-TCP-RD-CHK] fd=\(fd) data=\(data.count)B inTcpFdToKey=\(tcpFdToKey[fd] != nil)\n")
            guard let key = tcpFdToKey[fd], var entry = tcpEntries[key] else { continue }
            let st = entry.connection.state
            guard st == .synReceived || st == .established || st == .finWait1 || st == .finWait2
                || st == .closeWait || st == .lastAck else { continue }
            if entry.connection.externalEOF { continue }

            debugLog("[NAT-TCP-RD] read \(data.count)B external→VM for \(key.dstIP):\(key.dstPort), state=\(st)\n")
            entry.lastActivity = nowSec
            let queued = data.withUnsafeBytes { buf in
                entry.connection.writeSendBuf(buf.baseAddress!, data.count)
            }
            if queued == 0, !entry.connection.sendQueueBlocked {
                entry.connection.sendQueueBlocked = true
                transport.setFDEvents(fd, events: 0)  // pause reads until queue drains
            }
            if let pw = self.externalPcap, queued > 0 {
                captureExternalPacket(pcap: pw, fd: fd, direction: .fromExternal,
                    conn: entry.connection, flags: [.ack, .psh], payload: data,
                    hostMAC: hostMAC)
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
                    entry.lastActivity = nowSec
                    entry.connection.externalEOF = true
                    entry.connection.pendingExternalFin = false
                    tcpEntries[key] = entry
                    dirtyConnections.insert(key)
                    handleTCPExternalFIN(key: key, hostMAC: hostMAC, transport: &transport,
                                         io: io)
                    continue
                }
                cleanupTCP(fd: entry.connection.posixFD, key: key, transport: &transport)
                continue
            }
            if entry.connection.externalEOF { continue }
            debugLog("[NAT-TCP-HUP] external EOF for \(key.dstIP):\(key.dstPort), state=\(st)\n")
            entry.lastActivity = nowSec
            entry.connection.externalEOF = true
            entry.connection.pendingExternalFin = false
            tcpEntries[key] = entry
            dirtyConnections.insert(key)
            handleTCPExternalFIN(key: key, hostMAC: hostMAC, transport: &transport,
                                 io: io)
        }

        stats.tcpExtReadNs &+= cpuNanos() - tExtR

        // ── Step 5: Flush dirty connections (drain queues, forward FIN) ──
        let tFlush = cpuNanos()
        for key in dirtyConnections {
            guard var entry = tcpEntries[key] else { continue }
            guard entry.connection.state == .established || entry.connection.state == .closeWait
                  || entry.connection.state == .finWait1 || entry.connection.state == .finWait2
                  || entry.connection.state == .lastAck else { continue }

            flushOneConnection(key: key, conn: &entry.connection, hostMAC: hostMAC,
                               transport: &transport, io: io)
            tcpEntries[key] = entry
        }
        stats.tcpFlushNs &+= cpuNanos() - tFlush
        dirtyConnections.removeAll(keepingCapacity: true)
    }

    // MARK: - Per-connection flush (send queues + FIN forwarding)

    private mutating func flushOneConnection(
        key: NATKey, conn: inout TCPConnection,
        hostMAC: MACAddress,
        transport: inout PollingTransport,
        io: IOBuffer
    ) {
        let sqBufBase = conn.sendQueue.buf.baseAddress!

        // ── Drain sendQueue (external→VM) with inline writes ──
        // Each frame is sent immediately via sendmsg. TCP state (snd.nxt,
        // sendQueueSent) advances only on successful delivery. On EAGAIN/
        // ENOBUFS we break without advancing — the data stays in the send
        // queue and peekSendData returns it again next round. This uses
        // TCP's own sequence-number state machine to drive retry, avoiding
        // external bookkeeping.
        if conn.totalQueuedBytes > 0 {
            guard let epFD = transport.fdForEndpoint(conn.endpointID) else { return }
            var segCount = 0
            let maxSegs = 64
            while segCount < maxSegs {
                let inFlight = conn.snd.nxt &- conn.snd.una
                var canSend = Int(conn.snd.wnd) - Int(inFlight)
                if canSend <= 0 { break }
                if canSend > mss { canSend = mss }
                guard let data = conn.peekSendData(max: canSend) else { break }
                debugLog("[NAT-TCP-FLUSH] flushing \(data.len)B to VM \(conn.vmIP):\(conn.vmPort), state=\(conn.state), queued=\(conn.totalQueuedBytes)\n")
                let hdrOfs = buildTCPHeader(
                    io: io, hostMAC: hostMAC, dstMAC: conn.vmMAC,
                    srcIP: conn.dstIP, dstIP: conn.vmIP,
                    srcPort: conn.dstPort, dstPort: conn.vmPort,
                    seqNumber: conn.snd.nxt, ackNumber: conn.rcv.nxt,
                    flags: [.ack, .psh], window: 65535)
                guard hdrOfs >= 0 else { break }
                finalizeTCPChecksum(io: io, hdrOfs: hdrOfs,
                    srcIP: conn.dstIP, dstIP: conn.vmIP,
                    payloadPtr: data.ptr, payloadLen: data.len)

                // Inline write — only advance state on success
                let hdrPtr = io.output.baseAddress!.advanced(by: hdrOfs)
                var iov0 = iovec(iov_base: UnsafeMutableRawPointer(mutating: hdrPtr), iov_len: 54)
                var iov1 = iovec(iov_base: UnsafeMutableRawPointer(mutating: data.ptr), iov_len: data.len)
                var iovs: [iovec] = [iov0, iov1]
                var savedErrno: Int32 = 0
                let r = iovs.withUnsafeMutableBufferPointer { iovPtr in
                    var msg = msghdr(msg_name: nil, msg_namelen: 0,
                                     msg_iov: iovPtr.baseAddress, msg_iovlen: 2,
                                     msg_control: nil, msg_controllen: 0, msg_flags: 0)
                    let r = Darwin.sendmsg(epFD, &msg, Int32(MSG_DONTWAIT | MSG_NOSIGNAL))
                    if r < 0 { savedErrno = errno }
                    return r
                }
                if r < 0 {
                    if savedErrno == EAGAIN || savedErrno == ENOBUFS {
                        break  // data stays in send queue — retry next round
                    }
                    break
                }
                // Delivered — advance TCP sender state
                conn.snd.nxt = conn.snd.nxt &+ UInt32(data.len)
                conn.sendQueueSent += data.len
                segCount += 1
            }
        }

        // ── Drain externalSendQueue (VM→external) ──
        while conn.externalSendQueued > 0 {
            guard let (ptr, len) = conn.externalSendQueue.peek(max: min(conn.externalSendQueued, 65536)) else { break }
            let chunk = [UInt8](UnsafeRawBufferPointer(start: ptr, count: len))
            let written = transport.writeStream(chunk, to: conn.posixFD)
            if written < 0 {
                if errno == EAGAIN {
                    transport.setFDEvents(conn.posixFD, events: Int16(POLLIN | POLLOUT))
                    break
                }
                debugLog("[NAT-TCP-EXT] write to \(key.dstIP):\(key.dstPort) failed: errno=\(errno)\n")
                break
            }
            if written == 0 { break }
            debugLog("[NAT-TCP-EXT] flushed \(written)B to \(key.dstIP):\(key.dstPort)\n")
            if let pw = self.externalPcap {
                let sentChunk = Array(chunk.prefix(written))
                captureExternalPacket(pcap: pw, fd: conn.posixFD, direction: .toExternal,
                    conn: conn, flags: [.ack, .psh], payload: sentChunk,
                    hostMAC: hostMAC)
            }
            conn.drainExternalSend(written)
        }
        // Revert to POLLIN-only when queue is drained, so we don't spin on POLLOUT.
        if conn.externalSendQueued == 0 {
            transport.setFDEvents(conn.posixFD, events: Int16(POLLIN))
        }

        // ── Forward pending FIN once externalSendQueue is drained ──
        if conn.pendingExternalFin, conn.externalSendQueued == 0 {
            debugLog("[NAT-TCP-FIN] forwarding FIN to \(key.dstIP):\(key.dstPort)\n")
            shutdown(conn.posixFD, SHUT_WR)
            if let pw = self.externalPcap {
                captureExternalPacket(pcap: pw, fd: conn.posixFD, direction: .toExternal,
                    conn: conn, flags: [.fin, .ack], payload: nil,
                    hostMAC: hostMAC)
            }
            conn.pendingExternalFin = false
        }

        // ── Retry deferred external→VM FIN once sendQueue is drained ──
        if conn.pendingFinToVM, conn.totalQueuedBytes == 0 {
            debugLog("[NAT-TCP-FIN] deferred FIN to VM \(conn.vmIP):\(conn.vmPort)\n")
            let dummySeg = TCPSegmentInfo(
                seq: conn.rcv.nxt, ack: conn.snd.una,
                flags: .ack, window: 65535
            )
            let (newState, toSend, _, _) = tcpProcess(
                state: conn.state, seg: dummySeg,
                payloadPtr: nil, payloadLen: 0,
                snd: &conn.snd, rcv: &conn.rcv, appClose: true
            )
            conn.state = newState
            for segToSend in toSend {
                let hdrOfs = buildTCPHeader(
                    io: io, hostMAC: hostMAC, dstMAC: conn.vmMAC,
                    srcIP: conn.dstIP, dstIP: conn.vmIP,
                    srcPort: conn.dstPort, dstPort: conn.vmPort,
                    seqNumber: segToSend.seq, ackNumber: segToSend.ack,
                    flags: segToSend.flags, window: segToSend.window)
                if hdrOfs >= 0 {
                    finalizeTCPChecksum(io: io, hdrOfs: hdrOfs,
                        srcIP: conn.dstIP, dstIP: conn.vmIP,
                        payloadPtr: nil, payloadLen: 0)
                    _ = addTCPOutput(hdrOfs: hdrOfs, endpointID: conn.endpointID, io: io, transport: &transport)
                }
            }
            conn.pendingFinToVM = false
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
        payload: [UInt8]?,
        hostMAC: MACAddress
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

        // Build synthetic frame in a local buffer — pcap only, not on hot path
        let payLen = payload?.count ?? 0
        let frameLen = 14 + 20 + 20 + payLen
        var frame = [UInt8](repeating: 0, count: frameLen)
        frame.withUnsafeMutableBytes { buf in
            let ptr = buf.baseAddress!
            // Ethernet
            hostMAC.write(to: ptr)
            hostMAC.write(to: ptr.advanced(by: 6))
            writeUInt16BE(EtherType.ipv4.rawValue, to: ptr.advanced(by: 12))
            // IPv4
            let ipPtr = ptr.advanced(by: ethHeaderLen)
            writeIPv4Header(to: ipPtr, totalLength: UInt16(20 + 20 + payLen), protocol: .tcp,
                            srcIP: srcIP, dstIP: dstIP)
            // TCP
            let tcpPtr = ipPtr.advanced(by: ipv4HeaderLen)
            writeUInt16BE(srcPort, to: tcpPtr)
            writeUInt16BE(dstPort, to: tcpPtr.advanced(by: 2))
            writeUInt32BE(0, to: tcpPtr.advanced(by: 4))   // seq
            writeUInt32BE(0, to: tcpPtr.advanced(by: 8))   // ack
            tcpPtr.advanced(by: 12).storeBytes(of: UInt8(0x50), as: UInt8.self)
            tcpPtr.advanced(by: 13).storeBytes(of: flags.rawValue, as: UInt8.self)
            writeUInt16BE(65535, to: tcpPtr.advanced(by: 14))
            // Payload
            if let pl = payload, pl.count > 0 {
                pl.withUnsafeBytes { plBuf in
                    tcpPtr.advanced(by: 20).copyMemory(from: plBuf.baseAddress!, byteCount: pl.count)
                }
            }
            // TCP checksum
            let tcpTotalLen = 20 + payLen
            let ck = computeTCPChecksum(pseudoSrcAddr: srcIP, pseudoDstAddr: dstIP,
                                        tcpData: tcpPtr, tcpLen: tcpTotalLen)
            writeUInt16BE(ck, to: tcpPtr.advanced(by: 16))
        }
        pcap.writeRaw(framePtr: &frame, len: frameLen)
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
        io: IOBuffer
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
                          transport: &transport, io: io)
        }

        // Datagram reads → UDP data from external
        for (fd, data, from) in result.datagramReads {
            if udpListeners.contains(where: { $0.fd == fd }) {
                pollUDPAccept(fd: fd, data: data, from: from,
                              hostMAC: hostMAC, arpMapping: arpMapping,
                              io: io, transport: &transport)
            } else if let key = udpFdToKey[fd] {
                pollUDPReadable(key: key, data: data, hostMAC: hostMAC,
                                arpMapping: arpMapping, io: io, transport: &transport)
            }
        }
    }

    // MARK: - External FD registration (for unified poll)

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
        io: IOBuffer
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
            dstIP: externalIP, dstPort: externalPort, endpointID: vmEp,
            hostMAC: hostMAC
        )
        conn.snd.nxt = isn
        conn.snd.una = isn

        let synSeg = TCPSegmentToSend(flags: .syn, seq: isn, ack: 0, window: 65535, payload: nil)
        conn.snd.nxt = isn &+ 1

        tcpEntries[key] = NATEntry(connection: conn, isInbound: true)
        tcpFdToKey[newFD] = key
        transport.registerFD(newFD, events: Int16(POLLIN), kind: .stream)

        let hdrOfs = buildTCPHeader(
            io: io, hostMAC: hostMAC, dstMAC: vmMAC,
            srcIP: externalIP, dstIP: pf.vmIP,
            srcPort: externalPort, dstPort: pf.vmPort,
            seqNumber: synSeg.seq, ackNumber: synSeg.ack,
            flags: synSeg.flags, window: synSeg.window)
        if hdrOfs >= 0 {
            finalizeTCPChecksum(io: io, hdrOfs: hdrOfs,
                srcIP: externalIP, dstIP: pf.vmIP,
                payloadPtr: nil, payloadLen: 0)
            _ = addTCPOutput(hdrOfs: hdrOfs, endpointID: vmEp, io: io, transport: &transport)
        }
    }

    // MARK: ── UDP accept / readable ──

    private mutating func pollUDPAccept(
        fd: Int32, data: [UInt8], from srcAddr: sockaddr_in,
        hostMAC: MACAddress, arpMapping: ARPMapping,
        io: IOBuffer, transport: inout PollingTransport
    ) {
        guard let pf = findUDPListener(fd: fd) else { return }
        let externalIP = IPv4Address(addr: srcAddr.sin_addr.s_addr.bigEndian)
        let externalPort = srcAddr.sin_port.bigEndian
        guard let (vmMAC, vmEp) = lookupVM(ip: pf.vmIP, arpMapping: arpMapping) else { return }

        buildUDPToVM(hostMAC: hostMAC, dstMAC: vmMAC,
                     srcIP: externalIP, dstIP: pf.vmIP,
                     srcPort: externalPort, dstPort: pf.vmPort,
                     payload: data, endpointID: vmEp,
                     io: io, transport: &transport)
    }

    private mutating func pollUDPReadable(
        key: NATKey, data: [UInt8],
        hostMAC: MACAddress, arpMapping: ARPMapping,
        io: IOBuffer, transport: inout PollingTransport
    ) {
        guard var mapping = udpEntries[key] else { return }
        mapping.lastActivity = currentTime()
        udpEntries[key] = mapping

        guard let (vmMAC, vmEp) = lookupVM(ip: key.vmIP, arpMapping: arpMapping) else { return }
        buildUDPToVM(hostMAC: hostMAC, dstMAC: vmMAC,
                     srcIP: key.dstIP, dstIP: key.vmIP,
                     srcPort: key.dstPort, dstPort: key.vmPort,
                     payload: data, endpointID: vmEp,
                     io: io, transport: &transport)
    }

    /// Build a complete Ethernet+IPv4+UDP+payload frame into IOBuffer.output and
    /// write directly via transport. Used by pollUDPAccept and pollUDPReadable.
    private func buildUDPToVM(
        hostMAC: MACAddress, dstMAC: MACAddress,
        srcIP: IPv4Address, dstIP: IPv4Address,
        srcPort: UInt16, dstPort: UInt16,
        payload: [UInt8], endpointID: Int,
        io: IOBuffer, transport: inout PollingTransport
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

        _ = transport.writeSingleFrame(endpointID: endpointID, io: io,
                                        hdrOfs: ofs, hdrLen: frameLen,
                                        payPtr: nil, payLen: 0)
    }

    // MARK: ── TCP outbound SYN ──

    private mutating func handleOutboundSYN(
        key: NATKey, srcMAC: MACAddress, seg: TCPSegmentInfo,
        payloadPtr: UnsafeRawPointer?, payloadLen: Int,
        endpointID: Int, hostMAC: MACAddress,
        transport: inout PollingTransport,
        io: IOBuffer
    ) {
        if tcpEntries.count >= maxTCPConnections {
            let hdrOfs = buildTCPHeader(
                io: io, hostMAC: hostMAC, dstMAC: srcMAC,
                srcIP: key.dstIP, dstIP: key.vmIP,
                srcPort: key.dstPort, dstPort: key.vmPort,
                seqNumber: 0, ackNumber: seg.seq &+ 1,
                flags: [.rst, .ack], window: 0)
            if hdrOfs >= 0 {
                finalizeTCPChecksum(io: io, hdrOfs: hdrOfs,
                    srcIP: key.dstIP, dstIP: key.vmIP,
                    payloadPtr: nil, payloadLen: 0)
                _ = addTCPOutput(hdrOfs: hdrOfs, endpointID: endpointID, io: io, transport: &transport)
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
            vmMAC: srcMAC, vmIP: key.vmIP, vmPort: key.vmPort,
            dstIP: key.dstIP, dstPort: key.dstPort, endpointID: endpointID,
            hostMAC: hostMAC
        )
        conn.externalConnecting = true

        let (newState, toSend, _, _) = tcpProcess(
            state: .listen, seg: seg,
            payloadPtr: payloadPtr, payloadLen: payloadLen,
            snd: &conn.snd, rcv: &conn.rcv, appClose: false
        )
        conn.state = newState
        debugLog("[NAT-TCP-OUT] TCP FSM: .listen → \(newState), isn=\(conn.snd.nxt)\n")

        var entry = NATEntry(connection: conn, isInbound: false)
        entry.lastActivity = currentTime()
        tcpEntries[key] = entry
        tcpFdToKey[fd] = key
        transport.registerFD(fd, events: Int16(POLLIN | POLLOUT), kind: .stream)

        for segToSend in toSend {
            let hdrOfs = buildTCPHeader(
                io: io, hostMAC: hostMAC, dstMAC: srcMAC,
                srcIP: key.dstIP, dstIP: key.vmIP,
                srcPort: key.dstPort, dstPort: key.vmPort,
                seqNumber: segToSend.seq, ackNumber: segToSend.ack,
                flags: segToSend.flags, window: segToSend.window)
            if hdrOfs >= 0 {
                finalizeTCPChecksum(io: io, hdrOfs: hdrOfs,
                    srcIP: key.dstIP, dstIP: key.vmIP,
                    payloadPtr: nil, payloadLen: 0)
                _ = addTCPOutput(hdrOfs: hdrOfs, endpointID: endpointID, io: io, transport: &transport)
            }
        }
    }

    // MARK: ── TCP external FIN ──

    private mutating func handleTCPExternalFIN(
        key: NATKey, hostMAC: MACAddress, transport: inout PollingTransport,
        io: IOBuffer
    ) {
        guard var entry = tcpEntries[key] else { return }

        var needsCleanup = false
        var cleanupFD: Int32 = 0

        let sqBufBase = entry.connection.sendQueue.buf.baseAddress!

        // Flush sendQueue with inline writes before sending FIN to VM.
        // State advances only on successful sendmsg — if EAGAIN/ENOBUFS
        // strikes, we set pendingFinToVM so flushOneConnection retries later.
        debugLog("[NAT-TCP-FIN-FLUSH] flushing sendQueue to VM, totalQueued=\(entry.connection.totalQueuedBytes) state=\(entry.connection.state) snd.nxt=\(entry.connection.snd.nxt) snd.una=\(entry.connection.snd.una)\n")
        debugLog("[NAT-TCP-FIN-FLUSH] ips: dstIP=\(entry.connection.dstIP) vmIP=\(entry.connection.vmIP) dstPort=\(entry.connection.dstPort) vmPort=\(entry.connection.vmPort)\n")
        var finDrainComplete = true
        if entry.connection.totalQueuedBytes > 0 {
            guard let epFD = transport.fdForEndpoint(entry.connection.endpointID) else { return }
            while entry.connection.totalQueuedBytes > 0 {
                let inFlight = entry.connection.snd.nxt &- entry.connection.snd.una
                var canSend = Int(entry.connection.snd.wnd) - Int(inFlight)
                if canSend <= 0 { break }
                if canSend > mss { canSend = mss }
                guard let data = entry.connection.peekSendData(max: canSend) else { break }
                debugLog("[NAT-TCP-FIN-FLUSH] sending \(data.len)B to VM, seq=\(entry.connection.snd.nxt) ack=\(entry.connection.rcv.nxt)\n")
                let hdrOfs = buildTCPHeader(
                    io: io, hostMAC: hostMAC, dstMAC: entry.connection.vmMAC,
                    srcIP: entry.connection.dstIP, dstIP: entry.connection.vmIP,
                    srcPort: entry.connection.dstPort, dstPort: entry.connection.vmPort,
                    seqNumber: entry.connection.snd.nxt, ackNumber: entry.connection.rcv.nxt,
                    flags: [.ack, .psh], window: 65535)
                guard hdrOfs >= 0 else { break }
                finalizeTCPChecksum(io: io, hdrOfs: hdrOfs,
                    srcIP: entry.connection.dstIP, dstIP: entry.connection.vmIP,
                    payloadPtr: data.ptr, payloadLen: data.len)

                // Inline write — only advance state on success
                let hdrPtr = io.output.baseAddress!.advanced(by: hdrOfs)
                var iov0 = iovec(iov_base: UnsafeMutableRawPointer(mutating: hdrPtr), iov_len: 54)
                var iov1 = iovec(iov_base: UnsafeMutableRawPointer(mutating: data.ptr), iov_len: data.len)
                var iovs: [iovec] = [iov0, iov1]
                var savedErrno: Int32 = 0
                let r = iovs.withUnsafeMutableBufferPointer { iovPtr in
                    var msg = msghdr(msg_name: nil, msg_namelen: 0,
                                     msg_iov: iovPtr.baseAddress, msg_iovlen: 2,
                                     msg_control: nil, msg_controllen: 0, msg_flags: 0)
                    let r = Darwin.sendmsg(epFD, &msg, Int32(MSG_DONTWAIT | MSG_NOSIGNAL))
                    if r < 0 { savedErrno = errno }
                    return r
                }
                if r < 0 {
                    if savedErrno == EAGAIN || savedErrno == ENOBUFS {
                        finDrainComplete = false
                        break
                    }
                    break
                }
                // Delivered — advance TCP sender state
                entry.connection.snd.nxt = entry.connection.snd.nxt &+ UInt32(data.len)
                entry.connection.sendQueueSent += data.len
            }
        }

        // If drain didn't finish, defer FIN to flushOneConnection
        if !finDrainComplete {
            entry.connection.pendingFinToVM = true
            tcpEntries[key] = entry
            return
        }

        // Create a synthetic ACK segment to trigger FSM close processing
        let dummySeg = TCPSegmentInfo(
            seq: entry.connection.rcv.nxt, ack: entry.connection.snd.una,
            flags: .ack, window: 65535
        )
        let (newState, toSend, _, _) = tcpProcess(
            state: entry.connection.state, seg: dummySeg,
            payloadPtr: nil, payloadLen: 0,
            snd: &entry.connection.snd, rcv: &entry.connection.rcv, appClose: true
        )
        entry.connection.state = newState

        for segToSend in toSend {
            let hdrOfs = buildTCPHeader(
                io: io, hostMAC: hostMAC, dstMAC: entry.connection.vmMAC,
                srcIP: entry.connection.dstIP, dstIP: entry.connection.vmIP,
                srcPort: entry.connection.dstPort, dstPort: entry.connection.vmPort,
                seqNumber: segToSend.seq, ackNumber: segToSend.ack,
                flags: segToSend.flags, window: segToSend.window)
            if hdrOfs >= 0 {
                finalizeTCPChecksum(io: io, hdrOfs: hdrOfs,
                    srcIP: entry.connection.dstIP, dstIP: entry.connection.vmIP,
                    payloadPtr: nil, payloadLen: 0)
                _ = addTCPOutput(hdrOfs: hdrOfs, endpointID: entry.connection.endpointID, io: io, transport: &transport)
            }
        }

        if newState == .closed {
            needsCleanup = true
            cleanupFD = entry.connection.posixFD
        }

        tcpEntries[key] = entry

        if needsCleanup {
            cleanupTCP(fd: cleanupFD, key: key, transport: &transport)
        }
    }

    // MARK: ── Helpers ──

    private func lookupVM(ip: IPv4Address, arpMapping: ARPMapping) -> (MACAddress, Int)? {
        guard let mac = arpMapping.lookup(ip: ip),
              let ep = arpMapping.lookupEndpoint(mac: mac) else { return nil }
        return (mac, ep)
    }

    private func sendUDP(fd: Int32, data: [UInt8], dstIP: IPv4Address, dstPort: UInt16, transport: inout PollingTransport) {
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
        let expired = udpEntries.compactMap { (key, mapping) in
            now - mapping.lastActivity > timeout ? (key, mapping.fd) : nil
        }
        for (key, fd) in expired {
            cleanupUDP(fd: fd, key: key, transport: &transport)
        }
    }

    private mutating func cleanupExpiredTCP(transport: inout PollingTransport) {
        let now = currentTime()
        var expired: [(fd: Int32, key: NATKey)] = []
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
                expired.append((entry.connection.posixFD, key))
            }
        }
        for (fd, key) in expired {
            cleanupTCP(fd: fd, key: key, transport: &transport)
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
    /// Dump one connection's full state to stderr. Called before idle-timeout
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
