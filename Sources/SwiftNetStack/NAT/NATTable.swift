import Darwin

/// Monotonic microseconds clock for timer-based operations.
/// Uses CLOCK_MONOTONIC for sub-millisecond precision without wall-clock jumps.
public func monotonicMicros() -> UInt64 {
    var ts = timespec()
    clock_gettime(CLOCK_MONOTONIC, &ts)
    return UInt64(ts.tv_sec) * 1_000_000 + UInt64(ts.tv_nsec) / 1_000
}

/// RFC 1122 delayed ACK timeout in microseconds.
/// 500µs batches more ACKs than the typical 200µs without perceivable latency impact
/// on a sub-100µs virtio-net RTT. Reduces per-byte CPU overhead for bulk transfers.
private let delayedACKMicros: UInt64 = 500

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
    // Connection limits (configurable via init, default 256)
    public let maxTCPConnections: Int
    public let maxUDPMappings: Int

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
    public let mss: Int

    /// TCP protocol engine — owns all "what to send, when to send" logic.
    private var tcpEngine: TCPProxyEngine

    /// Gateway endpoint IPs — TCP connections to these IPs on port 53 are
    /// redirected to `upstreamDNS` (if configured).
    public var localIPs: Set<IPv4Address> = []
    /// Upstream DNS server for TCP DNS redirect (NAT-based, non-blocking).
    public var upstreamDNS: IPv4Address? = nil

    public init(portForwards: [PortForwardEntry] = [], mss: Int = 1400,
                maxTCPConnections: Int = 256, maxUDPMappings: Int = 256) {
        self.maxTCPConnections = maxTCPConnections
        self.maxUDPMappings = maxUDPMappings
        self.mss = mss
        self.tcpEngine = TCPProxyEngine(mss: mss)
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

    /// Check whether a UDP NAT mapping exists for the given 5-tuple key.
    public func hasUDPEntry(for key: NATKey) -> Bool {
        udpEntries[key] != nil
    }

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

    /// Process an inbound UDP datagram through NAT.
    /// Returns true if the datagram was forwarded (existing or newly created mapping).
    /// Returns false if no mapping existed and we're at capacity — caller should
    /// generate ICMP Port Unreachable.
    @discardableResult
    public mutating func processUDP(
        srcMAC: MACAddress, srcIP: IPv4Address, dstIP: IPv4Address,
        srcPort: UInt16, dstPort: UInt16,
        payloadOfs: Int, payloadLen: Int,
        endpointID: Int,
        hostMAC: MACAddress,
        transport: inout PollingTransport,
        io: IOBuffer,
        nowSec: UInt64
    ) -> Bool {
        let key = NATKey(vmIP: srcIP, vmPort: srcPort, dstIP: dstIP, dstPort: dstPort, protocol: .udp)

        if var mapping = udpEntries[key] {
            mapping.lastActivity = nowSec
            udpEntries[key] = mapping
            let ptr = UnsafeRawPointer(io.inputBase.advanced(by: payloadOfs))
            sendUDP(fd: mapping.fd, ptr: ptr, len: payloadLen, dstIP: key.dstIP, dstPort: key.dstPort, transport: &transport)
            return true
        }

        if udpEntries.count >= maxUDPMappings {
            stats.udpMappingRejected += 1
            return false
        }

        let fd = socket(AF_INET, SOCK_DGRAM, 0)
        guard fd >= 0 else { return false }
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
        guard bindOK >= 0 else { close(fd); return false }

        let mapping = UDPNATMapping(
            key: key, fd: fd,
            vmMAC: srcMAC, endpointID: endpointID,
            isInbound: false
        )
        udpEntries[key] = mapping
        udpFdToKey[fd] = key
        transport.registerFD(fd, events: Int16(POLLIN), kind: .datagram)

        let ptr = UnsafeRawPointer(io.inputBase.advanced(by: payloadOfs))
        sendUDP(fd: fd, ptr: ptr, len: payloadLen, dstIP: key.dstIP, dstPort: key.dstPort, transport: &transport)
        return true
    }

    // MARK: - Delayed ACK (RFC 1122 timer-based coalescing)

    // MARK: - Deadline queries (single pass)

    /// Returns the earliest deadline for each timer category, or nil if none.
    /// Scans tcpEntries once instead of three separate passes.
    public func nextDeadlines() -> (ack: UInt64?, rto: UInt64?, persist: UInt64?) {
        var ackDL: UInt64?
        var rtoDL: UInt64?
        var persistDL: UInt64?
        for entry in tcpEntries.values {
            let c = entry.connection
            if c.pendingDelayedACK {
                let dl = c.delayedACKDeadline
                if ackDL == nil || dl < ackDL! { ackDL = dl }
            }
            let rdl = c.rtoDeadline
            if rdl != 0, rtoDL == nil || rdl < rtoDL! { rtoDL = rdl }
            let pdl = c.persistDeadline
            if pdl != 0, persistDL == nil || pdl < persistDL! { persistDL = pdl }
        }
        return (ackDL, rtoDL, persistDL)
    }

    // MARK: - Unified timer processing (single pass over tcpEntries)

    /// Process expired RTO, delayed ACK, and persist timers in one pass over
    /// tcpEntries. Called at the top of processTCPRound.
    private mutating func processTCPTimers(
        io: IOBuffer, transport: inout PollingTransport, hostMAC: MACAddress, nowUs: UInt64
    ) {
        tcpEngine.processTCPTimers(
            entries: tcpEntries, io: io, transport: &transport,
            hostMAC: hostMAC, nowUs: nowUs, stats: &stats, pcap: externalPcap)
    }

    /// Build a pure ACK frame into IOBuffer and add to outBatch.
    /// Uses the pre-built template and incremental checksum (RFC 1146) when available.
    /// Writes directly via transport — no outBatch intermediate.
    @discardableResult
    private mutating func buildAckFrame(
        conn: TCPConnection, seq: UInt32, ack: UInt32, window: UInt16,
        io: IOBuffer, transport: inout PollingTransport
    ) -> Bool {
        tcpEngine.buildAckFrame(
            conn: conn, seq: seq, ack: ack, window: window,
            io: io, transport: &transport, stats: &stats, pcap: externalPcap)
    }


    // MARK: - Window scale helper

    private func wireWindow(_ actual: UInt32, scale: UInt8) -> UInt16 {
        tcpEngine.wireWindow(actual, scale: scale)
    }

    // MARK: - Helper: write a TCP output frame directly (no OutBatch)

    @discardableResult
    private func addTCPOutput(
        hdrOfs: Int, endpointID: Int, io: IOBuffer,
        transport: inout PollingTransport, hdrLen: Int = 54
    ) -> Bool {
        if let pw = self.externalPcap {
            let hdrPtr = io.output.baseAddress!.advanced(by: hdrOfs)
            pw.writeRaw(framePtr: hdrPtr, len: hdrLen)
        }
        return transport.writeSingleFrame(endpointID: endpointID, io: io,
                                          hdrOfs: hdrOfs, hdrLen: hdrLen,
                                          payPtr: nil, payLen: 0)
    }

    @discardableResult
    private func addTCPOutput(
        hdrOfs: Int, endpointID: Int, payPtr: UnsafeRawPointer, payLen: Int,
        io: IOBuffer, transport: inout PollingTransport, hdrLen: Int = 54
    ) -> Bool {
        if let pw = self.externalPcap {
            let hdrPtr = io.output.baseAddress!.advanced(by: hdrOfs)
            pw.writeRawSplit(hdr: hdrPtr, hdrLen: hdrLen,
                             pay: UnsafeMutableRawPointer(mutating: payPtr), payLen: payLen)
        }
        return transport.writeSingleFrame(endpointID: endpointID, io: io,
                                          hdrOfs: hdrOfs, hdrLen: hdrLen,
                                          payPtr: payPtr, payLen: payLen)
    }

    // MARK: - Phase 11: Unified TCP processing (VM ↔ external)

    /// Unified TCP processing — all VM↔external work in one method.
    public mutating func processTCPRound(
        out: ParseOutput,
        io: IOBuffer,
        streamReads: [(fd: Int32, offset: Int, len: Int)],
        streamDataBuffer: [UInt8],
        streamHangup: [Int32],
        streamConnects: [Int32],
        zeroCopyReads: [(fd: Int32, bytesRead: Int)],
        transport: inout PollingTransport,
        hostMAC: MACAddress,
        arpMapping: ARPMapping,
        nowSec: UInt64
    ) {
#if DEBUG
        // debug round tracking; caller can update via debugRound if desired
#endif

        // Capture fresh timestamp for deadline computations — poll() + parse
        // phases 2-10 complete between runOneRound's timestamp and here.
        let freshNowUs = monotonicMicros()

        // ── Step 0: Process TCP timers (RTO, delayed ACK, persist) in one pass ──
        let tAckFlush = cpuNanos()
        processTCPTimers(io: io, transport: &transport, hostMAC: hostMAC, nowUs: freshNowUs)
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
        let tKeys = out.tcp.keys
        let tSegs = out.tcp.segs
        let tEPs = out.tcp.endpointIDs
        let tMACs = out.tcp.srcMACs
        let tPayLens = out.tcp.payloadLen
        let tPayOfs = out.tcp.payloadOfs
        for i in 0..<out.tcp.count {
            let key = tKeys[i]
            let seg = tSegs[i]
            let ep = tEPs[i]
            let srcMAC = tMACs[i]
            let payloadPtr: UnsafeRawPointer? = tPayLens[i] > 0
                ? UnsafeRawPointer(io.inputBase.advanced(by: tPayOfs[i])) : nil
            let payloadLen = tPayLens[i]

            // New outbound connection
            if seg.flags.isSyn, !seg.flags.isAck {
                // DNS TCP redirect: VM→gateway:53 → upstream DNS:53 (non-blocking, via NAT)
                var redirectIP: IPv4Address? = nil
                if key.dstPort == 53, let upstream = upstreamDNS, localIPs.contains(key.dstIP) {
                    redirectIP = upstream
                }
                handleOutboundSYN(
                    key: key, srcMAC: srcMAC, seg: seg,
                    payloadPtr: payloadPtr, payloadLen: payloadLen,
                    endpointID: ep,
                    hostMAC: hostMAC, transport: &transport,
                    io: io, redirectIP: redirectIP
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

            guard let entry = tcpEntries[key] else { continue }
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
            let oldRcvNxt = entry.connection.rcv.nxt

            // Buffer out-of-order data BEFORE calling FSM (so FSM can still
            // send the dup ACK, but data isn't lost). Only buffer segments
            // that are ahead of rcv.nxt — duplicates (seq < rcv.nxt) are ignored.
            if payloadLen > 0, let pptr = payloadPtr, seg.seq > oldRcvNxt {
                if !entry.connection.bufferOOO(seq: seg.seq, data: pptr, len: payloadLen) {
                    stats.oooBufferDropped += 1
                } else {
                    stats.oooBufferInserted += 1
                }
            }

            let (newState, toSend, dataPtr, dataLen) = tcpProcess(
                state: entry.connection.state, seg: seg,
                payloadPtr: payloadPtr, payloadLen: payloadLen,
                snd: &entry.connection.snd, rcv: &entry.connection.rcv
            )
            entry.connection.state = newState
            // Apply peer window scaling (FSM stores raw wire window from seg.window)
            entry.connection.snd.wnd = UInt32(seg.window) << entry.connection.peerWindowScale
            // Disarm persist timer if window opened
            if entry.connection.snd.wnd > 0 {
                entry.connection.persistDeadline = 0
                entry.connection.persistBackoffCount = 0
            }

            if newState == .established && entry.connection.ackTemplate == nil {
                // For inbound connections, learn VM capabilities from SYN-ACK
                if entry.isInbound, seg.flags.isSyn {
                    entry.connection.peerWindowScale = seg.peerWindowScale
                }
                entry.connection.ackTemplate = makeAckTemplate(
                    hostMAC: entry.connection.hostMAC, vmMAC: entry.connection.vmMAC,
                    srcIP: entry.connection.dstIP, dstIP: entry.connection.vmIP,
                    srcPort: entry.connection.dstPort, dstPort: entry.connection.vmPort,
                    window: wireWindow(entry.connection.availableWindow, scale: entry.connection.ourWindowScale)
                )
            }
            let unaDelta = Int(entry.connection.snd.una &- oldUna)
            if unaDelta > 0 {
                // SYN flag uses 1 seq number but has no sendQueue byte.
                // Skip it on the first ACK so we don't dequeue real data.
                if !entry.connection.snd.synAcked {
                    entry.connection.snd.synAcked = true
                    if unaDelta > 1 {
                        entry.connection.ackSendBuf(delta: unaDelta - 1)
                    }
                } else {
                    entry.connection.ackSendBuf(delta: unaDelta)
                }
                entry.connection.dupAckCount = 0
                entry.connection.lastAckValue = entry.connection.snd.una
                entry.connection.snd.nonRecoveryRtxCount = 0  // new hole position, reset escalation
                // RFC 5681 slow start: cwnd += MSS per ACK.
                // Adaptive cap: scales inversely with total connections to
                // prevent incast. 1 conn → full window; 32 conns → window/8.
                let n = UInt32(max(1, tcpEntries.count))
                // Floor at 3×MSS: ensures 2+ segments/round for immediate ACK.
                let cap = max(UInt32(6 * mss),
                    entry.connection.snd.wnd &* 8 / n)
                if entry.connection.snd.cwnd < entry.connection.snd.ssthresh {
                    entry.connection.snd.cwnd = min(
                        entry.connection.snd.cwnd &+ UInt32(mss),
                        min(entry.connection.snd.wnd, cap))
                }
                // Approximate send time of the new oldest in-flight segment.
                // Uses rtoSendTime (time of last send) as a conservative proxy —
                // errs on the side of reordering tolerance.
                entry.connection.snd.sndUnaSendTime = entry.connection.rtoSendTime

                // RFC 6298 RTT measurement: compute sample if we have a valid send timestamp
                // and this ACK acknowledges new (non-retransmitted) data.
                let measurable = entry.connection.rtoMeasuredSeq != 0
                    && (entry.connection.snd.una &- entry.connection.rtoMeasuredSeq) < (1 << 31)
                if measurable, !entry.connection.rtoIsRetransmit {
                    let sampleRTT = freshNowUs &- entry.connection.rtoSendTime
                    let srtt = entry.connection.srtt
                    let rttvar = entry.connection.rttvar
                    if srtt == 0 {
                        entry.connection.srtt = sampleRTT
                        entry.connection.rttvar = sampleRTT >> 1
                    } else {
                        // RFC 6298 §2: SRTT = 7/8*SRTT + 1/8*R', RTTVAR = 3/4*RTTVAR + 1/4*|SRTT - R'|
                        let delta = sampleRTT > srtt ? sampleRTT &- srtt : srtt &- sampleRTT
                        entry.connection.rttvar = rttvar &- (rttvar >> 2) &+ (delta >> 2)
                        entry.connection.srtt = srtt &- (srtt >> 3) &+ (sampleRTT >> 3)
                    }
                    // RFC 6298 §2.4: RTO = SRTT + max(G, 4*RTTVAR), G = 100ms clock granularity
                    let minRTTVar = max(100_000, entry.connection.rttvar << 2)
                    entry.connection.rtoValue = clampRTO(entry.connection.srtt &+ minRTTVar)
                    entry.connection.rtoBackoffCount = 0
                    stats.rttSamples += 1
                }
                entry.connection.rtoMeasuredSeq = 0
                entry.connection.rtoIsRetransmit = false

                // Restart RTO timer if there's still data in flight.
                // Keep rtoSendTime from flushOneConnection (the actual send time)
                // so RTT samples don't include local processing delay.
                let inFlight = entry.connection.snd.nxt &- entry.connection.snd.una
                if inFlight > 0 {
                    entry.connection.rtoDeadline = monotonicMicros() &+ entry.connection.rtoValue
                } else {
                    entry.connection.rtoDeadline = 0
                }
            } else if seg.flags.isAck, !seg.flags.isSyn, payloadLen == 0 {
                // Pure ACK that didn't advance snd.una — track dup ACKs (RFC 5681)
                // Use seg.ack (the received ACK value), not snd.una, so that
                // ACKs with different ack values aren't conflated as duplicates.
                let ackVal = seg.ack
                if ackVal == entry.connection.lastAckValue, entry.connection.lastAckValue != 0 {
                    let (sum, didOverflow) = entry.connection.dupAckCount.addingReportingOverflow(1 as UInt8)
                    if !didOverflow { entry.connection.dupAckCount = sum }
                } else {
                    entry.connection.lastAckValue = ackVal
                    entry.connection.dupAckCount = 1
                }
            }
            // Loss-tolerant fast retransmit.
            // virtio-net has zero real congestion — all apparent "loss" is
            // buffer pressure, not network congestion. On 3 dup ACKs,
            // retransmit snd.una immediately.
            let inFlight = entry.connection.snd.nxt &- entry.connection.snd.una
            let unaAdvanced = unaDelta > 0
            var doRetransmit = false
            if entry.connection.dupAckCount >= 3 && !unaAdvanced, inFlight > 0 {
                if entry.connection.snd.nonRecoveryRtxCount == 0 {
                    // First retransmit for this hole: immediate.
                    entry.connection.snd.nonRecoveryRtxCount = 1
                    entry.connection.snd.lastNonRecoveryRtxTime = freshNowUs
                    stats.tcpFastRecovery += 1
                    doRetransmit = true
                } else {
                    // Already retransmitted this hole. Retransmit again
                    // at most once per RTT (srtt-based interval).
                    let elapsed = freshNowUs &- entry.connection.snd.lastNonRecoveryRtxTime
                    let minInterval = entry.connection.srtt > 0
                        ? entry.connection.srtt
                        : 200_000
                    if elapsed > minInterval {
                        entry.connection.snd.nonRecoveryRtxCount += 1
                        entry.connection.snd.lastNonRecoveryRtxTime = freshNowUs
                        stats.tcpFastRecovery += 1
                        doRetransmit = true
                    }
                }
            }
            if doRetransmit {
                retransmitHole(from: entry.connection, hostMAC: hostMAC,
                               transport: &transport, io: io)
            }
            // Trim OOO buffer past acknowledged data
            if entry.connection.rcv.nxt != oldRcvNxt {
                entry.connection.trimOOO(rcvNxt: entry.connection.rcv.nxt)
            }
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
            // Queue FSM data to externalSendQueue. Copy cost is offset by
            // batched write in flushOneConnection (1 syscall vs N per segment).
            // TODO: zero-copy writev if io.input stability extends past here.
            if dataLen > 0, let ptr = dataPtr {
                let queued = entry.connection.appendExternalSend(ptr, dataLen)
                if queued == 0 {
                    fputs("[NAT-TCP-ERR] external send queue full, \(dataLen)B dropped for \(key.dstIP):\(key.dstPort) extQ=\(entry.connection.externalSendQueued) maxQ=\(TCPConnection.maxQueueBytes)\n", stderr)
                }
            }
            // Drain reassembly buffer AFTER FSM data is queued, preserving seq order:
            // FSM data [oldRcvNxt, rcv.nxt) → OOO data [rcv.nxt, newNxt).
            if entry.connection.rcv.nxt != oldRcvNxt {
                let oldNxt = entry.connection.rcv.nxt
                let oooDrained = entry.connection.drainOOO()
                if oooDrained > 0 {
                    stats.oooBytesDrained += UInt64(oooDrained)
                    stats.oooDrainEvents += 1
                    debugLog("[NAT-TCP-OOO] C\(entry.connection.connectionID) drained \(oooDrained)B OOO, rcv.nxt \(oldNxt)→\(entry.connection.rcv.nxt)\n")
                }
            }

            if newState == .closeWait {
                entry.connection.pendingExternalFin = true
            }

            toSend.forEach { segToSend in
                if segToSend.flags == .ack {
                    // Delayed ACK (RFC 1122): batch ACKs to reduce overhead.
                    // On virtio-net (lossless, sub-100µs RTT), sending an ACK
                    // for every segment doubles CPU cost at 5+ Gbps without
                    // improving throughput.
                    if entry.connection.pendingDelayedACK {
                        // RFC 5681: duplicate ACKs MUST be sent immediately so
                        // the sender can count them for fast retransmit.
                        if entry.connection.delayedACKAck == segToSend.ack {
                            _ = buildAckFrame(
                                conn: entry.connection, seq: entry.connection.delayedACKSeq,
                                ack: entry.connection.delayedACKAck,
                                window: wireWindow(entry.connection.availableWindow, scale: entry.connection.ourWindowScale),
                                io: io, transport: &transport
                            )
                            stats.ackFlushedImmediate += 1
                        } else {
                            stats.ackOverwritten += 1
                        }
                    }
                    stats.ackDeferred += 1
                    entry.connection.pendingDelayedACK = true
                    entry.connection.delayedACKDeadline = freshNowUs + delayedACKMicros
                    entry.connection.delayedACKSeq = segToSend.seq
                    entry.connection.delayedACKAck = entry.connection.rcv.nxt
                    entry.connection.delayedACKWindow = entry.connection.availableWindow
                } else {
                    // Non-ACK segment — flush any pending delayed ACK first
                    if entry.connection.pendingDelayedACK {
                        _ = buildAckFrame(
                            conn: entry.connection, seq: entry.connection.delayedACKSeq,
                            ack: entry.connection.delayedACKAck,
                            window: wireWindow(entry.connection.availableWindow, scale: entry.connection.ourWindowScale),
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
                        flags: segToSend.flags, window: wireWindow(entry.connection.availableWindow, scale: entry.connection.ourWindowScale))
                    if hdrOfs >= 0 {
                        finalizeTCPChecksum(io: io, hdrOfs: hdrOfs,
                            srcIP: key.dstIP, dstIP: key.vmIP,
                            payloadPtr: nil, payloadLen: 0)
                        _ = addTCPOutput(hdrOfs: hdrOfs, endpointID: ep, io: io, transport: &transport)
                    }
                }
            }

            dirtyConnections.insert(key)

            if newState == .closed {
                cleanupTCP(fd: entry.connection.posixFD, key: key, transport: &transport)
            }
        }

        stats.tcpFsmNs &+= cpuNanos() - tFSM

        // ── Step 3: Process external→VM reads ──
        let tExtR = cpuNanos()

        // Zero-copy reads: data was recv'd directly into sendQueue.buf.
        // Just advance writePos — no copy needed.
        for (fd, bytesRead) in zeroCopyReads {
            guard let key = tcpFdToKey[fd], let entry = tcpEntries[key] else { continue }
            let st = entry.connection.state
            guard st == .synReceived || st == .established || st == .finWait1 || st == .finWait2
                || st == .closeWait || st == .lastAck else { continue }
            guard !entry.connection.externalEOF else { continue }
            entry.lastActivity = nowSec
            entry.connection.sendQueue.commitRecv(bytesRead)
            dirtyConnections.insert(key)
        }

        if !streamReads.isEmpty {
            debugLog("[NAT-TCP-RD-RAW] streamReads count=\(streamReads.count), fds=\(streamReads.map { $0.fd }), tcpFdToKey=\(tcpFdToKey.keys.sorted())\n")
        }
        for (fd, offset, len) in streamReads {
            debugLog("[NAT-TCP-RD-CHK] fd=\(fd) data=\(len)B inTcpFdToKey=\(tcpFdToKey[fd] != nil)\n")
            guard let key = tcpFdToKey[fd], let entry = tcpEntries[key] else { continue }
            let st = entry.connection.state
            guard st == .synReceived || st == .established || st == .finWait1 || st == .finWait2
                || st == .closeWait || st == .lastAck else { continue }
            if entry.connection.externalEOF { continue }

            debugLog("[NAT-TCP-RD] read \(len)B external→VM for \(key.dstIP):\(key.dstPort), state=\(st)\n")
            entry.lastActivity = nowSec
            let queued = streamDataBuffer.withUnsafeBytes { buf in
                entry.connection.writeSendBuf(buf.baseAddress! + offset, len)
            }
            if queued == 0, !entry.connection.sendQueueBlocked {
                entry.connection.sendQueueBlocked = true
                transport.setFDEvents(fd, events: 0)  // pause reads until queue drains
            }
            if let pw = self.externalPcap, queued > 0 {
                let payloadSlice = Array(streamDataBuffer[offset..<offset + queued])
                captureExternalPacket(pcap: pw, fd: fd, direction: .fromExternal,
                    conn: entry.connection, flags: [.ack, .psh], payload: payloadSlice,
                    hostMAC: hostMAC)
            }
            dirtyConnections.insert(key)
        }

        // ── Step 4: Handle external hangups ──
        for fd in streamHangup {
            guard let key = tcpFdToKey[fd], let entry = tcpEntries[key] else { continue }
            let st = entry.connection.state
            if st == .listen || st == .synReceived {
                if entry.connection.totalQueuedBytes > 0 {
                    debugLog("[NAT-TCP-HUP] external EOF for \(key.dstIP):\(key.dstPort) (data queued in synReceived)\n")
                    entry.lastActivity = nowSec
                    entry.connection.externalEOF = true
                    entry.connection.pendingExternalFin = false
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
            dirtyConnections.insert(key)
            handleTCPExternalFIN(key: key, hostMAC: hostMAC, transport: &transport,
                                 io: io)
        }

        stats.tcpExtReadNs &+= cpuNanos() - tExtR

        // ── Step 5: Flush dirty + queued connections (drain queues, forward FIN) ──
        let tFlush = cpuNanos()
        let totalConns = tcpEntries.count
        if totalConns <= 16 {
            // Few connections: iterate dirty only (O(dirty) ≪ O(N)).
            for key in dirtyConnections {
                guard let entry = tcpEntries[key] else { continue }
                guard entry.connection.state == .established || entry.connection.state == .closeWait
                      || entry.connection.state == .finWait1 || entry.connection.state == .finWait2
                      || entry.connection.state == .lastAck else { continue }
                flushOneConnection(key: key, conn: entry.connection, hostMAC: hostMAC,
                                   transport: &transport, io: io, nowUs: freshNowUs,
                                   totalConnections: totalConns)
            }
        } else {
            // Many connections: scan all to prevent incast starvation.
            for (key, entry) in tcpEntries {
                guard entry.connection.state == .established || entry.connection.state == .closeWait
                      || entry.connection.state == .finWait1 || entry.connection.state == .finWait2
                      || entry.connection.state == .lastAck else { continue }
                flushOneConnection(key: key, conn: entry.connection, hostMAC: hostMAC,
                                   transport: &transport, io: io, nowUs: freshNowUs,
                                   totalConnections: totalConns)
            }
        }
        stats.tcpFlushNs &+= cpuNanos() - tFlush
        dirtyConnections.removeAll(keepingCapacity: true)
    }

    // MARK: - Per-connection flush (send queues + FIN forwarding)

    /// Build header, finalize checksum, and sendmsg one TCP data segment to the VM.
    /// Returns bytes sent on success, -1 on EAGAIN/ENOBUFS, -2 on other error.
    /// Does NOT advance snd.nxt or sendQueueSent — callers decide.
    private func sendOneDataSegment(
        to conn: TCPConnection,
        seq: UInt32,
        ack: UInt32,
        flags: TCPFlags,
        data: (ptr: UnsafeRawPointer, len: Int),
        via epFD: Int32,
        hostMAC: MACAddress,
        io: IOBuffer
    ) -> Int {
        tcpEngine.sendOneDataSegment(
            to: conn, seq: seq, ack: ack, flags: flags,
            data: data, via: epFD, hostMAC: hostMAC, io: io)
    }

    /// Retransmit one SACK-truncated segment from snd.una.
    /// Called immediately from processTCPRound on recovery events so that
    /// inFlight and snd.una are accurate — no deferred-flag timing gap.
    private mutating func retransmitHole(
        from conn: TCPConnection,
        hostMAC: MACAddress,
        transport: inout PollingTransport,
        io: IOBuffer
    ) {
        tcpEngine.retransmitHole(
            from: conn, hostMAC: hostMAC,
            transport: &transport, io: io, stats: &stats)
    }

    private mutating func flushOneConnection(
        key: NATKey, conn: TCPConnection,
        hostMAC: MACAddress,
        transport: inout PollingTransport,
        io: IOBuffer,
        nowUs: UInt64,
        totalConnections: Int = 1
    ) {
        tcpEngine.flushOneConnection(
            key: key, conn: conn, hostMAC: hostMAC,
            transport: &transport, io: io, nowUs: nowUs,
            totalConnections: totalConnections,
            stats: &stats, pcap: externalPcap)
    }

    // MARK: - External pcap capture (centralized helper)

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

    /// Refresh zero-copy recv targets only. Call every round before poll.
    /// Lighter than syncExternalFDs — does not re-register FDs.
    public mutating func refreshRecvTargets(with transport: inout PollingTransport) {
        transport.clearRecvTargets()
        for (_, entry) in tcpEntries {
            let c = entry.connection
            if c.sendQueueBlocked || c.externalEOF {
                continue
            }
            let (buf, cap) = c.sendQueue.recvTarget()
            if cap > 0 {
                transport.setRecvTarget(fd: c.posixFD, buffer: buf, capacity: cap)
            } else {
                // sendQueue full — don't recv, let kernel buffer backpressure
                transport.skipRecv(fd: c.posixFD)
            }
        }
    }

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
        guard tcpEntries.count < maxTCPConnections else {
            stats.tcpConnRejected += 1; close(newFD); return
        }
        setNoDelay(newFD)
        setSocketBuffers(newFD)

        guard let pf = findTCPListener(fd: listenerFd) else { close(newFD); return }
        let externalIP = IPv4Address(addr: clientAddr.sin_addr.s_addr.bigEndian)
        let externalPort = clientAddr.sin_port.bigEndian

        let key = NATKey(vmIP: pf.vmIP, vmPort: pf.vmPort, dstIP: externalIP, dstPort: externalPort, protocol: .tcp)
        guard let (vmMAC, vmEp) = lookupVM(ip: pf.vmIP, arpMapping: arpMapping) else { close(newFD); return }

        let isn = tcpGenerateISN()
        let conn = TCPConnection(
            connectionID: nextID(), posixFD: newFD, state: .synReceived,
            vmMAC: vmMAC, vmIP: pf.vmIP, vmPort: pf.vmPort,
            dstIP: externalIP, dstPort: externalPort, endpointID: vmEp,
            hostMAC: hostMAC
        )
        conn.snd.nxt = isn
        conn.snd.una = isn

        let synSeg = TCPSegmentToSend(flags: .syn, seq: isn, ack: 0, window: 262144, payload: nil)
        conn.snd.nxt = isn &+ 1

        tcpEntries[key] = NATEntry(connection: conn, isInbound: true)
        tcpFdToKey[newFD] = key
        transport.registerFD(newFD, events: Int16(POLLIN), kind: .stream)

        let wireWin = UInt16(min(synSeg.window >> conn.ourWindowScale, 65535))
        // SYN options: MSS + WSCALE. VM uses TCP timestamps; subtract 20 for TS+SACK.
        let vmMSS = mss - 20
        var synOpts: [UInt8] = [
            2, 4, UInt8(vmMSS >> 8), UInt8(vmMSS & 0xFF),  // MSS
            3, 3, conn.ourWindowScale,  // WSCALE
        ]
        while synOpts.count % 4 != 0 { synOpts.append(1) }  // NOP padding
        let synTcpHdrLen = 20 + synOpts.count
        let synHdrLen = 14 + 20 + synTcpHdrLen
        let hdrOfs = buildTCPHeaderWithOptions(
            io: io, hostMAC: hostMAC, dstMAC: vmMAC,
            srcIP: externalIP, dstIP: pf.vmIP,
            srcPort: externalPort, dstPort: pf.vmPort,
            seqNumber: synSeg.seq, ackNumber: synSeg.ack,
            flags: synSeg.flags, window: wireWin,
            options: synOpts)
        if hdrOfs >= 0 {
            finalizeTCPChecksumEx(io: io, hdrOfs: hdrOfs,
                srcIP: externalIP, dstIP: pf.vmIP,
                tcpHdrLen: synTcpHdrLen, payloadPtr: nil, payloadLen: 0)
            _ = addTCPOutput(hdrOfs: hdrOfs, endpointID: vmEp, io: io, transport: &transport, hdrLen: synHdrLen)
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
        io: IOBuffer,
        redirectIP: IPv4Address? = nil
    ) {
        if tcpEntries.count >= maxTCPConnections {
            stats.tcpConnRejected += 1
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
        let connectIP = redirectIP ?? key.dstIP
        debugLog("[NAT-TCP-OUT] outbound SYN to \(key.dstIP):\(key.dstPort) from VM \(key.vmIP):\(key.vmPort)")

        if redirectIP != nil {
            debugLog(" → redirect to \(connectIP):\(key.dstPort)")
        }
        debugLog("\n")

        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { debugLog("[NAT-TCP-OUT] socket() failed for \(connectIP):\(key.dstPort)\n"); return }
        setNonBlocking(fd)
        setNoDelay(fd)
        setSocketBuffers(fd)

        let connectOK = withSockAddr(ip: connectIP, port: key.dstPort) { sa, saLen in
            Darwin.connect(fd, sa, saLen)
        }
        if connectOK < 0 && errno != EINPROGRESS {
            fputs("[NAT-TCP-OUT] connect() to \(connectIP):\(key.dstPort) failed: errno=\(errno)\n", stderr)
            close(fd); return
        }

        let conn = TCPConnection(
            connectionID: nextID(), posixFD: fd, state: .listen,
            vmMAC: srcMAC, vmIP: key.vmIP, vmPort: key.vmPort,
            dstIP: connectIP, dstPort: key.dstPort, endpointID: endpointID,
            hostMAC: hostMAC
        )
        conn.externalConnecting = true
        conn.peerWindowScale = seg.peerWindowScale

        let (newState, toSend, _, _) = tcpProcess(
            state: .listen, seg: seg,
            payloadPtr: payloadPtr, payloadLen: payloadLen,
            snd: &conn.snd, rcv: &conn.rcv
        )
        conn.state = newState
        // Apply peer window scaling after FSM (FSM stores raw wire window)
        conn.snd.wnd = UInt32(seg.window) << conn.peerWindowScale
        debugLog("[NAT-TCP-OUT] TCP FSM: .listen → \(newState), isn=\(conn.snd.nxt)\n")

        let entry = NATEntry(connection: conn, isInbound: false)
        entry.lastActivity = currentTime()
        tcpEntries[key] = entry
        tcpFdToKey[fd] = key
        transport.registerFD(fd, events: Int16(POLLIN | POLLOUT), kind: .stream)

        toSend.forEach { segToSend in
            let wireWin = wireWindow(conn.availableWindow, scale: conn.ourWindowScale)
            let isSynAck = segToSend.flags.contains(.syn) && segToSend.flags.contains(.ack)
            let hdrOfs: Int
            let hdrLen: Int
            var synAckTcpHdrLen: Int = 20
            if isSynAck {
                // SYN-ACK options: MSS + WSCALE.
                // VM enables TCP timestamps (+12 bytes) by default, so the
                // effective MSS is MTU-20(IP)-20(TCP)-12(ts) = MTU-52.
                // Our send path uses MTU-40 since we don't set timestamps.
                let vmMSS = mss - 20  // 1440 for MTU 1500; headroom for TS+SACK
                var opts: [UInt8] = [
                    2, 4, UInt8(vmMSS >> 8), UInt8(vmMSS & 0xFF),  // MSS
                    3, 3, conn.ourWindowScale,  // WSCALE
                ]
                while opts.count % 4 != 0 { opts.append(1) }  // NOP padding
                synAckTcpHdrLen = 20 + opts.count
                hdrLen = 14 + 20 + synAckTcpHdrLen
                hdrOfs = buildTCPHeaderWithOptions(
                    io: io, hostMAC: hostMAC, dstMAC: srcMAC,
                    srcIP: key.dstIP, dstIP: key.vmIP,
                    srcPort: key.dstPort, dstPort: key.vmPort,
                    seqNumber: segToSend.seq, ackNumber: segToSend.ack,
                    flags: segToSend.flags, window: wireWin,
                    options: opts)
            } else {
                hdrLen = 54
                hdrOfs = buildTCPHeader(
                    io: io, hostMAC: hostMAC, dstMAC: srcMAC,
                    srcIP: key.dstIP, dstIP: key.vmIP,
                    srcPort: key.dstPort, dstPort: key.vmPort,
                    seqNumber: segToSend.seq, ackNumber: segToSend.ack,
                    flags: segToSend.flags, window: wireWin)
            }
            if hdrOfs >= 0 {
                if isSynAck {
                    finalizeTCPChecksumEx(io: io, hdrOfs: hdrOfs,
                        srcIP: key.dstIP, dstIP: key.vmIP,
                        tcpHdrLen: synAckTcpHdrLen, payloadPtr: nil, payloadLen: 0)
                } else {
                    finalizeTCPChecksum(io: io, hdrOfs: hdrOfs,
                        srcIP: key.dstIP, dstIP: key.vmIP,
                        payloadPtr: nil, payloadLen: 0)
                }
                _ = addTCPOutput(hdrOfs: hdrOfs, endpointID: endpointID, io: io, transport: &transport, hdrLen: hdrLen)
            }
        }
    }

    // MARK: ── TCP external FIN ──

    private mutating func handleTCPExternalFIN(
        key: NATKey, hostMAC: MACAddress, transport: inout PollingTransport,
        io: IOBuffer
    ) {
        guard let entry = tcpEntries[key] else { return }
        let (needsCleanup, cleanupFD) = tcpEngine.handleTCPExternalFIN(
            key: key, entry: entry, hostMAC: hostMAC,
            transport: &transport, io: io, stats: &stats, pcap: externalPcap)
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

    private func sendUDP(fd: Int32, ptr: UnsafeRawPointer, len: Int, dstIP: IPv4Address, dstPort: UInt16, transport: inout PollingTransport) {
        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = dstPort.bigEndian
        withUnsafeMutableBytes(of: &addr.sin_addr) { dstIP.write(to: $0.baseAddress!) }
        transport.writeDatagram(ptr, len, to: fd, addr: addr)
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
                tooOld = age > 1800  // 30 min (RFC 5382 §5)
                reason = "established idle timeout"
            case .finWait1, .finWait2, .closeWait, .lastAck:
                tooOld = age > 300   // 5 min (TIME_WAIT substitute)
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

    private func clampRTO(_ rto: UInt64) -> UInt64 {
        tcpEngine.clampRTO(rto)
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
