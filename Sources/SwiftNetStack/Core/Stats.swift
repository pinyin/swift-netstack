import Darwin

/// Process CPU time in nanoseconds for phase timing.
/// Uses CLOCK_PROCESS_CPUTIME_ID to measure actual CPU consumption,
/// excluding time blocked in poll() or other syscalls.
/// This gives real CPU load percentages, not wall-clock duty cycle.
public func cpuNanos() -> UInt64 {
    var ts = timespec()
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &ts)
    return UInt64(ts.tv_sec) * 1_000_000_000 + UInt64(ts.tv_nsec)
}

// MARK: - TransportStats

/// Transport-level syscall and I/O counters.
public struct TransportStats {
    /// Number of poll() calls.
    public var pollCalls: UInt64 = 0
    /// Number of poll() calls that returned 0 (timeout).
    public var pollTimeouts: UInt64 = 0
    /// Number of recvmsg() calls on VM endpoints.
    public var recvmsgCalls: UInt64 = 0
    /// Number of recv() calls on external stream sockets.
    public var recvCalls: UInt64 = 0
    /// Number of recvfrom() calls on external datagram sockets.
    public var recvfromCalls: UInt64 = 0
    /// Number of sendmsg() calls (VM endpoints + external).
    public var sendmsgCalls: UInt64 = 0
    /// Total bytes written via sendmsg.
    public var sendBytes: UInt64 = 0

    /// Snapshot and reset. Returns previous values.
    public mutating func snap() -> TransportStats {
        let s = self
        self = TransportStats()
        return s
    }
}

// MARK: - NATStats

/// NAT-level delayed ACK and checksum counters.
public struct NATStats {
    /// Number of pure ACK segments deferred (delayed ACK).
    public var ackDeferred: UInt64 = 0
    /// Number of deferred ACKs replaced by a newer ACK before being sent.
    public var ackOverwritten: UInt64 = 0
    /// Number of deferred ACKs sent via timer expiry (flushExpiredDelayedACKs).
    public var ackFlushedTimer: UInt64 = 0
    /// Number of deferred ACKs sent immediately (before a non-ACK segment).
    public var ackFlushedImmediate: UInt64 = 0
    /// Number of ACK frames built from the pre-built 54-byte template.
    public var ackTemplateUsed: UInt64 = 0
    /// Number of ACK frames built via full buildTCPFrame (no template or fallback).
    public var ackTemplateFallback: UInt64 = 0
    /// Number of ACK frames whose checksum was computed incrementally (RFC 1146).
    public var ackChecksumIncremental: UInt64 = 0
    /// Number of ACK frames whose checksum was computed from scratch.
    public var ackChecksumFull: UInt64 = 0
    /// Sub-phase CPU timing for TCP hot-spot analysis.
    public var tcpAckFlushNs: UInt64 = 0
    public var tcpFsmNs: UInt64 = 0
    public var tcpExtReadNs: UInt64 = 0
    public var tcpFlushNs: UInt64 = 0
    /// Number of fast retransmit segments sent (RFC 5681, triggered by 3 dup ACKs).
    public var tcpFastRetransmit: UInt64 = 0
    /// Number of fast recovery episodes entered (RFC 5681).
    public var tcpFastRecovery: UInt64 = 0
    /// Number of RTO timer expirations that triggered retransmission.
    public var rtoExpired: UInt64 = 0
    /// Number of RTO expirations where no data was available to retransmit.
    public var rtoExpiredNoData: UInt64 = 0
    /// Number of RTO expirations where sendOneDataSegment failed.
    public var rtoExpiredSendFail: UInt64 = 0
    /// Number of valid RTT samples collected (non-retransmit).
    public var rttSamples: UInt64 = 0
    // ── retransmitHole debug counters ──
    /// Total calls to retransmitHole.
    public var rtHoleCalled: UInt64 = 0
    /// retransmitHole: inFlight == 0 (no data in flight to retransmit).
    public var rtHoleNoInflight: UInt64 = 0
    /// retransmitHole: no endpoint FD found.
    public var rtHoleNoEPFD: UInt64 = 0
    /// retransmitHole: peekRetransmitData returned nil (send queue empty).
    public var rtHoleNoData: UInt64 = 0
    /// retransmitHole: all data was SACKed (rtLen truncated to 0).
    public var rtHoleNoLen: UInt64 = 0
    /// retransmitHole: all guards passed, retransmit attempted.
    public var rtHoleOK: UInt64 = 0
    /// retransmitHole: sendOneDataSegment returned < 0 (send failure).
    public var rtHoleFail: UInt64 = 0
    /// Recovery entered with queued data available for retransmit.
    public var recvEnteredWithData: UInt64 = 0
    /// Recovery entered with NO queued data (spurious entry).
    public var recvEnteredNoData: UInt64 = 0
    /// Recovery entered when inFlight == 0 (should not happen).
    public var recvEnteredZeroIF: UInt64 = 0
    /// OOO segments inserted into reassembly buffer.
    public var oooBufferInserted: UInt64 = 0
    /// OOO segments dropped (buffer full or out of window).
    public var oooBufferDropped: UInt64 = 0
    /// Bytes drained from reassembly buffer to external send queue.
    public var oooBytesDrained: UInt64 = 0
    /// Number of drain events (gap-filled-then-drain).
    public var oooDrainEvents: UInt64 = 0
    /// FSM sub-phase breakdown: dict lookup, tcpProcess call, ACK build, dict write-back.
    public var tcpFsmDictNs: UInt64 = 0
    public var tcpFsmFuncNs: UInt64 = 0
    public var tcpFsmAckNs: UInt64 = 0
    public var tcpFsmWBkNs: UInt64 = 0

    /// Snapshot and reset. Returns previous values.
    public mutating func snap() -> NATStats {
        let s = self
        self = NATStats()
        return s
    }
}

// MARK: - PhaseTiming

/// Cumulative CPU time per BDP phase. All values in nanoseconds.
/// Used to identify hotspots — which phase burns the most CPU.
public struct PhaseTiming {
    /// Phase 1: poll() + read all FDs (poll syscall overhead + read loops)
    public var pollRead: UInt64 = 0
    /// Phase 2-6: Parse (Ethernet, MAC filter, IPv4, ARP, transport headers)
    public var parse: UInt64 = 0
    /// Phase 7-8: ICMP processing
    public var icmp: UInt64 = 0
    /// Phase 9: UDP processing
    public var udp: UInt64 = 0
    /// Phase 10: DNS processing
    public var dns: UInt64 = 0
    /// Phase 11: TCP NAT (unified processTCPRound)
    public var tcp: UInt64 = 0
    /// Phase 12: NAT transport result (non-TCP)
    public var natResult: UInt64 = 0
    /// Phase 13: DNS upstream
    public var dnsUpstream: UInt64 = 0
    /// Phase 14-15: DHCP + ARP
    public var dhcpArp: UInt64 = 0
    /// Phase 16: Batch write + cleanup
    public var write: UInt64 = 0

    /// Wall-clock nanoseconds across all rounds (monotonic time, not CPU time).
    /// Used to compute CPU utilization: totalNanos / wallNanos.
    public var wallNanos: UInt64 = 0

    public var totalRounds: UInt64 = 0

    /// Total CPU nanoseconds across all phases.
    public var totalNanos: UInt64 {
        pollRead + parse + icmp + udp + dns + tcp
        + natResult + dnsUpstream + dhcpArp + write
    }

    /// Phase labels and values, ordered by BDP phase number.
    public func ordered() -> [(label: String, nanos: UInt64)] {
        [
            ("poll",   pollRead),
            ("parse",  parse),
            ("icmp",   icmp),
            ("udp",    udp),
            ("dns",    dns),
            ("tcp",    tcp),
            ("natRst", natResult),
            ("dnsUp",  dnsUpstream),
            ("dhcpArp",dhcpArp),
            ("write",  write),
        ]
    }

    public mutating func snap() -> PhaseTiming {
        let s = self
        self = PhaseTiming()
        return s
    }

    /// CPU utilization percentage (0-100). Returns nil if no wall-clock data.
    public func utilization() -> Int? {
        guard wallNanos > 0 else { return nil }
        let pct = Int(Double(totalNanos) / Double(wallNanos) * 100)
        return Swift.min(pct, 100)
    }
}

// MARK: - printStats

/// Periodic stats printing helper. Prints every `interval` rounds.
public func printStats(
    round: UInt64, interval: UInt64,
    transport: TransportStats, nat: NATStats,
    phase: PhaseTiming? = nil
) {
    guard round > 0 && round % interval == 0 else { return }
    let t = transport
    let n = nat
    var parts: [String] = []
    parts.append("rounds=\(round)")

    // ── Phase CPU hotspot breakdown ──
    if let p = phase, p.totalNanos > 0 {
        let total = p.totalNanos
        var phParts: [String] = []
        for (label, nanos) in p.ordered() {
            let pct = Int(Double(nanos) / Double(total) * 100)
            if pct > 0 { phParts.append("\(label)=\(pct)%") }
        }
        if !phParts.isEmpty {
            let avgUs = total / 1000 / p.totalRounds
            parts.append("cpu[\(phParts.joined(separator: " "))] avg=\(avgUs)us/r")
                if let util = p.utilization() {
                    parts.append("util=\(util)%")
                }
        }
    }

    // ── Transport counters ──
    if t.pollCalls > 0 {
        let pct = t.pollCalls > 0 ? Int(Double(t.pollTimeouts) / Double(t.pollCalls) * 100) : 0
        parts.append("poll=\(t.pollCalls) timeout=\(t.pollTimeouts)(\(pct)%)")
    }
    if t.recvmsgCalls > 0 { parts.append("recvmsg=\(t.recvmsgCalls)") }
    if t.recvCalls > 0     { parts.append("recv=\(t.recvCalls)") }
    if t.recvfromCalls > 0 { parts.append("recvfrom=\(t.recvfromCalls)") }
    if t.sendmsgCalls > 0  { parts.append("sendmsg=\(t.sendmsgCalls)") }
    if t.sendBytes > 0     { parts.append("sendMB=\(t.sendBytes / 1_000_000)") }

    // ── NAT counters ──
    if n.ackDeferred > 0 {
        let flushed = n.ackFlushedTimer + n.ackFlushedImmediate
        let remaining = flushed >= n.ackDeferred ? UInt64(0) : n.ackDeferred - flushed
        let coalesce = Int(Double(remaining) / Double(n.ackDeferred) * 100)
        parts.append("ackDef=\(n.ackDeferred) ovrw=\(n.ackOverwritten) timer=\(n.ackFlushedTimer) imm=\(n.ackFlushedImmediate) coalesce=\(coalesce)%")
    }
    if n.ackTemplateUsed + n.ackTemplateFallback > 0 {
        parts.append("ackTmpl=\(n.ackTemplateUsed)/\(n.ackTemplateUsed + n.ackTemplateFallback)")
    }
    if n.ackChecksumIncremental + n.ackChecksumFull > 0 {
        parts.append("ackCKinc=\(n.ackChecksumIncremental)/\(n.ackChecksumIncremental + n.ackChecksumFull)")
    }
    if n.tcpFastRetransmit + n.tcpFastRecovery > 0 {
        parts.append("fastRT=\(n.tcpFastRetransmit) fastRec=\(n.tcpFastRecovery)")
    }
    if n.rtoExpired + n.rttSamples > 0 {
        parts.append("rto[exp=\(n.rtoExpired) noDat=\(n.rtoExpiredNoData) fail=\(n.rtoExpiredSendFail) samples=\(n.rttSamples)]")
    }
    // ── retransmitHole debug breakdown ──
    if n.rtHoleCalled > 0 {
        parts.append("rtHole[ok=\(n.rtHoleOK) fail=\(n.rtHoleFail) noInf=\(n.rtHoleNoInflight) noEP=\(n.rtHoleNoEPFD) noDat=\(n.rtHoleNoData) noLen=\(n.rtHoleNoLen)]")
        if n.recvEnteredWithData + n.recvEnteredNoData > 0 {
            parts.append("recvEnt[data=\(n.recvEnteredWithData) noDat=\(n.recvEnteredNoData) zeroIF=\(n.recvEnteredZeroIF)]")
        }
    }
    // ── TCP sub-phase timing ──
    let subTotal = n.tcpAckFlushNs + n.tcpFsmNs + n.tcpExtReadNs + n.tcpFlushNs
    if subTotal > 0 {
        let base = phase?.tcp ?? subTotal
        let ackFlushPct = Int(Double(n.tcpAckFlushNs) / Double(base) * 100)
        let fsmPct      = Int(Double(n.tcpFsmNs)      / Double(base) * 100)
        let extPct      = Int(Double(n.tcpExtReadNs)  / Double(base) * 100)
        let flushPct    = Int(Double(n.tcpFlushNs)    / Double(base) * 100)
        parts.append("tcpSub[ackFlush=\(ackFlushPct)% fsm=\(fsmPct)% ext=\(extPct)% flush=\(flushPct)%]")
    }
    // ── FSM sub-phase timing ──
    let fsmSubTotal = n.tcpFsmDictNs + n.tcpFsmFuncNs + n.tcpFsmAckNs + n.tcpFsmWBkNs
    if fsmSubTotal > 0 {
        let dictPct = Int(Double(n.tcpFsmDictNs) / Double(fsmSubTotal) * 100)
        let funcPct = Int(Double(n.tcpFsmFuncNs) / Double(fsmSubTotal) * 100)
        let ackPct  = Int(Double(n.tcpFsmAckNs)  / Double(fsmSubTotal) * 100)
        let wbkPct  = Int(Double(n.tcpFsmWBkNs)  / Double(fsmSubTotal) * 100)
        parts.append("fsmSub[dict=\(dictPct)% func=\(funcPct)% ack=\(ackPct)% wbk=\(wbkPct)%]")
    }
    // ── OOO reassembly buffer ──
    if n.oooBufferInserted + n.oooBufferDropped + n.oooBytesDrained > 0 {
        parts.append("ooo[ins=\(n.oooBufferInserted) drop=\(n.oooBufferDropped) drain=\(n.oooBytesDrained)B ev=\(n.oooDrainEvents)]")
    }
    let line = "[STATS] " + parts.joined(separator: " ")
    _ = line.withCString { Darwin.write(STDERR_FILENO, $0, strlen($0)) }
    _ = "\n".withCString { Darwin.write(STDERR_FILENO, $0, 1) }
}
