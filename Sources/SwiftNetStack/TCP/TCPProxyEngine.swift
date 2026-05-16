import Darwin

/// TCP protocol engine — owns all TCP "what to send, when to send" logic.
///
/// Extracted from NATTable so that NAT concerns (socket management, address
/// mapping, fd tracking) are separate from TCP protocol concerns (state
/// machine integration, congestion control, timers, retransmission).
///
/// All methods are self-contained: they operate on TCPConnection state and
/// receive NAT-specific services (pcap, stats, transport) via parameters.
/// TCPProxyEngine never touches NAT dictionaries or manages fd lifecycles.
struct TCPProxyEngine {
    /// Maximum segment size for data segments.
    let mss: Int

    init(mss: Int = 1400) {
        self.mss = mss
    }

    // MARK: - Leaf helpers

    /// Clamp computed RTO to [200ms, 60s] per RFC 6298 §2.4.
    func clampRTO(_ rto: UInt64) -> UInt64 {
        max(200_000, min(60_000_000, rto))
    }

    /// Convert logical window to wire-format UInt16 using RFC 1323 window scaling.
    func wireWindow(_ actual: UInt32, scale: UInt8) -> UInt16 {
        UInt16(min(actual >> scale, 65535))
    }

    // MARK: - TCP segment I/O

    /// Build header, finalize checksum, and sendmsg one TCP data segment to the VM.
    /// Returns bytes sent on success, -1 on EAGAIN/ENOBUFS, -2 on other error.
    /// Does NOT advance snd.nxt or sendQueueSent — callers decide.
    @discardableResult
    func sendOneDataSegment(
        to conn: TCPConnection,
        seq: UInt32, ack: UInt32, flags: TCPFlags,
        data: (ptr: UnsafeRawPointer, len: Int),
        via epFD: Int32, hostMAC: MACAddress, io: IOBuffer
    ) -> Int {
        let hdrOfs = buildTCPHeader(
            io: io, hostMAC: hostMAC, dstMAC: conn.vmMAC,
            srcIP: conn.dstIP, dstIP: conn.vmIP,
            srcPort: conn.dstPort, dstPort: conn.vmPort,
            seqNumber: seq, ackNumber: ack,
            flags: flags, window: wireWindow(conn.availableWindow, scale: conn.ourWindowScale),
            payloadLen: data.len)
        guard hdrOfs >= 0 else { return -2 }
        finalizeTCPChecksum(io: io, hdrOfs: hdrOfs,
            srcIP: conn.dstIP, dstIP: conn.vmIP,
            payloadPtr: data.ptr, payloadLen: data.len)
        let hdrPtr = io.output.baseAddress!.advanced(by: hdrOfs)
        let iov0 = iovec(iov_base: UnsafeMutableRawPointer(mutating: hdrPtr), iov_len: 54)
        let iov1 = iovec(iov_base: UnsafeMutableRawPointer(mutating: data.ptr), iov_len: data.len)
        var iovs = (iov0, iov1)
        var savedErrno: Int32 = 0
        let r = withUnsafeMutableBytes(of: &iovs) { buf in
            var msg = msghdr(msg_name: nil, msg_namelen: 0,
                             msg_iov: buf.baseAddress!.assumingMemoryBound(to: iovec.self), msg_iovlen: 2,
                             msg_control: nil, msg_controllen: 0, msg_flags: 0)
            let r = Darwin.sendmsg(epFD, &msg, Int32(MSG_DONTWAIT | MSG_NOSIGNAL))
            if r < 0 { savedErrno = errno }
            return r
        }
        if r < 0 {
            if savedErrno == EAGAIN || savedErrno == ENOBUFS { return -1 }
            return -2
        }
        return r
    }

    /// Retransmit one SACK-truncated segment from snd.una.
    /// Called immediately from processTCPRound on recovery events so that
    /// inFlight and snd.una are accurate — no deferred-flag timing gap.
    mutating func retransmitHole(
        from conn: TCPConnection,
        hostMAC: MACAddress,
        transport: inout PollingTransport,
        io: IOBuffer,
        stats: inout NATStats
    ) {
        stats.rtHoleCalled += 1
        let inFlight = conn.snd.nxt &- conn.snd.una
        guard inFlight > 0 else { stats.rtHoleNoInflight += 1; return }
        guard let epFD = transport.fdForEndpoint(conn.endpointID) else { stats.rtHoleNoEPFD += 1; return }
        guard let rtData = conn.peekRetransmitData(max: min(mss, conn.totalQueuedBytes)) else { stats.rtHoleNoData += 1; return }
        let rtLen = rtData.len
        guard rtLen > 0 else { stats.rtHoleNoLen += 1; return }
        stats.rtHoleOK += 1
        let rr = sendOneDataSegment(
            to: conn, seq: conn.snd.una, ack: conn.rcv.nxt,
            flags: [.ack], data: (rtData.ptr, rtLen),
            via: epFD, hostMAC: hostMAC, io: io)
        if rr >= 0 {
            stats.tcpFastRetransmit += 1
            conn.rtoIsRetransmit = true  // Karn's algorithm
        }
        else { stats.rtHoleFail += 1 }
    }

    // MARK: - ACK frame construction

    /// Build a pure ACK frame into IOBuffer and write via transport.
    /// Uses pre-built template and incremental checksum (RFC 1146) when available.
    @discardableResult
    mutating func buildAckFrame(
        conn: TCPConnection, seq: UInt32, ack: UInt32, window: UInt16,
        io: IOBuffer, transport: inout PollingTransport,
        stats: inout NATStats, pcap: PCAPWriter?
    ) -> Bool {
        var outCK: UInt16 = 0
        let hdrOfs: Int
        let hdrLen: Int

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
            hdrLen = 54
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
            hdrLen = 54
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
        conn.lastAdvertisedWindow = UInt32(window) << conn.ourWindowScale
        conn.lastACKChecksum = outCK
        conn.ackChecksumValid = true

        if let pw = pcap {
            let hdrPtr = io.output.baseAddress!.advanced(by: hdrOfs)
            pw.writeRaw(framePtr: hdrPtr, len: hdrLen)
        }
        return transport.writeSingleFrame(endpointID: conn.endpointID, io: io,
                                          hdrOfs: hdrOfs, hdrLen: hdrLen,
                                          payPtr: nil, payLen: 0)
    }

    // MARK: - Timer processing

    /// Process expired RTO, delayed ACK, and persist timers in one pass over
    /// tcpEntries. Called at the top of processTCPRound.
    mutating func processTCPTimers(
        entries: [NATKey: NATEntry],
        io: IOBuffer, transport: inout PollingTransport, hostMAC: MACAddress,
        nowUs: UInt64, stats: inout NATStats, pcap: PCAPWriter?
    ) {
        for (_, entry) in entries {
            let c = entry.connection

            // ── RTO expiry (RFC 6298) ──
            if c.rtoDeadline != 0, c.rtoDeadline <= nowUs {
                if let epFD = transport.fdForEndpoint(c.endpointID) {
                    let inFlight = c.snd.nxt &- c.snd.una
                    if inFlight > 0 {
                        c.dupAckCount = 0
                        c.lastAckValue = 0
                        let oldRTO = c.rtoValue
                        c.rtoBackoffCount = min(6, c.rtoBackoffCount &+ 1)
                        c.rtoValue = min(60_000_000, oldRTO &* 2)
                        c.rtoDeadline = nowUs &+ c.rtoValue
                        c.rtoIsRetransmit = true

                        if let rtData = c.peekRetransmitData(max: min(mss, c.totalQueuedBytes)) {
                            let rtLen = rtData.len
                            if rtLen > 0 {
                                stats.rtoExpired += 1
                                let rr = sendOneDataSegment(
                                    to: c, seq: c.snd.una, ack: c.rcv.nxt,
                                    flags: [.ack], data: (rtData.ptr, rtLen),
                                    via: epFD, hostMAC: hostMAC, io: io)
                                if rr < 0 { stats.rtoExpiredSendFail += 1 }
                            } else {
                                stats.rtoExpiredNoData += 1
                            }
                        } else {
                            stats.rtoExpiredNoData += 1
                        }
                    } else {
                        c.rtoDeadline = 0
                    }
                }
            }

            // ── Delayed ACK flush ──
            if c.pendingDelayedACK, c.delayedACKDeadline <= nowUs {
                if buildAckFrame(
                    conn: c, seq: c.delayedACKSeq, ack: c.delayedACKAck,
                    window: wireWindow(c.delayedACKWindow, scale: c.ourWindowScale),
                    io: io, transport: &transport, stats: &stats, pcap: pcap
                ) {
                    stats.ackFlushedTimer += 1
                }
                c.pendingDelayedACK = false
            }

            // ── Persist timer (RFC 1122 §4.2.2.17) ──
            if c.persistDeadline != 0, c.persistDeadline <= nowUs,
               c.state == .established || c.state == .closeWait
               || c.state == .finWait1 || c.state == .finWait2 {
                if let epFD = transport.fdForEndpoint(c.endpointID) {
                    if let data = c.peekSendData(max: 1) {
                        _ = sendOneDataSegment(
                            to: c, seq: c.snd.nxt, ack: c.rcv.nxt,
                            flags: [.ack], data: (data.ptr, 1),
                            via: epFD, hostMAC: hostMAC, io: io)

                        let backoffCount = min(6, c.persistBackoffCount &+ 1)
                        c.persistBackoffCount = backoffCount
                        let interval = min(60_000_000, c.rtoValue << backoffCount)
                        c.persistDeadline = nowUs + interval
                    } else {
                        c.persistDeadline = 0
                    }
                }
            }
        }
    }

    // MARK: - Connection flush

    /// Drain send queues for one connection, forward FINs if ready.
    mutating func flushOneConnection(
        key: NATKey, conn: TCPConnection,
        hostMAC: MACAddress,
        transport: inout PollingTransport,
        io: IOBuffer,
        nowUs: UInt64,
        totalConnections: Int = 1,
        stats: inout NATStats,
        pcap: PCAPWriter?
    ) {
        // ── Drain sendQueue (external→VM) with inline writes ──
        if conn.totalQueuedBytes > 0 {
            // Flush any pending delayed ACK before sending data
            if conn.pendingDelayedACK {
                _ = buildAckFrame(
                    conn: conn, seq: conn.delayedACKSeq,
                    ack: conn.delayedACKAck,
                    window: wireWindow(conn.delayedACKWindow, scale: conn.ourWindowScale),
                    io: io, transport: &transport, stats: &stats, pcap: pcap
                )
                stats.ackFlushedImmediate += 1
                conn.pendingDelayedACK = false
            }

            guard let epFD = transport.fdForEndpoint(conn.endpointID) else { return }
            var segCount = 0
            let effectiveWnd = min(conn.snd.wnd, conn.snd.cwnd)
            let maxSegsPerRound = kMaxBatchedSegments
            let sndNxtBefore = conn.snd.nxt
            while segCount < maxSegsPerRound {
                let inFlight = conn.snd.nxt &- conn.snd.una
                if inFlight == 0 { conn.snd.sndUnaSendTime = nowUs }
                var canSend = Int(effectiveWnd) - Int(inFlight)

                // Limited Transmit (RFC 3042)
                if canSend <= 0, conn.dupAckCount >= 1, conn.dupAckCount <= 2,
                   Int(conn.snd.wnd) > Int(inFlight) {
                    canSend = mss
                }

                if canSend <= 0 {
                    if conn.snd.wnd == 0, conn.totalQueuedBytes > 0, conn.persistDeadline == 0 {
                        conn.persistDeadline = nowUs + max(conn.rtoValue, 200_000)
                    }
                    break
                }
                if canSend > mss { canSend = mss }
                guard let data = conn.peekSendData(max: canSend) else {
                    if conn.totalQueuedBytes > 0, inFlight > 0,
                       conn.dupAckCount >= 3 {
                        retransmitHole(from: conn, hostMAC: hostMAC,
                                       transport: &transport, io: io, stats: &stats)
                    }
                    break
                }
                let r = sendOneDataSegment(
                    to: conn, seq: conn.snd.nxt, ack: conn.rcv.nxt,
                    flags: [.ack, .psh], data: data,
                    via: epFD, hostMAC: hostMAC, io: io)
                if r < 0 {
                    if r == -1 { break }
                    break
                }
                conn.snd.nxt = conn.snd.nxt &+ UInt32(data.len)
                conn.sendQueueSent += data.len
                segCount += 1
            }

            if segCount > 0, conn.rtoDeadline == 0 {
                let now = monotonicMicros()
                conn.rtoDeadline = now &+ conn.rtoValue
                conn.rtoSendTime = now
                conn.rtoMeasuredSeq = sndNxtBefore
                conn.rtoIsRetransmit = false
            }
        }

        // ── Drain externalSendQueue (VM→external) ──
        if conn.externalSendQueued > 0,
           let (ptr, len) = conn.externalSendQueue.peek(max: conn.externalSendQueued) {
            let written = transport.writeStream(ptr, len, to: conn.posixFD)
            if written < 0 {
                if errno == EAGAIN {
                    transport.setFDEvents(conn.posixFD, events: Int16(POLLIN | POLLOUT))
                }
            } else if written > 0 {
                if let pw = pcap {
                    let sentChunk = [UInt8](UnsafeRawBufferPointer(start: ptr, count: written))
                    captureExternalPacket(pcap: pw, fd: conn.posixFD, direction: .toExternal,
                        conn: conn, flags: [.ack, .psh], payload: sentChunk,
                        hostMAC: hostMAC)
                }
                conn.drainExternalSend(written)
            }
        }
        if conn.externalSendQueued == 0 {
            transport.setFDEvents(conn.posixFD, events: Int16(POLLIN))
        }

        // ── Window update ──
        let newAvail = conn.availableWindow
        if newAvail > conn.lastAdvertisedWindow
           && newAvail >= conn.lastAdvertisedWindow + (conn.lastAdvertisedWindow >> 2) {
            if buildAckFrame(
                conn: conn, seq: conn.snd.nxt, ack: conn.rcv.nxt,
                window: wireWindow(newAvail, scale: conn.ourWindowScale),
                io: io, transport: &transport, stats: &stats, pcap: pcap
            ) {
                stats.ackFlushedImmediate += 1
            }
        }

        // ── Flush any pending delayed ACK ──
        if conn.pendingDelayedACK {
            if buildAckFrame(
                conn: conn, seq: conn.delayedACKSeq,
                ack: conn.delayedACKAck,
                window: wireWindow(conn.availableWindow, scale: conn.ourWindowScale),
                io: io, transport: &transport, stats: &stats, pcap: pcap
            ) {
                stats.ackFlushedImmediate += 1
            }
            conn.pendingDelayedACK = false
        }

        // ── Forward pending FIN once externalSendQueue is drained ──
        if conn.pendingExternalFin, conn.externalSendQueued == 0 {
            shutdown(conn.posixFD, SHUT_WR)
            if let pw = pcap {
                captureExternalPacket(pcap: pw, fd: conn.posixFD, direction: .toExternal,
                    conn: conn, flags: [.fin, .ack], payload: nil,
                    hostMAC: hostMAC)
            }
            conn.pendingExternalFin = false
        }

        // ── Retry deferred external→VM FIN once sendQueue is drained ──
        if conn.pendingFinToVM, conn.totalQueuedBytes == 0 {
            let (newState, toSend) = tcpAppClose(
                state: conn.state,
                snd: &conn.snd,
                rcv: &conn.rcv
            )
            conn.state = newState
            toSend.forEach { segToSend in
                let hdrOfs = buildTCPHeader(
                    io: io, hostMAC: hostMAC, dstMAC: conn.vmMAC,
                    srcIP: conn.dstIP, dstIP: conn.vmIP,
                    srcPort: conn.dstPort, dstPort: conn.vmPort,
                    seqNumber: segToSend.seq, ackNumber: segToSend.ack,
                    flags: segToSend.flags, window: wireWindow(conn.availableWindow, scale: conn.ourWindowScale))
                if hdrOfs >= 0 {
                    finalizeTCPChecksum(io: io, hdrOfs: hdrOfs,
                        srcIP: conn.dstIP, dstIP: conn.vmIP,
                        payloadPtr: nil, payloadLen: 0)
                    _ = transport.writeSingleFrame(endpointID: conn.endpointID, io: io,
                                                  hdrOfs: hdrOfs, hdrLen: 54,
                                                  payPtr: nil, payLen: 0)
                }
            }
            conn.pendingFinToVM = false
        }
    }

    // MARK: - External FIN handling

    /// Handle external→VM FIN: drain sendQueue, send FIN to VM, transition state.
    mutating func handleTCPExternalFIN(
        key: NATKey, entry: NATEntry, hostMAC: MACAddress,
        transport: inout PollingTransport, io: IOBuffer,
        stats: inout NATStats, pcap: PCAPWriter?
    ) -> (needsCleanup: Bool, cleanupFD: Int32) {
        let conn = entry.connection
        var needsCleanup = false
        var cleanupFD: Int32 = 0

        var finDrainComplete = true
        if conn.totalQueuedBytes > 0 {
            guard let epFD = transport.fdForEndpoint(conn.endpointID) else { return (false, 0) }
            var drainIters = 0
            while conn.totalQueuedBytes > 0, drainIters < kMaxDrainIterations {
                drainIters += 1
                let inFlight = conn.snd.nxt &- conn.snd.una
                var canSend = Int(conn.snd.wnd) - Int(inFlight)
                if canSend <= 0 { break }
                if canSend > mss { canSend = mss }
                guard let data = conn.peekSendData(max: canSend) else { break }
                let r = sendOneDataSegment(
                    to: conn, seq: conn.snd.nxt, ack: conn.rcv.nxt,
                    flags: [.ack, .psh], data: data,
                    via: epFD, hostMAC: hostMAC, io: io)
                if r < 0 {
                    if r == -1 { finDrainComplete = false; break }
                    break
                }
                conn.snd.nxt = conn.snd.nxt &+ UInt32(data.len)
                conn.sendQueueSent += data.len
            }
            if drainIters >= kMaxDrainIterations {
                sanityLog("FIN drain cap hit for \(key.vmIP):\(key.vmPort), q=\(conn.totalQueuedBytes)")
            }
        }

        if !finDrainComplete {
            conn.pendingFinToVM = true
            return (false, 0)
        }

        let (newState, toSend) = tcpAppClose(
            state: conn.state,
            snd: &conn.snd,
            rcv: &conn.rcv
        )
        conn.state = newState

        toSend.forEach { segToSend in
            let hdrOfs = buildTCPHeader(
                io: io, hostMAC: hostMAC, dstMAC: conn.vmMAC,
                srcIP: conn.dstIP, dstIP: conn.vmIP,
                srcPort: conn.dstPort, dstPort: conn.vmPort,
                seqNumber: segToSend.seq, ackNumber: segToSend.ack,
                flags: segToSend.flags, window: wireWindow(conn.availableWindow, scale: conn.ourWindowScale))
            if hdrOfs >= 0 {
                finalizeTCPChecksum(io: io, hdrOfs: hdrOfs,
                    srcIP: conn.dstIP, dstIP: conn.vmIP,
                    payloadPtr: nil, payloadLen: 0)
                _ = transport.writeSingleFrame(endpointID: conn.endpointID, io: io,
                                              hdrOfs: hdrOfs, hdrLen: 54,
                                              payPtr: nil, payLen: 0)
            }
        }

        if newState == .closed {
            needsCleanup = true
            cleanupFD = conn.posixFD
        }

        return (needsCleanup, cleanupFD)
    }
}

// MARK: - External packet capture helper

/// Capture a synthetic Ethernet frame representing external socket traffic.
func captureExternalPacket(
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

    let payLen = payload?.count ?? 0
    let frameLen = 14 + 20 + 20 + payLen
    var frame = [UInt8](repeating: 0, count: frameLen)
    frame.withUnsafeMutableBytes { buf in
        let ptr = buf.baseAddress!
        hostMAC.write(to: ptr)
        hostMAC.write(to: ptr.advanced(by: 6))
        writeUInt16BE(EtherType.ipv4.rawValue, to: ptr.advanced(by: 12))
        let ipPtr = ptr.advanced(by: ethHeaderLen)
        writeIPv4Header(to: ipPtr, totalLength: UInt16(20 + 20 + payLen), protocol: .tcp,
                        srcIP: srcIP, dstIP: dstIP)
        let tcpPtr = ipPtr.advanced(by: ipv4HeaderLen)
        writeUInt16BE(srcPort, to: tcpPtr)
        writeUInt16BE(dstPort, to: tcpPtr.advanced(by: 2))
        writeUInt32BE(0, to: tcpPtr.advanced(by: 4))
        writeUInt32BE(0, to: tcpPtr.advanced(by: 8))
        tcpPtr.advanced(by: 12).storeBytes(of: UInt8(0x50), as: UInt8.self)
        tcpPtr.advanced(by: 13).storeBytes(of: flags.rawValue, as: UInt8.self)
        writeUInt16BE(65535, to: tcpPtr.advanced(by: 14))
        if let pl = payload, pl.count > 0 {
            pl.withUnsafeBytes { plBuf in
                tcpPtr.advanced(by: 20).copyMemory(from: plBuf.baseAddress!, byteCount: pl.count)
            }
        }
        let tcpTotalLen = 20 + payLen
        let ck = computeTCPChecksum(pseudoSrcAddr: srcIP, pseudoDstAddr: dstIP,
                                    tcpData: tcpPtr, tcpLen: tcpTotalLen)
        writeUInt16BE(ck, to: tcpPtr.advanced(by: 16))
    }
    pcap.writeRaw(framePtr: &frame, len: frameLen)
}

enum ExternalDirection {
    case toExternal
    case fromExternal
}
