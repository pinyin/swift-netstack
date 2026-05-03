import Foundation

// MARK: - Phase 1: Timer Processing

extension TCPState {

    func processTimers() {
        let expired = timerWheel.expired(currentTick: tick)

        for tuple in expired {
            if let conn = synSent[tuple] {
                conn.sndNxt = conn.iss
                conn.retransmitAt = 0
            }
            if let conn = synRcvd[tuple] {
                conn.sndNxt = conn.iss
                conn.retransmitAt = 0
            }
            if let conn = lastAck[tuple] {
                conn.finSent = false
                if conn.sndNxt > conn.sndUna {
                    conn.sndNxt -= 1
                }
                conn.retransmitAt = 0
            }
            if let conn = established[tuple] {
                conn.sndNxt = conn.sndUna
                conn.retransmitCount += 1
                conn.retransmitAt = 0
            }
            if timeWait[tuple] != nil {
                timeWait[tuple] = nil
            }
        }
    }

    // MARK: - Phase 2: Dispatch Segments

    func dispatchSegments() {
        for seg in pending {
            let tuple = seg.tuple.reversed()

            if let conn = findConn(tuple) {
                conn.pendingSegs.append(seg)
                conn.lastActivityTick = tick
                continue
            }

            if seg.header.isSYN() && !seg.header.isACK() && seg.tuple.dstPort == listenPort && listener != nil {
                createSynRcvd(seg)
                continue
            }
        }
        pending = []
    }

    func createSynRcvd(_ seg: TCPSegment) {
        let iss = generateISN()
        let tuple = seg.tuple.reversed()

        let conn = TCPConn(tuple: tuple, irs: seg.header.seqNum, iss: iss, window: seg.header.windowSize, bufSize: cfg.bufferSize)
        conn.lastActivityTick = tick

        let ws = parseWindowScale(seg.raw)
        if ws > 0 {
            conn.sndShift = ws
        }
        conn.rcvShift = cfg.windowScale
        conn.retransmitAt = tick + msToTicks(200)

        synRcvd[tuple] = conn
    }

    // MARK: - Phase 3: Process App Requests

    func processAppRequests() {
        for (tuple, data) in appWrites {
            if let conn = findConn(in: established, closeWait, finWait1, tuple: tuple) {
                _ = conn.writeSendBuf(data)
                conn.lastActivityTick = tick
            }
        }
        for tuple in appCloses {
            if let conn = established[tuple] {
                established[tuple] = nil
                finWait1[tuple] = conn
            } else if let conn = closeWait[tuple] {
                closeWait[tuple] = nil
                lastAck[tuple] = conn
            } else if synSent[tuple] != nil {
                synSent[tuple] = nil
            } else if synRcvd[tuple] != nil {
                synRcvd[tuple] = nil
            }
        }
        appWrites = [:]
        appCloses = []
    }

    // MARK: - Phase 4a: advanceSynSent

    func advanceSynSent() {
        for (tuple, conn) in synSent {
            var acked = false

            for seg in conn.pendingSegs {
                if seg.header.isSYN() && seg.header.isACK() {
                    if seg.header.ackNum != conn.iss + 1 { continue }
                    conn.irs = seg.header.seqNum
                    conn.rcvNxt = seg.header.seqNum + 1
                    conn.sndUna = seg.header.ackNum
                    conn.sndNxt = conn.iss + 1
                    conn.sndWnd = UInt32(seg.header.windowSize)
                    acked = true
                }
            }

            if acked {
                synSent[tuple] = nil
                conn.pendingSegs = conn.pendingSegs.filter { !($0.header.isSYN() && $0.header.isACK()) }
                established[tuple] = conn
                sendACK(conn)
                continue
            }

            if conn.sndNxt == conn.iss {
                sendSYN(conn)
            }
            conn.pendingSegs = []
        }
    }

    // MARK: - Phase 4b: advanceSynRcvd

    func advanceSynRcvd() {
        for (tuple, conn) in synRcvd {
            var acked = false

            for seg in conn.pendingSegs {
                if seg.header.isACK() && seg.header.ackNum == conn.iss + 1 {
                    conn.sndUna = seg.header.ackNum
                    conn.sndNxt = conn.iss + 1
                    acked = true
                }
            }

            if acked {
                synRcvd[tuple] = nil
                conn.pendingSegs = conn.pendingSegs.filter { !($0.header.isACK() && $0.header.ackNum == conn.iss + 1 && $0.payload.isEmpty) }
                established[tuple] = conn
                listener?.onAccept(conn)
                continue
            }

            if conn.sndNxt == conn.iss {
                sendSYNACK(conn)
            }
            conn.pendingSegs = []
        }
    }

    // MARK: - Phase 4c: advanceEstablished

    func advanceEstablished() {
        for (tuple, conn) in established {
            var forward = false

            for seg in conn.pendingSegs {
                if seg.header.isACK() {
                    if seqGT(seg.header.ackNum, conn.sndUna) {
                        conn.ackSendBuf(seg.header.ackNum)
                        if seqGT(conn.sndUna, conn.sndNxt) {
                            conn.sndNxt = conn.sndUna
                        }
                    }
                    if seqGE(seg.header.ackNum, conn.sndUna) {
                        conn.sndWnd = UInt32(seg.header.windowSize) << conn.sndShift
                    }
                }

                if !seg.payload.isEmpty && seg.header.seqNum == conn.rcvNxt {
                    let n = conn.writeRecvBuf(seg.payload)
                    if n > 0 {
                        conn.rcvNxt += UInt32(n)
                    }
                }

                if seg.header.isFIN() {
                    conn.finReceived = true
                    conn.finSeq = seg.header.seqNum + UInt32(seg.payload.count)
                    if conn.finSeq == conn.rcvNxt {
                        conn.rcvNxt = conn.finSeq + 1
                    }
                    forward = true
                }
            }

            if conn.finReceived && !forward {
                if conn.finSeq == conn.rcvNxt {
                    conn.rcvNxt = conn.finSeq + 1
                }
                forward = true
            }

            if forward {
                established[tuple] = nil
                conn.pendingSegs = []
                closeWait[tuple] = conn
                continue
            }

            sendDataAndAcks(conn)
            conn.pendingSegs = []
        }
    }

    // MARK: - Phase 4d: advanceCloseWait

    func advanceCloseWait() {
        for (tuple, conn) in closeWait {
            for seg in conn.pendingSegs {
                if seg.header.isACK() {
                    if seqGT(seg.header.ackNum, conn.sndUna) {
                        conn.ackSendBuf(seg.header.ackNum)
                        if seqGT(conn.sndUna, conn.sndNxt) {
                            conn.sndNxt = conn.sndUna
                        }
                    }
                    if seqGE(seg.header.ackNum, conn.sndUna) {
                        conn.sndWnd = UInt32(seg.header.windowSize) << conn.sndShift
                    }
                }
                if !seg.payload.isEmpty && seg.header.seqNum == conn.rcvNxt {
                    let n = conn.writeRecvBuf(seg.payload)
                    if n > 0 {
                        conn.rcvNxt += UInt32(n)
                    }
                }
            }

            if closeWait[tuple] == nil { continue }

            sendDataAndAcks(conn)
            conn.pendingSegs = []
        }
    }

    // MARK: - Phase 4e: advanceLastAck

    func advanceLastAck() {
        for (tuple, conn) in lastAck {
            var acked = false

            for seg in conn.pendingSegs {
                if seg.header.isACK() && seqGT(seg.header.ackNum, conn.sndUna) {
                    conn.ackSendBuf(seg.header.ackNum)
                    if seqGT(conn.sndUna, conn.sndNxt) {
                        conn.sndNxt = conn.sndUna
                    }
                    if seqGE(seg.header.ackNum, conn.sndNxt) {
                        acked = true
                    }
                }
            }

            if acked {
                lastAck[tuple] = nil
                conn.pendingSegs = []
                continue
            }

            if !conn.finSent {
                sendFIN(conn)
                conn.retransmitAt = tick + msToTicks(200)
                timerWheel.schedule(tuple: conn.tuple, tick: conn.retransmitAt)
            }
            conn.pendingSegs = []
        }
    }

    // MARK: - Phase 4f: advanceFinWait1

    func advanceFinWait1() {
        for (tuple, conn) in finWait1 {
            var hasAckOfFin = false
            var hasPeerFin = false
            var peerFinSeq: UInt32 = 0

            for seg in conn.pendingSegs {
                if seg.header.isACK() {
                    conn.ackSendBuf(seg.header.ackNum)
                    if seqGT(conn.sndUna, conn.sndNxt) {
                        conn.sndNxt = conn.sndUna
                    }
                    if conn.finSent && seqGE(seg.header.ackNum, conn.sndNxt) {
                        hasAckOfFin = true
                    }
                }
                if seg.header.isFIN() {
                    hasPeerFin = true
                    peerFinSeq = seg.header.seqNum + UInt32(seg.payload.count)
                    conn.finReceived = true
                    conn.finSeq = peerFinSeq
                    if conn.finSeq == conn.rcvNxt {
                        conn.rcvNxt = conn.finSeq + 1
                    }
                }
                if !seg.payload.isEmpty && seg.header.seqNum == conn.rcvNxt {
                    let n = conn.writeRecvBuf(seg.payload)
                    if n > 0 {
                        conn.rcvNxt += UInt32(n)
                    }
                }
            }

            if hasPeerFin && hasAckOfFin {
                finWait1[tuple] = nil
                conn.pendingSegs = []
                conn.timeWaitUntil = tick + msToTicks(60000)
                timerWheel.schedule(tuple: conn.tuple, tick: conn.timeWaitUntil)
                timeWait[tuple] = conn
                sendACK(conn)
                continue
            }

            if hasAckOfFin {
                finWait1[tuple] = nil
                conn.pendingSegs = []
                finWait2[tuple] = conn
                if hasPeerFin { sendACK(conn) }
                continue
            }

            if !conn.finSent {
                sendDataAndAcks(conn)
            }
            sendFIN(conn)
            conn.pendingSegs = []
        }
    }

    // MARK: - Phase 4g: advanceFinWait2

    func advanceFinWait2() {
        for (tuple, conn) in finWait2 {
            var forward = false

            for seg in conn.pendingSegs {
                if seg.header.isACK() {
                    conn.ackSendBuf(seg.header.ackNum)
                    if seqGT(conn.sndUna, conn.sndNxt) {
                        conn.sndNxt = conn.sndUna
                    }
                }
                if seg.header.isFIN() {
                    conn.finReceived = true
                    conn.finSeq = seg.header.seqNum + UInt32(seg.payload.count)
                    if conn.finSeq == conn.rcvNxt {
                        conn.rcvNxt = conn.finSeq + 1
                    }
                    forward = true
                }
            }

            if forward {
                finWait2[tuple] = nil
                conn.pendingSegs = []
                conn.timeWaitUntil = tick + msToTicks(60000)
                timerWheel.schedule(tuple: conn.tuple, tick: conn.timeWaitUntil)
                timeWait[tuple] = conn
                sendACK(conn)
                continue
            }

            conn.pendingSegs = []
        }
    }

    // MARK: - Phase 4h: advanceTimeWait

    func advanceTimeWait() {
        // TIME_WAIT entries auto-expire via timer wheel
    }

    // MARK: - Phase 5: Reclaim

    func reclaimClosed() {
        reclaimIdle()
    }

    func reclaimIdle() {
        guard cfg.idleTimeout > 0 else { return }
        let idleTicks = Int64(cfg.idleTimeout / (TimeInterval(timerWheel.slotSize) / 1e9))
        guard idleTicks > 0 else { return }

        synSent = synSent.filter { tick - $0.value.lastActivityTick <= idleTicks }
        synRcvd = synRcvd.filter { tick - $0.value.lastActivityTick <= idleTicks }
        established = established.filter { tick - $0.value.lastActivityTick <= idleTicks }
        closeWait = closeWait.filter { tick - $0.value.lastActivityTick <= idleTicks }
        finWait1 = finWait1.filter { tick - $0.value.lastActivityTick <= idleTicks }
        finWait2 = finWait2.filter { tick - $0.value.lastActivityTick <= idleTicks }
    }

    // MARK: - Output Helpers

    func sendDataAndAcks(_ conn: TCPConn) {
        let mss = cfg.mtu - 20
        let maxSegs = cfg.maxSegsPerTick > 0 ? cfg.maxSegsPerTick : 12
        var sentData = false
        var segCount = 0

        while segCount < maxSegs {
            let inFlight = conn.sndNxt - conn.sndUna
            let window = conn.sndWnd
            var canSend = Int(window) - Int(inFlight)
            if canSend <= 0 { break }
            if canSend > mss { canSend = mss }

            let data = conn.peekSendData(max: canSend)
            if data.isEmpty { break }

            let flags = TCPFlag.ack | TCPFlag.psh
            let win = conn.scaledWindow(syn: false)
            let rawSeg = buildSegment(tuple: conn.tuple, seq: conn.sndNxt, ack: conn.rcvNxt,
                                       flags: flags, window: win, wscale: 0, payload: data)

            let seg = TCPSegment(
                header: TCPHeader(
                    srcPort: conn.tuple.srcPort, dstPort: conn.tuple.dstPort,
                    seqNum: conn.sndNxt, ackNum: conn.rcvNxt,
                    dataOffset: 20, flags: flags,
                    windowSize: win, checksum: 0, urgentPtr: 0
                ),
                payload: data,
                tuple: conn.tuple,
                raw: rawSeg
            )

            if let wf = writeFunc {
                if let err = wf(seg) {
                    break
                }
            } else {
                outputs.append(seg)
            }

            conn.sndNxt += UInt32(data.count)
            sentData = true
            segCount += 1
        }

        if sentData {
            conn.lastAckSent = conn.rcvNxt
            conn.lastAckWin = conn.scaledWindow(syn: false)
            var base: Int64 = 200
            for _ in 0..<min(conn.retransmitCount, 10) { base *= 2 }
            if base > 60000 { base = 60000 }
            conn.retransmitAt = tick + msToTicks(base)
            timerWheel.schedule(tuple: conn.tuple, tick: conn.retransmitAt)
        } else if needACK(conn) {
            sendACK(conn)
        }
    }

    func sendACK(_ conn: TCPConn) {
        let win = conn.scaledWindow(syn: false)
        let rawSeg = buildSegment(tuple: conn.tuple, seq: conn.sndNxt, ack: conn.rcvNxt,
                                   flags: TCPFlag.ack, window: win, wscale: 0, payload: [])

        conn.lastAckSent = conn.rcvNxt
        conn.lastAckTime = tick
        conn.lastAckWin = conn.scaledWindow(syn: false)

        let seg = TCPSegment(
            header: TCPHeader(
                srcPort: conn.tuple.srcPort, dstPort: conn.tuple.dstPort,
                seqNum: conn.sndNxt, ackNum: conn.rcvNxt,
                dataOffset: 20, flags: TCPFlag.ack,
                windowSize: win, checksum: 0, urgentPtr: 0
            ),
            payload: [],
            tuple: conn.tuple,
            raw: rawSeg
        )

        if let wf = writeFunc {
            _ = wf(seg)
        } else {
            outputs.append(seg)
        }
    }

    func sendSYN(_ conn: TCPConn) {
        let win = conn.scaledWindow(syn: true)
        let rawSeg = buildSegmentWithWScale(tuple: conn.tuple, seq: conn.iss, ack: 0,
                                              flags: TCPFlag.syn, window: win,
                                              wscale: conn.rcvShift, payload: [])

        let seg = TCPSegment(
            header: TCPHeader(
                srcPort: conn.tuple.srcPort, dstPort: conn.tuple.dstPort,
                seqNum: conn.iss, ackNum: 0,
                dataOffset: conn.rcvShift > 0 ? 24 : 20, flags: TCPFlag.syn,
                windowSize: win, checksum: 0, urgentPtr: 0
            ),
            payload: [],
            tuple: conn.tuple,
            raw: rawSeg
        )

        if let wf = writeFunc {
            if let _ = wf(seg) { return }
        } else {
            outputs.append(seg)
        }

        conn.sndNxt = conn.iss + 1
        conn.retransmitAt = tick + msToTicks(200)
        timerWheel.schedule(tuple: conn.tuple, tick: conn.retransmitAt)
    }

    func sendSYNACK(_ conn: TCPConn) {
        let win = conn.scaledWindow(syn: true)
        let rawSeg = buildSegmentWithWScale(tuple: conn.tuple, seq: conn.iss, ack: conn.rcvNxt,
                                              flags: TCPFlag.syn | TCPFlag.ack, window: win,
                                              wscale: conn.rcvShift, payload: [])

        let seg = TCPSegment(
            header: TCPHeader(
                srcPort: conn.tuple.srcPort, dstPort: conn.tuple.dstPort,
                seqNum: conn.iss, ackNum: conn.rcvNxt,
                dataOffset: conn.rcvShift > 0 ? 24 : 20,
                flags: TCPFlag.syn | TCPFlag.ack,
                windowSize: win, checksum: 0, urgentPtr: 0
            ),
            payload: [],
            tuple: conn.tuple,
            raw: rawSeg
        )

        if let wf = writeFunc {
            if let _ = wf(seg) { return }
        } else {
            outputs.append(seg)
        }

        conn.sndNxt = conn.iss + 1
        conn.retransmitAt = tick + msToTicks(200)
        timerWheel.schedule(tuple: conn.tuple, tick: conn.retransmitAt)
    }

    func sendFIN(_ conn: TCPConn) {
        let win = conn.scaledWindow(syn: false)
        let rawSeg = buildSegment(tuple: conn.tuple, seq: conn.sndNxt, ack: conn.rcvNxt,
                                   flags: TCPFlag.fin | TCPFlag.ack, window: win, wscale: 0, payload: [])

        let seg = TCPSegment(
            header: TCPHeader(
                srcPort: conn.tuple.srcPort, dstPort: conn.tuple.dstPort,
                seqNum: conn.sndNxt, ackNum: conn.rcvNxt,
                dataOffset: 20, flags: TCPFlag.fin | TCPFlag.ack,
                windowSize: win, checksum: 0, urgentPtr: 0
            ),
            payload: [],
            tuple: conn.tuple,
            raw: rawSeg
        )

        if let wf = writeFunc {
            if let _ = wf(seg) { return }
        } else {
            outputs.append(seg)
        }

        if !conn.finSent {
            conn.sndNxt += 1
        }
        conn.finSent = true
    }

    func needACK(_ conn: TCPConn) -> Bool {
        if conn.rcvNxt != conn.lastAckSent { return true }
        let mss = cfg.mtu - 20
        if Int(conn.lastAckWin) < mss && conn.recvWritable() >= mss { return true }
        return false
    }

    // MARK: - Invariants

    func checkInvariants() {
        let all: [[Tuple: TCPConn]] = [synSent, synRcvd, established, closeWait, lastAck, finWait1, finWait2, timeWait]
        for coll in all {
            for (tuple, conn) in coll {
                if seqGT(conn.sndUna, conn.sndNxt) {
                    fatalError("SND_UNA > SND_NXT in \(tuple)")
                }
                if Int(conn.sndNxt - conn.sndUna) > conn.sendSize + 2 {
                    fatalError("inflight exceeds sendSize+2 in \(tuple)")
                }
                if conn.sendSize < 0 || conn.sendSize > conn.sendBuf.count {
                    fatalError("sendSize out of bounds in \(tuple)")
                }
                if conn.recvSize < 0 || conn.recvSize > conn.recvBuf.count {
                    fatalError("recvSize out of bounds in \(tuple)")
                }
            }
        }
    }
}
