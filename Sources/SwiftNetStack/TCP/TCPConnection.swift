import Darwin

/// Aggregates all per-connection TCP state for a NAT-proxied connection.
final class TCPConnection {
    public let connectionID: UInt64
    public let posixFD: Int32
    public var state: TCPState
    public var snd: SendSequence
    public var rcv: RecvSequence

    public let vmMAC: MACAddress
    public let vmIP: IPv4Address
    public let vmPort: UInt16
    public let dstIP: IPv4Address
    public let dstPort: UInt16
    public let endpointID: Int
    public let hostMAC: MACAddress

    /// True when external side has closed its write side.
    public var externalEOF: Bool
    /// True while the external POSIX socket is performing a non-blocking connect().
    public var externalConnecting: Bool

    /// RFC 1323 window scale shift advertised to the VM (our receive window scale).
    public var ourWindowScale: UInt8 = 6
    /// RFC 1323 window scale shift received from the VM in SYN (their receive window scale).
    public var peerWindowScale: UInt8 = 0

    // MARK: - RFC 2018 SACK

    /// True when peer advertised SACK-Permitted option.
    public var sackOK: Bool = false
    /// Always true — we always advertise SACK-Permitted in SYN/SYN-ACK.
    public var ourSackOK: Bool = true
    /// SACK scoreboard tracking out-of-order data.
    public var sackBlocks: SACKScoreboard = .init()

    // MARK: - RFC 5681 Fast Retransmit

    /// Count of consecutive duplicate ACKs received (same ack number, no data).
    /// Reset to 0 whenever snd.una advances. Fast retransmit triggers at 3.
    public var dupAckCount: UInt8 = 0
    /// The last ACK value received (to detect duplicates).
    public var lastAckValue: UInt32 = 0

    // MARK: - RFC 7323 Timestamps

    /// True when TSopt negotiated (both sides sent TSopt during handshake).
    public var tsOK: Bool = false
    /// Always true — we always advertise TSopt in SYN/SYN-ACK.
    public var ourTSOK: Bool = true
    /// TSval from the most recent valid segment (for PAWS).
    public var tsRecent: UInt32 = 0
    /// Monotonic timestamp when tsRecent was recorded (for PAWS age check).
    public var tsRecentAge: UInt64 = 0

    // MARK: - Extended ACK template (66-byte, with NOP+NOP+TSopt)

    /// 66-byte ACK template: Ethernet(14) + IPv4(20) + TCP(32=20+12).
    /// TCP header includes NOP(1)+NOP(1)+TSopt(kind=8,len=10,TSval,Tsecr).
    public var ackTemplateExt: [UInt8]? = nil

    /// VM→external send queue.
    public var externalSendQueue: SendQueue
    /// True when the VM sent FIN and it hasn't been forwarded to external yet.
    public var pendingExternalFin: Bool = false
    /// True when external→VM FIN needs to be sent after sendQueue drains.
    /// Set by handleTCPExternalFIN when inline write hits EAGAIN/ENOBUFS.
    public var pendingFinToVM: Bool = false

    /// Whether POLLOUT should be requested for this connection's fd.
    public func wantsPOLLOUT() -> Bool { externalConnecting || externalSendQueued > 0 }

    // MARK: - Delayed ACK

    public var pendingDelayedACK: Bool = false
    public var delayedACKDeadline: UInt64 = 0
    public var delayedACKSeq: UInt32 = 0
    public var delayedACKAck: UInt32 = 0
    public var delayedACKWindow: UInt32 = 262144

    // MARK: - ACK frame template

    public var ackTemplate: [UInt8]? = nil

    // MARK: - Incremental TCP checksum cache

    public var lastACKChecksum: UInt16 = 0
    public var lastACKSeq: UInt32 = 0
    public var lastACKAck: UInt32 = 0
    public var lastACKWindow: UInt16 = 0
    public var ackChecksumValid: Bool = false

    // MARK: - Send queue (external→VM data)

    public var sendQueue: SendQueue
    public var sendQueueSent: Int = 0
    public static let maxQueueBytes: Int = 4 * 1024 * 1024

    /// True when the send queue is full and the external socket should not be
    /// read from until the queue drains.
    public var sendQueueBlocked: Bool = false

    public var totalQueuedBytes: Int { sendQueue.count }

    /// Bytes queued in the external (VM→external) send queue.
    public var externalSendQueued: Int { externalSendQueue.count }

    /// Available receive window to advertise to the VM, derived from external
    /// send queue headroom. Advertises 0 when the queue is full so the VM
    /// pauses via standard TCP flow control instead of seeing packet loss.
    public var availableWindow: UInt32 {
        let used = UInt32(externalSendQueued)
        let maxQ = UInt32(Self.maxQueueBytes)
        if used >= maxQ { return 0 }
        return min(maxQ - used, 262144)
    }

    /// Last logical availableWindow we advertised to the VM.
    /// Tracked so we can send a window update when the queue drains.
    public var lastAdvertisedWindow: UInt32 = 262144

    // MARK: - RFC 6298 RTO (Retransmission Timeout)

    /// Current RTO value in microseconds. Initial 1 second per RFC 6298 §2.
    public var rtoValue: UInt64 = 1_000_000
    /// Monotonic-µs deadline when RTO next fires. 0 when timer is not armed.
    public var rtoDeadline: UInt64 = 0
    /// Number of consecutive RTO expirations without new data ACKed.
    public var rtoBackoffCount: UInt8 = 0
    /// Smoothed RTT estimate in microseconds (RFC 6298 §2).
    public var srtt: UInt64 = 0
    /// RTT variance estimate in microseconds (RFC 6298 §2).
    public var rttvar: UInt64 = 0
    /// Monotonic-µs timestamp when the first unacked data was sent (for RTT sample).
    public var rtoSendTime: UInt64 = 0
    /// snd.nxt at the time rtoSendTime was recorded. When snd.una passes this,
    /// we have a valid RTT sample.
    public var rtoMeasuredSeq: UInt32 = 0
    /// True when the outstanding send is a retransmission (Karn's algorithm).
    public var rtoIsRetransmit: Bool = false

    // MARK: - Persist timer (RFC 1122 §4.2.2.17)

    /// Persist timer deadline in monotonic microseconds. 0 = not armed.
    /// Armed when the receiver window is zero and we have data to send.
    public var persistDeadline: UInt64 = 0
    /// Number of consecutive persist timer expirations (exponential backoff).
    public var persistBackoffCount: UInt8 = 0

    public init(
        connectionID: UInt64, posixFD: Int32, state: TCPState,
        vmMAC: MACAddress, vmIP: IPv4Address, vmPort: UInt16,
        dstIP: IPv4Address, dstPort: UInt16, endpointID: Int,
        hostMAC: MACAddress, mss: Int = 1460
    ) {
        self.connectionID = connectionID
        self.posixFD = posixFD
        self.state = state
        self.snd = SendSequence(nxt: 0, una: 0, wnd: 65535)
        self.rcv = RecvSequence(nxt: 0, initialSeq: 0)
        self.vmMAC = vmMAC; self.vmIP = vmIP; self.vmPort = vmPort
        self.dstIP = dstIP; self.dstPort = dstPort
        self.endpointID = endpointID
        self.hostMAC = hostMAC
        self.externalEOF = false
        self.externalConnecting = false
        self.sendQueue = SendQueue(capacity: Self.maxQueueBytes)
        self.externalSendQueue = SendQueue(capacity: Self.maxQueueBytes)
    }

    deinit {
        sendQueue.free()
        externalSendQueue.free()
        for seg in oooSegments { seg.base.deallocate() }
    }

    // MARK: - Send queue operations

    /// Enqueue data from external recv(). Returns bytes queued, or 0 if full.
    @discardableResult
    public func writeSendBuf(_ data: UnsafeRawPointer, _ len: Int) -> Int {        guard len > 0, sendQueue.count + len <= Self.maxQueueBytes else { return 0 }
        return sendQueue.enqueue(data, len)
    }

    /// Remove acknowledged data from the front of the send queue.
    public func ackSendBuf(delta: Int) {
        sendQueue.dequeue(delta)
        if delta > sendQueueSent {
            sendQueueSent = 0
        } else {
            sendQueueSent -= delta
        }
    }

    /// Peek up to `max` bytes of unsent data. Returns pointer and length (always contiguous).
    /// Accounts for sendQueueSent to skip bytes already passed to sendmsg but not yet dequeued.
    public func peekSendData(max: Int) -> (ptr: UnsafeRawPointer, len: Int)? {
        let remaining = sendQueue.count - sendQueueSent
        guard remaining > 0, max > 0 else { return nil }
        let n = Swift.min(remaining, max)
        let ptr = UnsafeRawPointer(sendQueue.buf.baseAddress! + sendQueue.readPos + sendQueueSent)
        return (ptr, n)
    }

    /// Peek the first unacknowledged byte(s) for retransmission (RFC 5681).
    /// Ignores sendQueueSent — always reads from readPos, which corresponds
    /// to snd.una. Returns at most `max` bytes.
    public func peekRetransmitData(max: Int) -> (ptr: UnsafeRawPointer, len: Int)? {
        let n = Swift.min(sendQueue.count, max)
        guard n > 0 else { return nil }
        return (UnsafeRawPointer(sendQueue.buf.baseAddress! + sendQueue.readPos), n)
    }

    // MARK: - External send queue (VM→external)

    /// Enqueue VM→external data. Returns bytes queued, or 0 if full.
    @discardableResult
    public func appendExternalSend(_ data: UnsafeRawPointer, _ len: Int) -> Int {
        guard len > 0, externalSendQueue.count + len <= Self.maxQueueBytes else { return 0 }
        return externalSendQueue.enqueue(data, len)
    }

    /// Remove written bytes from the front of the external send queue.
    public func drainExternalSend(_ delta: Int) {
        externalSendQueue.dequeue(delta)
    }

    // MARK: - Reassembly buffer (out-of-order VM→external data)

    /// Sorted list of out-of-order segments awaiting gap fill.
    /// Each segment owns a separately allocated buffer to avoid data copies
    /// during overlap resolution. Adjacent segments are NOT merged —
    /// drainOOO drains them sequentially into the external send queue.
    ///
    /// Layout: (seq, base: allocated pointer, offset: within allocation, len: valid bytes)
    var oooSegments: [(seq: UInt32, base: UnsafeMutableRawPointer, offset: Int, len: Int)] = []
    var oooTotalBytes: Int = 0
    static let oooMaxBytes: Int = 256 * 1024

    /// Buffer an out-of-order segment. Data is copied into an owned buffer.
    /// Overlaps are resolved by trimming; adjacent segments are merged.
    /// Returns true if buffered, false if the buffer is full.
    func bufferOOO(seq: UInt32, data: UnsafeRawPointer, len: Int) -> Bool {
        guard len > 0, oooTotalBytes + len <= Self.oooMaxBytes else { return false }
        let endSeq = seq &+ UInt32(len)
        guard endSeq > seq else { return false }

        let base = UnsafeMutableRawPointer.allocate(byteCount: len, alignment: 1)
        base.copyMemory(from: data, byteCount: len)
        insertOOO(seq: seq, base: base, offset: 0, len: len)
        return true
    }

    /// Insert a segment into the sorted OOO list.
    /// Resolves overlaps by trimming; merges adjacent segments into a single buffer.
    private func insertOOO(seq: UInt32, base: UnsafeMutableRawPointer, offset: Int, len: Int) {
        var seq = seq
        var offset = offset
        var len = len
        let endSeq = seq &+ UInt32(len)

        // Find insertion index (maintain sort by seq)
        var idx = 0
        while idx < oooSegments.count && oooSegments[idx].seq < seq { idx += 1 }

        // Remove any existing segments fully contained within the new segment
        while idx < oooSegments.count, oooSegments[idx].seq >= seq,
              oooSegments[idx].seq &+ UInt32(oooSegments[idx].len) <= endSeq {
            oooTotalBytes -= oooSegments[idx].len
            oooSegments[idx].base.deallocate()
            oooSegments.remove(at: idx)
        }

        // Trim overlap with previous segment (new starts within previous)
        if idx > 0 {
            let prevEnd = oooSegments[idx - 1].seq &+ UInt32(oooSegments[idx - 1].len)
            if seq < prevEnd {
                let overlap = Int(prevEnd &- seq)
                seq = prevEnd
                offset += overlap
                len -= overlap
                guard len > 0 else { base.deallocate(); return }
            }
        }

        // Trim overlap with next segment (new extends into next)
        if idx < oooSegments.count {
            let nextSeq = oooSegments[idx].seq
            if endSeq > nextSeq {
                let overlap = Int(endSeq &- nextSeq)
                if overlap >= len { base.deallocate(); return }

                len -= overlap
                // If next is fully contained in the new segment, remove it
                if oooSegments[idx].seq &+ UInt32(oooSegments[idx].len) <= endSeq {
                    oooTotalBytes -= oooSegments[idx].len
                    oooSegments[idx].base.deallocate()
                    oooSegments.remove(at: idx)
                }
            }
        }

        guard len > 0 else { base.deallocate(); return }

        // Merge with previous segment if adjacent (seq == prevEnd).
        var merged = false
        if idx > 0 {
            let prev = oooSegments[idx - 1]
            let prevEnd = prev.seq &+ UInt32(prev.len)
            if seq == prevEnd {
                let mergedLen = prev.len + len
                let buf = UnsafeMutableRawPointer.allocate(byteCount: mergedLen, alignment: 1)
                buf.copyMemory(from: prev.base + prev.offset, byteCount: prev.len)
                (buf + prev.len).copyMemory(from: base + offset, byteCount: len)
                prev.base.deallocate()
                base.deallocate()
                oooSegments[idx - 1] = (prev.seq, buf, 0, mergedLen)

                // If now adjacent to next segment, merge again (three-way).
                let mergedEnd = prev.seq &+ UInt32(mergedLen)
                if idx < oooSegments.count, mergedEnd == oooSegments[idx].seq {
                    let next = oooSegments[idx]
                    let tripleLen = mergedLen + next.len
                    let triple = UnsafeMutableRawPointer.allocate(byteCount: tripleLen, alignment: 1)
                    triple.copyMemory(from: buf, byteCount: mergedLen)
                    (triple + mergedLen).copyMemory(from: next.base + next.offset, byteCount: next.len)
                    buf.deallocate()
                    next.base.deallocate()
                    oooSegments[idx - 1] = (prev.seq, triple, 0, tripleLen)
                    oooSegments.remove(at: idx)
                }
                merged = true
            }
        }

        // Merge with next segment if adjacent (endSeq == nextSeq).
        if !merged, idx < oooSegments.count {
            let next = oooSegments[idx]
            if endSeq == next.seq {
                let mergedLen = len + next.len
                let buf = UnsafeMutableRawPointer.allocate(byteCount: mergedLen, alignment: 1)
                buf.copyMemory(from: base + offset, byteCount: len)
                (buf + len).copyMemory(from: next.base + next.offset, byteCount: next.len)
                base.deallocate()
                next.base.deallocate()
                oooSegments[idx] = (seq, buf, 0, mergedLen)
                merged = true
            }
        }

        if !merged {
            oooSegments.insert((seq, base, offset, len), at: idx)
        }
        oooTotalBytes += len
    }

    /// Discard or trim buffered segments that are now behind rcv.nxt
    /// (already delivered via a gap-filling segment that partially overlapped).
    func trimOOO(rcvNxt: UInt32) {
        while !oooSegments.isEmpty && oooSegments[0].seq < rcvNxt {
            let segEnd = oooSegments[0].seq &+ UInt32(oooSegments[0].len)
            if segEnd <= rcvNxt {
                oooTotalBytes -= oooSegments[0].len
                oooSegments[0].base.deallocate()
                oooSegments.removeFirst()
            } else {
                let overlap = Int(rcvNxt &- oooSegments[0].seq)
                oooTotalBytes -= oooSegments[0].len
                oooSegments[0].seq = rcvNxt
                oooSegments[0].offset += overlap
                oooSegments[0].len -= overlap
                oooTotalBytes += oooSegments[0].len
                break
            }
        }
    }

    /// Drain contiguous OOO segments starting at rcv.nxt into externalSendQueue.
    /// Each segment's data is copied directly from its buffer to the send queue
    /// (eliminating the intermediate [UInt8] array from the old design).
    /// Updates rcv.nxt. Returns bytes drained, 0 if nothing to drain.
    @discardableResult
    func drainOOO() -> Int {
        guard !oooSegments.isEmpty, oooSegments[0].seq == rcv.nxt else { return 0 }
        var total = 0
        while !oooSegments.isEmpty && oooSegments[0].seq == rcv.nxt {
            let seg = oooSegments[0]
            let written = externalSendQueue.enqueue(seg.base + seg.offset, seg.len)
            total += written
            rcv.nxt = rcv.nxt &+ UInt32(written)
            if written < seg.len {
                // Partial write — keep remainder in OOO buffer
                oooSegments[0].offset += written
                oooSegments[0].len -= written
                oooTotalBytes -= written
                break
            }
            oooTotalBytes -= seg.len
            seg.base.deallocate()
            oooSegments.removeFirst()
        }
        return total
    }
}
