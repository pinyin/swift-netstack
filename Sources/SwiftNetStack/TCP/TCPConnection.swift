import Darwin

// MARK: - RFC 2018 SACK scoreboard (inline, zero heap allocation)

/// Fixed-capacity SACK scoreboard — 4 blocks max, no heap allocation.
/// Blocks are sorted by left edge (ascending).
struct SACKScoreboard {
    var count: UInt8 = 0
    var l0: UInt32 = 0; var l1: UInt32 = 0; var l2: UInt32 = 0; var l3: UInt32 = 0
    var r0: UInt32 = 0; var r1: UInt32 = 0; var r2: UInt32 = 0; var r3: UInt32 = 0

    private func leftAt(_ i: Int) -> UInt32 {
        switch i {
        case 0: return l0; case 1: return l1
        case 2: return l2; case 3: return l3
        default: return 0
        }
    }
    private func rightAt(_ i: Int) -> UInt32 {
        switch i {
        case 0: return r0; case 1: return r1
        case 2: return r2; case 3: return r3
        default: return 0
        }
    }
    private mutating func setAt(_ i: Int, _ l: UInt32, _ r: UInt32) {
        switch i {
        case 0: l0 = l; r0 = r
        case 1: l1 = l; r1 = r
        case 2: l2 = l; r2 = r
        case 3: l3 = l; r3 = r
        default: break
        }
    }

    /// Record a newly received out-of-order data block.
    mutating func record(_ left: UInt32, _ right: UInt32) {
        guard right > left else { return }
        let n = Int(count)

        // Try to merge with an existing block
        for i in 0..<n {
            let bl = leftAt(i), br = rightAt(i)
            if left <= br && right >= bl {
                setAt(i, min(bl, left), max(br, right))
                mergeAdjacent()
                return
            }
        }

        // Insert new block, maintaining sort by left edge
        if n < 4 {
            var ins = 0
            while ins < n && leftAt(ins) < left { ins += 1 }
            var j = n - 1
            while j >= ins { setAt(j + 1, leftAt(j), rightAt(j)); j -= 1 }
            setAt(ins, left, right)
            count = UInt8(n + 1)
        } else if left > leftAt(0) {
            // Full — discard oldest (lowest left edge), insert newer
            var ins = 1
            while ins < 4 && leftAt(ins) < left { ins += 1 }
            var j = 1
            while j < ins { setAt(j - 1, leftAt(j), rightAt(j)); j += 1 }
            setAt(ins - 1, left, right)
        }
    }

    private mutating func mergeAdjacent() {
        var n = Int(count)
        var i = 0
        while i < n - 1 {
            if rightAt(i) >= leftAt(i + 1) {
                setAt(i, leftAt(i), max(rightAt(i), rightAt(i + 1)))
                var j = i + 1
                while j < n - 1 { setAt(j, leftAt(j + 1), rightAt(j + 1)); j += 1 }
                n -= 1
                count = UInt8(n)
            } else { i += 1 }
        }
    }

    /// Call `body` for each block, most recent first (RFC 2018 order).
    func forEachBlock(_ body: (UInt32, UInt32) -> Void) {
        let n = Int(count)
        var i = n - 1
        while i >= 0 { body(leftAt(i), rightAt(i)); i -= 1 }
    }

    /// Build SACK option bytes (kind=5, len=2+8*N, N blocks) for TCP header.
    /// Returns empty array when no blocks are recorded.
    func buildSACKOption() -> [UInt8] {
        let n = Int(count)
        guard n > 0 else { return [] }
        let optLen = 2 + n * 8
        var opt = [UInt8](repeating: 0, count: optLen)
        opt[0] = 5  // SACK kind
        opt[1] = UInt8(optLen)
        // RFC 2018: blocks in most-recent-first order
        for i in 0..<n {
            let base = 2 + i * 8
            let bi = n - 1 - i  // most recent first
            writeUInt32BE(leftAt(bi), to: &opt[base])
            writeUInt32BE(rightAt(bi), to: &opt[base + 4])
        }
        return opt
    }

    func isSacked(_ seq: UInt32) -> Bool {
        let n = Int(count)
        for i in 0..<n where seq >= leftAt(i) && seq < rightAt(i) { return true }
        return false
    }

    /// Left edge of the first SACK block at or after `seq`, or nil if none.
    func firstSackedAfter(from seq: UInt32) -> UInt32? {
        let n = Int(count)
        var result: UInt32? = nil
        for i in 0..<n {
            let l = leftAt(i)
            if l >= seq, result == nil || l < result! { result = l }
        }
        return result
    }

    /// Remove blocks fully before `seq` (acknowledged data).
    mutating func ackThrough(_ seq: UInt32) {
        let n = Int(count)
        var start = 0
        while start < n && leftAt(start) < seq { start += 1 }
        guard start > 0 else { return }
        let remaining = n - start
        for i in 0..<remaining { setAt(i, leftAt(start + i), rightAt(start + i)) }
        for i in remaining..<n { setAt(i, 0, 0) }
        count = UInt8(remaining)
    }

    mutating func clear() { count = 0; l0 = 0; r0 = 0; l1 = 0; r1 = 0; l2 = 0; r2 = 0; l3 = 0; r3 = 0 }
}

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
    public static let maxQueueBytes: Int = 256 * 1024

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

    public init(
        connectionID: UInt64, posixFD: Int32, state: TCPState,
        vmMAC: MACAddress, vmIP: IPv4Address, vmPort: UInt16,
        dstIP: IPv4Address, dstPort: UInt16, endpointID: Int,
        hostMAC: MACAddress, mss: Int = 1460
    ) {
        self.connectionID = connectionID
        self.posixFD = posixFD
        self.state = state
        let iw = UInt32(min(4 * mss, max(2 * mss, 4380)))
        self.snd = SendSequence(nxt: 0, una: 0, wnd: 65535, cwnd: iw)
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
    /// Each entry is (seq, data). When a segment arrives that fills the gap at
    /// rcv.nxt, all contiguous buffered segments are drained and delivered
    /// to the external send queue in order.
    var oooSegments: [(seq: UInt32, data: [UInt8])] = []
    var oooTotalBytes: Int = 0
    static let oooMaxBytes: Int = 256 * 1024

    /// Buffer an out-of-order segment. Overlapping segments are merged.
    /// Returns true if buffered, false if the buffer is full.
    func bufferOOO(seq: UInt32, data: UnsafeRawPointer, len: Int) -> Bool {
        guard len > 0, oooTotalBytes + len <= Self.oooMaxBytes else { return false }
        let bytes = [UInt8](UnsafeRawBufferPointer(start: data, count: len))
        return _bufferOOO(seq: seq, bytes: bytes)
    }

    private func _bufferOOO(seq: UInt32, bytes: [UInt8]) -> Bool {
        let endSeq = seq &+ UInt32(bytes.count)
        guard endSeq > seq else { return false }

        // Find insertion index (maintain sort by seq)
        var idx = 0
        while idx < oooSegments.count && oooSegments[idx].seq < seq { idx += 1 }

        // Consume any fully-contained existing segments (must start at or after new seq)
        while idx < oooSegments.count && oooSegments[idx].seq >= seq && oooSegments[idx].seq &+ UInt32(oooSegments[idx].data.count) <= endSeq {
            oooTotalBytes -= oooSegments[idx].data.count
            oooSegments.remove(at: idx)
        }

        // Merge with previous if overlapping
        if idx > 0 {
            let prevEnd = oooSegments[idx - 1].seq &+ UInt32(oooSegments[idx - 1].data.count)
            if seq <= prevEnd {
                // Extend previous segment if new data goes beyond it
                if endSeq > prevEnd {
                    let overlap = Int(prevEnd &- seq)
                    let extra = bytes[overlap...]
                    oooSegments[idx - 1].data.append(contentsOf: extra)
                    oooTotalBytes += extra.count
                }
                // Check if this merged segment now overlaps with next
                let newEnd = oooSegments[idx - 1].seq &+ UInt32(oooSegments[idx - 1].data.count)
                while idx < oooSegments.count && oooSegments[idx].seq <= newEnd {
                    let nextEnd = oooSegments[idx].seq &+ UInt32(oooSegments[idx].data.count)
                    if nextEnd > newEnd {
                        let overlap = Int(newEnd &- oooSegments[idx].seq)
                        let extra = oooSegments[idx].data[overlap...]
                        oooSegments[idx - 1].data.append(contentsOf: extra)
                        oooTotalBytes += extra.count
                    }
                    oooTotalBytes -= oooSegments[idx].data.count
                    oooSegments.remove(at: idx)
                }
                return true
            }
        }

        // Merge with next if overlapping
        if idx < oooSegments.count && endSeq >= oooSegments[idx].seq {
            let nextStart = oooSegments[idx].seq
            let nextEnd = nextStart &+ UInt32(oooSegments[idx].data.count)
            if endSeq < nextEnd {
                // Trim new data to not overlap next segment
                let keep = Int(nextStart &- seq)
                if keep <= 0 { return true }
                oooSegments.insert((seq, Array(bytes[0..<keep])), at: idx)
                oooTotalBytes += keep
            } else {
                // New data completely covers next segment(s) — replace
                oooTotalBytes -= oooSegments[idx].data.count
                oooSegments[idx] = (seq, bytes)
                oooTotalBytes += bytes.count
                // Merge any subsequent segments covered by this one
                let finalEnd = seq &+ UInt32(bytes.count)
                let j = idx + 1
                while j < oooSegments.count && oooSegments[j].seq &+ UInt32(oooSegments[j].data.count) <= finalEnd {
                    oooTotalBytes -= oooSegments[j].data.count
                    oooSegments.remove(at: j)
                }
                if j < oooSegments.count && oooSegments[j].seq <= finalEnd {
                    let overlap = Int(finalEnd &- oooSegments[j].seq)
                    if overlap < oooSegments[j].data.count {
                        let extra = oooSegments[j].data[overlap...]
                        oooSegments[idx].data.append(contentsOf: extra)
                        oooTotalBytes += extra.count
                    }
                    oooTotalBytes -= oooSegments[j].data.count
                    oooSegments.remove(at: j)
                }
            }
            return true
        }

        // No overlap — insert as new segment
        oooSegments.insert((seq, bytes), at: idx)
        oooTotalBytes += bytes.count
        return true
    }

    /// Discard or trim buffered segments that are now behind rcv.nxt
    /// (already delivered via a gap-filling segment that partially overlapped).
    func trimOOO(rcvNxt: UInt32) {
        while !oooSegments.isEmpty && oooSegments[0].seq < rcvNxt {
            let segEnd = oooSegments[0].seq &+ UInt32(oooSegments[0].data.count)
            if segEnd <= rcvNxt {
                oooTotalBytes -= oooSegments[0].data.count
                oooSegments.removeFirst()
            } else {
                let overlap = Int(rcvNxt &- oooSegments[0].seq)
                let trimmed = Array(oooSegments[0].data[overlap...])
                oooTotalBytes -= oooSegments[0].data.count
                oooSegments[0].seq = rcvNxt
                oooSegments[0].data = trimmed
                oooTotalBytes += trimmed.count
                break
            }
        }
    }

    /// Drain contiguous segments starting at rcv.nxt.
    /// Returns the concatenated data and new rcv.nxt, or nil if no data is contiguous.
    func drainOOO(rcvNxt: UInt32) -> (data: [UInt8], newNxt: UInt32)? {
        guard !oooSegments.isEmpty, oooSegments[0].seq == rcvNxt else { return nil }
        var result: [UInt8] = []
        var nxt = rcvNxt
        while !oooSegments.isEmpty && oooSegments[0].seq == nxt {
            let seg = oooSegments.removeFirst()
            oooTotalBytes -= seg.data.count
            result.append(contentsOf: seg.data)
            nxt = nxt &+ UInt32(seg.data.count)
        }
        return (result, nxt)
    }
}
