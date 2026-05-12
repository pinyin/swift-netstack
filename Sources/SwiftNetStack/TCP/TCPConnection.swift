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

    public init(
        connectionID: UInt64, posixFD: Int32, state: TCPState,
        vmMAC: MACAddress, vmIP: IPv4Address, vmPort: UInt16,
        dstIP: IPv4Address, dstPort: UInt16, endpointID: Int,
        hostMAC: MACAddress
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
}
