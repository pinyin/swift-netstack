import Darwin

/// Aggregates all per-connection TCP state for a NAT-proxied connection.
struct TCPConnection {
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

    /// True when external side has closed its write side (read returned 0).
    public var externalEOF: Bool

    /// True while the external POSIX socket is performing a non-blocking connect().
    /// POLLOUT is requested until the connect completes (detected via getpeername).
    public var externalConnecting: Bool

    /// VM→external send queue. Data from VM is buffered here (zero-copy via
    /// appendView) and drained to the external socket by flushOneConnection.
    /// FIN is forwarded only after the queue is fully drained — no timer needed.
    public var externalSendQueue: PacketBuffer = .empty
    public var externalSendQueued: Int = 0

    /// True when the VM sent FIN and it hasn't been forwarded to external yet.
    /// Cleared when the external send queue is drained and shutdown(SHUT_WR)
    /// is called, forwarding FIN to the server identical to how any other TCP
    /// flag would be forwarded.
    public var pendingExternalFin: Bool = false

    /// Whether POLLOUT should be requested for this connection's fd
    /// (only during non-blocking connect).
    public func wantsPOLLOUT() -> Bool { externalConnecting }

    // MARK: - Delayed ACK (RFC 1122 timer-based coalescing)

    /// True when a pure ACK is pending and should be coalesced with the next
    /// outgoing segment or flushed on timer expiry.
    public var pendingDelayedACK: Bool = false
    /// Deadline (monotonic µs) after which this ACK must be sent.
    public var delayedACKDeadline: UInt64 = 0
    /// Saved sequence number for the deferred ACK.
    public var delayedACKSeq: UInt32 = 0
    /// Saved acknowledgment number for the deferred ACK.
    public var delayedACKAck: UInt32 = 0
    /// Saved receive window for the deferred ACK.
    public var delayedACKWindow: UInt16 = 65535

    // MARK: - ACK frame template (pre-built 54-byte frame)

    /// Pre-built Ethernet+IPv4+TCP header for pure ACK frames.
    /// Contains all static fields; only seq, ack, and checksum are overwritten at send time.
    public var ackTemplate: [UInt8]? = nil

    // MARK: - Incremental TCP checksum cache (RFC 1146)

    /// Cached checksum of the last sent pure ACK frame.
    public var lastACKChecksum: UInt16 = 0
    /// Sequence number of the last sent pure ACK frame.
    public var lastACKSeq: UInt32 = 0
    /// Acknowledgment number of the last sent pure ACK frame.
    public var lastACKAck: UInt32 = 0
    /// Receive window of the last sent pure ACK frame.
    public var lastACKWindow: UInt16 = 0
    /// True when lastACK{Checksum,Seq,Ack,Window} are valid for incremental update.
    public var ackChecksumValid: Bool = false

    // MARK: - Send queue (external→VM data queued for zero-copy transmission)

    /// Queued PacketBuffers from external recv(), sharing Storage via ARC.
    /// Appended via writeSendBuf, drained via ackSendBuf, peeked via peekSendData.
    public var sendQueue: PacketBuffer = .empty
    public var totalQueuedBytes: Int = 0
    public var sendQueueSent: Int = 0
    public static let maxQueueBytes: Int = 256 * 1024

    /// True when the send queue is full and the external socket should not be
    /// read from until the queue drains. Cleared by the flush when space opens.
    public var sendQueueBlocked: Bool = false

    public var sendAvail: Int { totalQueuedBytes }
    public var sendSpace: Int { max(0, Self.maxQueueBytes - totalQueuedBytes) }

    public init(
        connectionID: UInt64,
        posixFD: Int32,
        state: TCPState,
        vmMAC: MACAddress,
        vmIP: IPv4Address,
        vmPort: UInt16,
        dstIP: IPv4Address,
        dstPort: UInt16,
        endpointID: Int,
        hostMAC: MACAddress
    ) {
        self.connectionID = connectionID
        self.posixFD = posixFD
        self.state = state
        self.snd = SendSequence(nxt: 0, una: 0, wnd: 65535)
        self.rcv = RecvSequence(nxt: 0, initialSeq: 0)
        self.vmMAC = vmMAC
        self.vmIP = vmIP
        self.vmPort = vmPort
        self.dstIP = dstIP
        self.dstPort = dstPort
        self.endpointID = endpointID
        self.hostMAC = hostMAC
        self.externalEOF = false
        self.externalConnecting = false
    }

    // MARK: - Send queue operations (zero-copy)

    /// Append a PacketBuffer to the send queue. Shares Storage via ARC — no copy.
    /// Returns bytes queued, or 0 if backpressure threshold exceeded.
    @discardableResult
    public mutating func writeSendBuf(_ pkt: PacketBuffer) -> Int {
        let n = pkt.totalLength
        guard n > 0 else { return 0 }
        guard totalQueuedBytes + n <= Self.maxQueueBytes else { return 0 }
        sendQueue.appendView(pkt)
        totalQueuedBytes += n
        return n
    }

    /// Remove acknowledged data from the front of the send queue (zero-copy).
    public mutating func ackSendBuf(delta: Int) {
        var d = delta
        if d > totalQueuedBytes { d = totalQueuedBytes }
        guard d > 0 else { return }
        sendQueue.trimFront(d)
        totalQueuedBytes -= d
        if d > sendQueueSent {
            sendQueueSent = 0
        } else {
            sendQueueSent -= d
        }
    }

    /// Peek up to `max` bytes of unsent data from the send queue.
    /// Returns a zero-copy PacketBuffer slice sharing Storage with the queue.
    public func peekSendData(max: Int) -> PacketBuffer? {
        let remaining = totalQueuedBytes - sendQueueSent
        guard remaining > 0, max > 0 else { return nil }
        var n = remaining
        if n > max { n = max }
        return sendQueue.slice(from: sendQueueSent, length: n)
    }

    // MARK: - External send queue (VM→external, zero-copy)

    /// Append VM→external data to the send queue (zero-copy via appendView).
    /// Returns bytes queued, or 0 if the queue is at capacity.
    @discardableResult
    public mutating func appendExternalSend(_ pkt: PacketBuffer) -> Int {
        let n = pkt.totalLength
        guard n > 0 else { return 0 }
        guard externalSendQueued + n <= Self.maxQueueBytes else { return 0 }
        externalSendQueue.appendView(pkt)
        externalSendQueued += n
        return n
    }

    /// Remove written bytes from the front of the external send queue.
    public mutating func drainExternalSend(_ delta: Int) {
        var d = delta
        if d > externalSendQueued { d = externalSendQueued }
        guard d > 0 else { return }
        externalSendQueue.trimFront(d)
        externalSendQueued -= d
    }
}
