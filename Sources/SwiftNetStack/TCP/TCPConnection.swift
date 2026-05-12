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

    /// True when external side has closed its write side.
    public var externalEOF: Bool
    /// True while the external POSIX socket is performing a non-blocking connect().
    public var externalConnecting: Bool

    /// RFC 1323 window scale shift advertised to the VM (our receive window scale).
    public var ourWindowScale: UInt8 = 6
    /// RFC 1323 window scale shift received from the VM in SYN (their receive window scale).
    public var peerWindowScale: UInt8 = 0

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
    public mutating func writeSendBuf(_ data: UnsafeRawPointer, _ len: Int) -> Int {        guard len > 0, sendQueue.count + len <= Self.maxQueueBytes else { return 0 }
        return sendQueue.enqueue(data, len)
    }

    /// Remove acknowledged data from the front of the send queue.
    public mutating func ackSendBuf(delta: Int) {
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
    public mutating func appendExternalSend(_ data: UnsafeRawPointer, _ len: Int) -> Int {
        guard len > 0, externalSendQueue.count + len <= Self.maxQueueBytes else { return 0 }
        return externalSendQueue.enqueue(data, len)
    }

    /// Remove written bytes from the front of the external send queue.
    public mutating func drainExternalSend(_ delta: Int) {
        externalSendQueue.dequeue(delta)
    }
}
