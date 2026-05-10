import Darwin

private let defaultSendBufSize = 256 * 1024

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

    /// True when external side has closed its write side (read returned 0).
    public var externalEOF: Bool

    /// True while the external POSIX socket is performing a non-blocking connect().
    /// POLLOUT is requested until the connect completes (detected via getpeername).
    public var externalConnecting: Bool

    /// Explicit FIN buffering model: tracks rounds since VM sent FIN (closeWait)
    /// before forwarding to the external socket via shutdown(SHUT_WR).
    /// - 0: no pending FIN (or FIN already forwarded / external closed first)
    /// - >0: counting rounds, FIN not yet forwarded
    /// Set when closeWait is entered; reset when FIN is forwarded or connection closes.
    public var finWaitRounds: Int = 0

    /// True when the external server has sent data since the VM sent FIN.
    /// Indicates the server is responsive — safe to forward FIN without
    /// breaking the response path.
    public var externalResponded: Bool = false

    /// Whether POLLOUT should be requested for this connection's fd.
    public func wantsPOLLOUT() -> Bool { externalConnecting }

    // MARK: - Send buffer (external→VM data queued for transmission + retransmit)

    public var sendBuf: [UInt8]
    public var sendHead: Int = 0
    public var sendTail: Int = 0
    public var sendSize: Int = 0

    public var retransmitAt: UInt64 = 0
    public var retransmitCount: Int = 0

    public var sendAvail: Int { sendSize }
    public var sendSpace: Int { sendBuf.count - sendSize }

    public init(
        connectionID: UInt64,
        posixFD: Int32,
        state: TCPState,
        vmMAC: MACAddress,
        vmIP: IPv4Address,
        vmPort: UInt16,
        dstIP: IPv4Address,
        dstPort: UInt16,
        endpointID: Int
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
        self.externalEOF = false
        self.externalConnecting = false
        self.sendBuf = [UInt8](repeating: 0, count: defaultSendBufSize)
    }

    // MARK: - Send buffer operations

    /// Write data from an array into the send buffer. Returns bytes written.
    @discardableResult
    public mutating func writeSendBuf(_ data: [UInt8]) -> Int {
        data.withUnsafeBytes { writeSendBuf(ptr: $0.baseAddress!, count: data.count) }
    }

    /// Write data from a raw pointer into the send buffer. Returns bytes written.
    @discardableResult
    public mutating func writeSendBuf(ptr: UnsafeRawPointer, count: Int) -> Int {
        let space = sendSpace
        var n = count
        if n > space { n = space }
        guard n > 0 else { return 0 }
        let first = min(n, sendBuf.count - sendTail)
        sendBuf.withUnsafeMutableBytes { raw in
            guard let base = raw.baseAddress else { return }
            memcpy(base.advanced(by: sendTail), ptr, first)
            if n > first {
                memcpy(base, ptr.advanced(by: first), n - first)
            }
        }
        sendTail = (sendTail + n) % sendBuf.count
        sendSize += n
        return n
    }

    /// Remove acknowledged data from the send buffer.
    /// Called after the FSM advances snd.una.
    public mutating func ackSendBuf(delta: Int) {
        var d = delta
        if d > sendSize { d = sendSize }
        guard d > 0 else { return }
        sendHead = (sendHead + d) % sendBuf.count
        sendSize -= d
        retransmitCount = 0
    }

    /// Peek up to `max` bytes of unsent data from the send buffer.
    /// Returns a contiguous copy of the data.
    public func peekSendData(max: Int) -> [UInt8] {
        let avail = sendAvail
        let sent = Int(snd.nxt &- snd.una)
        guard sent < avail, avail > 0, max > 0 else { return [] }
        let remaining = avail - sent
        var n = remaining
        if n > max { n = max }
        var result = [UInt8](repeating: 0, count: n)
        let start = (sendHead + sent) % sendBuf.count
        let first = min(n, sendBuf.count - start)
        sendBuf.withUnsafeBytes { src in
            guard let srcBase = src.baseAddress else { return }
            result.withUnsafeMutableBytes { dst in
                guard let dstBase = dst.baseAddress else { return }
                memcpy(dstBase, srcBase.advanced(by: start), first)
                if n > first {
                    memcpy(dstBase.advanced(by: first), srcBase, n - first)
                }
            }
        }
        return result
    }
}
