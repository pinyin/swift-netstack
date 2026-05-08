/// Aggregates all per-connection TCP state for a NAT-proxied connection.
struct TCPConnection {
    /// Tracks the deferred shutdown(SHUT_WR) sequence.
    ///
    /// macOS has a kernel quirk where `shutdown(SHUT_WR)` called immediately
    /// after `write()` causes the remote peer's response to be lost (observed
    /// with internet TCP connections).  To avoid this, we defer shutdown until
    /// we receive at least one `read()` from the external socket after our
    /// last write — proving the round-trip has completed.
    public enum DeferredShutdown: Equatable {
        case idle               // VM has not sent FIN
        case waitingForData     // VM sent FIN after write; waiting for external response
        case ready              // response received (or no data was written), safe to shutdown
        case done               // shutdown(SHUT_WR) completed
    }

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

    /// Data from the VM waiting to be written to the external POSIX socket.
    public var writeBuffer: [UInt8]

    /// True when external side has closed its write side (read returned 0).
    /// Prevents repeated EOF-triggered FINs on every poll cycle.
    public var externalEOF: Bool

    public var deferredShutdown: DeferredShutdown

    /// Whether data has been written to the external socket since the last
    /// successful read.  Used to gate deferred shutdown: we must not call
    /// shutdown(SHUT_WR) while unacknowledged writes are in flight.
    public var wroteSinceRead: Bool

    /// Number of poll cycles spent in `.waitingForData`.  When this exceeds
    /// a threshold (e.g. 200 ≈ 2 seconds at 100 Hz), force shutdown anyway
    /// to avoid leaking connections when the remote peer sends no response.
    public var waitingCycles: Int

    /// Whether POLLOUT should be requested for this connection's fd.
    public func wantsPOLLOUT() -> Bool {
        if state == .listen || state == .synReceived { return true }
        if !writeBuffer.isEmpty { return true }
        if deferredShutdown == .waitingForData || deferredShutdown == .ready { return true }
        return false
    }

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
        self.writeBuffer = []
        self.externalEOF = false
        self.deferredShutdown = .idle
        self.wroteSinceRead = false
        self.waitingCycles = 0
    }
}
