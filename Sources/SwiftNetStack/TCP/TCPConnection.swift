/// Aggregates all per-connection TCP state for a NAT-proxied connection.
struct TCPConnection {
    public let connectionID: UInt64
    public let posixFD: Int32
    public var state: TCPState
    public var snd: SendSequence
    public var rcv: RecvSequence
    public var retransmitTimer: TCPRetransmitTimer

    public let vmMAC: MACAddress
    public let vmIP: IPv4Address
    public let vmPort: UInt16
    public let dstIP: IPv4Address
    public let dstPort: UInt16
    public let endpointID: Int

    /// Data received from the external side, waiting to be sent to the VM.
    public var externalBuffer: [UInt8]
    /// Data from the VM waiting to be written to the external POSIX socket.
    public var writeBuffer: [UInt8]
    /// Pending segments that require ACK (for retransmission).
    public var pendingSegments: [TCPSegmentToSend]

    /// True when external side has closed its write side (read returned 0)
    /// but the FIN has not yet been forwarded to the VM because unacknowledged
    /// data remains in pendingSegments.
    public var externalEOF: Bool

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
        self.retransmitTimer = TCPRetransmitTimer()
        self.vmMAC = vmMAC
        self.vmIP = vmIP
        self.vmPort = vmPort
        self.dstIP = dstIP
        self.dstPort = dstPort
        self.endpointID = endpointID
        self.externalBuffer = []
        self.writeBuffer = []
        self.pendingSegments = []
        self.externalEOF = false
    }
}
