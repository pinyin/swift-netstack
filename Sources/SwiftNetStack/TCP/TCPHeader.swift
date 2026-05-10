/// TCP header (RFC 793) with zero-copy payload.
public struct TCPHeader {
    public let srcPort: UInt16
    public let dstPort: UInt16
    public let sequenceNumber: UInt32
    public let acknowledgmentNumber: UInt32
    public let dataOffset: UInt8        // header length in 32-bit words (5...15)
    public let flags: TCPFlags
    public let window: UInt16
    public let checksum: UInt16
    public let urgentPointer: UInt16
    public let payload: PacketBuffer
    public let pseudoSrcAddr: IPv4Address
    public let pseudoDstAddr: IPv4Address
    private let _checksumValid: Bool

    init(
        srcPort: UInt16, dstPort: UInt16,
        sequenceNumber: UInt32, acknowledgmentNumber: UInt32,
        dataOffset: UInt8, flags: TCPFlags,
        window: UInt16, checksum: UInt16, urgentPointer: UInt16,
        payload: PacketBuffer,
        pseudoSrcAddr: IPv4Address, pseudoDstAddr: IPv4Address,
        checksumValid: Bool
    ) {
        self.srcPort = srcPort; self.dstPort = dstPort
        self.sequenceNumber = sequenceNumber; self.acknowledgmentNumber = acknowledgmentNumber
        self.dataOffset = dataOffset; self.flags = flags
        self.window = window; self.checksum = checksum
        self.urgentPointer = urgentPointer; self.payload = payload
        self.pseudoSrcAddr = pseudoSrcAddr; self.pseudoDstAddr = pseudoDstAddr
        self._checksumValid = checksumValid
    }

    /// Parse a TCP header from the IP payload.
    /// Returns nil if shorter than 20 bytes or header fields are invalid.
    public static func parse(
        from pkt: PacketBuffer,
        pseudoSrcAddr: IPv4Address,
        pseudoDstAddr: IPv4Address
    ) -> TCPHeader? {
        var pkt = pkt
        let tcpLen = pkt.totalLength
        guard tcpLen >= 20 else { return nil }
        guard pkt.pullUp(tcpLen) else { return nil }

        return pkt.withUnsafeReadableBytes { buf in
            let srcPort = (UInt16(buf[0]) << 8) | UInt16(buf[1])
            let dstPort = (UInt16(buf[2]) << 8) | UInt16(buf[3])
            let seqNum  = (UInt32(buf[4]) << 24) | (UInt32(buf[5]) << 16)
                        | (UInt32(buf[6]) << 8)  |  UInt32(buf[7])
            let ackNum  = (UInt32(buf[8]) << 24) | (UInt32(buf[9]) << 16)
                        | (UInt32(buf[10]) << 8) |  UInt32(buf[11])

            let dataOff = buf[12] >> 4
            guard dataOff >= 5 && dataOff <= 15 else { return nil }
            let headerLen = Int(dataOff) * 4
            guard tcpLen >= headerLen else { return nil }

            let flags    = TCPFlags(rawValue: buf[13])

            let window   = (UInt16(buf[14]) << 8) | UInt16(buf[15])
            let checksum = (UInt16(buf[16]) << 8) | UInt16(buf[17])
            let urgent   = (UInt16(buf[18]) << 8) | UInt16(buf[19])

            guard let payload = pkt.slice(from: headerLen, length: tcpLen - headerLen) else { return nil }

            let ck = computeTCPChecksum(
                pseudoSrcAddr: pseudoSrcAddr,
                pseudoDstAddr: pseudoDstAddr,
                tcpData: buf.baseAddress!,
                tcpLen: tcpLen
            )
            let checksumValid = (ck == 0)

            return TCPHeader(
                srcPort: srcPort, dstPort: dstPort,
                sequenceNumber: seqNum, acknowledgmentNumber: ackNum,
                dataOffset: dataOff, flags: flags,
                window: window, checksum: checksum,
                urgentPointer: urgent, payload: payload,
                pseudoSrcAddr: pseudoSrcAddr, pseudoDstAddr: pseudoDstAddr,
                checksumValid: checksumValid
            )
        }
    }

    public func verifyChecksum() -> Bool { _checksumValid }

    /// Fixed header length in bytes (4 * dataOffset).
    public var headerLength: Int { Int(dataOffset) * 4 }

    // MARK: - Synthetic segments for FSM events

    /// Create a minimal TCP ACK segment for injecting external events (e.g. FIN)
    /// into the VM-side state machine. The segment carries no data and
    /// acknowledges `ackNumber`. `pseudoSrcAddr` and `pseudoDstAddr` must match
    /// the connection's IP addresses for correct FSM behavior.
    static func syntheticAck(
        ackNumber: UInt32,
        sequenceNumber: UInt32 = 0,
        pseudoSrcAddr: IPv4Address,
        pseudoDstAddr: IPv4Address,
        payload: PacketBuffer
    ) -> TCPHeader {
        TCPHeader(
            srcPort: 0, dstPort: 0,
            sequenceNumber: sequenceNumber, acknowledgmentNumber: ackNumber,
            dataOffset: 5, flags: .ack,
            window: 65535, checksum: 0, urgentPointer: 0,
            payload: payload,
            pseudoSrcAddr: pseudoSrcAddr, pseudoDstAddr: pseudoDstAddr,
            checksumValid: true
        )
    }
}
