import Foundation

// MARK: - Protocol Constants

struct TCPFlag {
    static let fin: UInt8 = 1 << 0
    static let syn: UInt8 = 1 << 1
    static let rst: UInt8 = 1 << 2
    static let psh: UInt8 = 1 << 3
    static let ack: UInt8 = 1 << 4
    static let urg: UInt8 = 1 << 5
}

// MARK: - Tuple (4-tuple connection identifier)

struct Tuple: Hashable, CustomStringConvertible {
    let srcIP: UInt32
    let dstIP: UInt32
    let srcPort: UInt16
    let dstPort: UInt16

    init(srcIP: UInt32, dstIP: UInt32, srcPort: UInt16, dstPort: UInt16) {
        self.srcIP = srcIP
        self.dstIP = dstIP
        self.srcPort = srcPort
        self.dstPort = dstPort
    }

    func reversed() -> Tuple {
        Tuple(srcIP: dstIP, dstIP: srcIP, srcPort: dstPort, dstPort: srcPort)
    }

    var description: String {
        "\(ipString(srcIP)):\(srcPort)→\(ipString(dstIP)):\(dstPort)"
    }
}

public func ipString(_ ip: UInt32) -> String {
    "\(ip >> 24).\((ip >> 16) & 0xFF).\((ip >> 8) & 0xFF).\(ip & 0xFF)"
}

public func ipToUInt32(_ ip: String) -> UInt32 {
    let parts = ip.split(separator: ".").compactMap { UInt8($0) }
    guard parts.count == 4 else { return 0 }
    return (UInt32(parts[0]) << 24) | (UInt32(parts[1]) << 16) | (UInt32(parts[2]) << 8) | UInt32(parts[3])
}

// MARK: - TCP Header

struct TCPHeader {
    let srcPort: UInt16
    let dstPort: UInt16
    let seqNum: UInt32
    let ackNum: UInt32
    let dataOffset: UInt8
    let flags: UInt8
    let windowSize: UInt16
    let checksum: UInt16
    let urgentPtr: UInt16

    func hasFlag(_ f: UInt8) -> Bool { (flags & f) != 0 }
    func isSYN() -> Bool { hasFlag(TCPFlag.syn) }
    func isACK() -> Bool { hasFlag(TCPFlag.ack) }
    func isFIN() -> Bool { hasFlag(TCPFlag.fin) }
    func isRST() -> Bool { hasFlag(TCPFlag.rst) }

    static func parse(_ data: [UInt8]) -> TCPHeader? {
        guard data.count >= 20 else { return nil }
        let raw = data
        return TCPHeader(
            srcPort: UInt16(raw[0]) << 8 | UInt16(raw[1]),
            dstPort: UInt16(raw[2]) << 8 | UInt16(raw[3]),
            seqNum: UInt32(raw[4]) << 24 | UInt32(raw[5]) << 16 | UInt32(raw[6]) << 8 | UInt32(raw[7]),
            ackNum: UInt32(raw[8]) << 24 | UInt32(raw[9]) << 16 | UInt32(raw[10]) << 8 | UInt32(raw[11]),
            dataOffset: (raw[12] >> 4) * 4,
            flags: raw[13],
            windowSize: UInt16(raw[14]) << 8 | UInt16(raw[15]),
            checksum: UInt16(raw[16]) << 8 | UInt16(raw[17]),
            urgentPtr: UInt16(raw[18]) << 8 | UInt16(raw[19])
        )
    }

    func marshal() -> [UInt8] {
        var d = [UInt8](repeating: 0, count: 20)
        d[0] = UInt8(srcPort >> 8); d[1] = UInt8(srcPort & 0xFF)
        d[2] = UInt8(dstPort >> 8); d[3] = UInt8(dstPort & 0xFF)
        d[4] = UInt8(seqNum >> 24); d[5] = UInt8(seqNum >> 16 & 0xFF)
        d[6] = UInt8(seqNum >> 8 & 0xFF); d[7] = UInt8(seqNum & 0xFF)
        d[8] = UInt8(ackNum >> 24); d[9] = UInt8(ackNum >> 16 & 0xFF)
        d[10] = UInt8(ackNum >> 8 & 0xFF); d[11] = UInt8(ackNum & 0xFF)
        d[12] = (5 << 4)
        d[13] = flags
        d[14] = UInt8(windowSize >> 8); d[15] = UInt8(windowSize & 0xFF)
        d[16] = 0; d[17] = 0 // checksum placeholder
        d[18] = UInt8(urgentPtr >> 8); d[19] = UInt8(urgentPtr & 0xFF)
        return d
    }
}

// MARK: - TCP Segment

struct TCPSegment {
    let header: TCPHeader
    let payload: [UInt8]
    let tuple: Tuple
    let raw: [UInt8]

    static func parse(_ data: [UInt8], srcIP: UInt32, dstIP: UInt32) -> TCPSegment? {
        guard let h = TCPHeader.parse(data) else { return nil }
        let offset = Int(h.dataOffset)
        let clippedOffset = min(offset, data.count)
        return TCPSegment(
            header: h,
            payload: Array(data[clippedOffset...]),
            tuple: Tuple(srcIP: srcIP, dstIP: dstIP, srcPort: h.srcPort, dstPort: h.dstPort),
            raw: data
        )
    }
}

// MARK: - Segment Builder

func buildSegment(tuple: Tuple, seq: UInt32, ack: UInt32, flags: UInt8, window: UInt16, wscale: UInt8, payload: [UInt8]) -> [UInt8] {
    let hasOptions = wscale > 0
    let headerLen = hasOptions ? 24 : 20

    var d = [UInt8](repeating: 0, count: headerLen)
    d[0] = UInt8(tuple.srcPort >> 8); d[1] = UInt8(tuple.srcPort & 0xFF)
    d[2] = UInt8(tuple.dstPort >> 8); d[3] = UInt8(tuple.dstPort & 0xFF)
    d[4] = UInt8(seq >> 24); d[5] = UInt8(seq >> 16 & 0xFF)
    d[6] = UInt8(seq >> 8 & 0xFF); d[7] = UInt8(seq & 0xFF)
    d[8] = UInt8(ack >> 24); d[9] = UInt8(ack >> 16 & 0xFF)
    d[10] = UInt8(ack >> 8 & 0xFF); d[11] = UInt8(ack & 0xFF)
    d[12] = UInt8(headerLen / 4) << 4
    d[13] = flags
    d[14] = UInt8(window >> 8); d[15] = UInt8(window & 0xFF)
    d[16] = 0; d[17] = 0 // checksum placeholder
    d[18] = 0; d[19] = 0 // urgent pointer

    if hasOptions {
        d[20] = 3  // Kind: Window Scale
        d[21] = 3  // Length: 3
        d[22] = wscale
        d[23] = 1  // NOP
    }

    guard !payload.isEmpty else { return d }
    var result = d
    result.append(contentsOf: payload)
    return result
}

func buildSegmentWithWScale(tuple: Tuple, seq: UInt32, ack: UInt32, flags: UInt8, window: UInt16, wscale: UInt8, payload: [UInt8]) -> [UInt8] {
    buildSegment(tuple: tuple, seq: seq, ack: ack, flags: flags, window: window, wscale: wscale, payload: payload)
}

// MARK: - Window Scale Parsing

func parseWindowScale(_ data: [UInt8]) -> UInt8 {
    guard data.count >= 20 else { return 0 }
    let dataOffset = (data[12] >> 4) * 4
    guard dataOffset > 20, dataOffset <= data.count else { return 0 }
    let options = Array(data[20..<Int(dataOffset)])
    var i = 0
    while i < options.count {
        if options[i] == 0 { break }
        if options[i] == 1 { i += 1; continue }
        guard i + 1 < options.count else { break }
        let kind = options[i]
        let length = Int(options[i + 1])
        guard length >= 2, i + length <= options.count else { break }
        if kind == 3, length == 3 { return options[i + 2] }
        i += length
    }
    return 0
}

// MARK: - Sequence Number Helpers (RFC 1323)

func seqLT(_ a: UInt32, _ b: UInt32) -> Bool { Int32(bitPattern: a &- b) < 0 }
func seqLE(_ a: UInt32, _ b: UInt32) -> Bool { Int32(bitPattern: a &- b) <= 0 }
func seqGT(_ a: UInt32, _ b: UInt32) -> Bool { Int32(bitPattern: a &- b) > 0 }
func seqGE(_ a: UInt32, _ b: UInt32) -> Bool { Int32(bitPattern: a &- b) >= 0 }

// MARK: - TCP Checksum

func tcpChecksum(srcIP: UInt32, dstIP: UInt32, tcpData: [UInt8]) -> UInt16 {
    var pseudoHdr = [UInt8](repeating: 0, count: 12)
    pseudoHdr[0] = UInt8(srcIP >> 24); pseudoHdr[1] = UInt8(srcIP >> 16 & 0xFF)
    pseudoHdr[2] = UInt8(srcIP >> 8 & 0xFF); pseudoHdr[3] = UInt8(srcIP & 0xFF)
    pseudoHdr[4] = UInt8(dstIP >> 24); pseudoHdr[5] = UInt8(dstIP >> 16 & 0xFF)
    pseudoHdr[6] = UInt8(dstIP >> 8 & 0xFF); pseudoHdr[7] = UInt8(dstIP & 0xFF)
    pseudoHdr[8] = 0
    pseudoHdr[9] = 6 // TCP protocol
    let tcpLen = UInt16(tcpData.count)
    pseudoHdr[10] = UInt8(tcpLen >> 8); pseudoHdr[11] = UInt8(tcpLen & 0xFF)

    return onesComplementSum(pseudoHdr + tcpData)
}

func onesComplementSum(_ data: [UInt8]) -> UInt16 {
    var sum: UInt32 = 0
    var i = 0
    while i < data.count - 1 {
        sum += UInt32(UInt16(data[i]) << 8 | UInt16(data[i + 1]))
        i += 2
    }
    if data.count % 2 == 1 {
        sum += UInt32(data[data.count - 1]) << 8
    }
    while sum > 0xFFFF {
        sum = (sum & 0xFFFF) + (sum >> 16)
    }
    return ~UInt16(sum & 0xFFFF)
}

// MARK: - Listener

struct TCPListener {
    let port: UInt16
    let onAccept: (TCPConn) -> Void
}

// MARK: - TCPConn (replaces Go's Conn struct, state members only)

final class TCPConn {
    let tuple: Tuple

    // Sequence space
    let iss: UInt32
    var irs: UInt32
    var sndNxt: UInt32
    var sndUna: UInt32
    var rcvNxt: UInt32
    var sndWnd: UInt32
    var rcvWnd: UInt32
    var window: UInt16

    // Data buffers (circular)
    private(set) var sendBuf: [UInt8]
    private(set) var sendHead: Int = 0
    private(set) var sendTail: Int = 0
    private(set) var sendSize: Int = 0
    private(set) var recvBuf: [UInt8]
    private(set) var recvHead: Int = 0
    private(set) var recvTail: Int = 0
    private(set) var recvSize: Int = 0

    // Pending segments for this round
    var pendingSegs: [TCPSegment] = []

    // Timer state
    var retransmitAt: Int64 = 0
    var retransmitCount: Int = 0
    var timeWaitUntil: Int64 = 0

    // Last ACK tracking
    var lastAckSent: UInt32 = 0
    var lastAckTime: Int64 = 0
    var lastAckWin: UInt16 = 0

    // Activity tracking
    var lastActivityTick: Int64 = 0

    // Window scaling (RFC 1323)
    var sndShift: UInt8 = 0
    var rcvShift: UInt8 = 0

    // Close tracking
    var finSent: Bool = false
    var finReceived: Bool = false
    var finSeq: UInt32 = 0

    func isFinReceived() -> Bool { finReceived }

    init(tuple: Tuple, irs: UInt32, iss: UInt32, window: UInt16, bufSize: Int) {
        self.tuple = tuple
        self.iss = iss
        self.irs = irs
        self.sndNxt = iss
        self.sndUna = iss
        self.rcvNxt = irs + 1
        self.sndWnd = 65535
        self.rcvWnd = 65535
        self.window = window
        let sz = bufSize > 0 ? bufSize : 65536
        self.sendBuf = [UInt8](repeating: 0, count: sz)
        self.recvBuf = [UInt8](repeating: 0, count: sz)
        self.lastAckWin = UInt16(min(sz, 65535))
    }

    var recvAvail: Int { recvSize }
    var sendAvail: Int { sendSize }
    var sendSpace: Int { sendBuf.count - sendSize }

    func recvWritable() -> Int { recvBuf.count - recvSize }

    func scaledWindow(syn: Bool) -> UInt16 {
        var raw = recvWritable()
        if rcvShift > 0 && !syn { raw = raw >> rcvShift }
        if raw > 65535 { raw = 65535 }
        return UInt16(raw)
    }

    func writeRecvBuf(_ data: [UInt8]) -> Int {
        var n = data.count
        let writable = recvWritable()
        if n > writable { n = writable }
        guard n > 0 else { return 0 }
        let first = min(n, recvBuf.count - recvTail)
        for i in 0..<first { recvBuf[recvTail + i] = data[i] }
        for i in 0..<(n - first) { recvBuf[i] = data[first + i] }
        recvTail = (recvTail + n) % recvBuf.count
        recvSize += n
        return n
    }

    func readRecvBuf(into buf: inout [UInt8]) -> Int {
        var n = buf.count
        if n > recvSize { n = recvSize }
        guard n > 0 else { return 0 }
        let first = min(n, recvBuf.count - recvHead)
        for i in 0..<first { buf[i] = recvBuf[recvHead + i] }
        for i in 0..<(n - first) { buf[first + i] = recvBuf[i] }
        recvHead = (recvHead + n) % recvBuf.count
        recvSize -= n
        return n
    }

    func peekRecvData() -> [UInt8] {
        guard recvSize > 0 else { return [] }
        let end = recvHead + recvSize
        if end <= recvBuf.count {
            return Array(recvBuf[recvHead..<end])
        }
        return Array(recvBuf[recvHead...])
    }

    func consumeRecvData(_ n: Int) {
        guard n > 0, n <= recvSize else { return }
        recvHead = (recvHead + n) % recvBuf.count
        recvSize -= n
    }

    func writeSendBuf(_ data: [UInt8]) -> Int {
        let space = sendBuf.count - sendSize
        guard space > 0 else { return 0 }
        var n = data.count
        if n > space { n = space }
        let first = min(n, sendBuf.count - sendTail)
        for i in 0..<first { sendBuf[sendTail + i] = data[i] }
        for i in 0..<(n - first) { sendBuf[i] = data[first + i] }
        sendTail = (sendTail + n) % sendBuf.count
        sendSize += n
        return n
    }

    func ackSendBuf(_ seq: UInt32) {
        guard seqGT(seq, sndUna) else { return }
        var acked = Int(seq - sndUna)
        if acked > sendSize { acked = sendSize }
        sendHead = (sendHead + acked) % sendBuf.count
        sndUna += UInt32(acked)
        sendSize -= acked
        retransmitCount = 0
    }

    func peekSendData(max: Int) -> [UInt8] {
        let avail = sendAvail
        let sent = Int(sndNxt - sndUna)
        guard sent < avail, avail > 0, max > 0 else { return [] }
        let remaining = avail - sent
        var n = remaining
        if n > max { n = max }
        let start = (sendHead + sent) % sendBuf.count
        let end = start + n
        if end <= sendBuf.count {
            return Array(sendBuf[start..<end])
        }
        return Array(sendBuf[start...])
    }
}
