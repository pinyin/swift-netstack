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
        return TCPHeader(
            srcPort: UInt16(data[0]) << 8 | UInt16(data[1]),
            dstPort: UInt16(data[2]) << 8 | UInt16(data[3]),
            seqNum: UInt32(data[4]) << 24 | UInt32(data[5]) << 16 | UInt32(data[6]) << 8 | UInt32(data[7]),
            ackNum: UInt32(data[8]) << 24 | UInt32(data[9]) << 16 | UInt32(data[10]) << 8 | UInt32(data[11]),
            dataOffset: (data[12] >> 4) * 4,
            flags: data[13],
            windowSize: UInt16(data[14]) << 8 | UInt16(data[15]),
            checksum: UInt16(data[16]) << 8 | UInt16(data[17]),
            urgentPtr: UInt16(data[18]) << 8 | UInt16(data[19])
        )
    }

    static func parse(_ data: Data) -> TCPHeader? {
        guard data.count >= 20 else { return nil }
        return TCPHeader(
            srcPort: UInt16(data[0]) << 8 | UInt16(data[1]),
            dstPort: UInt16(data[2]) << 8 | UInt16(data[3]),
            seqNum: UInt32(data[4]) << 24 | UInt32(data[5]) << 16 | UInt32(data[6]) << 8 | UInt32(data[7]),
            ackNum: UInt32(data[8]) << 24 | UInt32(data[9]) << 16 | UInt32(data[10]) << 8 | UInt32(data[11]),
            dataOffset: (data[12] >> 4) * 4,
            flags: data[13],
            windowSize: UInt16(data[14]) << 8 | UInt16(data[15]),
            checksum: UInt16(data[16]) << 8 | UInt16(data[17]),
            urgentPtr: UInt16(data[18]) << 8 | UInt16(data[19])
        )
    }

    func marshal() -> [UInt8] {
        let nb = NetBuf(capacity: 20, headroom: 20)
        marshal(into: nb)
        return nb.toArray()
    }

    /// Write the TCP header (20 bytes) into a NetBuf at the current offset,
    /// consuming 20 bytes of headroom (using prependPointer).
    @discardableResult
    func marshal(into buf: NetBuf) -> Bool {
        let hdrLen = 20
        guard let ptr = buf.prependPointer(count: hdrLen) else { return false }
        ptr[0] = UInt8(srcPort >> 8); ptr[1] = UInt8(srcPort & 0xFF)
        ptr[2] = UInt8(dstPort >> 8); ptr[3] = UInt8(dstPort & 0xFF)
        ptr[4] = UInt8(seqNum >> 24); ptr[5] = UInt8(seqNum >> 16 & 0xFF)
        ptr[6] = UInt8(seqNum >> 8 & 0xFF); ptr[7] = UInt8(seqNum & 0xFF)
        ptr[8] = UInt8(ackNum >> 24); ptr[9] = UInt8(ackNum >> 16 & 0xFF)
        ptr[10] = UInt8(ackNum >> 8 & 0xFF); ptr[11] = UInt8(ackNum & 0xFF)
        ptr[12] = (5 << 4)
        ptr[13] = flags
        ptr[14] = UInt8(windowSize >> 8); ptr[15] = UInt8(windowSize & 0xFF)
        ptr[16] = 0; ptr[17] = 0 // checksum placeholder
        ptr[18] = UInt8(urgentPtr >> 8); ptr[19] = UInt8(urgentPtr & 0xFF)
        return true
    }
}

// MARK: - TCP Segment

struct TCPSegment {
    let header: TCPHeader
    let payload: Data
    let tuple: Tuple
    let raw: [UInt8]
    var netBuf: NetBuf? = nil

    static func parse(_ data: [UInt8], srcIP: UInt32, dstIP: UInt32) -> TCPSegment? {
        // Legacy path: copy to Data first. Prefer parse(Data) for hot path.
        parse(Data(data), srcIP: srcIP, dstIP: dstIP)
    }

    /// Zero-copy parse: payload is a Data slice sharing the input buffer.
    static func parse(_ data: Data, srcIP: UInt32, dstIP: UInt32) -> TCPSegment? {
        guard let h = TCPHeader.parse(data) else { return nil }
        let offset = Int(h.dataOffset)
        let clippedOffset = min(offset, data.count)
        let payload: Data
        if clippedOffset < data.count {
            payload = data.subdata(in: clippedOffset..<data.count)
        } else {
            payload = Data()
        }
        return TCPSegment(
            header: h,
            payload: payload,
            tuple: Tuple(srcIP: srcIP, dstIP: dstIP, srcPort: h.srcPort, dstPort: h.dstPort),
            raw: [UInt8](data)
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

// MARK: - NetBuf Segment Builder

/// Build a TCP segment in a NetBuf with headroom reserved for IP (20B) + Ethernet (14B) headers.
/// Returns a NetBuf with: [14B Eth headroom | 20B IP headroom | TCP header | payload].
/// The caller can then prepend IP and Ethernet headers without any copies.
func buildSegmentNetBuf(tuple: Tuple, seq: UInt32, ack: UInt32, flags: UInt8, window: UInt16, wscale: UInt8, payload: NetBuf) -> NetBuf {
    let hasOptions = wscale > 0
    let tcpHdrLen = hasOptions ? 24 : 20
    let ipHdrLen = 20
    let ethHdrLen = 14
    let totalHeadroom = ethHdrLen + ipHdrLen + tcpHdrLen

    let nb = NetBuf(capacity: totalHeadroom + payload.length, headroom: totalHeadroom)

    // Append payload first (at offset = totalHeadroom)
    _ = nb.append(copying: payload)

    // Prepend TCP header (consumes tcpHdrLen from headroom)
    guard let ptr = nb.prependPointer(count: tcpHdrLen) else { return nb }
    ptr[0] = UInt8(tuple.srcPort >> 8); ptr[1] = UInt8(tuple.srcPort & 0xFF)
    ptr[2] = UInt8(tuple.dstPort >> 8); ptr[3] = UInt8(tuple.dstPort & 0xFF)
    ptr[4] = UInt8(seq >> 24); ptr[5] = UInt8(seq >> 16 & 0xFF)
    ptr[6] = UInt8(seq >> 8 & 0xFF); ptr[7] = UInt8(seq & 0xFF)
    ptr[8] = UInt8(ack >> 24); ptr[9] = UInt8(ack >> 16 & 0xFF)
    ptr[10] = UInt8(ack >> 8 & 0xFF); ptr[11] = UInt8(ack & 0xFF)
    ptr[12] = UInt8(tcpHdrLen / 4) << 4
    ptr[13] = flags
    ptr[14] = UInt8(window >> 8); ptr[15] = UInt8(window & 0xFF)
    ptr[16] = 0; ptr[17] = 0 // checksum placeholder
    ptr[18] = 0; ptr[19] = 0 // urgent pointer

    if hasOptions {
        ptr[20] = 3  // Kind: Window Scale
        ptr[21] = 3  // Length: 3
        ptr[22] = wscale
        ptr[23] = 1  // NOP
    }
    return nb
}

/// Build a TCP segment from [UInt8] payload via NetBuf (backward compat).
func buildSegmentViaNetBuf(tuple: Tuple, seq: UInt32, ack: UInt32, flags: UInt8, window: UInt16, wscale: UInt8, payload: [UInt8]) -> [UInt8] {
    let payloadBuf = NetBuf(copying: payload)
    return buildSegmentNetBuf(tuple: tuple, seq: seq, ack: ack, flags: flags, window: window, wscale: wscale, payload: payloadBuf).toArray()
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
    tcpData.withUnsafeBytes { tcpChecksum(srcIP: srcIP, dstIP: dstIP, tcpDataPtr: $0.baseAddress!, tcpDataCount: tcpData.count) }
}

/// Zero-allocation TCP checksum over pseudo-header + TCP data.
func tcpChecksum(srcIP: UInt32, dstIP: UInt32, tcpDataPtr: UnsafeRawPointer, tcpDataCount: Int) -> UInt16 {
    var sum: UInt32 = 0

    // Pseudo-header
    sum += UInt32(srcIP >> 16)
    sum += UInt32(srcIP & 0xFFFF)
    sum += UInt32(dstIP >> 16)
    sum += UInt32(dstIP & 0xFFFF)
    sum += 6  // TCP protocol
    sum += UInt32(tcpDataCount)

    // TCP data
    let bytes = tcpDataPtr.assumingMemoryBound(to: UInt8.self)
    var i = 0
    while i < tcpDataCount - 1 {
        sum += UInt32(UInt16(bytes[i]) << 8 | UInt16(bytes[i + 1]))
        i += 2
    }
    if tcpDataCount % 2 == 1 {
        sum += UInt32(bytes[tcpDataCount - 1]) << 8
    }

    while sum > 0xFFFF {
        sum = (sum & 0xFFFF) + (sum >> 16)
    }
    return ~UInt16(sum & 0xFFFF)
}

func onesComplementSum(_ data: [UInt8]) -> UInt16 {
    data.withUnsafeBytes { onesComplementSum(ptr: $0.baseAddress!, count: data.count) }
}

func onesComplementSum(ptr: UnsafeRawPointer, count: Int) -> UInt16 {
    var sum: UInt32 = 0
    let bytes = ptr.assumingMemoryBound(to: UInt8.self)
    var i = 0
    while i < count - 1 {
        sum += UInt32(UInt16(bytes[i]) << 8 | UInt16(bytes[i + 1]))
        i += 2
    }
    if count % 2 == 1 {
        sum += UInt32(bytes[count - 1]) << 8
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
        return data.withUnsafeBytes { ptr in
            writeRecvBuf(ptr: ptr.baseAddress!, count: data.count)
        }
    }

    func writeRecvBuf(_ data: Data) -> Int {
        return data.withUnsafeBytes { ptr in
            writeRecvBuf(ptr: ptr.baseAddress!, count: data.count)
        }
    }

    func writeRecvBuf(ptr: UnsafeRawPointer, count: Int) -> Int {
        let writable = recvWritable()
        var n = count
        if n > writable { n = writable }
        guard n > 0 else { return 0 }
        let first = min(n, recvBuf.count - recvTail)
        recvBuf.withUnsafeMutableBytes { raw in
            guard let base = raw.baseAddress else { return }
            memcpy(base.advanced(by: recvTail), ptr, first)
            if n > first {
                memcpy(base, ptr.advanced(by: first), n - first)
            }
        }
        recvTail = (recvTail + n) % recvBuf.count
        recvSize += n
        return n
    }

    func readRecvBuf(into buf: inout [UInt8]) -> Int {
        var n = buf.count
        if n > recvSize { n = recvSize }
        guard n > 0 else { return 0 }
        let first = min(n, recvBuf.count - recvHead)
        buf.withUnsafeMutableBytes { dst in
            guard let dstBase = dst.baseAddress else { return }
            recvBuf.withUnsafeBytes { src in
                guard let srcBase = src.baseAddress else { return }
                memcpy(dstBase, srcBase.advanced(by: recvHead), first)
                if n > first {
                    memcpy(dstBase.advanced(by: first), srcBase, n - first)
                }
            }
        }
        recvHead = (recvHead + n) % recvBuf.count
        recvSize -= n
        return n
    }

    func peekRecvData() -> [UInt8] {
        peekRecvDataNetBuf(headroom: 0).toArray()
    }

    /// Copy data from the recv circular buffer into a contiguous NetBuf.
    /// Handles wrap-around correctly. Optional headroom for future header prepending.
    func peekRecvDataNetBuf(headroom: Int = 0) -> NetBuf {
        guard recvSize > 0 else { return NetBuf(capacity: 0) }
        let nb = NetBuf(capacity: headroom + recvSize, headroom: headroom)
        guard let ptr = nb.appendPointer(count: recvSize) else { return nb }
        let first = min(recvSize, recvBuf.count - recvHead)
        recvBuf.withUnsafeBytes { src in
            guard let srcBase = src.baseAddress else { return }
            memcpy(ptr, srcBase.advanced(by: recvHead), first)
            if recvSize > first {
                memcpy(ptr.advanced(by: first), srcBase, recvSize - first)
            }
        }
        return nb
    }

    func withRecvData<T>(_ body: (UnsafePointer<UInt8>, Int) throws -> T) rethrows -> T {
        guard recvSize > 0 else {
            return try body(UnsafePointer<UInt8>(bitPattern: 0)!, 0)
        }
        let end = recvHead + recvSize
        if end <= recvBuf.count {
            return try recvBuf.withUnsafeBytes { raw in
                guard let base = raw.baseAddress else {
                    return try body(UnsafePointer<UInt8>(bitPattern: 0)!, 0)
                }
                return try body(base.advanced(by: recvHead).assumingMemoryBound(to: UInt8.self), recvSize)
            }
        }
        // Wrapping case: linearize into temp buffer
        let first = recvBuf.count - recvHead
        var tmp = [UInt8](repeating: 0, count: recvSize)
        recvBuf.withUnsafeBytes { src in
            guard let srcBase = src.baseAddress else { return }
            tmp.withUnsafeMutableBytes { dst in
                guard let dstBase = dst.baseAddress else { return }
                memcpy(dstBase, srcBase.advanced(by: recvHead), first)
                memcpy(dstBase.advanced(by: first), srcBase, recvSize - first)
            }
        }
        return try tmp.withUnsafeBytes { raw in
            guard let base = raw.baseAddress else {
                return try body(UnsafePointer<UInt8>(bitPattern: 0)!, 0)
            }
            return try body(base.assumingMemoryBound(to: UInt8.self), recvSize)
        }
    }

    func consumeRecvData(_ n: Int) {
        guard n > 0, n <= recvSize else { return }
        recvHead = (recvHead + n) % recvBuf.count
        recvSize -= n
    }

    func writeSendBuf(_ data: [UInt8]) -> Int {
        return data.withUnsafeBytes { ptr in
            writeSendBuf(ptr: ptr.baseAddress!, count: data.count)
        }
    }

    func writeSendBuf(ptr: UnsafeRawPointer, count: Int) -> Int {
        let space = sendBuf.count - sendSize
        guard space > 0 else { return 0 }
        var n = count
        if n > space { n = space }
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
        peekSendDataNetBuf(max: max, headroom: 0).toArray()
    }

    /// Copy up to `max` bytes of unacked data from the send circular buffer
    /// into a contiguous NetBuf. Handles wrap-around correctly.
    /// `headroom` bytes are reserved for future IP+Ethernet header prepending.
    func peekSendDataNetBuf(max: Int, headroom: Int = 0) -> NetBuf {
        let avail = sendAvail
        let sent = Int(sndNxt - sndUna)
        guard sent < avail, avail > 0, max > 0 else { return NetBuf(capacity: 0) }
        let remaining = avail - sent
        var n = remaining
        if n > max { n = max }
        let nb = NetBuf(capacity: headroom + n, headroom: headroom)
        guard let ptr = nb.appendPointer(count: n) else { return nb }
        let start = (sendHead + sent) % sendBuf.count
        let first = min(n, sendBuf.count - start)
        sendBuf.withUnsafeBytes { src in
            guard let srcBase = src.baseAddress else { return }
            memcpy(ptr, srcBase.advanced(by: start), first)
            if n > first {
                memcpy(ptr.advanced(by: first), srcBase, n - first)
            }
        }
        return nb
    }
}
