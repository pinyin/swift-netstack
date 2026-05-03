import Foundation

// MARK: - UDP Datagram

struct UDPDatagram {
    let srcIP: UInt32
    let dstIP: UInt32
    let srcPort: UInt16
    let dstPort: UInt16
    let payload: Data
}

// MARK: - UDP Header

struct UDPHeader {
    let srcPort: UInt16
    let dstPort: UInt16
    let length: UInt16
    let checksum: UInt16

    static func parse(_ data: [UInt8]) -> UDPHeader? {
        guard data.count >= 8 else { return nil }
        return UDPHeader(
            srcPort: UInt16(data[0]) << 8 | UInt16(data[1]),
            dstPort: UInt16(data[2]) << 8 | UInt16(data[3]),
            length: UInt16(data[4]) << 8 | UInt16(data[5]),
            checksum: UInt16(data[6]) << 8 | UInt16(data[7])
        )
    }

    static func parse(_ data: Data) -> UDPHeader? {
        guard data.count >= 8 else { return nil }
        return UDPHeader(
            srcPort: UInt16(data[0]) << 8 | UInt16(data[1]),
            dstPort: UInt16(data[2]) << 8 | UInt16(data[3]),
            length: UInt16(data[4]) << 8 | UInt16(data[5]),
            checksum: UInt16(data[6]) << 8 | UInt16(data[7])
        )
    }
}

func parseUDP(_ data: [UInt8]) -> (UDPHeader, Data)? {
    parseUDP(Data(data))
}

/// Zero-copy parse: payload is a Data slice sharing the input buffer.
func parseUDP(_ data: Data) -> (UDPHeader, Data)? {
    guard let hdr = UDPHeader.parse(data) else { return nil }
    var payloadLen = Int(hdr.length) - 8
    if payloadLen < 0 { payloadLen = 0 }
    let maxPayload = data.count - 8
    if payloadLen > maxPayload { payloadLen = maxPayload }
    let payload = payloadLen > 0 ? data.subdata(in: 8..<8 + payloadLen) : Data()
    return (hdr, payload)
}

func buildDatagram(srcPort: UInt16, dstPort: UInt16, payload: Data) -> [UInt8] {
    let nb = NetBuf(capacity: payload.count, headroom: 0)
    payload.withUnsafeBytes { _ = nb.append(bytes: $0.baseAddress!, count: payload.count) }
    return buildDatagramNetBuf(srcPort: srcPort, dstPort: dstPort, payload: nb).toArray()
}

/// Build a UDP datagram in a NetBuf with headroom for IP (20B) + Ethernet (14B) headers.
/// Returns a NetBuf with: [14B Eth headroom | 20B IP headroom | 8B UDP header | payload].
func buildDatagramNetBuf(srcPort: UInt16, dstPort: UInt16, payload: NetBuf) -> NetBuf {
    let ethHdrLen = 14
    let ipHdrLen = 20
    let udpHdrLen = 8
    let totalHeadroom = ethHdrLen + ipHdrLen + udpHdrLen

    let nb = NetBuf(capacity: totalHeadroom + payload.length, headroom: totalHeadroom)
    _ = nb.append(copying: payload)

    guard let ptr = nb.prependPointer(count: udpHdrLen) else { return nb }
    ptr[0] = UInt8(srcPort >> 8); ptr[1] = UInt8(srcPort & 0xFF)
    ptr[2] = UInt8(dstPort >> 8); ptr[3] = UInt8(dstPort & 0xFF)
    let totalLen = UInt16(udpHdrLen + payload.length)
    ptr[4] = UInt8(totalLen >> 8); ptr[5] = UInt8(totalLen & 0xFF)
    ptr[6] = 0; ptr[7] = 0 // checksum optional for IPv4
    return nb
}

// MARK: - UDP Checksum

/// Compute UDP checksum over the pseudo-header + UDP datagram.
/// Returns 0 if the checksum is correct.
func udpChecksum(srcIP: UInt32, dstIP: UInt32, udpData: [UInt8]) -> UInt16 {
    udpData.withUnsafeBytes { udpChecksum(srcIP: srcIP, dstIP: dstIP, udpDataPtr: $0.baseAddress!, udpDataCount: udpData.count) }
}

func udpChecksum(srcIP: UInt32, dstIP: UInt32, udpDataPtr: UnsafeRawPointer, udpDataCount: Int) -> UInt16 {
    var sum: UInt32 = 0

    // Pseudo-header
    sum += UInt32(srcIP >> 16)
    sum += UInt32(srcIP & 0xFFFF)
    sum += UInt32(dstIP >> 16)
    sum += UInt32(dstIP & 0xFFFF)
    sum += UInt32(protocolUDP)
    sum += UInt32(udpDataCount)

    // UDP datagram
    let bytes = udpDataPtr.assumingMemoryBound(to: UInt8.self)
    var i = 0
    while i < udpDataCount - 1 {
        sum += UInt32(UInt16(bytes[i]) << 8 | UInt16(bytes[i + 1]))
        i += 2
    }
    if i < udpDataCount {
        sum += UInt32(bytes[i]) << 8
    }

    while sum > 0xFFFF {
        sum = (sum & 0xFFFF) + (sum >> 16)
    }
    return ~UInt16(sum & 0xFFFF)
}

// MARK: - UDP Handler

typealias UDPHandler = (UDPDatagram) -> [UDPDatagram]

// MARK: - UDP Mux

final class UDPMux {
    private var handlers: [UInt16: UDPHandler] = [:]
    private var outputs: [UDPDatagram] = []

    init() {}

    func register(port: UInt16, handler: @escaping UDPHandler) {
        handlers[port] = handler
    }

    func deliver(_ dg: UDPDatagram) {
        guard let h = handlers[dg.dstPort] else { return }
        let responses = h(dg)
        outputs.append(contentsOf: responses)
    }

    func consumeOutputs() -> [UDPDatagram] {
        let out = outputs
        outputs = []
        return out
    }
}
