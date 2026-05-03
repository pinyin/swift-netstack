import Foundation

// MARK: - UDP Datagram

struct UDPDatagram {
    let srcIP: UInt32
    let dstIP: UInt32
    let srcPort: UInt16
    let dstPort: UInt16
    let payload: [UInt8]
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
}

func parseUDP(_ data: [UInt8]) -> (UDPHeader, [UInt8])? {
    guard let hdr = UDPHeader.parse(data) else { return nil }
    var payloadLen = Int(hdr.length) - 8
    if payloadLen < 0 { payloadLen = 0 }
    let maxPayload = data.count - 8
    if payloadLen > maxPayload { payloadLen = maxPayload }
    let payload = payloadLen > 0 ? Array(data[8..<8 + payloadLen]) : []
    return (hdr, payload)
}

func buildDatagram(srcPort: UInt16, dstPort: UInt16, payload: [UInt8]) -> [UInt8] {
    let totalLen = 8 + payload.count
    var buf = [UInt8](repeating: 0, count: totalLen)
    buf[0] = UInt8(srcPort >> 8); buf[1] = UInt8(srcPort & 0xFF)
    buf[2] = UInt8(dstPort >> 8); buf[3] = UInt8(dstPort & 0xFF)
    buf[4] = UInt8(UInt16(totalLen) >> 8); buf[5] = UInt8(UInt16(totalLen) & 0xFF)
    buf[6] = 0; buf[7] = 0 // checksum optional for IPv4
    for i in 0..<payload.count { buf[8 + i] = payload[i] }
    return buf
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
