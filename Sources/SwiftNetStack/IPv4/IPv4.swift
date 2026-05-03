import Foundation

// MARK: - Constants

let protocolICMP: UInt8 = 1
let protocolTCP: UInt8 = 6
let protocolUDP: UInt8 = 17

let icmpTypeEchoReply: UInt8 = 0
let icmpTypeEchoRequest: UInt8 = 8

// MARK: - IPv4 Packet

struct IPv4Packet {
    let version: UInt8
    let ihl: UInt8
    let tos: UInt8
    let totalLen: UInt16
    let id: UInt16
    let flags: UInt8
    let fragOffset: UInt16
    let ttl: UInt8
    let `protocol`: UInt8
    let checksum: UInt16
    let srcIP: UInt32
    let dstIP: UInt32
    let payload: [UInt8]

    static func parse(_ data: [UInt8]) -> IPv4Packet? {
        guard data.count >= 20 else { return nil }
        let verIHL = data[0]
        let ihl = (verIHL & 0x0F) * 4
        guard ihl >= 20, Int(ihl) <= data.count else { return nil }

        var totalLen = UInt16(data[2]) << 8 | UInt16(data[3])
        if Int(totalLen) > data.count { totalLen = UInt16(data.count) }

        let srcIP = UInt32(data[12]) << 24 | UInt32(data[13]) << 16 | UInt32(data[14]) << 8 | UInt32(data[15])
        let dstIP = UInt32(data[16]) << 24 | UInt32(data[17]) << 16 | UInt32(data[18]) << 8 | UInt32(data[19])

        let fragField = UInt16(data[6]) << 8 | UInt16(data[7])

        let payloadEnd = Int(totalLen)
        let clippedEnd = min(payloadEnd, data.count)
        let hdrEnd = Int(ihl)
        var payload = [UInt8]()
        if hdrEnd < clippedEnd {
            payload = Array(data[hdrEnd..<clippedEnd])
        }

        return IPv4Packet(
            version: verIHL >> 4,
            ihl: ihl,
            tos: data[1],
            totalLen: totalLen,
            id: UInt16(data[4]) << 8 | UInt16(data[5]),
            flags: data[6] >> 5,
            fragOffset: fragField & 0x1FFF,
            ttl: data[8],
            protocol: data[9],
            checksum: UInt16(data[10]) << 8 | UInt16(data[11]),
            srcIP: srcIP,
            dstIP: dstIP,
            payload: payload
        )
    }

    func serialize() -> [UInt8] {
        let hdrLen = Int(ihl > 0 ? ihl : 20)
        var buf = [UInt8](repeating: 0, count: hdrLen + payload.count)

        buf[0] = (version << 4) | (ihl / 4)
        buf[1] = tos
        let totalLen16 = UInt16(buf.count)
        buf[2] = UInt8(totalLen16 >> 8); buf[3] = UInt8(totalLen16 & 0xFF)
        buf[4] = UInt8(id >> 8); buf[5] = UInt8(id & 0xFF)
        let fragField = (UInt16(flags) << 13) | (fragOffset & 0x1FFF)
        buf[6] = UInt8(fragField >> 8); buf[7] = UInt8(fragField & 0xFF)
        buf[8] = ttl
        buf[9] = self.protocol
        buf[10] = 0; buf[11] = 0 // checksum placeholder
        buf[12] = UInt8(srcIP >> 24); buf[13] = UInt8(srcIP >> 16 & 0xFF)
        buf[14] = UInt8(srcIP >> 8 & 0xFF); buf[15] = UInt8(srcIP & 0xFF)
        buf[16] = UInt8(dstIP >> 24); buf[17] = UInt8(dstIP >> 16 & 0xFF)
        buf[18] = UInt8(dstIP >> 8 & 0xFF); buf[19] = UInt8(dstIP & 0xFF)
        for i in 0..<payload.count { buf[hdrLen + i] = payload[i] }

        let cs = ipChecksum(Array(buf[0..<hdrLen]))
        buf[10] = UInt8(cs >> 8); buf[11] = UInt8(cs & 0xFF)
        return buf
    }

    func isForUs(_ ourIP: UInt32) -> Bool {
        dstIP == ourIP || dstIP == 0xFFFFFFFF
    }

    func isFragmented() -> Bool {
        fragOffset != 0 || (flags & 0x01) != 0
    }
}

// MARK: - ICMP Packet

struct ICMPPacket {
    let type: UInt8
    let code: UInt8
    let checksum: UInt16
    let restHdr: UInt32
    let payload: [UInt8]

    static func parse(_ data: [UInt8]) -> ICMPPacket? {
        guard data.count >= 8 else { return nil }
        return ICMPPacket(
            type: data[0],
            code: data[1],
            checksum: UInt16(data[2]) << 8 | UInt16(data[3]),
            restHdr: UInt32(data[4]) << 24 | UInt32(data[5]) << 16 | UInt32(data[6]) << 8 | UInt32(data[7]),
            payload: Array(data[8...])
        )
    }

    func serialize() -> [UInt8] {
        var buf = [UInt8](repeating: 0, count: 8 + payload.count)
        buf[0] = type; buf[1] = code
        buf[2] = 0; buf[3] = 0 // checksum placeholder
        buf[4] = UInt8(restHdr >> 24); buf[5] = UInt8(restHdr >> 16 & 0xFF)
        buf[6] = UInt8(restHdr >> 8 & 0xFF); buf[7] = UInt8(restHdr & 0xFF)
        for i in 0..<payload.count { buf[8 + i] = payload[i] }
        let cs = ipChecksum(buf)
        buf[2] = UInt8(cs >> 8); buf[3] = UInt8(cs & 0xFF)
        return buf
    }
}

func buildEchoReply(_ req: ICMPPacket) -> ICMPPacket {
    ICMPPacket(type: icmpTypeEchoReply, code: 0, checksum: 0, restHdr: req.restHdr, payload: req.payload)
}

// MARK: - IP Checksum

func ipChecksum(_ data: [UInt8]) -> UInt16 {
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
