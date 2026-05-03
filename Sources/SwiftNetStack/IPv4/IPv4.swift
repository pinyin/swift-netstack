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
    let payload: Data

    static func parse(_ data: [UInt8]) -> IPv4Packet? {
        // Legacy path: copy to Data first. Prefer parse(Data) for hot path.
        parse(Data(data))
    }

    /// Zero-copy parse: payload is a Data slice sharing the input buffer.
    static func parse(_ data: Data) -> IPv4Packet? {
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
        let payload: Data
        if hdrEnd < clippedEnd {
            payload = data.subdata(in: hdrEnd..<clippedEnd)
        } else {
            payload = Data()
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
        let nb = NetBuf(capacity: hdrLen + payload.count, headroom: hdrLen)
        payload.withUnsafeBytes { _ = nb.append(bytes: $0.baseAddress!, count: payload.count) }
        _ = serialize(into: nb)
        return nb.toArray()
    }

    /// Prepend IPv4 header into a NetBuf's headroom.
    /// The payload should already be in the NetBuf's data region.
    @discardableResult
    func serialize(into buf: NetBuf) -> Bool {
        let hdrLen = Int(ihl > 0 ? ihl : 20)
        guard let ptr = buf.prependPointer(count: hdrLen) else { return false }

        ptr[0] = (version << 4) | (ihl / 4)
        ptr[1] = tos
        let total = UInt16(buf.length)
        ptr[2] = UInt8(total >> 8); ptr[3] = UInt8(total & 0xFF)
        ptr[4] = UInt8(id >> 8); ptr[5] = UInt8(id & 0xFF)
        let fragField = (UInt16(flags) << 13) | (fragOffset & 0x1FFF)
        ptr[6] = UInt8(fragField >> 8); ptr[7] = UInt8(fragField & 0xFF)
        ptr[8] = ttl
        ptr[9] = self.protocol
        ptr[10] = 0; ptr[11] = 0 // checksum placeholder
        ptr[12] = UInt8(srcIP >> 24); ptr[13] = UInt8(srcIP >> 16 & 0xFF)
        ptr[14] = UInt8(srcIP >> 8 & 0xFF); ptr[15] = UInt8(srcIP & 0xFF)
        ptr[16] = UInt8(dstIP >> 24); ptr[17] = UInt8(dstIP >> 16 & 0xFF)
        ptr[18] = UInt8(dstIP >> 8 & 0xFF); ptr[19] = UInt8(dstIP & 0xFF)

        // Compute checksum directly on the header bytes (no copy)
        let cs = ipChecksum(ptr: UnsafeRawPointer(ptr), count: hdrLen)
        ptr[10] = UInt8(cs >> 8); ptr[11] = UInt8(cs & 0xFF)
        return true
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
    let payload: Data

    static func parse(_ data: [UInt8]) -> ICMPPacket? {
        parse(Data(data))
    }

    static func parse(_ data: Data) -> ICMPPacket? {
        guard data.count >= 8 else { return nil }
        return ICMPPacket(
            type: data[0],
            code: data[1],
            checksum: UInt16(data[2]) << 8 | UInt16(data[3]),
            restHdr: UInt32(data[4]) << 24 | UInt32(data[5]) << 16 | UInt32(data[6]) << 8 | UInt32(data[7]),
            payload: data.count > 8 ? data.subdata(in: 8..<data.count) : Data()
        )
    }

    func serialize() -> [UInt8] {
        let nb = NetBuf(capacity: 8 + payload.count, headroom: 8)
        payload.withUnsafeBytes { _ = nb.append(bytes: $0.baseAddress!, count: payload.count) }
        _ = serialize(into: nb)
        return nb.toArray()
    }

    /// Prepend ICMP header (8 bytes) into a NetBuf's headroom.
    /// The payload should already be in the NetBuf's data region.
    @discardableResult
    func serialize(into buf: NetBuf) -> Bool {
        guard let ptr = buf.prependPointer(count: 8) else { return false }
        ptr[0] = type; ptr[1] = code
        ptr[2] = 0; ptr[3] = 0 // checksum placeholder
        ptr[4] = UInt8(restHdr >> 24); ptr[5] = UInt8(restHdr >> 16 & 0xFF)
        ptr[6] = UInt8(restHdr >> 8 & 0xFF); ptr[7] = UInt8(restHdr & 0xFF)

        // Compute checksum over ICMP header + payload
        let cs = ipChecksum(ptr: UnsafeRawPointer(ptr), count: buf.length)
        ptr[2] = UInt8(cs >> 8); ptr[3] = UInt8(cs & 0xFF)
        return true
    }
}

func buildEchoReply(_ req: ICMPPacket) -> ICMPPacket {
    ICMPPacket(type: icmpTypeEchoReply, code: 0, checksum: 0, restHdr: req.restHdr, payload: req.payload)
}

// MARK: - IP Checksum

func ipChecksum(_ data: [UInt8]) -> UInt16 {
    data.withUnsafeBytes { ipChecksum(ptr: $0.baseAddress!, count: data.count) }
}

func ipChecksum(ptr: UnsafeRawPointer, count: Int) -> UInt16 {
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
