import Foundation

// MARK: - Constants

let etherTypeIPv4: UInt16 = 0x0800
let etherTypeARP: UInt16 = 0x0806

let arpRequest: UInt16 = 1
let arpReply: UInt16 = 2
let hardwareTypeEthernet: UInt16 = 1

let broadcastMAC = Data([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF])
let zeroMAC = Data([0, 0, 0, 0, 0, 0])

// MARK: - Ethernet Frame

struct Frame: CustomStringConvertible {
    let dstMAC: Data
    let srcMAC: Data
    let etherType: UInt16
    let payload: Data

    static let headerSize = 14

    static func parse(_ data: [UInt8]) -> Frame? {
        // Legacy path: bridge through Data (one copy). Prefer parse(Data) for hot path.
        parse(Data(data))
    }

    static func parse(_ data: Data) -> Frame? {
        guard data.count >= headerSize else { return nil }
        return Frame(
            dstMAC: data.subdata(in: 0..<6),
            srcMAC: data.subdata(in: 6..<12),
            etherType: UInt16(data[12]) << 8 | UInt16(data[13]),
            payload: data.subdata(in: headerSize..<data.count)
        )
    }

    func serialize() -> [UInt8] {
        let nb = NetBuf(capacity: Frame.headerSize + payload.count, headroom: Frame.headerSize)
        payload.withUnsafeBytes { _ = nb.append(bytes: $0.baseAddress!, count: payload.count) }
        _ = prependEtherHeader(into: nb)
        return nb.toArray()
    }

    /// Prepend Ethernet header (14 bytes) into a NetBuf's headroom.
    /// The payload should already be in the NetBuf's data region.
    @discardableResult
    func prependEtherHeader(into buf: NetBuf) -> Bool {
        guard let ptr = buf.prependPointer(count: Frame.headerSize) else { return false }
        dstMAC.withUnsafeBytes { r in memcpy(ptr, r.baseAddress!, min(6, dstMAC.count)) }
        srcMAC.withUnsafeBytes { r in memcpy(ptr.advanced(by: 6), r.baseAddress!, min(6, srcMAC.count)) }
        ptr[12] = UInt8(etherType >> 8)
        ptr[13] = UInt8(etherType & 0xFF)
        return true
    }

    var description: String {
        "Frame src=\(macStr(srcMAC)) dst=\(macStr(dstMAC)) type=0x\(String(etherType, radix: 16)) len=\(payload.count)"
    }
}

func macStr(_ mac: Data) -> String {
    mac.prefix(6).map { String(format: "%02x", $0) }.joined(separator: ":")
}

/// Prepend Ethernet header (14 bytes) directly into a NetBuf's headroom.
/// Usually called after IP+payload are already in the NetBuf.
/// Returns false if headroom is insufficient.
@discardableResult
func prependEthernetHeader(into buf: NetBuf, dstMAC: Data, srcMAC: Data, etherType: UInt16) -> Bool {
    guard let ptr = buf.prependPointer(count: 14) else { return false }
    dstMAC.withUnsafeBytes { r in memcpy(ptr, r.baseAddress!, min(6, dstMAC.count)) }
    srcMAC.withUnsafeBytes { r in memcpy(ptr.advanced(by: 6), r.baseAddress!, min(6, srcMAC.count)) }
    ptr[12] = UInt8(etherType >> 8)
    ptr[13] = UInt8(etherType & 0xFF)
    return true
}

// MARK: - ARP Packet

struct ARPPacket {
    let hardwareType: UInt16
    let protocolType: UInt16
    let hardwareLen: UInt8
    let protocolLen: UInt8
    let operation: UInt16
    let senderMAC: Data
    let senderIP: Data
    let targetMAC: Data
    let targetIP: Data

    static func parse(_ data: [UInt8]) -> ARPPacket? {
        guard data.count >= 28 else { return nil }
        return ARPPacket(
            hardwareType: UInt16(data[0]) << 8 | UInt16(data[1]),
            protocolType: UInt16(data[2]) << 8 | UInt16(data[3]),
            hardwareLen: data[4],
            protocolLen: data[5],
            operation: UInt16(data[6]) << 8 | UInt16(data[7]),
            senderMAC: Data(data[8..<14]),
            senderIP: Data(data[14..<18]),
            targetMAC: Data(data[18..<24]),
            targetIP: Data(data[24..<28])
        )
    }

    func serialize() -> [UInt8] {
        let nb = NetBuf(capacity: 28, headroom: 0)
        return serialize(into: nb).toArray()
    }

    /// Write ARP packet into the data region of a NetBuf.
    /// Returns the NetBuf for chaining.
    @discardableResult
    func serialize(into buf: NetBuf) -> NetBuf {
        guard let ptr = buf.appendPointer(count: 28) else { return buf }
        ptr[0] = UInt8(hardwareType >> 8); ptr[1] = UInt8(hardwareType & 0xFF)
        ptr[2] = UInt8(protocolType >> 8); ptr[3] = UInt8(protocolType & 0xFF)
        ptr[4] = hardwareLen; ptr[5] = protocolLen
        ptr[6] = UInt8(operation >> 8); ptr[7] = UInt8(operation & 0xFF)
        senderMAC.withUnsafeBytes { r in memcpy(ptr.advanced(by: 8), r.baseAddress!, min(6, senderMAC.count)) }
        senderIP.withUnsafeBytes { r in memcpy(ptr.advanced(by: 14), r.baseAddress!, min(4, senderIP.count)) }
        targetMAC.withUnsafeBytes { r in memcpy(ptr.advanced(by: 18), r.baseAddress!, min(6, targetMAC.count)) }
        targetIP.withUnsafeBytes { r in memcpy(ptr.advanced(by: 24), r.baseAddress!, min(4, targetIP.count)) }
        return buf
    }
}

func buildARPReply(senderMAC: Data, senderIP: Data, targetMAC: Data, targetIP: Data) -> ARPPacket {
    ARPPacket(
        hardwareType: hardwareTypeEthernet,
        protocolType: etherTypeIPv4,
        hardwareLen: 6,
        protocolLen: 4,
        operation: arpReply,
        senderMAC: senderMAC,
        senderIP: senderIP,
        targetMAC: targetMAC,
        targetIP: targetIP
    )
}
