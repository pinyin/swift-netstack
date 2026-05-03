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
        guard data.count >= headerSize else { return nil }
        return Frame(
            dstMAC: Data(data[0..<6]),
            srcMAC: Data(data[6..<12]),
            etherType: UInt16(data[12]) << 8 | UInt16(data[13]),
            payload: Data(data[headerSize...])
        )
    }

    func serialize() -> [UInt8] {
        var buf = [UInt8](repeating: 0, count: Frame.headerSize + payload.count)
        for i in 0..<min(6, dstMAC.count) { buf[i] = dstMAC[i] }
        for i in 0..<min(6, srcMAC.count) { buf[6 + i] = srcMAC[i] }
        buf[12] = UInt8(etherType >> 8)
        buf[13] = UInt8(etherType & 0xFF)
        for i in 0..<payload.count { buf[Frame.headerSize + i] = payload[i] }
        return buf
    }

    var description: String {
        "Frame src=\(macStr(srcMAC)) dst=\(macStr(dstMAC)) type=0x\(String(etherType, radix: 16)) len=\(payload.count)"
    }
}

func macStr(_ mac: Data) -> String {
    mac.prefix(6).map { String(format: "%02x", $0) }.joined(separator: ":")
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
        var buf = [UInt8](repeating: 0, count: 28)
        buf[0] = UInt8(hardwareType >> 8); buf[1] = UInt8(hardwareType & 0xFF)
        buf[2] = UInt8(protocolType >> 8); buf[3] = UInt8(protocolType & 0xFF)
        buf[4] = hardwareLen; buf[5] = protocolLen
        buf[6] = UInt8(operation >> 8); buf[7] = UInt8(operation & 0xFF)
        for i in 0..<min(6, senderMAC.count) { buf[8 + i] = senderMAC[i] }
        for i in 0..<min(4, senderIP.count) { buf[14 + i] = senderIP[i] }
        for i in 0..<min(6, targetMAC.count) { buf[18 + i] = targetMAC[i] }
        for i in 0..<min(4, targetIP.count) { buf[24 + i] = targetIP[i] }
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
