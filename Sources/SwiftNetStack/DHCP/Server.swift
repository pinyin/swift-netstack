import Foundation

// MARK: - Constants

let serverPort: UInt16 = 67
let clientPort: UInt16 = 68

let opReply: UInt8 = 2

let msgDiscover: UInt8 = 1
let msgOffer: UInt8 = 2
let msgRequest: UInt8 = 3
let msgAck: UInt8 = 5
let msgNak: UInt8 = 6
let msgRelease: UInt8 = 7
let msgInform: UInt8 = 8

let optSubnetMask: UInt8 = 1
let optRouter: UInt8 = 3
let optDNSServer: UInt8 = 6
let optDomainName: UInt8 = 15
let optRequestedIP: UInt8 = 50
let optLeaseTime: UInt8 = 51
let optMessageType: UInt8 = 53
let optServerIdentifier: UInt8 = 54
let optEnd: UInt8 = 255

let magicCookie: UInt32 = 0x63825363

struct MACAddr: Hashable {
    let b0, b1, b2, b3, b4, b5: UInt8
}
extension MACAddr {
    init(_ a: UInt8, _ b: UInt8, _ c: UInt8, _ d: UInt8, _ e: UInt8, _ f: UInt8) {
        b0 = a; b1 = b; b2 = c; b3 = d; b4 = e; b5 = f
    }
    var tuple: (UInt8, UInt8, UInt8, UInt8, UInt8, UInt8) { (b0, b1, b2, b3, b4, b5) }
}

// MARK: - Server Config

struct DHCPServerConfig {
    var gatewayIP: UInt32 = ipToUInt32("192.168.65.1")
    var subnetMask: UInt32 = ipToUInt32("255.255.255.0")
    var dnsIP: UInt32 = ipToUInt32("192.168.65.1")
    var domainName: String = "bdp.local"
    var poolStart: UInt32 = ipToUInt32("192.168.65.2")
    var poolSize: Int = 50

    static func defaultConfig() -> DHCPServerConfig { DHCPServerConfig() }
}

// MARK: - Lease

struct Lease {
    let clientMAC: MACAddr
    let ip: UInt32
}

// MARK: - DHCP Server

final class DHCPServer {
    let cfg: DHCPServerConfig
    var leases: [MACAddr: Lease] = [:]
    var allocated: Set<UInt32> = []

    var onLease: ((UInt32, MACAddr) -> Void)?

    init(cfg: DHCPServerConfig) {
        self.cfg = cfg
    }

    func handler() -> UDPHandler {
        return { [weak self] dg in
            guard let self = self, let resp = self.process(dg) else { return [] }
            return [resp]
        }
    }

    // MARK: - Process

    func process(_ dg: UDPDatagram) -> UDPDatagram? {
        let payload = dg.payload
        guard payload.count >= 240 else { return nil }
        guard payload[0] == 1 else { return nil } // not a request

        let clientMAC = MACAddr(
            payload[28], payload[29], payload[30],
            payload[31], payload[32], payload[33]
        )

        guard let msgType = getOption(payload, optType: optMessageType), msgType.count >= 1 else {
            return nil
        }

        switch msgType[0] {
        case msgDiscover:
            return buildOffer(dg, clientMAC: clientMAC)
        case msgRequest:
            return buildAck(dg, clientMAC: clientMAC)
        case msgRelease:
            releaseLease(clientMAC)
            return nil
        default:
            return nil
        }
    }

    // MARK: - Build Responses

    func buildOffer(_ dg: UDPDatagram, clientMAC: MACAddr) -> UDPDatagram? {
        guard let ip = allocateIP(clientMAC) else { return nil }
        let txID = Array(dg.payload[4..<8])
        let responsePayload = buildResponse(msgOffer, txID: txID, clientMAC: clientMAC, assignedIP: ip)
        let broadcastIP = ipToUInt32("255.255.255.255")
        return UDPDatagram(srcIP: cfg.gatewayIP, dstIP: broadcastIP,
                           srcPort: serverPort, dstPort: clientPort,
                           payload: responsePayload)
    }

    func buildAck(_ dg: UDPDatagram, clientMAC: MACAddr) -> UDPDatagram? {
        let txID = Array(dg.payload[4..<8])

        var reqIP: UInt32 = 0
        if let reqIPOpt = getOption(dg.payload, optType: optRequestedIP), reqIPOpt.count >= 4 {
            reqIP = UInt32(reqIPOpt[0]) << 24 | UInt32(reqIPOpt[1]) << 16 |
                    UInt32(reqIPOpt[2]) << 8 | UInt32(reqIPOpt[3])
        } else {
            let p = dg.payload
            reqIP = UInt32(p[12]) << 24 | UInt32(p[13]) << 16 |
                    UInt32(p[14]) << 8 | UInt32(p[15])
        }

        guard reqIP != 0 else { return nil }

        let lease = leases[clientMAC]
        let isAck = lease != nil && lease!.ip == reqIP
        let msgType: UInt8 = isAck ? msgAck : msgNak
        let dstIP: UInt32 = isAck ? reqIP : ipToUInt32("255.255.255.255")

        let responsePayload = buildResponse(msgType, txID: txID, clientMAC: clientMAC, assignedIP: reqIP)

        if isAck {
            onLease?(reqIP, clientMAC)
        }

        return UDPDatagram(srcIP: cfg.gatewayIP, dstIP: dstIP,
                           srcPort: serverPort, dstPort: clientPort,
                           payload: responsePayload)
    }

    // MARK: - buildResponse

    func buildResponse(_ msgType: UInt8, txID: [UInt8], clientMAC: MACAddr, assignedIP: UInt32) -> [UInt8] {
        var buf = [UInt8](repeating: 0, count: 300)

        buf[0] = opReply
        buf[1] = 1 // htype
        buf[2] = 6 // hlen
        buf[3] = 0 // hops
        buf[4] = txID[0]; buf[5] = txID[1]; buf[6] = txID[2]; buf[7] = txID[3]
        buf[10] = 0x80 // flags: broadcast

        // yiaddr
        buf[16] = UInt8(assignedIP >> 24); buf[17] = UInt8(assignedIP >> 16 & 0xFF)
        buf[18] = UInt8(assignedIP >> 8 & 0xFF); buf[19] = UInt8(assignedIP & 0xFF)

        // chaddr
        buf[28] = clientMAC.b0; buf[29] = clientMAC.b1; buf[30] = clientMAC.b2
        buf[31] = clientMAC.b3; buf[32] = clientMAC.b4; buf[33] = clientMAC.b5

        // Magic cookie
        buf[236] = UInt8(magicCookie >> 24); buf[237] = UInt8(magicCookie >> 16 & 0xFF)
        buf[238] = UInt8(magicCookie >> 8 & 0xFF); buf[239] = UInt8(magicCookie & 0xFF)

        var offset = 240

        offset = writeOption(&buf, offset: offset, optType: optMessageType, val: [msgType])
        offset = writeOption(&buf, offset: offset, optType: optServerIdentifier,
                             val: [UInt8(cfg.gatewayIP >> 24), UInt8(cfg.gatewayIP >> 16 & 0xFF),
                                   UInt8(cfg.gatewayIP >> 8 & 0xFF), UInt8(cfg.gatewayIP & 0xFF)])
        offset = writeOption(&buf, offset: offset, optType: optSubnetMask,
                             val: [UInt8(cfg.subnetMask >> 24), UInt8(cfg.subnetMask >> 16 & 0xFF),
                                   UInt8(cfg.subnetMask >> 8 & 0xFF), UInt8(cfg.subnetMask & 0xFF)])
        offset = writeOption(&buf, offset: offset, optType: optRouter,
                             val: [UInt8(cfg.gatewayIP >> 24), UInt8(cfg.gatewayIP >> 16 & 0xFF),
                                   UInt8(cfg.gatewayIP >> 8 & 0xFF), UInt8(cfg.gatewayIP & 0xFF)])
        offset = writeOption(&buf, offset: offset, optType: optDNSServer,
                             val: [UInt8(cfg.dnsIP >> 24), UInt8(cfg.dnsIP >> 16 & 0xFF),
                                   UInt8(cfg.dnsIP >> 8 & 0xFF), UInt8(cfg.dnsIP & 0xFF)])

        // Lease time: 3600 seconds
        let lt: [UInt8] = [0, 0, 0x0E, 0x10]
        offset = writeOption(&buf, offset: offset, optType: optLeaseTime, val: lt)

        if !cfg.domainName.isEmpty {
            offset = writeOption(&buf, offset: offset, optType: optDomainName,
                                 val: [UInt8](cfg.domainName.utf8))
        }

        buf[offset] = optEnd
        offset += 1

        return Array(buf[..<offset])
    }

    // MARK: - IP Allocation

    func allocateIP(_ clientMAC: MACAddr) -> UInt32? {
        if let lease = leases[clientMAC] {
            return lease.ip
        }

        for i in 0..<cfg.poolSize {
            let ip = cfg.poolStart + UInt32(i)
            if !allocated.contains(ip) {
                allocated.insert(ip)
                leases[clientMAC] = Lease(clientMAC: clientMAC, ip: ip)
                return ip
            }
        }
        return nil
    }

    func releaseLease(_ clientMAC: MACAddr) {
        guard let lease = leases[clientMAC] else { return }
        allocated.remove(lease.ip)
        leases[clientMAC] = nil
    }

    // MARK: - Option Parsing

    func getOption(_ data: [UInt8], optType: UInt8) -> [UInt8]? {
        guard data.count >= 240 else { return nil }
        let cookie = UInt32(data[236]) << 24 | UInt32(data[237]) << 16 |
                     UInt32(data[238]) << 8 | UInt32(data[239])
        guard cookie == magicCookie else { return nil }

        var i = 240
        while i < data.count {
            let t = data[i]
            if t == optEnd { return nil }
            guard i + 2 <= data.count else { return nil }
            let l = Int(data[i + 1])
            guard i + 2 + l <= data.count else { return nil }
            if t == optType {
                return Array(data[i + 2..<i + 2 + l])
            }
            i += 2 + l
        }
        return nil
    }
}

func writeOption(_ buf: inout [UInt8], offset: Int, optType: UInt8, val: [UInt8]) -> Int {
    buf[offset] = optType
    buf[offset + 1] = UInt8(val.count)
    for i in 0..<val.count { buf[offset + 2 + i] = val[i] }
    return offset + 2 + val.count
}
