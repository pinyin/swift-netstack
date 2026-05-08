import Darwin
@testable import SwiftNetStack

// MARK: - Buffer helpers

func packetFrom(_ bytes: [UInt8]) -> PacketBuffer {
    let s = Storage.allocate(capacity: bytes.count)
    bytes.withUnsafeBytes { s.data.copyMemory(from: $0.baseAddress!, byteCount: bytes.count) }
    return PacketBuffer(storage: s, offset: 0, length: bytes.count)
}

func ipBytes(_ ip: IPv4Address) -> [UInt8] {
    var buf = [UInt8](repeating: 0, count: 4)
    ip.write(to: &buf)
    return buf
}

// MARK: - Ethernet frame builders

func makeEthernetFrameBytes(dst: MACAddress, src: MACAddress, type: EtherType, payload: [UInt8]) -> [UInt8] {
    var bytes: [UInt8] = []
    var buf6 = [UInt8](repeating: 0, count: 6)
    dst.write(to: &buf6); bytes.append(contentsOf: buf6)
    src.write(to: &buf6); bytes.append(contentsOf: buf6)
    let etRaw = type.rawValue
    bytes.append(UInt8(etRaw >> 8))
    bytes.append(UInt8(etRaw & 0xFF))
    bytes.append(contentsOf: payload)
    return bytes
}

func makeEthernetFrame(dst: MACAddress, src: MACAddress, type: EtherType, payload: [UInt8]) -> PacketBuffer {
    packetFrom(makeEthernetFrameBytes(dst: dst, src: src, type: type, payload: payload))
}

func extractEtherPayload(_ pkt: PacketBuffer) -> [UInt8] {
    guard pkt.totalLength > 14, let payload = pkt.slice(from: 14, length: pkt.totalLength - 14) else { return [] }
    return payload.withUnsafeReadableBytes { Array($0) }
}

// MARK: - ARP payload

func makeARPPayload(op: ARPOperation, senderMAC: MACAddress, senderIP: IPv4Address, targetMAC: MACAddress, targetIP: IPv4Address) -> [UInt8] {
    var bytes = [UInt8](repeating: 0, count: 28)
    bytes[0] = 0x00; bytes[1] = 0x01
    bytes[2] = 0x08; bytes[3] = 0x00
    bytes[4] = 6; bytes[5] = 4
    bytes[6] = UInt8(op.rawValue >> 8)
    bytes[7] = UInt8(op.rawValue & 0xFF)
    var buf6 = [UInt8](repeating: 0, count: 6)
    var buf4 = [UInt8](repeating: 0, count: 4)
    senderMAC.write(to: &buf6); bytes.replaceSubrange(8..<14, with: buf6)
    senderIP.write(to: &buf4); bytes.replaceSubrange(14..<18, with: buf4)
    targetMAC.write(to: &buf6); bytes.replaceSubrange(18..<24, with: buf6)
    targetIP.write(to: &buf4); bytes.replaceSubrange(24..<28, with: buf4)
    return bytes
}

// MARK: - ICMP Echo frame

func makeICMPEchoFrame(dstMAC: MACAddress, clientMAC: MACAddress, clientIP: IPv4Address, dstIP: IPv4Address, id: UInt16, seq: UInt16, payload: [UInt8] = [0x70, 0x69, 0x6E, 0x67]) -> PacketBuffer {
    let icmpLen = 8 + payload.count
    let ipTotalLen = 20 + icmpLen

    var icmpBytes: [UInt8] = []
    icmpBytes.append(8); icmpBytes.append(0)
    icmpBytes.append(0); icmpBytes.append(0)
    icmpBytes.append(UInt8(id >> 8)); icmpBytes.append(UInt8(id & 0xFF))
    icmpBytes.append(UInt8(seq >> 8)); icmpBytes.append(UInt8(seq & 0xFF))
    icmpBytes.append(contentsOf: payload)
    let icmpCksum = icmpBytes.withUnsafeBytes { internetChecksum($0) }
    icmpBytes[2] = UInt8(icmpCksum >> 8)
    icmpBytes[3] = UInt8(icmpCksum & 0xFF)

    var ipHdr = [UInt8](repeating: 0, count: 20)
    ipHdr[0] = 0x45
    ipHdr[2] = UInt8(ipTotalLen >> 8)
    ipHdr[3] = UInt8(ipTotalLen & 0xFF)
    ipHdr[8] = 64
    ipHdr[9] = IPProtocol.icmp.rawValue
    clientIP.write(to: &ipHdr[12])
    dstIP.write(to: &ipHdr[16])
    let ipCksum = ipHdr.withUnsafeBytes { internetChecksum($0) }
    ipHdr[10] = UInt8(ipCksum >> 8)
    ipHdr[11] = UInt8(ipCksum & 0xFF)

    return makeEthernetFrame(dst: dstMAC, src: clientMAC, type: .ipv4, payload: ipHdr + icmpBytes)
}

func makeICMPEchoFrameBytes(dstMAC: MACAddress, clientMAC: MACAddress, clientIP: IPv4Address, dstIP: IPv4Address, id: UInt16, seq: UInt16, payload: [UInt8] = [0x70, 0x69, 0x6E, 0x67]) -> [UInt8] {
    let pkt = makeICMPEchoFrame(dstMAC: dstMAC, clientMAC: clientMAC, clientIP: clientIP, dstIP: dstIP, id: id, seq: seq, payload: payload)
    return pkt.withUnsafeReadableBytes { Array($0) }
}

// MARK: - DHCP frame

func makeDHCPFrame(dstMAC: MACAddress, clientMAC: MACAddress, dhcpPayload: [UInt8]) -> PacketBuffer {
    let udpLen = 8 + dhcpPayload.count
    let ipTotalLen = 20 + udpLen

    var ipHdr = [UInt8](repeating: 0, count: 20)
    ipHdr[0] = 0x45
    ipHdr[2] = UInt8(ipTotalLen >> 8)
    ipHdr[3] = UInt8(ipTotalLen & 0xFF)
    ipHdr[8] = 64
    ipHdr[9] = IPProtocol.udp.rawValue
    IPv4Address(10, 0, 0, 50).write(to: &ipHdr[12])
    IPv4Address(100, 64, 1, 1).write(to: &ipHdr[16])
    let ipCksum = ipHdr.withUnsafeBytes { internetChecksum($0) }
    ipHdr[10] = UInt8(ipCksum >> 8)
    ipHdr[11] = UInt8(ipCksum & 0xFF)

    var udpHdr = [UInt8](repeating: 0, count: 8)
    udpHdr[0] = 0x00; udpHdr[1] = 68
    udpHdr[2] = 0x00; udpHdr[3] = 67
    udpHdr[4] = UInt8(udpLen >> 8)
    udpHdr[5] = UInt8(udpLen & 0xFF)

    return makeEthernetFrame(dst: dstMAC, src: clientMAC, type: .ipv4, payload: ipHdr + udpHdr + dhcpPayload)
}

func makeDHCPFrameBytes(dstMAC: MACAddress, clientMAC: MACAddress, dhcpPayload: [UInt8]) -> [UInt8] {
    makeDHCPFrame(dstMAC: dstMAC, clientMAC: clientMAC, dhcpPayload: dhcpPayload)
        .withUnsafeReadableBytes { Array($0) }
}

func makeDHCPPacketBytes(op: UInt8, xid: UInt32, chaddr: MACAddress,
                          msgType: DHCPMessageType,
                          extraOptions: [(UInt8, [UInt8])] = []) -> [UInt8] {
    var bytes = [UInt8](repeating: 0, count: 243)
    bytes[0] = op
    bytes[1] = 1; bytes[2] = 6
    bytes[4] = UInt8((xid >> 24) & 0xFF)
    bytes[5] = UInt8((xid >> 16) & 0xFF)
    bytes[6] = UInt8((xid >> 8) & 0xFF)
    bytes[7] = UInt8(xid & 0xFF)
    var buf6 = [UInt8](repeating: 0, count: 6)
    chaddr.write(to: &buf6); bytes.replaceSubrange(28..<34, with: buf6)
    bytes[236] = 99; bytes[237] = 130; bytes[238] = 83; bytes[239] = 99
    bytes[240] = 53; bytes[241] = 1; bytes[242] = msgType.rawValue

    var optIdx = 243
    for (code, value) in extraOptions {
        if optIdx + 2 + value.count > bytes.count {
            bytes.append(contentsOf: [UInt8](repeating: 0, count: optIdx + 2 + value.count - bytes.count))
        }
        bytes[optIdx] = code
        bytes[optIdx + 1] = UInt8(value.count)
        bytes.replaceSubrange((optIdx + 2)..<(optIdx + 2 + value.count), with: value)
        optIdx += 2 + value.count
    }
    if optIdx >= bytes.count { bytes.append(0) }
    bytes[optIdx] = 255
    return bytes
}

// MARK: - UDP frame

func makeUDPFrame(dstMAC: MACAddress, clientMAC: MACAddress,
                  srcIP: IPv4Address, dstIP: IPv4Address,
                  srcPort: UInt16, dstPort: UInt16,
                  payload: [UInt8]) -> PacketBuffer {
    let udpLen = 8 + payload.count
    let ipTotalLen = 20 + udpLen

    var ipHdr = [UInt8](repeating: 0, count: 20)
    ipHdr[0] = 0x45
    ipHdr[2] = UInt8(ipTotalLen >> 8)
    ipHdr[3] = UInt8(ipTotalLen & 0xFF)
    ipHdr[6] = 0x40; ipHdr[7] = 0x00
    ipHdr[8] = 64
    ipHdr[9] = IPProtocol.udp.rawValue
    srcIP.write(to: &ipHdr[12])
    dstIP.write(to: &ipHdr[16])
    let ipCksum = ipHdr.withUnsafeBytes { internetChecksum($0) }
    ipHdr[10] = UInt8(ipCksum >> 8)
    ipHdr[11] = UInt8(ipCksum & 0xFF)

    var udpBytes: [UInt8] = []
    udpBytes.append(UInt8(srcPort >> 8))
    udpBytes.append(UInt8(srcPort & 0xFF))
    udpBytes.append(UInt8(dstPort >> 8))
    udpBytes.append(UInt8(dstPort & 0xFF))
    udpBytes.append(UInt8(udpLen >> 8))
    udpBytes.append(UInt8(udpLen & 0xFF))
    udpBytes.append(0); udpBytes.append(0)
    udpBytes.append(contentsOf: payload)

    var ckBuf = [UInt8](repeating: 0, count: 12 + udpLen)
    srcIP.write(to: &ckBuf[0])
    dstIP.write(to: &ckBuf[4])
    ckBuf[9] = IPProtocol.udp.rawValue
    ckBuf[10] = UInt8(udpLen >> 8)
    ckBuf[11] = UInt8(udpLen & 0xFF)
    for i in 0..<udpLen { ckBuf[12 + i] = udpBytes[i] }
    let ck = ckBuf.withUnsafeBytes { internetChecksum($0) }
    let finalCk = ck == 0 ? 0xFFFF : ck
    udpBytes[6] = UInt8(finalCk >> 8)
    udpBytes[7] = UInt8(finalCk & 0xFF)

    return makeEthernetFrame(dst: dstMAC, src: clientMAC, type: .ipv4, payload: ipHdr + udpBytes)
}

// MARK: - TCP SYN frame

func makeTCPSYNFrame(dstMAC: MACAddress, clientMAC: MACAddress,
                     srcIP: IPv4Address, dstIP: IPv4Address,
                     srcPort: UInt16, dstPort: UInt16) -> PacketBuffer {
    let tcpLen = 20
    let ipTotalLen = 20 + tcpLen

    var ipHdr = [UInt8](repeating: 0, count: 20)
    ipHdr[0] = 0x45
    ipHdr[2] = UInt8(ipTotalLen >> 8)
    ipHdr[3] = UInt8(ipTotalLen & 0xFF)
    ipHdr[6] = 0x40; ipHdr[7] = 0x00
    ipHdr[8] = 64
    ipHdr[9] = IPProtocol.tcp.rawValue
    srcIP.write(to: &ipHdr[12])
    dstIP.write(to: &ipHdr[16])
    let ipCksum = ipHdr.withUnsafeBytes { internetChecksum($0) }
    ipHdr[10] = UInt8(ipCksum >> 8)
    ipHdr[11] = UInt8(ipCksum & 0xFF)

    var tcpHdr = [UInt8](repeating: 0, count: 20)
    tcpHdr[0] = UInt8(srcPort >> 8)
    tcpHdr[1] = UInt8(srcPort & 0xFF)
    tcpHdr[2] = UInt8(dstPort >> 8)
    tcpHdr[3] = UInt8(dstPort & 0xFF)
    tcpHdr[12] = 0x50
    tcpHdr[13] = 0x02  // SYN

    return makeEthernetFrame(dst: dstMAC, src: clientMAC, type: .ipv4, payload: ipHdr + tcpHdr)
}

// MARK: - General TCP frame (any flags/seq/ack/payload)

/// Build a full Ethernet/IPv4/TCP frame with arbitrary sequence numbers,
/// flags, and payload. TCP checksum is computed via the pseudo-header.
func makeTCPFrame(dstMAC: MACAddress, srcMAC: MACAddress,
                   srcIP: IPv4Address, dstIP: IPv4Address,
                   srcPort: UInt16, dstPort: UInt16,
                   seq: UInt32, ack: UInt32,
                   flags: TCPFlags, window: UInt16 = 65535,
                   payload: [UInt8] = []) -> PacketBuffer {
    let tcpLen = 20 + payload.count
    let ipTotalLen = 20 + tcpLen

    var ipBytes = [UInt8](repeating: 0, count: 20)
    ipBytes[0] = 0x45
    ipBytes[2] = UInt8(ipTotalLen >> 8)
    ipBytes[3] = UInt8(ipTotalLen & 0xFF)
    ipBytes[6] = 0x40; ipBytes[7] = 0x00
    ipBytes[8] = 64
    ipBytes[9] = IPProtocol.tcp.rawValue
    srcIP.write(to: &ipBytes[12])
    dstIP.write(to: &ipBytes[16])
    let ipCksum = ipBytes.withUnsafeBytes { internetChecksum($0) }
    ipBytes[10] = UInt8(ipCksum >> 8)
    ipBytes[11] = UInt8(ipCksum & 0xFF)

    var tcpBytes = [UInt8](repeating: 0, count: tcpLen)
    tcpBytes[0] = UInt8(srcPort >> 8); tcpBytes[1] = UInt8(srcPort & 0xFF)
    tcpBytes[2] = UInt8(dstPort >> 8); tcpBytes[3] = UInt8(dstPort & 0xFF)
    tcpBytes[4] = UInt8((seq >> 24) & 0xFF)
    tcpBytes[5] = UInt8((seq >> 16) & 0xFF)
    tcpBytes[6] = UInt8((seq >> 8) & 0xFF)
    tcpBytes[7] = UInt8(seq & 0xFF)
    tcpBytes[8] = UInt8((ack >> 24) & 0xFF)
    tcpBytes[9] = UInt8((ack >> 16) & 0xFF)
    tcpBytes[10] = UInt8((ack >> 8) & 0xFF)
    tcpBytes[11] = UInt8(ack & 0xFF)
    tcpBytes[12] = 0x50  // data offset = 5 (20 bytes)
    tcpBytes[13] = flags.rawValue
    tcpBytes[14] = UInt8(window >> 8); tcpBytes[15] = UInt8(window & 0xFF)
    for i in 0..<payload.count { tcpBytes[20 + i] = payload[i] }

    let ck = computeTCPChecksum(
        pseudoSrcAddr: srcIP, pseudoDstAddr: dstIP,
        tcpData: &tcpBytes, tcpLen: tcpLen
    )
    tcpBytes[16] = UInt8(ck >> 8)
    tcpBytes[17] = UInt8(ck & 0xFF)

    return makeEthernetFrame(dst: dstMAC, src: srcMAC, type: .ipv4,
                              payload: ipBytes + tcpBytes)
}

// MARK: - Parse helpers

func parseDHCPFromBytes(_ bytes: [UInt8]) -> DHCPPacket? {
    let pkt = packetFrom(bytes)
    guard let eth = EthernetFrame.parse(from: pkt),
          eth.etherType == .ipv4,
          let ip = IPv4Header.parse(from: eth.payload),
          ip.protocol == .udp else { return nil }
    let udpPayload = ip.payload
    guard udpPayload.totalLength >= 8 else { return nil }
    guard let dhcpPayload = udpPayload.slice(from: 8, length: udpPayload.totalLength - 8) else { return nil }
    return DHCPPacket.parse(from: dhcpPayload)
}

func extractDHCPFromReply(_ pkt: PacketBuffer) -> DHCPPacket? {
    guard let eth = EthernetFrame.parse(from: pkt),
          eth.etherType == .ipv4,
          let ip = IPv4Header.parse(from: eth.payload),
          ip.protocol == .udp else { return nil }
    let udpPayload = ip.payload
    guard udpPayload.totalLength >= 8 else { return nil }
    guard let dhcpPayload = udpPayload.slice(from: 8, length: udpPayload.totalLength - 8) else { return nil }
    return DHCPPacket.parse(from: dhcpPayload)
}

// MARK: - Chaos helpers

/// Return a copy of `bytes` with the byte at `offset` replaced by `value`.
func corruptByte(in bytes: [UInt8], at offset: Int, to value: UInt8) -> [UInt8] {
    var corrupted = bytes
    if offset < corrupted.count { corrupted[offset] = value }
    return corrupted
}

/// Return a copy of `bytes` with the checksum at byte offsets `lo` and `hi` flipped.
func corruptChecksum(in bytes: [UInt8], atLo lo: Int, hi: Int) -> [UInt8] {
    var corrupted = bytes
    if lo < corrupted.count { corrupted[lo] = corrupted[lo] &+ 1 }
    if hi < corrupted.count { corrupted[hi] = corrupted[hi] &+ 1 }
    return corrupted
}

/// Return a frame truncated to `newLength` bytes.
func truncatedFrame(_ bytes: [UInt8], to newLength: Int) -> [UInt8] {
    if newLength >= bytes.count { return bytes }
    return Array(bytes[0..<newLength])
}
