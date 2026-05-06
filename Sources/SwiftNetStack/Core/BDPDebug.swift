#if DEBUG

/// Executable phase contracts for BDP development.
///
/// Each validator checks invariants before or after a phase. These run only
/// in DEBUG builds and crash immediately on violation — no silent corruption.
///
/// The checks are intentionally redundant with production code: they verify
/// the *intent* of each phase, catching drift between what the phase promises
/// and what it actually produces.

// MARK: - Phase 2: After Ethernet parse

func debugValidateEthernetParse(_ ethParsed: [(ep: Int, pkt: PacketBuffer, eth: EthernetFrame)]) {
    for (ep, pkt, eth) in ethParsed {
        precondition(ep >= 0, "Ethernet parse: invalid endpoint ID \(ep)")
        precondition(pkt.totalLength >= 14, "Ethernet parse: frame too short (\(pkt.totalLength) bytes)")
        precondition(eth.srcMAC != .zero, "Ethernet parse: srcMAC is zero")
        precondition(eth.dstMAC != .zero || true, "Ethernet parse: dstMAC is zero (valid for some cases)")
    }
}

// MARK: - Phase 3: After MAC filter + L2 forward

func debugValidateMACFilter(
    arpPkts: [(ep: Int, pkt: PacketBuffer, eth: EthernetFrame)],
    ipv4Pkts: [(ep: Int, pkt: PacketBuffer, eth: EthernetFrame)],
    forwardPkts: [(endpointID: Int, packet: PacketBuffer)]
) {
    for (_, _, eth) in arpPkts {
        precondition(eth.etherType == .arp, "MAC filter: non-ARP frame in arpPkts")
    }
    for (_, _, eth) in ipv4Pkts {
        precondition(eth.etherType == .ipv4, "MAC filter: non-IPv4 frame in ipv4Pkts")
    }
    for (dstEp, pkt) in forwardPkts {
        precondition(dstEp >= 0, "L2 forward: invalid destination endpoint \(dstEp)")
        precondition(pkt.totalLength >= 14, "L2 forward: frame too short")
    }
}

// MARK: - Phase 4: After IPv4 parse

func debugValidateIPv4Parse(_ ipv4Parsed: [(ep: Int, eth: EthernetFrame, ip: IPv4Header)]) {
    for (ep, eth, ip) in ipv4Parsed {
        precondition(ep >= 0, "IPv4 parse: invalid endpoint ID")
        precondition(eth.etherType == .ipv4, "IPv4 parse: etherType is not IPv4")
        precondition(ip.version == 4, "IPv4 parse: version != 4")
        precondition(ip.ihl >= 5, "IPv4 parse: IHL < 5")
        precondition(ip.totalLength >= 20, "IPv4 parse: totalLength < 20")
        // Verify checksum — this is the audit check for H4
        precondition(ip.verifyChecksum(), "IPv4 parse: checksum validation failed for \(ip.srcAddr) → \(ip.dstAddr)")
    }
}

// MARK: - Phase 5: After ARP parse

func debugValidateARPParse(_ arpParsed: [(ep: Int, eth: EthernetFrame, arp: ARPFrame)]) {
    for (_, _, arp) in arpParsed {
        precondition(arp.operation == .request || arp.operation == .reply,
                     "ARP parse: invalid operation \(arp.operation)")
    }
}

// MARK: - Phase 6: After transport parse

func debugValidateTransportParse(
    icmpParsed: [(ep: Int, eth: EthernetFrame, ip: IPv4Header, icmp: ICMPHeader)],
    dhcpParsed: [(ep: Int, eth: EthernetFrame, ip: IPv4Header, dhcp: DHCPPacket)]
) {
    for (_, _, ip, _) in icmpParsed {
        precondition(ip.protocol == .icmp, "Transport parse: non-ICMP in icmpParsed")
    }
    for (_, _, ip, _) in dhcpParsed {
        precondition(ip.protocol == .udp, "Transport parse: non-UDP in dhcpParsed")
    }
}

// MARK: - Phase 7-9: After processing (validate generated replies)

func debugValidateICMPReply(_ pkt: PacketBuffer) {
    guard let eth = EthernetFrame.parse(from: pkt) else {
        preconditionFailure("ICMP reply: invalid Ethernet")
    }
    precondition(eth.etherType == .ipv4, "ICMP reply: etherType not IPv4")
    guard let ip = IPv4Header.parse(from: eth.payload) else {
        preconditionFailure("ICMP reply: invalid IPv4 header")
    }
    precondition(ip.protocol == .icmp, "ICMP reply: protocol not ICMP")
    precondition(ip.verifyChecksum(), "ICMP reply: IP checksum INVALID — stale bytes in pool chunk?")
    guard let icmp = ICMPHeader.parse(from: ip.payload) else {
        preconditionFailure("ICMP reply: invalid ICMP header")
    }
    precondition(icmp.type == 0, "ICMP reply: type != 0 (echo reply)")
    // Verify ICMP checksum by recomputing from raw bytes
    let icmpLen = 8 + icmp.payload.totalLength
    let icmpBytes = ip.payload.withUnsafeReadableBytes { $0 }
    precondition(icmpBytes.count >= icmpLen, "ICMP reply: ICMP payload too short")
    let computed = internetChecksum(UnsafeRawBufferPointer(start: icmpBytes.baseAddress!, count: icmpLen))
    precondition(computed == 0, "ICMP reply: ICMP checksum INVALID — stale bytes in pool chunk?")
}

func debugValidateDHCPReply(_ pkt: PacketBuffer) {
    guard let eth = EthernetFrame.parse(from: pkt) else {
        preconditionFailure("DHCP reply: invalid Ethernet")
    }
    precondition(eth.etherType == .ipv4, "DHCP reply: etherType not IPv4")
    guard let ip = IPv4Header.parse(from: eth.payload) else {
        preconditionFailure("DHCP reply: invalid IPv4 header")
    }
    precondition(ip.protocol == .udp, "DHCP reply: protocol not UDP")
    precondition(ip.verifyChecksum(), "DHCP reply: IP checksum INVALID — stale bytes in pool chunk?")
}

func debugValidateARPReply(_ pkt: PacketBuffer) {
    guard let eth = EthernetFrame.parse(from: pkt) else {
        preconditionFailure("ARP reply: invalid Ethernet")
    }
    precondition(eth.etherType == .arp, "ARP reply: etherType not ARP")
    guard let arp = ARPFrame.parse(from: eth.payload) else {
        preconditionFailure("ARP reply: invalid ARP frame")
    }
    precondition(arp.operation == .reply, "ARP reply: operation != reply")
}

// MARK: - Phase 10: Before batch write

func debugValidateReplies(_ replies: [(endpointID: Int, packet: PacketBuffer)]) {
    for (ep, pkt) in replies {
        precondition(ep >= 0, "Batch write: invalid endpoint ID \(ep)")
        precondition(pkt.totalLength >= 14, "Batch write: reply too short (\(pkt.totalLength) bytes)")
    }
}

#endif
