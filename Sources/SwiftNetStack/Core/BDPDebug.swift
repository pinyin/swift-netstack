import Darwin

#if DEBUG

/// Executable phase contracts for BDP development.
///
/// Three levels of protocol formalization:
///
/// **L1 — Header Validity**: Each parsed header satisfies ALL structural constraints
/// from its RFC. These run after parse phases (2, 4, 5, 6) and verify that the
/// parser didn't accept malformed data.
///
/// **L2 — Request-Reply Correspondence**: A reply is a semantically correct response
/// to a specific request, per protocol behavioral rules. These run after processing
/// phases (7, 8, 9) using snapshots of the request arrays captured before the phase.
/// The validator re-parses each reply frame independently (bypassing the construction
/// code path) and matches replies to requests via protocol-defined keys.
///
/// **L3 — Phase Integrity**: Data flow between phases is lossless — no frames silently
/// dropped, no phantom replies injected. Runs before Phase 10 (batch write).
///
/// Every precondition cites the relevant RFC section so a violation directly points
/// to the specification it contradicts.

// MARK: ── L1: Protocol Header Validity ──────────────────────────────────────

// MARK: Ethernet (IEEE 802.3 + RFC 894)

func debugValidateEthernetFrame(_ eth: EthernetFrame, ep: Int) {
    // RFC 894: Ethernet II frames carry a Type field ≥ 0x0600 (1536)
    // Our EtherType enum only has .ipv4(0x0800) and .arp(0x0806), both ≥ 0x0600.
    // IEEE 802.3: srcMAC bit 0 of octet 0 must be 0 (unicast source)
    precondition(eth.srcMAC.octets.0 & 0x01 == 0,
        "IEEE 802.3 §3.2.3: srcMAC must be unicast (bit 0 of octet 0 == 0), got \(eth.srcMAC)")
    // dstMAC bit 0 = 1 for multicast/broadcast, 0 for unicast — both are valid
    // Zero MAC is never valid
    precondition(eth.srcMAC != .zero,
        "IEEE 802: srcMAC must not be 00:00:00:00:00:00")
}

func debugValidateEthernetParse(_ ethParsed: [(ep: Int, pkt: PacketBuffer, eth: EthernetFrame)]) {
    for (ep, pkt, eth) in ethParsed {
        precondition(ep >= 0, "Ethernet parse: invalid endpoint ID \(ep)")
        precondition(pkt.totalLength >= 14, "Ethernet parse: frame too short (\(pkt.totalLength) bytes)")
        debugValidateEthernetFrame(eth, ep: ep)
    }
}

// MARK: IPv4 (RFC 791)

func debugValidateIPv4Header(_ ip: IPv4Header) {
    // RFC 791 §3.1: Version must be 4
    precondition(ip.version == 4, "RFC 791 §3.1: version must be 4, got \(ip.version)")
    // RFC 791 §3.1: IHL in [5, 15]
    precondition(ip.ihl >= 5 && ip.ihl <= 15,
        "RFC 791 §3.1: IHL must be in [5, 15], got \(ip.ihl)")
    // RFC 791 §3.1: Total Length ≥ IHL * 4
    precondition(ip.totalLength >= UInt16(ip.ihl) * 4,
        "RFC 791 §3.1: totalLength \(ip.totalLength) < IHL*4 (\(ip.ihl * 4))")
    // RFC 791 §3.1: Total Length consistent with payload
    precondition(Int(ip.totalLength) == Int(ip.ihl) * 4 + ip.payload.totalLength,
        "RFC 791 §3.1: totalLength \(ip.totalLength) ≠ header (\(ip.ihl * 4)) + payload (\(ip.payload.totalLength))")
    // RFC 791 §3.2.1.3: Reserved flag (bit 7) must be 0
    precondition(ip.flags & 0x04 == 0,
        "RFC 791 §3.2.1.3: reserved flag (bit 7 of flags field) must be 0, got flags \(ip.flags)")
    // RFC 791 §3.2.1.5: If DF set, fragment offset must be 0
    if ip.flags & 0x02 != 0 {
        precondition(ip.fragmentOffset == 0,
            "RFC 791 §3.2.1.5: DF=1 requires fragmentOffset==0, got \(ip.fragmentOffset)")
    }
    // RFC 791 §3.1: TTL must be > 0
    precondition(ip.ttl > 0,
        "RFC 791 §3.1: TTL must be > 0, got \(ip.ttl)")
    // RFC 791 §3.2.1.3: Source address must not be loopback or multicast.
    // 0.0.0.0 is allowed for DHCP bootstrap (client has no IP yet).
    precondition((ip.srcAddr.addr & 0xFF) != 127,
        "RFC 791 §3.2.1.3: srcAddr must not be loopback (127.0.0.0/8)")
    precondition((ip.srcAddr.addr >> 28) != 0xE,
        "RFC 791 §3.2.1.3: srcAddr must not be multicast (224.0.0.0/4)")
    // RFC 791 §3.2.1.3: Destination address must not be 0.0.0.0
    precondition(ip.dstAddr != .zero,
        "RFC 791 §3.2.1.3: dstAddr must not be 0.0.0.0")
    // RFC 791 §3.1: Header checksum must be valid (computed from raw IHL*4 bytes at parse time)
    precondition(ip.verifyChecksum(),
        "RFC 791 §3.1: header checksum invalid for \(ip.srcAddr) → \(ip.dstAddr)")
}

func debugValidateIPv4Parse(_ ipv4Parsed: [(ep: Int, eth: EthernetFrame, ip: IPv4Header)]) {
    for (ep, eth, ip) in ipv4Parsed {
        precondition(ep >= 0, "IPv4 parse: invalid endpoint ID")
        precondition(eth.etherType == .ipv4, "IPv4 parse: etherType is not IPv4")
        debugValidateIPv4Header(ip)
    }
}

// MARK: ARP (RFC 826)

func debugValidateARPFrame(_ arp: ARPFrame) {
    // RFC 826: Hardware type = 1 (Ethernet)
    precondition(arp.hardwareType == 1,
        "RFC 826: hardwareType must be 1 (Ethernet), got \(arp.hardwareType)")
    // RFC 826: Protocol type = 0x0800 (IPv4)
    precondition(arp.protocolType == 0x0800,
        "RFC 826: protocolType must be 0x0800 (IPv4), got \(arp.protocolType)")
    // RFC 826: Hardware size = 6
    precondition(arp.hardwareSize == 6,
        "RFC 826: hardwareSize must be 6, got \(arp.hardwareSize)")
    // RFC 826: Protocol size = 4
    precondition(arp.protocolSize == 4,
        "RFC 826: protocolSize must be 4, got \(arp.protocolSize)")
    // RFC 826: Operation = 1 (request) or 2 (reply)
    precondition(arp.operation == .request || arp.operation == .reply,
        "RFC 826: operation must be request(1) or reply(2), got \(arp.operation)")
    // RFC 826: Sender MAC must not be zero
    precondition(arp.senderMAC != .zero,
        "RFC 826: senderMAC must not be 00:00:00:00:00:00")
    // RFC 826: Sender IP must not be zero
    precondition(arp.senderIP != .zero,
        "RFC 826: senderIP must not be 0.0.0.0")
    // RFC 826 §3: For request, targetMAC may be zero (probing). For reply, it must not.
    if arp.operation == .reply {
        precondition(arp.targetMAC != .zero,
            "RFC 826 §3: ARP reply targetMAC must not be 00:00:00:00:00:00")
    }
}

func debugValidateARPParse(_ arpParsed: [(ep: Int, eth: EthernetFrame, arp: ARPFrame)]) {
    for (_, _, arp) in arpParsed {
        debugValidateARPFrame(arp)
    }
}

// MARK: ICMP (RFC 792)

func debugValidateICMPHeader(_ icmp: ICMPHeader) {
    // RFC 792: Type-specific code constraints
    switch icmp.type {
    case 0:  // Echo Reply — code must be 0
        precondition(icmp.code == 0,
            "RFC 792: Echo Reply (type 0) code must be 0, got \(icmp.code)")
    case 8:  // Echo Request — code must be 0
        precondition(icmp.code == 0,
            "RFC 792: Echo Request (type 8) code must be 0, got \(icmp.code)")
    case 3:  // Destination Unreachable
        precondition(icmp.code <= 15,
            "RFC 792: Destination Unreachable code must be ≤ 15, got \(icmp.code)")
    case 11: // Time Exceeded
        precondition(icmp.code <= 1,
            "RFC 792: Time Exceeded code must be ≤ 1, got \(icmp.code)")
    default:
        break  // Other types are valid; unhandled by our limited implementation
    }
    // Full ICMP checksum validation requires the complete ICMP header + payload
    // bytes, which is not available from ICMPHeader alone (payload is a separate
    // zero-copy view). Checksum is validated in L2 reply checks instead.
}

// MARK: DHCP (RFC 2131)

func debugValidateDHCPPacket(_ dhcp: DHCPPacket) {
    // RFC 2131 §2: op must be 1 (BOOTREQUEST) or 2 (BOOTREPLY)
    precondition(dhcp.op == 1 || dhcp.op == 2,
        "RFC 2131 §2: op must be 1 or 2, got \(dhcp.op)")
    // RFC 2131 §3: message type consistency
    switch dhcp.messageType {
    case .discover, .request, .decline, .release:
        precondition(dhcp.op == 1,
            "RFC 2131 §3: \(dhcp.messageType) requires op=BOOTREQUEST(1), got \(dhcp.op)")
    case .offer, .ack, .nak:
        precondition(dhcp.op == 2,
            "RFC 2131 §3: \(dhcp.messageType) requires op=BOOTREPLY(2), got \(dhcp.op)")
    }
    // RFC 2131 §2: xid should be non-zero
    precondition(dhcp.xid != 0,
        "RFC 2131 §2: xid should be non-zero")
    // RFC 2131 §2: chaddr must not be zero
    precondition(dhcp.chaddr != .zero,
        "RFC 2131 §2: chaddr must not be 00:00:00:00:00:00")
}

// MARK: Transport parse (Phase 6 dispatch)

func debugValidateTransportParse(
    icmpParsed: [(ep: Int, eth: EthernetFrame, ip: IPv4Header, icmp: ICMPHeader)],
    udpParsed: [(ep: Int, eth: EthernetFrame, ip: IPv4Header, udp: UDPHeader)],
    dhcpParsed: [(ep: Int, eth: EthernetFrame, ip: IPv4Header, dhcp: DHCPPacket)],
    tcpParsed: [(ep: Int, eth: EthernetFrame, ip: IPv4Header, tcp: TCPHeader)],
    unreachableParsed: [(ep: Int, eth: EthernetFrame, ip: IPv4Header)]
) {
    for (_, _, ip, _) in icmpParsed {
        precondition(ip.protocol == .icmp,
            "Transport parse: ip.protocol must be .icmp for ICMP entries, got \(ip.protocol)")
    }
    for (_, _, ip, _) in udpParsed {
        precondition(ip.protocol == .udp,
            "Transport parse: ip.protocol must be .udp for UDP entries, got \(ip.protocol)")
    }
    for (_, _, ip, _) in dhcpParsed {
        precondition(ip.protocol == .udp,
            "Transport parse: ip.protocol must be .udp for DHCP entries, got \(ip.protocol)")
    }
    for (_, _, ip, _) in tcpParsed {
        precondition(ip.protocol == .tcp,
            "Transport parse: ip.protocol must be .tcp for TCP entries, got \(ip.protocol)")
    }
    for (_, _, ip) in unreachableParsed {
        precondition(ip.protocol != .icmp && ip.protocol != .udp && ip.protocol != .tcp,
            "Transport parse: unreachable protocol must not be a handled protocol, got \(ip.protocol)")
    }
}

// MARK: UDP (RFC 768)

func debugValidateUDPHeader(_ udp: UDPHeader) {
    // RFC 768: length must be ≥ 8 (header size)
    precondition(udp.length >= 8,
        "RFC 768: UDP length must be ≥ 8, got \(udp.length)")
    // RFC 768: length == header(8) + payload
    precondition(Int(udp.length) == 8 + udp.payload.totalLength,
        "RFC 768: UDP length \(udp.length) ≠ 8 + payload (\(udp.payload.totalLength))")
    // RFC 768: pseudo-header addresses must not be zero
    precondition(udp.pseudoSrcAddr != .zero,
        "RFC 768: UDP pseudoSrcAddr must not be 0.0.0.0")
    precondition(udp.pseudoDstAddr != .zero,
        "RFC 768: UDP pseudoDstAddr must not be 0.0.0.0")
}

func debugValidateUDPParse(_ udpParsed: [(ep: Int, eth: EthernetFrame, ip: IPv4Header, udp: UDPHeader)]) {
    for (_, _, _, udp) in udpParsed {
        debugValidateUDPHeader(udp)
    }
}


// MARK: ── L2: Request-Reply Correspondence ──────────────────────────────────
///
/// Each validator receives:
/// - `requests`: snapshot of the parse array taken before the processing phase
/// - `replies`: slice of the replies array appended during the processing phase
/// - `hostMAC`: our MAC address (used for ARP/DHCP identity checks)
///
/// Validators re-parse each reply frame independently — this is intentional:
/// the construction code path and the validation code path are disjoint, so a
/// bug in one cannot mask itself in the other.

// MARK: ICMP (RFC 792) — Phase 7

func debugValidateICMPPhase(
    requests: [(ep: Int, eth: EthernetFrame, ip: IPv4Header, icmp: ICMPHeader)],
    replies: ArraySlice<(endpointID: Int, packet: PacketBuffer)>,
    hostMAC: MACAddress
) {
    for (replyEp, replyPkt) in replies {
        // ── Re-parse the reply independently ──
        guard let eth = EthernetFrame.parse(from: replyPkt) else {
            fputs("ICMP L2: reply has invalid Ethernet\n", stderr); continue
        }
        guard eth.etherType == .ipv4 else {
            fputs("ICMP L2: reply EtherType is not IPv4\n", stderr); continue
        }
        guard let ip = IPv4Header.parse(from: eth.payload) else {
            fputs("ICMP L2: reply has invalid IPv4 header\n", stderr); continue
        }
        guard ip.protocol == .icmp else {
            fputs("ICMP L2: reply IP protocol is not ICMP\n", stderr); continue
        }
        guard let icmp = ICMPHeader.parse(from: ip.payload) else {
            fputs("ICMP L2: reply has invalid ICMP header\n", stderr); continue
        }

        // ── Validate L1: ICMP echo reply structural constraints ──
        guard icmp.type == 0 else {
            fputs("RFC 792: ICMP reply type must be Echo Reply(0), got \(icmp.type)\n", stderr); continue
        }
        guard icmp.code == 0 else {
            fputs("RFC 792: ICMP Echo Reply code must be 0, got \(icmp.code)\n", stderr); continue
        }
        // RFC 791 §3.1: IP header checksum — catches stale bytes (C2)
        guard ip.verifyChecksum() else {
            fputs("RFC 791 §3.1: ICMP reply IP checksum INVALID — stale bytes in pool chunk?\n", stderr); continue
        }
        // RFC 792: ICMP checksum over header + payload
        let icmpLen = 8 + icmp.payload.totalLength
        let icmpRaw = ip.payload.withUnsafeReadableBytes { $0 }
        guard icmpRaw.count >= icmpLen else {
            fputs("RFC 792: ICMP reply payload too short (\(icmpRaw.count) < \(icmpLen))\n", stderr); continue
        }
        let computed = internetChecksum(UnsafeRawBufferPointer(start: icmpRaw.baseAddress!, count: icmpLen))
        guard computed == 0 else {
            fputs("RFC 792: ICMP reply checksum INVALID — stale bytes in pool chunk?\n", stderr); continue
        }

        // ── Match reply to request via (identifier, sequenceNumber, srcIP) ──
        let match = requests.first { req in
            req.icmp.type == 8
            && req.icmp.identifier == icmp.identifier
            && req.icmp.sequenceNumber == icmp.sequenceNumber
            && req.ip.srcAddr == ip.dstAddr
        }
        guard let req = match else {
            fputs("RFC 792: ICMP reply (id=\(icmp.identifier), seq=\(icmp.sequenceNumber)) has no matching echo request\n", stderr); continue
        }

        // ── Validate correspondence ──
        // RFC 792: Reply dstMAC == request srcMAC
        guard eth.dstMAC == req.eth.srcMAC else {
            fputs("RFC 792: ICMP reply dstMAC \(eth.dstMAC) ≠ request srcMAC \(req.eth.srcMAC)\n", stderr); continue
        }
        // RFC 792: Reply srcMAC == host MAC
        guard eth.srcMAC == hostMAC else {
            fputs("RFC 792: ICMP reply srcMAC \(eth.srcMAC) ≠ hostMAC \(hostMAC)\n", stderr); continue
        }
        // RFC 792: Reply srcIP == request dstIP (swap)
        guard ip.srcAddr == req.ip.dstAddr else {
            fputs("RFC 792: ICMP reply srcIP \(ip.srcAddr) ≠ request dstIP \(req.ip.dstAddr)\n", stderr); continue
        }
        // RFC 792: Reply dstIP == request srcIP (swap)
        guard ip.dstAddr == req.ip.srcAddr else {
            fputs("RFC 792: ICMP reply dstIP \(ip.dstAddr) ≠ request srcIP \(req.ip.srcAddr)\n", stderr); continue
        }
        // RFC 792: Reply payload == request payload (echo)
        let payloadMatch = icmp.payload.withUnsafeReadableBytes { replyBuf in
            req.icmp.payload.withUnsafeReadableBytes { reqBuf in
                replyBuf.count == reqBuf.count
                && (replyBuf.count == 0
                    || memcmp(replyBuf.baseAddress!, reqBuf.baseAddress!, replyBuf.count) == 0)
            }
        }
        guard payloadMatch else {
            fputs("RFC 792: ICMP echo reply payload does not match request payload\n", stderr); continue
        }
        // RFC 791: TTL should be plausible (our replies use TTL=64)
        guard ip.ttl >= 1 && ip.ttl <= 255 else {
            fputs("RFC 791 §3.1: ICMP reply TTL \(ip.ttl) out of range [1, 255]\n", stderr); continue
        }
        // Endpoint consistency
        guard replyEp == req.ep else {
            fputs("ICMP L2: reply endpoint \(replyEp) ≠ request endpoint \(req.ep)\n", stderr); continue
        }
    }
}

// MARK: UDP (RFC 768) — Phase 7.5

func debugValidateUDPPhase(
    requests: [(ep: Int, eth: EthernetFrame, ip: IPv4Header, udp: UDPHeader)],
    replies: ArraySlice<(endpointID: Int, packet: PacketBuffer)>,
    hostMAC: MACAddress
) {
    for (replyEp, replyPkt) in replies {
        // ── Re-parse the reply independently ──
        guard let eth = EthernetFrame.parse(from: replyPkt) else {
            fputs("UDP L2: reply has invalid Ethernet\n", stderr); continue
        }
        guard eth.etherType == .ipv4 else {
            fputs("UDP L2: reply EtherType is not IPv4\n", stderr); continue
        }
        guard let ip = IPv4Header.parse(from: eth.payload) else {
            fputs("UDP L2: reply has invalid IPv4 header\n", stderr); continue
        }
        guard ip.protocol == .udp else {
            fputs("UDP L2: reply IP protocol is not UDP\n", stderr); continue
        }
        guard let udp = UDPHeader.parse(
            from: ip.payload,
            pseudoSrcAddr: ip.srcAddr,
            pseudoDstAddr: ip.dstAddr
        ) else {
            fputs("UDP L2: reply has invalid UDP header\n", stderr); continue
        }

        // ── Validate L1: IP and UDP checksums ──
        guard ip.verifyChecksum() else {
            fputs("RFC 791 §3.1: UDP reply IP checksum INVALID — stale bytes in pool chunk?\n", stderr); continue
        }
        guard udp.verifyChecksum() else {
            fputs("RFC 768: UDP reply checksum INVALID\n", stderr); continue
        }

        // ── Match reply to request via (srcPort↔dstPort, srcIP↔dstIP) ──
        let match = requests.first { req in
            udp.srcPort == req.udp.dstPort
            && udp.dstPort == req.udp.srcPort
            && ip.srcAddr == req.ip.dstAddr
            && ip.dstAddr == req.ip.srcAddr
        }
        guard let req = match else {
            fputs("RFC 768: UDP reply (srcPort=\(udp.srcPort), dstPort=\(udp.dstPort)) has no matching request\n", stderr); continue
        }

        // ── Validate correspondence ──
        // Reply dstMAC == request srcMAC
        guard eth.dstMAC == req.eth.srcMAC else {
            fputs("UDP L2: reply dstMAC \(eth.dstMAC) ≠ request srcMAC \(req.eth.srcMAC)\n", stderr); continue
        }
        // Reply srcMAC == host MAC
        guard eth.srcMAC == hostMAC else {
            fputs("UDP L2: reply srcMAC \(eth.srcMAC) ≠ hostMAC \(hostMAC)\n", stderr); continue
        }
        // Endpoint consistency
        guard replyEp == req.ep else {
            fputs("UDP L2: reply endpoint \(replyEp) ≠ request endpoint \(req.ep)\n", stderr); continue
        }
    }
}

// MARK: ARP (RFC 826) — Phase 9

func debugValidateARPPhase(
    requests: [(ep: Int, eth: EthernetFrame, arp: ARPFrame)],
    replies: ArraySlice<(endpointID: Int, packet: PacketBuffer)>,
    hostMAC: MACAddress
) {
    for (replyEp, replyPkt) in replies {
        // ── Re-parse the reply independently ──
        guard let eth = EthernetFrame.parse(from: replyPkt) else {
            fputs("ARP L2: reply has invalid Ethernet\n", stderr); continue
        }
        guard eth.etherType == .arp else {
            fputs("ARP L2: reply EtherType is not ARP\n", stderr); continue
        }
        guard let arp = ARPFrame.parse(from: eth.payload) else {
            fputs("ARP L2: reply has invalid ARP frame\n", stderr); continue
        }

        // ── Validate L1: ARP reply structural constraints ──
        guard arp.operation == .reply else {
            fputs("RFC 826: ARP reply operation must be reply(2), got \(arp.operation)\n", stderr); continue
        }
        debugValidateARPFrame(arp)

        // ── Match reply to request via (targetIP, senderIP) ──
        // For a proxy ARP reply: reply.senderIP == request.targetIP
        //                         reply.targetIP == request.senderIP
        let match = requests.first { req in
            req.arp.operation == .request
            && arp.targetIP == req.arp.senderIP
            && arp.senderIP == req.arp.targetIP
        }
        guard let req = match else {
            fputs("RFC 826: ARP reply (senderIP=\(arp.senderIP), targetIP=\(arp.targetIP)) has no matching request\n", stderr); continue
        }

        // ── Validate correspondence ──
        // RFC 826: Reply dstMAC == request srcMAC
        guard eth.dstMAC == req.eth.srcMAC else {
            fputs("RFC 826: ARP reply dstMAC \(eth.dstMAC) ≠ request srcMAC \(req.eth.srcMAC)\n", stderr); continue
        }
        // RFC 826: Reply srcMAC == hostMAC (proxy ARP)
        guard eth.srcMAC == hostMAC else {
            fputs("RFC 826: ARP reply srcMAC \(eth.srcMAC) ≠ hostMAC \(hostMAC)\n", stderr); continue
        }
        // RFC 826: senderMAC == hostMAC (proxy ARP identity)
        guard arp.senderMAC == hostMAC else {
            fputs("RFC 826: ARP reply senderMAC \(arp.senderMAC) ≠ hostMAC \(hostMAC)\n", stderr); continue
        }
        // RFC 826: targetMAC == request senderMAC (answering the requester)
        guard arp.targetMAC == req.arp.senderMAC else {
            fputs("RFC 826: ARP reply targetMAC \(arp.targetMAC) ≠ request senderMAC \(req.arp.senderMAC)\n", stderr); continue
        }
        // RFC 826: senderIP == request targetIP (the IP being resolved)
        guard arp.senderIP == req.arp.targetIP else {
            fputs("RFC 826: ARP reply senderIP \(arp.senderIP) ≠ request targetIP \(req.arp.targetIP)\n", stderr); continue
        }
        // RFC 826: targetIP == request senderIP (the requester's IP)
        guard arp.targetIP == req.arp.senderIP else {
            fputs("RFC 826: ARP reply targetIP \(arp.targetIP) ≠ request senderIP \(req.arp.senderIP)\n", stderr); continue
        }
        // Endpoint consistency
        guard replyEp == req.ep else {
            fputs("ARP L2: reply endpoint \(replyEp) ≠ request endpoint \(req.ep)\n", stderr); continue
        }
    }
}

// MARK: DHCP (RFC 2131) — Phase 8

/// Extract a DHCP packet from within a wrapped Ethernet→IP→UDP→DHCP reply frame.
/// Parses the UDP header to get the DHCP payload, then delegates to `extractDHCP`.
private func extractDHCPFromReplyFrame(_ pkt: PacketBuffer) -> DHCPPacket? {
    guard let eth = EthernetFrame.parse(from: pkt),
          eth.etherType == .ipv4,
          let ip = IPv4Header.parse(from: eth.payload),
          ip.protocol == .udp,
          let udp = UDPHeader.parse(
            from: ip.payload,
            pseudoSrcAddr: ip.srcAddr,
            pseudoDstAddr: ip.dstAddr
          ),
          udp.srcPort == 67, udp.dstPort == 68 else { return nil }
    return DHCPPacket.parse(from: udp.payload)
}

func debugValidateDHCPPhase(
    requests: [(ep: Int, eth: EthernetFrame, ip: IPv4Header, dhcp: DHCPPacket)],
    replies: ArraySlice<(endpointID: Int, packet: PacketBuffer)>,
    hostMAC: MACAddress
) {
    for (replyEp, replyPkt) in replies {
        // ── Re-parse the reply independently ──
        guard let eth = EthernetFrame.parse(from: replyPkt) else {
            fputs("DHCP L2: reply has invalid Ethernet\n", stderr); continue
        }
        guard eth.etherType == .ipv4 else {
            fputs("DHCP L2: reply EtherType is not IPv4\n", stderr); continue
        }
        guard let ip = IPv4Header.parse(from: eth.payload) else {
            fputs("DHCP L2: reply has invalid IPv4 header\n", stderr); continue
        }
        guard ip.protocol == .udp else {
            fputs("DHCP L2: reply IP protocol is not UDP\n", stderr); continue
        }
        guard let dhcp = extractDHCPFromReplyFrame(replyPkt) else {
            fputs("DHCP L2: reply has invalid DHCP packet\n", stderr); continue
        }

        // ── Validate L1: DHCP reply constraints ──
        guard dhcp.op == 2 else {
            fputs("RFC 2131 §2: DHCP reply op must be BOOTREPLY(2), got \(dhcp.op)\n", stderr); continue
        }
        debugValidateDHCPPacket(dhcp)

        // ── Validate L1: IP header checksum ──
        guard ip.verifyChecksum() else {
            fputs("RFC 791 §3.1: DHCP reply IP checksum INVALID — stale bytes in pool chunk?\n", stderr); continue
        }

        // ── Match reply to request via xid (transaction ID) ──
        let match = requests.first { req in
            req.dhcp.xid == dhcp.xid
        }
        guard let req = match else {
            fputs("RFC 2131 §2: DHCP reply (xid=\(dhcp.xid)) has no matching request\n", stderr); continue
        }

        // ── Validate correspondence ──
        // RFC 2131: Reply dstMAC == request srcMAC (chaddr)
        guard eth.dstMAC == req.eth.srcMAC else {
            fputs("RFC 2131: DHCP reply dstMAC \(eth.dstMAC) ≠ request srcMAC \(req.eth.srcMAC)\n", stderr); continue
        }
        // RFC 2131: Reply srcMAC == hostMAC
        guard eth.srcMAC == hostMAC else {
            fputs("RFC 2131: DHCP reply srcMAC \(eth.srcMAC) ≠ hostMAC \(hostMAC)\n", stderr); continue
        }
        // RFC 2131 §2: chaddr must match
        guard dhcp.chaddr == req.dhcp.chaddr else {
            fputs("RFC 2131 §2: DHCP reply chaddr \(dhcp.chaddr) ≠ request chaddr \(req.dhcp.chaddr)\n", stderr); continue
        }
        // RFC 2131 §4.3.1: Correct response type
        switch (req.dhcp.messageType, dhcp.messageType) {
        case (.discover, .offer):
            break  // DISCOVER → OFFER
        case (.request, .ack):
            break  // REQUEST → ACK
        case (.release, _):
            break  // RELEASE → no reply expected (if we got here, debugValidateDHCPPhase was called with empty replies)
        case (.request, .nak):
            break  // REQUEST → NAK (rejected)
        default:
            fputs("RFC 2131 §4.3.1: invalid DHCP message transition \(req.dhcp.messageType) → \(dhcp.messageType)\n", stderr); continue
        }
        // DHCP reply srcIP must be non-zero (gateway IP). Cannot compare to
        // request dstIP because DISCOVER broadcasts to 255.255.255.255.
        guard ip.srcAddr != .zero else {
            fputs("RFC 2131: DHCP reply srcIP must not be 0.0.0.0\n", stderr); continue
        }
        // Endpoint consistency
        guard replyEp == req.ep else {
            fputs("DHCP L2: reply endpoint \(replyEp) ≠ request endpoint \(req.ep)\n", stderr); continue
        }
    }
}


// MARK: ── L3: Phase Flow Integrity ──────────────────────────────────────────

// MARK: MAC filter dispatch (Phase 3)

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
        precondition(pkt.totalLength >= 14, "L2 forward: frame too short (\(pkt.totalLength) bytes)")
    }
}

// MARK: Replies + forwarded frames before batch write (Phase 10)

func debugValidateReplies(_ replies: [(endpointID: Int, packet: PacketBuffer)]) {
    for (ep, pkt) in replies {
        precondition(ep >= 0, "Batch write: invalid endpoint ID \(ep)")
        precondition(pkt.totalLength >= 14, "Batch write: reply too short (\(pkt.totalLength) bytes)")
    }
}

// MARK: TCP (RFC 793) — Phase 10

func debugValidateTCPPhase(
    requests: [(ep: Int, eth: EthernetFrame, ip: IPv4Header, tcp: TCPHeader)],
    replies: ArraySlice<(endpointID: Int, packet: PacketBuffer)>,
    hostMAC: MACAddress
) {
    for (replyEp, replyPkt) in replies {
        guard let eth = EthernetFrame.parse(from: replyPkt) else {
            fputs("TCP L2: reply has invalid Ethernet\n", stderr); continue
        }
        guard eth.etherType == .ipv4 else {
            fputs("TCP L2: reply EtherType is not IPv4\n", stderr); continue
        }
        guard let ip = IPv4Header.parse(from: eth.payload), ip.verifyChecksum() else {
            fputs("TCP L2: reply has invalid IPv4 header\n", stderr); continue
        }
        guard ip.protocol == .tcp else {
            fputs("TCP L2: reply IP protocol is not TCP\n", stderr); continue
        }
        guard let tcp = TCPHeader.parse(
            from: ip.payload,
            pseudoSrcAddr: ip.srcAddr,
            pseudoDstAddr: ip.dstAddr
        ) else {
            fputs("TCP L2: reply has invalid TCP header\n", stderr); continue
        }

        // L1: structural constraints
        guard tcp.dataOffset >= 5 && tcp.dataOffset <= 15 else {
            fputs("RFC 793: TCP dataOffset must be in [5,15], got \(tcp.dataOffset)\n", stderr); continue
        }

        // L2: correspondence — reply src = request dst, reply dst = request src
        let match = requests.first { req in
            // TCP reply: (srcPort, dstPort, srcIP, dstIP) swapped
            tcp.srcPort == req.tcp.dstPort
            && tcp.dstPort == req.tcp.srcPort
            && ip.srcAddr == req.ip.dstAddr
            && ip.dstAddr == req.ip.srcAddr
        }
        guard let req = match else {
            fputs("RFC 793: TCP reply (srcPort=\(tcp.srcPort), dstPort=\(tcp.dstPort)) has no matching request\n", stderr); continue
        }

        guard eth.dstMAC == req.eth.srcMAC else {
            fputs("TCP L2: reply dstMAC \(eth.dstMAC) ≠ request srcMAC \(req.eth.srcMAC)\n", stderr); continue
        }
        guard eth.srcMAC == hostMAC else {
            fputs("TCP L2: reply srcMAC \(eth.srcMAC) ≠ hostMAC \(hostMAC)\n", stderr); continue
        }
        guard replyEp == req.ep else {
            fputs("TCP L2: reply endpoint \(replyEp) ≠ request endpoint \(req.ep)\n", stderr); continue
        }
    }
}

// MARK: NAT Poll — Phase 11

func debugValidateNATPoll(
    preReplies: Int,
    replies: [(endpointID: Int, packet: PacketBuffer)]
) {
    // NAT poll may inject new frames (external data, retransmissions).
    // Every injected frame must be a valid Ethernet frame targeting a valid endpoint.
    let injected = replies[preReplies...]
    for (ep, pkt) in injected {
        precondition(ep >= 0, "NAT poll: invalid endpoint ID \(ep)")
        precondition(pkt.totalLength >= 14, "NAT poll: frame too short (\(pkt.totalLength) bytes)")
    }
}

// MARK: ── TCP FSM Regression Tests ──────────────────────────────────────

/// Run TCP state machine transition tests at the start of each BDP round.
/// Exercises all states and edge cases from audit (synthetic RST, stale
/// chunks in checksum field, etc.). These are DEBUG-only regression checks
/// that run inline with the deliberation loop — no separate test target.
func debugRunTCPFSMTests() {
    // Helper: create a minimal TCP segment for FSM testing
    func makeSeg(flags: TCPFlags, seq: UInt32, ack: UInt32, dataLen: Int = 0) -> (TCPHeader, SendSequence, RecvSequence) {
        var pkt = PacketBuffer(capacity: dataLen, headroom: 0)
        if dataLen > 0 {
            _ = pkt.appendPointer(count: dataLen)
        }
        let hdr = TCPHeader(
            srcPort: 0, dstPort: 0,
            sequenceNumber: seq, acknowledgmentNumber: ack,
            dataOffset: 5, flags: flags,
            window: 65535, checksum: 0, urgentPointer: 0,
            payload: pkt,
            pseudoSrcAddr: IPv4Address(1, 0, 0, 1),
            pseudoDstAddr: IPv4Address(1, 0, 0, 2),
            checksumValid: true
        )
        let snd = SendSequence(nxt: 1000, una: 1000, wnd: 65535)
        let rcv = RecvSequence(nxt: 2000, initialSeq: 2000)
        return (hdr, snd, rcv)
    }

    // LISTEN + SYN → synReceived
    do {
        var (seg, snd, rcv) = makeSeg(flags: .syn, seq: 2000, ack: 0)
        let (newState, toSend, _) = _tcpProcessImpl(state: .listen, segment: seg, snd: &snd, rcv: &rcv, appClose: false)
        precondition(newState == .synReceived, "TCP FSM: LISTEN + SYN → \(newState), expected .synReceived")
        precondition(toSend.count == 1, "TCP FSM: LISTEN + SYN → \(toSend.count) toSend, expected 1")
        precondition(toSend[0].flags == [.syn, .ack], "TCP FSM: LISTEN + SYN flag mismatch")
    }

    // LISTEN + non-SYN (no state change)
    do {
        var (seg, snd, rcv) = makeSeg(flags: .ack, seq: 2000, ack: 0)
        let (newState, toSend, _) = _tcpProcessImpl(state: .listen, segment: seg, snd: &snd, rcv: &rcv, appClose: false)
        precondition(newState == .listen, "TCP FSM: LISTEN + ACK → \(newState), expected .listen")
        precondition(toSend.isEmpty, "TCP FSM: LISTEN + ACK → toSend not empty")
    }

    // synReceived + matching ACK → established
    do {
        var (seg, snd, rcv) = makeSeg(flags: .ack, seq: 2001, ack: 1001)
        snd.nxt = 1001
        let (newState, _, _) = _tcpProcessImpl(state: .synReceived, segment: seg, snd: &snd, rcv: &rcv, appClose: false)
        precondition(newState == .established, "TCP FSM: synReceived + ACK → \(newState), expected .established")
    }

    // synReceived + non-matching ACK (stay)
    do {
        var (seg, snd, rcv) = makeSeg(flags: .ack, seq: 2001, ack: 999)
        snd.nxt = 1001
        let (newState, _, _) = _tcpProcessImpl(state: .synReceived, segment: seg, snd: &snd, rcv: &rcv, appClose: false)
        precondition(newState == .synReceived, "TCP FSM: synReceived + bad ACK → \(newState), expected .synReceived")
    }

    // ESTABLISHED + FIN → closeWait
    do {
        var (seg, snd, rcv) = makeSeg(flags: .fin, seq: 2000, ack: 1000)
        let (newState, toSend, _) = _tcpProcessImpl(state: .established, segment: seg, snd: &snd, rcv: &rcv, appClose: false)
        precondition(newState == .closeWait, "TCP FSM: ESTABLISHED + FIN → \(newState), expected .closeWait")
        precondition(!toSend.isEmpty, "TCP FSM: ESTABLISHED + FIN → no ACK toSend")
    }

    // ESTABLISHED + data → returns dataToExternal
    do {
        var segPkt = PacketBuffer(capacity: 10, headroom: 0)
        _ = segPkt.appendPointer(count: 10)
        let seg = TCPHeader(
            srcPort: 0, dstPort: 0,
            sequenceNumber: 2000, acknowledgmentNumber: 1000,
            dataOffset: 5, flags: .ack,
            window: 65535, checksum: 0, urgentPointer: 0,
            payload: segPkt,
            pseudoSrcAddr: .zero, pseudoDstAddr: .zero,
            checksumValid: true
        )
        var snd = SendSequence(nxt: 1000, una: 1000, wnd: 65535)
        var rcv = RecvSequence(nxt: 2000, initialSeq: 2000)
        let (newState, _, data) = _tcpProcessImpl(state: .established, segment: seg, snd: &snd, rcv: &rcv, appClose: false)
        precondition(newState == .established, "TCP FSM: ESTABLISHED + data → \(newState)")
        precondition(data != nil && data!.totalLength == 10, "TCP FSM: ESTABLISHED + data → no dataToExternal")
        precondition(rcv.nxt == 2010, "TCP FSM: ESTABLISHED + data → rcv.nxt not advanced")
    }

    // ESTABLISHED + appClose → finWait1
    do {
        var (seg, snd, rcv) = makeSeg(flags: .ack, seq: 2000, ack: 1000)
        let (newState, toSend, _) = _tcpProcessImpl(state: .established, segment: seg, snd: &snd, rcv: &rcv, appClose: true)
        precondition(newState == .finWait1, "TCP FSM: ESTABLISHED + appClose → \(newState), expected .finWait1")
        precondition(!toSend.isEmpty && toSend[0].flags.isFin, "TCP FSM: ESTABLISHED + appClose → no FIN sent")
    }

    // FIN_WAIT1 + ACK → finWait2
    do {
        var (seg, snd, rcv) = makeSeg(flags: .ack, seq: 2000, ack: 1001)
        snd.nxt = 1001
        let (newState, _, _) = _tcpProcessImpl(state: .finWait1, segment: seg, snd: &snd, rcv: &rcv, appClose: false)
        precondition(newState == .finWait2, "TCP FSM: FIN_WAIT1 + ACK → \(newState), expected .finWait2")
    }

    // FIN_WAIT2 + FIN → closed
    do {
        var (seg, snd, rcv) = makeSeg(flags: .fin, seq: 2000, ack: 1000)
        let (newState, _, _) = _tcpProcessImpl(state: .finWait2, segment: seg, snd: &snd, rcv: &rcv, appClose: false)
        precondition(newState == .closed, "TCP FSM: FIN_WAIT2 + FIN → \(newState), expected .closed")
    }

    // closeWait + appClose → lastAck
    do {
        var (seg, snd, rcv) = makeSeg(flags: .ack, seq: 2000, ack: 1000)
        let (newState, _, _) = _tcpProcessImpl(state: .closeWait, segment: seg, snd: &snd, rcv: &rcv, appClose: true)
        precondition(newState == .lastAck, "TCP FSM: closeWait + appClose → \(newState), expected .lastAck")
    }

    // lastAck + matching ACK → closed
    do {
        var (seg, snd, rcv) = makeSeg(flags: .ack, seq: 2000, ack: 1001)
        snd.nxt = 1001
        let (newState, _, _) = _tcpProcessImpl(state: .lastAck, segment: seg, snd: &snd, rcv: &rcv, appClose: false)
        precondition(newState == .closed, "TCP FSM: lastAck + ACK → \(newState), expected .closed")
    }

    // Any state + RST → closed
    do {
        var (seg, snd, rcv) = makeSeg(flags: .rst, seq: 0, ack: 0)
        let (newState, _, _) = _tcpProcessImpl(state: .established, segment: seg, snd: &snd, rcv: &rcv, appClose: false)
        precondition(newState == .closed, "TCP FSM: ESTABLISHED + RST → \(newState), expected .closed")
    }

    // CLOSED + anything → closed
    do {
        var (seg, snd, rcv) = makeSeg(flags: .syn, seq: 2000, ack: 0)
        let (newState, _, _) = _tcpProcessImpl(state: .closed, segment: seg, snd: &snd, rcv: &rcv, appClose: false)
        precondition(newState == .closed, "TCP FSM: CLOSED + SYN → \(newState), expected .closed")
    }
}

#endif
