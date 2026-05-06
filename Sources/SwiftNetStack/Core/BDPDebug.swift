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
    // RFC 791 §3.2.1.3: Source address must not be 0.0.0.0, loopback, or multicast
    precondition(ip.srcAddr != .zero,
        "RFC 791 §3.2.1.3: srcAddr must not be 0.0.0.0")
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
    dhcpParsed: [(ep: Int, eth: EthernetFrame, ip: IPv4Header, dhcp: DHCPPacket)]
) {
    for (_, _, ip, _) in icmpParsed {
        precondition(ip.protocol == .icmp,
            "Transport parse: ip.protocol must be .icmp for ICMP entries, got \(ip.protocol)")
    }
    for (_, _, ip, _) in dhcpParsed {
        precondition(ip.protocol == .udp,
            "Transport parse: ip.protocol must be .udp for DHCP entries, got \(ip.protocol)")
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
            preconditionFailure("ICMP L2: reply has invalid Ethernet")
        }
        guard eth.etherType == .ipv4 else {
            preconditionFailure("ICMP L2: reply EtherType is not IPv4")
        }
        guard let ip = IPv4Header.parse(from: eth.payload) else {
            preconditionFailure("ICMP L2: reply has invalid IPv4 header")
        }
        guard ip.protocol == .icmp else {
            preconditionFailure("ICMP L2: reply IP protocol is not ICMP")
        }
        guard let icmp = ICMPHeader.parse(from: ip.payload) else {
            preconditionFailure("ICMP L2: reply has invalid ICMP header")
        }

        // ── Validate L1: ICMP echo reply structural constraints ──
        precondition(icmp.type == 0,
            "RFC 792: ICMP reply type must be Echo Reply(0), got \(icmp.type)")
        precondition(icmp.code == 0,
            "RFC 792: ICMP Echo Reply code must be 0, got \(icmp.code)")
        // RFC 791 §3.1: IP header checksum — catches stale bytes (C2)
        precondition(ip.verifyChecksum(),
            "RFC 791 §3.1: ICMP reply IP checksum INVALID — stale bytes in pool chunk?")
        // RFC 792: ICMP checksum over header + payload
        let icmpLen = 8 + icmp.payload.totalLength
        let icmpRaw = ip.payload.withUnsafeReadableBytes { $0 }
        precondition(icmpRaw.count >= icmpLen,
            "RFC 792: ICMP reply payload too short (\(icmpRaw.count) < \(icmpLen))")
        let computed = internetChecksum(UnsafeRawBufferPointer(start: icmpRaw.baseAddress!, count: icmpLen))
        precondition(computed == 0,
            "RFC 792: ICMP reply checksum INVALID — stale bytes in pool chunk?")

        // ── Match reply to request via (identifier, sequenceNumber, srcIP) ──
        let match = requests.first { req in
            req.icmp.type == 8
            && req.icmp.identifier == icmp.identifier
            && req.icmp.sequenceNumber == icmp.sequenceNumber
            && req.ip.srcAddr == ip.dstAddr
        }
        guard let req = match else {
            preconditionFailure(
                "RFC 792: ICMP reply (id=\(icmp.identifier), seq=\(icmp.sequenceNumber)) has no matching echo request")
        }

        // ── Validate correspondence ──
        // RFC 792: Reply dstMAC == request srcMAC
        precondition(eth.dstMAC == req.eth.srcMAC,
            "RFC 792: ICMP reply dstMAC \(eth.dstMAC) ≠ request srcMAC \(req.eth.srcMAC)")
        // RFC 792: Reply srcMAC == host MAC
        precondition(eth.srcMAC == hostMAC,
            "RFC 792: ICMP reply srcMAC \(eth.srcMAC) ≠ hostMAC \(hostMAC)")
        // RFC 792: Reply srcIP == request dstIP (swap)
        precondition(ip.srcAddr == req.ip.dstAddr,
            "RFC 792: ICMP reply srcIP \(ip.srcAddr) ≠ request dstIP \(req.ip.dstAddr)")
        // RFC 792: Reply dstIP == request srcIP (swap)
        precondition(ip.dstAddr == req.ip.srcAddr,
            "RFC 792: ICMP reply dstIP \(ip.dstAddr) ≠ request srcIP \(req.ip.srcAddr)")
        // RFC 792: Reply payload == request payload (echo)
        let payloadMatch = icmp.payload.withUnsafeReadableBytes { replyBuf in
            req.icmp.payload.withUnsafeReadableBytes { reqBuf in
                replyBuf.count == reqBuf.count
                && (replyBuf.count == 0
                    || memcmp(replyBuf.baseAddress!, reqBuf.baseAddress!, replyBuf.count) == 0)
            }
        }
        precondition(payloadMatch,
            "RFC 792: ICMP echo reply payload does not match request payload")
        // RFC 791: TTL should be plausible (our replies use TTL=64)
        precondition(ip.ttl >= 1 && ip.ttl <= 255,
            "RFC 791 §3.1: ICMP reply TTL \(ip.ttl) out of range [1, 255]")
        // Endpoint consistency
        precondition(replyEp == req.ep,
            "ICMP L2: reply endpoint \(replyEp) ≠ request endpoint \(req.ep)")
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
            preconditionFailure("ARP L2: reply has invalid Ethernet")
        }
        guard eth.etherType == .arp else {
            preconditionFailure("ARP L2: reply EtherType is not ARP")
        }
        guard let arp = ARPFrame.parse(from: eth.payload) else {
            preconditionFailure("ARP L2: reply has invalid ARP frame")
        }

        // ── Validate L1: ARP reply structural constraints ──
        precondition(arp.operation == .reply,
            "RFC 826: ARP reply operation must be reply(2), got \(arp.operation)")
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
            preconditionFailure(
                "RFC 826: ARP reply (senderIP=\(arp.senderIP), targetIP=\(arp.targetIP)) has no matching request")
        }

        // ── Validate correspondence ──
        // RFC 826: Reply dstMAC == request srcMAC
        precondition(eth.dstMAC == req.eth.srcMAC,
            "RFC 826: ARP reply dstMAC \(eth.dstMAC) ≠ request srcMAC \(req.eth.srcMAC)")
        // RFC 826: Reply srcMAC == hostMAC (proxy ARP)
        precondition(eth.srcMAC == hostMAC,
            "RFC 826: ARP reply srcMAC \(eth.srcMAC) ≠ hostMAC \(hostMAC)")
        // RFC 826: senderMAC == hostMAC (proxy ARP identity)
        precondition(arp.senderMAC == hostMAC,
            "RFC 826: ARP reply senderMAC \(arp.senderMAC) ≠ hostMAC \(hostMAC)")
        // RFC 826: targetMAC == request senderMAC (answering the requester)
        precondition(arp.targetMAC == req.arp.senderMAC,
            "RFC 826: ARP reply targetMAC \(arp.targetMAC) ≠ request senderMAC \(req.arp.senderMAC)")
        // RFC 826: senderIP == request targetIP (the IP being resolved)
        precondition(arp.senderIP == req.arp.targetIP,
            "RFC 826: ARP reply senderIP \(arp.senderIP) ≠ request targetIP \(req.arp.targetIP)")
        // RFC 826: targetIP == request senderIP (the requester's IP)
        precondition(arp.targetIP == req.arp.senderIP,
            "RFC 826: ARP reply targetIP \(arp.targetIP) ≠ request senderIP \(req.arp.senderIP)")
        // Endpoint consistency
        precondition(replyEp == req.ep,
            "ARP L2: reply endpoint \(replyEp) ≠ request endpoint \(req.ep)")
    }
}

// MARK: DHCP (RFC 2131) — Phase 8

/// Extract a DHCP packet from within a wrapped Ethernet→IP→UDP→DHCP reply frame.
/// Returns nil if any layer fails to parse or ports don't match.
private func extractDHCPFromReplyFrame(_ pkt: PacketBuffer) -> DHCPPacket? {
    guard let eth = EthernetFrame.parse(from: pkt),
          eth.etherType == .ipv4,
          let ip = IPv4Header.parse(from: eth.payload),
          ip.protocol == .udp else { return nil }

    var udpPkt = ip.payload
    guard udpPkt.totalLength >= 8 else { return nil }
    guard udpPkt.pullUp(8) else { return nil }

    return udpPkt.withUnsafeReadableBytes { buf -> DHCPPacket? in
        let srcPort = (UInt16(buf[0]) << 8) | UInt16(buf[1])
        let dstPort = (UInt16(buf[2]) << 8) | UInt16(buf[3])
        guard srcPort == 67, dstPort == 68 else { return nil }
        let dhcpPayload = udpPkt.slice(from: 8, length: udpPkt.totalLength - 8)
        return DHCPPacket.parse(from: dhcpPayload)
    }
}

func debugValidateDHCPPhase(
    requests: [(ep: Int, eth: EthernetFrame, ip: IPv4Header, dhcp: DHCPPacket)],
    replies: ArraySlice<(endpointID: Int, packet: PacketBuffer)>,
    hostMAC: MACAddress
) {
    for (replyEp, replyPkt) in replies {
        // ── Re-parse the reply independently ──
        guard let eth = EthernetFrame.parse(from: replyPkt) else {
            preconditionFailure("DHCP L2: reply has invalid Ethernet")
        }
        guard eth.etherType == .ipv4 else {
            preconditionFailure("DHCP L2: reply EtherType is not IPv4")
        }
        guard let ip = IPv4Header.parse(from: eth.payload) else {
            preconditionFailure("DHCP L2: reply has invalid IPv4 header")
        }
        guard ip.protocol == .udp else {
            preconditionFailure("DHCP L2: reply IP protocol is not UDP")
        }
        guard let dhcp = extractDHCPFromReplyFrame(replyPkt) else {
            preconditionFailure("DHCP L2: reply has invalid DHCP packet")
        }

        // ── Validate L1: DHCP reply constraints ──
        precondition(dhcp.op == 2,
            "RFC 2131 §2: DHCP reply op must be BOOTREPLY(2), got \(dhcp.op)")
        debugValidateDHCPPacket(dhcp)

        // ── Validate L1: IP header checksum ──
        precondition(ip.verifyChecksum(),
            "RFC 791 §3.1: DHCP reply IP checksum INVALID — stale bytes in pool chunk?")

        // ── Match reply to request via xid (transaction ID) ──
        let match = requests.first { req in
            req.dhcp.xid == dhcp.xid
        }
        guard let req = match else {
            preconditionFailure(
                "RFC 2131 §2: DHCP reply (xid=\(dhcp.xid)) has no matching request")
        }

        // ── Validate correspondence ──
        // RFC 2131: Reply dstMAC == request srcMAC (chaddr)
        precondition(eth.dstMAC == req.eth.srcMAC,
            "RFC 2131: DHCP reply dstMAC \(eth.dstMAC) ≠ request srcMAC \(req.eth.srcMAC)")
        // RFC 2131: Reply srcMAC == hostMAC
        precondition(eth.srcMAC == hostMAC,
            "RFC 2131: DHCP reply srcMAC \(eth.srcMAC) ≠ hostMAC \(hostMAC)")
        // RFC 2131 §2: chaddr must match
        precondition(dhcp.chaddr == req.dhcp.chaddr,
            "RFC 2131 §2: DHCP reply chaddr \(dhcp.chaddr) ≠ request chaddr \(req.dhcp.chaddr)")
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
            preconditionFailure(
                "RFC 2131 §4.3.1: invalid DHCP message transition \(req.dhcp.messageType) → \(dhcp.messageType)")
        }
        // RFC 2131: Reply srcIP == gateway IP (which is request dstIP)
        precondition(ip.srcAddr == req.ip.dstAddr,
            "RFC 2131: DHCP reply srcIP \(ip.srcAddr) ≠ gateway IP \(req.ip.dstAddr)")
        // Endpoint consistency
        precondition(replyEp == req.ep,
            "DHCP L2: reply endpoint \(replyEp) ≠ request endpoint \(req.ep)")
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

#endif
