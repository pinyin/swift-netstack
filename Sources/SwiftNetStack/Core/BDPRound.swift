/// BDP main round: poll → classify → dispatch → write → endRound.
///
/// All phases execute synchronously within a single thread. Blocking poll
/// is part of deliberation for network infrastructure — where the next packet
/// comes from is unknown until poll returns, so blocking is the correct
/// deliberation posture.
///
/// ## Phase separation
///
/// Each phase keeps a single code path in L1 cache. Parse phases never
/// interleave with business-logic phases — intermediate arrays carry results
/// between phases so I-cache stays hot within each phase.
///
///   Phase 1:  Poll + batch read              (syscall)
///   Phase 2:  Parse ALL Ethernet headers     (EthernetFrame.parse, ~15 insns)
///   Phase 3:  MAC filter + EtherType dispatch (branch logic only)
///   Phase 4:  Parse ALL IPv4 headers         (IPv4Header.parse, ~25 insns)
///   Phase 5:  Parse ALL ARP frames           (ARPFrame.parse, ~20 insns)
///   Phase 6:  Parse ALL transport headers   (ICMPHeader.parse + extractDHCP)
///   Phase 7:  Process ALL ICMP               (buildICMPEchoReply)
///   Phase 8:  Process ALL DHCP               (DHCPServer.process + buildDHCPFrame)
///   Phase 9:  Process ALL ARP                (processARPRequest)
///   Phase 10: Batch write + endRound         (syscall + reclaim)
///
/// Zero-copy throughout: every .parse returns a view (slice) over the original
/// PacketBuffer. Intermediate arrays hold small value types (MAC, IP, headers)
/// plus a PacketBuffer reference — no byte copies of frame data.
///
/// Forwarding (NAT, L3 routing between VMs) is deferred to a later phase.
@discardableResult
public func bdpRound(
    transport: inout Transport,
    arpMapping: inout ARPMapping,
    dhcpServer: inout DHCPServer,
    routingTable: RoutingTable,
    round: RoundContext
) -> Int {
    // ── Phase 1: Poll + batch read ──
    var taggedFrames = transport.readPackets(round: round)
    if taggedFrames.isEmpty {
        round.endRound()
        return 0
    }

    // ── Phase 2: Parse ALL Ethernet headers ──
    // I-cache: EthernetFrame.parse only
    var ethParsed: [(ep: Int, pkt: PacketBuffer, eth: EthernetFrame)] = []
    for (ep, pkt) in taggedFrames {
        if let eth = EthernetFrame.parse(from: pkt) {
            ethParsed.append((ep, pkt, eth))
        }
    }
#if DEBUG
    // Contract: Every Ethernet-parsed entry has valid endpoint ID, ≥14-byte frame,
    // and non-zero srcMAC. Catches malformed Ethernet frames making it past the
    // parse guard — if EthernetFrame.parse returned non-nil, these invariants
    // must hold. Invalid endpoint IDs would cause misdelivery in later phases.
    debugValidateEthernetParse(ethParsed)
#endif

    // ── Phase 3: MAC filter + EtherType dispatch + L2 forward ──
    var arpPkts: [(ep: Int, pkt: PacketBuffer, eth: EthernetFrame)] = []
    var ipv4Pkts: [(ep: Int, pkt: PacketBuffer, eth: EthernetFrame)] = []
    var forwardPkts: [(endpointID: Int, packet: PacketBuffer)] = []
    for (ep, pkt, eth) in ethParsed {
        if eth.dstMAC == arpMapping.hostMAC || eth.dstMAC == .broadcast {
            switch eth.etherType {
            case .arp:  arpPkts.append((ep, pkt, eth))
            case .ipv4: ipv4Pkts.append((ep, pkt, eth))
            @unknown default: break
            }
        } else if let dstEp = arpMapping.lookupEndpoint(mac: eth.dstMAC), dstEp != ep {
            forwardPkts.append((dstEp, pkt))
        }
    }
#if DEBUG
    // Contract: After MAC dispatch, arpPkts contains only .arp EtherTypes, ipv4Pkts
    // contains only .ipv4 EtherTypes, and forwardPkts has valid destination endpoints
    // with ≥14-byte frames. A protocol-type mismatch here means the dispatch switch
    // in Phase 3 has a logic error — the wrong EtherType ended up in the wrong array.
    // Forward entries with invalid endpoints would crash the transport write.
    debugValidateMACFilter(arpPkts: arpPkts, ipv4Pkts: ipv4Pkts, forwardPkts: forwardPkts)
#endif

    // ── Phase 4: Parse ALL IPv4 headers ──
    // I-cache: IPv4Header.parse + verifyChecksum — no business logic
    var ipv4Parsed: [(ep: Int, eth: EthernetFrame, ip: IPv4Header)] = []
    for (ep, _, eth) in ipv4Pkts {
        if let ip = IPv4Header.parse(from: eth.payload), ip.verifyChecksum() {
            ipv4Parsed.append((ep, eth, ip))
        }
    }
#if DEBUG
    // Contract: Every IPv4-parsed entry has version==4, IHL≥5, totalLength≥20,
    // and valid header checksum (RFC 791). The checksum check is the key guard:
    // it catches stale pool bytes (0xCC sentinel) that would otherwise produce
    // corrupted IP headers. A failed checksum here means either the sender
    // generated a bad checksum, or COW/zeroing failed and we're reading garbage.
    debugValidateIPv4Parse(ipv4Parsed)
#endif

    // ── Phase 5: Parse ALL ARP frames ──
    // I-cache: ARPFrame.parse only — no reply generation
    var arpParsed: [(ep: Int, eth: EthernetFrame, arp: ARPFrame)] = []
    for (ep, _, eth) in arpPkts {
        if let arp = ARPFrame.parse(from: eth.payload) {
            arpParsed.append((ep, eth, arp))
        }
    }
#if DEBUG
    // Contract: Every ARP-parsed entry has operation == .request or .reply.
    // ARPFrame.parse checks htype/ptype/hlen/plen but does NOT validate the
    // operation field — a frame with an invalid opcode (e.g., 0 or 42) would
    // silently pass parsing. This contract catches those before Phase 9 tries
    // to process them (processARPRequest's own guard is the production fix for H3).
    debugValidateARPParse(arpParsed)
#endif

    // ── Phase 6: Parse ALL transport headers ──
    // I-cache: ICMPHeader.parse + extractDHCP — no reply construction
    var icmpParsed: [(ep: Int, eth: EthernetFrame, ip: IPv4Header, icmp: ICMPHeader)] = []
    var dhcpParsed: [(ep: Int, eth: EthernetFrame, ip: IPv4Header, dhcp: DHCPPacket)] = []
    for (ep, eth, ip) in ipv4Parsed {
        switch ip.protocol {
        case .icmp:
            if let icmp = ICMPHeader.parse(from: ip.payload) {
                icmpParsed.append((ep, eth, ip, icmp))
            }
        case .udp:
            if let dhcp = extractDHCP(from: ip.payload) {
                dhcpParsed.append((ep, eth, ip, dhcp))
            }
        default:
            break
        }
    }
#if DEBUG
    // Contract: icmpParsed contains only .icmp protocol, dhcpParsed contains only
    // .udp protocol. The switch in Phase 6 dispatches by ip.protocol — a mismatch
    // here means the wrong case arm matched or ICMPHeader/DHCPPacket.parse returned
    // nil for a valid packet, which would indicate a parse regression.
    debugValidateTransportParse(icmpParsed: icmpParsed, dhcpParsed: dhcpParsed)
#endif

    var replies: [(endpointID: Int, packet: PacketBuffer)] = []

    // ── Phase 7: Process ALL ICMP ──
#if DEBUG
    // L2 snapshot: capture request array and reply count before the phase.
    // After the phase, each new reply is validated against its matching request
    // via (identifier, sequenceNumber, srcIP). The validator re-parses each
    // reply independently — the construction and validation code paths are
    // disjoint, so a bug in one cannot mask itself in the other.
    let icmpSnapshot = icmpParsed
    let replyCountPreICMP = replies.count
#endif
    // I-cache: buildICMPEchoReply — no parsing
    for (ep, eth, ip, icmp) in icmpParsed {
        guard icmp.type == 8, icmp.code == 0 else { continue }  // echo request only
        if let reply = buildICMPEchoReply(
            hostMAC: arpMapping.hostMAC, eth: eth, ip: ip, icmp: icmp, round: round
        ) {
            replies.append((ep, reply))
        }
    }
#if DEBUG
    // L2: Validate every ICMP reply satisfies RFC 792 echo correspondence rules:
    // identifier/sequenceNumber match, payload byte-identical, src↔dst swap at L3,
    // dstMAC＝request srcMAC. Also re-validates L1 (checksums, type==0) independently.
    debugValidateICMPPhase(
        requests: icmpSnapshot,
        replies: replies[replyCountPreICMP...],
        hostMAC: arpMapping.hostMAC
    )
#endif

    // ── Phase 8: Process ALL DHCP ──
#if DEBUG
    // L2 snapshot: DHCP replies are matched to requests via xid (RFC 2131 §2).
    let dhcpSnapshot = dhcpParsed
    let replyCountPreDHCP = replies.count
#endif
    // I-cache: DHCPServer.process + buildDHCPFrame — no parsing
    for (ep, eth, ip, dhcp) in dhcpParsed {
        if let (rawReply, targetEp) = dhcpServer.process(
            packet: dhcp, srcMAC: eth.srcMAC,
            endpointID: ep, arpMapping: &arpMapping, round: round
        ) {
            // Extract yiaddr from raw DHCP reply (offset 16, 4 bytes)
            guard rawReply.totalLength >= 20 else { continue }
            let yiaddr = rawReply.withUnsafeReadableBytes { buf in
                IPv4Address(buf[16], buf[17], buf[18], buf[19])
            }

            if let frame = buildDHCPFrame(
                hostMAC: arpMapping.hostMAC,
                clientMAC: eth.srcMAC,
                gatewayIP: ip.dstAddr,
                yiaddr: yiaddr,
                dhcpPayload: rawReply,
                round: round
            ) {
                replies.append((targetEp, frame))
            }
        }
    }
#if DEBUG
    // L2: Validate every DHCP reply satisfies RFC 2131 correspondence rules:
    // xid match, chaddr match, message transition valid (DISCOVER→OFFER,
    // REQUEST→ACK), srcIP＝gateway IP. Re-parses Eth→IP→UDP→DHCP independently.
    debugValidateDHCPPhase(
        requests: dhcpSnapshot,
        replies: replies[replyCountPreDHCP...],
        hostMAC: arpMapping.hostMAC
    )
#endif

    // ── Phase 9: Process ALL ARP ──
#if DEBUG
    // L2 snapshot: ARP replies are matched to requests via (targetIP, senderIP).
    let arpSnapshot = arpParsed
    let replyCountPreARP = replies.count
#endif
    // I-cache: ARPMapping.processARPRequest + ARP reply frame construction
    for (ep, _, arp) in arpParsed {
        if let reply = arpMapping.processARPRequest(arp, round: round) {
            replies.append((ep, reply))
        }
    }
#if DEBUG
    // L2: Validate every ARP reply satisfies RFC 826 correspondence rules:
    // operation=reply, targetMAC＝request senderMAC, senderMAC＝hostMAC (proxy ARP),
    // senderIP＝request targetIP, targetIP＝request senderIP, dstMAC＝request srcMAC.
    debugValidateARPPhase(
        requests: arpSnapshot,
        replies: replies[replyCountPreARP...],
        hostMAC: arpMapping.hostMAC
    )
#endif

    // ── Phase 10: Batch write + endRound ──
#if DEBUG
    // L3: Phase flow integrity. After all processing phases, every reply and
    // forwarded frame must have a valid endpoint ID and ≥14 bytes. Protocol-level
    // validation (L1+L2) already completed in the per-phase debug blocks above.
    debugValidateReplies(replies)
    debugValidateReplies(forwardPkts)
#endif
    let forwardCount = forwardPkts.count
    let replyCount = replies.count
    if !forwardPkts.isEmpty {
        transport.writePackets(forwardPkts)
    }
    if !replies.isEmpty {
        transport.writePackets(replies)
    }

    // Drop all local references before endRound so isKnownUniquelyReferenced
    // can detect chunks held only by allocatedChunks → those get recycled.
    taggedFrames.removeAll()
    ethParsed.removeAll()
    arpPkts.removeAll()
    ipv4Pkts.removeAll()
    ipv4Parsed.removeAll()
    arpParsed.removeAll()
    icmpParsed.removeAll()
    dhcpParsed.removeAll()
    forwardPkts.removeAll()
    replies.removeAll()

    round.endRound()
    return forwardCount + replyCount
}

/// Extract a DHCP packet from a UDP datagram payload.
/// Returns nil if the destination port doesn't match or the DHCP packet is malformed.
func extractDHCP(from udpPayload: PacketBuffer, srcPort: UInt16? = nil, dstPort: UInt16? = 67) -> DHCPPacket? {
    var pkt = udpPayload
    // UDP header: srcPort(2) + dstPort(2) + length(2) + checksum(2) = 8
    guard pkt.totalLength >= 8 else { return nil }
    guard pkt.pullUp(8) else { return nil }

    return pkt.withUnsafeReadableBytes { buf in
        let sp = (UInt16(buf[0]) << 8) | UInt16(buf[1])
        let dp = (UInt16(buf[2]) << 8) | UInt16(buf[3])
        if let expected = srcPort, sp != expected { return nil }
        if let expected = dstPort, dp != expected { return nil }

        guard let dhcpPayload = pkt.slice(from: 8, length: pkt.totalLength - 8) else { return nil }
        return DHCPPacket.parse(from: dhcpPayload)
    }
}

/// Wrap a raw DHCP payload in Ethernet/IPv4/UDP headers.
private func buildDHCPFrame(
    hostMAC: MACAddress,
    clientMAC: MACAddress,
    gatewayIP: IPv4Address,
    yiaddr: IPv4Address,
    dhcpPayload: PacketBuffer,
    round: RoundContext
) -> PacketBuffer? {
    let dhcpLen = dhcpPayload.totalLength
    let udpLen = 8 + dhcpLen
    let ipTotalLen = 20 + udpLen
    let frameLen = 14 + ipTotalLen

    var pkt = round.allocate(capacity: frameLen, headroom: 0)
    guard let ptr = pkt.appendPointer(count: frameLen) else { return nil }
    ptr.initializeMemory(as: UInt8.self, repeating: 0, count: frameLen)

    // ── Ethernet header ──
    clientMAC.write(to: ptr)                                   // dst = client
    hostMAC.write(to: ptr.advanced(by: 6))                     // src = host
    writeUInt16BE(EtherType.ipv4.rawValue, to: ptr.advanced(by: 12))

    // ── IPv4 header (offset 14) ──
    let ipOff = 14
    ptr.advanced(by: ipOff).storeBytes(of: UInt8(0x45), as: UInt8.self)
    ptr.advanced(by: ipOff + 2).storeBytes(of: UInt8(ipTotalLen >> 8), as: UInt8.self)
    ptr.advanced(by: ipOff + 3).storeBytes(of: UInt8(ipTotalLen & 0xFF), as: UInt8.self)
    ptr.advanced(by: ipOff + 8).storeBytes(of: UInt8(64), as: UInt8.self)  // TTL
    ptr.advanced(by: ipOff + 9).storeBytes(of: IPProtocol.udp.rawValue, as: UInt8.self)
    gatewayIP.write(to: ptr.advanced(by: ipOff + 12))          // src IP
    yiaddr.write(to: ptr.advanced(by: ipOff + 16))             // dst IP
    let ipCksum = UnsafeRawBufferPointer(start: ptr.advanced(by: ipOff), count: 20)
        .withUnsafeBytes { internetChecksum($0) }
    ptr.advanced(by: ipOff + 10).storeBytes(of: UInt8(ipCksum >> 8), as: UInt8.self)
    ptr.advanced(by: ipOff + 11).storeBytes(of: UInt8(ipCksum & 0xFF), as: UInt8.self)

    // ── UDP header (offset 34) ──
    let udpOff = 34
    ptr.advanced(by: udpOff).storeBytes(of: UInt8(0x00), as: UInt8.self)
    ptr.advanced(by: udpOff + 1).storeBytes(of: UInt8(67), as: UInt8.self)  // src port = 67
    ptr.advanced(by: udpOff + 2).storeBytes(of: UInt8(0x00), as: UInt8.self)
    ptr.advanced(by: udpOff + 3).storeBytes(of: UInt8(68), as: UInt8.self)  // dst port = 68
    ptr.advanced(by: udpOff + 4).storeBytes(of: UInt8(udpLen >> 8), as: UInt8.self)
    ptr.advanced(by: udpOff + 5).storeBytes(of: UInt8(udpLen & 0xFF), as: UInt8.self)

    // ── DHCP payload (offset 42) ──
    let dhcpOff = 42
    dhcpPayload.withUnsafeReadableBytes { buf in
        ptr.advanced(by: dhcpOff).copyMemory(from: buf.baseAddress!, byteCount: dhcpLen)
    }

    return pkt
}
