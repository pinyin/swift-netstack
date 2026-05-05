/// BDP main round: poll → classify → dispatch → write → endRound.
///
/// All phases execute synchronously within a single thread. Blocking poll
/// is part of deliberation for network infrastructure — where the next packet
/// comes from is unknown until poll returns, so blocking is the correct
/// deliberation posture.
///
/// This function duplicates the parsing phases from `classifyFrames` because
/// it needs to track endpointID alongside each frame to route replies back
/// to the correct VM endpoint. `classifyFrames` is a stateless utility for
/// contexts where endpoint tracking isn't needed.
///
/// ## Phase separation
///
/// Each phase keeps a single code path in L1 cache. Parse phases never
/// interleave with business-logic phases — intermediate arrays carry results
/// between phases so I-cache stays hot within each phase.
///
///   Phase 1: Poll + batch read          (syscall)
///   Phase 2: Parse ALL Ethernet headers (EthernetFrame.parse, ~15 insns)
///   Phase 3: MAC filter + EtherType     (branch logic only)
///   Phase 4: Parse ALL IPv4 headers     (IPv4Header.parse, ~25 insns)
///   Phase 5: Parse ALL ARP frames       (ARPFrame.parse, ~20 insns)
///   Phase 6: Process ALL ICMP           (ICMPHeader.parse + buildICMPEchoReply)
///   Phase 7: Process ALL DHCP           (DHCPServer.process)
///   Phase 8: Process ALL ARP            (processARPRequest)
///   Phase 9: Batch write + endRound     (syscall + reclaim)
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

    // ── Phase 3: MAC filter + EtherType dispatch ──
    // I-cache: integer comparison + switch
    var arpPkts: [(ep: Int, pkt: PacketBuffer, eth: EthernetFrame)] = []
    var ipv4Pkts: [(ep: Int, pkt: PacketBuffer, eth: EthernetFrame)] = []
    for (ep, pkt, eth) in ethParsed {
        guard eth.dstMAC == arpMapping.ourMAC || eth.dstMAC == .broadcast else {
            continue
        }
        switch eth.etherType {
        case .arp:  arpPkts.append((ep, pkt, eth))
        case .ipv4: ipv4Pkts.append((ep, pkt, eth))
        @unknown default: break
        }
    }

    // ── Phase 4: Parse ALL IPv4 headers ──
    // I-cache: IPv4Header.parse + verifyChecksum — no business logic
    var ipv4Parsed: [(ep: Int, eth: EthernetFrame, ip: IPv4Header)] = []
    for (ep, _, eth) in ipv4Pkts {
        if let ip = IPv4Header.parse(from: eth.payload), ip.verifyChecksum() {
            ipv4Parsed.append((ep, eth, ip))
        }
    }

    // ── Phase 5: Parse ALL ARP frames ──
    // I-cache: ARPFrame.parse only — no reply generation
    var arpParsed: [(ep: Int, eth: EthernetFrame, arp: ARPFrame)] = []
    for (ep, _, eth) in arpPkts {
        if let arp = ARPFrame.parse(from: eth.payload) {
            arpParsed.append((ep, eth, arp))
        }
    }

    var replies: [(endpointID: Int, packet: PacketBuffer)] = []

    // ── Phase 6: Process ALL ICMP ──
    // I-cache: ICMPHeader.parse + buildICMPEchoReply
    for (ep, eth, ip) in ipv4Parsed {
        guard ip.protocol == .icmp else { continue }
        guard let icmp = ICMPHeader.parse(from: ip.payload) else { continue }
        guard icmp.type == 8, icmp.code == 0 else { continue }  // echo request only

        if let reply = buildICMPEchoReply(
            ourMAC: arpMapping.ourMAC, eth: eth, ip: ip, icmp: icmp, round: round
        ) {
            replies.append((ep, reply))
        }
    }

    // ── Phase 7: Process ALL DHCP ──
    // I-cache: extractDHCP + DHCPServer.process + buildDHCPReply
    for (ep, eth, ip) in ipv4Parsed {
        guard ip.protocol == .udp else { continue }
        guard let dhcpPkt = extractDHCP(from: ip.payload) else { continue }

        if let (reply, targetEp) = dhcpServer.process(
            packet: dhcpPkt, srcMAC: eth.srcMAC,
            endpointID: ep, arpMapping: &arpMapping, round: round
        ) {
            replies.append((targetEp, reply))
        }
    }

    // ── Phase 8: Process ALL ARP ──
    // I-cache: ARPMapping.processARPRequest + ARP reply frame construction
    for (ep, _, arp) in arpParsed {
        if let reply = arpMapping.processARPRequest(arp, round: round) {
            replies.append((ep, reply))
        }
    }

    // ── Phase 9: Batch write + endRound ──
    let replyCount = replies.count
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
    replies.removeAll()

    round.endRound()
    return replyCount
}

/// Extract a DHCP packet from a UDP datagram payload.
/// Returns nil if the destination port is not 67 (DHCP server) or if
/// the DHCP packet is malformed.
private func extractDHCP(from udpPayload: PacketBuffer) -> DHCPPacket? {
    var pkt = udpPayload
    // UDP header: srcPort(2) + dstPort(2) + length(2) + checksum(2) = 8
    guard pkt.totalLength >= 8 else { return nil }
    guard pkt.pullUp(8) else { return nil }

    return pkt.withUnsafeReadableBytes { buf in
        let dstPort = (UInt16(buf[2]) << 8) | UInt16(buf[3])
        guard dstPort == 67 else { return nil }

        let dhcpPayload = pkt.slice(from: 8, length: pkt.totalLength - 8)
        return DHCPPacket.parse(from: dhcpPayload)
    }
}
