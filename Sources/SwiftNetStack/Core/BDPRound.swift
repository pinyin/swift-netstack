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
///   Phase 6:  Parse ALL transport headers   (ICMP + UDP + DHCP + DNS + TCP parse)
///   Phase 7:  Process ALL ICMP Echo           (buildICMPEchoReply)
///   Phase 8:  Process ALL ICMP Unreachable    (buildICMPProtocolUnreachable, unsupported proto)
///   Phase 9:  Process ALL UDP                 (SocketHandler or NATTable.processUDP)
///   Phase 9a: Process ALL DNS                 (DNSServer.processQuery)
///   Phase 10: Process ALL TCP                 (NATTable.processTCP, VM→external)
///   Phase 11: NAT socket poll                 (NATTable.pollSockets, external→VM, TCP+UDP)
///   Phase 12: Process ALL DHCP                (DHCPServer.process, L2/L3 bootstrapping)
///   Phase 13: Process ALL ARP                 (processARPRequest)
///   Phase 14: Batch write + endRound          (syscall + reclaim)
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
    dnsServer: inout DNSServer,
    routingTable: RoutingTable,
    socketRegistry: inout SocketRegistry,
    ipFragmentReassembler: inout IPFragmentReassembler,
    natTable: inout NATTable,
    round: RoundContext,
    pcapWriter: PCAPWriter? = nil
) -> Int {
    // ── Phase 1: Poll + batch read ──
    var taggedFrames = transport.readPackets(round: round)
    if let pw = pcapWriter {
        for (_, pkt) in taggedFrames { pw.write(packet: pkt) }
    }

    // Phases 2–10 and 12–13 are skipped when there are no VM frames, but
    // Phase 11 (pollSockets) must still run — external TCP/UDP sockets may
    // have data waiting regardless of VM-side activity.
    if taggedFrames.isEmpty {
        var replies: [(endpointID: Int, packet: PacketBuffer)] = []
        natTable.pollSockets(
            hostMAC: arpMapping.hostMAC,
            arpMapping: arpMapping,
            replies: &replies, round: round
        )
        dnsServer.pollUpstream(
            hostMAC: arpMapping.hostMAC,
            replies: &replies, round: round
        )
        let replyCount = replies.count
        if !replies.isEmpty {
            transport.writePackets(replies)
            if let pw = pcapWriter {
                for (_, pkt) in replies { pw.write(packet: pkt) }
            }
        }
        replies.removeAll()
        round.endRound()
        return replyCount
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
    // I-cache: IPv4Header.parse + verifyChecksum + fragment reassembly
    //
    // Fragment detection: (MF=1 or offset>0) means this is a fragment.
    // Fragments are routed to the reassembler and excluded from ipv4Parsed
    // until reassembly is complete. When the last fragment arrives, the
    // reassembled datagram is re-parsed and injected into the pipeline.
    var ipv4Parsed: [(ep: Int, eth: EthernetFrame, ip: IPv4Header)] = []
    for (ep, _, eth) in ipv4Pkts {
        guard let ip = IPv4Header.parse(from: eth.payload), ip.verifyChecksum() else { continue }
        let isFragment = (ip.flags & 0x01) != 0 || ip.fragmentOffset != 0
        if isFragment {
            if let reassembled = ipFragmentReassembler.process(fragment: ip, rawIPPacket: eth.payload) {
                // Reassembly complete — re-parse the full datagram into the pipeline
                if let fullIP = IPv4Header.parse(from: reassembled), fullIP.verifyChecksum() {
                    ipv4Parsed.append((ep, eth, fullIP))
                }
            }
            // Fragment stored but not yet complete — skip this entry
        } else {
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
    // ARPFrame.parse validates operation via ARPOperation(rawValue:) — invalid
    // opcodes (e.g., 0 or 42) cause parse to return nil before reaching Phase 11.
    // This contract catches any remaining edge cases that survive parsing.
    debugValidateARPParse(arpParsed)
#endif

    // ── Phase 6: Parse ALL transport headers ──
    // I-cache: ICMPHeader.parse + UDPHeader.parse + DHCPPacket.parse + TCPHeader.parse
    var icmpParsed: [(ep: Int, eth: EthernetFrame, ip: IPv4Header, icmp: ICMPHeader)] = []
    var udpParsed: [(ep: Int, eth: EthernetFrame, ip: IPv4Header, udp: UDPHeader)] = []
    var dhcpParsed: [(ep: Int, eth: EthernetFrame, ip: IPv4Header, dhcp: DHCPPacket)] = []
    var dnsParsed: [(ep: Int, eth: EthernetFrame, ip: IPv4Header, udp: UDPHeader)] = []
    var tcpParsed: [(ep: Int, eth: EthernetFrame, ip: IPv4Header, tcp: TCPHeader)] = []
    var unreachableParsed: [(ep: Int, eth: EthernetFrame, ip: IPv4Header)] = []
    for (ep, eth, ip) in ipv4Parsed {
        switch ip.protocol {
        case .icmp:
            if let icmp = ICMPHeader.parse(from: ip.payload) {
                icmpParsed.append((ep, eth, ip, icmp))
            }
        case .udp:
            guard let udp = UDPHeader.parse(
                from: ip.payload,
                pseudoSrcAddr: ip.srcAddr,
                pseudoDstAddr: ip.dstAddr
            ) else { break }
            if udp.dstPort == 67 || udp.srcPort == 67 {
                if let dhcp = DHCPPacket.parse(from: udp.payload) {
                    dhcpParsed.append((ep, eth, ip, dhcp))
                }
            } else if udp.dstPort == 53 {
                dnsParsed.append((ep, eth, ip, udp))
            } else {
                udpParsed.append((ep, eth, ip, udp))
            }
        case .tcp:
            guard let tcp = TCPHeader.parse(
                from: ip.payload,
                pseudoSrcAddr: ip.srcAddr,
                pseudoDstAddr: ip.dstAddr
            ) else { break }
            tcpParsed.append((ep, eth, ip, tcp))
        @unknown default:
            unreachableParsed.append((ep, eth, ip))
        }
    }
#if DEBUG
    // Contract: icmpParsed contains only .icmp protocol, udpParsed contains only .udp
    // protocol, dhcpParsed contains only DHCP packets (from UDP port 67). The switch
    // in Phase 6 dispatches by ip.protocol — a mismatch here means the wrong case arm
    // matched or ICMPHeader/UDPHeader/DHCPPacket.parse returned nil for a valid packet.
    debugValidateTransportParse(icmpParsed: icmpParsed, udpParsed: udpParsed, dhcpParsed: dhcpParsed, tcpParsed: tcpParsed, unreachableParsed: unreachableParsed)
#endif


    var replies: [(endpointID: Int, packet: PacketBuffer)] = []

    // ── Phase 7: Process ALL ICMP Echo ──
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

    // ── Phase 8: Process ALL ICMP Protocol Unreachable ──
    // Generate ICMP Destination Unreachable (Protocol Unreachable, Type 3 Code 2)
    // for packets with unsupported transport protocols (e.g., TCP).
    for (ep, eth, ip) in unreachableParsed {
        if let reply = buildICMPProtocolUnreachable(
            hostMAC: arpMapping.hostMAC,
            clientMAC: eth.srcMAC,
            gatewayIP: ip.dstAddr,
            clientIP: ip.srcAddr,
            rawIPPacket: eth.payload,
            round: round
        ) {
            replies.append((ep, reply))
        }
    }

    // ── Phase 9: Process ALL UDP ──
    // I-cache: SocketRegistry.lookup + NATTable.processUDP
    // Registered socket handlers take priority; unmatched traffic is NATed.
#if DEBUG
    let udpSnapshot = udpParsed
    let replyCountPreUDP = replies.count
#endif
    for (ep, eth, ip, udp) in udpParsed {
        if let socket = socketRegistry.lookup(port: udp.dstPort) {
            socket.handleDatagram(
                payload: udp.payload,
                srcIP: ip.srcAddr, dstIP: ip.dstAddr,
                srcPort: udp.srcPort, dstPort: udp.dstPort,
                srcMAC: eth.srcMAC,
                endpointID: ep,
                hostMAC: arpMapping.hostMAC,
                replies: &replies,
                round: round
            )
        } else {
            natTable.processUDP(
                eth: eth, ip: ip, udp: udp, endpointID: ep,
                hostMAC: arpMapping.hostMAC,
                replies: &replies, round: round
            )
        }
    }
#if DEBUG
    // L2: Validate every UDP reply against its matching request via
    // (srcPort, dstPort, srcIP). Re-parses Eth→IP→UDP independently.
    debugValidateUDPPhase(
        requests: udpSnapshot,
        replies: replies[replyCountPreUDP...],
        hostMAC: arpMapping.hostMAC
    )
#endif

    // ── Phase 9a: Process ALL DNS ──
    // I-cache: DNSServer.processQuery — hosts-file lookup only
    for (ep, eth, ip, udp) in dnsParsed {
        dnsServer.processQuery(
            payload: udp.payload,
            srcIP: ip.srcAddr, dstIP: ip.dstAddr,
            srcPort: udp.srcPort, dstPort: udp.dstPort,
            srcMAC: eth.srcMAC,
            endpointID: ep,
            hostMAC: arpMapping.hostMAC,
            replies: &replies,
            round: round
        )
    }

    // ── Phase 10: Process ALL TCP (VM → external) ──
    // I-cache: NATTable.processTCP — FSM dispatch only, no syscalls
#if DEBUG
    let tcpSnapshot = tcpParsed
    let replyCountPreTCP = replies.count
#endif
    for (ep, eth, ip, tcp) in tcpParsed {
        natTable.processTCP(
            eth: eth, ip: ip, tcp: tcp, endpointID: ep,
            hostMAC: arpMapping.hostMAC,
            replies: &replies, round: round
        )
    }
#if DEBUG
    debugValidateTCPPhase(
        requests: tcpSnapshot,
        replies: replies[replyCountPreTCP...],
        hostMAC: arpMapping.hostMAC
    )
#endif

    // ── Phase 11: NAT socket poll (external → VM) ──
    // I-cache: NATTable.pollSockets — poll + read/write, both TCP and UDP
#if DEBUG
    let replyCountPreNAT = replies.count
#endif
    natTable.pollSockets(
        hostMAC: arpMapping.hostMAC,
        arpMapping: arpMapping,
        replies: &replies, round: round
    )
#if DEBUG
    debugValidateNATPoll(
        preReplies: replyCountPreNAT,
        replies: replies
    )
#endif

    // ── Phase 11a: DNS upstream poll ──
    dnsServer.pollUpstream(
        hostMAC: arpMapping.hostMAC,
        replies: &replies, round: round
    )

    // ── Phase 12: Process ALL DHCP ──
#if DEBUG
    // L2 snapshot: DHCP replies are matched to requests via xid (RFC 2131 §2).
    let dhcpSnapshot = dhcpParsed
    let replyCountPreDHCP = replies.count
#endif
    // I-cache: DHCPServer.process — no parsing
    for (ep, eth, _, dhcp) in dhcpParsed {
        // Only process BOOTREQUEST (op=1). DHCP replies (op=2) in the inbound
        // path are either misconfigured guest servers or routing errors — neither
        // belongs in the server pipeline.
        guard dhcp.op == 1 else { continue }
        if let (frame, targetEp) = dhcpServer.process(
            packet: dhcp, srcMAC: eth.srcMAC,
            endpointID: ep, hostMAC: arpMapping.hostMAC,
            arpMapping: &arpMapping, round: round
        ) {
            replies.append((targetEp, frame))
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

    // ── Phase 13: Process ALL ARP ──
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

    // ── Phase 14: Batch write + endRound ──
#if DEBUG
    // L3: Phase flow integrity. After all processing phases, every reply and
    // forwarded frame must have a valid endpoint ID and ≥14 bytes. Protocol-level
    // validation (L1+L2) already completed in the per-phase debug blocks above.
    debugValidateReplies(replies)
    debugValidateReplies(forwardPkts)
#endif
    if let pw = pcapWriter {
        for (_, pkt) in forwardPkts { pw.write(packet: pkt) }
        for (_, pkt) in replies  { pw.write(packet: pkt) }
    }
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
    udpParsed.removeAll()
    dhcpParsed.removeAll()
    dnsParsed.removeAll()
    tcpParsed.removeAll()
    unreachableParsed.removeAll()
    forwardPkts.removeAll()
    replies.removeAll()

    round.endRound()
    return forwardCount + replyCount
}

