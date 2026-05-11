import Darwin

/// Persistent BDP deliberation loop — the library entry point for callers.
///
/// Owns long-lived protocol state (ARP table, DHCP leases, NAT connections)
/// and exposes two levels of control:
/// - `run(transport:while:)` — continuous loop with a caller-provided condition
/// - `runOneRound(transport:)` — single 14-phase cycle for caller-driven pacing
///
/// DeliberationLoop never creates fds and runs entirely within sandbox constraints.
/// The caller owns all file descriptors and thread management.
///
/// Usage:
///   var loop = DeliberationLoop(endpoints: [vm1], hostMAC: myMAC)
///   var transport = PollingTransport(endpoints: [vm1])
///   loop.run(transport: &transport, while: { !shutdown })
public struct DeliberationLoop {
    public let hostMAC: MACAddress
    public var arpMapping: ARPMapping
    public var dhcpServer: DHCPServer
    public var dnsServer: DNSServer
    public let routingTable: RoutingTable
    public var socketRegistry: SocketRegistry
    public var natTable: NATTable

    /// Optional pcap writer for capturing VM↔NAT Ethernet frames.
    /// Set before calling run() to record traffic for Wireshark/tcpdump analysis.
    public var pcapWriter: PCAPWriter?

    /// Per-phase cumulative CPU time for hotspot analysis.
    public var phaseTiming = PhaseTiming()

    public init(
        endpoints: [VMEndpoint],
        hostMAC: MACAddress,
        portForwards: [PortForwardEntry] = [],
        hosts: [String: IPv4Address] = [:],
        upstreamDNS: IPv4Address? = nil,
        pcapWriter: PCAPWriter? = nil
    ) {
        self.hostMAC = hostMAC
        self.arpMapping = ARPMapping(hostMAC: hostMAC, endpoints: endpoints)
        self.dhcpServer = DHCPServer(endpoints: endpoints)
        self.routingTable = RoutingTable()
        self.socketRegistry = SocketRegistry()
        let mss = (endpoints.map { $0.mtu }.min() ?? 1500) - 40
        self.natTable = NATTable(portForwards: portForwards, mss: mss)
        self.dnsServer = DNSServer(hosts: hosts, upstream: upstreamDNS)
        self.pcapWriter = pcapWriter

#if DEBUG
        debugRunTCPFSMTests()
#endif
    }

    // MARK: - Dynamic port forwarding

    public var activePortForwards: [PortForwardEntry] { natTable.activePortForwards }

    @discardableResult
    public mutating func addPortForward(_ pf: PortForwardEntry) -> Bool { natTable.addPortForward(pf) }

    @discardableResult
    public mutating func removePortForward(hostPort: UInt16, protocol: IPProtocol) -> Bool {
        natTable.removePortForward(hostPort: hostPort, protocol: `protocol`)
    }

    // MARK: - Main loop

    /// Execute one BDP deliberation round (16 phases).
    ///
    /// Returns the number of packets written to the transport.
    @discardableResult
    public mutating func runOneRound(transport: inout PollingTransport, roundNumber: UInt64) -> Int {
        let round = RoundContext()
        round.roundNumber = roundNumber

        var replies: [(endpointID: Int, packet: PacketBuffer)] = []
        var forwardPkts: [(endpointID: Int, packet: PacketBuffer)] = []

        // ── Dynamic poll timeout for delayed ACK coalescing ──
        let nowUs = monotonicMicros()
        if let deadline = natTable.nextDelayedACKDeadline() {
            let deltaUs = deadline > nowUs ? deadline - nowUs : 0
            transport.pollTimeout = Int32(max(1, Int(deltaUs / 1000)))
        } else {
            transport.pollTimeout = 100
        }

        // ── Phase 1: Unified poll — all FDs treated equally ──
        let tPoll = cpuNanos()
        let result = transport.readPackets(round: round)

        // Capture VM→NAT frames for pcap debugging
        if let pw = pcapWriter {
            for (_, pkt) in result.vmFrames {
                pw.write(packet: pkt)
            }
        }
        phaseTiming.pollRead &+= cpuNanos() - tPoll

        // ── Phase 2-6: Parse ALL headers ──
        let tParse = cpuNanos()

        // ── Phase 2: Parse ALL Ethernet headers ──
        var ethParsed: [(ep: Int, pkt: PacketBuffer, eth: EthernetFrame)] = []
        ethParsed.reserveCapacity(result.vmFrames.count)
        for (ep, pkt) in result.vmFrames {
            if let eth = EthernetFrame.parse(from: pkt) {
                ethParsed.append((ep, pkt, eth))
            }
        }
#if DEBUG
        debugValidateEthernetParse(ethParsed)
#endif

        // ── Phase 3: MAC filter + EtherType dispatch + L2 forward ──
        var arpPkts: [(ep: Int, pkt: PacketBuffer, eth: EthernetFrame)] = []
        var ipv4Pkts: [(ep: Int, pkt: PacketBuffer, eth: EthernetFrame)] = []
        let ethCount = ethParsed.count
        arpPkts.reserveCapacity(ethCount)
        ipv4Pkts.reserveCapacity(ethCount)
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
        debugValidateMACFilter(arpPkts: arpPkts, ipv4Pkts: ipv4Pkts, forwardPkts: forwardPkts)
#endif

        // ── Phase 4: Parse ALL IPv4 headers ──
        var ipv4Parsed: [(ep: Int, eth: EthernetFrame, ip: IPv4Header)] = []
        ipv4Parsed.reserveCapacity(ipv4Pkts.count)
        for (ep, _, eth) in ipv4Pkts {
            guard let ip = IPv4Header.parse(from: eth.payload) else { continue }
            ipv4Parsed.append((ep, eth, ip))
        }
#if DEBUG
        debugValidateIPv4Parse(ipv4Parsed)
#endif

        // ── Phase 5: Parse ALL ARP frames ──
        var arpParsed: [(ep: Int, eth: EthernetFrame, arp: ARPFrame)] = []
        arpParsed.reserveCapacity(arpPkts.count)
        for (ep, _, eth) in arpPkts {
            if let arp = ARPFrame.parse(from: eth.payload) {
                arpParsed.append((ep, eth, arp))
            }
        }
#if DEBUG
        debugValidateARPParse(arpParsed)
#endif

        // ── Phase 6: Parse ALL transport headers ──
        var icmpParsed: [(ep: Int, eth: EthernetFrame, ip: IPv4Header, icmp: ICMPHeader)] = []
        var udpParsed: [(ep: Int, eth: EthernetFrame, ip: IPv4Header, udp: UDPHeader)] = []
        var dhcpParsed: [(ep: Int, eth: EthernetFrame, ip: IPv4Header, dhcp: DHCPPacket)] = []
        var dnsParsed: [(ep: Int, eth: EthernetFrame, ip: IPv4Header, udp: UDPHeader)] = []
        var tcpParsed: [(ep: Int, eth: EthernetFrame, ip: IPv4Header, tcp: TCPHeader)] = []
        var unreachableParsed: [(ep: Int, eth: EthernetFrame, ip: IPv4Header)] = []
        let ipv4Count = ipv4Parsed.count
        icmpParsed.reserveCapacity(ipv4Count)
        udpParsed.reserveCapacity(ipv4Count)
        dhcpParsed.reserveCapacity(ipv4Count)
        dnsParsed.reserveCapacity(ipv4Count)
        tcpParsed.reserveCapacity(ipv4Count)
        unreachableParsed.reserveCapacity(ipv4Count)
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
        debugValidateTransportParse(icmpParsed: icmpParsed, udpParsed: udpParsed, dhcpParsed: dhcpParsed, tcpParsed: tcpParsed, unreachableParsed: unreachableParsed)
#endif
        phaseTiming.parse &+= cpuNanos() - tParse

        // ── Phase 7-8: Process ALL ICMP ──
        let tICMP = cpuNanos()

        // ── Phase 7: Process ALL ICMP Echo ──
#if DEBUG
        let icmpSnapshot = icmpParsed
        let replyCountPreICMP = replies.count
#endif
        for (ep, eth, ip, icmp) in icmpParsed {
            guard icmp.type == 8, icmp.code == 0 else { continue }
            if let reply = buildICMPEchoReply(
                hostMAC: arpMapping.hostMAC, eth: eth, ip: ip, icmp: icmp, round: round
            ) {
                replies.append((ep, reply))
            }
        }
#if DEBUG
        debugValidateICMPPhase(
            requests: icmpSnapshot,
            replies: replies[replyCountPreICMP...],
            hostMAC: arpMapping.hostMAC
        )
#endif

        // ── Phase 8: Process ALL ICMP Protocol Unreachable ──
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

        phaseTiming.icmp &+= cpuNanos() - tICMP

        // ── Phase 9: Process ALL UDP ──
        let tUDP = cpuNanos()
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
                    transport: &transport,
                    replies: &replies, round: round
                )
            }
        }
#if DEBUG
        debugValidateUDPPhase(
            requests: udpSnapshot,
            replies: replies[replyCountPreUDP...],
            hostMAC: arpMapping.hostMAC
        )
#endif

        phaseTiming.udp &+= cpuNanos() - tUDP

        // ── Phase 10: Process ALL DNS ──
        let tDNS = cpuNanos()
        for (ep, eth, ip, udp) in dnsParsed {
            dnsServer.processQuery(
                payload: udp.payload,
                srcIP: ip.srcAddr, dstIP: ip.dstAddr,
                srcPort: udp.srcPort, dstPort: udp.dstPort,
                srcMAC: eth.srcMAC,
                endpointID: ep,
                hostMAC: arpMapping.hostMAC,
                transport: &transport,
                replies: &replies,
                round: round
            )
        }

        phaseTiming.dns &+= cpuNanos() - tDNS

        // ── Phase 11: Unified TCP processing (VM ↔ external) ──
        let tTCP = cpuNanos()
        // Handles all TCP work in one method: connect completion, VM segment
        // processing, external reads/hangups, and queue draining.  Eliminates
        // the old 4-phase design and its "manual updated flag" anti-pattern.
#if DEBUG
        let tcpSnapshot = tcpParsed
        let replyCountPreTCP = replies.count
#endif
        natTable.processTCPRound(
            vmSegments: tcpParsed,
            streamReads: result.streamReads,
            streamHangup: result.streamHangup,
            streamConnects: result.streamConnects,
            transport: &transport,
            hostMAC: arpMapping.hostMAC,
            arpMapping: arpMapping,
            replies: &replies,
            round: round
        )
#if DEBUG
        debugValidateTCPPhase(
            requests: tcpSnapshot,
            replies: replies[replyCountPreTCP...],
            hostMAC: arpMapping.hostMAC
        )
#endif

        phaseTiming.tcp &+= cpuNanos() - tTCP

        // ── Phase 12: Non-TCP transport results ──
        let tNATResult = cpuNanos()
        // Handles dead FDs, stream accepts, and UDP reads only.
        // TCP reads/hangups/connects are handled by processTCPRound above.
#if DEBUG
        let replyCountPreNAT = replies.count
#endif
        natTable.processTransportResult(
            result,
            transport: &transport,
            hostMAC: arpMapping.hostMAC,
            arpMapping: arpMapping,
            replies: &replies,
            round: round
        )
#if DEBUG
        debugValidateNATPoll(preReplies: replyCountPreNAT, replies: replies)
#endif

        phaseTiming.natResult &+= cpuNanos() - tNATResult

        // ── Phase 13: DNS upstream — expire + process ──
        let tDNSUp = cpuNanos()
        dnsServer.expireQueries(
            hostMAC: arpMapping.hostMAC,
            replies: &replies,
            round: round
        )
        dnsServer.processUpstreamReady(
            data: result.rawDatagramReads,
            hostMAC: arpMapping.hostMAC,
            replies: &replies,
            round: round
        )

        phaseTiming.dnsUpstream &+= cpuNanos() - tDNSUp

        // ── Phase 14-15: Process DHCP + ARP ──
        let tDHCPARP = cpuNanos()

        // ── Phase 14: Process ALL DHCP ──
#if DEBUG
        let dhcpSnapshot = dhcpParsed
        let replyCountPreDHCP = replies.count
#endif
        for (ep, eth, _, dhcp) in dhcpParsed {
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
        debugValidateDHCPPhase(
            requests: dhcpSnapshot,
            replies: replies[replyCountPreDHCP...],
            hostMAC: arpMapping.hostMAC
        )
#endif

        // ── Phase 15: Process ALL ARP ──
#if DEBUG
        let arpSnapshot = arpParsed
        let replyCountPreARP = replies.count
#endif
        for (ep, _, arp) in arpParsed {
            if let reply = arpMapping.processARPRequest(arp, round: round) {
                replies.append((ep, reply))
            }
        }
#if DEBUG
        debugValidateARPPhase(
            requests: arpSnapshot,
            replies: replies[replyCountPreARP...],
            hostMAC: arpMapping.hostMAC
        )
#endif

        phaseTiming.dhcpArp &+= cpuNanos() - tDHCPARP

        // ── Phase 16: Batch write + cleanup ──
        let tWrite = cpuNanos()
#if DEBUG
        debugValidateReplies(replies)
        debugValidateReplies(forwardPkts)
#endif

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

        round.endRound()

        let allOutputs = replies + forwardPkts
        if let pw = pcapWriter {
            for (_, pkt) in allOutputs {
                pw.write(packet: pkt)
            }
        }
        if !allOutputs.isEmpty {
            transport.writePackets(allOutputs)
        }
        phaseTiming.write &+= cpuNanos() - tWrite
        phaseTiming.totalRounds += 1
        return allOutputs.count
    }

    /// Run the BDP loop continuously until `shouldContinue` returns false.
    ///
    /// Returns the total number of rounds executed.
    @discardableResult
    public mutating func run(transport: inout PollingTransport, while shouldContinue: () -> Bool) -> UInt64 {
        natTable.syncExternalFDs(with: &transport)
        dnsServer.registerUpstreamFD(with: &transport)
        natTable.externalPcap = pcapWriter
        var roundCount: UInt64 = 0
        while shouldContinue() {
            runOneRound(transport: &transport, roundNumber: roundCount)
            roundCount += 1
            if roundCount % 1000 == 0 {
                printStats(round: roundCount, interval: 1000,
                           transport: transport.stats.snap(),
                           nat: natTable.stats.snap(),
                           phase: phaseTiming.snap())
            }
        }
        return roundCount
    }
}
