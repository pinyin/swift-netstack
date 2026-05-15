import Darwin

/// Persistent BDP deliberation loop — the library entry point for callers.
///
/// Owns long-lived protocol state (ARP table, DHCP leases, NAT connections)
/// and exposes two levels of control:
/// - `run(transport:while:)` — continuous loop with a caller-provided condition
/// - `runOneRound(transport:)` — single cycle for caller-driven pacing
///
/// DeliberationLoop never creates fds and runs entirely within sandbox constraints.
/// The caller owns all file descriptors and thread management.
public struct DeliberationLoop {
    public let hostMAC: MACAddress
    public var arpMapping: ARPMapping
    public var dhcpServer: DHCPServer
    public var dnsServer: DNSServer
    public let routingTable: RoutingTable
    public var socketRegistry: SocketRegistry
    public var natTable: NATTable

    /// Optional pcap writer for capturing VM↔NAT Ethernet frames.
    public var pcapWriter: PCAPWriter?

    /// Per-phase cumulative CPU time for hotspot analysis.
    public var phaseTiming = PhaseTiming()

    /// Timestamp of last ARP reap (seconds since epoch).
    private var lastARPReapSec: UInt64 = 0

    /// IPv4 fragment reassembly state machine.
    private var fragmentReassembly = FragmentReassembly(maxReassemblies: 16)
    /// Rate limiter for ICMP error messages (RFC 1812 §4.3.2.8).
    private var icmpErrorLimiter = RateLimiter<IPv4Address>(window: 1, maxRequests: 10)

    // ── Pre-allocated SoA infrastructure ──
    private let io: IOBuffer
    private let parseOutput: ParseOutput
    private var fwdBatch: OutBatch
    private var outBatch: OutBatch

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
        natTable.localIPs = Set(endpoints.map { $0.gateway })
        natTable.upstreamDNS = upstreamDNS
        self.dnsServer = DNSServer(hosts: hosts, upstream: upstreamDNS)
        self.pcapWriter = pcapWriter

        let maxFrames = 4096
        let mtu = endpoints.map { $0.mtu }.max() ?? 1500
        self.io = IOBuffer(maxFrames: maxFrames, mtu: mtu)
        self.parseOutput = ParseOutput(maxFrames: maxFrames)
        self.fwdBatch = OutBatch(maxFrames: maxFrames)
        self.outBatch = OutBatch(maxFrames: maxFrames)

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

    @discardableResult
    public mutating func runOneRound(transport: inout PollingTransport, roundNumber: UInt64) -> Int {
        var totalWritten = 0

        // Reset output arena — readPackets resets frameCount, but not outputUsed.
        io.reset()

        // ── Dynamic poll timeout ──
        let nowSec = UInt64(Darwin.time(nil))
        let nowUs = monotonicMicros()

        // Periodic ARP reap (every 60 seconds)
        if nowSec - lastARPReapSec > 60 {
            arpMapping.reapExpired(now: nowSec)
            lastARPReapSec = nowSec
        }
        // Pick the earliest deadline among ACK, RTO, and persist timers
        let deadlines = natTable.nextDeadlines()
        var earliestDeadline: UInt64?
        if let ackDL = deadlines.ack {
            earliestDeadline = ackDL
        }
        if let rtoDL = deadlines.rto {
            if earliestDeadline == nil || rtoDL < earliestDeadline! { earliestDeadline = rtoDL }
        }
        if let persistDL = deadlines.persist {
            if earliestDeadline == nil || persistDL < earliestDeadline! { earliestDeadline = persistDL }
        }
        if let deadline = earliestDeadline {
            let deltaUs = deadline > nowUs ? deadline - nowUs : 0
            transport.pollTimeout = Int32(max(1, Int(deltaUs / 1000)))
        } else {
            transport.pollTimeout = 5  // 5ms fallback (was 100ms)
        }

        // ── Phase 1: Poll ──
        let tPoll = cpuNanos()
        let result = transport.readPackets(io: io)
        // pcap capture for VM→NAT frames
        if let pw = pcapWriter {
            for i in 0..<io.frameCount {
                let ptr = io.framePtr(i)
                let len = io.frameLengths[i]
                pw.writeRaw(framePtr: ptr, len: len)
            }
        }
        phaseTiming.pollRead &+= cpuNanos() - tPoll

        // ── Phase 2-6: Unified parse ──
        let tParse = cpuNanos()
        parseAllFrames(io: io, out: parseOutput, hostMAC: hostMAC,
                       arpMapping: arpMapping, fwdBatch: fwdBatch)
        phaseTiming.parse &+= cpuNanos() - tParse

        // Write L2 forwarded frames
        if fwdBatch.count > 0 {
            let tW = cpuNanos()
            transport.writeBatch(fwdBatch, io: io)
            phaseTiming.write &+= cpuNanos() - tW
            totalWritten += fwdBatch.count
        }

        // ── Phase 7: ICMP Echo ──
        let tICMP = cpuNanos()
        outBatch.reset()
        processICMPEcho(outBatch: outBatch)
        if outBatch.count > 0 {
            let tW = cpuNanos()
            if let pw = pcapWriter { writeBatchToPcap(batch: outBatch, pcap: pw) }
            transport.writeBatch(outBatch, io: io)
            phaseTiming.write &+= cpuNanos() - tW
            totalWritten += outBatch.count
        }

        // ── Phase 8: ICMP Unreachable ──
        outBatch.reset()
        processICMPUnreachable(outBatch: outBatch)
        if outBatch.count > 0 {
            let tW = cpuNanos()
            if let pw = pcapWriter { writeBatchToPcap(batch: outBatch, pcap: pw) }
            transport.writeBatch(outBatch, io: io)
            phaseTiming.write &+= cpuNanos() - tW
            totalWritten += outBatch.count
        }
        phaseTiming.icmp &+= cpuNanos() - tICMP

        // ── Phase 8.5: IPv4 Fragment Reassembly ──
        if parseOutput.fragment.count > 0 {
            for i in 0..<parseOutput.fragment.count {
                let f = parseOutput.fragment.frames[i]
                let framePtr = io.framePtr(f.frameIdx)
                let result = fragmentReassembly.processFragment(
                    framePtr: framePtr,
                    frameLen: f.frameLen,
                    frameIndex: f.frameIdx,
                    identification: f.identification,
                    flagsFrag: f.flagsFrag,
                    srcIP: f.srcIP,
                    dstIP: f.dstIP,
                    protocol: f.ipProtocol,
                    now: nowSec, io: io,
                    ipHeaderLen: f.ipHeaderLen
                )
                // Reassembled datagram ready — re-inject into parse pipeline.
                // The reassembled payload is in io.output; for now the caller
                // could dispatch it directly. Future: re-parse the assembled datagram.
                if let _ = result {
                    // Reassembly complete. The assembled payload is in io.output.
                    // TODO: dispatch to transport layer (e.g., via natTable).
                }
            }
            // Periodic reap of expired fragment reassemblies (every 30s)
            fragmentReassembly.reapExpired(now: nowSec)
        }

        // ── Phase 9: UDP ──
        let tUDP = cpuNanos()
        outBatch.reset()
        processUDP(outBatch: outBatch, transport: &transport, nowSec: nowSec)
        if outBatch.count > 0 {
            let tW = cpuNanos()
            if let pw = pcapWriter { writeBatchToPcap(batch: outBatch, pcap: pw) }
            transport.writeBatch(outBatch, io: io)
            phaseTiming.write &+= cpuNanos() - tW
            totalWritten += outBatch.count
        }
        phaseTiming.udp &+= cpuNanos() - tUDP

        // ── Phase 10: DNS ──
        let tDNS = cpuNanos()
        outBatch.reset()
        processDNS(outBatch: outBatch, transport: &transport)
        if outBatch.count > 0 {
            let tW = cpuNanos()
            if let pw = pcapWriter { writeBatchToPcap(batch: outBatch, pcap: pw) }
            transport.writeBatch(outBatch, io: io)
            phaseTiming.write &+= cpuNanos() - tW
            totalWritten += outBatch.count
        }
        phaseTiming.dns &+= cpuNanos() - tDNS

        // ── Phase 11: TCP ──
        let tTCP = cpuNanos()
        natTable.processTCPRound(
            out: parseOutput, io: io,
            streamReads: result.streamReads,
            streamDataBuffer: result.streamDataBuffer,
            streamHangup: result.streamHangup,
            streamConnects: result.streamConnects,
            transport: &transport,
            hostMAC: hostMAC,
            arpMapping: arpMapping,
            nowSec: nowSec,
            nowUs: nowUs
        )
        phaseTiming.tcp &+= cpuNanos() - tTCP

        // ── Phase 12: Non-TCP transport results ──
        let tNATResult = cpuNanos()
        natTable.processTransportResult(
            result, transport: &transport,
            hostMAC: hostMAC, arpMapping: arpMapping,
            io: io
        )
        phaseTiming.natResult &+= cpuNanos() - tNATResult

        // ── Phase 13: DNS upstream ──
        let tDNSUp = cpuNanos()
        outBatch.reset()
        dnsServer.expireQueries(
            hostMAC: hostMAC, outBatch: outBatch, io: io
        )
        if outBatch.count > 0 {
            let tW = cpuNanos()
            transport.writeBatch(outBatch, io: io)
            phaseTiming.write &+= cpuNanos() - tW
            totalWritten += outBatch.count
        }
        outBatch.reset()
        dnsServer.processUpstreamReady(
            data: result.rawDatagramReads,
            hostMAC: hostMAC, outBatch: outBatch, io: io
        )
        if outBatch.count > 0 {
            let tW = cpuNanos()
            transport.writeBatch(outBatch, io: io)
            phaseTiming.write &+= cpuNanos() - tW
            totalWritten += outBatch.count
        }
        phaseTiming.dnsUpstream &+= cpuNanos() - tDNSUp

        // ── Phase 14-15: DHCP + ARP ──
        let tDHCPARP = cpuNanos()
        outBatch.reset()
        processDHCP(outBatch: outBatch)
        if outBatch.count > 0 {
            let tW = cpuNanos()
            if let pw = pcapWriter { writeBatchToPcap(batch: outBatch, pcap: pw) }
            transport.writeBatch(outBatch, io: io)
            phaseTiming.write &+= cpuNanos() - tW
            totalWritten += outBatch.count
        }

        outBatch.reset()
        processARP(outBatch: outBatch)
        if outBatch.count > 0 {
            let tW = cpuNanos()
            if let pw = pcapWriter { writeBatchToPcap(batch: outBatch, pcap: pw) }
            transport.writeBatch(outBatch, io: io)
            phaseTiming.write &+= cpuNanos() - tW
            totalWritten += outBatch.count
        }
        phaseTiming.dhcpArp &+= cpuNanos() - tDHCPARP

        // ── Cleanup ──
        phaseTiming.totalRounds += 1
        let wallEnd = monotonicMicros()
        phaseTiming.wallNanos &+= (wallEnd - nowUs) * 1000
        return totalWritten
    }

    // MARK: - Protocol processing (inline for simple protocols)

    private mutating func processICMPEcho(outBatch: OutBatch) {
        for i in 0..<parseOutput.icmpEcho.count {
            let f = parseOutput.icmpEcho.frames[i]
            let hdrOfs = buildICMPEchoReplyHeader(
                io: io,
                hostMAC: hostMAC,
                dstMAC: f.srcMAC,
                srcIP: f.dstIP,
                dstIP: f.srcIP,
                identifier: f.identifier,
                sequenceNumber: f.sequenceNumber,
                payloadLen: f.payloadLen,
                payloadSum: f.payloadSum
            )
            guard hdrOfs >= 0 else { break }
            let idx = outBatch.count
            guard idx < outBatch.maxFrames else { break }
            outBatch.hdrOfs[idx] = hdrOfs
            outBatch.hdrLen[idx] = ethHeaderLen + ipv4HeaderLen + 8  // 42
            outBatch.payOfs[idx] = f.payloadOfs
            outBatch.payLen[idx] = f.payloadLen
            outBatch.epIDs[idx] = f.endpointID
            outBatch.payBase[idx] = nil
            outBatch.count += 1
        }
    }

    private mutating func processICMPUnreachable(outBatch: OutBatch) {
        for i in 0..<parseOutput.unreach.count {
            let f = parseOutput.unreach.frames[i]
            // Rate limit per destination IP to prevent ICMP error floods.
            guard icmpErrorLimiter.allow(f.clientIP) else { continue }

            // Compute payload length first so the IPv4 totalLength is accurate.
            let copyLen = min(28, f.rawLen)
            let payloadPtr = copyLen > 0
                ? UnsafeRawPointer(io.inputBase.advanced(by: f.rawOfs)) : nil
            let hdrOfs = buildICMPUnreachableHeader(
                io: io,
                hostMAC: hostMAC,
                clientMAC: f.srcMAC,
                gatewayIP: f.gatewayIP,
                clientIP: f.clientIP,
                code: f.code,
                type: f.type,
                payloadPtr: payloadPtr,
                payloadLen: copyLen
            )
            guard hdrOfs >= 0 else { break }
            let idx = outBatch.count
            guard idx < outBatch.maxFrames else { break }
            outBatch.hdrOfs[idx] = hdrOfs
            outBatch.hdrLen[idx] = ethHeaderLen + ipv4HeaderLen + 8  // 42
            outBatch.payOfs[idx] = f.rawOfs
            outBatch.payLen[idx] = copyLen
            outBatch.epIDs[idx] = f.endpointID
            outBatch.payBase[idx] = nil
            outBatch.count += 1
        }
    }

    private mutating func processUDP(outBatch: OutBatch,
                                      transport: inout PollingTransport,
                                      nowSec: UInt64) {
        for i in 0..<parseOutput.udp.count {
            let f = parseOutput.udp.frames[i]

            if let socket = socketRegistry.lookup(port: f.dstPort) {
                socket.handleDatagram(
                    payloadPtr: io.inputBase.advanced(by: f.payloadOfs),
                    payloadLen: f.payloadLen,
                    srcIP: f.srcIP, dstIP: f.dstIP,
                    srcPort: f.srcPort, dstPort: f.dstPort,
                    srcMAC: f.srcMAC,
                    endpointID: f.endpointID,
                    hostMAC: hostMAC,
                    outBatch: outBatch, io: io
                )
            } else {
                let handled = natTable.processUDP(
                    srcMAC: f.srcMAC, srcIP: f.srcIP, dstIP: f.dstIP,
                    srcPort: f.srcPort, dstPort: f.dstPort,
                    payloadOfs: f.payloadOfs, payloadLen: f.payloadLen,
                    endpointID: f.endpointID,
                    hostMAC: hostMAC,
                    transport: &transport,
                    io: io,
                    nowSec: nowSec
                )
                if !handled {
                    // No socket listener and NAT table at capacity → Port Unreachable
                    let idx = parseOutput.unreach.count
                    if idx < parseOutput.unreach.capacity {
                        let ipHdrOfs = f.payloadOfs - f.ipHeaderLen - udpHeaderLen
                        parseOutput.unreach.frames[idx] = ICMPUnreachParsedFrame(
                            endpointID: f.endpointID, srcMAC: f.srcMAC,
                            gatewayIP: f.dstIP, clientIP: f.srcIP,
                            rawOfs: ipHdrOfs, rawLen: f.ipHeaderLen + udpHeaderLen + f.payloadLen,
                            code: 3, type: 3)
                        parseOutput.unreach.count += 1
                    }
                }
            }
        }
    }

    private mutating func processDNS(outBatch: OutBatch,
                                      transport: inout PollingTransport) {
        for i in 0..<parseOutput.dns.count {
            let f = parseOutput.dns.frames[i]
            dnsServer.processQuery(
                payloadPtr: io.inputBase.advanced(by: f.payloadOfs),
                payloadLen: f.payloadLen,
                srcIP: f.srcIP,
                dstIP: f.dstIP,
                srcPort: f.srcPort,
                dstPort: 53,
                srcMAC: f.srcMAC,
                endpointID: f.endpointID,
                hostMAC: hostMAC,
                transport: &transport,
                outBatch: outBatch, io: io
            )
        }
    }

    private mutating func processDHCP(outBatch: OutBatch) {
        for i in 0..<parseOutput.dhcp.count {
            let f = parseOutput.dhcp.frames[i]
            guard f.packet.op == 1 else { continue }
            if let (hdrOfs, hdrLen, epID) = dhcpServer.process(
                packet: f.packet,
                srcMAC: f.srcMAC,
                endpointID: f.endpointID,
                hostMAC: hostMAC,
                arpMapping: &arpMapping,
                io: io
            ) {
                let idx = outBatch.count
                guard idx < outBatch.maxFrames else { break }
                outBatch.hdrOfs[idx] = hdrOfs
                outBatch.hdrLen[idx] = hdrLen
                outBatch.payOfs[idx] = -1
                outBatch.payLen[idx] = 0
                outBatch.epIDs[idx] = epID
                outBatch.payBase[idx] = nil
                outBatch.count += 1
            }
        }
    }

    private mutating func processARP(outBatch: OutBatch) {
        for i in 0..<parseOutput.arp.count {
            let f = parseOutput.arp.frames[i]
            guard let (hdrOfs, hdrLen) = arpMapping.processARPRequest(
                f.frame, io: io
            ) else { continue }
            let idx = outBatch.count
            guard idx < outBatch.maxFrames else { break }
            outBatch.hdrOfs[idx] = hdrOfs
            outBatch.hdrLen[idx] = hdrLen
            outBatch.payOfs[idx] = -1
            outBatch.payLen[idx] = 0
            outBatch.epIDs[idx] = f.endpointID
            outBatch.payBase[idx] = nil
            outBatch.count += 1
        }
    }

    // MARK: - Pcap helper

    private func writeBatchToPcap(batch: OutBatch, pcap: PCAPWriter) {
        for i in 0..<batch.count {
            let hdrPtr = io.output.baseAddress!.advanced(by: batch.hdrOfs[i])
            let hdrLen = batch.hdrLen[i]
            if batch.payOfs[i] >= 0, batch.payLen[i] > 0 {
                let payBase = batch.payBase[i] ?? io.input.baseAddress!
                let payPtr = payBase.advanced(by: batch.payOfs[i])
                pcap.writeRawSplit(hdr: hdrPtr, hdrLen: hdrLen,
                                   pay: payPtr, payLen: batch.payLen[i])
            } else {
                pcap.writeRaw(framePtr: hdrPtr, len: hdrLen)
            }
        }
    }

    // MARK: - Run loop

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
