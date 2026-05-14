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

        let maxFrames = 256
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
        // Pick the earliest deadline among delayed ACKs, RTO, and persist timers
        var earliestDeadline: UInt64?
        if let ackDL = natTable.nextDelayedACKDeadline() { earliestDeadline = ackDL }
        if let rtoDL = natTable.nextRTODeadline() {
            if earliestDeadline == nil || rtoDL < earliestDeadline! { earliestDeadline = rtoDL }
        }
        if let persistDL = natTable.nextPersistDeadline() {
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
        if parseOutput.fragmentCount > 0 {
            for i in 0..<parseOutput.fragmentCount {
                let frameIdx = parseOutput.fragmentFrameIdxs[i]
                let framePtr = io.framePtr(frameIdx)
                let result = fragmentReassembly.processFragment(
                    framePtr: framePtr,
                    frameLen: parseOutput.fragmentFrameLens[i],
                    frameIndex: frameIdx,
                    identification: parseOutput.fragmentIdentifications[i],
                    flagsFrag: parseOutput.fragmentFlagsFrags[i],
                    srcIP: parseOutput.fragmentSrcIPs[i],
                    dstIP: parseOutput.fragmentDstIPs[i],
                    protocol: parseOutput.fragmentProtocols[i],
                    now: nowSec, io: io,
                    ipHeaderLen: parseOutput.fragmentIPHeaderLens[i]
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
        for i in 0..<parseOutput.icmpEchoCount {
            let hdrOfs = buildICMPEchoReplyHeader(
                io: io,
                hostMAC: hostMAC,
                dstMAC: parseOutput.icmpEchoSrcMACs[i],
                srcIP: parseOutput.icmpEchoDstIPs[i],
                dstIP: parseOutput.icmpEchoSrcIPs[i],
                identifier: parseOutput.icmpEchoIDs[i],
                sequenceNumber: parseOutput.icmpEchoSeqNums[i],
                payloadLen: parseOutput.icmpEchoPayloadLen[i],
                payloadSum: parseOutput.icmpEchoPayloadSum[i]
            )
            guard hdrOfs >= 0 else { break }
            let idx = outBatch.count
            guard idx < outBatch.maxFrames else { break }
            outBatch.hdrOfs[idx] = hdrOfs
            outBatch.hdrLen[idx] = ethHeaderLen + ipv4HeaderLen + 8  // 42
            outBatch.payOfs[idx] = parseOutput.icmpEchoPayloadOfs[i]
            outBatch.payLen[idx] = parseOutput.icmpEchoPayloadLen[i]
            outBatch.epIDs[idx] = parseOutput.icmpEchoEndpointIDs[i]
            outBatch.payBase[idx] = nil
            outBatch.count += 1
        }
    }

    private mutating func processICMPUnreachable(outBatch: OutBatch) {
        for i in 0..<parseOutput.unreachCount {
            // Compute payload length first so the IPv4 totalLength is accurate.
            let copyLen = min(28, parseOutput.unreachRawLen[i])
            let hdrOfs = buildICMPUnreachableHeader(
                io: io,
                hostMAC: hostMAC,
                clientMAC: parseOutput.unreachSrcMACs[i],
                gatewayIP: parseOutput.unreachGatewayIPs[i],
                clientIP: parseOutput.unreachClientIPs[i],
                code: parseOutput.unreachCodes[i],
                type: parseOutput.unreachTypes[i],
                payloadLen: copyLen
            )
            guard hdrOfs >= 0 else { break }
            let idx = outBatch.count
            guard idx < outBatch.maxFrames else { break }
            outBatch.hdrOfs[idx] = hdrOfs
            outBatch.hdrLen[idx] = ethHeaderLen + ipv4HeaderLen + 8  // 42
            outBatch.payOfs[idx] = parseOutput.unreachRawOfs[i]
            outBatch.payLen[idx] = copyLen
            outBatch.epIDs[idx] = parseOutput.unreachEndpointIDs[i]
            outBatch.payBase[idx] = nil
            outBatch.count += 1
        }
    }

    private mutating func processUDP(outBatch: OutBatch,
                                      transport: inout PollingTransport,
                                      nowSec: UInt64) {
        for i in 0..<parseOutput.udpCount {
            let srcMAC = parseOutput.udpSrcMACs[i]
            let srcIP = parseOutput.udpSrcIPs[i]
            let dstIP = parseOutput.udpDstIPs[i]
            let srcPort = parseOutput.udpSrcPorts[i]
            let dstPort = parseOutput.udpDstPorts[i]
            let payloadOfs = parseOutput.udpPayloadOfs[i]
            let payloadLen = parseOutput.udpPayloadLen[i]
            let epID = parseOutput.udpEndpointIDs[i]

            if let socket = socketRegistry.lookup(port: dstPort) {
                socket.handleDatagram(
                    payloadPtr: io.inputBase.advanced(by: payloadOfs),
                    payloadLen: payloadLen,
                    srcIP: srcIP, dstIP: dstIP,
                    srcPort: srcPort, dstPort: dstPort,
                    srcMAC: srcMAC,
                    endpointID: epID,
                    hostMAC: hostMAC,
                    outBatch: outBatch, io: io
                )
            } else {
                let key = NATKey(vmIP: srcIP, vmPort: srcPort, dstIP: dstIP, dstPort: dstPort, protocol: .udp)
                let handled = natTable.processUDP(
                    srcMAC: srcMAC, srcIP: srcIP, dstIP: dstIP,
                    srcPort: srcPort, dstPort: dstPort,
                    payloadOfs: payloadOfs, payloadLen: payloadLen,
                    endpointID: epID,
                    hostMAC: hostMAC,
                    transport: &transport,
                    io: io,
                    nowSec: nowSec
                )
                if !handled {
                    // No socket listener and NAT table at capacity → Port Unreachable
                    let idx = parseOutput.unreachCount
                    if idx < parseOutput.maxFrames {
                        // payloadOfs points to UDP payload. IP header is 28 bytes back
                        // (20-byte IPv4 + 8-byte UDP). This is the absolute offset in io.input.
                        let ipHdrOfs = payloadOfs - ipv4HeaderLen - udpHeaderLen
                        parseOutput.unreachEndpointIDs[idx] = epID
                        parseOutput.unreachSrcMACs[idx] = srcMAC
                        parseOutput.unreachGatewayIPs[idx] = dstIP
                        parseOutput.unreachClientIPs[idx] = srcIP
                        parseOutput.unreachRawOfs[idx] = ipHdrOfs
                        parseOutput.unreachRawLen[idx] = ipv4HeaderLen + udpHeaderLen + payloadLen
                        parseOutput.unreachCodes[idx] = 3   // Port Unreachable
                        parseOutput.unreachTypes[idx] = 3   // Destination Unreachable
                        parseOutput.unreachCount += 1
                    }
                }
            }
        }
    }

    private mutating func processDNS(outBatch: OutBatch,
                                      transport: inout PollingTransport) {
        for i in 0..<parseOutput.dnsCount {
            dnsServer.processQuery(
                payloadPtr: io.inputBase.advanced(by: parseOutput.dnsPayloadOfs[i]),
                payloadLen: parseOutput.dnsPayloadLen[i],
                srcIP: parseOutput.dnsSrcIPs[i],
                dstIP: parseOutput.dnsDstIPs[i],
                srcPort: parseOutput.dnsSrcPorts[i],
                dstPort: 53,
                srcMAC: parseOutput.dnsSrcMACs[i],
                endpointID: parseOutput.dnsEndpointIDs[i],
                hostMAC: hostMAC,
                transport: &transport,
                outBatch: outBatch, io: io
            )
        }
    }

    private mutating func processDHCP(outBatch: OutBatch) {
        for i in 0..<parseOutput.dhcpCount {
            guard parseOutput.dhcpPackets[i].op == 1 else { continue }
            if let (hdrOfs, hdrLen, epID) = dhcpServer.process(
                packet: parseOutput.dhcpPackets[i],
                srcMAC: parseOutput.dhcpSrcMACs[i],
                endpointID: parseOutput.dhcpEndpointIDs[i],
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
        for i in 0..<parseOutput.arpCount {
            guard let (hdrOfs, hdrLen) = arpMapping.processARPRequest(
                parseOutput.arpFrames[i], io: io
            ) else { continue }
            let idx = outBatch.count
            guard idx < outBatch.maxFrames else { break }
            outBatch.hdrOfs[idx] = hdrOfs
            outBatch.hdrLen[idx] = hdrLen
            outBatch.payOfs[idx] = -1
            outBatch.payLen[idx] = 0
            outBatch.epIDs[idx] = parseOutput.arpEndpointIDs[i]
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
