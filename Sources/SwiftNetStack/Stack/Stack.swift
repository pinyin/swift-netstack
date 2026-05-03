import Foundation
import Darwin

// MARK: - Stack Config

public struct StackConfig {
    public var socketPath: String = "/tmp/bdp-stack.sock"
    public var gatewayMAC: Data = Data([0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xee])
    public var gatewayIP: UInt32 = ipToUInt32("192.168.65.1")
    public var subnetCIDR: String = "192.168.65.0/24"
    public var mtu: Int = 1500
    public var bpt: TimeInterval = 0.001
    public var tcpBufSize: Int = 64 * 1024
    public var portForwards: [ForwarderMapping] = []
    public var debug: Bool = false

    public init() {}
    public static func defaultConfig() -> StackConfig { StackConfig() }
}

// MARK: - Stack

public final class Stack {
    let cfg: StackConfig
    var conn: VZDebugConn?
    let arp: ARPResolver
    let tcpState: TCPState
    let udpMux: UDPMux
    let dhcpSrv: DHCPServer
    let dnsProxy: DNSProxy
    let natTable: NATTable
    var fwd: Forwarder?
    var icmpFwd: ICMPForwarder?
    let udpNAT: UDPNATTable

    // Monotonic IP ID counter (replaces Date-based ID to avoid collisions)
    private var nextIPID: UInt16 = 0

    // Single-threaded: accessed only from the deliberation loop
    public var bytesIn: UInt64 = 0
    public var bytesOut: UInt64 = 0

    // Diagnostic counters (removable)
    public var diagRoundCount: Int = 0
    public var diagFrameCount: Int = 0
    public var diagMaxFramesPerRound: Int = 0
    public var diagTotalDeliberateUs: UInt64 = 0
    public var diagTotalProcessFrameUs: UInt64 = 0

    public init(cfg: StackConfig, tcpState: TCPState) {
        self.cfg = cfg
        self.arp = ARPResolver()
        self.tcpState = tcpState
        self.udpMux = UDPMux()
        self.natTable = NATTable()
        self.udpNAT = UDPNATTable()

        // DHCP
        let dhcpCfg = DHCPServerConfig(
            gatewayIP: cfg.gatewayIP,
            subnetMask: ipToUInt32("255.255.255.0"),
            dnsIP: cfg.gatewayIP,
            domainName: "bdp.local",
            poolStart: ipToUInt32("192.168.65.2"),
            poolSize: 50
        )
        self.dhcpSrv = DHCPServer(cfg: dhcpCfg)
        udpMux.register(port: serverPort, handler: dhcpSrv.handler())

        // DNS Proxy
        self.dnsProxy = DNSProxy(listenIP: cfg.gatewayIP, upstreamAddr: "")
        udpMux.register(port: dnsPort, handler: dnsProxy.handler())

        // Port forwarding
        if !cfg.portForwards.isEmpty {
            self.fwd = Forwarder(gatewayIP: cfg.gatewayIP, mappings: cfg.portForwards)
            // Set DHCP lease callback for ARP learning
            dhcpSrv.onLease = { [weak self] clientIP, clientMAC in
                let macData = Data([clientMAC.b0, clientMAC.b1, clientMAC.b2,
                                    clientMAC.b3, clientMAC.b4, clientMAC.b5])
                self?.arp.set(ip: clientIP, mac: macData)
            }
        }

        // ICMP forwarder
        self.icmpFwd = ICMPForwarder()

        // ARP: static gateway entry
        arp.set(ip: cfg.gatewayIP, mac: cfg.gatewayMAC)

        // TCP write callback
        tcpState.setWriteFunc { [weak self] seg in
            return self?.sendSegment(seg)
        }
    }

    // MARK: - Connection

    public func setConn(_ conn: VZDebugConn) {
        self.conn = conn
    }

    /// Poll the underlying socket for readability.
    /// - Parameter timeout: seconds to wait; 0 = non-blocking check.
    /// - Returns: true if data is available to read.
    public func waitForData(timeout: TimeInterval) -> Bool {
        conn?.waitForData(timeout: timeout) ?? false
    }

    // MARK: - Run

    public func run() throws {
        if self.conn == nil && !cfg.socketPath.isEmpty {
            guard let conn = VZDebugConn.listen(socketPath: cfg.socketPath) else {
                throw NSError(domain: "Stack", code: 1,
                              userInfo: [NSLocalizedDescriptionKey: "Failed to listen on \(cfg.socketPath)"])
            }
            self.conn = conn
        }

        let interval = cfg.bpt

        while true {
            deliberate(now: Date())

            // Check if more data is immediately available (non-blocking poll).
            // If so, loop immediately — no fixed tick, event-driven.
            if let conn = conn, conn.waitForData(timeout: 0) {
                continue
            }

            // No pending input. Block until data arrives, or BPT expires.
            // BPT serves as the maximum wait ceiling, ensuring timer
            // expiration and other internal events are handled promptly.
            _ = conn?.waitForData(timeout: interval)
        }
    }

    // MARK: - Deliberate

    public func deliberate(now: Date) {
        let t0 = CFAbsoluteTimeGetCurrent()

        // Phase 1: Read all available Ethernet frames
        if let conn = conn {
            let frames = conn.readAllFrames()
            diagFrameCount += frames.count
            if frames.count > diagMaxFramesPerRound { diagMaxFramesPerRound = frames.count }
            for frame in frames {
                bytesIn += UInt64(frame.payload.count)
                processFrame(frame)
            }
        }

        let t1 = CFAbsoluteTimeGetCurrent()

        // Phase 2: Forwarder accept + poll
        if let fwd = fwd {
            fwd.pollAccept(tcpState: tcpState)
            fwd.poll()
        }

        // Phase 3: NAT poll
        natTable.poll()

        // Phase 4: UDP NAT poll
        udpNAT.poll()

        // Phase 5: TCP deliberation
        tcpState.deliberate(now: now)

        // Phase 6: ICMP forwarder poll
        if let icmpFwd = icmpFwd {
            icmpFwd.poll()
            icmpFwd.cleanup(timeout: 30)
        }

        // Phase 7: Forwarder proxy VM→Host
        fwd?.proxyVMToHost()

        // Phase 8: NAT proxy VM→Host
        natTable.proxyVMToHost()

        // Phase 9: UDP NAT flush egress
        udpNAT.flushEgress()

        // Phase 10: DNS poll
        dnsProxy.poll()

        // Phase 11: Write DNS responses
        for dg in dnsProxy.consumeResponses() {
            sendDatagram(dg)
        }

        // Phase 12: Write remaining TCP outputs (should be empty with writeFunc)
        for seg in tcpState.consumeOutputs() {
            if let err = sendSegment(seg) {
                if (err as NSError).domain == NSPOSIXErrorDomain &&
                    (err as NSError).code == Int(ENOBUFS) {
                    break
                }
            }
        }

        // Phase 13: Write outgoing UDP datagrams
        for dg in udpMux.consumeOutputs() {
            sendDatagram(dg)
        }

        // Phase 14: Write ICMP replies
        if let icmpFwd = icmpFwd {
            for reply in icmpFwd.consumeReplies() {
                sendICMPReply(reply)
            }
        }

        // Phase 15: UDP NAT deliver to VM
        for dg in udpNAT.deliverToVM() {
            sendDatagram(dg)
        }

        // Phase 16: Forwarder cleanup
        fwd?.cleanup()

        // Phase 17: NAT cleanup
        natTable.cleanup()

        // Phase 18: UDP NAT cleanup
        udpNAT.cleanup(now: now)

        // Phase 19: DHCP lease expiration
        dhcpSrv.expireLeases(now: now)

        // Phase 20: ARP cache cleanup
        arp.cleanup(now: now)

        FlowStats.global.printIfDue()

        let t2 = CFAbsoluteTimeGetCurrent()
        diagRoundCount += 1
        diagTotalProcessFrameUs += UInt64((t1 - t0) * 1_000_000)
        diagTotalDeliberateUs += UInt64((t2 - t0) * 1_000_000)
    }

    // MARK: - Frame Processing

    func processFrame(_ frame: Frame) {
        switch frame.etherType {
        case etherTypeARP:
            processARP(frame)
        case etherTypeIPv4:
            processIPv4(frame)
        default:
            break
        }
    }

    func processARP(_ frame: Frame) {
        guard let arpPkt = ARPPacket.parse([UInt8](frame.payload)) else { return }

        // Learn sender's MAC
        arp.set(ip: ipFromData(arpPkt.senderIP), mac: arpPkt.senderMAC)

        // Reply to ARP requests for our gateway IP
        if arpPkt.operation == arpRequest && ipFromData(arpPkt.targetIP) == cfg.gatewayIP {
            let reply = buildARPReply(
                senderMAC: cfg.gatewayMAC, senderIP: ipData(from: cfg.gatewayIP),
                targetMAC: arpPkt.senderMAC, targetIP: arpPkt.senderIP
            )
            let outFrame = Frame(
                dstMAC: arpPkt.senderMAC, srcMAC: cfg.gatewayMAC,
                etherType: etherTypeARP, payload: Data(reply.serialize())
            )
            if let err = conn?.write(frame: outFrame) {
                NSLog("write ARP reply: %@", err.localizedDescription)
            }
            bytesOut += UInt64(outFrame.payload.count)
        }
    }

    func processIPv4(_ frame: Frame) {
        // Zero-copy: pass frame.payload (Data) directly to IPv4Packet.parse(Data)
        guard let pkt = IPv4Packet.parse(frame.payload) else { return }

        // Learn source IP→MAC
        arp.set(ip: pkt.srcIP, mac: frame.srcMAC)

        // TCP to external IPs → NAT
        if pkt.protocol == protocolTCP && !pkt.isForUs(cfg.gatewayIP) {
            processNAT(frame, pkt)
            return
        }

        // ICMP to external IPs → forwarder
        if pkt.protocol == protocolICMP && !pkt.isForUs(cfg.gatewayIP) {
            processICMPForward(frame, pkt)
            return
        }

        // UDP to external IPs → UDP NAT
        if pkt.protocol == protocolUDP && !pkt.isForUs(cfg.gatewayIP) {
            processUDPNAT(frame, pkt)
            return
        }

        guard pkt.isForUs(cfg.gatewayIP) else { return }

        switch pkt.protocol {
        case protocolICMP:
            processICMP(frame, pkt)
        case protocolTCP:
            processTCP(frame, pkt)
        case protocolUDP:
            processUDP(frame, pkt)
        default:
            break
        }
    }

    // MARK: - Protocol Handlers

    func processICMP(_ frame: Frame, _ pkt: IPv4Packet) {
        guard let icmp = ICMPPacket.parse(pkt.payload) else { return }
        guard icmp.type == icmpTypeEchoRequest else { return }

        let reply = buildEchoReply(icmp)
        let ipReply = IPv4Packet(
            version: 4, ihl: 20, tos: 0, totalLen: 0, id: pkt.id,
            flags: 0, fragOffset: 0, ttl: 64, protocol: protocolICMP,
            checksum: 0, srcIP: pkt.dstIP, dstIP: pkt.srcIP,
            payload: Data(reply.serialize())
        )
        _ = writeIPv4Packet(dstMAC: frame.srcMAC, pkt: ipReply)
    }

    func processICMPForward(_ frame: Frame, _ pkt: IPv4Packet) {
        guard let icmpFwd = icmpFwd else { return }
        guard let icmpPkt = ICMPPacket.parse(pkt.payload) else { return }
        guard icmpPkt.type == icmpTypeEchoRequest else { return }

        let id = UInt16(icmpPkt.restHdr >> 16)
        let seq = UInt16(icmpPkt.restHdr & 0xFFFF)
        icmpFwd.forward(srcIP: pkt.srcIP, dstIP: pkt.dstIP,
                        id: id, seq: seq, payload: [UInt8](icmpPkt.payload))
    }

    func processUDPNAT(_ frame: Frame, _ pkt: IPv4Packet) {
        guard let (hdr, payload) = parseUDP(pkt.payload) else { return }
        let dg = UDPDatagram(srcIP: pkt.srcIP, dstIP: pkt.dstIP,
                             srcPort: hdr.srcPort, dstPort: hdr.dstPort,
                             payload: payload)
        _ = udpNAT.intercept(dg)
    }

    func processTCP(_ frame: Frame, _ pkt: IPv4Packet) {
        // Verify TCP checksum on ingress (zero-copy: Data withUnsafeBytes)
        let cs = pkt.payload.withUnsafeBytes { ptr in
            tcpChecksum(srcIP: pkt.srcIP, dstIP: pkt.dstIP, tcpDataPtr: ptr.baseAddress!, tcpDataCount: pkt.payload.count)
        }
        guard cs == 0 else { return }

        guard let seg = TCPSegment.parse(pkt.payload, srcIP: pkt.srcIP, dstIP: pkt.dstIP) else { return }
        tcpState.injectSegment(seg)
    }

    func processUDP(_ frame: Frame, _ pkt: IPv4Packet) {
        guard let (hdr, payload) = parseUDP(pkt.payload) else { return }
        // Verify UDP checksum if present (non-zero)
        if hdr.checksum != 0 {
            let cs = pkt.payload.withUnsafeBytes { ptr in
                udpChecksum(srcIP: pkt.srcIP, dstIP: pkt.dstIP, udpDataPtr: ptr.baseAddress!, udpDataCount: pkt.payload.count)
            }
            guard cs == 0 else { return }
        }
        let dg = UDPDatagram(srcIP: pkt.srcIP, dstIP: pkt.dstIP,
                             srcPort: hdr.srcPort, dstPort: hdr.dstPort,
                             payload: payload)
        udpMux.deliver(dg)
    }

    func processNAT(_ frame: Frame, _ pkt: IPv4Packet) {
        guard let seg = TCPSegment.parse(pkt.payload, srcIP: pkt.srcIP, dstIP: pkt.dstIP) else { return }
        _ = natTable.intercept(seg, tcpState: tcpState)
    }

    // MARK: - Output Helpers

    func sendSegment(_ seg: TCPSegment) -> Error? {
        let dstIP = seg.tuple.dstIP
        guard let dstMAC = arp.lookup(ip: dstIP) else {
            FlowStats.global.outARPMiss += 1
            return nil
        }

        // NetBuf fast path: segment was built with buildSegmentNetBuf
        // Layout: [14 Eth headroom | 20 IP headroom | TCP header | payload]
        if let nb = seg.netBuf {
            let srcIP = seg.tuple.srcIP
            let tcpLen = nb.length

            // Compute TCP checksum directly on NetBuf (zero-allocation)
            let cs = nb.withUnsafeReadableBytes { ptr in
                tcpChecksum(srcIP: srcIP, dstIP: dstIP, tcpDataPtr: ptr.baseAddress!, tcpDataCount: tcpLen)
            }
            nb.setUInt16BE(at: 16, cs)  // checksum at offset 16 in TCP header

            // Prepend IP header into headroom (20 bytes)
            let ipPkt = IPv4Packet(
                version: 4, ihl: 20, tos: 0, totalLen: 0,
                id: nextIPID,
                flags: 0, fragOffset: 0, ttl: 64, protocol: protocolTCP,
                checksum: 0, srcIP: srcIP, dstIP: dstIP,
                payload: Data()
            )
            nextIPID = nextIPID &+ 1
            _ = ipPkt.serialize(into: nb)

            // Prepend Ethernet header into headroom (14 bytes)
            _ = prependEthernetHeader(into: nb, dstMAC: dstMAC, srcMAC: cfg.gatewayMAC, etherType: etherTypeIPv4)

            // Write directly from NetBuf to socket
            let payloadBytes = tcpLen - Int(seg.header.dataOffset)
            FlowStats.global.outSegs += 1
            FlowStats.global.outBytes += Int64(payloadBytes)
            return writeNetBuf(nb)
        }

        // Legacy path (fallback for segments without netBuf)
        var tcpBytes = seg.raw
        if tcpBytes.isEmpty {
            tcpBytes = seg.header.marshal() + seg.payload
        }
        let cs = tcpChecksum(srcIP: seg.tuple.srcIP, dstIP: seg.tuple.dstIP, tcpData: tcpBytes)
        tcpBytes[16] = UInt8(cs >> 8)
        tcpBytes[17] = UInt8(cs & 0xFF)

        let ipPkt = IPv4Packet(
            version: 4, ihl: 20, tos: 0, totalLen: 0,
            id: nextIPID,
            flags: 0, fragOffset: 0, ttl: 64, protocol: protocolTCP,
            checksum: 0, srcIP: seg.tuple.srcIP, dstIP: seg.tuple.dstIP,
            payload: Data(tcpBytes)
        )
        nextIPID = nextIPID &+ 1

        FlowStats.global.outSegs += 1
        FlowStats.global.outBytes += Int64(seg.payload.count)
        return writeIPv4Packet(dstMAC: dstMAC, pkt: ipPkt)
    }

    /// Write a NetBuf directly to the connection socket.
    func writeNetBuf(_ nb: NetBuf) -> Error? {
        guard let conn = conn else { return nil }
        if let err = conn.write(netBuf: nb) {
            if (err as NSError).domain == NSPOSIXErrorDomain &&
                (err as NSError).code == Int(ENOBUFS) {
                FlowStats.global.outBufFull += 1
            }
            return err
        }
        bytesOut += UInt64(nb.length)
        return nil
    }

    func sendDatagram(_ dg: UDPDatagram) {
        let dstMAC: Data
        if let mac = arp.lookup(ip: dg.dstIP) {
            dstMAC = mac
        } else {
            dstMAC = broadcastMAC
        }

        // NetBuf zero-copy: build complete frame [Eth | IP | UDP | payload] in one buffer
        let payloadBuf = dg.payload.withUnsafeBytes { ptr in
            NetBuf(copying: ptr.baseAddress!, count: dg.payload.count, headroom: 0)
        }
        let nb = buildDatagramNetBuf(srcPort: dg.srcPort, dstPort: dg.dstPort, payload: payloadBuf)

        // Prepend IP header
        let ipPkt = IPv4Packet(
            version: 4, ihl: 20, tos: 0, totalLen: 0,
            id: nextIPID,
            flags: 0, fragOffset: 0, ttl: 64, protocol: protocolUDP,
            checksum: 0, srcIP: dg.srcIP, dstIP: dg.dstIP,
            payload: Data()
        )
        nextIPID = nextIPID &+ 1
        _ = ipPkt.serialize(into: nb)

        // Prepend Ethernet header
        _ = prependEthernetHeader(into: nb, dstMAC: dstMAC, srcMAC: cfg.gatewayMAC, etherType: etherTypeIPv4)

        FlowStats.global.outSegs += 1
        FlowStats.global.outBytes += Int64(dg.payload.count)
        _ = writeNetBuf(nb)
    }

    func sendICMPReply(_ reply: ICMPReply) {
        guard let dstMAC = arp.lookup(ip: reply.dstIP) else {
            NSLog("ICMP reply: no ARP entry for %@", ipString(reply.dstIP))
            return
        }

        let icmpData = buildICMPReplyData(id: reply.id, seq: reply.seq, payload: reply.payload)

        let ipPkt = IPv4Packet(
            version: 4, ihl: 20, tos: 0, totalLen: 0, id: nextIPID,
            flags: 0, fragOffset: 0, ttl: 64, protocol: protocolICMP,
            checksum: 0, srcIP: reply.srcIP, dstIP: reply.dstIP,
            payload: Data(icmpData)
        )
        nextIPID = nextIPID &+ 1

        _ = writeIPv4Packet(dstMAC: dstMAC, pkt: ipPkt)
    }

    func writeIPv4Packet(dstMAC: Data, pkt: IPv4Packet) -> Error? {
        guard let conn = conn else { return nil }
        let ipBytes = pkt.serialize()
        let frame = Frame(dstMAC: dstMAC, srcMAC: cfg.gatewayMAC,
                          etherType: etherTypeIPv4, payload: Data(ipBytes))
        if let err = conn.write(frame: frame) {
            if (err as NSError).domain == NSPOSIXErrorDomain &&
                (err as NSError).code == Int(ENOBUFS) {
                FlowStats.global.outBufFull += 1
            }
            return err
        }
        bytesOut += UInt64(ipBytes.count)
        return nil
    }
}

// MARK: - IP Helpers

func ipFromData(_ data: Data) -> UInt32 {
    guard data.count >= 4 else { return 0 }
    return UInt32(data[0]) << 24 | UInt32(data[1]) << 16 |
           UInt32(data[2]) << 8 | UInt32(data[3])
}

func ipData(from ip: UInt32) -> Data {
    Data([UInt8(ip >> 24), UInt8(ip >> 16 & 0xFF),
          UInt8(ip >> 8 & 0xFF), UInt8(ip & 0xFF)])
}
