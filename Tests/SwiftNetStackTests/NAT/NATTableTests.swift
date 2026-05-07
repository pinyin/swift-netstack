import Testing
import Darwin
@testable import SwiftNetStack

@Suite(.serialized)
struct NATTableTests {

    let hostMAC = MACAddress(0x00, 0x11, 0x22, 0x33, 0x44, 0x55)
    let subnet = IPv4Subnet(network: IPv4Address(100, 64, 1, 0), prefixLength: 24)
    let gateway = IPv4Address(100, 64, 1, 1)

    // VM identity
    let vmMAC = MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF)
    let vmIP = IPv4Address(100, 64, 1, 50)

    func makeEndpoint(id: Int = 1) -> VMEndpoint {
        VMEndpoint(id: id, fd: Int32(id + 100), subnet: subnet, gateway: gateway, mtu: 1500)
    }

    // MARK: - TCP echo server helper

    /// Start a TCP echo server on localhost, return (fd, port). The server
    /// accepts one connection, echoes all received data, and closes.
    private func startEchoServer() -> (fd: Int32, port: UInt16)? {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { return nil }

        var reuse: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, socklen_t(MemoryLayout<Int32>.size))

        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = 0
        addr.sin_addr.s_addr = INADDR_ANY.bigEndian

        let b = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard b >= 0 else { close(fd); return nil }
        guard Darwin.listen(fd, 1) >= 0 else { close(fd); return nil }

        // Get the assigned port
        var boundAddr = sockaddr_in()
        var len = socklen_t(MemoryLayout<sockaddr_in>.size)
        withUnsafeMutablePointer(to: &boundAddr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                getsockname(fd, $0, &len)
            }
        }
        let port = boundAddr.sin_port

        // Set non-blocking for accept
        let flags = fcntl(fd, F_GETFL, 0)
        if flags >= 0 { _ = fcntl(fd, F_SETFL, flags | O_NONBLOCK) }

        return (fd, port)
    }

    // MARK: - TCP frame builders

    /// Build an Ethernet/IPv4/TCP frame with a valid TCP checksum.
    private func makeTCPFrame(
        srcIP: IPv4Address, dstIP: IPv4Address,
        srcPort: UInt16, dstPort: UInt16,
        seq: UInt32, ack: UInt32,
        flags: TCPFlags, window: UInt16 = 65535,
        payload: [UInt8] = []
    ) -> PacketBuffer {
        let tcpLen = 20 + payload.count
        let ipTotalLen = 20 + tcpLen

        // IPv4 header
        var ipBytes = [UInt8](repeating: 0, count: 20)
        ipBytes[0] = 0x45
        ipBytes[2] = UInt8(ipTotalLen >> 8)
        ipBytes[3] = UInt8(ipTotalLen & 0xFF)
        ipBytes[6] = 0x40; ipBytes[7] = 0x00
        ipBytes[8] = 64
        ipBytes[9] = IPProtocol.tcp.rawValue
        srcIP.write(to: &ipBytes[12])
        dstIP.write(to: &ipBytes[16])
        let ipCksum = ipBytes.withUnsafeBytes { internetChecksum($0) }
        ipBytes[10] = UInt8(ipCksum >> 8)
        ipBytes[11] = UInt8(ipCksum & 0xFF)

        // TCP header
        var tcpBytes = [UInt8](repeating: 0, count: tcpLen)
        tcpBytes[0] = UInt8(srcPort >> 8); tcpBytes[1] = UInt8(srcPort & 0xFF)
        tcpBytes[2] = UInt8(dstPort >> 8); tcpBytes[3] = UInt8(dstPort & 0xFF)
        tcpBytes[4] = UInt8((seq >> 24) & 0xFF)
        tcpBytes[5] = UInt8((seq >> 16) & 0xFF)
        tcpBytes[6] = UInt8((seq >> 8) & 0xFF)
        tcpBytes[7] = UInt8(seq & 0xFF)
        tcpBytes[8] = UInt8((ack >> 24) & 0xFF)
        tcpBytes[9] = UInt8((ack >> 16) & 0xFF)
        tcpBytes[10] = UInt8((ack >> 8) & 0xFF)
        tcpBytes[11] = UInt8(ack & 0xFF)
        tcpBytes[12] = 0x50
        tcpBytes[13] = flags.rawValue
        tcpBytes[14] = UInt8(window >> 8); tcpBytes[15] = UInt8(window & 0xFF)
        // checksum at [16..<18], computed below
        if !payload.isEmpty {
            for i in 0..<payload.count { tcpBytes[20 + i] = payload[i] }
        }

        // TCP checksum over pseudo-header + TCP segment
        let ck = computeTCPChecksum(
            pseudoSrcAddr: srcIP, pseudoDstAddr: dstIP,
            tcpData: &tcpBytes, tcpLen: tcpLen
        )
        tcpBytes[16] = UInt8(ck >> 8)
        tcpBytes[17] = UInt8(ck & 0xFF)

        return makeEthernetFrame(dst: hostMAC, src: vmMAC, type: .ipv4,
                                  payload: ipBytes + tcpBytes)
    }

    private func makeEthernetFrame(dst: MACAddress, src: MACAddress, type: EtherType,
                                     payload: [UInt8]) -> PacketBuffer {
        var bytes: [UInt8] = []
        var buf6 = [UInt8](repeating: 0, count: 6)
        dst.write(to: &buf6); bytes.append(contentsOf: buf6)
        src.write(to: &buf6); bytes.append(contentsOf: buf6)
        let etRaw = type.rawValue
        bytes.append(UInt8(etRaw >> 8))
        bytes.append(UInt8(etRaw & 0xFF))
        bytes.append(contentsOf: payload)
        let s = Storage.allocate(capacity: bytes.count)
        bytes.withUnsafeBytes { s.data.copyMemory(from: $0.baseAddress!, byteCount: bytes.count) }
        return PacketBuffer(storage: s, offset: 0, length: bytes.count)
    }

    /// Extract TCP flags from a reply frame.
    private func extractTCPFlags(from frame: PacketBuffer) -> TCPFlags? {
        guard let eth = EthernetFrame.parse(from: frame),
              let ip = IPv4Header.parse(from: eth.payload),
              let tcp = TCPHeader.parse(from: ip.payload,
                                        pseudoSrcAddr: ip.srcAddr,
                                        pseudoDstAddr: ip.dstAddr)
        else { return nil }
        return tcp.flags
    }

    /// Extract TCP payload from a reply frame.
    private func extractTCPPayload(from frame: PacketBuffer) -> [UInt8]? {
        guard let eth = EthernetFrame.parse(from: frame),
              let ip = IPv4Header.parse(from: eth.payload),
              let tcp = TCPHeader.parse(from: ip.payload,
                                        pseudoSrcAddr: ip.srcAddr,
                                        pseudoDstAddr: ip.dstAddr)
        else { return nil }
        return tcp.payload.withUnsafeReadableBytes { Array($0) }
    }

    // MARK: ── Background echo server thread ──

    /// Result from a background echo server.
    private struct EchoResult {
        let received: [UInt8]
        let eofSeen: Bool
    }

    /// Start a TCP echo server in a background pthread.
    /// Returns the port, stdin fd of a pipe for signaling completion, and the server fd.
    /// When the server finishes, it writes a byte to notify completion.
    private func startThreadedEchoServer() -> (port: UInt16, doneFD: Int32, serverFD: Int32)? {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { return nil }

        var reuse: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, socklen_t(MemoryLayout<Int32>.size))

        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = 0
        addr.sin_addr.s_addr = INADDR_ANY.bigEndian

        let bound = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard bound >= 0 else { close(fd); return nil }
        guard Darwin.listen(fd, 1) >= 0 else { close(fd); return nil }

        var boundAddr = sockaddr_in()
        var len = socklen_t(MemoryLayout<sockaddr_in>.size)
        _ = withUnsafeMutablePointer(to: &boundAddr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &len) }
        }
        let port = boundAddr.sin_port

        // Pipe for signaling completion
        var pipeFDs: [Int32] = [0, 0]
        guard pipe(&pipeFDs) >= 0 else { close(fd); return nil }
        let readFD = pipeFDs[0]
        let writeFD = pipeFDs[1]

        // Raw pointer to hold result
        let resultPtr = UnsafeMutablePointer<EchoResult?>.allocate(capacity: 1)
        resultPtr.initialize(to: nil)

        // Context for pthread
        let ctxPtr = UnsafeMutablePointer<(serverFD: Int32, writeFD: Int32, resultPtr: UnsafeMutablePointer<EchoResult?>)>.allocate(capacity: 1)
        ctxPtr.initialize(to: (fd, writeFD, resultPtr))

        var thread: pthread_t? = nil
        pthread_create(&thread, nil, { raw in
            let ctx = raw.assumingMemoryBound(to: (Int32, Int32, UnsafeMutablePointer<EchoResult?>).self).pointee
            defer { close(ctx.1); close(ctx.0) }

            // Blocking accept
            var clientAddr = sockaddr_in()
            var addrLen = socklen_t(MemoryLayout<sockaddr_in>.size)
            let conn = withUnsafeMutablePointer(to: &clientAddr) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.accept(ctx.0, $0, &addrLen) }
            }
            guard conn >= 0 else {
                var done: UInt8 = 1; write(ctx.1, &done, 1)
                return nil
            }

            // Blocking read
            var buf = [UInt8](repeating: 0, count: 1024)
            let nr = Darwin.read(conn, &buf, buf.count)
            guard nr > 0 else { close(conn); var done: UInt8 = 1; write(ctx.1, &done, 1); return nil }
            let received = Array(buf[0..<nr])

            // Echo back
            _ = Darwin.write(conn, received, received.count)

            // Wait for FIN (read EOF)
            let eof = Darwin.read(conn, &buf, buf.count)
            close(conn)
            ctx.2.pointee = EchoResult(received: received, eofSeen: eof == 0)
            var done: UInt8 = 1; write(ctx.1, &done, 1)
            return nil
        }, ctxPtr)

        return (port, readFD, fd)
    }

    // MARK: - Outbound TCP handshake + data

    @Test func outboundTCPHandshakeWithEchoServer() {
        // Start echo server in background pthread
        guard let server = startThreadedEchoServer() else {
            Issue.record("failed to start echo server")
            return
        }
        defer { close(server.serverFD); close(server.doneFD) }

        let ep = makeEndpoint()
        var arpMapping = ARPMapping(hostMAC: hostMAC, endpoints: [ep])
        var dhcpServer = DHCPServer(endpoints: [ep])
        var registry = SocketRegistry()
        var reasm = IPFragmentReassembler()
        var natTable = NATTable(); var dnsServer = DNSServer(hosts: [:])

        let srcPort: UInt16 = 12345
        let dstIP = IPv4Address(127, 0, 0, 1)

        // ── Round 1: VM sends SYN ──
        let synFrame = makeTCPFrame(
            srcIP: vmIP, dstIP: dstIP,
            srcPort: srcPort, dstPort: server.port,
            seq: 0, ack: 0, flags: .syn
        )

        var transport1: any Transport = InMemoryTransport(inputs: [(endpointID: 1, packet: synFrame)])
        let round1 = RoundContext()
        bdpRound(transport: &transport1, arpMapping: &arpMapping, dhcpServer: &dhcpServer, dnsServer: &dnsServer,
                 routingTable: RoutingTable(), socketRegistry: &registry,
                 ipFragmentReassembler: &reasm, natTable: &natTable, round: round1)

        let round1Out = (transport1 as! InMemoryTransport).outputs
        #expect(round1Out.count >= 1, "expected SYN+ACK reply, got \(round1Out.count)")

        if !round1Out.isEmpty {
            guard let synAckFlags = extractTCPFlags(from: round1Out[0].packet) else {
                Issue.record("failed to parse SYN+ACK reply")
                return
            }
            #expect(synAckFlags.isSynAck, "expected SYN+ACK, got flags=\(synAckFlags.rawValue)")
        }

        // Parse the SYN+ACK to learn the ISN chosen by the NAT
        guard let synAckEth = EthernetFrame.parse(from: round1Out[0].packet),
              let synAckIP = IPv4Header.parse(from: synAckEth.payload),
              let synAckTCP = TCPHeader.parse(from: synAckIP.payload,
                                              pseudoSrcAddr: synAckIP.srcAddr,
                                              pseudoDstAddr: synAckIP.dstAddr)
        else {
            Issue.record("failed to parse SYN+ACK for ISN extraction")
            return
        }
        let natISN = synAckTCP.sequenceNumber

        // Verify transparent proxy: reply srcIP matches original dstIP
        #expect(synAckIP.srcAddr == IPv4Address(127, 0, 0, 1),
                "transparent proxy: reply srcIP should be original dstIP (127.0.0.1)")

        // ── Round 2: VM sends ACK to complete handshake ──
        let ackFrame = makeTCPFrame(
            srcIP: vmIP, dstIP: dstIP,
            srcPort: srcPort, dstPort: server.port,
            seq: 1, ack: natISN &+ 1, flags: .ack
        )

        var transport2: any Transport = InMemoryTransport(inputs: [(endpointID: 1, packet: ackFrame)])
        let round2 = RoundContext()
        bdpRound(transport: &transport2, arpMapping: &arpMapping, dhcpServer: &dhcpServer, dnsServer: &dnsServer,
                 routingTable: RoutingTable(), socketRegistry: &registry,
                 ipFragmentReassembler: &reasm, natTable: &natTable, round: round2)

        #expect(natTable.tcpCount == 1, "NAT should have 1 active TCP entry")

        // ── Round 3: VM sends data ──
        let vmData: [UInt8] = [0x48, 0x65, 0x6C, 0x6C, 0x6F]  // "Hello"
        let dataFrame = makeTCPFrame(
            srcIP: vmIP, dstIP: dstIP,
            srcPort: srcPort, dstPort: server.port,
            seq: 1, ack: natISN &+ 1, flags: [.ack, .psh],
            payload: vmData
        )

        var transport3: any Transport = InMemoryTransport(inputs: [(endpointID: 1, packet: dataFrame)])
        let round3 = RoundContext()
        bdpRound(transport: &transport3, arpMapping: &arpMapping, dhcpServer: &dhcpServer, dnsServer: &dnsServer,
                 routingTable: RoutingTable(), socketRegistry: &registry,
                 ipFragmentReassembler: &reasm, natTable: &natTable, round: round3)

        // ── Let pollSockets pick up the echo ──
        // Run rounds until we get a reply or timeout
        var echoed: [UInt8]? = nil
        for _ in 0..<10 {
            var transport: any Transport = InMemoryTransport(inputs: [])
            let round = RoundContext()
            bdpRound(transport: &transport, arpMapping: &arpMapping, dhcpServer: &dhcpServer, dnsServer: &dnsServer,
                     routingTable: RoutingTable(), socketRegistry: &registry,
                     ipFragmentReassembler: &reasm, natTable: &natTable, round: round)

            let outputs = (transport as! InMemoryTransport).outputs
            for out in outputs {
                if let payload = extractTCPPayload(from: out.packet), !payload.isEmpty {
                    echoed = payload
                    break
                }
            }
            if echoed != nil { break }
            usleep(10000)
        }
        #expect(echoed == vmData, "echoed data should match sent data, got \(String(describing: echoed))")

        // ── Cleanup: VM sends FIN ──
        let finFrame = makeTCPFrame(
            srcIP: vmIP, dstIP: dstIP,
            srcPort: srcPort, dstPort: server.port,
            seq: 1 &+ UInt32(vmData.count), ack: natISN &+ 1 &+ UInt32(vmData.count),
            flags: [.ack, .fin]
        )

        var transport5: any Transport = InMemoryTransport(inputs: [(endpointID: 1, packet: finFrame)])
        let round5 = RoundContext()
        bdpRound(transport: &transport5, arpMapping: &arpMapping, dhcpServer: &dhcpServer, dnsServer: &dnsServer,
                 routingTable: RoutingTable(), socketRegistry: &registry,
                 ipFragmentReassembler: &reasm, natTable: &natTable, round: round5)

        // Echo data may arrive via Phase 11 pollSockets in step 4 or step 5
        let round5Out = (transport5 as! InMemoryTransport).outputs
        if echoed == nil {
            for out in round5Out {
                if let payload = extractTCPPayload(from: out.packet), !payload.isEmpty {
                    echoed = payload
                    break
                }
            }
        }

        // NAT's FIN to VM arrives via pollSockets when the echo server
        // responds to shutdown(SHUT_WR).  The echo server may not finish
        // closing within the same poll cycle, so poll in a loop.
        var natFinSeqPlusOne: UInt32? = nil
        var natFinOutputs: [(endpointID: Int, packet: PacketBuffer)] = []
        for out in round5Out {
            if let flags = extractTCPFlags(from: out.packet), flags.contains(.fin) {
                natFinOutputs.append(out)
                if let eth = EthernetFrame.parse(from: out.packet),
                   let ip = IPv4Header.parse(from: eth.payload),
                   let tcp = TCPHeader.parse(from: ip.payload,
                                             pseudoSrcAddr: ip.srcAddr,
                                             pseudoDstAddr: ip.dstAddr) {
                    natFinSeqPlusOne = tcp.sequenceNumber &+ 1
                }
            }
        }
        if natFinSeqPlusOne == nil {
            for _ in 0..<20 {
                var transport: any Transport = InMemoryTransport(inputs: [])
                let round = RoundContext()
                bdpRound(transport: &transport, arpMapping: &arpMapping, dhcpServer: &dhcpServer, dnsServer: &dnsServer,
                         routingTable: RoutingTable(), socketRegistry: &registry,
                         ipFragmentReassembler: &reasm, natTable: &natTable, round: round)
                let outputs = (transport as! InMemoryTransport).outputs
                for out in outputs {
                    if let flags = extractTCPFlags(from: out.packet), flags.contains(.fin) {
                        natFinOutputs.append(out)
                        if let eth = EthernetFrame.parse(from: out.packet),
                           let ip = IPv4Header.parse(from: eth.payload),
                           let tcp = TCPHeader.parse(from: ip.payload,
                                                     pseudoSrcAddr: ip.srcAddr,
                                                     pseudoDstAddr: ip.dstAddr) {
                            natFinSeqPlusOne = tcp.sequenceNumber &+ 1
                        }
                    }
                }
                if natFinSeqPlusOne != nil { break }
                usleep(10000)
            }
        }

        guard let ackNum = natFinSeqPlusOne else {
            Issue.record("NAT FIN not found in round 5 or subsequent poll outputs")
            return
        }

        // VM ACKs the NAT's FIN (NAT sent FIN in Phase 11 of round 5
        // when it detected the echo server's close).
        let finalAckFrame = makeTCPFrame(
            srcIP: vmIP, dstIP: dstIP,
            srcPort: srcPort, dstPort: server.port,
            seq: 1 &+ UInt32(vmData.count) &+ 1,
            ack: ackNum,
            flags: .ack
        )

        var transport6: any Transport = InMemoryTransport(inputs: [(endpointID: 1, packet: finalAckFrame)])
        let round6 = RoundContext()
        bdpRound(transport: &transport6, arpMapping: &arpMapping, dhcpServer: &dhcpServer, dnsServer: &dnsServer,
                 routingTable: RoutingTable(), socketRegistry: &registry,
                 ipFragmentReassembler: &reasm, natTable: &natTable, round: round6)

        // Run a few more poll rounds to let NAT finish cleanup
        for _ in 0..<5 {
            var transport: any Transport = InMemoryTransport(inputs: [])
            let round = RoundContext()
            bdpRound(transport: &transport, arpMapping: &arpMapping, dhcpServer: &dhcpServer, dnsServer: &dnsServer,
                     routingTable: RoutingTable(), socketRegistry: &registry,
                     ipFragmentReassembler: &reasm, natTable: &natTable, round: round)
            if natTable.tcpCount == 0 { break }
            usleep(10000)
        }

        // After both sides close, the entry should be cleaned up
        #expect(natTable.tcpCount == 0, "TCP entry should be cleaned after both sides close, got \(natTable.tcpCount)")
    }

    // MARK: - UDP NAT

    @Test func udpNATForwardsDatagramToExternal() {
        // Start a UDP echo server on localhost
        let udpFD = socket(AF_INET, SOCK_DGRAM, 0)
        guard udpFD >= 0 else { Issue.record("failed to create UDP socket"); return }
        defer { close(udpFD) }

        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = 0
        addr.sin_addr.s_addr = INADDR_ANY.bigEndian

        let b = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.bind(udpFD, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard b >= 0 else { Issue.record("UDP bind failed"); return }

        var boundAddr = sockaddr_in()
        var len = socklen_t(MemoryLayout<sockaddr_in>.size)
        withUnsafeMutablePointer(to: &boundAddr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                getsockname(udpFD, $0, &len)
            }
        }
        let udpPort = boundAddr.sin_port

        // Set non-blocking
        let flags = fcntl(udpFD, F_GETFL, 0)
        if flags >= 0 { _ = fcntl(udpFD, F_SETFL, flags | O_NONBLOCK) }

        let ep = makeEndpoint()
        var arpMapping = ARPMapping(hostMAC: hostMAC, endpoints: [ep])
        var dhcpServer = DHCPServer(endpoints: [ep])
        var registry = SocketRegistry()
        var reasm = IPFragmentReassembler()
        var natTable = NATTable(); var dnsServer = DNSServer(hosts: [:])

        // Build UDP frame from VM to 127.0.0.1:udpPort (unregistered port → NAT)
        let payload: [UInt8] = [0x70, 0x69, 0x6E, 0x67]  // "ping"
        let frame = makeUDPFrame(
            srcIP: vmIP, dstIP: IPv4Address(127, 0, 0, 1),
            srcPort: 12345, dstPort: udpPort,
            payload: payload
        )

        var transport: any Transport = InMemoryTransport(inputs: [(endpointID: 1, packet: frame)])
        let round = RoundContext()
        bdpRound(transport: &transport, arpMapping: &arpMapping, dhcpServer: &dhcpServer, dnsServer: &dnsServer,
                 routingTable: RoutingTable(), socketRegistry: &registry,
                 ipFragmentReassembler: &reasm, natTable: &natTable, round: round)

        // NAT should have created an entry
        #expect(natTable.udpCount == 1, "NAT should have 1 UDP entry, got \(natTable.udpCount)")

        // Read from the UDP socket to verify forwarding
        var buf = [UInt8](repeating: 0, count: 1024)
        var srcAddr = sockaddr_in()
        var srcLen = socklen_t(MemoryLayout<sockaddr_in>.size)
        let n = withUnsafeMutablePointer(to: &srcAddr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.recvfrom(udpFD, &buf, buf.count, 0, $0, &srcLen)
            }
        }
        #expect(n == payload.count, "UDP server should receive \(payload.count) bytes, got \(n)")
        if n > 0 {
            #expect(Array(buf[0..<n]) == payload)
        }

        // Send response back
        let response: [UInt8] = [0x70, 0x6F, 0x6E, 0x67]  // "pong"
        withUnsafePointer(to: &srcAddr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                _ = Darwin.sendto(udpFD, response, response.count, 0, sa, srcLen)
            }
        }

        // Poll the NAT to receive the response
        var transport2: any Transport = InMemoryTransport(inputs: [])
        let round2 = RoundContext()
        bdpRound(transport: &transport2, arpMapping: &arpMapping, dhcpServer: &dhcpServer, dnsServer: &dnsServer,
                 routingTable: RoutingTable(), socketRegistry: &registry,
                 ipFragmentReassembler: &reasm, natTable: &natTable, round: round2)

        let round2Out = (transport2 as! InMemoryTransport).outputs
        // Should get the response back as a UDP frame to the VM
        if !round2Out.isEmpty {
            guard let eth = EthernetFrame.parse(from: round2Out[0].packet),
                  let ip = IPv4Header.parse(from: eth.payload),
                  let udp = UDPHeader.parse(from: ip.payload,
                                            pseudoSrcAddr: ip.srcAddr,
                                            pseudoDstAddr: ip.dstAddr)
            else { return }
            let echoed = udp.payload.withUnsafeReadableBytes { Array($0) }
            #expect(echoed == response)
        }
    }

    // MARK: - Helpers

    private func makeUDPFrame(
        srcIP: IPv4Address, dstIP: IPv4Address,
        srcPort: UInt16, dstPort: UInt16,
        payload: [UInt8]
    ) -> PacketBuffer {
        let udpLen = 8 + payload.count
        let ipTotalLen = 20 + udpLen

        var ipBytes = [UInt8](repeating: 0, count: 20)
        ipBytes[0] = 0x45
        ipBytes[2] = UInt8(ipTotalLen >> 8)
        ipBytes[3] = UInt8(ipTotalLen & 0xFF)
        ipBytes[6] = 0x40; ipBytes[7] = 0x00
        ipBytes[8] = 64
        ipBytes[9] = IPProtocol.udp.rawValue
        srcIP.write(to: &ipBytes[12])
        dstIP.write(to: &ipBytes[16])
        let ipCksum = ipBytes.withUnsafeBytes { internetChecksum($0) }
        ipBytes[10] = UInt8(ipCksum >> 8)
        ipBytes[11] = UInt8(ipCksum & 0xFF)

        var udpBytes: [UInt8] = []
        udpBytes.append(UInt8(srcPort >> 8))
        udpBytes.append(UInt8(srcPort & 0xFF))
        udpBytes.append(UInt8(dstPort >> 8))
        udpBytes.append(UInt8(dstPort & 0xFF))
        udpBytes.append(UInt8(udpLen >> 8))
        udpBytes.append(UInt8(udpLen & 0xFF))
        udpBytes.append(0); udpBytes.append(0)  // checksum placeholder
        udpBytes.append(contentsOf: payload)

        var ckBuf = [UInt8](repeating: 0, count: 12 + udpLen)
        var ipOut = [UInt8](repeating: 0, count: 4)
        srcIP.write(to: &ipOut); ckBuf[0...3] = ipOut[0...3]
        dstIP.write(to: &ipOut); ckBuf[4...7] = ipOut[0...3]
        ckBuf[9] = IPProtocol.udp.rawValue
        ckBuf[10] = UInt8(udpLen >> 8)
        ckBuf[11] = UInt8(udpLen & 0xFF)
        for i in 0..<udpLen { ckBuf[12 + i] = udpBytes[i] }
        let ck = ckBuf.withUnsafeBytes { internetChecksum($0) }
        let finalCk = ck == 0 ? 0xFFFF : ck
        udpBytes[6] = UInt8(finalCk >> 8)
        udpBytes[7] = UInt8(finalCk & 0xFF)

        return makeEthernetFrameSimple(dst: hostMAC, src: vmMAC, type: .ipv4,
                                        payload: ipBytes + udpBytes)
    }

    // MARK: - TCP client helper (for inbound port forwarding tests)

    /// Context for the background TCP client thread.
    private struct TCPClientCtx {
        let port: UInt16
        let sendData: [UInt8]
        let expectRead: Int
        let readyFD: Int32  // signal "connected + data written"
        let doneFD: Int32   // signal "fully done, ready to clean up"
    }

    /// Start a TCP client in a pthread. The client:
    /// 1. connects to localhost:port
    /// 2. writes `sendData`
    /// 3. writes a byte to readyFD to signal "I'm connected and data is written"
    /// 4. blocks on reading a byte from doneFD (main thread signals when accepted)
    /// 5. closes and exits
    private func startThreadedTCPClientSync(
        port: UInt16,
        sendData: [UInt8]
    ) -> (readyFD: Int32, doneFD: Int32)? {
        var readyFds: [Int32] = [0, 0]
        var doneFds: [Int32] = [0, 0]
        guard pipe(&readyFds) >= 0, pipe(&doneFds) >= 0 else { return nil }

        let ctxPtr = UnsafeMutablePointer<TCPClientCtx>.allocate(capacity: 1)
        ctxPtr.initialize(to: TCPClientCtx(
            port: port, sendData: sendData, expectRead: 0,
            readyFD: readyFds[1], doneFD: doneFds[0]
        ))

        var thread: pthread_t? = nil
        pthread_create(&thread, nil, { raw in
            let ctx = raw.assumingMemoryBound(to: TCPClientCtx.self).pointee
            defer { close(ctx.readyFD); close(ctx.doneFD) }

            let fd = socket(AF_INET, SOCK_STREAM, 0)
            guard fd >= 0 else { return nil }

            var addr = sockaddr_in()
            addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
            addr.sin_family = sa_family_t(AF_INET)
            addr.sin_port = ctx.port
            addr.sin_addr.s_addr = inet_addr("127.0.0.1")

            let connOK = withUnsafePointer(to: &addr) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }
            guard connOK >= 0 else { close(fd); return nil }

            // Write data
            let data = ctx.sendData
            Darwin.write(fd, data, data.count)

            // Signal main thread that we're connected and data is written
            var ready: UInt8 = 1
            write(ctx.readyFD, &ready, 1)

            // Wait for main thread to signal it has accepted the connection
            var done: UInt8 = 0
            read(ctx.doneFD, &done, 1)

            close(fd)
            return nil
        }, ctxPtr)

        return (readyFds[0], doneFds[1])
    }

    // MARK: - Inbound port forwarding

    @Test func inboundTCPPortForwardingFullFlow() {
        let ep = makeEndpoint()
        var arpMapping = ARPMapping(hostMAC: hostMAC, endpoints: [ep])
        var dhcpServer = DHCPServer(endpoints: [ep])
        var registry = SocketRegistry()
        var reasm = IPFragmentReassembler()

        // Create NATTable with a port forward to the VM
        let pf = PortForwardEntry(hostPort: 0, vmIP: vmIP, vmPort: 8080, protocol: .tcp)
        var natTable = NATTable(portForwards: [pf]); var dnsServer = DNSServer(hosts: [:])

        // Register the VM's IP→MAC mapping so lookupVM succeeds
        arpMapping.add(ip: vmIP, mac: vmMAC, endpointID: ep.id)

        // Get the OS-assigned listener port
        guard let hostPort = natTable.tcpListenerPorts.first else {
            Issue.record("failed to get listener port")
            return
        }

        // Start TCP client in background that connects and sends "PING".
        // The client signals "ready" after connect+write, then waits for our signal to close.
        let sendData: [UInt8] = [0x50, 0x49, 0x4E, 0x47]  // "PING"
        guard let client = startThreadedTCPClientSync(port: hostPort, sendData: sendData) else {
            Issue.record("failed to start TCP client")
            return
        }
        defer { close(client.readyFD); close(client.doneFD) }

        // Wait for the client to connect and write data
        var ready: UInt8 = 0
        let nr = Darwin.read(client.readyFD, &ready, 1)
        #expect(nr == 1, "client should signal ready")
        guard nr == 1 else { return }

        // ── Round 1: poll to accept and get SYN ──
        var round1Out: [(endpointID: Int, packet: PacketBuffer)] = []
        let roundCtx = RoundContext()
        natTable.pollSockets(hostMAC: hostMAC, arpMapping: arpMapping, replies: &round1Out, round: roundCtx)
        #expect(round1Out.count >= 1, "expected SYN to VM from NAT, got \(round1Out.count)")
        guard !round1Out.isEmpty else { return }

        guard let synEth = EthernetFrame.parse(from: round1Out[0].packet),
              let synIP = IPv4Header.parse(from: synEth.payload),
              let synTCP = TCPHeader.parse(from: synIP.payload,
                                            pseudoSrcAddr: synIP.srcAddr,
                                            pseudoDstAddr: synIP.dstAddr)
        else {
            Issue.record("failed to parse SYN from NAT")
            return
        }
        #expect(synTCP.flags.isSyn, "expected SYN flag")
        #expect(synIP.dstAddr == vmIP, "SYN should be addressed to VM IP")
        #expect(synTCP.dstPort == 8080, "SYN should target VM port 8080")

        let natISN = synTCP.sequenceNumber

        // ── Round 2: VM responds with SYN+ACK ──
        let synAckFrame = makeTCPFrame(
            srcIP: vmIP, dstIP: synIP.srcAddr,
            srcPort: 8080, dstPort: synTCP.srcPort,
            seq: 5000, ack: natISN &+ 1, flags: [.syn, .ack]
        )

        var transport2: any Transport = InMemoryTransport(inputs: [(endpointID: 1, packet: synAckFrame)])
        let round2 = RoundContext()
        bdpRound(transport: &transport2, arpMapping: &arpMapping, dhcpServer: &dhcpServer, dnsServer: &dnsServer,
                 routingTable: RoutingTable(), socketRegistry: &registry,
                 ipFragmentReassembler: &reasm, natTable: &natTable, round: round2)

        let round2Out = (transport2 as! InMemoryTransport).outputs
        #expect(round2Out.count >= 1, "expected ACK from NAT to complete handshake, got \(round2Out.count)")
        guard !round2Out.isEmpty else { return }

        #expect(natTable.tcpCount == 1, "NAT should have 1 active TCP entry")

        // Data from the client may arrive in round2Out (Phase 11 pollSockets runs
        // inside bdpRound after Phase 10 processTCP), or in a subsequent poll.
        var vmReceivedData: [UInt8]? = nil
        var dataSeq: UInt32 = 0
        for out in round2Out {
            if let payload = extractTCPPayload(from: out.packet), !payload.isEmpty {
                vmReceivedData = payload
                if let eth = EthernetFrame.parse(from: out.packet),
                   let ip = IPv4Header.parse(from: eth.payload),
                   let tcp = TCPHeader.parse(from: ip.payload,
                                             pseudoSrcAddr: ip.srcAddr,
                                             pseudoDstAddr: ip.dstAddr) {
                    dataSeq = tcp.sequenceNumber
                }
                break
            }
        }

        // If data didn't arrive in round2Out (e.g. timing), poll separately
        if vmReceivedData == nil {
            for _ in 0..<20 {
                var replies: [(endpointID: Int, packet: PacketBuffer)] = []
                let roundCtx = RoundContext()
                natTable.pollSockets(hostMAC: hostMAC, arpMapping: arpMapping, replies: &replies, round: roundCtx)
                for out in replies {
                    if let payload = extractTCPPayload(from: out.packet), !payload.isEmpty {
                        vmReceivedData = payload
                        if let eth = EthernetFrame.parse(from: out.packet),
                           let ip = IPv4Header.parse(from: eth.payload),
                           let tcp = TCPHeader.parse(from: ip.payload,
                                                     pseudoSrcAddr: ip.srcAddr,
                                                     pseudoDstAddr: ip.dstAddr) {
                            dataSeq = tcp.sequenceNumber
                        }
                        break
                    }
                }
                if vmReceivedData != nil { break }
                usleep(10000)
            }
        }
        #expect(vmReceivedData == sendData, "VM should receive client's 'PING' data, got \(String(describing: vmReceivedData))")
        guard vmReceivedData != nil else { return }

        // ── Round 3: VM ACKs the data ──
        let dataAckNum = dataSeq &+ UInt32(sendData.count)
        let vmAckFrame = makeTCPFrame(
            srcIP: vmIP, dstIP: synIP.srcAddr,
            srcPort: 8080, dstPort: synTCP.srcPort,
            seq: 5000 &+ 1, ack: dataAckNum, flags: .ack
        )

        var transport4: any Transport = InMemoryTransport(inputs: [(endpointID: 1, packet: vmAckFrame)])
        let round4 = RoundContext()
        bdpRound(transport: &transport4, arpMapping: &arpMapping, dhcpServer: &dhcpServer, dnsServer: &dnsServer,
                 routingTable: RoutingTable(), socketRegistry: &registry,
                 ipFragmentReassembler: &reasm, natTable: &natTable, round: round4)

        // ── Signal client to close ──
        var done: UInt8 = 1
        Darwin.write(client.doneFD, &done, 1)
        usleep(50000)

        // ── Round 4: poll — client closed, should get FIN to VM ──
        var round5Out: [(endpointID: Int, packet: PacketBuffer)] = []
        for _ in 0..<20 {
            var replies: [(endpointID: Int, packet: PacketBuffer)] = []
            let roundCtx = RoundContext()
            natTable.pollSockets(hostMAC: hostMAC, arpMapping: arpMapping, replies: &replies, round: roundCtx)
            let hasFin = replies.contains(where: {
                if let f = extractTCPFlags(from: $0.packet) { return f.contains(.fin) }
                return false
            })
            if hasFin { round5Out = replies; break }
            usleep(10000)
        }
        var sawFin = false
        for out in round5Out {
            if let flags = extractTCPFlags(from: out.packet), flags.contains(.fin) {
                sawFin = true
                break
            }
        }
        #expect(sawFin, "NAT should send FIN to VM after client closes")
        guard sawFin else { return }

        // ── Rounds 5-6: VM ACKs FIN and sends own FIN ──
        if let finFrame = round5Out.first(where: {
            if let f = extractTCPFlags(from: $0.packet) { return f.contains(.fin) }
            return false
        }) {
            guard let finEth = EthernetFrame.parse(from: finFrame.packet),
                  let finIP = IPv4Header.parse(from: finEth.payload),
                  let finTCP = TCPHeader.parse(from: finIP.payload,
                                                pseudoSrcAddr: finIP.srcAddr,
                                                pseudoDstAddr: finIP.dstAddr)
            else { return }

            // VM ACKs the external FIN
            let vmFinAck = makeTCPFrame(
                srcIP: vmIP, dstIP: synIP.srcAddr,
                srcPort: 8080, dstPort: synTCP.srcPort,
                seq: 5001, ack: finTCP.sequenceNumber &+ 1, flags: .ack
            )

            var transport6: any Transport = InMemoryTransport(inputs: [(endpointID: 1, packet: vmFinAck)])
            let round6 = RoundContext()
            bdpRound(transport: &transport6, arpMapping: &arpMapping, dhcpServer: &dhcpServer, dnsServer: &dnsServer,
                     routingTable: RoutingTable(), socketRegistry: &registry,
                     ipFragmentReassembler: &reasm, natTable: &natTable, round: round6)

            // VM sends its own FIN
            let vmFin = makeTCPFrame(
                srcIP: vmIP, dstIP: synIP.srcAddr,
                srcPort: 8080, dstPort: synTCP.srcPort,
                seq: 5001, ack: finTCP.sequenceNumber &+ 1, flags: [.fin, .ack]
            )

            var transport7: any Transport = InMemoryTransport(inputs: [(endpointID: 1, packet: vmFin)])
            let round7 = RoundContext()
            bdpRound(transport: &transport7, arpMapping: &arpMapping, dhcpServer: &dhcpServer, dnsServer: &dnsServer,
                     routingTable: RoutingTable(), socketRegistry: &registry,
                     ipFragmentReassembler: &reasm, natTable: &natTable, round: round7)

            // ── Cleanup poll rounds ──
            for _ in 0..<10 {
                var replies: [(endpointID: Int, packet: PacketBuffer)] = []
                let roundCtx = RoundContext()
                natTable.pollSockets(hostMAC: hostMAC, arpMapping: arpMapping, replies: &replies, round: roundCtx)
                if natTable.tcpCount == 0 { break }
                usleep(10000)
            }
        }

        #expect(natTable.tcpCount == 0, "TCP entry should be cleaned up after close, got \(natTable.tcpCount)")
    }

    // MARK: - EndpointRateState unit tests

    @Test func endpointRateStateTryAcquireSucceeds() {
        var state = EndpointRateState(maxTokens: 100, maxConcurrent: 256, refillRate: 100)
        let now: UInt64 = 1000
        #expect(state.tryAcquire(now: now) == true)
        #expect(state.concurrentCount == 1)
        #expect(state.tokens < 100)  // one token consumed
    }

    @Test func endpointRateStateTokenExhaustion() {
        var state = EndpointRateState(maxTokens: 3, maxConcurrent: 256, refillRate: 100)
        let now: UInt64 = 1000

        // Consume all 3 tokens
        for _ in 0..<3 {
            #expect(state.tryAcquire(now: now) == true)
        }
        // 4th should fail — no tokens left
        #expect(state.tryAcquire(now: now) == false)
        #expect(state.concurrentCount == 3)
    }

    @Test func endpointRateStateTokenRefill() {
        // Use non-zero epoch: lastRefill==0 is the "first call" sentinel in refill()
        var state = EndpointRateState(maxTokens: 10, maxConcurrent: 256, refillRate: 10)  // 10 tokens/sec

        // Consume all tokens at t=1000
        let t0: UInt64 = 1000
        for _ in 0..<10 {
            #expect(state.tryAcquire(now: t0) == true)
        }
        #expect(state.tryAcquire(now: t0) == false)

        // After 1 second, 10 tokens refilled (10 tokens/sec * 1 sec)
        let t1: UInt64 = t0 + 1
        #expect(state.tryAcquire(now: t1) == true, "should refill after 1 second")
    }

    @Test func endpointRateStateConcurrentCap() {
        var state = EndpointRateState(maxTokens: 1000, maxConcurrent: 3, refillRate: 100)
        let now: UInt64 = 1000

        for _ in 0..<3 {
            #expect(state.tryAcquire(now: now) == true)
        }
        // 4th should fail — concurrent limit reached
        #expect(state.tryAcquire(now: now) == false)
        #expect(state.concurrentCount == 3)
    }

    @Test func endpointRateStateReleaseDecrementsCount() {
        var state = EndpointRateState(maxTokens: 100, maxConcurrent: 256, refillRate: 100)
        let now: UInt64 = 1000

        #expect(state.tryAcquire(now: now) == true)
        #expect(state.concurrentCount == 1)
        state.release()
        #expect(state.concurrentCount == 0)
    }

    @Test func endpointRateStateReleaseFloorZero() {
        var state = EndpointRateState(maxTokens: 100, maxConcurrent: 256, refillRate: 100)
        // release without acquire should not go negative
        state.release()
        #expect(state.concurrentCount == 0)
    }

    @Test func endpointRateStateIndependentEndpoints() {
        var ep1 = EndpointRateState(maxTokens: 1, maxConcurrent: 256, refillRate: 100)
        var ep2 = EndpointRateState(maxTokens: 100, maxConcurrent: 256, refillRate: 100)
        let now: UInt64 = 1000

        // Exhaust ep1
        #expect(ep1.tryAcquire(now: now) == true)
        #expect(ep1.tryAcquire(now: now) == false)

        // ep2 still has tokens
        #expect(ep2.tryAcquire(now: now) == true)
    }

    // MARK: - Rate limit integration: multiple connections from same endpoint

    @Test func multipleOutboundConnectionsFromSameEndpoint() {
        // Verify that multiple TCP connections from the same endpoint are
        // established and tracked independently.
        let ep = makeEndpoint()
        var arpMapping = ARPMapping(hostMAC: hostMAC, endpoints: [ep])
        var dhcpServer = DHCPServer(endpoints: [ep])
        var dnsServer = DNSServer(hosts: [:])
        var registry = SocketRegistry()
        var reasm = IPFragmentReassembler()

        // Start two echo servers
        guard let s1 = startEchoServer(), let s2 = startEchoServer() else {
            Issue.record("failed to start echo server")
            return
        }
        defer { close(s1.fd); close(s2.fd) }

        var natTable = NATTable()

        // Round 1: First outbound SYN
        let syn1 = makeTCPFrame(
            srcIP: vmIP, dstIP: IPv4Address(127, 0, 0, 1),
            srcPort: 50001, dstPort: s1.port,
            seq: 1000, ack: 0, flags: .syn
        )
        var transport1: any Transport = InMemoryTransport(inputs: [(endpointID: 1, packet: syn1)])
        let round1 = RoundContext()
        bdpRound(transport: &transport1, arpMapping: &arpMapping, dhcpServer: &dhcpServer, dnsServer: &dnsServer,
                 routingTable: RoutingTable(), socketRegistry: &registry,
                 ipFragmentReassembler: &reasm, natTable: &natTable, round: round1)
        let out1 = (transport1 as! InMemoryTransport).outputs
        #expect(out1.contains { extractTCPFlags(from: $0.packet)?.contains(.syn) == true && extractTCPFlags(from: $0.packet)?.contains(.ack) == true },
                 "first SYN should get SYN+ACK")
        #expect(natTable.tcpCount == 1, "expected 1 TCP entry, got \(natTable.tcpCount)")

        // Round 2: Second outbound SYN (different srcPort, different echo server)
        let syn2 = makeTCPFrame(
            srcIP: vmIP, dstIP: IPv4Address(127, 0, 0, 1),
            srcPort: 50002, dstPort: s2.port,
            seq: 2000, ack: 0, flags: .syn
        )
        var transport2: any Transport = InMemoryTransport(inputs: [(endpointID: 1, packet: syn2)])
        let round2 = RoundContext()
        bdpRound(transport: &transport2, arpMapping: &arpMapping, dhcpServer: &dhcpServer, dnsServer: &dnsServer,
                 routingTable: RoutingTable(), socketRegistry: &registry,
                 ipFragmentReassembler: &reasm, natTable: &natTable, round: round2)
        let out2 = (transport2 as! InMemoryTransport).outputs
        #expect(out2.contains { extractTCPFlags(from: $0.packet)?.contains(.syn) == true && extractTCPFlags(from: $0.packet)?.contains(.ack) == true },
                 "second SYN should get SYN+ACK")
        #expect(natTable.tcpCount == 2, "expected 2 TCP entries, got \(natTable.tcpCount)")
    }

    private func makeEthernetFrameSimple(dst: MACAddress, src: MACAddress, type: EtherType,
                                          payload: [UInt8]) -> PacketBuffer {
        var bytes: [UInt8] = []
        var buf6 = [UInt8](repeating: 0, count: 6)
        dst.write(to: &buf6); bytes.append(contentsOf: buf6)
        src.write(to: &buf6); bytes.append(contentsOf: buf6)
        let etRaw = type.rawValue
        bytes.append(UInt8(etRaw >> 8))
        bytes.append(UInt8(etRaw & 0xFF))
        bytes.append(contentsOf: payload)
        let s = Storage.allocate(capacity: bytes.count)
        bytes.withUnsafeBytes { s.data.copyMemory(from: $0.baseAddress!, byteCount: bytes.count) }
        return PacketBuffer(storage: s, offset: 0, length: bytes.count)
    }
}
