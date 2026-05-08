import Testing
import Darwin
import Foundation
@testable import SwiftNetStack

@Suite(.serialized)
struct TCPStressTests {

    let hostMAC = MACAddress(0x00, 0x11, 0x22, 0x33, 0x44, 0x55)
    let subnet = IPv4Subnet(network: IPv4Address(100, 64, 1, 0), prefixLength: 24)
    let gateway = IPv4Address(100, 64, 1, 1)
    let vmMAC = MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF)
    let vmIP = IPv4Address(100, 64, 1, 50)

    func makeEndpoint(id: Int = 1) -> VMEndpoint {
        VMEndpoint(id: id, fd: Int32(id + 100), subnet: subnet, gateway: gateway, mtu: 1500)
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

    // MARK: - Single connection data transfer

    @Test func tcpSingleConnection1KBTransfer() {
        guard let echo = TCPEchoServer.make() else {
            Issue.record("failed to start echo server"); return
        }

        let ep = makeEndpoint()
        var arpMapping = ARPMapping(hostMAC: hostMAC, endpoints: [ep])
        var dhcpServer = DHCPServer(endpoints: [ep])
        var natTable = NATTable()
        var dnsServer = DNSServer(hosts: [:])
        var registry = SocketRegistry()
        var reasm = IPFragmentReassembler()

        let dstIP = IPv4Address(127, 0, 0, 1)
        let srcPort: UInt16 = 22345

        // Round 1: SYN
        let synFrame = makeTCPFrame(dstMAC: hostMAC, srcMAC: vmMAC,
                                     srcIP: vmIP, dstIP: dstIP,
                                     srcPort: srcPort, dstPort: echo.port,
                                     seq: 0, ack: 0, flags: .syn)
        var t1: any Transport = InMemoryTransport(inputs: [(1, synFrame)])
        bdpRound(transport: &t1, arpMapping: &arpMapping, dhcpServer: &dhcpServer, dnsServer: &dnsServer,
                 socketRegistry: &registry,
                 ipFragmentReassembler: &reasm, natTable: &natTable, round: RoundContext())

        let r1 = (t1 as! InMemoryTransport).outputs
        guard r1.count >= 1,
              let synAckEth = EthernetFrame.parse(from: r1[0].packet),
              let synAckIP = IPv4Header.parse(from: synAckEth.payload),
              let synAckTCP = TCPHeader.parse(from: synAckIP.payload,
                                              pseudoSrcAddr: synAckIP.srcAddr,
                                              pseudoDstAddr: synAckIP.dstAddr)
        else { Issue.record("no SYN+ACK"); return }
        #expect(synAckTCP.flags.isSynAck)
        let natISN = synAckTCP.sequenceNumber

        // Round 2: ACK to complete handshake
        let ackFrame = makeTCPFrame(dstMAC: hostMAC, srcMAC: vmMAC,
                                     srcIP: vmIP, dstIP: dstIP,
                                     srcPort: srcPort, dstPort: echo.port,
                                     seq: 1, ack: natISN &+ 1, flags: .ack)
        var t2: any Transport = InMemoryTransport(inputs: [(1, ackFrame)])
        bdpRound(transport: &t2, arpMapping: &arpMapping, dhcpServer: &dhcpServer, dnsServer: &dnsServer,
                 socketRegistry: &registry,
                 ipFragmentReassembler: &reasm, natTable: &natTable, round: RoundContext())

        // Round 3: Send 1KB data
        let data: [UInt8] = Array(repeating: 0, count: 1024)
        for i in 0..<1024 { _ = i }  // not needed, already zeroed
        let vmData: [UInt8] = (0..<1024).map { UInt8($0 & 0xFF) }
        let dataFrame = makeTCPFrame(dstMAC: hostMAC, srcMAC: vmMAC,
                                      srcIP: vmIP, dstIP: dstIP,
                                      srcPort: srcPort, dstPort: echo.port,
                                      seq: 1, ack: natISN &+ 1, flags: [.ack, .psh],
                                      payload: vmData)
        var t3: any Transport = InMemoryTransport(inputs: [(1, dataFrame)])
        bdpRound(transport: &t3, arpMapping: &arpMapping, dhcpServer: &dhcpServer, dnsServer: &dnsServer,
                 socketRegistry: &registry,
                 ipFragmentReassembler: &reasm, natTable: &natTable, round: RoundContext())

        // Poll for echo reply
        var echoed: [UInt8]? = nil
        for _ in 0..<20 {
            var tp: any Transport = InMemoryTransport(inputs: [])
            bdpRound(transport: &tp, arpMapping: &arpMapping, dhcpServer: &dhcpServer, dnsServer: &dnsServer,
                     socketRegistry: &registry,
                     ipFragmentReassembler: &reasm, natTable: &natTable, round: RoundContext())
            for out in (tp as! InMemoryTransport).outputs {
                if let payload = extractTCPPayload(from: out.packet), !payload.isEmpty {
                    echoed = payload
                }
            }
            if echoed != nil { break }
            Thread.sleep(forTimeInterval: 0.01)
        }
        #expect(echoed == vmData, "echoed data should match sent data (\(vmData.count) bytes), got \(echoed?.count ?? 0) bytes")

        // Cleanup: FIN
        let finFrame = makeTCPFrame(dstMAC: hostMAC, srcMAC: vmMAC,
                                     srcIP: vmIP, dstIP: dstIP,
                                     srcPort: srcPort, dstPort: echo.port,
                                     seq: 1 &+ UInt32(vmData.count),
                                     ack: UInt32(1025),
                                     flags: [.ack, .fin])
        var t4: any Transport = InMemoryTransport(inputs: [(1, finFrame)])
        bdpRound(transport: &t4, arpMapping: &arpMapping, dhcpServer: &dhcpServer, dnsServer: &dnsServer,
                 socketRegistry: &registry,
                 ipFragmentReassembler: &reasm, natTable: &natTable, round: RoundContext())

        echo.waitDone()
    }

    // MARK: - Large transfer

    @Test func tcpSingleConnection64KBTransfer() {
        guard let echo = TCPEchoServer.make() else {
            Issue.record("failed to start echo server"); return
        }

        let ep = makeEndpoint()
        var arpMapping = ARPMapping(hostMAC: hostMAC, endpoints: [ep])
        var dhcpServer = DHCPServer(endpoints: [ep])
        var natTable = NATTable()
        var dnsServer = DNSServer(hosts: [:])
        var registry = SocketRegistry()
        var reasm = IPFragmentReassembler()

        let dstIP = IPv4Address(127, 0, 0, 1)
        let srcPort: UInt16 = 32345

        // Handshake
        let synFrame = makeTCPFrame(dstMAC: hostMAC, srcMAC: vmMAC,
                                     srcIP: vmIP, dstIP: dstIP,
                                     srcPort: srcPort, dstPort: echo.port,
                                     seq: 0, ack: 0, flags: .syn)
        var t1: any Transport = InMemoryTransport(inputs: [(1, synFrame)])
        bdpRound(transport: &t1, arpMapping: &arpMapping, dhcpServer: &dhcpServer, dnsServer: &dnsServer,
                 socketRegistry: &registry,
                 ipFragmentReassembler: &reasm, natTable: &natTable, round: RoundContext())
        guard let natISN = extractISN(from: (t1 as! InMemoryTransport).outputs) else {
            Issue.record("no SYN+ACK"); return
        }

        let ackFrame = makeTCPFrame(dstMAC: hostMAC, srcMAC: vmMAC,
                                     srcIP: vmIP, dstIP: dstIP,
                                     srcPort: srcPort, dstPort: echo.port,
                                     seq: 1, ack: natISN &+ 1, flags: .ack)
        var t2: any Transport = InMemoryTransport(inputs: [(1, ackFrame)])
        bdpRound(transport: &t2, arpMapping: &arpMapping, dhcpServer: &dhcpServer, dnsServer: &dnsServer,
                 socketRegistry: &registry,
                 ipFragmentReassembler: &reasm, natTable: &natTable, round: RoundContext())

        // Send 64KB in 4 chunks of 16KB
        let totalBytes = 65536
        let chunkSize = 16384
        let vmData: [UInt8] = (0..<totalBytes).map { UInt8($0 & 0xFF) }
        var totalEchoed: [UInt8] = []

        for chunkStart in stride(from: 0, to: totalBytes, by: chunkSize) {
            let end = min(chunkStart + chunkSize, totalBytes)
            let chunk = Array(vmData[chunkStart..<end])
            let dataFrame = makeTCPFrame(dstMAC: hostMAC, srcMAC: vmMAC,
                                          srcIP: vmIP, dstIP: dstIP,
                                          srcPort: srcPort, dstPort: echo.port,
                                          seq: 1 &+ UInt32(chunkStart),
                                          ack: natISN &+ 1 &+ UInt32(totalEchoed.count),
                                          flags: [.ack, .psh], payload: chunk)
            var tp: any Transport = InMemoryTransport(inputs: [(1, dataFrame)])
            bdpRound(transport: &tp, arpMapping: &arpMapping, dhcpServer: &dhcpServer, dnsServer: &dnsServer,
                     socketRegistry: &registry,
                     ipFragmentReassembler: &reasm, natTable: &natTable, round: RoundContext())

            // Poll for echo
            for _ in 0..<10 {
                var tp2: any Transport = InMemoryTransport(inputs: [])
                bdpRound(transport: &tp2, arpMapping: &arpMapping, dhcpServer: &dhcpServer, dnsServer: &dnsServer,
                         socketRegistry: &registry,
                         ipFragmentReassembler: &reasm, natTable: &natTable, round: RoundContext())
                for out in (tp2 as! InMemoryTransport).outputs {
                    if let payload = extractTCPPayload(from: out.packet), !payload.isEmpty {
                        totalEchoed.append(contentsOf: payload)
                    }
                }
                if totalEchoed.count >= end { break }
                Thread.sleep(forTimeInterval: 0.01)
            }
        }

        #expect(totalEchoed.count == totalBytes, "echoed \(totalEchoed.count) bytes, expected \(totalBytes)")
        #expect(totalEchoed == vmData)

        // FIN
        let finFrame = makeTCPFrame(dstMAC: hostMAC, srcMAC: vmMAC,
                                     srcIP: vmIP, dstIP: dstIP,
                                     srcPort: srcPort, dstPort: echo.port,
                                     seq: 1 &+ UInt32(totalBytes),
                                     ack: natISN &+ 1 &+ UInt32(totalEchoed.count),
                                     flags: [.ack, .fin])
        var t4: any Transport = InMemoryTransport(inputs: [(1, finFrame)])
        bdpRound(transport: &t4, arpMapping: &arpMapping, dhcpServer: &dhcpServer, dnsServer: &dnsServer,
                 socketRegistry: &registry,
                 ipFragmentReassembler: &reasm, natTable: &natTable, round: RoundContext())

        echo.waitDone(timeout: 10.0)
    }

    // MARK: - Concurrent connections

    @Test func tcpConcurrent4Connections() {
        let ep = makeEndpoint()
        var arpMapping = ARPMapping(hostMAC: hostMAC, endpoints: [ep])
        var dhcpServer = DHCPServer(endpoints: [ep])
        var natTable = NATTable()
        var dnsServer = DNSServer(hosts: [:])
        var registry = SocketRegistry()
        var reasm = IPFragmentReassembler()

        let dstIP = IPv4Address(127, 0, 0, 1)

        struct ConnState {
            let server: TCPEchoServer
            let srcPort: UInt16
            var natISN: UInt32 = 0
            var echoed: [UInt8]? = nil
        }

        var conns: [ConnState] = []
        for i in 0..<4 {
            guard let echo = TCPEchoServer.make() else {
                Issue.record("failed to start echo server \(i)"); return
            }
            conns.append(ConnState(server: echo, srcPort: UInt16(40001 + i)))
        }

        // Phase 1: All SYNs in one round
        var inputs: [(Int, PacketBuffer)] = []
        for conn in conns {
            let syn = makeTCPFrame(dstMAC: hostMAC, srcMAC: vmMAC,
                                    srcIP: vmIP, dstIP: dstIP,
                                    srcPort: conn.srcPort, dstPort: conn.server.port,
                                    seq: 0, ack: 0, flags: .syn)
            inputs.append((1, syn))
        }
        var t1: any Transport = InMemoryTransport(inputs: inputs)
        bdpRound(transport: &t1, arpMapping: &arpMapping, dhcpServer: &dhcpServer, dnsServer: &dnsServer,
                 socketRegistry: &registry,
                 ipFragmentReassembler: &reasm, natTable: &natTable, round: RoundContext())

        let round1Out = (t1 as! InMemoryTransport).outputs
        #expect(round1Out.count == 4, "expected 4 SYN+ACKs, got \(round1Out.count)")

        // Extract ISN for each connection
        for out in round1Out {
            guard let eth = EthernetFrame.parse(from: out.packet),
                  let ip = IPv4Header.parse(from: eth.payload),
                  let tcp = TCPHeader.parse(from: ip.payload,
                                            pseudoSrcAddr: ip.srcAddr,
                                            pseudoDstAddr: ip.dstAddr),
                  tcp.flags.isSynAck
            else { continue }
            let sport = tcp.dstPort
            if let idx = conns.firstIndex(where: { $0.srcPort == sport }) {
                conns[idx].natISN = tcp.sequenceNumber
            }
        }

        // Phase 2: All ACKs (complete handshake, no data yet)
        var round2Inputs: [(Int, PacketBuffer)] = []
        for conn in conns {
            let ack = makeTCPFrame(dstMAC: hostMAC, srcMAC: vmMAC,
                                    srcIP: vmIP, dstIP: dstIP,
                                    srcPort: conn.srcPort, dstPort: conn.server.port,
                                    seq: 1, ack: conn.natISN &+ 1, flags: .ack)
            round2Inputs.append((1, ack))
        }
        var t2: any Transport = InMemoryTransport(inputs: round2Inputs)
        bdpRound(transport: &t2, arpMapping: &arpMapping, dhcpServer: &dhcpServer, dnsServer: &dnsServer,
                 socketRegistry: &registry,
                 ipFragmentReassembler: &reasm, natTable: &natTable, round: RoundContext())

        // Phase 3: All data frames
        var round3Inputs: [(Int, PacketBuffer)] = []
        for conn in conns {
            let data: [UInt8] = [0x41, 0x42, 0x43, 0x44]  // "ABCD"
            let df = makeTCPFrame(dstMAC: hostMAC, srcMAC: vmMAC,
                                   srcIP: vmIP, dstIP: dstIP,
                                   srcPort: conn.srcPort, dstPort: conn.server.port,
                                   seq: 1, ack: conn.natISN &+ 1, flags: [.ack, .psh],
                                   payload: data)
            round3Inputs.append((1, df))
        }
        var t3: any Transport = InMemoryTransport(inputs: round3Inputs)
        bdpRound(transport: &t3, arpMapping: &arpMapping, dhcpServer: &dhcpServer, dnsServer: &dnsServer,
                 socketRegistry: &registry,
                 ipFragmentReassembler: &reasm, natTable: &natTable, round: RoundContext())

        // Verify NAT entries survived the data write (ENOTCONN should buffer, not cleanup)
        #expect(natTable.tcpCount == 4, "entries should survive data write, got \(natTable.tcpCount)")

        // Collect echoed data from the data-writing round's outputs (echo may
        // arrive in the same bdpRound as the write for fast localhost connections)
        // and from subsequent polling rounds.
        func collectEchoes(from outputs: [(endpointID: Int, packet: PacketBuffer)]) {
            for out in outputs {
                if let payload = extractTCPPayload(from: out.packet), !payload.isEmpty {
                    guard let eth = EthernetFrame.parse(from: out.packet),
                          let ip = IPv4Header.parse(from: eth.payload),
                          let tcp = TCPHeader.parse(from: ip.payload,
                                                    pseudoSrcAddr: ip.srcAddr,
                                                    pseudoDstAddr: ip.dstAddr)
                    else { continue }
                    if let idx = conns.firstIndex(where: { $0.srcPort == tcp.dstPort }) {
                        if conns[idx].echoed == nil { conns[idx].echoed = [] }
                        conns[idx].echoed!.append(contentsOf: payload)
                    }
                }
            }
        }
        collectEchoes(from: (t3 as! InMemoryTransport).outputs)

        // Poll for any remaining echoes
        for _ in 0..<30 {
            var tp: any Transport = InMemoryTransport(inputs: [])
            bdpRound(transport: &tp, arpMapping: &arpMapping, dhcpServer: &dhcpServer, dnsServer: &dnsServer,
                     socketRegistry: &registry,
                     ipFragmentReassembler: &reasm, natTable: &natTable, round: RoundContext())
            collectEchoes(from: (tp as! InMemoryTransport).outputs)
            if conns.allSatisfy({ $0.echoed != nil && $0.echoed!.count >= 4 }) { break }
            Thread.sleep(forTimeInterval: 0.01)
        }

        for (i, conn) in conns.enumerated() {
            #expect(conn.echoed == [0x41, 0x42, 0x43, 0x44], "conn \(i) echoed \(String(describing: conn.echoed))")
        }

        // Send FIN on all connections so echo servers exit cleanly
        var finInputs: [(Int, PacketBuffer)] = []
        for conn in conns {
            let fin = makeTCPFrame(dstMAC: hostMAC, srcMAC: vmMAC,
                                    srcIP: vmIP, dstIP: dstIP,
                                    srcPort: conn.srcPort, dstPort: conn.server.port,
                                    seq: 1 &+ 4, ack: conn.natISN &+ 1 &+ 4,
                                    flags: [.ack, .fin])
            finInputs.append((1, fin))
        }
        var tFin: any Transport = InMemoryTransport(inputs: finInputs)
        bdpRound(transport: &tFin, arpMapping: &arpMapping, dhcpServer: &dhcpServer, dnsServer: &dnsServer,
                 socketRegistry: &registry,
                 ipFragmentReassembler: &reasm, natTable: &natTable, round: RoundContext())

        // Let the FIN exchange complete
        for _ in 0..<5 {
            var tp: any Transport = InMemoryTransport(inputs: [])
            bdpRound(transport: &tp, arpMapping: &arpMapping, dhcpServer: &dhcpServer, dnsServer: &dnsServer,
                     socketRegistry: &registry,
                     ipFragmentReassembler: &reasm, natTable: &natTable, round: RoundContext())
            Thread.sleep(forTimeInterval: 0.01)
        }

        for conn in conns { conn.server.waitDone(timeout: 3.0) }

        // Entries may still exist if FULL FIN handshake incomplete (VM ACK to
        // external FIN not sent). NAT lifecycle is verified in rapidOpenCloseCycle.
    }

    // MARK: - Rapid open/close

    /// Cycles through 10 TCP connections: SYN → SYN+ACK → ACK → small data → FIN.
    /// Sends data before FIN so the echo server reads, echoes, then sees EOF,
    /// allowing clean shutdown. Verifies all NAT entries are cleaned up.
    @Test func tcpRapidOpenCloseCycle() {
        let ep = makeEndpoint()
        var arpMapping = ARPMapping(hostMAC: hostMAC, endpoints: [ep])
        var dhcpServer = DHCPServer(endpoints: [ep])
        var natTable = NATTable()
        var dnsServer = DNSServer(hosts: [:])
        var registry = SocketRegistry()
        var reasm = IPFragmentReassembler()

        let dstIP = IPv4Address(127, 0, 0, 1)

        for i in 0..<10 {
            guard let echo = TCPEchoServer.make() else {
                Issue.record("echo server \(i) failed"); return
            }
            let srcPort: UInt16 = UInt16(50000 + i)

            // SYN
            let syn = makeTCPFrame(dstMAC: hostMAC, srcMAC: vmMAC,
                                    srcIP: vmIP, dstIP: dstIP,
                                    srcPort: srcPort, dstPort: echo.port,
                                    seq: 0, ack: 0, flags: .syn)
            var t1: any Transport = InMemoryTransport(inputs: [(1, syn)])
            bdpRound(transport: &t1, arpMapping: &arpMapping, dhcpServer: &dhcpServer, dnsServer: &dnsServer,
                     socketRegistry: &registry,
                     ipFragmentReassembler: &reasm, natTable: &natTable, round: RoundContext())
            guard let isn = extractISN(from: (t1 as! InMemoryTransport).outputs) else { continue }

            // ACK
            let ack = makeTCPFrame(dstMAC: hostMAC, srcMAC: vmMAC,
                                    srcIP: vmIP, dstIP: dstIP,
                                    srcPort: srcPort, dstPort: echo.port,
                                    seq: 1, ack: isn &+ 1, flags: .ack)
            var t2: any Transport = InMemoryTransport(inputs: [(1, ack)])
            bdpRound(transport: &t2, arpMapping: &arpMapping, dhcpServer: &dhcpServer, dnsServer: &dnsServer,
                     socketRegistry: &registry,
                     ipFragmentReassembler: &reasm, natTable: &natTable, round: RoundContext())

            // Small data (so echo server exits its read loop cleanly on EOF)
            let payload: [UInt8] = [0x01]
            let dataFrame = makeTCPFrame(dstMAC: hostMAC, srcMAC: vmMAC,
                                          srcIP: vmIP, dstIP: dstIP,
                                          srcPort: srcPort, dstPort: echo.port,
                                          seq: 1, ack: isn &+ 1,
                                          flags: [.ack, .psh], payload: payload)
            var td: any Transport = InMemoryTransport(inputs: [(1, dataFrame)])
            bdpRound(transport: &td, arpMapping: &arpMapping, dhcpServer: &dhcpServer, dnsServer: &dnsServer,
                     socketRegistry: &registry,
                     ipFragmentReassembler: &reasm, natTable: &natTable, round: RoundContext())

            // FIN
            let fin = makeTCPFrame(dstMAC: hostMAC, srcMAC: vmMAC,
                                    srcIP: vmIP, dstIP: dstIP,
                                    srcPort: srcPort, dstPort: echo.port,
                                    seq: 1 &+ 1, ack: isn &+ 1,
                                    flags: [.ack, .fin])
            var t3: any Transport = InMemoryTransport(inputs: [(1, fin)])
            bdpRound(transport: &t3, arpMapping: &arpMapping, dhcpServer: &dhcpServer, dnsServer: &dnsServer,
                     socketRegistry: &registry,
                     ipFragmentReassembler: &reasm, natTable: &natTable, round: RoundContext())

            echo.waitDone(timeout: 2.0)
        }

        // Let pollSockets clean up the last batch of entries
        for _ in 0..<10 {
            var tp: any Transport = InMemoryTransport(inputs: [])
            bdpRound(transport: &tp, arpMapping: &arpMapping, dhcpServer: &dhcpServer, dnsServer: &dnsServer,
                     socketRegistry: &registry,
                     ipFragmentReassembler: &reasm, natTable: &natTable, round: RoundContext())
            if natTable.tcpCount == 0 { break }
            Thread.sleep(forTimeInterval: 0.01)
        }

        // All connections should be cleaned up
        #expect(natTable.tcpCount == 0, "all TCP entries should be cleaned, got \(natTable.tcpCount)")
    }

    // MARK: - Interleaved data and ACK

    @Test func tcpInterleavedDataAndAck() {
        guard let echo = TCPEchoServer.make() else {
            Issue.record("failed to start echo server"); return
        }

        let ep = makeEndpoint()
        var arpMapping = ARPMapping(hostMAC: hostMAC, endpoints: [ep])
        var dhcpServer = DHCPServer(endpoints: [ep])
        var natTable = NATTable()
        var dnsServer = DNSServer(hosts: [:])
        var registry = SocketRegistry()
        var reasm = IPFragmentReassembler()

        let dstIP = IPv4Address(127, 0, 0, 1)
        let srcPort: UInt16 = 22346

        // SYN
        let syn = makeTCPFrame(dstMAC: hostMAC, srcMAC: vmMAC,
                                srcIP: vmIP, dstIP: dstIP,
                                srcPort: srcPort, dstPort: echo.port,
                                seq: 0, ack: 0, flags: .syn)
        var t0: any Transport = InMemoryTransport(inputs: [(1, syn)])
        bdpRound(transport: &t0, arpMapping: &arpMapping, dhcpServer: &dhcpServer, dnsServer: &dnsServer,
                 socketRegistry: &registry,
                 ipFragmentReassembler: &reasm, natTable: &natTable, round: RoundContext())
        guard let natISN = extractISN(from: (t0 as! InMemoryTransport).outputs) else {
            Issue.record("no SYN+ACK"); return
        }

        // ACK to complete handshake
        let ack = makeTCPFrame(dstMAC: hostMAC, srcMAC: vmMAC,
                                srcIP: vmIP, dstIP: dstIP,
                                srcPort: srcPort, dstPort: echo.port,
                                seq: 1, ack: natISN &+ 1, flags: .ack)
        var ta: any Transport = InMemoryTransport(inputs: [(1, ack)])
        bdpRound(transport: &ta, arpMapping: &arpMapping, dhcpServer: &dhcpServer, dnsServer: &dnsServer,
                 socketRegistry: &registry,
                 ipFragmentReassembler: &reasm, natTable: &natTable, round: RoundContext())

        // Send data chunk, then ACK, then more data, all interleaved
        let chunk1: [UInt8] = [0x01, 0x02, 0x03, 0x04, 0x05]
        let chunk2: [UInt8] = [0x06, 0x07, 0x08, 0x09, 0x0A]
        let pureACK = makeTCPFrame(dstMAC: hostMAC, srcMAC: vmMAC,
                                    srcIP: vmIP, dstIP: dstIP,
                                    srcPort: srcPort, dstPort: echo.port,
                                    seq: 1 &+ UInt32(chunk1.count),
                                    ack: natISN &+ 1,
                                    flags: .ack)

        let data1 = makeTCPFrame(dstMAC: hostMAC, srcMAC: vmMAC,
                                  srcIP: vmIP, dstIP: dstIP,
                                  srcPort: srcPort, dstPort: echo.port,
                                  seq: 1, ack: natISN &+ 1,
                                  flags: [.ack, .psh], payload: chunk1)
        let data2 = makeTCPFrame(dstMAC: hostMAC, srcMAC: vmMAC,
                                  srcIP: vmIP, dstIP: dstIP,
                                  srcPort: srcPort, dstPort: echo.port,
                                  seq: 1 &+ UInt32(chunk1.count),
                                  ack: natISN &+ 1 &+ UInt32(chunk1.count),
                                  flags: [.ack, .psh], payload: chunk2)

        // Submit data1 + pureACK + data2 in one batch
        var tb: any Transport = InMemoryTransport(inputs: [(1, data1), (1, pureACK), (1, data2)])
        bdpRound(transport: &tb, arpMapping: &arpMapping, dhcpServer: &dhcpServer, dnsServer: &dnsServer,
                 socketRegistry: &registry,
                 ipFragmentReassembler: &reasm, natTable: &natTable, round: RoundContext())

        // Echo may arrive in the same round as the write on fast localhost connections
        var echoed: [UInt8] = []
        for out in (tb as! InMemoryTransport).outputs {
            if let payload = extractTCPPayload(from: out.packet), !payload.isEmpty {
                echoed.append(contentsOf: payload)
            }
        }

        // Poll for remaining echoes
        for _ in 0..<20 {
            var tp: any Transport = InMemoryTransport(inputs: [])
            bdpRound(transport: &tp, arpMapping: &arpMapping, dhcpServer: &dhcpServer, dnsServer: &dnsServer,
                     socketRegistry: &registry,
                     ipFragmentReassembler: &reasm, natTable: &natTable, round: RoundContext())
            for out in (tp as! InMemoryTransport).outputs {
                if let payload = extractTCPPayload(from: out.packet), !payload.isEmpty {
                    echoed.append(contentsOf: payload)
                }
            }
            if echoed.count >= chunk1.count + chunk2.count { break }
            Thread.sleep(forTimeInterval: 0.01)
        }
        #expect(echoed == chunk1 + chunk2)

        echo.waitDone()
    }

    // MARK: - TCP chaos: interleave with ARP and ICMP

    @Test func tcpChaosInterleavedWithARPICMP() {
        guard let echo = TCPEchoServer.make() else {
            Issue.record("failed to start echo server"); return
        }

        let ep = makeEndpoint()
        var arpMapping = ARPMapping(hostMAC: hostMAC, endpoints: [ep])
        arpMapping.add(ip: vmIP, mac: vmMAC, endpointID: 1)
        var dhcpServer = DHCPServer(endpoints: [ep])
        var natTable = NATTable()
        var dnsServer = DNSServer(hosts: [:])
        var registry = SocketRegistry()
        var reasm = IPFragmentReassembler()

        let dstIP = IPv4Address(127, 0, 0, 1)
        let srcPort: UInt16 = 22347

        // Round 1: SYN + ARP + ICMP all together
        let syn = makeTCPFrame(dstMAC: hostMAC, srcMAC: vmMAC,
                                srcIP: vmIP, dstIP: dstIP,
                                srcPort: srcPort, dstPort: echo.port,
                                seq: 0, ack: 0, flags: .syn)
        let arpFrame = makeEthernetFrame(
            dst: .broadcast, src: MACAddress(0xCC, 0x00, 0x00, 0x00, 0x00, 0x01), type: .arp,
            payload: makeARPPayload(op: .request,
                                     senderMAC: MACAddress(0xCC, 0x00, 0x00, 0x00, 0x00, 0x01),
                                     senderIP: IPv4Address(100, 64, 1, 99),
                                     targetMAC: .zero, targetIP: gateway))
        let icmpFrame = makeICMPEchoFrame(dstMAC: hostMAC, clientMAC: vmMAC,
                                           clientIP: vmIP, dstIP: gateway, id: 99, seq: 1)

        var t1: any Transport = InMemoryTransport(inputs: [(1, syn), (1, arpFrame), (1, icmpFrame)])
        bdpRound(transport: &t1, arpMapping: &arpMapping, dhcpServer: &dhcpServer, dnsServer: &dnsServer,
                 socketRegistry: &registry,
                 ipFragmentReassembler: &reasm, natTable: &natTable, round: RoundContext())

        let r1 = (t1 as! InMemoryTransport).outputs
        #expect(r1.count == 3, "expected 3 replies (SYN+ACK + ARP reply + ICMP reply), got \(r1.count)")

        guard let natISN = extractISN(from: r1) else {
            Issue.record("no SYN+ACK in mixed round"); return
        }

        // Complete handshake + send data
        let ackFrame = makeTCPFrame(dstMAC: hostMAC, srcMAC: vmMAC,
                                     srcIP: vmIP, dstIP: dstIP,
                                     srcPort: srcPort, dstPort: echo.port,
                                     seq: 1, ack: natISN &+ 1, flags: .ack)
        var t2: any Transport = InMemoryTransport(inputs: [(1, ackFrame)])
        bdpRound(transport: &t2, arpMapping: &arpMapping, dhcpServer: &dhcpServer, dnsServer: &dnsServer,
                 socketRegistry: &registry,
                 ipFragmentReassembler: &reasm, natTable: &natTable, round: RoundContext())

        let vmData: [UInt8] = [0xCA, 0xFE, 0xBA, 0xBE]
        let dataFrame = makeTCPFrame(dstMAC: hostMAC, srcMAC: vmMAC,
                                      srcIP: vmIP, dstIP: dstIP,
                                      srcPort: srcPort, dstPort: echo.port,
                                      seq: 1, ack: natISN &+ 1,
                                      flags: [.ack, .psh], payload: vmData)
        var t3: any Transport = InMemoryTransport(inputs: [(1, dataFrame)])
        bdpRound(transport: &t3, arpMapping: &arpMapping, dhcpServer: &dhcpServer, dnsServer: &dnsServer,
                 socketRegistry: &registry,
                 ipFragmentReassembler: &reasm, natTable: &natTable, round: RoundContext())

        // Poll for echo
        var echoed: [UInt8]? = nil
        for _ in 0..<10 {
            var tp: any Transport = InMemoryTransport(inputs: [])
            bdpRound(transport: &tp, arpMapping: &arpMapping, dhcpServer: &dhcpServer, dnsServer: &dnsServer,
                     socketRegistry: &registry,
                     ipFragmentReassembler: &reasm, natTable: &natTable, round: RoundContext())
            for out in (tp as! InMemoryTransport).outputs {
                if let payload = extractTCPPayload(from: out.packet), !payload.isEmpty {
                    echoed = payload
                }
            }
            if echoed != nil { break }
            Thread.sleep(forTimeInterval: 0.01)
        }
        #expect(echoed == vmData)

        echo.waitDone()
    }

    // MARK: - Throughput benchmark

    @Test func tcpThroughputBenchmark() {
        guard let echo = TCPEchoServer.make() else {
            Issue.record("failed to start echo server"); return
        }

        let ep = makeEndpoint()
        var arpMapping = ARPMapping(hostMAC: hostMAC, endpoints: [ep])
        var dhcpServer = DHCPServer(endpoints: [ep])
        var natTable = NATTable()
        var dnsServer = DNSServer(hosts: [:])
        var registry = SocketRegistry()
        var reasm = IPFragmentReassembler()

        let dstIP = IPv4Address(127, 0, 0, 1)
        let srcPort: UInt16 = 22348

        // Handshake
        let syn = makeTCPFrame(dstMAC: hostMAC, srcMAC: vmMAC,
                                srcIP: vmIP, dstIP: dstIP,
                                srcPort: srcPort, dstPort: echo.port,
                                seq: 0, ack: 0, flags: .syn)
        var ts: any Transport = InMemoryTransport(inputs: [(1, syn)])
        bdpRound(transport: &ts, arpMapping: &arpMapping, dhcpServer: &dhcpServer, dnsServer: &dnsServer,
                 socketRegistry: &registry,
                 ipFragmentReassembler: &reasm, natTable: &natTable, round: RoundContext())
        guard let natISN = extractISN(from: (ts as! InMemoryTransport).outputs) else {
            Issue.record("no SYN+ACK"); return
        }

        let ack = makeTCPFrame(dstMAC: hostMAC, srcMAC: vmMAC,
                                srcIP: vmIP, dstIP: dstIP,
                                srcPort: srcPort, dstPort: echo.port,
                                seq: 1, ack: natISN &+ 1, flags: .ack)
        var ta: any Transport = InMemoryTransport(inputs: [(1, ack)])
        bdpRound(transport: &ta, arpMapping: &arpMapping, dhcpServer: &dhcpServer, dnsServer: &dnsServer,
                 socketRegistry: &registry,
                 ipFragmentReassembler: &reasm, natTable: &natTable, round: RoundContext())

        // Send 256 echo requests of 1KB each
        let totalChunks = 256
        let chunkSize = 1024
        var totalEchoed = 0

        let benchmark = ThroughputBenchmark.measure {
            let chunkStart = totalEchoed
            guard chunkStart < totalChunks * chunkSize else { return (false, 0) }

            let chunk: [UInt8] = (chunkStart..<(chunkStart + chunkSize)).map { UInt8($0 & 0xFF) }
            let dataFrame = makeTCPFrame(dstMAC: hostMAC, srcMAC: vmMAC,
                                          srcIP: vmIP, dstIP: dstIP,
                                          srcPort: srcPort, dstPort: echo.port,
                                          seq: 1 &+ UInt32(chunkStart),
                                          ack: natISN &+ 1 &+ UInt32(chunkStart),
                                          flags: [.ack, .psh], payload: chunk)
            var tp: any Transport = InMemoryTransport(inputs: [(1, dataFrame)])
            bdpRound(transport: &tp, arpMapping: &arpMapping, dhcpServer: &dhcpServer, dnsServer: &dnsServer,
                     socketRegistry: &registry,
                     ipFragmentReassembler: &reasm, natTable: &natTable, round: RoundContext())

            // Poll for echo
            var bytesThisRound = 0
            for _ in 0..<5 {
                var tp2: any Transport = InMemoryTransport(inputs: [])
                bdpRound(transport: &tp2, arpMapping: &arpMapping, dhcpServer: &dhcpServer, dnsServer: &dnsServer,
                         socketRegistry: &registry,
                         ipFragmentReassembler: &reasm, natTable: &natTable, round: RoundContext())
                for out in (tp2 as! InMemoryTransport).outputs {
                    if let payload = extractTCPPayload(from: out.packet), !payload.isEmpty {
                        bytesThisRound += payload.count
                    }
                }
                if bytesThisRound >= chunkSize { break }
            }
            totalEchoed += bytesThisRound
            return (totalEchoed < totalChunks * chunkSize, bytesThisRound)
        }

        #expect(totalEchoed >= chunkSize, "should have echoed at least \(chunkSize) bytes, got \(totalEchoed)")
        // Log throughput for manual review
        print("TCP throughput: \(benchmark.mbps) Mbps over \(benchmark.roundCount) rounds, \(totalEchoed) bytes in \(benchmark.duration)")

        echo.waitDone(timeout: 10.0)
    }

    // MARK: - Helpers

    /// Extract the ISN from the first SYN+ACK reply.
    private func extractISN(from outputs: [(endpointID: Int, packet: PacketBuffer)]) -> UInt32? {
        for out in outputs {
            guard let eth = EthernetFrame.parse(from: out.packet),
                  let ip = IPv4Header.parse(from: eth.payload),
                  let tcp = TCPHeader.parse(from: ip.payload,
                                            pseudoSrcAddr: ip.srcAddr,
                                            pseudoDstAddr: ip.dstAddr),
                  tcp.flags.isSynAck
            else { continue }
            return tcp.sequenceNumber
        }
        return nil
    }
}
