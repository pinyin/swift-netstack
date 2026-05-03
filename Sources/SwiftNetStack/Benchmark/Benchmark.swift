import Foundation
import Darwin

// MARK: - Public benchmark entry point

public final class BenchRunner {
    public static func run() {
        guard let (stackConn, testConn) = VZDebugConn.newLoopbackPair() else {
            fputs("FATAL: socketpair failed\n", stderr)
            exit(1)
        }

        var cfg = StackConfig.defaultConfig()
        cfg.socketPath = ""
        cfg.debug = false

        let benchPort: UInt16 = 9090
        var tcpCfg = TCPConfig.defaultConfig()
        tcpCfg.listenPort = benchPort
        let tcpState = TCPState(cfg: tcpCfg)
        tcpState.listen { _ in }

        let stack = Stack(cfg: cfg, tcpState: tcpState)
        stack.setConn(stackConn)

        let runningFlag = BenchRunningFlag()
        let queue = DispatchQueue(label: "bench.deliberation", qos: .userInitiated)
        queue.async {
            while runningFlag.value {
                stack.deliberate(now: Date())
                Thread.sleep(forTimeInterval: 0.001)
            }
        }

        Thread.sleep(forTimeInterval: 0.01)

        let runner = InternalBenchRunner(connB: testConn)
        runner.runBenchmarks()

        runningFlag.value = false
        Thread.sleep(forTimeInterval: 0.1)
    }
}

// MARK: - Internal running flag

final class BenchRunningFlag: @unchecked Sendable {
    var value: Bool = true
}

// MARK: - Internal benchmark logic (has access to all internal types)

final class InternalBenchRunner {
    let connB: VZDebugConn
    let vmMAC = Data([0x02, 0x00, 0x00, 0x00, 0x00, 0x01])
    let gwMAC = Data([0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xee])
    let gwIP = ipToUInt32("192.168.65.1")
    let vmIP = ipToUInt32("192.168.65.2")
    let benchPort: UInt16 = 9090

    init(connB: VZDebugConn) {
        self.connB = connB
    }

    func runBenchmarks() {
        print("")
        print("========== swift-netstack benchmarks ==========")
        print("")

        // Warmup
        _ = handshake(srcPort: 60001)
        _ = handshake(srcPort: 60002)
        drain()

        benchTCPStream()
        benchTCPCRR()
        benchTCPRR()
        benchBurst()
        benchMaxConn()

        print("")
        print("========== end ==========")
        print("")
    }

    // MARK: - Helpers

    func sleepDL(_ seconds: Double = 0.01) {
        Thread.sleep(forTimeInterval: seconds)
    }

    func readFrames(timeout: Double = 0.1) -> [Frame] {
        let deadline = Date().addingTimeInterval(timeout)
        var frames: [Frame] = []
        while Date() < deadline {
            let batch = connB.readAllFrames()
            frames.append(contentsOf: batch)
            if !batch.isEmpty {
                Thread.sleep(forTimeInterval: 0.003)
            } else {
                Thread.sleep(forTimeInterval: 0.001)
            }
        }
        return frames
    }

    func inject(srcPort: UInt16, seq: UInt32, ack: UInt32, flags: UInt8,
                window: UInt16 = 65535, wscale: UInt8 = 0, payload: [UInt8] = []) {
        let tuple = Tuple(srcIP: vmIP, dstIP: gwIP, srcPort: srcPort, dstPort: benchPort)
        var raw = buildSegment(tuple: tuple, seq: seq, ack: ack, flags: flags,
                               window: window, wscale: wscale, payload: payload)
        let cs = tcpChecksum(srcIP: vmIP, dstIP: gwIP, tcpData: raw)
        raw[16] = UInt8(cs >> 8); raw[17] = UInt8(cs & 0xFF)
        let id = UInt16((srcPort & 0xFF00) | (benchPort & 0xFF))
        let ipPkt = IPv4Packet(version: 4, ihl: 20, tos: 0, totalLen: 0, id: id,
                               flags: 0, fragOffset: 0, ttl: 64, protocol: protocolTCP,
                               checksum: 0, srcIP: vmIP, dstIP: gwIP, payload: raw)
        _ = connB.write(frame: Frame(dstMAC: gwMAC, srcMAC: vmMAC,
                                      etherType: etherTypeIPv4, payload: Data(ipPkt.serialize())))
    }

    func handshake(srcPort: UInt16, startSeq: UInt32 = 1000) -> (seq: UInt32, ack: UInt32)? {
        inject(srcPort: srcPort, seq: startSeq, ack: 0, flags: TCPFlag.syn)
        sleepDL(0.03)

        let frames = readFrames(timeout: 0.05)
        guard let saFrame = frames.first(where: { $0.etherType == etherTypeIPv4 }),
              let saIP = IPv4Packet.parse([UInt8](saFrame.payload)),
              saIP.protocol == protocolTCP,
              let saHdr = TCPHeader.parse(saIP.payload) else { return nil }

        let ackSeq = saHdr.ackNum
        inject(srcPort: srcPort, seq: ackSeq, ack: saHdr.seqNum + 1, flags: TCPFlag.ack)
        sleepDL(0.03)
        return (seq: ackSeq, ack: saHdr.seqNum + 1)
    }

    func teardown(srcPort: UInt16, seq: UInt32, ack: UInt32) {
        inject(srcPort: srcPort, seq: seq, ack: ack, flags: TCPFlag.rst)
    }

    func drain() {
        sleepDL(0.03)
        _ = readFrames(timeout: 0.02)
    }

    // MARK: - TCP_STREAM

    func benchTCPStream() {
        let srcPort: UInt16 = 50001
        let segSize = 1400
        let segCount = 500
        let batchSize = 25  // Pace injection to avoid socketpair ENOBUFS

        guard let state = handshake(srcPort: srcPort) else {
            print("TCP_STREAM: handshake failed")
            return
        }

        let payload = [UInt8](repeating: 0x41, count: segSize)
        let start = CFAbsoluteTimeGetCurrent()
        var nextSeq = state.seq
        var sent = 0
        while sent < segCount {
            let end = min(sent + batchSize, segCount)
            for _ in sent..<end {
                inject(srcPort: srcPort, seq: nextSeq, ack: state.ack,
                       flags: TCPFlag.ack | TCPFlag.psh, payload: payload)
                nextSeq += UInt32(segSize)
            }
            sent = end
            // Let deliberation process the batch AND drain response frames
            // to prevent ENOBUFS on the output side
            sleepDL(0.008)
            _ = readFrames(timeout: 0.005)
        }
        // Final drain
        sleepDL(0.05)
        _ = readFrames(timeout: 0.05)
        let elapsed = CFAbsoluteTimeGetCurrent() - start

        let totalBytes = segCount * segSize
        let throughputMbps = Double(totalBytes * 8) / (elapsed * 1_000_000)

        teardown(srcPort: srcPort, seq: nextSeq, ack: state.ack)
        drain()

        print("=== benchmark: TCP_STREAM ===")
        print("segments: \(segCount)")
        print("segment_bytes: \(segSize)")
        print("total_bytes: \(totalBytes)")
        print("duration_ms: \(String(format: "%.1f", elapsed * 1000))")
        print("throughput_mbps: \(String(format: "%.1f", throughputMbps))")
        print("=== end ===")
        print("")
    }

    // MARK: - TCP_CRR

    func benchTCPCRR() {
        let count = 50

        let start = CFAbsoluteTimeGetCurrent()
        var completed = 0
        for i in 0..<count {
            let srcPort = UInt16(51000 + i)
            guard let state = handshake(srcPort: srcPort,
                                         startSeq: UInt32(2000 + i * 100)) else { continue }
            completed += 1
            teardown(srcPort: srcPort, seq: state.seq, ack: state.ack)
            // Drain responses to prevent ENOBUFS
            if i % 5 == 4 { sleepDL(0.01); _ = readFrames(timeout: 0.01) }
        }
        drain()
        let elapsed = CFAbsoluteTimeGetCurrent() - start

        print("=== benchmark: TCP_CRR ===")
        print("connections: \(completed)")
        print("duration_ms: \(String(format: "%.1f", elapsed * 1000))")
        print("conn_per_sec: \(String(format: "%.1f", Double(completed) / elapsed))")
        print("=== end ===")
        print("")
    }

    // MARK: - TCP_RR

    func benchTCPRR() {
        let srcPort: UInt16 = 52001
        let count = 200
        let batchSize = 20

        guard let state = handshake(srcPort: srcPort) else {
            print("TCP_RR: handshake failed")
            return
        }

        let payload = [UInt8](repeating: 0x42, count: 64)
        let start = CFAbsoluteTimeGetCurrent()
        var nextSeq = state.seq
        var sent = 0
        while sent < count {
            let end = min(sent + batchSize, count)
            for _ in sent..<end {
                inject(srcPort: srcPort, seq: nextSeq, ack: state.ack,
                       flags: TCPFlag.ack | TCPFlag.psh, payload: payload)
                nextSeq += UInt32(payload.count)
            }
            sent = end
            sleepDL(0.008)
            _ = readFrames(timeout: 0.005)
        }
        sleepDL(0.05)
        _ = readFrames(timeout: 0.05)
        let elapsed = CFAbsoluteTimeGetCurrent() - start

        teardown(srcPort: srcPort, seq: nextSeq, ack: state.ack)
        drain()

        print("=== benchmark: TCP_RR ===")
        print("transactions: \(count)")
        print("duration_ms: \(String(format: "%.1f", elapsed * 1000))")
        print("tx_per_sec: \(String(format: "%.1f", Double(count) / elapsed))")
        print("=== end ===")
        print("")
    }

    // MARK: - BURST

    func benchBurst() {
        let srcPort: UInt16 = 53001
        let burstSize = 30
        let segBytes = 1024

        guard let state = handshake(srcPort: srcPort) else {
            print("BURST: handshake failed")
            return
        }

        var nextSeq = state.seq
        for i in 0..<burstSize {
            let payload = [UInt8](repeating: UInt8(i & 0xFF), count: segBytes)
            inject(srcPort: srcPort, seq: nextSeq, ack: state.ack,
                   flags: TCPFlag.ack | TCPFlag.psh, payload: payload)
            nextSeq += UInt32(payload.count)
            // Drain every 10 to avoid ENOBUFS while still creating a burst
            if i % 10 == 9 { sleepDL(0.005); _ = readFrames(timeout: 0.005) }
        }

        let start = CFAbsoluteTimeGetCurrent()
        var tickCount = 0
        let deadline = Date().addingTimeInterval(0.5)
        while Date() < deadline {
            let frames = readFrames(timeout: 0.008)
            tickCount += 1
            if frames.isEmpty && tickCount > 2 { break }
        }
        let elapsed = CFAbsoluteTimeGetCurrent() - start

        teardown(srcPort: srcPort, seq: nextSeq, ack: state.ack)
        drain()

        print("=== benchmark: BURST ===")
        print("burst_segments: \(burstSize)")
        print("segment_bytes: \(segBytes)")
        print("total_bytes: \(burstSize * segBytes)")
        print("drain_ticks: \(tickCount)")
        print("drain_ms: \(String(format: "%.1f", elapsed * 1000))")
        print("avg_tick_us: \(String(format: "%.0f", elapsed * 1_000_000 / Double(max(tickCount, 1))))")
        print("=== end ===")
        print("")
    }

    // MARK: - MAX_CONN

    func benchMaxConn() {
        let maxAttempt = 100
        var established: [(UInt16, UInt32, UInt32)] = []

        let start = CFAbsoluteTimeGetCurrent()
        for i in 0..<maxAttempt {
            let srcPort = UInt16(54000 + i)
            if let state = handshake(srcPort: srcPort,
                                      startSeq: UInt32(3000 + i * 100)) {
                established.append((srcPort, state.seq, state.ack))
            }
            if i % 20 == 19 { sleepDL(0.03) }
        }
        sleepDL(0.2)
        let elapsed = CFAbsoluteTimeGetCurrent() - start

        for (srcPort, seq, ack) in established {
            teardown(srcPort: srcPort, seq: seq, ack: ack)
        }
        drain()

        print("=== benchmark: MAX_CONN ===")
        print("attempted: \(maxAttempt)")
        print("established: \(established.count)")
        print("duration_ms: \(String(format: "%.1f", elapsed * 1000))")
        print("conn_per_sec: \(String(format: "%.1f", Double(established.count) / elapsed))")
        print("=== end ===")
        print("")
    }
}
