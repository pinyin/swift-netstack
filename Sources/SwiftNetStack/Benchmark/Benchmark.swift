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
        tcpCfg.bufferSize = 4 * 1024 * 1024  // 4MB buffers to measure true throughput
        let tcpState = TCPState(cfg: tcpCfg)
        tcpState.listen { _ in }

        let stack = Stack(cfg: cfg, tcpState: tcpState)
        stack.setConn(stackConn)

        let runningFlag = BenchRunningFlag()
        let queue = DispatchQueue(label: "bench.deliberation", qos: .userInitiated)
        queue.async {
            while runningFlag.value {
                stack.deliberate(now: Date())
                // Event-driven: if more data is already available, loop immediately.
                // Otherwise block until data arrives or BPT expires (1ms).
                if let conn = stack.conn, conn.waitForData(timeout: 0) {
                    continue
                }
                _ = stack.conn?.waitForData(timeout: 0.001)
            }
        }

        Thread.sleep(forTimeInterval: 0.01)

        let runner = InternalBenchRunner(connB: testConn, stack: stack)
        runner.runBenchmarks()

        // Diagnostic output
        let avgFramesPerRound = stack.diagRoundCount > 0
            ? Double(stack.diagFrameCount) / Double(stack.diagRoundCount) : 0
        let avgRoundUs = stack.diagRoundCount > 0
            ? Double(stack.diagTotalDeliberateUs) / Double(stack.diagRoundCount) : 0
        let avgFrameUs = stack.diagRoundCount > 0
            ? Double(stack.diagTotalProcessFrameUs) / Double(stack.diagRoundCount) : 0
        print("=== diagnostics ===")
        print("deliberation_rounds: \(stack.diagRoundCount)")
        print("total_frames: \(stack.diagFrameCount)")
        print("max_frames_per_round: \(stack.diagMaxFramesPerRound)")
        print(String(format: "avg_frames_per_round: %.1f", avgFramesPerRound))
        print(String(format: "avg_deliberate_us: %.1f", avgRoundUs))
        print(String(format: "avg_process_frame_us: %.1f", avgFrameUs))
        print("=== end diagnostics ===")

        runningFlag.value = false
        Thread.sleep(forTimeInterval: 0.1)
    }
}

// MARK: - Internal running flag

final class BenchRunningFlag: @unchecked Sendable {
    var value: Bool = true
}

// MARK: - Internal benchmark logic

final class InternalBenchRunner {
    let connB: VZDebugConn
    let stack: Stack
    let vmMAC = Data([0x02, 0x00, 0x00, 0x00, 0x00, 0x01])
    let gwMAC = Data([0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xee])
    let gwIP = ipToUInt32("192.168.65.1")
    let vmIP = ipToUInt32("192.168.65.2")
    let benchPort: UInt16 = 9090

    init(connB: VZDebugConn, stack: Stack) {
        self.connB = connB
        self.stack = stack
    }

    func runBenchmarks() {
        print("")
        print("========== swift-netstack benchmarks ==========")
        print("")

        // Warmup
        _ = handshake(srcPort: 60001)
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

    func drain() {
        var drained = 0
        let deadline = Date().addingTimeInterval(0.5)
        while Date() < deadline {
            let frames = connB.readAllFrames()
            if frames.isEmpty && drained > 0 { break }
            drained += frames.count
            if !frames.isEmpty { continue }
            Thread.sleep(forTimeInterval: 0.001)
        }
    }

    /// Read all available frames, return the maximum ACK number seen in TCP segments
    func readFramesAndMaxAck() -> [Frame] {
        return connB.readAllFrames()
    }

    func inject(srcPort: UInt16, seq: UInt32, ack: UInt32, flags: UInt8,
                window: UInt16 = 65535, wscale: UInt8 = 0, payload: [UInt8] = []) -> Bool {
        let tuple = Tuple(srcIP: vmIP, dstIP: gwIP, srcPort: srcPort, dstPort: benchPort)
        var raw = buildSegment(tuple: tuple, seq: seq, ack: ack, flags: flags,
                               window: window, wscale: wscale, payload: payload)
        let cs = tcpChecksum(srcIP: vmIP, dstIP: gwIP, tcpData: raw)
        raw[16] = UInt8(cs >> 8); raw[17] = UInt8(cs & 0xFF)
        let id = UInt16((srcPort & 0xFF00) | (benchPort & 0xFF))
        let ipPkt = IPv4Packet(version: 4, ihl: 20, tos: 0, totalLen: 0, id: id,
                               flags: 0, fragOffset: 0, ttl: 64, protocol: protocolTCP,
                               checksum: 0, srcIP: vmIP, dstIP: gwIP, payload: Data(raw))
        if let err = connB.write(frame: Frame(dstMAC: gwMAC, srcMAC: vmMAC,
                                               etherType: etherTypeIPv4, payload: Data(ipPkt.serialize()))) {
            let nsErr = err as NSError
            if nsErr.domain == NSPOSIXErrorDomain && nsErr.code == Int(ENOBUFS) {
                return false
            }
        }
        return true
    }

    func handshake(srcPort: UInt16, startSeq: UInt32 = 1000) -> (seq: UInt32, ack: UInt32)? {
        _ = inject(srcPort: srcPort, seq: startSeq, ack: 0, flags: TCPFlag.syn)
        let deadline = Date().addingTimeInterval(0.5)
        var synAckFrame: Frame?
        while Date() < deadline {
            let frames = connB.readAllFrames()
            for f in frames {
                if f.etherType == etherTypeIPv4,
                   let ip = IPv4Packet.parse([UInt8](f.payload)),
                   ip.protocol == protocolTCP,
                   let hdr = TCPHeader.parse(ip.payload),
                   hdr.isSYN() && hdr.isACK() {
                    synAckFrame = f
                    break
                }
            }
            if synAckFrame != nil { break }
            Thread.sleep(forTimeInterval: 0.002)
        }

        guard let saFrame = synAckFrame,
              let saIP = IPv4Packet.parse([UInt8](saFrame.payload)),
              let saHdr = TCPHeader.parse(saIP.payload) else { return nil }

        let ackSeq = saHdr.ackNum
        _ = inject(srcPort: srcPort, seq: ackSeq, ack: saHdr.seqNum + 1, flags: TCPFlag.ack)
        return (seq: ackSeq, ack: saHdr.seqNum + 1)
    }

    func teardown(srcPort: UInt16, seq: UInt32, ack: UInt32) {
        _ = inject(srcPort: srcPort, seq: seq, ack: ack, flags: TCPFlag.rst)
    }

    /// Extract the max ACK number from response frames for a given srcPort.
    func maxAckFromFrames(_ frames: [Frame], srcPort: UInt16) -> UInt32 {
        var maxAck: UInt32 = 0
        for f in frames {
            guard f.etherType == etherTypeIPv4,
                  let ip = IPv4Packet.parse([UInt8](f.payload)),
                  ip.protocol == protocolTCP,
                  let hdr = TCPHeader.parse(ip.payload),
                  hdr.dstPort == srcPort else { continue }
            if hdr.isACK() && hdr.ackNum > maxAck {
                maxAck = hdr.ackNum
            }
        }
        return maxAck
    }

    // MARK: - TCP_STREAM

    func benchTCPStream() {
        let srcPort: UInt16 = 50001
        let segSize = 1400
        let segCount = 2000

        guard let state = handshake(srcPort: srcPort) else {
            print("TCP_STREAM: handshake failed")
            return
        }

        let payload = [UInt8](repeating: 0x41, count: segSize)

        // Full-speed injection: write all segments without artificial sleeps.
        // Track max ACK continuously to avoid discarding ACKs mid-drain.
        let start = CFAbsoluteTimeGetCurrent()
        var nextSeq = state.seq
        var enobufs = 0
        var maxAck: UInt32 = 0

        for i in 0..<segCount {
            while !inject(srcPort: srcPort, seq: nextSeq, ack: state.ack,
                          flags: TCPFlag.ack | TCPFlag.psh, payload: payload) {
                enobufs += 1
                // Drain ACKs to free output buffer space, tracking max ACK seen
                let drained = connB.readAllFrames()
                let ack = maxAckFromFrames(drained, srcPort: srcPort)
                if ack > maxAck { maxAck = ack }
            }
            nextSeq += UInt32(segSize)

            // Drain responses every 50 segments, tracking ACKs
            if i % 50 == 49 {
                let drained = connB.readAllFrames()
                let ack = maxAckFromFrames(drained, srcPort: srcPort)
                if ack > maxAck { maxAck = ack }
            }
        }
        let injectEnd = CFAbsoluteTimeGetCurrent()

        // Full drain: wait for remaining ACKs
        let drainDeadline = Date().addingTimeInterval(2.0)
        var idleCount = 0
        while Date() < drainDeadline {
            let batch = connB.readAllFrames()
            let ack = maxAckFromFrames(batch, srcPort: srcPort)
            if ack > maxAck { maxAck = ack }
            if batch.isEmpty {
                idleCount += 1
                if idleCount > 20 { break }
                Thread.sleep(forTimeInterval: 0.005)
            } else {
                idleCount = 0
            }
        }
        let elapsed = CFAbsoluteTimeGetCurrent() - start
        let injectTime = injectEnd - start

        let processedBytes = Int(maxAck) - Int(state.seq)
        let throughputMbps = processedBytes > 0
            ? Double(processedBytes * 8) / (elapsed * 1_000_000)
            : 0.0

        teardown(srcPort: srcPort, seq: nextSeq, ack: state.ack)
        drain()

        print("=== benchmark: TCP_STREAM ===")
        print("segments_injected: \(segCount)")
        print("segment_bytes: \(segSize)")
        print("total_injected_bytes: \(segCount * segSize)")
        print("processed_bytes: \(processedBytes)")
        print("inject_time_ms: \(String(format: "%.1f", injectTime * 1000))")
        print("total_time_ms: \(String(format: "%.1f", elapsed * 1000))")
        print("throughput_mbps: \(String(format: "%.1f", throughputMbps))")
        print("enobufs: \(enobufs)")
        print("=== end ===")
        print("")
    }

    // MARK: - TCP_CRR

    func benchTCPCRR() {
        let count = 100

        let start = CFAbsoluteTimeGetCurrent()
        var completed = 0
        for i in 0..<count {
            let srcPort = UInt16(51000 + i)
            guard let state = handshake(srcPort: srcPort,
                                         startSeq: UInt32(2000 + i * 100)) else { continue }
            completed += 1
            teardown(srcPort: srcPort, seq: state.seq, ack: state.ack)
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
        let count = 500
        let payloadSize = 64

        guard let state = handshake(srcPort: srcPort) else {
            print("TCP_RR: handshake failed")
            return
        }

        let payload = [UInt8](repeating: 0x42, count: payloadSize)

        let start = CFAbsoluteTimeGetCurrent()
        var nextSeq = state.seq
        var enobufs = 0
        var maxAck: UInt32 = 0
        for i in 0..<count {
            while !inject(srcPort: srcPort, seq: nextSeq, ack: state.ack,
                          flags: TCPFlag.ack | TCPFlag.psh, payload: payload) {
                enobufs += 1
                let drained = connB.readAllFrames()
                let ack = maxAckFromFrames(drained, srcPort: srcPort)
                if ack > maxAck { maxAck = ack }
            }
            nextSeq += UInt32(payloadSize)
            if i % 100 == 99 {
                let drained = connB.readAllFrames()
                let ack = maxAckFromFrames(drained, srcPort: srcPort)
                if ack > maxAck { maxAck = ack }
            }
        }

        let drainDeadline = Date().addingTimeInterval(1.0)
        var idle = 0
        while Date() < drainDeadline {
            let batch = connB.readAllFrames()
            let ack = maxAckFromFrames(batch, srcPort: srcPort)
            if ack > maxAck { maxAck = ack }
            if batch.isEmpty { idle += 1; if idle > 20 { break } }
            else { idle = 0 }
            Thread.sleep(forTimeInterval: 0.005)
        }
        let elapsed = CFAbsoluteTimeGetCurrent() - start

        let processedBytes = Int(maxAck) - Int(state.seq)
        let throughputMbps = processedBytes > 0
            ? Double(processedBytes * 8) / (elapsed * 1_000_000)
            : 0.0

        teardown(srcPort: srcPort, seq: nextSeq, ack: state.ack)
        drain()

        print("=== benchmark: TCP_RR ===")
        print("transactions: \(count)")
        print("payload_bytes: \(payloadSize)")
        print("total_injected_bytes: \(count * payloadSize)")
        print("processed_bytes: \(processedBytes)")
        print("duration_ms: \(String(format: "%.1f", elapsed * 1000))")
        print("tx_per_sec: \(String(format: "%.1f", Double(count) / elapsed))")
        print("throughput_mbps: \(String(format: "%.1f", throughputMbps))")
        print("enobufs: \(enobufs)")
        print("=== end ===")
        print("")
    }

    // MARK: - BURST

    func benchBurst() {
        let srcPort: UInt16 = 53001
        let burstSize = 200
        let segBytes = 1024

        guard let state = handshake(srcPort: srcPort) else {
            print("BURST: handshake failed")
            return
        }

        // Inject all segments in one burst — no intermediate drains
        var nextSeq = state.seq
        var enobufs = 0
        var maxAck: UInt32 = 0
        for i in 0..<burstSize {
            let payload = [UInt8](repeating: UInt8(i & 0xFF), count: segBytes)
            while !inject(srcPort: srcPort, seq: nextSeq, ack: state.ack,
                          flags: TCPFlag.ack | TCPFlag.psh, payload: payload) {
                enobufs += 1
                let drained = connB.readAllFrames()
                let ack = maxAckFromFrames(drained, srcPort: srcPort)
                if ack > maxAck { maxAck = ack }
            }
            nextSeq += UInt32(payload.count)
        }

        // Measure drain time
        let start = CFAbsoluteTimeGetCurrent()
        let drainDeadline = Date().addingTimeInterval(2.0)
        var idleCount = 0
        while Date() < drainDeadline {
            let batch = connB.readAllFrames()
            let ack = maxAckFromFrames(batch, srcPort: srcPort)
            if ack > maxAck { maxAck = ack }
            if batch.isEmpty {
                idleCount += 1
                if idleCount > 15 { break }
            } else {
                idleCount = 0
            }
            Thread.sleep(forTimeInterval: 0.003)
        }
        let elapsed = CFAbsoluteTimeGetCurrent() - start

        let processedBytes = Int(maxAck) - Int(state.seq)

        teardown(srcPort: srcPort, seq: nextSeq, ack: state.ack)
        drain()

        print("=== benchmark: BURST ===")
        print("burst_segments: \(burstSize)")
        print("segment_bytes: \(segBytes)")
        print("total_injected_bytes: \(burstSize * segBytes)")
        print("processed_bytes: \(processedBytes)")
        print("drain_ms: \(String(format: "%.1f", elapsed * 1000))")
        print("throughput_mbps: \(String(format: "%.1f", Double(processedBytes * 8) / (elapsed * 1_000_000)))")
        print("enobufs: \(enobufs)")
        print("=== end ===")
        print("")
    }

    // MARK: - MAX_CONN

    func benchMaxConn() {
        let maxAttempt = 200
        var established: [(UInt16, UInt32, UInt32)] = []

        let start = CFAbsoluteTimeGetCurrent()
        for i in 0..<maxAttempt {
            let srcPort = UInt16(54000 + i)
            if let state = handshake(srcPort: srcPort,
                                      startSeq: UInt32(3000 + i * 100)) {
                established.append((srcPort, state.seq, state.ack))
            }
        }
        drain()
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
