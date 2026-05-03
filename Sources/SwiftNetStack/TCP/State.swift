import Foundation

// MARK: - Segment Write Callback

typealias SegmentWriteFunc = (TCPSegment) -> Error?

// MARK: - Config

public struct TCPConfig {
    public var listenPort: UInt16 = 0
    public var gatewayIP: UInt32 = 0
    public var bpt: TimeInterval = 0.001 // 1ms
    public var bufferSize: Int = 512 * 1024
    public var mtu: Int = 1400
    public var idleTimeout: TimeInterval = 30 * 60
    public var maxSegsPerTick: Int = 128
    public var windowScale: UInt8 = 7

    public init() {}
    public static func defaultConfig() -> TCPConfig { TCPConfig() }
}

// MARK: - TCPState

public final class TCPState {
    let cfg: TCPConfig

    // State collections (state = set membership)
    var synSent: [Tuple: TCPConn] = [:]
    var synRcvd: [Tuple: TCPConn] = [:]
    var established: [Tuple: TCPConn] = [:]
    var closeWait: [Tuple: TCPConn] = [:]
    var lastAck: [Tuple: TCPConn] = [:]
    var finWait1: [Tuple: TCPConn] = [:]
    var finWait2: [Tuple: TCPConn] = [:]
    var timeWait: [Tuple: TCPConn] = [:]

    var listenPort: UInt16
    var listener: TCPListener?

    // Incoming segments (this round's batch)
    var pending: [TCPSegment] = []

    // Outgoing segments
    var outputs: [TCPSegment] = []

    // Timer wheel
    let timerWheel: TimerWheel
    var tick: Int64 = 0

    // App layer callbacks
    var onAccept: ((TCPConn) -> Void)?
    var appWrites: [Tuple: [UInt8]] = [:]
    var appCloses: Set<Tuple> = []

    // Segment write callback
    var writeFunc: SegmentWriteFunc?

    public init(cfg: TCPConfig) {
        self.cfg = cfg
        self.listenPort = cfg.listenPort
        self.timerWheel = TimerWheel(slotSizeNs: 10_000_000, numSlots: 3000) // 10ms slots, 30s span
        self.tick = Int64(Date().timeIntervalSince1970 * 1e9) / 10_000_000
    }

    func setWriteFunc(_ f: @escaping SegmentWriteFunc) {
        writeFunc = f
    }

    func listen(_ fn: @escaping (TCPConn) -> Void) {
        listener = TCPListener(port: listenPort, onAccept: fn)
    }

    func setGatewayIP(_ ip: UInt32) {
        var c = cfg
        c.gatewayIP = ip
    }

    // MARK: - Segment Injection

    func injectSegment(_ seg: TCPSegment) {
        pending.append(seg)
    }

    // MARK: - App-layer API

    func appWrite(tuple: Tuple, data: [UInt8]) {
        appWrites[tuple, default: []].append(contentsOf: data)
    }

    func appClose(tuple: Tuple) {
        appCloses.insert(tuple)
    }

    func consumeOutputs() -> [TCPSegment] {
        let out = outputs
        outputs = []
        return out
    }

    func hasConn(_ tuple: Tuple) -> Bool {
        findConn(tuple) != nil
    }

    func recvData(tuple: Tuple, buf: inout [UInt8]) -> Int {
        let all: [[Tuple: TCPConn]] = [synSent, synRcvd, established, closeWait, lastAck, finWait1, finWait2]
        for coll in all {
            if let conn = coll[tuple] {
                return conn.readRecvBuf(into: &buf)
            }
        }
        return 0
    }

    func connectionCount() -> Int {
        synSent.count + synRcvd.count + established.count + closeWait.count +
            lastAck.count + finWait1.count + finWait2.count + timeWait.count
    }

    // MARK: - Connection Creation

    func createExternalConn(tuple: Tuple, irs: UInt32, window: UInt16, rawSeg: [UInt8]) -> TCPConn {
        let iss = generateISN()
        let conn = TCPConn(tuple: tuple, irs: irs, iss: iss, window: window, bufSize: cfg.bufferSize)
        conn.lastActivityTick = tick
        conn.retransmitAt = tick + msToTicks(200)
        let ws = parseWindowScale(rawSeg)
        if ws > 0 {
            conn.sndShift = ws
        }
        conn.rcvShift = cfg.windowScale
        synRcvd[tuple] = conn
        return conn
    }

    func activeOpen(tuple: Tuple, vmWindow: UInt16) -> TCPConn {
        let iss = generateISN()
        let conn = TCPConn(tuple: tuple, irs: 0, iss: iss, window: vmWindow, bufSize: cfg.bufferSize)
        conn.lastActivityTick = tick
        conn.retransmitAt = tick + msToTicks(200)
        conn.rcvShift = cfg.windowScale
        synSent[tuple] = conn
        return conn
    }

    // MARK: - Deliberate

    func deliberate(now: Date) {
        tick = timerWheel.advance(now: now)

        processTimers()
        dispatchSegments()
        processAppRequests()
        advanceSynSent()
        advanceSynRcvd()
        advanceEstablished()
        advanceCloseWait()
        advanceLastAck()
        advanceFinWait1()
        advanceFinWait2()
        advanceTimeWait()
        reclaimClosed()
#if DEBUG
        checkInvariants()
#endif
    }

    // MARK: - Lookup Helpers

    func findConn(_ tuple: Tuple) -> TCPConn? {
        let all: [[Tuple: TCPConn]] = [synSent, synRcvd, established, closeWait, lastAck, finWait1, finWait2]
        for coll in all {
            if let conn = coll[tuple] { return conn }
        }
        return nil
    }

    func findConn(in states: [Tuple: TCPConn]..., tuple: Tuple) -> TCPConn? {
        for s in states {
            if let conn = s[tuple] { return conn }
        }
        return nil
    }

    // MARK: - ISN Generation

    func generateISN() -> UInt32 {
        var b: UInt32 = 0
        withUnsafeMutableBytes(of: &b) { ptr in
            if SecRandomCopyBytes(kSecRandomDefault, 4, ptr.baseAddress!) == errSecSuccess {
                return
            }
            ptr.storeBytes(of: arc4random(), as: UInt32.self)
        }
        return b
    }

    func msToTicks(_ ms: Int64) -> Int64 {
        ms * 1_000_000 / timerWheel.slotSize
    }
}
