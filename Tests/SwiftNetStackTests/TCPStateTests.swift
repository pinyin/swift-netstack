import Foundation
import Testing
@testable import SwiftNetStack

// MARK: - Test Helpers

func fakeSegment(srcIP: UInt32, dstIP: UInt32, srcPort: UInt16, dstPort: UInt16,
                 seq: UInt32, ack: UInt32, flags: UInt8, payload: [UInt8] = [],
                 window: UInt16 = 65535) -> TCPSegment {
    let tuple = Tuple(srcIP: srcIP, dstIP: dstIP, srcPort: srcPort, dstPort: dstPort)
    let raw = buildSegment(tuple: tuple, seq: seq, ack: ack, flags: flags, window: window, wscale: 0, payload: payload)
    let dataOffset: UInt8 = 20
    let header = TCPHeader(
        srcPort: srcPort, dstPort: dstPort,
        seqNum: seq, ackNum: ack,
        dataOffset: dataOffset, flags: flags,
        windowSize: window, checksum: 0, urgentPtr: 0
    )
    return TCPSegment(header: header, payload: Data(payload), tuple: tuple, raw: raw)
}

func fakeSegmentWithWindow(srcIP: UInt32, dstIP: UInt32, srcPort: UInt16, dstPort: UInt16,
                           seq: UInt32, ack: UInt32, flags: UInt8, window: UInt16,
                           payload: [UInt8] = []) -> TCPSegment {
    let tuple = Tuple(srcIP: srcIP, dstIP: dstIP, srcPort: srcPort, dstPort: dstPort)
    let raw = buildSegment(tuple: tuple, seq: seq, ack: ack, flags: flags, window: window, wscale: 0, payload: payload)
    let header = TCPHeader(
        srcPort: srcPort, dstPort: dstPort,
        seqNum: seq, ackNum: ack,
        dataOffset: 20, flags: flags,
        windowSize: window, checksum: 0, urgentPtr: 0
    )
    return TCPSegment(header: header, payload: Data(payload), tuple: tuple, raw: raw)
}

func doHandshake(_ ts: TCPState, vmIP: UInt32, gwIP: UInt32, srcPort: UInt16, dstPort: UInt16) {
    let synSeg = fakeSegment(srcIP: vmIP, dstIP: gwIP, srcPort: srcPort, dstPort: dstPort,
                             seq: 1000, ack: 0, flags: TCPFlag.syn)
    ts.injectSegment(synSeg)
    ts.deliberate(now: Date())

    let outputs = ts.consumeOutputs()
    guard !outputs.isEmpty else {
        fatalError("no SYN-ACK in handshake")
    }
    let synAck = outputs[0]

    let ackSeg = fakeSegment(srcIP: vmIP, dstIP: gwIP, srcPort: srcPort, dstPort: dstPort,
                             seq: 1001, ack: synAck.header.seqNum + 1, flags: TCPFlag.ack)
    ts.injectSegment(ackSeg)
    ts.deliberate(now: Date())
    _ = ts.consumeOutputs()
}

func firstConn(in dict: [Tuple: TCPConn]) -> TCPConn? {
    dict.first?.value
}

func makeConfig(listenPort: UInt16 = 8080, gatewayIP: UInt32 = 0) -> TCPConfig {
    var cfg = TCPConfig.defaultConfig()
    cfg.listenPort = listenPort
    cfg.gatewayIP = gatewayIP
    return cfg
}

// MARK: - TestHandshake

@Test func testHandshake() {
    let gwIP = ipToUInt32("192.168.65.1")
    let vmIP = ipToUInt32("192.168.65.2")

    let cfg = makeConfig(listenPort: 8080, gatewayIP: gwIP)
    let ts = TCPState(cfg: cfg)

    var accepted: TCPConn?
    ts.listen { conn in accepted = conn }

    // Step 1: VM sends SYN → should create SynRcvd entry
    let synSeg = fakeSegment(srcIP: vmIP, dstIP: gwIP, srcPort: 12345, dstPort: 8080,
                             seq: 1000, ack: 0, flags: TCPFlag.syn)
    ts.injectSegment(synSeg)
    ts.deliberate(now: Date())

    #expect(ts.synRcvd.count == 1, "expected 1 SynRcvd connection, got \(ts.synRcvd.count)")

    // Should have generated a SYN-ACK
    let outputs = ts.consumeOutputs()
    #expect(!outputs.isEmpty, "expected SYN-ACK output")

    let synAck = outputs[0]
    #expect(synAck.header.hasFlag(TCPFlag.syn | TCPFlag.ack),
            "expected SYN|ACK, got flags=\(String(synAck.header.flags, radix: 16))")
    #expect(synAck.header.ackNum == 1001, "expected ACK=1001, got \(synAck.header.ackNum)")

    // Step 2: VM sends ACK confirming SYN-ACK → should move to Established
    let ackSeg = fakeSegment(srcIP: vmIP, dstIP: gwIP, srcPort: 12345, dstPort: 8080,
                             seq: 1001, ack: synAck.header.seqNum + 1, flags: TCPFlag.ack)
    ts.injectSegment(ackSeg)
    ts.deliberate(now: Date())

    #expect(ts.synRcvd.count == 0, "expected 0 SynRcvd, got \(ts.synRcvd.count)")

    guard let conn = firstConn(in: ts.established) else {
        fatalError("expected connection in Established")
    }
    #expect(accepted != nil, "expected accept callback to be called")
    #expect(accepted === conn, "accepted connection != established connection")
}

// MARK: - TestDataTransfer

@Test func testDataTransfer() {
    let gwIP = ipToUInt32("192.168.65.1")
    let vmIP = ipToUInt32("192.168.65.2")

    let cfg = makeConfig(listenPort: 8080, gatewayIP: gwIP)
    let ts = TCPState(cfg: cfg)
    ts.listen { _ in }

    doHandshake(ts, vmIP: vmIP, gwIP: gwIP, srcPort: 12345, dstPort: 8080)

    guard let conn = firstConn(in: ts.established) else {
        fatalError("no connection in Established")
    }

    // Send data from VM
    let payload = Array("hello world".utf8)
    let dataSeg = fakeSegment(srcIP: vmIP, dstIP: gwIP, srcPort: 12345, dstPort: 8080,
                              seq: 1001, ack: conn.iss + 1,
                              flags: TCPFlag.ack | TCPFlag.psh, payload: payload)
    ts.injectSegment(dataSeg)
    ts.deliberate(now: Date())

    var buf = [UInt8](repeating: 0, count: 1024)
    let n = conn.readRecvBuf(into: &buf)
    #expect(n == payload.count, "expected \(payload.count) bytes, got \(n)")
    #expect(Array(buf[0..<n]) == payload, "expected 'hello world'")

    // Immediate ACK
    let outputs = ts.consumeOutputs()
    let hasAck = outputs.contains { out in
        out.header.hasFlag(TCPFlag.ack) && out.header.ackNum == 1001 + UInt32(payload.count)
    }
    #expect(hasAck, "expected immediate ACK for received data")
}

// MARK: - TestForwardCascade

@Test func testForwardCascade() {
    let gwIP = ipToUInt32("192.168.65.1")
    let vmIP = ipToUInt32("192.168.65.2")

    let cfg = makeConfig(listenPort: 8080, gatewayIP: gwIP)
    let ts = TCPState(cfg: cfg)
    ts.listen { _ in }

    // Test 1: Passive close cascade
    doHandshake(ts, vmIP: vmIP, gwIP: gwIP, srcPort: 12345, dstPort: 8080)
    guard let conn1 = firstConn(in: ts.established) else {
        fatalError("no connection in Established")
    }

    // Inject FIN from peer → CloseWait
    let finSeg = fakeSegment(srcIP: vmIP, dstIP: gwIP, srcPort: 12345, dstPort: 8080,
                             seq: 1001, ack: conn1.iss + 1,
                             flags: TCPFlag.ack | TCPFlag.fin)
    ts.injectSegment(finSeg)
    ts.deliberate(now: Date())

    #expect(ts.closeWait[conn1.tuple] != nil,
            "expected connection in CloseWait. CloseWait=\(ts.closeWait.count), Established=\(ts.established.count)")

    // AppClose + last ACK in same round
    ts.appClose(tuple: conn1.tuple)
    let ackOurFin = fakeSegment(srcIP: vmIP, dstIP: gwIP, srcPort: 12345, dstPort: 8080,
                                seq: 1002, ack: conn1.iss + 2, flags: TCPFlag.ack)
    ts.injectSegment(ackOurFin)
    ts.deliberate(now: Date())

    #expect(ts.lastAck[conn1.tuple] == nil, "expected connection cleaned up from LastAck")
    #expect(ts.connectionCount() == 0, "expected 0 connections, got \(ts.connectionCount())")

    // Consume leftovers
    _ = ts.consumeOutputs()

    // Test 2: Active close cascade
    doHandshake(ts, vmIP: vmIP, gwIP: gwIP, srcPort: 12346, dstPort: 8080)
    guard let conn2 = firstConn(in: ts.established) else {
        fatalError("no connection in Established for test 2")
    }

    // AppClose → FinWait1, then FIN is sent
    ts.appClose(tuple: conn2.tuple)
    ts.deliberate(now: Date())

    #expect(ts.finWait1[conn2.tuple] != nil,
            "expected connection in FinWait1. FinWait1=\(ts.finWait1.count), Established=\(ts.established.count)")

    // VM ACKs our FIN → FinWait2
    let ackFin = fakeSegment(srcIP: vmIP, dstIP: gwIP, srcPort: 12346, dstPort: 8080,
                             seq: 1001, ack: conn2.iss + 2, flags: TCPFlag.ack)
    ts.injectSegment(ackFin)
    ts.deliberate(now: Date())

    #expect(ts.finWait2[conn2.tuple] != nil,
            "expected connection in FinWait2. FinWait1=\(ts.finWait1.count), FinWait2=\(ts.finWait2.count)")
}

// MARK: - TestStateAsPosition

@Test func testStateAsPosition() {
    let gwIP = ipToUInt32("192.168.65.1")
    let vmIP = ipToUInt32("192.168.65.2")

    let cfg = makeConfig(listenPort: 8080, gatewayIP: gwIP)
    let ts = TCPState(cfg: cfg)
    ts.listen { _ in }

    doHandshake(ts, vmIP: vmIP, gwIP: gwIP, srcPort: 12345, dstPort: 8080)

    #expect(ts.connectionCount() == 1, "expected 1 total connection")
    #expect(ts.established.count == 1, "expected 1 in Established")
    #expect(ts.synRcvd.count == 0, "conn should NOT be in SynRcvd")
    #expect(ts.finWait1.count == 0, "conn should NOT be in FinWait1")
}

// MARK: - TestActiveOpen

@Test func testActiveOpen() {
    let gwIP = ipToUInt32("192.168.65.1")
    let vmIP = ipToUInt32("192.168.65.2")

    let cfg = makeConfig(gatewayIP: gwIP)
    let ts = TCPState(cfg: cfg)

    let tuple = Tuple(srcIP: gwIP, dstIP: vmIP, srcPort: 32768, dstPort: 22)
    let conn = ts.activeOpen(tuple: tuple, vmWindow: 65535)

    #expect(ts.synSent.count == 1, "expected 1 SynSent, got \(ts.synSent.count)")

    // Deliberate → SYN send
    ts.deliberate(now: Date())
    let outputs = ts.consumeOutputs()

    #expect(!outputs.isEmpty, "expected SYN output")
    let syn = outputs[0]
    #expect(syn.header.hasFlag(TCPFlag.syn) && !syn.header.hasFlag(TCPFlag.ack),
            "expected pure SYN, got flags=\(String(syn.header.flags, radix: 16))")
    #expect(syn.header.seqNum == conn.iss, "expected SYN seq=\(conn.iss), got \(syn.header.seqNum)")

    // VM responds with SYN-ACK
    let synAckSeg = fakeSegment(srcIP: vmIP, dstIP: gwIP, srcPort: 22, dstPort: 32768,
                                seq: 5000, ack: conn.iss + 1, flags: TCPFlag.syn | TCPFlag.ack)
    ts.injectSegment(synAckSeg)
    ts.deliberate(now: Date())

    #expect(ts.synSent.count == 0, "expected 0 SynSent, got \(ts.synSent.count)")
    #expect(ts.established[tuple] != nil, "expected connection in Established")

    // Should have sent ACK for SYN-ACK
    let outputs2 = ts.consumeOutputs()
    let hasAck = outputs2.contains { out in
        out.header.hasFlag(TCPFlag.ack) && out.header.ackNum == 5001
    }
    #expect(hasAck, "expected ACK for SYN-ACK")
}

// MARK: - TestIdleTimeout

@Test func testIdleTimeout() {
    let gwIP = ipToUInt32("192.168.65.1")
    let vmIP = ipToUInt32("192.168.65.2")

    var cfg = makeConfig(listenPort: 8080, gatewayIP: gwIP)
    cfg.idleTimeout = 0.1 // 100ms
    let ts = TCPState(cfg: cfg)
    ts.listen { _ in }

    doHandshake(ts, vmIP: vmIP, gwIP: gwIP, srcPort: 12345, dstPort: 8080)

    #expect(ts.connectionCount() == 1, "expected 1 connection, got \(ts.connectionCount())")

    // Advance tick past idle timeout
    let idleTicks = Int64(cfg.idleTimeout / (TimeInterval(ts.timerWheel.slotSize) / 1e9))
    ts.tick += idleTicks + 1

    ts.reclaimIdle()

    #expect(ts.connectionCount() == 0, "expected 0 connections after idle timeout, got \(ts.connectionCount())")
}

// MARK: - Test ACK processing in state machine (preProcessACKs removed)

@Test func testACKProcessingInStateMachine() {
    let gwIP = ipToUInt32("192.168.65.1")
    let vmIP = ipToUInt32("192.168.65.2")

    let cfg = makeConfig(gatewayIP: gwIP)
    let ts = TCPState(cfg: cfg)

    let tuple = Tuple(srcIP: gwIP, dstIP: vmIP, srcPort: 32769, dstPort: 22)
    let conn = ts.activeOpen(tuple: tuple, vmWindow: 65535)

    // Deliberate to send SYN
    ts.deliberate(now: Date())
    _ = ts.consumeOutputs()

    // Write 22 bytes to SendBuf
    let testData = Array("SSH-2.0-OpenSSH_10.2\r\n".utf8)
    #expect(testData.count == 22, "test data must be 22 bytes")
    let n = conn.writeSendBuf(testData)
    #expect(n == 22, "WriteSendBuf returned \(n), expected 22")
    #expect(conn.sendAvail == 22, "SendAvail = \(conn.sendAvail), expected 22")
    let sendHeadBefore = conn.sendHead

    // Inject SYN-ACK from VM — ACK processing now happens in advanceSynSent
    let synAckSeg = fakeSegment(srcIP: vmIP, dstIP: gwIP, srcPort: 22, dstPort: 32769,
                                seq: 5000, ack: conn.iss + 1, flags: TCPFlag.syn | TCPFlag.ack)
    ts.injectSegment(synAckSeg)

    // Deliberate: advanceSynSent processes the ACK of SYN → moves to Established
    ts.deliberate(now: Date())

    #expect(ts.established[tuple] != nil, "expected connection in Established")

    // Verify SendBuf was NOT corrupted by ACK processing
    #expect(conn.sendAvail == 22,
            "ACK processing corrupted SendBuf: SendAvail = \(conn.sendAvail), expected 22")

    // Verify 22-byte data was sent
    let outputs = ts.consumeOutputs()
    var totalDataLen = 0
    for out in outputs {
        if !out.payload.isEmpty {
            totalDataLen += out.payload.count
            #expect(out.payload.count == 22, "data payload length = \(out.payload.count), expected 22")
            #expect([UInt8](out.payload) == testData, "data payload mismatch")
        }
    }
    #expect(totalDataLen == 22, "total data sent = \(totalDataLen) bytes, expected 22")
}

// MARK: - TestZeroWindowFlowControl

@Test func testZeroWindowFlowControl() {
    let gwIP = ipToUInt32("192.168.65.1")
    let vmIP = ipToUInt32("192.168.65.2")

    let cfg = makeConfig(listenPort: 8080, gatewayIP: gwIP)
    let ts = TCPState(cfg: cfg)
    ts.listen { _ in }

    doHandshake(ts, vmIP: vmIP, gwIP: gwIP, srcPort: 12345, dstPort: 8080)
    guard let conn = firstConn(in: ts.established) else {
        fatalError("no connection in Established")
    }

    // Write data
    ts.appWrite(tuple: conn.tuple, data: Array("hello world".utf8))
    ts.deliberate(now: Date())
    let outputs1 = ts.consumeOutputs()

    var dataSent = false
    for out in outputs1 {
        if !out.payload.isEmpty { dataSent = true }
    }
    #expect(dataSent, "expected data segments in first round")

    // Peer ACKs with WindowSize=0
    let ackSeg = fakeSegmentWithWindow(srcIP: vmIP, dstIP: gwIP, srcPort: 12345, dstPort: 8080,
                                       seq: 1001, ack: conn.sndNxt, flags: TCPFlag.ack, window: 0)
    ts.injectSegment(ackSeg)

    // Write more data — must NOT be sent
    ts.appWrite(tuple: conn.tuple, data: Array("more data".utf8))
    ts.deliberate(now: Date())
    let outputs2 = ts.consumeOutputs()

    for out in outputs2 {
        #expect(out.payload.isEmpty, "sent data despite zero-window advertisement")
    }

    // Peer reopens window → data flows again
    let reopenSeg = fakeSegment(srcIP: vmIP, dstIP: gwIP, srcPort: 12345, dstPort: 8080,
                                seq: 1001, ack: conn.sndNxt, flags: TCPFlag.ack)
    ts.injectSegment(reopenSeg)
    ts.deliberate(now: Date())
    let outputs3 = ts.consumeOutputs()

    dataSent = false
    for out in outputs3 {
        if !out.payload.isEmpty { dataSent = true }
    }
    #expect(dataSent, "expected data after window reopened")
}

// MARK: - TestLastAckFINAckDetection

@Test func testLastAckFINAckDetection() {
    let gwIP = ipToUInt32("192.168.65.1")
    let vmIP = ipToUInt32("192.168.65.2")

    let cfg = makeConfig(listenPort: 8080, gatewayIP: gwIP)
    let ts = TCPState(cfg: cfg)
    ts.listen { _ in }

    doHandshake(ts, vmIP: vmIP, gwIP: gwIP, srcPort: 12345, dstPort: 8080)
    guard let conn = firstConn(in: ts.established) else {
        fatalError("no connection in Established")
    }
    let iss = conn.iss

    // Send data
    ts.appWrite(tuple: conn.tuple, data: Array("hello".utf8))
    ts.deliberate(now: Date())
    _ = ts.consumeOutputs()

    let sndNxtAfterData = conn.sndNxt

    // Peer sends standalone FIN
    let finSeg = fakeSegment(srcIP: vmIP, dstIP: gwIP, srcPort: 12345, dstPort: 8080,
                             seq: 1001, ack: iss + 1, flags: TCPFlag.ack | TCPFlag.fin)
    ts.injectSegment(finSeg)
    ts.deliberate(now: Date())

    #expect(ts.closeWait[conn.tuple] != nil,
            "expected conn in CloseWait. Established=\(ts.established.count) CloseWait=\(ts.closeWait.count)")

    // AppClose + sendFIN
    ts.appClose(tuple: conn.tuple)
    ts.deliberate(now: Date())

    #expect(ts.lastAck[conn.tuple] != nil,
            "expected conn in LastAck. CloseWait=\(ts.closeWait.count) LastAck=\(ts.lastAck.count)")

    let sndNxtAfterFIN = conn.sndNxt

    // ACK covers data but NOT the FIN
    let dataOnlyAck = fakeSegment(srcIP: vmIP, dstIP: gwIP, srcPort: 12345, dstPort: 8080,
                                  seq: 1002, ack: sndNxtAfterData, flags: TCPFlag.ack)
    ts.injectSegment(dataOnlyAck)
    ts.deliberate(now: Date())

    #expect(ts.lastAck[conn.tuple] != nil,
            "connection incorrectly cleaned up: ACK covered data but NOT the FIN")

    // ACK that covers the FIN
    let finAck = fakeSegment(srcIP: vmIP, dstIP: gwIP, srcPort: 12345, dstPort: 8080,
                             seq: 1002, ack: sndNxtAfterFIN, flags: TCPFlag.ack)
    ts.injectSegment(finAck)
    ts.deliberate(now: Date())

    #expect(ts.lastAck[conn.tuple] == nil, "connection should be cleaned up after FIN is acked")
    #expect(ts.connectionCount() == 0, "expected 0 connections, got \(ts.connectionCount())")
}

// MARK: - TestEstablishedToCloseWaitPreservesData

@Test func testEstablishedToCloseWaitPreservesData() {
    let gwIP = ipToUInt32("192.168.65.1")
    let vmIP = ipToUInt32("192.168.65.2")

    let cfg = makeConfig(listenPort: 8080, gatewayIP: gwIP)
    let ts = TCPState(cfg: cfg)
    ts.listen { _ in }

    doHandshake(ts, vmIP: vmIP, gwIP: gwIP, srcPort: 12345, dstPort: 8080)
    guard let conn = firstConn(in: ts.established) else {
        fatalError("no connection in Established")
    }

    // Data segment and FIN in same batch
    let payload = Array("data-before-fin".utf8)
    let dataSeg = fakeSegment(srcIP: vmIP, dstIP: gwIP, srcPort: 12345, dstPort: 8080,
                              seq: conn.rcvNxt, ack: conn.iss + 1, flags: TCPFlag.ack, payload: payload)
    let finSeq = conn.rcvNxt + UInt32(payload.count)
    let finSeg = fakeSegment(srcIP: vmIP, dstIP: gwIP, srcPort: 12345, dstPort: 8080,
                             seq: finSeq, ack: conn.iss + 1, flags: TCPFlag.ack | TCPFlag.fin)
    ts.injectSegment(dataSeg)
    ts.injectSegment(finSeg)

    ts.deliberate(now: Date())

    #expect(ts.closeWait[conn.tuple] != nil,
            "expected conn in CloseWait. Established=\(ts.established.count) CloseWait=\(ts.closeWait.count)")

    #expect(conn.recvAvail == payload.count,
            "data lost: RecvAvail=\(conn.recvAvail), expected \(payload.count)")

    var buf = [UInt8](repeating: 0, count: 1024)
    let n = conn.readRecvBuf(into: &buf)
    #expect(n == payload.count && Array(buf[0..<n]) == payload,
            "RecvBuf content wrong: got \(Array(buf[0..<n])), expected \(payload)")
}

// MARK: - TestFinWait1FINAckAfterData

@Test func testFinWait1FINAckAfterData() {
    let gwIP = ipToUInt32("192.168.65.1")
    let vmIP = ipToUInt32("192.168.65.2")

    let cfg = makeConfig(listenPort: 8080, gatewayIP: gwIP)
    let ts = TCPState(cfg: cfg)
    ts.listen { _ in }

    doHandshake(ts, vmIP: vmIP, gwIP: gwIP, srcPort: 12346, dstPort: 8080)
    guard let conn = firstConn(in: ts.established) else {
        fatalError("no connection in Established")
    }

    // Write data then close
    ts.appWrite(tuple: conn.tuple, data: Array("hello".utf8))
    ts.appClose(tuple: conn.tuple)
    ts.deliberate(now: Date())

    #expect(ts.finWait1[conn.tuple] != nil,
            "expected conn in FinWait1, got FinWait1=\(ts.finWait1.count)")

    let sndNxtAfterFIN = conn.sndNxt

    // ACK covers data but NOT the FIN
    let dataOnlyAck = fakeSegment(srcIP: vmIP, dstIP: gwIP, srcPort: 12346, dstPort: 8080,
                                  seq: 1001, ack: sndNxtAfterFIN - 1, flags: TCPFlag.ack)
    ts.injectSegment(dataOnlyAck)
    ts.deliberate(now: Date())

    #expect(ts.finWait1[conn.tuple] != nil,
            "FIN_WAIT1→FIN_WAIT2 transition triggered by data-only ACK")

    // ACK that covers the FIN
    let finAck = fakeSegment(srcIP: vmIP, dstIP: gwIP, srcPort: 12346, dstPort: 8080,
                             seq: 1001, ack: sndNxtAfterFIN, flags: TCPFlag.ack)
    ts.injectSegment(finAck)
    ts.deliberate(now: Date())

    #expect(ts.finWait2[conn.tuple] != nil, "FIN_WAIT1→FIN_WAIT2 expected after FIN ack")
}

// MARK: - TestTimerWheelLastTickInit

@Test func testTimerWheelLastTickInit() {
    let tw = TimerWheel(slotSizeNs: 10_000_000, numSlots: 100)

    let now = Date()
    let tick = tw.advance(now: now)

    let futureTuple = Tuple(srcIP: 0, dstIP: 0, srcPort: 1, dstPort: 2)
    tw.schedule(tuple: futureTuple, tick: tick + 100)

    // Expired should return nothing
    let expired = tw.expired(currentTick: tick)
    #expect(expired.isEmpty, "Expired returned \(expired.count) tuples, expected 0")

    // Advance far → timer fires
    let farTick = tick + 200
    let expired2 = tw.expired(currentTick: farTick)
    let found = expired2.contains { $0 == futureTuple }
    #expect(found, "timer at tick+100 did not fire at tick+200")
}

// MARK: - TestRecvDataIncludesSynRcvd

@Test func testRecvDataIncludesSynRcvd() {
    let gwIP = ipToUInt32("192.168.65.1")
    let vmIP = ipToUInt32("192.168.65.2")

    let cfg = makeConfig(listenPort: 8080, gatewayIP: gwIP)
    let ts = TCPState(cfg: cfg)
    ts.listen { _ in }

    // Initiate handshake → SynRcvd
    let synSeg = fakeSegment(srcIP: vmIP, dstIP: gwIP, srcPort: 12345, dstPort: 8080,
                             seq: 1000, ack: 0, flags: TCPFlag.syn)
    ts.injectSegment(synSeg)
    ts.deliberate(now: Date())

    #expect(ts.synRcvd.count == 1, "expected 1 SynRcvd, got \(ts.synRcvd.count)")

    // Manually inject data into SynRcvd connection's RecvBuf
    guard let conn = firstConn(in: ts.synRcvd) else {
        fatalError("no connection in SynRcvd")
    }
    _ = conn.writeRecvBuf(Array("early-data".utf8))

    var buf = [UInt8](repeating: 0, count: 1024)
    let n = ts.recvData(tuple: conn.tuple, buf: &buf)
    #expect(n == 10, "RecvData returned \(n) bytes, expected 10")
    #expect(Array(buf[0..<n]) == Array("early-data".utf8),
            "RecvData returned wrong content")
}

// MARK: - TestAppCloseSynSent

@Test func testAppCloseSynSent() {
    let gwIP = ipToUInt32("192.168.65.1")
    let vmIP = ipToUInt32("192.168.65.2")

    let cfg = makeConfig(gatewayIP: gwIP)
    let ts = TCPState(cfg: cfg)

    let tuple = Tuple(srcIP: gwIP, dstIP: vmIP, srcPort: 32769, dstPort: 22)
    let conn = ts.activeOpen(tuple: tuple, vmWindow: 65535)

    #expect(ts.synSent[tuple] != nil, "expected connection in SynSent")
    #expect(ts.connectionCount() == 1, "expected 1 connection")

    ts.appClose(tuple: conn.tuple)
    ts.deliberate(now: Date())

    #expect(ts.synSent[tuple] == nil, "AppClose did not remove connection from SynSent")
    #expect(ts.connectionCount() == 0, "expected 0 connections, got \(ts.connectionCount())")
    #expect(!ts.hasConn(tuple), "HasConn should return false")
}

// MARK: - TestAppCloseSynRcvd

@Test func testAppCloseSynRcvd() {
    let gwIP = ipToUInt32("192.168.65.1")
    let vmIP = ipToUInt32("192.168.65.2")

    let cfg = makeConfig(listenPort: 8080, gatewayIP: gwIP)
    let ts = TCPState(cfg: cfg)
    ts.listen { _ in }

    // Inject SYN → SynRcvd
    let synSeg = fakeSegment(srcIP: vmIP, dstIP: gwIP, srcPort: 12345, dstPort: 8080,
                             seq: 1000, ack: 0, flags: TCPFlag.syn)
    ts.injectSegment(synSeg)
    ts.deliberate(now: Date())

    let tuple = Tuple(srcIP: gwIP, dstIP: vmIP, srcPort: 8080, dstPort: 12345)
    #expect(ts.synRcvd[tuple] != nil, "expected connection in SynRcvd")

    ts.appClose(tuple: tuple)
    ts.deliberate(now: Date())

    #expect(ts.synRcvd[tuple] == nil, "AppClose did not remove connection from SynRcvd")
    #expect(ts.connectionCount() == 0, "expected 0 connections, got \(ts.connectionCount())")
}

// MARK: - TestWindowScaling

@Test func testWindowScaling() {
    let gwIP = ipToUInt32("192.168.65.1")
    let vmIP = ipToUInt32("192.168.65.2")

    var cfg = makeConfig(listenPort: 8080, gatewayIP: gwIP)
    cfg.windowScale = 7
    let ts = TCPState(cfg: cfg)
    ts.listen { _ in }

    // Handshake with window scale in SYN raw bytes
    let tuple = Tuple(srcIP: vmIP, dstIP: gwIP, srcPort: 12345, dstPort: 8080)
    let synRaw = buildSegmentWithWScale(tuple: tuple, seq: 1000, ack: 0,
                                         flags: TCPFlag.syn, window: 65535,
                                         wscale: 7, payload: [])
    let synHdr = TCPHeader(srcPort: 12345, dstPort: 8080, seqNum: 1000, ackNum: 0,
                           dataOffset: 24, flags: TCPFlag.syn,
                           windowSize: 65535, checksum: 0, urgentPtr: 0)
    let synSeg = TCPSegment(header: synHdr, payload: Data(), tuple: tuple, raw: synRaw)
    ts.injectSegment(synSeg)
    ts.deliberate(now: Date())

    let outputs = ts.consumeOutputs()
    #expect(!outputs.isEmpty, "expected SYN-ACK output")
    let synAck = outputs[0]

    // ACK the SYN-ACK
    let ackSeg = fakeSegment(srcIP: vmIP, dstIP: gwIP, srcPort: 12345, dstPort: 8080,
                             seq: 1001, ack: synAck.header.seqNum + 1, flags: TCPFlag.ack)
    ts.injectSegment(ackSeg)
    ts.deliberate(now: Date())

    guard let conn = firstConn(in: ts.established) else {
        fatalError("expected connection in Established")
    }

    #expect(conn.sndShift == 7, "expected SndShift=7, got \(conn.sndShift)")

    // Send ACK with window=1000 → after shift should be 128000
    let ackSeg2 = fakeSegmentWithWindow(srcIP: vmIP, dstIP: gwIP, srcPort: 12345, dstPort: 8080,
                                        seq: 1001, ack: conn.iss + 1, flags: TCPFlag.ack, window: 1000)
    ts.injectSegment(ackSeg2)
    ts.deliberate(now: Date())

    let expected = UInt32(1000) << conn.sndShift
    #expect(conn.sndWnd == expected, "window scaling: expected SND_WND=\(expected), got \(conn.sndWnd)")
}

// MARK: - TestRetransmitEstablished

@Test func testRetransmitEstablished() {
    let gwIP = ipToUInt32("192.168.65.1")
    let vmIP = ipToUInt32("192.168.65.2")

    let cfg = makeConfig(listenPort: 8080, gatewayIP: gwIP)
    let ts = TCPState(cfg: cfg)
    ts.listen { _ in }

    doHandshake(ts, vmIP: vmIP, gwIP: gwIP, srcPort: 12345, dstPort: 8080)
    guard let conn = firstConn(in: ts.established) else {
        fatalError("no connection in Established")
    }

    // Write data to send buffer
    let data = [UInt8](repeating: 0, count: 3000)
    _ = conn.writeSendBuf(data)
    #expect(conn.sendAvail == 3000, "expected 3000 bytes, got \(conn.sendAvail)")

    // Send data
    ts.deliberate(now: Date())
    #expect(seqGT(conn.sndNxt, conn.sndUna), "expected SND_NXT to advance past SND_UNA")

    // Retransmit: reset SND_NXT to SND_UNA
    conn.sndNxt = conn.sndUna
    conn.retransmitCount += 1

    #expect(conn.sndNxt == conn.sndUna, "retransmit: SND_NXT != SND_UNA")

    // PeekSendData returns data again after reset
    let d = conn.peekSendData(max: 1400)
    #expect(!d.isEmpty, "PeekSendData returned nil after retransmit reset")
}

// MARK: - TestSeqWraparound

@Test func testSeqWraparound() {
    // Normal comparison
    #expect(seqGT(200, 100), "seqGT(200, 100) should be true")
    #expect(!seqGT(100, 200), "seqGT(100, 200) should be false")
    #expect(seqGE(200, 100), "seqGE(200, 100) should be true")
    #expect(seqGE(200, 200), "seqGE(200, 200) should be true")
    #expect(!seqGE(100, 200), "seqGE(100, 200) should be false")
    #expect(seqLT(100, 200), "seqLT(100, 200) should be true")
    #expect(!seqLT(200, 100), "seqLT(200, 100) should be false")
    #expect(seqLE(100, 200), "seqLE(100, 200) should be true")
    #expect(seqLE(200, 200), "seqLE(200, 200) should be true")

    // Wraparound case
    let a: UInt32 = 0x00000100
    let b: UInt32 = 0xFFFF0000
    #expect(seqGT(a, b), "seqGT(0x00000100, 0xFFFF0000) should be true (wraparound)")
    #expect(!seqLT(a, b), "seqLT(0x00000100, 0xFFFF0000) should be false (wraparound)")

    // Within valid range
    let largeButValid: UInt32 = 0x7FFFFFFF
    #expect(seqGT(largeButValid, 0), "seqGT(0x7FFFFFFF, 0) should be true")
    #expect(!seqGT(0, largeButValid), "seqGT(0, 0x7FFFFFFF) should be false")
}

// MARK: - TestTimerWheelLongTimeout

@Test func testTimerWheelLongTimeout() {
    let tw = TimerWheel(slotSizeNs: 10_000_000, numSlots: 3000)

    // Use current tick as base
    let baseTick = tw.advance(now: Date())
    let tuple1 = Tuple(srcIP: 0, dstIP: 0, srcPort: 1, dstPort: 2)

    // Schedule timer 60s in the future (beyond 30s span)
    let farTick = baseTick + 6000
    tw.schedule(tuple: tuple1, tick: farTick)

    // Schedule timer at +30s
    let tuple2 = Tuple(srcIP: 0, dstIP: 0, srcPort: 3, dstPort: 4)
    let nearTick = baseTick + 3000
    tw.schedule(tuple: tuple2, tick: nearTick)

    // Advance to +30s
    let midTick = baseTick + 3000
    let expired = tw.expired(currentTick: midTick)

    var foundNear = false, foundFar = false
    for tup in expired {
        if tup == tuple1 { foundFar = true }
        if tup == tuple2 { foundNear = true }
    }
    #expect(foundNear, "+30s timer should have expired at +30s")
    #expect(!foundFar, "+60s timer expired too early (at +30s, slot aliasing bug)")

    // Advance to +60s
    let finalTick = baseTick + 6000
    let expired2 = tw.expired(currentTick: finalTick)
    foundFar = false
    for tup in expired2 {
        if tup == tuple1 { foundFar = true }
    }
    #expect(foundFar, "+60s timer should have expired at +60s")
}

// MARK: - TestRetransmitCountReset

@Test func testRetransmitCountReset() {
    var cfg = makeConfig()
    cfg.bufferSize = 64 * 1024

    let conn = TCPConn(tuple: Tuple(srcIP: 0, dstIP: 0, srcPort: 0, dstPort: 0),
                       irs: 1000, iss: 2000, window: 65535, bufSize: cfg.bufferSize)

    // Simulate retransmit
    conn.retransmitCount = 3
    conn.sndNxt = 2500
    _ = conn.writeSendBuf([UInt8](repeating: 0, count: 500))
    conn.ackSendBuf(2500)

    #expect(conn.retransmitCount == 0, "RetransmitCount should reset to 0 after ACK progress, got \(conn.retransmitCount)")

    // No-op ACK should not reset
    conn.retransmitCount = 2
    conn.ackSendBuf(2500)
    #expect(conn.retransmitCount == 2, "RetransmitCount should not reset on no-op ACK, got \(conn.retransmitCount)")
}

// MARK: - TestInvariants

@Test func testInvariantsNoCrash() {
    let gwIP = ipToUInt32("192.168.65.1")
    let vmIP = ipToUInt32("192.168.65.2")

    let cfg = makeConfig(listenPort: 8080, gatewayIP: gwIP)
    let ts = TCPState(cfg: cfg)
    ts.listen { _ in }

    doHandshake(ts, vmIP: vmIP, gwIP: gwIP, srcPort: 12345, dstPort: 8080)
    #expect(ts.connectionCount() == 1)

    // checkInvariants should not fatalError for a healthy connection
    ts.checkInvariants()
}

// MARK: - TestChecksum

@Test func testChecksum() {
    let srcIP = ipToUInt32("192.168.65.2")
    let dstIP = ipToUInt32("192.168.65.1")

    let tcpData: [UInt8] = [
        0x30, 0x39, 0x1F, 0x90, // srcPort=12345, dstPort=8080
        0x00, 0x00, 0x03, 0xE8, // seq=1000
        0x00, 0x00, 0x00, 0x00, // ack=0
        0x50, 0x02, 0xFF, 0xFF, // dataOffset=20, flags=SYN, window=65535
        0x00, 0x00, 0x00, 0x00, // checksum=0, urgent=0
    ]

    let cs = tcpChecksum(srcIP: srcIP, dstIP: dstIP, tcpData: tcpData)
    // Checksum should be non-zero for valid TCP data
    #expect(cs != 0, "TCP checksum should be non-zero")
}

// MARK: - TestIPConversion

@Test func testIPConversion() {
    let ip = ipToUInt32("192.168.65.1")
    #expect(ip == 0xC0A84101, "expected 0xC0A84101, got \(String(ip, radix: 16))")
    #expect(ipString(ip) == "192.168.65.1")
}

// MARK: - TestMultipleConnections

@Test func testMultipleConnections() {
    let gwIP = ipToUInt32("192.168.65.1")
    let vmIP = ipToUInt32("192.168.65.2")

    let cfg = makeConfig(listenPort: 8080, gatewayIP: gwIP)
    let ts = TCPState(cfg: cfg)
    ts.listen { _ in }

    // Two handshakes from different ports
    doHandshake(ts, vmIP: vmIP, gwIP: gwIP, srcPort: 12345, dstPort: 8080)
    doHandshake(ts, vmIP: vmIP, gwIP: gwIP, srcPort: 12346, dstPort: 8080)

    #expect(ts.connectionCount() == 2, "expected 2 connections, got \(ts.connectionCount())")
    #expect(ts.established.count == 2, "expected 2 Established, got \(ts.established.count)")
}

// MARK: - TestBufferWraparound

@Test func testBufferWraparound() {
    let conn = TCPConn(tuple: Tuple(srcIP: 0, dstIP: 0, srcPort: 0, dstPort: 0),
                       irs: 0, iss: 1000, window: 65535, bufSize: 100)

    // Fill buffer
    let data = [UInt8](repeating: 0xAA, count: 100)
    let n1 = conn.writeSendBuf(data)
    #expect(n1 == 100, "wrote \(n1), expected 100")

    // Read half
    conn.sndNxt = conn.iss + 50
    conn.ackSendBuf(conn.iss + 50)
    #expect(conn.sendAvail == 50)

    // Write more → wraps around
    let more = [UInt8](repeating: 0xBB, count: 30)
    let n2 = conn.writeSendBuf(more)
    #expect(n2 == 30, "wrote \(n2), expected 30")
    #expect(conn.sendAvail == 80)
}

// MARK: - TestTupleReversal

@Test func testTupleReversal() {
    let a = Tuple(srcIP: 0x0A000001, dstIP: 0x0A000002, srcPort: 1234, dstPort: 5678)
    let b = a.reversed()

    #expect(b.srcIP == 0x0A000002)
    #expect(b.dstIP == 0x0A000001)
    #expect(b.srcPort == 5678)
    #expect(b.dstPort == 1234)
    #expect(a.reversed().reversed() == a)
}

// MARK: - TestTCPHeaderParse

@Test func testTCPHeaderParse() {
    let raw: [UInt8] = [
        0x30, 0x39, // srcPort=12345
        0x1F, 0x90, // dstPort=8080
        0x00, 0x00, 0x03, 0xE8, // seq=1000
        0x00, 0x00, 0x00, 0x00, // ack=0
        0x50,       // dataOffset=20 (5<<4)
        0x02,       // flags=SYN
        0xFF, 0xFF, // window=65535
        0x00, 0x00, // checksum=0
        0x00, 0x00, // urgent=0
    ]

    guard let h = TCPHeader.parse(raw) else {
        fatalError("TCPHeader.parse returned nil")
    }
    #expect(h.srcPort == 12345)
    #expect(h.dstPort == 8080)
    #expect(h.seqNum == 1000)
    #expect(h.ackNum == 0)
    #expect(h.dataOffset == 20)
    #expect(h.isSYN())
    #expect(!h.isACK())
    #expect(!h.isFIN())
    #expect(!h.isRST())
}

// MARK: - TestTCPHeaderMarshalRoundtrip

@Test func testTCPHeaderMarshalRoundtrip() {
    let h = TCPHeader(srcPort: 12345, dstPort: 8080, seqNum: 1000, ackNum: 0,
                      dataOffset: 20, flags: TCPFlag.syn,
                      windowSize: 65535, checksum: 0, urgentPtr: 0)
    let marshaled = h.marshal()
    guard let parsed = TCPHeader.parse(marshaled) else {
        fatalError("parse of marshaled header returned nil")
    }
    #expect(parsed.srcPort == h.srcPort)
    #expect(parsed.dstPort == h.dstPort)
    #expect(parsed.seqNum == h.seqNum)
    #expect(parsed.ackNum == h.ackNum)
    #expect(parsed.flags == h.flags)
    #expect(parsed.windowSize == h.windowSize)
}

// MARK: - Regression: findConn excludes TimeWait

@Test func testFindConnExcludesTimeWait() {
    let gwIP = ipToUInt32("192.168.65.1")
    let vmIP = ipToUInt32("192.168.65.2")

    let cfg = makeConfig(gatewayIP: gwIP)
    let ts = TCPState(cfg: cfg)

    let tuple = Tuple(srcIP: gwIP, dstIP: vmIP, srcPort: 32770, dstPort: 22)
    let conn = ts.activeOpen(tuple: tuple, vmWindow: 65535)

    // Move connection directly into TimeWait (bypassing normal lifecycle)
    ts.synSent[tuple] = nil
    ts.timeWait[tuple] = conn

    // findConn should NOT find the connection in TimeWait
    #expect(ts.findConn(tuple) == nil, "findConn should exclude TimeWait connections")

    // hasConn should also return false for TimeWait
    #expect(!ts.hasConn(tuple), "hasConn should return false for TimeWait connections")
}

// MARK: - Regression: established→CloseWait preserves out-of-order segments

@Test func testEstablishedToCloseWaitPreservesOutOfOrderSegments() {
    let gwIP = ipToUInt32("192.168.65.1")
    let vmIP = ipToUInt32("192.168.65.2")

    let cfg = makeConfig(listenPort: 8080, gatewayIP: gwIP)
    let ts = TCPState(cfg: cfg)
    ts.listen { _ in }

    // Manually create connection in Established to avoid handshake uncertainty
    let tuple = Tuple(srcIP: gwIP, dstIP: vmIP, srcPort: 8080, dstPort: 22345)
    let iss: UInt32 = 50000
    let irs: UInt32 = 1000
    let conn = TCPConn(tuple: tuple, irs: irs, iss: iss, window: 65535, bufSize: 65536)
    conn.rcvNxt = irs + 1  // 1001
    conn.sndUna = iss + 1
    conn.sndNxt = iss + 1
    conn.lastActivityTick = ts.tick
    ts.established[tuple] = conn

    let rcvNxtBefore = conn.rcvNxt  // 1001

    // Inject out-of-order data segment (seq > rcvNxt, gap of 100 bytes)
    let oooPayload = Array("out-of-order-data".utf8)
    let oooSeg = fakeSegment(srcIP: vmIP, dstIP: gwIP, srcPort: 22345, dstPort: 8080,
                              seq: rcvNxtBefore + 100, ack: iss + 1,
                              flags: TCPFlag.ack, payload: oooPayload)
    ts.injectSegment(oooSeg)

    // Inject in-order FIN (seq == rcvNxt, triggers transition to CloseWait)
    let finSeg = fakeSegment(srcIP: vmIP, dstIP: gwIP, srcPort: 22345, dstPort: 8080,
                              seq: rcvNxtBefore, ack: iss + 1,
                              flags: TCPFlag.ack | TCPFlag.fin)
    ts.injectSegment(finSeg)

    ts.deliberate(now: Date())

    // Should be in CloseWait
    #expect(ts.closeWait[conn.tuple] != nil,
            "expected conn in CloseWait. Established=\(ts.established.count) CloseWait=\(ts.closeWait.count)")

    // Out-of-order segment should be preserved in pendingSegs
    #expect(!conn.pendingSegs.isEmpty,
            "out-of-order segments should be preserved in pendingSegs, but it's empty")

    let hasOOO = conn.pendingSegs.contains { seg in
        !seg.payload.isEmpty && seg.header.seqNum == rcvNxtBefore + 100
    }
    #expect(hasOOO, "out-of-order segment was lost during Established→CloseWait transition")
}

// MARK: - Regression: appClose is idempotent (duplicate appClose regression)

@Test func testAppCloseIdempotent() {
    let gwIP = ipToUInt32("192.168.65.1")
    let vmIP = ipToUInt32("192.168.65.2")

    let cfg = makeConfig(listenPort: 8080, gatewayIP: gwIP)
    let ts = TCPState(cfg: cfg)
    ts.listen { _ in }

    doHandshake(ts, vmIP: vmIP, gwIP: gwIP, srcPort: 32345, dstPort: 8080)
    guard let conn = firstConn(in: ts.established) else {
        fatalError("no connection in Established")
    }

    // appCloses is a Set, so duplicate appClose should be idempotent
    ts.appClose(tuple: conn.tuple)
    #expect(ts.appCloses.count == 1, "expected 1 entry in appCloses")

    // Second call should not change count
    ts.appClose(tuple: conn.tuple)
    #expect(ts.appCloses.count == 1, "duplicate appClose should be idempotent (Set semantics)")

    // Process the close
    ts.deliberate(now: Date())

    // Connection should have sent FIN (moved to FinWait1)
    let inFinWait1 = ts.finWait1[conn.tuple] != nil
    let inCloseWait = ts.closeWait[conn.tuple] != nil
    #expect(inFinWait1 || inCloseWait,
            "connection should be in FinWait1 or CloseWait after appClose")
}
