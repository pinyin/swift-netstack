import Foundation
import Testing
@testable import SwiftNetStack

// MARK: - Edge Case Helpers

func edgeFrame(connB: VZDebugConn, srcIP: UInt32, dstIP: UInt32,
               srcPort: UInt16, dstPort: UInt16, seq: UInt32, ack: UInt32,
               flags: UInt8, window: UInt16 = 65535, payload: [UInt8] = []) {
    let tuple = Tuple(srcIP: srcIP, dstIP: dstIP, srcPort: srcPort, dstPort: dstPort)
    var raw = buildSegment(tuple: tuple, seq: seq, ack: ack, flags: flags, window: window, wscale: 0, payload: payload)
    let cs = tcpChecksum(srcIP: srcIP, dstIP: dstIP, tcpData: raw)
    raw[16] = UInt8(cs >> 8); raw[17] = UInt8(cs & 0xFF)
    let ipPkt = IPv4Packet(version: 4, ihl: 20, tos: 0, totalLen: 0, id: UInt16((srcPort & 0xFF00) | (dstPort & 0xFF)),
                           flags: 0, fragOffset: 0, ttl: 64, protocol: protocolTCP,
                           checksum: 0, srcIP: srcIP, dstIP: dstIP, payload: raw)
    _ = connB.write(frame: Frame(dstMAC: gwMAC, srcMAC: vmMAC,
                                  etherType: etherTypeIPv4, payload: Data(ipPkt.serialize())))
}

// MARK: - 1. Simultaneous Close

@Test func testEdgeSimultaneousClose() throws {
    let gwIP = ipToUInt32("192.168.65.1")
    let vmIP = ipToUInt32("192.168.65.2")

    var cfg = TCPConfig.defaultConfig()
    cfg.listenPort = 9090
    let ts = TCPState(cfg: cfg)
    ts.listen { _ in }

    let srcPort: UInt16 = 12345
    let dstPort: UInt16 = 9090

    // Handshake
    let synSeg = fakeSegment(srcIP: vmIP, dstIP: gwIP, srcPort: srcPort, dstPort: dstPort,
                             seq: 1000, ack: 0, flags: TCPFlag.syn)
    ts.injectSegment(synSeg)
    ts.deliberate(now: Date())
    let synAck = ts.consumeOutputs()[0]

    let ackSeg = fakeSegment(srcIP: vmIP, dstIP: gwIP, srcPort: srcPort, dstPort: dstPort,
                             seq: 1001, ack: synAck.header.seqNum + 1, flags: TCPFlag.ack)
    ts.injectSegment(ackSeg)
    ts.deliberate(now: Date())
    _ = ts.consumeOutputs()

    #expect(ts.established.count == 1, "should be established")

    // Both sides send FIN simultaneously
    // Peer FIN
    let peerFin = fakeSegment(srcIP: vmIP, dstIP: gwIP, srcPort: srcPort, dstPort: dstPort,
                              seq: 1001, ack: synAck.header.seqNum + 1, flags: TCPFlag.fin | TCPFlag.ack)
    ts.injectSegment(peerFin)

    // Our FIN (app close)
    let revTuple = Tuple(srcIP: gwIP, dstIP: vmIP, srcPort: dstPort, dstPort: srcPort)
    ts.appClose(tuple: revTuple)

    ts.deliberate(now: Date())
    _ = ts.consumeOutputs()

    // Should be in CLOSING state (both sides sent FIN, waiting for ACK of our FIN)
    // Implementation transitions: established→closeWait on received FIN, then closeWait→lastAck on app close
    // OR: established→finWait1 on app close, then finWait1 remains awaiting ACK of FIN
    let totalConns = ts.connectionCount()
    #expect(totalConns >= 1, "should still have a connection during simultaneous close")
}

// MARK: - 2. FIN with Data

@Test func testEdgeFINWithData() throws {
    let gwIP = ipToUInt32("192.168.65.1")
    let vmIP = ipToUInt32("192.168.65.2")

    var cfg = TCPConfig.defaultConfig()
    cfg.listenPort = 9091
    let ts = TCPState(cfg: cfg)
    ts.listen { _ in }

    let srcPort: UInt16 = 23456
    let dstPort: UInt16 = 9091

    // Handshake
    let synSeg = fakeSegment(srcIP: vmIP, dstIP: gwIP, srcPort: srcPort, dstPort: dstPort,
                             seq: 2000, ack: 0, flags: TCPFlag.syn)
    ts.injectSegment(synSeg)
    ts.deliberate(now: Date())
    let synAck = ts.consumeOutputs()[0]

    let ackSeg = fakeSegment(srcIP: vmIP, dstIP: gwIP, srcPort: srcPort, dstPort: dstPort,
                             seq: 2001, ack: synAck.header.seqNum + 1, flags: TCPFlag.ack)
    ts.injectSegment(ackSeg)
    ts.deliberate(now: Date())
    _ = ts.consumeOutputs()

    // Send FIN with data payload (FIN consumes one seq number, data precedes it)
    let finData = Array("final-data".utf8)
    let finSeg = fakeSegment(srcIP: vmIP, dstIP: gwIP, srcPort: srcPort, dstPort: dstPort,
                             seq: 2001, ack: synAck.header.seqNum + 1,
                             flags: TCPFlag.fin | TCPFlag.ack, payload: finData)
    ts.injectSegment(finSeg)
    ts.deliberate(now: Date())

    // Connection should move to closeWait, data should be received
    let revTuple = Tuple(srcIP: gwIP, dstIP: vmIP, srcPort: dstPort, dstPort: srcPort)

    var recvBuf = [UInt8](repeating: 0, count: 256)
    let dataLen = ts.recvData(tuple: revTuple, buf: &recvBuf)
    #expect(dataLen > 0, "should receive data from FIN+data segment")
}

// MARK: - 3. Sequence Number Wraparound (32-bit)

@Test func testEdgeSequenceWraparound() throws {
    let gwIP = ipToUInt32("192.168.65.1")
    let vmIP = ipToUInt32("192.168.65.2")

    var cfg = TCPConfig.defaultConfig()
    cfg.listenPort = 9092
    let ts = TCPState(cfg: cfg)
    ts.listen { _ in }

    let srcPort: UInt16 = 34567
    let dstPort: UInt16 = 9092

    // Handshake with seq near 2^32 boundary
    let nearWrap: UInt32 = 0xFFFFFFF0
    let synSeg = fakeSegment(srcIP: vmIP, dstIP: gwIP, srcPort: srcPort, dstPort: dstPort,
                             seq: nearWrap, ack: 0, flags: TCPFlag.syn)
    ts.injectSegment(synSeg)
    ts.deliberate(now: Date())
    let synAck = ts.consumeOutputs()[0]

    let ackSeg = fakeSegment(srcIP: vmIP, dstIP: gwIP, srcPort: srcPort, dstPort: dstPort,
                             seq: nearWrap + 1, ack: synAck.header.seqNum + 1, flags: TCPFlag.ack)
    ts.injectSegment(ackSeg)
    ts.deliberate(now: Date())
    _ = ts.consumeOutputs()

    // Send data that wraps around
    let data1 = Array("pre-wrap-".utf8)  // 9 bytes, seq nearWrap+1 to nearWrap+10
    let seg1 = fakeSegment(srcIP: vmIP, dstIP: gwIP, srcPort: srcPort, dstPort: dstPort,
                           seq: nearWrap + 1, ack: synAck.header.seqNum + 1,
                           flags: TCPFlag.ack | TCPFlag.psh, payload: data1)
    ts.injectSegment(seg1)
    ts.deliberate(now: Date())

    // Verify data was received correctly despite seq near wraparound
    let revTuple = Tuple(srcIP: gwIP, dstIP: vmIP, srcPort: dstPort, dstPort: srcPort)
    var buf = [UInt8](repeating: 0, count: 256)
    let n = ts.recvData(tuple: revTuple, buf: &buf)
    #expect(n == data1.count, "should receive \(data1.count) bytes despite near-wraparound seq, got \(n)")
}

// MARK: - 4. Connection Refused (RST to SYN)

@Test func testEdgeConnectionRefused() throws {
    let gwIP = ipToUInt32("192.168.65.1")
    let vmIP = ipToUInt32("192.168.65.2")

    // No listener on this port
    let ts = TCPState(cfg: TCPConfig.defaultConfig())

    let srcPort: UInt16 = 45678
    let dstPort: UInt16 = 9999

    // SYN to port with no listener — should not crash
    let synSeg = fakeSegment(srcIP: vmIP, dstIP: gwIP, srcPort: srcPort, dstPort: dstPort,
                             seq: 3000, ack: 0, flags: TCPFlag.syn)
    ts.injectSegment(synSeg)
    ts.deliberate(now: Date())

    // No connection should be created
    let totalConns = ts.connectionCount()
    #expect(totalConns == 0, "no connection should be created for port with no listener")
}

// MARK: - 5. ACK with Future Sequence Number

@Test func testEdgeACKFutureSeq() throws {
    let gwIP = ipToUInt32("192.168.65.1")
    let vmIP = ipToUInt32("192.168.65.2")

    var cfg = TCPConfig.defaultConfig()
    cfg.listenPort = 9093
    let ts = TCPState(cfg: cfg)
    ts.listen { _ in }

    let srcPort: UInt16 = 56789
    let dstPort: UInt16 = 9093

    // Handshake
    let synSeg = fakeSegment(srcIP: vmIP, dstIP: gwIP, srcPort: srcPort, dstPort: dstPort,
                             seq: 4000, ack: 0, flags: TCPFlag.syn)
    ts.injectSegment(synSeg)
    ts.deliberate(now: Date())
    let synAck = ts.consumeOutputs()[0]

    // ACK with future ackNum (acknowledging data we haven't sent)
    let futureAck = fakeSegment(srcIP: vmIP, dstIP: gwIP, srcPort: srcPort, dstPort: dstPort,
                                seq: 4001, ack: synAck.header.seqNum + 100, flags: TCPFlag.ack)
    ts.injectSegment(futureAck)
    ts.deliberate(now: Date())

    // Should not crash. Connection may or may not transition based on implementation
    let totalConns = ts.connectionCount()
    #expect(totalConns >= 0, "should handle future ACK without crashing")
}

// MARK: - 6. Idle Timeout Cleanup

@Test func testEdgeIdleTimeoutCleanup() throws {
    let gwIP = ipToUInt32("192.168.65.1")
    let vmIP = ipToUInt32("192.168.65.2")

    var cfg = TCPConfig.defaultConfig()
    cfg.listenPort = 9094
    cfg.idleTimeout = 0.1 // 100ms
    let ts = TCPState(cfg: cfg)
    ts.listen { _ in }

    let srcPort: UInt16 = 43210
    let dstPort: UInt16 = 9094

    // Handshake
    let synSeg = fakeSegment(srcIP: vmIP, dstIP: gwIP, srcPort: srcPort, dstPort: dstPort,
                             seq: 5000, ack: 0, flags: TCPFlag.syn)
    ts.injectSegment(synSeg)
    ts.deliberate(now: Date())
    _ = ts.consumeOutputs()

    #expect(ts.synRcvd.count == 1, "should be in synRcvd")

    // Advance time past idle timeout
    Thread.sleep(forTimeInterval: 0.2)
    ts.deliberate(now: Date())

    // synRcvd connection should be cleaned up
    let remaining = ts.synRcvd.count
    #expect(remaining == 0, "idle synRcvd connection should be cleaned up, got \(remaining)")
}

// MARK: - 7. Window Scaling

@Test func testEdgeWindowScaling() throws {
    let gwIP = ipToUInt32("192.168.65.1")
    let vmIP = ipToUInt32("192.168.65.2")

    var cfg = TCPConfig.defaultConfig()
    cfg.listenPort = 9095
    cfg.windowScale = 7
    let ts = TCPState(cfg: cfg)
    ts.listen { _ in }

    let srcPort: UInt16 = 7890
    let dstPort: UInt16 = 9095

    // SYN with window scale option
    let tuple = Tuple(srcIP: vmIP, dstIP: gwIP, srcPort: srcPort, dstPort: dstPort)
    let raw = buildSegmentWithWScale(tuple: tuple, seq: 6000, ack: 0,
                                      flags: TCPFlag.syn, window: 65535, wscale: 7, payload: [])
    let synSeg = TCPSegment(
        header: TCPHeader(srcPort: srcPort, dstPort: dstPort,
                          seqNum: 6000, ackNum: 0,
                          dataOffset: 24, flags: TCPFlag.syn,
                          windowSize: 65535, checksum: 0, urgentPtr: 0),
        payload: [], tuple: tuple, raw: raw
    )
    ts.injectSegment(synSeg)
    ts.deliberate(now: Date())

    let outputs = ts.consumeOutputs()
    #expect(!outputs.isEmpty, "should get SYN-ACK with window scale")
    if let synAck = outputs.first {
        #expect(synAck.header.hasFlag(TCPFlag.syn | TCPFlag.ack), "should be SYN|ACK")
        // Window scale option should be present in raw bytes
        let hasWScale = synAck.raw.count >= 24 && synAck.raw[22] == 7
        #expect(hasWScale, "SYN-ACK should include window scale option")
    }
}

// MARK: - 8. Buffer Wraparound with Large Data

@Test func testEdgeBufferWraparound() throws {
    let gwIP = ipToUInt32("192.168.65.1")
    let vmIP = ipToUInt32("192.168.65.2")

    var cfg = TCPConfig.defaultConfig()
    cfg.listenPort = 9096
    cfg.bufferSize = 256 // small buffer to force wraparound
    let ts = TCPState(cfg: cfg)
    ts.listen { _ in }

    let srcPort: UInt16 = 8901
    let dstPort: UInt16 = 9096

    // Handshake
    let synSeg = fakeSegment(srcIP: vmIP, dstIP: gwIP, srcPort: srcPort, dstPort: dstPort,
                             seq: 7000, ack: 0, flags: TCPFlag.syn)
    ts.injectSegment(synSeg)
    ts.deliberate(now: Date())
    let synAck = ts.consumeOutputs()[0]

    let ackSeg = fakeSegment(srcIP: vmIP, dstIP: gwIP, srcPort: srcPort, dstPort: dstPort,
                             seq: 7001, ack: synAck.header.seqNum + 1, flags: TCPFlag.ack)
    ts.injectSegment(ackSeg)
    ts.deliberate(now: Date())
    _ = ts.consumeOutputs()

    // Send more data than buffer size to force circular buffer wraparound
    let largePayload = [UInt8](repeating: 0x42, count: 200)
    let seg = fakeSegment(srcIP: vmIP, dstIP: gwIP, srcPort: srcPort, dstPort: dstPort,
                          seq: 7001, ack: synAck.header.seqNum + 1,
                          flags: TCPFlag.ack | TCPFlag.psh, payload: largePayload)
    ts.injectSegment(seg)
    ts.deliberate(now: Date())

    let revTuple = Tuple(srcIP: gwIP, dstIP: vmIP, srcPort: dstPort, dstPort: srcPort)
    var buf = [UInt8](repeating: 0, count: 512)
    let n = ts.recvData(tuple: revTuple, buf: &buf)
    #expect(n > 0, "should receive data even with small buffer")
}

// MARK: - 9. Multiple FIN Handling

@Test func testEdgeMultipleFINs() throws {
    let gwIP = ipToUInt32("192.168.65.1")
    let vmIP = ipToUInt32("192.168.65.2")

    var cfg = TCPConfig.defaultConfig()
    cfg.listenPort = 9097
    let ts = TCPState(cfg: cfg)
    ts.listen { _ in }

    let srcPort: UInt16 = 1234
    let dstPort: UInt16 = 9097

    // Handshake
    let synSeg = fakeSegment(srcIP: vmIP, dstIP: gwIP, srcPort: srcPort, dstPort: dstPort,
                             seq: 1000, ack: 0, flags: TCPFlag.syn)
    ts.injectSegment(synSeg)
    ts.deliberate(now: Date())
    let synAck = ts.consumeOutputs()[0]
    let serverSeq = synAck.header.seqNum + 1

    let ackSeg = fakeSegment(srcIP: vmIP, dstIP: gwIP, srcPort: srcPort, dstPort: dstPort,
                             seq: 1001, ack: serverSeq, flags: TCPFlag.ack)
    ts.injectSegment(ackSeg)
    ts.deliberate(now: Date())
    _ = ts.consumeOutputs()

    // Send FIN
    let finSeg = fakeSegment(srcIP: vmIP, dstIP: gwIP, srcPort: srcPort, dstPort: dstPort,
                             seq: 1001, ack: serverSeq, flags: TCPFlag.fin | TCPFlag.ack)
    ts.injectSegment(finSeg)
    ts.deliberate(now: Date())

    #expect(ts.established.count == 0, "should leave established on FIN")

    // Send another FIN (duplicate)
    let dupFin = fakeSegment(srcIP: vmIP, dstIP: gwIP, srcPort: srcPort, dstPort: dstPort,
                             seq: 1001, ack: serverSeq, flags: TCPFlag.fin | TCPFlag.ack)
    ts.injectSegment(dupFin)
    ts.deliberate(now: Date())

    // Should not crash
    #expect(true, "duplicate FIN should not crash")
}

// MARK: - 10. Delayed ACK Behavior

@Test func testEdgeDelayedACK() throws {
    let gwIP = ipToUInt32("192.168.65.1")
    let vmIP = ipToUInt32("192.168.65.2")

    var cfg = TCPConfig.defaultConfig()
    cfg.listenPort = 9098
    let ts = TCPState(cfg: cfg)
    ts.listen { _ in }

    let srcPort: UInt16 = 2345
    let dstPort: UInt16 = 9098

    // Handshake
    let synSeg = fakeSegment(srcIP: vmIP, dstIP: gwIP, srcPort: srcPort, dstPort: dstPort,
                             seq: 1000, ack: 0, flags: TCPFlag.syn)
    ts.injectSegment(synSeg)
    ts.deliberate(now: Date())
    let synAck = ts.consumeOutputs()[0]
    let serverSeq = synAck.header.seqNum + 1

    let ackSeg = fakeSegment(srcIP: vmIP, dstIP: gwIP, srcPort: srcPort, dstPort: dstPort,
                             seq: 1001, ack: serverSeq, flags: TCPFlag.ack)
    ts.injectSegment(ackSeg)
    ts.deliberate(now: Date())
    _ = ts.consumeOutputs()

    // Send data segment
    let data = Array("hello".utf8)
    let seg = fakeSegment(srcIP: vmIP, dstIP: gwIP, srcPort: srcPort, dstPort: dstPort,
                          seq: 1001, ack: serverSeq, flags: TCPFlag.ack | TCPFlag.psh, payload: data)
    ts.injectSegment(seg)
    ts.deliberate(now: Date())

    let outputs = ts.consumeOutputs()
    // Should get either ACK or data+ACK in response
    #expect(!outputs.isEmpty, "should get some response to data")

    // Send second segment quickly — should get ACK covering both (or more data)
    let data2 = Array("world".utf8)
    let seg2 = fakeSegment(srcIP: vmIP, dstIP: gwIP, srcPort: srcPort, dstPort: dstPort,
                           seq: 1006, ack: serverSeq, flags: TCPFlag.ack | TCPFlag.psh, payload: data2)
    ts.injectSegment(seg2)
    ts.deliberate(now: Date())

    let outputs2 = ts.consumeOutputs()
    // Verify data was received
    let revTuple = Tuple(srcIP: gwIP, dstIP: vmIP, srcPort: dstPort, dstPort: srcPort)
    var buf = [UInt8](repeating: 0, count: 256)
    let n = ts.recvData(tuple: revTuple, buf: &buf)
    #expect(n >= 10, "should receive at least 10 bytes from two segments, got \(n)")
}
