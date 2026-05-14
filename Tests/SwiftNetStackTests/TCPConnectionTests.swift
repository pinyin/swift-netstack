import Testing
@testable import SwiftNetStack
import Darwin

// MARK: - peekRetransmitData ignores sendQueueSent

@Test func peekRetransmitData_ignores_sendQueueSent() {
    var conn = makeTestConnection()

    // Write known data into sendQueue
    let data: [UInt8] = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE]
    conn.writeSendBuf(data, data.count)

    // Simulate: all data was "sent" but not acknowledged
    conn.sendQueueSent = data.count  // all 5 bytes sent
    conn.snd.nxt = conn.snd.nxt &+ UInt32(data.count)

    // peekSendData should return nil (nothing unsent)
    #expect(conn.peekSendData(max: 10) == nil,
            "peekSendData nil when all bytes sent")

    // peekRetransmitData should still return the data at snd.una
    let rt = conn.peekRetransmitData(max: 10)
    #expect(rt != nil, "peekRetransmitData returns data even when all bytes sent")
    if let rt {
        #expect(rt.len == 5)
        let buf = UnsafeRawBufferPointer(start: rt.ptr, count: rt.len)
        #expect(Array(buf) == data, "peekRetransmitData returns original data")
    }
}

@Test func peekRetransmitData_respects_max() {
    var conn = makeTestConnection()
    let data = [UInt8](repeating: 0x42, count: 4096)
    conn.writeSendBuf(data, data.count)
    conn.sendQueueSent = 4096

    let rt = conn.peekRetransmitData(max: 1500)
    #expect(rt != nil)
    if let rt {
        #expect(rt.len == 1500)
    }
}

// MARK: - ackSendBuf + peekSendData interaction

@Test func ackSendBuf_partial_ack_then_peek() {
    var conn = makeTestConnection()

    let data = [UInt8](repeating: 0x77, count: 3000)
    conn.writeSendBuf(data, data.count)

    // Send 3000 bytes
    conn.sendQueueSent = 3000
    conn.snd.nxt = conn.snd.nxt &+ 3000

    // ACK first 1000 bytes
    conn.ackSendBuf(delta: 1000)

    // sendQueueSent should now be 2000, count 2000
    // peekSendData: remaining = 2000 - 2000 = 0 → nil
    #expect(conn.peekSendData(max: 1500) == nil,
            "peekSendData nil after all remaining bytes were sent")

    // peekRetransmitData: ignores sendQueueSent, reads from readPos
    // readPos is now at 1000 (dequeued 1000), count is 2000
    let rt = conn.peekRetransmitData(max: 10)
    #expect(rt != nil, "peekRetransmitData reads from readPos regardless of sendQueueSent")
    if let rt {
        // Should return data at position 1000 (0x77, the unacked portion)
        #expect(rt.len == 10)
        let buf = UnsafeRawBufferPointer(start: rt.ptr, count: 1)
        #expect(buf[0] == 0x77)
    }
}

// MARK: - sendQueueSent overflow protection

@Test func ackSendBuf_large_delta_resets_sendQueueSent() {
    var conn = makeTestConnection()
    let data = [UInt8](repeating: 0x11, count: 1000)
    conn.writeSendBuf(data, data.count)
    conn.sendQueueSent = 500  // half sent

    // ACK more than was sent (possible with delayed ACK combining acks)
    conn.ackSendBuf(delta: 800)

    // sendQueueSent should clamp to 0, not underflow
    #expect(conn.sendQueueSent == 0, "sendQueueSent clamps to 0 on large ack")
}

// MARK: - dupAckCount tracking

@Test func dupAckCount_defaults_to_zero() {
    let conn = makeTestConnection()
    #expect(conn.dupAckCount == 0)
    #expect(conn.lastAckValue == 0)
}

// MARK: - OOO reassembly buffer tests

@Test func oooBuffer_single_segment_drained_when_contiguous() async {
    let conn = makeTestConnection()
    conn.rcv.nxt = 1000

    // Buffer one segment ahead of rcv.nxt
    let data: [UInt8] = [1, 2, 3, 4, 5]
    let ok = data.withUnsafeBytes { conn.bufferOOO(seq: 1005, data: $0.baseAddress!, len: data.count) }
    #expect(ok)
    #expect(conn.oooTotalBytes == 5)

    // Should not drain — gap at 1000
    let d1 = conn.drainOOO()
    #expect(d1 == 0)

    // Simulate FSM processing: enqueue gap-filling data, advance rcv.nxt
    let gapData: [UInt8] = [0, 0, 0, 0, 0]
    _ = conn.appendExternalSend(gapData, gapData.count)
    conn.rcv.nxt = 1005

    // Now drain — OOO segment at 1005 should be contiguous
    let d2 = conn.drainOOO()
    #expect(d2 == 5)
    #expect(conn.rcv.nxt == 1010)
    #expect(conn.oooTotalBytes == 0)
    #expect(conn.oooSegments.isEmpty)

    // Verify externalSendQueue has both segments in order
    let peeked = conn.externalSendQueue.peek(max: 10)
    #expect(peeked != nil)
    if let (ptr, len) = peeked {
        #expect(len == 10)
        let buf = UnsafeRawBufferPointer(start: ptr, count: len)
        #expect(Array(buf) == [0, 0, 0, 0, 0, 1, 2, 3, 4, 5])
    }
}

@Test func oooBuffer_overlapping_segments_trimmed() async {
    let conn = makeTestConnection()

    let data1: [UInt8] = [10, 20, 30, 40, 50]
    _ = data1.withUnsafeBytes { conn.bufferOOO(seq: 100, data: $0.baseAddress!, len: data1.count) }

    // Second segment overlaps with first (starts within, extends beyond)
    let data2: [UInt8] = [40, 50, 60, 70]
    _ = data2.withUnsafeBytes { conn.bufferOOO(seq: 103, data: $0.baseAddress!, len: data2.count) }

    // Adjacent segments NOT merged — kept separate
    #expect(conn.oooSegments.count == 2)
    #expect(conn.oooTotalBytes == 7)

    // Drain
    conn.rcv.nxt = 100
    let d = conn.drainOOO()
    #expect(d == 7)
    #expect(conn.rcv.nxt == 107)

    let peeked = conn.externalSendQueue.peek(max: 7)
    #expect(peeked != nil)
    if let (ptr, len) = peeked {
        let buf = UnsafeRawBufferPointer(start: ptr, count: len)
        #expect(Array(buf) == [10, 20, 30, 40, 50, 60, 70])
    }
}

@Test func oooBuffer_contained_segment_ignored() async {
    let conn = makeTestConnection()

    let data1: [UInt8] = [1, 2, 3, 4, 5, 6, 7, 8]
    _ = data1.withUnsafeBytes { conn.bufferOOO(seq: 200, data: $0.baseAddress!, len: data1.count) }

    // Fully contained within existing segment — should be dropped
    let data2: [UInt8] = [3, 4, 5]
    _ = data2.withUnsafeBytes { conn.bufferOOO(seq: 202, data: $0.baseAddress!, len: data2.count) }

    #expect(conn.oooSegments.count == 1)
    #expect(conn.oooTotalBytes == 8)
}

@Test func oooBuffer_dup_data_before_rcvNxt_ignored() async {
    let conn = makeTestConnection()

    // seq < rcv.nxt — should not be buffered by caller,
    // but even if passed, bufferOOO handles gracefully
    let data: [UInt8] = [9, 9, 9]
    let ok = data.withUnsafeBytes { conn.bufferOOO(seq: 50, data: $0.baseAddress!, len: data.count) }
    #expect(ok)
}

@Test func oooBuffer_multiple_gaps() async {
    let conn = makeTestConnection()

    // Buffer three segments with two gaps
    _ = [UInt8]([1, 1]).withUnsafeBytes { conn.bufferOOO(seq: 10, data: $0.baseAddress!, len: 2) }  // 10-11
    _ = [UInt8]([3, 3, 3]).withUnsafeBytes { conn.bufferOOO(seq: 15, data: $0.baseAddress!, len: 3) }  // 15-17
    _ = [UInt8]([2, 2, 2]).withUnsafeBytes { conn.bufferOOO(seq: 12, data: $0.baseAddress!, len: 3) }  // 12-14 — fills gap

    // Adjacent segments kept separate (no merge): three segments covering 10-17
    #expect(conn.oooSegments.count == 3)
    #expect(conn.oooTotalBytes == 8)

    conn.rcv.nxt = 10
    let d = conn.drainOOO()
    #expect(d == 8)
    #expect(conn.rcv.nxt == 18)
}

@Test func oooBuffer_drain_respects_max_bytes() async {
    let conn = makeTestConnection()
    let bigData = [UInt8](repeating: 0xFF, count: TCPConnection.oooMaxBytes + 1)
    let ok = bigData.withUnsafeBytes { conn.bufferOOO(seq: 100, data: $0.baseAddress!, len: bigData.count) }
    #expect(!ok, "Should reject data larger than oooMaxBytes")
    #expect(conn.oooTotalBytes == 0)
}

@Test func oooBuffer_new_segment_starts_within_but_ends_after_existing() async {
    let conn = makeTestConnection()

    // Existing: seq=100, [A,B,C] (covers 100-102)
    let data1: [UInt8] = [0x41, 0x42, 0x43]  // A, B, C
    _ = data1.withUnsafeBytes { conn.bufferOOO(seq: 100, data: $0.baseAddress!, len: data1.count) }

    // New: seq=102, [C,D,E,F,G] (covers 102-106, start within existing)
    let data2: [UInt8] = [0x43, 0x44, 0x45, 0x46, 0x47]  // C, D, E, F, G
    _ = data2.withUnsafeBytes { conn.bufferOOO(seq: 102, data: $0.baseAddress!, len: data2.count) }

    // Adjacent segments kept separate (not merged): 2 segments, 7 bytes total
    #expect(conn.oooSegments.count == 2, "Should have 2 segments (adjacent, not merged)")
    #expect(conn.oooTotalBytes == 7, "Should have 7 bytes total")

    conn.rcv.nxt = 100
    let d = conn.drainOOO()
    #expect(d == 7)
    #expect(conn.rcv.nxt == 107)

    let peeked = conn.externalSendQueue.peek(max: 7)
    #expect(peeked != nil)
    if let (ptr, len) = peeked {
        let buf = UnsafeRawBufferPointer(start: ptr, count: len)
        #expect(Array(buf) == [0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47])
    }
}

// MARK: - helpers

private func makeTestConnection() -> TCPConnection {
    TCPConnection(
        connectionID: 1,
        posixFD: -1,  // not used in these tests
        state: .established,
        vmMAC: MACAddress(0x00, 0x11, 0x22, 0x33, 0x44, 0x55),
        vmIP: IPv4Address(100, 64, 1, 182),
        vmPort: 12345,
        dstIP: IPv4Address(192, 168, 3, 16),
        dstPort: 7777,
        endpointID: 0,
        hostMAC: MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF)
    )
}
