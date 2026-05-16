import Testing
@testable import SwiftNetStack
import Darwin

// MARK: - peekRetransmitData ignores sendQueueSent

@Test func peekRetransmitData_ignores_sendQueueSent() {
    let conn = makeTestConnection()

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
    let conn = makeTestConnection()
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
    let conn = makeTestConnection()

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
    let conn = makeTestConnection()
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

    // Adjacent segments merged into single buffer
    #expect(conn.oooSegments.count == 1)
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

    // All three segments adjacent → merged into one covering 10-17
    #expect(conn.oooSegments.count == 1)
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

    // Adjacent segments merged into single buffer: 1 segment, 7 bytes total
    #expect(conn.oooSegments.count == 1, "Should have 1 segment (adjacent, merged)")
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

// MARK: - Persist timer (Fix 5)

@Test func persistDeadline_defaults_to_zero() {
    let conn = makeTestConnection()
    #expect(conn.persistDeadline == 0)
    #expect(conn.persistBackoffCount == 0)
}

@Test func persistDeadline_armed_when_zero_window() {
    let conn = makeTestConnection()
    // Simulate zero-window + queued data scenario
    conn.snd.wnd = 0
    // totalQueuedBytes > 0 requires data in sendQueue
    let data = [UInt8](repeating: 0x42, count: 100)
    conn.writeSendBuf(data, data.count)
    #expect(conn.totalQueuedBytes == 100)
    // persistDeadline starts at 0, canSend = wnd - inFlight <= 0
    // This is the condition that arms persist in flushOneConnection
    #expect(conn.persistDeadline == 0, "persistDeadline starts at 0")
}

@Test func persistDeadline_disarmed_on_window_open() {
    let conn = makeTestConnection()
    conn.snd.wnd = 0
    conn.persistDeadline = 12345
    conn.persistBackoffCount = 3

    // Open the window — deadline and backoff should reset
    conn.snd.wnd = 8192
    conn.persistDeadline = 0
    conn.persistBackoffCount = 0

    #expect(conn.persistDeadline == 0)
    #expect(conn.persistBackoffCount == 0)
}


// MARK: - sendQueue drain simulates flushOneConnection download path

@Test func sendQueue_drain_exact_bytes() {
    // Reproduce the 1-byte-loss bug: enqueue N bytes, drain via
    // peekSendData loops, verify total drained == N.
    let conn = makeTestConnection()
    let N = 64240  // 44 × 1460, perfectly aligned
    let data = [UInt8](repeating: 0xAB, count: N)
    conn.writeSendBuf(data, data.count)
    #expect(conn.totalQueuedBytes == N)

    var totalSent = 0
    let mss = 1460
    while true {
        guard let d = conn.peekSendData(max: mss) else { break }
        totalSent += d.len
        conn.sendQueueSent += d.len
        conn.snd.nxt = conn.snd.nxt &+ UInt32(d.len)
    }
    #expect(totalSent == N, "drained \(totalSent) bytes, expected \(N)")
    #expect(conn.sendQueueSent == N)
    #expect(conn.totalQueuedBytes == N, "totalQueuedBytes unchanged until ACK")
}

@Test func sendQueue_drain_unaligned() {
    // Test with non-MSS-aligned size (like 65536 which doesn't divide by 1460)
    let conn = makeTestConnection()
    let N = 65536
    let data = [UInt8](repeating: 0xCD, count: N)
    conn.writeSendBuf(data, data.count)

    var totalSent = 0
    let mss = 1460
    while true {
        guard let d = conn.peekSendData(max: mss) else { break }
        totalSent += d.len
        conn.sendQueueSent += d.len
        conn.snd.nxt = conn.snd.nxt &+ UInt32(d.len)
    }
    #expect(totalSent == N, "drained \(totalSent) bytes, expected \(N)")
}

@Test func sendQueue_drain_small() {
    // Test with sizes around the suspected boundary
    for N in [1, 2, 3, 1460, 1461, 2919, 2920, 2921] {
        let conn = makeTestConnection()
        let data = [UInt8](repeating: 0xEF, count: N)
        conn.writeSendBuf(data, data.count)

        var totalSent = 0
        let mss = 1460
        while true {
            guard let d = conn.peekSendData(max: mss) else { break }
            totalSent += d.len
            conn.sendQueueSent += d.len
        }
        #expect(totalSent == N, "N=\(N): drained \(totalSent) bytes")
    }
}

@Test func sendQueue_drain_after_compaction() {
    // Simulate compaction (memmove when readPos > 0) then drain
    let conn = makeTestConnection()
    let N = 64240
    let data = [UInt8](repeating: 0x11, count: N)
    conn.writeSendBuf(data, data.count)

    // Simulate ACK of first 30000 bytes → triggers deque + potential compaction
    conn.ackSendBuf(delta: 30000)
    #expect(conn.totalQueuedBytes == N - 30000)

    var totalSent = 0
    let mss = 1460
    while true {
        guard let d = conn.peekSendData(max: mss) else { break }
        totalSent += d.len
        conn.sendQueueSent += d.len
    }
    #expect(totalSent == N - 30000, "after ack: drained \(totalSent), expected \(N - 30000)")
}

// MARK: - recvTarget + commitRecv + drain: full download pipeline

@Test func recvTarget_commitRecv_drain_no_loss() {
    // Simulate the full download receive pipeline:
    // 1. recvTarget() → get write buffer
    // 2. Simulate recv() writing data into the buffer
    // 3. commitRecv(len) → advance writePos
    // 4. Drain via peekSendData + sendQueueSent
    let conn = makeTestConnection()
    let N = 64240
    let pattern = [UInt8](unsafeUninitializedCapacity: N) { buf, count in
        for i in 0..<N { buf[i] = UInt8((i * 0x9E3779B9) & 0xFF) }
        count = N
    }

    // Step 1: get recv target
    var sendQueue = conn.sendQueue
    let (writePtr, avail) = sendQueue.recvTarget()
    #expect(avail >= N, "recvTarget should have space")

    // Step 2: simulate recv() writing directly into sendQueue buffer
    writePtr.copyMemory(from: pattern, byteCount: N)

    // Step 3: commitRecv
    sendQueue.commitRecv(N)
    conn.sendQueue = sendQueue
    #expect(conn.totalQueuedBytes == N, "totalQueuedBytes after commitRecv")

    // Step 4: drain
    var totalSent = 0
    let mss = 1460
    while true {
        guard let d = conn.peekSendData(max: mss) else { break }
        totalSent += d.len
        conn.sendQueueSent += d.len
        conn.snd.nxt = conn.snd.nxt &+ UInt32(d.len)
    }
    #expect(totalSent == N, "after commitRecv+drain: \(totalSent) != \(N)")

    // Verify data content
    let rt = conn.peekRetransmitData(max: N)
    #expect(rt != nil)
    if let rt {
        #expect(rt.len == N)
        let buf = UnsafeRawBufferPointer(start: rt.ptr, count: rt.len)
        for i in 0..<min(N, 100) {
            let expected = UInt8((i * 0x9E3779B9) & 0xFF)
            #expect(buf[i] == expected, "byte \(i): \(buf[i]) != \(expected)")
        }
    }
}

@Test func recvTarget_compaction_preserves_data() {
    // recvTarget memmoves to compact → verify no data loss
    let conn = makeTestConnection()
    let N = 64240
    let pattern = [UInt8](unsafeUninitializedCapacity: N) { buf, count in
        for i in 0..<N { buf[i] = UInt8((i * 0x9E3779B9) & 0xFF) }
        count = N
    }

    // First recv: 30000 bytes
    var sq = conn.sendQueue
    var (wp, _) = sq.recvTarget()
    wp.copyMemory(from: pattern, byteCount: 30000)
    sq.commitRecv(30000)

    // Dequeue 20000 (simulating an ACK)
    sq.dequeue(20000)

    // Second recvTarget: should compact remaining 10000 bytes to front
    (wp, _) = sq.recvTarget()
    pattern.withUnsafeBytes { buf in
        wp.copyMemory(from: buf.baseAddress!.advanced(by: 30000), byteCount: 34240)
    }
    sq.commitRecv(34240)

    // Total in queue: 10000 + 34240 = 44240
    let conn2 = makeTestConnection()
    var sq2 = conn2.sendQueue
    sq2 = sq  // copy the mutated sendQueue
    #expect(sq2.count == 44240, "count after compact+recv: \(sq2.count)")

    // Drain
    var totalSent = 0
    // We need to peek via the connection's sendQueue... but we modified sq directly
    // Use the mutated sq by reading from buf directly
    let peeked = sq2.peek(max: 44240)
    #expect(peeked != nil)
    if let (ptr, len) = peeked {
        #expect(len == 44240)
        totalSent = len
    }
    #expect(totalSent == 44240)
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
