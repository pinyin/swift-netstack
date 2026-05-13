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
