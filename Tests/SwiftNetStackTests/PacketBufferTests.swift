import Testing
import Darwin
@testable import SwiftNetStack

/// Tests for PacketBuffer: zero-copy data container, COW semantics, scatter-gather I/O.
@Suite(.serialized)
struct PacketBufferTests {

    // MARK: - Init & queries

    @Test func initWithCapacityAndHeadroom() {
        let pkt = PacketBuffer(capacity: 100, headroom: 50)
        #expect(pkt.totalLength == 0)
        #expect(pkt.headroom == 50)
        #expect(pkt.isEmpty)
        #expect(pkt.tailroom >= 100)
    }

    @Test func initWithStorage() {
        let s = Storage.allocate(capacity: 200)
        let pkt = PacketBuffer(storage: s, offset: 20, length: 80)
        #expect(pkt.totalLength == 80)
        #expect(pkt.headroom == 20)
        #expect(pkt.tailroom == 200 - 20 - 80)
    }

    @Test func fromPoolWithHeadroom() {
        let pkt = PacketBuffer.from(pool: ChunkPools.pool512B, headroom: 14)
        #expect(pkt.headroom == 14)
        #expect(pkt.totalLength == 0)
        #expect(pkt.tailroom >= 512 - 14)
    }

    @Test func emptyPacketBuffer() {
        let pkt = PacketBuffer(capacity: 0)
        #expect(pkt.isEmpty)
        #expect(pkt.totalLength == 0)
        #expect(pkt.viewCount == 1)
    }

    @Test func viewCount() {
        let pkt = PacketBuffer(capacity: 100)
        #expect(pkt.viewCount == 1)
    }

    // MARK: - Append / Prepend

    @Test func appendPointerReturnsValidPointer() {
        var pkt = PacketBuffer(capacity: 100)
        guard let ptr = pkt.appendPointer(count: 10) else {
            Issue.record("appendPointer returned nil")
            return
        }
        let fill = [UInt8](repeating: 0xAB, count: 10)
        fill.withUnsafeBytes { ptr.copyMemory(from: $0.baseAddress!, byteCount: 10) }
        #expect(pkt.totalLength == 10)
    }

    @Test func prependPointerConsumesHeadroom() {
        var pkt = PacketBuffer(capacity: 100, headroom: 50)
        guard let ptr = pkt.prependPointer(count: 14) else {
            Issue.record("prependPointer returned nil")
            return
        }
        let header = [UInt8](repeating: 0xCD, count: 14)
        header.withUnsafeBytes { ptr.copyMemory(from: $0.baseAddress!, byteCount: 14) }
        #expect(pkt.totalLength == 14)
        #expect(pkt.headroom == 36)
    }

    @Test func appendBeyondTailroomReturnsNil() {
        var pkt = PacketBuffer(capacity: 64)
        #expect(pkt.appendPointer(count: 64) != nil)
        #expect(pkt.appendPointer(count: 1) == nil)
    }

    @Test func prependBeyondHeadroomReturnsNil() {
        var pkt = PacketBuffer(capacity: 100, headroom: 10)
        #expect(pkt.prependPointer(count: 20) == nil)
    }

    @Test func appendZeroDoesNothing() {
        var pkt = PacketBuffer(capacity: 50)
        _ = pkt.appendPointer(count: 50)
        let ptr = pkt.appendPointer(count: 0)
        #expect(pkt.totalLength == 50)
    }

    // MARK: - Trim

    @Test func trimFrontReducesLength() {
        var pkt = PacketBuffer(capacity: 100)
        _ = pkt.appendPointer(count: 50)
        pkt.trimFront(20)
        #expect(pkt.totalLength == 30)
    }

    @Test func trimFrontEntireViewRemovesIt() {
        var pkt = PacketBuffer(capacity: 100)
        _ = pkt.appendPointer(count: 50)
        pkt.trimFront(50)
        #expect(pkt.totalLength == 0)
        #expect(pkt.viewCount == 0)
    }

    @Test func trimBackReducesLength() {
        var pkt = PacketBuffer(capacity: 100)
        _ = pkt.appendPointer(count: 60)
        pkt.trimBack(15)
        #expect(pkt.totalLength == 45)
    }

    @Test func trimBackEntireViewRemovesIt() {
        var pkt = PacketBuffer(capacity: 100)
        _ = pkt.appendPointer(count: 50)
        pkt.trimBack(50)
        #expect(pkt.totalLength == 0)
        #expect(pkt.viewCount == 0)
    }

    // MARK: - Zero-copy read (slice)

    @Test func sliceCreatesSharedView() {
        var pkt = PacketBuffer(capacity: 100)
        guard let ptr = pkt.appendPointer(count: 50) else {
            Issue.record("appendPointer failed")
            return
        }
        for i in 0..<50 { ptr.advanced(by: i).storeBytes(of: UInt8(i), as: UInt8.self) }

        let s = pkt.slice(from: 10, length: 20)
        #expect(s.totalLength == 20)
        s.withUnsafeReadableBytes { buf in
            let bytes = [UInt8](buf)
            #expect(bytes[0] == 10)
            #expect(bytes[19] == 29)
        }
    }

    @Test func sliceFromMultipleViews() {
        var pkt = PacketBuffer(capacity: 64)
        guard let p1 = pkt.appendPointer(count: 20) else { return }
        let d1: [UInt8] = Array(0..<20).map { UInt8($0) }
        d1.withUnsafeBytes { p1.copyMemory(from: $0.baseAddress!, byteCount: 20) }

        var pkt2 = PacketBuffer(capacity: 64)
        guard let p2 = pkt2.appendPointer(count: 20) else { return }
        let d2: [UInt8] = Array(20..<40).map { UInt8($0) }
        d2.withUnsafeBytes { p2.copyMemory(from: $0.baseAddress!, byteCount: 20) }

        pkt.appendView(pkt2)

        // Slice across the boundary
        let s = pkt.slice(from: 15, length: 10)
        #expect(s.totalLength == 10)
        s.withUnsafeReadableBytes { buf in
            let bytes = [UInt8](buf)
            #expect(bytes[0] == 15)
            #expect(bytes[4] == 19)
            #expect(bytes[5] == 20)
            #expect(bytes[9] == 24)
        }
    }

    // MARK: - withUnsafeReadableBytes

    @Test func readableBytesAccess() {
        var pkt = PacketBuffer(capacity: 64)
        guard let ptr = pkt.appendPointer(count: 5) else { return }
        let data: [UInt8] = [10, 20, 30, 40, 50]
        data.withUnsafeBytes { ptr.copyMemory(from: $0.baseAddress!, byteCount: 5) }

        pkt.withUnsafeReadableBytes { buf in
            #expect([UInt8](buf) == data)
        }
    }

    @Test func readableBytesAcrossMultipleViews() {
        var combined = PacketBuffer(capacity: 64)
        for i in 0..<3 {
            var seg = PacketBuffer(capacity: 32)
            guard let ptr = seg.appendPointer(count: 4) else { return }
            let fill = [UInt8](repeating: UInt8(i), count: 4)
            fill.withUnsafeBytes { ptr.copyMemory(from: $0.baseAddress!, byteCount: 4) }
            combined.appendView(seg)
        }

        combined.withUnsafeReadableBytes { buf in
            let bytes = [UInt8](buf)
            #expect(bytes.count == 12)
            #expect(bytes[0..<4].allSatisfy { $0 == 0 })
            #expect(bytes[4..<8].allSatisfy { $0 == 1 })
            #expect(bytes[8..<12].allSatisfy { $0 == 2 })
        }
    }

    // MARK: - COW behavior

    @Test func copySharesStorage() {
        var pkt = PacketBuffer(capacity: 100)
        guard let ptr = pkt.appendPointer(count: 10) else { return }
        let data = [UInt8](repeating: 0x42, count: 10)
        data.withUnsafeBytes { ptr.copyMemory(from: $0.baseAddress!, byteCount: 10) }

        let copied = pkt
        #expect(copied.totalLength == pkt.totalLength)

        copied.withUnsafeReadableBytes { buf in
            #expect([UInt8](buf).allSatisfy { $0 == 0x42 })
        }
    }

    @Test func copyTriggersCOWOnWrite() {
        var pkt = PacketBuffer(capacity: 100)
        _ = pkt.appendPointer(count: 10)

        var cloned = pkt
        guard let ptr = cloned.appendPointer(count: 5) else {
            Issue.record("Cannot append to clone")
            return
        }
        let ff = [UInt8](repeating: 0xFF, count: 5)
        ff.withUnsafeBytes { ptr.copyMemory(from: $0.baseAddress!, byteCount: 5) }

        #expect(cloned.totalLength == 15)
        #expect(pkt.totalLength == 10)
    }

    // MARK: - appendView

    @Test func appendViewCombinesTwoBuffers() {
        var pkt1 = PacketBuffer(capacity: 100)
        guard let ptr1 = pkt1.appendPointer(count: 10) else { return }
        let d1 = [UInt8](repeating: 0xAA, count: 10)
        d1.withUnsafeBytes { ptr1.copyMemory(from: $0.baseAddress!, byteCount: 10) }

        var pkt2 = PacketBuffer(capacity: 100)
        guard let ptr2 = pkt2.appendPointer(count: 10) else { return }
        let d2 = [UInt8](repeating: 0xBB, count: 10)
        d2.withUnsafeBytes { ptr2.copyMemory(from: $0.baseAddress!, byteCount: 10) }

        pkt1.appendView(pkt2)
        #expect(pkt1.totalLength == 20)
        #expect(pkt1.viewCount == 2)
    }

    @Test func appendViewToEmpty() {
        var empty = PacketBuffer(capacity: 0)
        var pkt = PacketBuffer(capacity: 50)
        guard let ptr = pkt.appendPointer(count: 5) else { return }
        let data: [UInt8] = [1, 2, 3, 4, 5]
        data.withUnsafeBytes { ptr.copyMemory(from: $0.baseAddress!, byteCount: 5) }

        empty.appendView(pkt)
        #expect(empty.totalLength == 5)
        #expect(empty.viewCount == 1)
    }

    @Test func appendViewEmptySourceDoesNothing() {
        var pkt = PacketBuffer(capacity: 100)
        _ = pkt.appendPointer(count: 20)
        let empty = PacketBuffer(capacity: 0)

        pkt.appendView(empty)
        #expect(pkt.totalLength == 20)
        #expect(pkt.viewCount == 1)
    }

    @Test func appendViewMultipleBuffers() {
        var combined = PacketBuffer(capacity: 64)
        for i in 0..<4 {
            var seg = PacketBuffer(capacity: 32)
            guard let ptr = seg.appendPointer(count: 8) else { return }
            let fill = [UInt8](repeating: UInt8(i), count: 8)
            fill.withUnsafeBytes { ptr.copyMemory(from: $0.baseAddress!, byteCount: 8) }
            combined.appendView(seg)
        }
        #expect(combined.totalLength == 32)
        #expect(combined.viewCount == 4)
    }

    @Test func appendViewSkipsEmptyViews() {
        var pkt1 = PacketBuffer(capacity: 100)
        _ = pkt1.appendPointer(count: 10)

        var pkt2 = PacketBuffer(capacity: 100)
        _ = pkt2.appendPointer(count: 30)
        pkt2.trimFront(30)

        let before = pkt1.viewCount
        pkt1.appendView(pkt2)
        #expect(pkt1.viewCount == before)
    }

    // MARK: - pullUp

    @Test func pullUpAlreadyContiguousReturnsTrue() {
        var pkt = PacketBuffer(capacity: 100)
        guard let ptr = pkt.appendPointer(count: 50) else { return }
        for i in 0..<50 { ptr.advanced(by: i).storeBytes(of: UInt8(i), as: UInt8.self) }

        let pulled = pkt.pullUp(30)
        #expect(pulled)
        #expect(pkt.totalLength == 50)
        #expect(pkt.viewCount == 1)
    }

    @Test func pullUpAcrossTwoViews() {
        var pkt = PacketBuffer(capacity: 64)
        guard let ptr1 = pkt.appendPointer(count: 20) else { return }
        let d1: [UInt8] = Array(0..<20).map { UInt8($0) }
        d1.withUnsafeBytes { ptr1.copyMemory(from: $0.baseAddress!, byteCount: 20) }

        var pkt2 = PacketBuffer(capacity: 64)
        guard let ptr2 = pkt2.appendPointer(count: 20) else { return }
        let d2: [UInt8] = Array(20..<40).map { UInt8($0) }
        d2.withUnsafeBytes { ptr2.copyMemory(from: $0.baseAddress!, byteCount: 20) }

        pkt.appendView(pkt2)
        #expect(pkt.viewCount == 2)
        let pulled = pkt.pullUp(30)
        #expect(pulled)

        #expect(pkt.totalLength == 40)
        pkt.withUnsafeReadableBytes { buf in
            let bytes = [UInt8](buf)
            #expect(Array(bytes[0..<30]) == Array(0..<30).map { UInt8($0) })
        }
    }

    @Test func pullUpExactViewBoundary() {
        var pkt = PacketBuffer(capacity: 64)
        guard let ptr1 = pkt.appendPointer(count: 16) else { return }
        let d1: [UInt8] = Array(0..<16).map { UInt8($0) }
        d1.withUnsafeBytes { ptr1.copyMemory(from: $0.baseAddress!, byteCount: 16) }

        var pkt2 = PacketBuffer(capacity: 64)
        guard let ptr2 = pkt2.appendPointer(count: 16) else { return }
        let d2: [UInt8] = Array(16..<32).map { UInt8($0) }
        d2.withUnsafeBytes { ptr2.copyMemory(from: $0.baseAddress!, byteCount: 16) }

        pkt.appendView(pkt2)
        let pulled = pkt.pullUp(16)
        #expect(pulled)
        #expect(pkt.totalLength == 32)
    }

    @Test func pullUpAcrossThreeViews() {
        var pkt = PacketBuffer(capacity: 64)
        for base in [0, 10, 20] {
            var seg = PacketBuffer(capacity: 32)
            guard let ptr = seg.appendPointer(count: 10) else { return }
            let d: [UInt8] = Array(base..<base+10).map { UInt8($0) }
            d.withUnsafeBytes { ptr.copyMemory(from: $0.baseAddress!, byteCount: 10) }
            pkt.appendView(seg)
        }
        #expect(pkt.viewCount == 3)
        let pulled = pkt.pullUp(25)
        #expect(pulled)

        pkt.withUnsafeReadableBytes { buf in
            let bytes = [UInt8](buf)
            #expect(Array(bytes[0..<25]) == Array(0..<25).map { UInt8($0) })
        }
    }

    @Test func pullUpEntireBuffer() {
        var pkt = PacketBuffer(capacity: 64)
        for base in [0, 8, 16] {
            var seg = PacketBuffer(capacity: 32)
            guard let ptr = seg.appendPointer(count: 8) else { return }
            let d: [UInt8] = Array(base..<base+8).map { UInt8($0) }
            d.withUnsafeBytes { ptr.copyMemory(from: $0.baseAddress!, byteCount: 8) }
            pkt.appendView(seg)
        }
        let pulled = pkt.pullUp(24)
        #expect(pulled)
        #expect(pkt.viewCount == 1)
        #expect(pkt.totalLength == 24)
    }

    @Test func pullUpCountExceedsLengthReturnsFalse() {
        var pkt = PacketBuffer(capacity: 100)
        _ = pkt.appendPointer(count: 10)
        let pulled = pkt.pullUp(20)
        #expect(!pulled)
        #expect(pkt.totalLength == 10)
    }

    @Test func pullUpZero() {
        var pkt = PacketBuffer(capacity: 100)
        _ = pkt.appendPointer(count: 10)
        let pulled = pkt.pullUp(0)
        #expect(pulled)
        #expect(pkt.totalLength == 10)
    }

    @Test func pullUpEmptyBufferReturnsFalse() {
        var pkt = PacketBuffer(capacity: 0)
        let pulled = pkt.pullUp(1)
        #expect(!pulled)
    }

    // MARK: - I/O

    @Test func iovecsFromSingleView() {
        var pkt = PacketBuffer(capacity: 100)
        _ = pkt.appendPointer(count: 20)
        let iov = pkt.iovecs()
        #expect(iov.count == 1)
        #expect(iov[0].iov_len == 20)
    }

    @Test func iovecsFromMultipleViews() {
        var pkt = PacketBuffer(capacity: 64)
        _ = pkt.appendPointer(count: 20)
        var pkt2 = PacketBuffer(capacity: 64)
        _ = pkt2.appendPointer(count: 20)
        pkt.appendView(pkt2)
        let iov = pkt.iovecs()
        #expect(iov.count == 2)
        #expect(iov[0].iov_len == 20)
        #expect(iov[1].iov_len == 20)
    }

    @Test func iovecsSkipsEmptyViews() {
        var pkt = PacketBuffer(capacity: 100, headroom: 14)
        _ = pkt.appendPointer(count: 30)
        pkt.trimFront(30)
        #expect(pkt.iovecs().isEmpty)
    }

    @Test func sendmsgWritesToFD() {
        var fds: [Int32] = [0, 0]
        guard socketpair(AF_UNIX, SOCK_DGRAM, 0, &fds) == 0 else {
            Issue.record("socketpair failed")
            return
        }
        defer { close(fds[0]); close(fds[1]) }

        var pkt = PacketBuffer(capacity: 64)
        guard let ptr = pkt.appendPointer(count: 4) else { return }
        let data: [UInt8] = [0xCA, 0xFE, 0xBA, 0xBE]
        data.withUnsafeBytes { ptr.copyMemory(from: $0.baseAddress!, byteCount: 4) }

        let written = pkt.sendmsg(to: fds[1])
        #expect(written == 4)

        var buf = [UInt8](repeating: 0, count: 64)
        let n = Darwin.read(fds[0], &buf, 64)
        #expect(n == 4)
        #expect(Array(buf[0..<4]) == data)
    }

    @Test func sendmsgWithMultipleViews() {
        var fds: [Int32] = [0, 0]
        guard socketpair(AF_UNIX, SOCK_DGRAM, 0, &fds) == 0 else { return }
        defer { close(fds[0]); close(fds[1]) }

        var pkt = PacketBuffer(capacity: 64)
        guard let ptr1 = pkt.appendPointer(count: 4) else { return }
        let d1: [UInt8] = [1, 2, 3, 4]
        d1.withUnsafeBytes { ptr1.copyMemory(from: $0.baseAddress!, byteCount: 4) }

        var pkt2 = PacketBuffer(capacity: 64)
        guard let ptr2 = pkt2.appendPointer(count: 4) else { return }
        let d2: [UInt8] = [5, 6, 7, 8]
        d2.withUnsafeBytes { ptr2.copyMemory(from: $0.baseAddress!, byteCount: 4) }

        pkt.appendView(pkt2)
        let written = pkt.sendmsg(to: fds[1])
        #expect(written == 8)

        var buf = [UInt8](repeating: 0, count: 64)
        let n = Darwin.read(fds[0], &buf, 64)
        #expect(n == 8)
        #expect(Array(buf[0..<8]) == [1, 2, 3, 4, 5, 6, 7, 8])
    }

    // MARK: - Round-trip

    @Test func roundTripWriteRead() {
        var pkt = PacketBuffer(capacity: 256, headroom: 14)

        guard let eth = pkt.prependPointer(count: 14) else { return }
        let ethBytes: [UInt8] = [
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
            0x08, 0x00,
        ]
        ethBytes.withUnsafeBytes { eth.copyMemory(from: $0.baseAddress!, byteCount: 14) }
        #expect(pkt.headroom == 0)
        #expect(pkt.totalLength == 14)

        guard let payload = pkt.appendPointer(count: 4) else { return }
        let payloadBytes: [UInt8] = [0xDE, 0xAD, 0xBE, 0xEF]
        payloadBytes.withUnsafeBytes { payload.copyMemory(from: $0.baseAddress!, byteCount: 4) }
        #expect(pkt.totalLength == 18)

        pkt.withUnsafeReadableBytes { buf in
            let bytes = [UInt8](buf)
            #expect(bytes.count == 18)
            #expect(Array(bytes[0..<14]) == ethBytes)
            #expect(Array(bytes[14..<18]) == payloadBytes)
        }
    }

    // MARK: - Description

    @Test func descriptionFormat() {
        var pkt = PacketBuffer(capacity: 256, headroom: 14)
        _ = pkt.appendPointer(count: 100)
        let desc = pkt.description
        #expect(desc.contains("len: 100"))
        #expect(desc.contains("headroom: 14"))
    }
}
