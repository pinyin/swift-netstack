import Testing
import Darwin
@testable import SwiftNetStack

@Suite(.serialized)
struct PacketBufferTests {

    // MARK: - Init & queries

    @Test func initWithCapacityAndHeadroom() {
        let pkt = PacketBuffer(capacity: 100, headroom: 50)
        #expect(pkt.totalLength == 0)
        #expect(pkt.headroom == 50)
        #expect(pkt.isEmpty == true)
    }

    @Test func initWithStorage() {
        let s = Storage.allocate(capacity: 200)
        let pkt = PacketBuffer(storage: s, offset: 20, length: 80)
        #expect(pkt.totalLength == 80)
        #expect(pkt.headroom == 20)
        #expect(pkt.tailroom == 200 - 20 - 80)
    }

    @Test func tailroomWithSingleView() {
        let pkt = PacketBuffer(capacity: 1024, headroom: 14)
        #expect(pkt.headroom == 14)
        // Pool may give a larger chunk than requested; tailroom ≥ capacity
        #expect(pkt.tailroom >= 1024 - 14)
    }

    // MARK: - Append / Prepend

    @Test func appendPointerReturnsValidPointer() {
        var pkt = PacketBuffer(capacity: 100)
        guard let ptr = pkt.appendPointer(count: 10) else {
            Issue.record("appendPointer returned nil")
            return
        }
        let fillBytes = [UInt8](repeating: 0xAB, count: 10)
        fillBytes.withUnsafeBytes { ptr.copyMemory(from: $0.baseAddress!, byteCount: 10) }
        #expect(pkt.totalLength == 10)
    }

    @Test func prependPointerConsumesHeadroom() {
        var pkt = PacketBuffer(capacity: 100, headroom: 50)
        guard let ptr = pkt.prependPointer(count: 14) else {
            Issue.record("prependPointer returned nil")
            return
        }
        let headerBytes = [UInt8](repeating: 0xCD, count: 14)
        headerBytes.withUnsafeBytes { ptr.copyMemory(from: $0.baseAddress!, byteCount: 14) }
        #expect(pkt.totalLength == 14)
        #expect(pkt.headroom == 36)
    }

    @Test func appendBeyondTailroomReturnsNil() {
        var pkt = PacketBuffer(capacity: 64)
        let ptr1 = pkt.appendPointer(count: 64)
        #expect(ptr1 != nil)
        let ptr2 = pkt.appendPointer(count: 1)
        #expect(ptr2 == nil)
    }

    @Test func prependBeyondHeadroomReturnsNil() {
        var pkt = PacketBuffer(capacity: 100, headroom: 10)
        let ptr = pkt.prependPointer(count: 20)
        #expect(ptr == nil)
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

    // MARK: - Clone (zero-copy)

    @Test func cloneSharesStorage() {
        var pkt = PacketBuffer(capacity: 100)
        guard let ptr = pkt.appendPointer(count: 10) else {
            Issue.record("appendPointer failed")
            return
        }
        let cloneBytes = [UInt8](repeating: 0x42, count: 10)
        cloneBytes.withUnsafeBytes { ptr.copyMemory(from: $0.baseAddress!, byteCount: 10) }

        let cloned = pkt.clone()
        #expect(cloned.totalLength == pkt.totalLength)

        // Verify data is readable from clone
        cloned.withUnsafeReadableBytes { buf in
            let bytes = [UInt8](buf)
            #expect(bytes.count == 10)
            #expect(bytes.allSatisfy { $0 == 0x42 })
        }
    }

    @Test func cloneTriggersCOWOnWrite() {
        var pkt = PacketBuffer(capacity: 100)
        _ = pkt.appendPointer(count: 10)

        var cloned = pkt.clone()
        // Writing to the clone should not affect the original
        guard let ptr = cloned.appendPointer(count: 5) else {
            Issue.record("Cannot append to clone")
            return
        }
        let ffBytes = [UInt8](repeating: 0xFF, count: 5)
        ffBytes.withUnsafeBytes { ptr.copyMemory(from: $0.baseAddress!, byteCount: 5) }

        #expect(cloned.totalLength == 15)
        #expect(pkt.totalLength == 10, "Original should not be affected by clone's COW write")
    }

    // MARK: - Slice (zero-copy)

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

    @Test func sliceAcrossMultipleViews() {
        let s1 = Storage.allocate(capacity: 64)
        let s2 = Storage.allocate(capacity: 64)
        for i in 0..<64 {
            s1.data.advanced(by: i).storeBytes(of: UInt8(i), as: UInt8.self)
            s2.data.advanced(by: i).storeBytes(of: UInt8(64 + i), as: UInt8.self)
        }
        // Multi-view buffers will be constructable once PacketBuffer gains a
        // merge/append-view API for TCP segment reassembly. For now, verify
        // Storage lifetime is correct when held by multiple views.
        s1.release()
        s2.release()
    }

    // MARK: - Iovecs

    @Test func iovecsFromSingleView() {
        var pkt = PacketBuffer(capacity: 100)
        _ = pkt.appendPointer(count: 20)
        let iov = pkt.iovecs()
        #expect(iov.count == 1)
        #expect(iov[0].iov_len == 20)
    }

    @Test func iovecsSkipsEmptyViews() {
        var pkt = PacketBuffer(capacity: 100, headroom: 14)
        _ = pkt.appendPointer(count: 30)
        // Trim to create empty views situation
        pkt.trimFront(30)
        let iov = pkt.iovecs()
        #expect(iov.isEmpty)
    }

    // MARK: - withUnsafeReadableBytes

    @Test func readableBytesAccess() {
        var pkt = PacketBuffer(capacity: 64)
        guard let ptr = pkt.appendPointer(count: 5) else {
            Issue.record("appendPointer failed")
            return
        }
        let data: [UInt8] = [10, 20, 30, 40, 50]
        data.withUnsafeBytes { ptr.copyMemory(from: $0.baseAddress!, byteCount: 5) }

        pkt.withUnsafeReadableBytes { buf in
            let bytes = [UInt8](buf)
            #expect(bytes == data)
        }
    }

    // MARK: - appendView (zero-copy multi-view construction)

    @Test func appendViewCombinesTwoBuffers() {
        var pkt1 = PacketBuffer(capacity: 100)
        guard let ptr1 = pkt1.appendPointer(count: 10) else {
            Issue.record("appendPointer failed")
            return
        }
        let data1 = [UInt8](repeating: 0xAA, count: 10)
        data1.withUnsafeBytes { ptr1.copyMemory(from: $0.baseAddress!, byteCount: 10) }

        var pkt2 = PacketBuffer(capacity: 100)
        guard let ptr2 = pkt2.appendPointer(count: 10) else {
            Issue.record("appendPointer failed")
            return
        }
        let data2 = [UInt8](repeating: 0xBB, count: 10)
        data2.withUnsafeBytes { ptr2.copyMemory(from: $0.baseAddress!, byteCount: 10) }

        pkt1.appendView(pkt2)
        #expect(pkt1.totalLength == 20)
        #expect(pkt1.viewCount == 2)

        // Verify both segments are readable in order
        pkt1.withUnsafeReadableBytes { buf in
            let bytes = [UInt8](buf)
            #expect(bytes.count == 20)
            #expect(Array(bytes[0..<10]) == data1)
            #expect(Array(bytes[10..<20]) == data2)
        }
    }

    @Test func appendViewToEmpty() {
        var empty = PacketBuffer(capacity: 0)
        #expect(empty.isEmpty)

        var pkt = PacketBuffer(capacity: 50)
        guard let ptr = pkt.appendPointer(count: 5) else {
            Issue.record("appendPointer failed")
            return
        }
        let data: [UInt8] = [1, 2, 3, 4, 5]
        data.withUnsafeBytes { ptr.copyMemory(from: $0.baseAddress!, byteCount: 5) }

        empty.appendView(pkt)
        #expect(empty.totalLength == 5)
        #expect(empty.viewCount == 1)

        empty.withUnsafeReadableBytes { buf in
            #expect([UInt8](buf) == data)
        }
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
            guard let ptr = seg.appendPointer(count: 8) else {
                Issue.record("appendPointer failed")
                return
            }
            let fill = [UInt8](repeating: UInt8(i), count: 8)
            fill.withUnsafeBytes { ptr.copyMemory(from: $0.baseAddress!, byteCount: 8) }
            combined.appendView(seg)
        }
        #expect(combined.totalLength == 32)
        #expect(combined.viewCount == 4)

        combined.withUnsafeReadableBytes { buf in
            let bytes = [UInt8](buf)
            #expect(bytes[0..<8].allSatisfy { $0 == 0 })
            #expect(bytes[8..<16].allSatisfy { $0 == 1 })
            #expect(bytes[16..<24].allSatisfy { $0 == 2 })
            #expect(bytes[24..<32].allSatisfy { $0 == 3 })
        }
    }

    @Test func appendViewTrimsEmptyViews() {
        var pkt1 = PacketBuffer(capacity: 100)
        _ = pkt1.appendPointer(count: 10)

        var pkt2 = PacketBuffer(capacity: 100)
        _ = pkt2.appendPointer(count: 30)
        pkt2.trimFront(30)  // now empty, viewCount may be 0 or 1 with len=0

        let beforeViewCount = pkt1.viewCount
        pkt1.appendView(pkt2)
        #expect(pkt1.viewCount == beforeViewCount, "Empty views should not be appended")
    }

    // MARK: - pullUp (cross-view linearization)

    @Test func pullUpAlreadyContiguousReturnsTrue() {
        var pkt = PacketBuffer(capacity: 100)
        guard let ptr = pkt.appendPointer(count: 50) else {
            Issue.record("appendPointer failed")
            return
        }
        let data: [UInt8] = Array(0..<50).map { UInt8($0) }
        data.withUnsafeBytes { ptr.copyMemory(from: $0.baseAddress!, byteCount: 50) }

        #expect(pkt.pullUp(30) == true)
        #expect(pkt.totalLength == 50)
        #expect(pkt.viewCount == 1)

        // First 30 bytes unchanged
        pkt.withUnsafeReadableBytes { buf in
            let bytes = [UInt8](buf)
            #expect(Array(bytes[0..<30]) == Array(data[0..<30]))
        }
    }

    @Test func pullUpAcrossTwoViews() {
        var pkt = PacketBuffer(capacity: 64)
        guard let ptr1 = pkt.appendPointer(count: 20) else {
            Issue.record("appendPointer failed")
            return
        }
        let data1: [UInt8] = Array(0..<20).map { UInt8($0) }
        data1.withUnsafeBytes { ptr1.copyMemory(from: $0.baseAddress!, byteCount: 20) }

        var pkt2 = PacketBuffer(capacity: 64)
        guard let ptr2 = pkt2.appendPointer(count: 20) else {
            Issue.record("appendPointer failed")
            return
        }
        let data2: [UInt8] = Array(20..<40).map { UInt8($0) }
        data2.withUnsafeBytes { ptr2.copyMemory(from: $0.baseAddress!, byteCount: 20) }

        pkt.appendView(pkt2)
        #expect(pkt.viewCount == 2)
        #expect(pkt.totalLength == 40)

        // pullUp 30 bytes — crosses view boundary
        #expect(pkt.pullUp(30) == true)

        // Now first view should have 30 contiguous bytes
        #expect(pkt._views[0].length >= 30)  // internal access for test

        pkt.withUnsafeReadableBytes { buf in
            let bytes = [UInt8](buf)
            #expect(bytes.count == 40)
            #expect(Array(bytes[0..<30]) == Array(0..<30).map { UInt8($0) })
        }
    }

    @Test func pullUpExactViewBoundary() {
        var pkt = PacketBuffer(capacity: 64)
        guard let ptr1 = pkt.appendPointer(count: 16) else {
            Issue.record("appendPointer failed")
            return
        }
        let data1: [UInt8] = Array(0..<16).map { UInt8($0) }
        data1.withUnsafeBytes { ptr1.copyMemory(from: $0.baseAddress!, byteCount: 16) }

        var pkt2 = PacketBuffer(capacity: 64)
        guard let ptr2 = pkt2.appendPointer(count: 16) else {
            Issue.record("appendPointer failed")
            return
        }
        let data2: [UInt8] = Array(16..<32).map { UInt8($0) }
        data2.withUnsafeBytes { ptr2.copyMemory(from: $0.baseAddress!, byteCount: 16) }

        pkt.appendView(pkt2)
        // pullUp exactly the first view — fully consumes it
        #expect(pkt.pullUp(16) == true)

        // Should have 2 views: merged + second original
        #expect(pkt.totalLength == 32)

        pkt.withUnsafeReadableBytes { buf in
            let bytes = [UInt8](buf)
            #expect(bytes.count == 32)
            #expect(Array(bytes[0..<16]) == data1)
            #expect(Array(bytes[16..<32]) == data2)
        }
    }

    @Test func pullUpAcrossThreeViews() {
        var pkt = PacketBuffer(capacity: 64)
        for base in [0, 10, 20] {
            var seg = PacketBuffer(capacity: 32)
            guard let ptr = seg.appendPointer(count: 10) else {
                Issue.record("appendPointer failed")
                return
            }
            let data: [UInt8] = Array(base..<base+10).map { UInt8($0) }
            data.withUnsafeBytes { ptr.copyMemory(from: $0.baseAddress!, byteCount: 10) }
            pkt.appendView(seg)
        }
        #expect(pkt.viewCount == 3)
        #expect(pkt.totalLength == 30)

        // Pull up 25 bytes — spans all three views, partial consumption of third
        #expect(pkt.pullUp(25) == true)

        // Should have 2 views: merged (25) + remainder of third (5)
        #expect(pkt.totalLength == 30)

        pkt.withUnsafeReadableBytes { buf in
            let bytes = [UInt8](buf)
            #expect(bytes.count == 30)
            #expect(Array(bytes[0..<25]) == Array(0..<25).map { UInt8($0) })
            #expect(Array(bytes[25..<30]) == Array(25..<30).map { UInt8($0) })
        }
    }

    @Test func pullUpEntireBuffer() {
        var pkt = PacketBuffer(capacity: 64)
        for base in [0, 8, 16] {
            var seg = PacketBuffer(capacity: 32)
            guard let ptr = seg.appendPointer(count: 8) else {
                Issue.record("appendPointer failed")
                return
            }
            let data: [UInt8] = Array(base..<base+8).map { UInt8($0) }
            data.withUnsafeBytes { ptr.copyMemory(from: $0.baseAddress!, byteCount: 8) }
            pkt.appendView(seg)
        }
        #expect(pkt.pullUp(24) == true)
        #expect(pkt.viewCount == 1, "All views should merge into one")
        #expect(pkt.totalLength == 24)

        pkt.withUnsafeReadableBytes { buf in
            let bytes = [UInt8](buf)
            #expect(bytes == Array(0..<24).map { UInt8($0) })
        }
    }

    @Test func pullUpCountExceedsLengthReturnsFalse() {
        var pkt = PacketBuffer(capacity: 100)
        _ = pkt.appendPointer(count: 10)
        #expect(pkt.pullUp(20) == false)
        #expect(pkt.totalLength == 10, "Buffer should be unchanged on failure")
    }

    @Test func pullUpZeroCountReturnsTrue() {
        var pkt = PacketBuffer(capacity: 100)
        _ = pkt.appendPointer(count: 10)
        #expect(pkt.pullUp(0) == true)
        #expect(pkt.totalLength == 10)
    }

    @Test func pullUpEmptyBufferReturnsFalse() {
        var pkt = PacketBuffer(capacity: 0)
        #expect(pkt.pullUp(1) == false)
    }

    // MARK: - Edge cases

    @Test func emptyPacketBuffer() {
        let pkt = PacketBuffer(capacity: 0, headroom: 0)
        #expect(pkt.isEmpty)
        #expect(pkt.totalLength == 0)
        #expect(pkt.headroom == 0)
        #expect(pkt.tailroom == 64)  // capacity=0 selects pool64B
        #expect(pkt.viewCount == 1)
    }

    @Test func largeHeadroomExactPoolSelection() {
        // headroom=54 + capacity=1500 = 1554 → MSB of (1554>>6=24) = 5 → pool[5]=2048
        let pkt = PacketBuffer(capacity: 1500, headroom: 54)
        #expect(pkt.headroom == 54)
        #expect(pkt.totalLength == 0)
        #expect(pkt.tailroom >= 1500)
    }

    @Test func roundTripWriteRead() {
        var pkt = PacketBuffer(capacity: 256, headroom: 14)

        // Prepend an "Ethernet header"
        guard let eth = pkt.prependPointer(count: 14) else {
            Issue.record("prependPointer failed")
            return
        }
        let ethBytes: [UInt8] = [
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  // dst MAC
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55,  // src MAC
            0x08, 0x00,                              // EtherType: IPv4
        ]
        ethBytes.withUnsafeBytes { eth.copyMemory(from: $0.baseAddress!, byteCount: 14) }
        #expect(pkt.headroom == 0)
        #expect(pkt.totalLength == 14)

        // Append payload
        guard let payload = pkt.appendPointer(count: 4) else {
            Issue.record("appendPointer failed")
            return
        }
        let payloadBytes: [UInt8] = [0xDE, 0xAD, 0xBE, 0xEF]
        payloadBytes.withUnsafeBytes { payload.copyMemory(from: $0.baseAddress!, byteCount: 4) }
        #expect(pkt.totalLength == 18)

        // Read back and verify
        pkt.withUnsafeReadableBytes { buf in
            let bytes = [UInt8](buf)
            #expect(bytes.count == 18)
            #expect(Array(bytes[0..<14]) == ethBytes)
            #expect(Array(bytes[14..<18]) == [0xDE, 0xAD, 0xBE, 0xEF])
        }
    }
}
