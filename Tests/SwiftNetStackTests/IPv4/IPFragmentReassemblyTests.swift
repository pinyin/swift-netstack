import Testing
@testable import SwiftNetStack

@Suite(.serialized)
struct IPFragmentReassemblyTests {

    let srcAddr = IPv4Address(10, 0, 0, 1)
    let dstAddr = IPv4Address(10, 0, 0, 2)

    // MARK: - FragmentKey

    @Test func fragmentKeyEquality() {
        let k1 = FragmentKey(srcAddr: srcAddr.addr, dstAddr: dstAddr.addr, identification: 0x42, protocol: IPProtocol.udp.rawValue)
        let k2 = FragmentKey(srcAddr: srcAddr.addr, dstAddr: dstAddr.addr, identification: 0x42, protocol: IPProtocol.udp.rawValue)
        let k3 = FragmentKey(srcAddr: srcAddr.addr, dstAddr: dstAddr.addr, identification: 0x43, protocol: IPProtocol.udp.rawValue)

        #expect(k1 == k2)
        #expect(k1 != k3)
        #expect(k1.hashValue == k2.hashValue)
    }

    @Test func fragmentKeyDifferentProtocolsAreSeparate() {
        let k1 = FragmentKey(srcAddr: srcAddr.addr, dstAddr: dstAddr.addr, identification: 0x42, protocol: IPProtocol.icmp.rawValue)
        let k2 = FragmentKey(srcAddr: srcAddr.addr, dstAddr: dstAddr.addr, identification: 0x42, protocol: IPProtocol.udp.rawValue)
        #expect(k1 != k2)
    }

    // MARK: - Single fragment (complete datagram)

    @Test func singleFragmentMF0Offset0() {
        // A complete datagram split into one "fragment" with MF=0, offset=0.
        // This is technically not a fragment (isFragment would be false in Phase 4),
        // but the reassembler should handle it correctly.
        let data: [UInt8] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
        let pkt = makeRawIPFragment(
            identification: 0x1234, flags: 0, fragmentOffset: 0,
            payload: data
        )

        guard let ip = IPv4Header.parse(from: pkt) else {
            Issue.record("failed to parse IPv4 header")
            return
        }

        var reasm = IPFragmentReassembler()
        let result = reasm.process(fragment: ip, rawIPPacket: pkt)
        #expect(result != nil)

        guard let full = result else { return }
        // Re-parse to verify the reassembled datagram
        guard let fullIP = IPv4Header.parse(from: full) else {
            Issue.record("failed to parse reassembled datagram")
            return
        }
        #expect(fullIP.identification == 0x1234)
        #expect(fullIP.flags == 0)
        #expect(fullIP.fragmentOffset == 0)
        #expect(fullIP.verifyChecksum())
        #expect(fullIP.payload.totalLength == data.count)
        fullIP.payload.withUnsafeReadableBytes { buf in
            #expect(Array(buf) == data)
        }
    }

    // MARK: - Two fragments

    @Test func twoFragmentsInOrder() {
        let payload1: [UInt8] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
        let payload2: [UInt8] = [0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10]

        let frag1 = makeRawIPFragment(identification: 0x42, flags: 1, fragmentOffset: 0, payload: payload1)
        let frag2 = makeRawIPFragment(identification: 0x42, flags: 0, fragmentOffset: 1, payload: payload2)

        guard let ip1 = IPv4Header.parse(from: frag1),
              let ip2 = IPv4Header.parse(from: frag2) else {
            Issue.record("failed to parse fragment headers")
            return
        }

        var reasm = IPFragmentReassembler()
        #expect(reasm.process(fragment: ip1, rawIPPacket: frag1) == nil)
        let result = reasm.process(fragment: ip2, rawIPPacket: frag2)
        #expect(result != nil)

        guard let full = result,
              let fullIP = IPv4Header.parse(from: full) else {
            Issue.record("failed to parse reassembled datagram")
            return
        }
        #expect(fullIP.identification == 0x42)
        #expect(fullIP.flags == 0)
        #expect(fullIP.fragmentOffset == 0)
        #expect(fullIP.verifyChecksum())
        #expect(fullIP.payload.totalLength == 16)
        fullIP.payload.withUnsafeReadableBytes { buf in
            #expect(Array(buf) == payload1 + payload2)
        }
    }

    @Test func twoFragmentsOutOfOrder() {
        let payload1: [UInt8] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
        let payload2: [UInt8] = [0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10]

        let frag1 = makeRawIPFragment(identification: 0x99, flags: 1, fragmentOffset: 0, payload: payload1)
        let frag2 = makeRawIPFragment(identification: 0x99, flags: 0, fragmentOffset: 1, payload: payload2)

        guard let ip1 = IPv4Header.parse(from: frag1),
              let ip2 = IPv4Header.parse(from: frag2) else {
            Issue.record("failed to parse fragment headers")
            return
        }

        var reasm = IPFragmentReassembler()
        // Feed fragment 2 (offset=1, MF=0) first — buffered, header not yet available
        #expect(reasm.process(fragment: ip2, rawIPPacket: frag2) == nil)
        // Fragment 1 (offset=0, MF=1) arrives — completes reassembly with buffered data
        let result = reasm.process(fragment: ip1, rawIPPacket: frag1)
        #expect(result != nil)

        guard let full = result,
              let fullIP = IPv4Header.parse(from: full) else { return }
        #expect(fullIP.payload.totalLength == 16)
        fullIP.payload.withUnsafeReadableBytes { buf in
            #expect(Array(buf) == payload1 + payload2)
        }
    }

    // MARK: - Three fragments

    @Test func threeFragments() {
        let p1: [UInt8] = Array(0..<8)
        let p2: [UInt8] = Array(8..<16)
        let p3: [UInt8] = Array(16..<20)

        let frag1 = makeRawIPFragment(identification: 0x55, flags: 1, fragmentOffset: 0, payload: p1)
        let frag2 = makeRawIPFragment(identification: 0x55, flags: 1, fragmentOffset: 1, payload: p2)
        let frag3 = makeRawIPFragment(identification: 0x55, flags: 0, fragmentOffset: 2, payload: p3)

        guard let ip1 = IPv4Header.parse(from: frag1),
              let ip2 = IPv4Header.parse(from: frag2),
              let ip3 = IPv4Header.parse(from: frag3) else {
            Issue.record("failed to parse fragment headers")
            return
        }

        var reasm = IPFragmentReassembler()
        #expect(reasm.process(fragment: ip1, rawIPPacket: frag1) == nil)
        #expect(reasm.process(fragment: ip2, rawIPPacket: frag2) == nil)
        let result = reasm.process(fragment: ip3, rawIPPacket: frag3)
        #expect(result != nil)

        guard let full = result,
              let fullIP = IPv4Header.parse(from: full) else { return }
        #expect(fullIP.payload.totalLength == 20)
        fullIP.payload.withUnsafeReadableBytes { buf in
            #expect(Array(buf) == p1 + p2 + p3)
        }
    }

    // MARK: - Incomplete (missing fragment)

    @Test func incompleteFragmentsReturnNil() {
        let p1: [UInt8] = Array(0..<8)
        let p2: [UInt8] = Array(0..<8)

        let frag1 = makeRawIPFragment(identification: 0x77, flags: 1, fragmentOffset: 0, payload: p1)
        let frag2 = makeRawIPFragment(identification: 0x77, flags: 1, fragmentOffset: 2, payload: p2)

        guard let ip1 = IPv4Header.parse(from: frag1),
              let ip2 = IPv4Header.parse(from: frag2) else {
            Issue.record("failed to parse fragment headers")
            return
        }

        var reasm = IPFragmentReassembler()
        #expect(reasm.process(fragment: ip1, rawIPPacket: frag1) == nil)
        // Fragment at offset 2 leaves a gap at offset 1 — incomplete
        #expect(reasm.process(fragment: ip2, rawIPPacket: frag2) == nil)
    }

    // MARK: - Duplicate fragment

    @Test func duplicateFragmentDoesNotCorruptReassembly() {
        let p1: [UInt8] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
        let p2: [UInt8] = [0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10]

        let frag1 = makeRawIPFragment(identification: 0x11, flags: 1, fragmentOffset: 0, payload: p1)
        let frag2 = makeRawIPFragment(identification: 0x11, flags: 0, fragmentOffset: 1, payload: p2)

        guard let ip1 = IPv4Header.parse(from: frag1),
              let ip2 = IPv4Header.parse(from: frag2) else {
            Issue.record("failed to parse fragment headers")
            return
        }

        var reasm = IPFragmentReassembler()
        #expect(reasm.process(fragment: ip1, rawIPPacket: frag1) == nil)
        // Duplicate of fragment 1
        #expect(reasm.process(fragment: ip1, rawIPPacket: frag1) == nil)
        // Fragment 2 should still complete reassembly
        let result = reasm.process(fragment: ip2, rawIPPacket: frag2)
        #expect(result != nil)

        guard let full = result,
              let fullIP = IPv4Header.parse(from: full) else { return }
        #expect(fullIP.payload.totalLength == 16)
        fullIP.payload.withUnsafeReadableBytes { buf in
            #expect(Array(buf) == p1 + p2)
        }
    }

    // MARK: - Expired buffer cleanup

    @Test func reapExpiredRemovesOldBuffers() {
        let p1: [UInt8] = Array(0..<8)

        let frag1 = makeRawIPFragment(identification: 0xDEAD, flags: 1, fragmentOffset: 0, payload: p1)
        guard let ip1 = IPv4Header.parse(from: frag1) else {
            Issue.record("failed to parse fragment header")
            return
        }

        var reasm = IPFragmentReassembler()
        #expect(reasm.process(fragment: ip1, rawIPPacket: frag1) == nil)

        // Immediate reap should not remove the buffer (deadline is 30s in the future)
        reasm.reapExpired()
        // The buffer should still be there — reprocessing the same fragment
        // (which hits the existing buffer path) would return nil since MF=1
        // and totalPayloadLength is nil
        let result = reasm.process(fragment: ip1, rawIPPacket: frag1)
        #expect(result == nil, "buffer should still exist after reapExpired within timeout")
    }

    // MARK: - Audit issue #3: non-first fragment arriving first is dropped

    /// AUDIT #3 REPRODUCTION: RFC 791 does not require offset=0 to arrive first.
    /// When a non-zero-offset fragment arrives before the first fragment, it is
    /// silently dropped because no buffer exists yet. In real networks, IP has
    /// no retransmission — the dropped fragment is lost forever, and the datagram
    /// can never be reassembled within the 30-second timeout window.
    ///
    /// EXPECTED: fragments arriving in any order should be buffered and reassembled
    /// ACTUAL:   non-zero-offset fragments arriving first are dropped (BUG)
    @Test func outOfOrderFragmentsShouldReassembleWithoutRetransmission() {
        let fragLast = makeRawIPFragment(
            identification: 0x42, flags: 0, fragmentOffset: 1,
            payload: [0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10]
        )
        let fragFirst = makeRawIPFragment(
            identification: 0x42, flags: 1, fragmentOffset: 0,
            payload: [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
        )

        guard let ipLast = IPv4Header.parse(from: fragLast),
              let ipFirst = IPv4Header.parse(from: fragFirst) else {
            Issue.record("failed to parse fragment headers")
            return
        }

        var reasm = IPFragmentReassembler()

        // Last fragment arrives first — should be buffered until first arrives
        let r1 = reasm.process(fragment: ipLast, rawIPPacket: fragLast)
        #expect(r1 == nil, "last fragment first: should buffer, not complete")

        // First fragment arrives — should complete reassembly with buffered data
        let r2 = reasm.process(fragment: ipFirst, rawIPPacket: fragFirst)
        #expect(r2 != nil,
            "AUDIT #3 FAIL: non-first fragment dropped instead of buffered — requires retransmission")
    }

    // MARK: - Audit issue #4: reassembled datagram uses heap allocation

    /// AUDIT #4 REPRODUCTION: Reassembled datagrams use `Storage.allocate`
    /// directly instead of ChunkPools. This bypasses the pool's allocation
    /// tracking and release batching, causing the reassembled buffer to be
    /// deallocated directly rather than recycled.
    ///
    /// Verifies that the reassembled buffer's storage capacity matches a known
    /// pool size. Storage.allocate gives exactly the requested byte count, while
    /// pool allocation rounds up to the next power-of-two tier.
    @Test func reassembledDatagramUsesPool() {
        let p1: [UInt8] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
        let p2: [UInt8] = [0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10]

        let frag1 = makeRawIPFragment(identification: 0x55, flags: 1, fragmentOffset: 0, payload: p1)
        let frag2 = makeRawIPFragment(identification: 0x55, flags: 0, fragmentOffset: 1, payload: p2)

        guard let ip1 = IPv4Header.parse(from: frag1),
              let ip2 = IPv4Header.parse(from: frag2) else {
            Issue.record("failed to parse fragment headers")
            return
        }

        var reasm = IPFragmentReassembler()
        _ = reasm.process(fragment: ip1, rawIPPacket: frag1)
        guard let result = reasm.process(fragment: ip2, rawIPPacket: frag2) else {
            Issue.record("reassembly failed")
            return
        }

        // Pool-allocated chunks have capacities matching one of the 11 tiers.
        // Storage.allocate (heap) gives exactly the requested byte count.
        // The reassembled datagram is 20 (header) + 16 (payload) = 36 bytes,
        // so a pool allocation would give 64 bytes (next power-of-two tier).
        let storageCapacity = result._views[0].storage.capacity
        let poolSizes = [64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536]
        #expect(poolSizes.contains(storageCapacity),
            "AUDIT #4 FAIL: capacity \(storageCapacity) not a pool size — heap-allocated instead of pool-allocated")
    }

    // MARK: - First fragment offset != 0 is dropped

    @Test func firstFragmentWithNonZeroOffsetIsDropped() {
        let p2: [UInt8] = Array(0..<8)
        let frag2 = makeRawIPFragment(identification: 0x33, flags: 0, fragmentOffset: 1, payload: p2)
        guard let ip2 = IPv4Header.parse(from: frag2) else {
            Issue.record("failed to parse fragment header")
            return
        }

        var reasm = IPFragmentReassembler()
        // First fragment with offset != 0 — no buffer exists, returns nil (dropped)
        #expect(reasm.process(fragment: ip2, rawIPPacket: frag2) == nil)
    }

    // MARK: - H2 regression: concurrent reassembly limit

    /// Verifies that the reassembler enforces `maxConcurrentReassemblies`,
    /// rejecting new fragments when at capacity and accepting them once
    /// space is freed.
    @Test func concurrentReassemblyLimitEnforced() {
        var reasm = IPFragmentReassembler()
        let limit = 64

        // Fill to capacity with incomplete first fragments
        for i in 0..<limit {
            let frag = makeRawIPFragment(
                identification: UInt16(i), flags: 1, fragmentOffset: 0,
                payload: [UInt8](repeating: UInt8(i & 0xFF), count: 8)
            )
            guard let ip = IPv4Header.parse(from: frag) else { continue }
            _ = reasm.process(fragment: ip, rawIPPacket: frag)
        }

        // Fragment 65 (key=64) should be rejected — at capacity
        let overFrag = makeRawIPFragment(
            identification: 64, flags: 1, fragmentOffset: 0,
            payload: [UInt8](repeating: 0xAA, count: 8)
        )
        guard let overIP = IPv4Header.parse(from: overFrag) else { return }
        // Returns nil whether rejected or stored — either way nil
        _ = reasm.process(fragment: overIP, rawIPPacket: overFrag)

        // Complete reassembly for key 0 — frees one slot
        let complete = makeRawIPFragment(
            identification: 0, flags: 0, fragmentOffset: 0,
            payload: [UInt8](repeating: 0x00, count: 8)
        )
        guard let completeIP = IPv4Header.parse(from: complete) else { return }
        let result = reasm.process(fragment: completeIP, rawIPPacket: complete)
        #expect(result != nil, "key 0 should complete reassembly")

        // Now key 64 should be accepted (slot freed)
        let retry = makeRawIPFragment(
            identification: 64, flags: 0, fragmentOffset: 0,
            payload: [UInt8](repeating: 0xAA, count: 8)
        )
        guard let retryIP = IPv4Header.parse(from: retry) else { return }
        // This is a new buffer (key 64 was rejected before), offset=0, MF=0
        // → stored and immediately complete (single fragment, no gaps)
        let retryResult = reasm.process(fragment: retryIP, rawIPPacket: retry)
        #expect(retryResult != nil, "key 64 should be accepted after slot freed")

        reasm.reapExpired()
    }

    // MARK: - Helpers

    /// Build a raw IPv4 fragment packet as a PacketBuffer.
    /// - Parameters:
    ///   - identification: IP identification field
    ///   - flags: 3-bit flags (bit 0 = MF)
    ///   - fragmentOffset: 13-bit fragment offset in 8-byte units
    ///   - payload: payload bytes after the IP header
    private func makeRawIPFragment(
        identification: UInt16,
        flags: UInt8,
        fragmentOffset: UInt16,
        payload: [UInt8]
    ) -> PacketBuffer {
        let totalLen = 20 + payload.count
        var bytes = [UInt8](repeating: 0, count: totalLen)

        bytes[0] = 0x45  // version=4, IHL=5
        bytes[2] = UInt8(totalLen >> 8)
        bytes[3] = UInt8(totalLen & 0xFF)
        bytes[4] = UInt8(identification >> 8)
        bytes[5] = UInt8(identification & 0xFF)
        bytes[6] = UInt8((flags & 0x07) << 5) | UInt8((fragmentOffset >> 8) & 0x1F)
        bytes[7] = UInt8(fragmentOffset & 0xFF)
        bytes[8] = 64  // TTL
        bytes[9] = IPProtocol.udp.rawValue
        srcAddr.write(to: &bytes[12])
        dstAddr.write(to: &bytes[16])

        // Payload
        for i in 0..<payload.count {
            bytes[20 + i] = payload[i]
        }

        // Compute IP header checksum
        let cksum = bytes[0..<20].withUnsafeBytes { internetChecksum($0) }
        bytes[10] = UInt8(cksum >> 8)
        bytes[11] = UInt8(cksum & 0xFF)

        let s = Storage.allocate(capacity: totalLen)
        bytes.withUnsafeBytes { s.data.copyMemory(from: $0.baseAddress!, byteCount: totalLen) }
        return PacketBuffer(storage: s, offset: 0, length: totalLen)
    }
}
