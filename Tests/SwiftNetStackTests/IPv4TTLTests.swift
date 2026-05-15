import Testing
@testable import SwiftNetStack
import Darwin

// MARK: - IP TTL Decrement

@Test func decrementTTL_updatesTTLAndChecksum() {
    let buf = UnsafeMutableRawBufferPointer.allocate(byteCount: 20, alignment: 4)
    defer { buf.deallocate() }
    writeIPv4Header(to: buf.baseAddress!, totalLength: 40, protocol: .tcp,
                    srcIP: IPv4Address(10, 0, 0, 1), dstIP: IPv4Address(10, 0, 0, 2))
    let oldChecksum = readUInt16BE(buf.baseAddress!, 10)
    #expect(buf.baseAddress!.advanced(by: 8).load(as: UInt8.self) == 64, "initial TTL == 64")

    let ok = decrementTTL(at: buf.baseAddress!)
    #expect(ok, "decrementTTL succeeds for TTL > 1")
    #expect(buf.baseAddress!.advanced(by: 8).load(as: UInt8.self) == 63, "TTL decremented")
    let newChecksum = readUInt16BE(buf.baseAddress!, 10)
    #expect(newChecksum != oldChecksum, "checksum changed")
    // Verify the new checksum is valid over the entire header
    let ck = internetChecksum(UnsafeRawBufferPointer(start: buf.baseAddress!, count: 20))
    #expect(ck == 0, "header checksum valid after decrement, got \(ck)")
}

@Test func decrementTTL_returnsFalseWhenTTLReachesZero() {
    let buf = UnsafeMutableRawBufferPointer.allocate(byteCount: 20, alignment: 4)
    defer { buf.deallocate() }
    writeIPv4Header(to: buf.baseAddress!, totalLength: 40, protocol: .tcp,
                    srcIP: IPv4Address(10, 0, 0, 1), dstIP: IPv4Address(10, 0, 0, 2))
    // Set TTL = 1 and fix checksum
    buf.baseAddress!.advanced(by: 8).storeBytes(of: UInt8(1), as: UInt8.self)
    writeUInt16BE(0, to: buf.baseAddress!.advanced(by: 10))
    let cksum = internetChecksum(UnsafeRawBufferPointer(start: buf.baseAddress!, count: 20))
    writeUInt16BE(cksum, to: buf.baseAddress!.advanced(by: 10))

    let ok = decrementTTL(at: buf.baseAddress!)
    #expect(!ok, "decrementTTL returns false when TTL reaches 0")
    #expect(buf.baseAddress!.advanced(by: 8).load(as: UInt8.self) == 0, "TTL == 0")
}

@Test func decrementTTL_multipleDecrements() {
    let buf = UnsafeMutableRawBufferPointer.allocate(byteCount: 20, alignment: 4)
    defer { buf.deallocate() }
    writeIPv4Header(to: buf.baseAddress!, totalLength: 40, protocol: .tcp,
                    srcIP: IPv4Address(10, 0, 0, 1), dstIP: IPv4Address(10, 0, 0, 2))

    // TTL starts at 64; each call decrements by 1
    for expectedTTL in (59...63).reversed() {
        let ok = decrementTTL(at: buf.baseAddress!)
        #expect(ok)
        let actualTTL = buf.baseAddress!.advanced(by: 8).load(as: UInt8.self)
        #expect(actualTTL == UInt8(expectedTTL),
                "TTL should be \(expectedTTL), got \(actualTTL)")
        let ck = internetChecksum(UnsafeRawBufferPointer(start: buf.baseAddress!, count: 20))
        #expect(ck == 0, "checksum valid at TTL \(expectedTTL), got \(ck)")
    }
}

// MARK: - IPv4 totalLength incremental checksum (RFC 1624)

@Test func incrementalIPv4Checksum_totalLengthChange() {
    /// Full recomputation: zero checksum, compute over 20 bytes.
    func fullCK(_ ptr: UnsafeMutableRawPointer) -> UInt16 {
        writeUInt16BE(0, to: ptr.advanced(by: 10))
        let ck = internetChecksum(UnsafeRawBufferPointer(start: ptr, count: 20))
        writeUInt16BE(ck, to: ptr.advanced(by: 10))
        return ck
    }

    /// Incremental: HC' = ~(~HC + delta). Only totalLength changed.
    func incCK(_ ptr: UnsafeMutableRawPointer, oldCK: UInt16, delta: Int) -> UInt16 {
        var sum = UInt32(~oldCK) &+ UInt32(delta)
        sum = (sum & 0xFFFF) &+ (sum >> 16)
        sum = (sum & 0xFFFF) &+ (sum >> 16)
        let ck = ~UInt16(sum & 0xFFFF)
        writeUInt16BE(ck, to: ptr.advanced(by: 10))
        return ck
    }

    for pl in [1, 40, 256, 512, 1024, 1460, 32767, 65535 - 40] {
        let buf = UnsafeMutableRawBufferPointer.allocate(byteCount: 20, alignment: 4)
        defer { buf.deallocate() }
        writeIPv4Header(to: buf.baseAddress!, totalLength: 40, protocol: .tcp,
                        srcIP: IPv4Address(10, 0, 0, 1), dstIP: IPv4Address(10, 0, 0, 2))
        let old = readUInt16BE(buf.baseAddress!, 10)
        writeUInt16BE(UInt16(40 + pl), to: buf.baseAddress!.advanced(by: 2))
        let inc = incCK(buf.baseAddress!, oldCK: old, delta: pl)
        let full = fullCK(buf.baseAddress!)
        #expect(inc == full, "payloadLen=\(pl): inc \(inc) != full \(full)")
    }
}
