import Testing
@testable import SwiftNetStack

@Suite struct NetBufTests {

    // MARK: - Creation

    @Test func testCreateEmpty() {
        let nb = NetBuf(capacity: 100, headroom: 20)
        #expect(nb.length == 0)
        #expect(nb.headroom == 20)
        #expect(nb.tailroom == 80)
        #expect(nb.totalCapacity == 100)
    }

    @Test func testCreateCopyWithHeadroom() {
        let data: [UInt8] = [1, 2, 3, 4, 5]
        let nb = NetBuf(copying: data, headroom: 10)
        #expect(nb.length == 5)
        #expect(nb.headroom == 10)
        #expect(nb.tailroom == 0)
        #expect(nb.toArray() == data)
    }

    @Test func testCreateCopyRawPointer() {
        let data: [UInt8] = [10, 20, 30]
        let nb = data.withUnsafeBytes { NetBuf(copying: $0.baseAddress!, count: data.count, headroom: 8) }
        #expect(nb.length == 3)
        #expect(nb.headroom == 8)
        #expect(nb.toArray() == data)
    }

    // MARK: - Slice (zero-copy)

    @Test func testSliceSharesStorage() {
        let nb = NetBuf(copying: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], headroom: 0)
        let slice = nb.slice(from: 3, count: 4)
        #expect(slice != nil)
        #expect(slice!.length == 4)
        #expect(slice!.toArray() == [3, 4, 5, 6])
        #expect(slice!.offset == 3)  // same storage, different offset
    }

    @Test func testSliceFromEnd() {
        let nb = NetBuf(copying: [0, 1, 2, 3, 4], headroom: 0)
        let slice = nb.slice(from: 2)
        #expect(slice != nil)
        #expect(slice!.length == 3)
        #expect(slice!.toArray() == [2, 3, 4])
    }

    @Test func testSliceOutOfBounds() {
        let nb = NetBuf(copying: [0, 1, 2], headroom: 0)
        #expect(nb.slice(from: 2, count: 5) == nil)
        #expect(nb.slice(from: 4) == nil)
    }

    @Test func testSliceEmpty() {
        let nb = NetBuf(capacity: 100, headroom: 20)
        let slice = nb.slice(from: 0, count: 0)
        #expect(slice != nil)
        #expect(slice!.length == 0)
    }

    // MARK: - Prepend

    @Test func testPrepend() {
        let nb = NetBuf(capacity: 100, headroom: 20)
        #expect(nb.length == 0)

        let header: [UInt8] = [0xDE, 0xAD, 0xBE, 0xEF]
        let ok = nb.prepend(copying: header)
        #expect(ok == true)
        #expect(nb.length == 4)
        #expect(nb.headroom == 16)
        #expect(nb.toArray() == header)
    }

    @Test func testPrependInsufficientHeadroom() {
        let nb = NetBuf(capacity: 100, headroom: 2)
        let data: [UInt8] = [1, 2, 3, 4, 5]
        #expect(nb.prepend(copying: data) == false)
        #expect(nb.length == 0)  // unchanged
    }

    @Test func testPrependMultipleLayers() {
        // Simulate building a packet: data, then prepend TCP, then prepend IP, then Eth
        let nb = NetBuf(copying: [UInt8](repeating: 0xDD, count: 100), headroom: 60)

        let tcpHdr = [UInt8](repeating: 0xAA, count: 20)
        #expect(nb.prepend(copying: tcpHdr))
        #expect(nb.length == 120)

        let ipHdr = [UInt8](repeating: 0xBB, count: 20)
        #expect(nb.prepend(copying: ipHdr))
        #expect(nb.length == 140)

        let ethHdr = [UInt8](repeating: 0xCC, count: 14)
        #expect(nb.prepend(copying: ethHdr))
        #expect(nb.length == 154)

        let arr = nb.toArray()
        #expect(arr[0..<14].allSatisfy { $0 == 0xCC })
        #expect(arr[14..<34].allSatisfy { $0 == 0xBB })
        #expect(arr[34..<54].allSatisfy { $0 == 0xAA })
        #expect(arr[54...].allSatisfy { $0 == 0xDD })
    }

    // MARK: - Append

    @Test func testAppend() {
        let extra: [UInt8] = [4, 5, 6]
        // Need tailroom — create with space
        let nb2 = NetBuf(capacity: 20, headroom: 0)
        #expect(nb2.append(copying: [1, 2, 3]))
        #expect(nb2.length == 3)
        #expect(nb2.append(copying: extra))
        #expect(nb2.length == 6)
        #expect(nb2.toArray() == [1, 2, 3, 4, 5, 6])
    }

    @Test func testAppendInsufficientTailroom() {
        let nb = NetBuf(copying: [1, 2, 3], headroom: 0)
        #expect(nb.append(copying: [4, 5, 6]) == false)
        #expect(nb.length == 3)
    }

    // MARK: - Pointer Access

    @Test func testWithUnsafeReadableBytes() {
        let data: [UInt8] = [5, 10, 15, 20]
        let nb = NetBuf(copying: data, headroom: 0)
        nb.withUnsafeReadableBytes { ptr in
            #expect(ptr.count == 4)
            #expect(ptr[0] == 5)
            #expect(ptr[3] == 20)
        }
    }

    @Test func testWithUnsafeMutableDataBytes() {
        let nb = NetBuf(copying: [0, 0, 0, 0], headroom: 0)
        nb.withUnsafeMutableDataBytes { ptr in
            ptr.storeBytes(of: UInt32(0x01020304).bigEndian, as: UInt32.self)
        }
        #expect(nb.toArray() == [1, 2, 3, 4])
    }

    @Test func testPrependPointer() {
        let nb = NetBuf(capacity: 100, headroom: 20)
        let ptr = nb.prependPointer(count: 4)
        #expect(ptr != nil)
        let raw = UnsafeMutableRawPointer(ptr!)
        raw.storeBytes(of: UInt32(0xDEADBEEF).bigEndian, as: UInt32.self)
        #expect(nb.length == 4)
        #expect(nb.toArray() == [0xDE, 0xAD, 0xBE, 0xEF])
    }

    @Test func testAppendPointer() {
        let nb = NetBuf(capacity: 100, headroom: 0)
        let ptr = nb.appendPointer(count: 4)
        #expect(ptr != nil)
        let raw = UnsafeMutableRawPointer(ptr!)
        raw.storeBytes(of: UInt32(0xCAFEBABE).bigEndian, as: UInt32.self)
        #expect(nb.length == 4)
        #expect(nb.toArray() == [0xCA, 0xFE, 0xBA, 0xBE])
    }

    // MARK: - Set Bytes

    @Test func testSetByte() {
        let nb = NetBuf(copying: [0, 0, 0, 0], headroom: 0)
        nb.setByte(at: 1, 0x42)
        nb.setByte(at: 2, 0xFF)
        #expect(nb.toArray() == [0, 0x42, 0xFF, 0])
    }

    @Test func testSetUInt16BE() {
        let nb = NetBuf(copying: [0, 0, 0, 0], headroom: 0)
        nb.setUInt16BE(at: 0, 0x1234)
        nb.setUInt16BE(at: 2, 0xABCD)
        #expect(nb.toArray() == [0x12, 0x34, 0xAB, 0xCD])
    }

    // MARK: - Conversion

    @Test func testToData() {
        let data: [UInt8] = [1, 2, 3]
        let nb = NetBuf(copying: data, headroom: 5)
        let d = nb.toData()
        #expect(d.count == 3)
        #expect(d[0] == 1 && d[1] == 2 && d[2] == 3)
    }

    @Test func testEmptyToArray() {
        let nb = NetBuf(capacity: 100, headroom: 20)
        #expect(nb.toArray() == [])
    }

    // MARK: - Copy from NetBuf

    @Test func testPrependFromNetBuf() {
        let src = NetBuf(copying: [0xAA, 0xBB, 0xCC], headroom: 0)
        let dst = NetBuf(capacity: 100, headroom: 20)
        #expect(dst.prepend(copying: src))
        #expect(dst.toArray() == [0xAA, 0xBB, 0xCC])
    }

    @Test func testAppendFromNetBuf() {
        let src = NetBuf(copying: [0x11, 0x22], headroom: 0)
        let dst = NetBuf(capacity: 100, headroom: 0)
        #expect(dst.append(copying: src))
        #expect(dst.length == 2)
        #expect(dst.toArray() == [0x11, 0x22])
    }

    // MARK: - Chained operations

    @Test func testChainedPrependAppend() {
        let nb = NetBuf(capacity: 200, headroom: 60)
        #expect(nb.append(copying: [UInt8](repeating: 0xDD, count: 50)))
        #expect(nb.prepend(copying: [UInt8](repeating: 0xAA, count: 20)))
        #expect(nb.prepend(copying: [UInt8](repeating: 0xBB, count: 14)))
        #expect(nb.length == 84)
        let arr = nb.toArray()
        #expect(arr[0..<14].allSatisfy { $0 == 0xBB })
        #expect(arr[14..<34].allSatisfy { $0 == 0xAA })
        #expect(arr[34...].allSatisfy { $0 == 0xDD })
    }
}
