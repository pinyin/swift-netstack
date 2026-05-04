import Testing
@testable import SwiftNetStack

@Suite(.serialized)
struct StorageTests {

    // MARK: - Basic allocation

    @Test func allocateSmallChunk() {
        let s = Storage.allocate(capacity: 128)
        #expect(s.capacity == 128)
        #expect(s.refCount == 1)
        #expect(s.isPageAligned == false)
        // No deinit crash = passes
    }

    @Test func allocatePageAlignedChunk() {
        let s = Storage.allocate(capacity: 16384)
        #expect(s.capacity == 16384)
        #expect(s.isPageAligned == true)
        #expect(s.refCount == 1)
    }

    @Test func allocateLargerThanPage() {
        let s = Storage.allocate(capacity: 65536)
        #expect(s.capacity == 65536)
        #expect(s.isPageAligned == true)
    }

    // MARK: - Ref counting

    @Test func retainIncrementsRefCount() {
        let s = Storage.allocate(capacity: 64)
        #expect(s.refCount == 1)
        s.retain()
        #expect(s.refCount == 2)
        s.retain()
        #expect(s.refCount == 3)
        // Cleanup
        s.release() // 2
        s.release() // 1
    }

    @Test func releaseDecrementsAndReturnsTrueAtZero() {
        let s = Storage.allocate(capacity: 64)
        #expect(s.refCount == 1)
        let isZero = s.release()
        #expect(isZero == true)
        // At refCount == 0, deinit will free the memory
    }

    @Test func releaseReturnsFalseWhenRefsRemain() {
        let s = Storage.allocate(capacity: 64)
        s.retain()
        #expect(s.refCount == 2)
        let isZero = s.release()
        #expect(isZero == false)
        #expect(s.refCount == 1)
    }

    // MARK: - Data access

    @Test func dataPointerIsWritable() {
        let s = Storage.allocate(capacity: 64)
        s.data.storeBytes(of: UInt8(42), as: UInt8.self)
        let val = s.data.load(as: UInt8.self)
        #expect(val == 42)
    }

    @Test func dataPointerFullCapacity() {
        let s = Storage.allocate(capacity: 1024)
        // Write to the last byte
        s.data.advanced(by: 1023).storeBytes(of: UInt8(0xFF), as: UInt8.self)
        let val = s.data.advanced(by: 1023).load(as: UInt8.self)
        #expect(val == 0xFF)
    }
}
