import Testing
@testable import SwiftNetStack

/// Tests for Storage allocation, ChunkPool acquire/release, and ChunkPools selection.
@Suite(.serialized)
struct StoragePoolTests {

    // MARK: - Storage

    @Test func storageAllocateSmallChunk() {
        let s = Storage.allocate(capacity: 128)
        #expect(s.capacity == 128)
        #expect(!s.isPageAligned)
        #expect(s.capacity > 0)
    }

    @Test func storageAllocatePageAlignedChunk() {
        let s = Storage.allocate(capacity: 16384)
        #expect(s.capacity == 16384)
        #expect(s.isPageAligned)
    }

    @Test func storageAllocateLargeChunk() {
        let s = Storage.allocate(capacity: 65536)
        #expect(s.capacity == 65536)
        #expect(s.isPageAligned)
    }

    @Test func storageDataIsWritable() {
        let s = Storage.allocate(capacity: 64)
        s.data.storeBytes(of: UInt32(0xDEADBEEF), as: UInt32.self)
        let value = s.data.load(as: UInt32.self)
        #expect(value == 0xDEADBEEF)
    }

    @Test func storageDataFullCapacityWritable() {
        let s = Storage.allocate(capacity: 1024)
        let marker: UInt8 = 0xAB
        // Write to the last byte to verify full capacity is usable
        s.data.advanced(by: 1023).storeBytes(of: marker, as: UInt8.self)
        #expect(s.data.advanced(by: 1023).load(as: UInt8.self) == 0xAB)
    }

    // MARK: - ChunkPool

    @Test func poolAcquireReturnsChunkOfCorrectSize() {
        let pool = ChunkPool(chunkSize: 256)
        let chunk = pool.acquire()
        #expect(chunk.capacity == 256)
    }

    @Test func poolReleaseAndReacquireReusesChunk() {
        let pool = ChunkPool(chunkSize: 512)
        let chunk = pool.acquire()
        pool.release(chunk)
        let chunk2 = pool.acquire()
        #expect(chunk === chunk2)
    }

    @Test func poolMultipleAcquireWithoutReleaseAllocatesNew() {
        let pool = ChunkPool(chunkSize: 128)
        let a = pool.acquire()
        let b = pool.acquire()
        #expect(a !== b)
    }

    @Test func poolAvailableTracksFreeList() {
        let pool = ChunkPool(chunkSize: 256)
        #expect(pool.available == 0)

        let chunk = pool.acquire()
        #expect(pool.available == 0)

        pool.release(chunk)
        #expect(pool.available == 1)
    }

    @Test func poolFreeListIsLIFO() {
        let pool = ChunkPool(chunkSize: 128)
        let a = pool.acquire()
        let b = pool.acquire()
        pool.release(a)
        pool.release(b)
        // LIFO: last released is first acquired
        #expect(pool.acquire() === b)
        #expect(pool.acquire() === a)
    }

    @Test func poolBatchRelease() {
        let pool = ChunkPool(chunkSize: 256)
        let chunks = [pool.acquire(), pool.acquire(), pool.acquire()]
        #expect(pool.available == 0)

        pool.batchRelease(chunks)
        #expect(pool.available == 3)
    }

    @Test func poolBatchReleaseEmptyArray() {
        let pool = ChunkPool(chunkSize: 128)
        pool.batchRelease([])
        #expect(pool.available == 0)
    }

    // MARK: - ChunkPools selection

    @Test func selectExactSizes() {
        #expect(ChunkPools.select(minCapacity: 64).chunkSize == 64)
        #expect(ChunkPools.select(minCapacity: 128).chunkSize == 128)
        #expect(ChunkPools.select(minCapacity: 256).chunkSize == 256)
        #expect(ChunkPools.select(minCapacity: 512).chunkSize == 512)
        #expect(ChunkPools.select(minCapacity: 1024).chunkSize == 1024)
        #expect(ChunkPools.select(minCapacity: 2048).chunkSize == 2048)
        #expect(ChunkPools.select(minCapacity: 65536).chunkSize == 65536)
    }

    @Test func selectRoundsUp() {
        #expect(ChunkPools.select(minCapacity: 65).chunkSize == 128)
        #expect(ChunkPools.select(minCapacity: 129).chunkSize == 256)
        #expect(ChunkPools.select(minCapacity: 1500).chunkSize == 2048)
    }

    @Test func selectTinyAmounts() {
        #expect(ChunkPools.select(minCapacity: 1).chunkSize == 64)
        #expect(ChunkPools.select(minCapacity: 0).chunkSize == 64)
    }

    @Test func selectAtThreshold() {
        // Exactly at the boundary between pools
        #expect(ChunkPools.select(minCapacity: 64).chunkSize == 64)
        #expect(ChunkPools.select(minCapacity: 63).chunkSize == 64)
    }

    @Test func selectMaxClamp() {
        // At max pool size — must be exactly 65536
        let pool = ChunkPools.select(minCapacity: 65536)
        #expect(pool.chunkSize == 65536)
    }

    @Test func poolForFindsExactPool() {
        #expect(ChunkPools.poolFor(chunkCapacity: 64).chunkSize == 64)
        #expect(ChunkPools.poolFor(chunkCapacity: 128).chunkSize == 128)
        #expect(ChunkPools.poolFor(chunkCapacity: 2048).chunkSize == 2048)
        #expect(ChunkPools.poolFor(chunkCapacity: 65536).chunkSize == 65536)
    }

    @Test func allPoolsHaveCorrectSizes() {
        let expectedSizes = [64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536]
        #expect(ChunkPools.all.count == 11)
        for (i, pool) in ChunkPools.all.enumerated() {
            #expect(pool.chunkSize == expectedSizes[i])
        }
    }
}
