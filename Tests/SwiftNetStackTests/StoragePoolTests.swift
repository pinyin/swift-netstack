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

    // MARK: - AUDIT: poolFor non-standard capacity

    /// Reproduces `poolFor` edge case: non-power-of-two capacities map to wrong pool.
    /// For capacity 36: shifted=0, trailingZeroBitCount=64, index=64 → clamp to pool64K.
    /// A 36-byte chunk (from `Storage.allocate(capacity: 36)`) would be released to the
    /// wrong pool, contaminating it with a chunk of unexpected size.
    @Test func poolForNonStandardCapacityReturnsWrongPool() {
        // 36 bytes is the size of a reassembled IP datagram (20 header + 16 payload).
        // poolFor should return pool64B (the pool that can hold 36 bytes), but instead
        // returns pool64K due to the shifted==0 edge case.
        let result = ChunkPools.poolFor(chunkCapacity: 36)
        #expect(result.chunkSize == 64,
            "FAIL: poolFor(36) returned pool with chunkSize \(result.chunkSize), expected 64 (pool64B)")
    }

    @Test func poolForSmallNonStandardCapacitiesAreWrong() {
        // All small non-pool-standard capacities hit the same shifted==0 path
        let wrongSizes = [1, 10, 36, 63]
        for cap in wrongSizes {
            let pool = ChunkPools.poolFor(chunkCapacity: cap)
            #expect(pool.chunkSize == 64,
                "FAIL: poolFor(\(cap)) returned pool\(pool.chunkSize)B instead of pool64B")
        }
    }

    // MARK: - AUDIT #4 fix: ChunkPool batchRelease double-release detection

    /// Fix for audit finding #4: `batchRelease` now detects duplicate chunks
    /// via a DEBUG precondition. The precondition catches double-release bugs
    /// at the call site instead of allowing silent aliasing.
    ///
    /// This test verifies the normal single-release + reacquire path.
    @Test func batchReleaseSingleReleaseReacquiresSameChunk() {
        let pool = ChunkPool(chunkSize: 256)
        let chunk = pool.acquire()
        pool.batchRelease([chunk])
        #expect(pool.available == 1)

        let reacquired = pool.acquire()
        #expect(chunk === reacquired, "single release should return same chunk on reacquire")
    }

    /// Verifies that normal batchRelease (distinct chunks) works correctly
    /// and doesn't trigger the duplicate-detection precondition.
    @Test func batchReleaseDistinctChunks() {
        let pool = ChunkPool(chunkSize: 128)
        let a = pool.acquire()
        let b = pool.acquire()
        pool.batchRelease([a, b])
        #expect(pool.available == 2)

        let c = pool.acquire()
        let d = pool.acquire()
        #expect(c !== d, "distinct chunks should be different objects")
    }

    // MARK: - AUDIT: global pool state pollution

    /// Demonstrates that pool state survives across logical test boundaries.
    /// After draining, priming, and leaking, the pool is left with one fewer chunk.
    /// Without `drain()`, `before` would be unpredictable due to cross-suite contamination.
    @Test func globalPoolStatePersistsAcrossOperations() {
        let pool = ChunkPools.pool64B
        pool.drain()
        #expect(pool.available == 0, "pool should be empty after drain")

        // Prime: add a known number of chunks
        let chunks = (0..<3).map { _ in pool.acquire() }
        pool.batchRelease(chunks)
        #expect(pool.available == 3)

        // Simulate a leaky operation: acquire and don't release
        let leaked = pool.acquire()
        _ = leaked

        #expect(pool.available == 2,
            "FAIL: pool state leaked: chunk acquired but not returned, state persists for subsequent tests")
    }
}
