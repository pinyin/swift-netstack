import Testing
@testable import SwiftNetStack

@Suite(.serialized)
struct ChunkPoolTests {

    // MARK: - Basic acquire/release

    @Test func acquireReturnsChunkOfCorrectSize() {
        let pool = ChunkPool(chunkSize: 2048)
        let s = pool.acquire()
        #expect(s.capacity == 2048)
        pool.release(s)
    }

    @Test func releaseAndReacquireReusesChunk() {
        let pool = ChunkPool(chunkSize: 1024)
        let s1 = pool.acquire()
        pool.release(s1)
        let s2 = pool.acquire()
        #expect(s1 === s2, "Released chunk should be reused via free-list")
    }

    @Test func multipleAcquireWithoutReleaseAllocatesNew() {
        let pool = ChunkPool(chunkSize: 512)
        let s1 = pool.acquire()
        let s2 = pool.acquire()
        #expect(s1 !== s2, "Without release, each acquire allocates a new chunk")
        pool.release(s1)
        pool.release(s2)
    }

    @Test func freeListIsLIFO() {
        let pool = ChunkPool(chunkSize: 256)
        let a = pool.acquire()
        let b = pool.acquire()
        pool.release(b)
        pool.release(a)
        let c = pool.acquire()
        let d = pool.acquire()
        #expect(c === a, "LIFO: last released = first acquired")
        #expect(d === b, "LIFO: first released = second acquired")
        pool.release(c)
        pool.release(d)
    }

    // MARK: - Batch release

    @Test func batchReleaseReusesAllChunks() {
        let pool = ChunkPool(chunkSize: 1024)
        let chunks = (0..<10).map { _ in pool.acquire() }
        #expect(pool.available == 0)

        pool.batchRelease(chunks)
        #expect(pool.available == 10)

        var reacquired: [Storage] = []
        for _ in 0..<10 {
            reacquired.append(pool.acquire())
        }
        #expect(pool.available == 0)

        for chunk in chunks {
            pool.release(chunk)
        }
    }

    @Test func batchReleaseEmptyArray() {
        let pool = ChunkPool(chunkSize: 512)
        #expect(pool.available == 0)
        pool.batchRelease([])
        #expect(pool.available == 0)
    }

    // MARK: - ChunkPools selection

    @Test func selectExactSizes() {
        // MSB-based selection rounds UP (like gVisor): exact pool sizes land in the next tier.
        // pool[0]=64 → capacity 64 picks 64
        #expect(ChunkPools.select(minCapacity: 64).chunkSize == 64)
        // pool[1]=128 → but 128>>6=2, MSB=2, pool[2]=256
        #expect(ChunkPools.select(minCapacity: 128).chunkSize == 256)
        #expect(ChunkPools.select(minCapacity: 256).chunkSize == 512)
        #expect(ChunkPools.select(minCapacity: 512).chunkSize == 1024)
        #expect(ChunkPools.select(minCapacity: 1024).chunkSize == 2048)
        #expect(ChunkPools.select(minCapacity: 2048).chunkSize == 4096)
        #expect(ChunkPools.select(minCapacity: 4096).chunkSize == 8192)
        #expect(ChunkPools.select(minCapacity: 8192).chunkSize == 16384)
        #expect(ChunkPools.select(minCapacity: 16384).chunkSize == 32768)
        #expect(ChunkPools.select(minCapacity: 32768).chunkSize == 65536)
        // 65536 is the max pool; MSB caps at 10
        #expect(ChunkPools.select(minCapacity: 65536).chunkSize == 65536)
    }

    @Test func selectRoundUp() {
        // 65 bytes needs 128-byte pool
        #expect(ChunkPools.select(minCapacity: 65).chunkSize == 128)
        // 1500 bytes needs 2048-byte pool
        #expect(ChunkPools.select(minCapacity: 1500).chunkSize == 2048)
        // 2049 bytes needs 4096-byte pool
        #expect(ChunkPools.select(minCapacity: 2049).chunkSize == 4096)
        // 16000 bytes needs 16384-byte pool
        #expect(ChunkPools.select(minCapacity: 16000).chunkSize == 16384)
    }

    @Test func selectTinyAmounts() {
        #expect(ChunkPools.select(minCapacity: 1).chunkSize == 64)
        #expect(ChunkPools.select(minCapacity: 0).chunkSize == 64)
        #expect(ChunkPools.select(minCapacity: 63).chunkSize == 64)
    }

    @Test func selectAtThreshold() {
        // MSB formula rounds exact power-of-two to next pool
        #expect(ChunkPools.select(minCapacity: 2048).chunkSize == 4096)
        // One byte over, same pool
        #expect(ChunkPools.select(minCapacity: 2049).chunkSize == 4096)
    }

    // MARK: - Available count

    @Test func availableTracksFreeListSize() {
        let pool = ChunkPool(chunkSize: 128)
        #expect(pool.available == 0)

        let s1 = pool.acquire()
        let s2 = pool.acquire()
        #expect(pool.available == 0)

        pool.release(s1)
        #expect(pool.available == 1)

        pool.release(s2)
        #expect(pool.available == 2)

        pool.batchRelease([pool.acquire(), pool.acquire()])
        #expect(pool.available == 2)
    }
}
