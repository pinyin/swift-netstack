import Testing
@testable import SwiftNetStack

@Suite(.serialized)
struct RoundContextTests {

    // MARK: - Allocation

    @Test func allocateCreatesPacketBuffer() {
        let round = RoundContext()
        let pkt = round.allocate(capacity: 100, headroom: 20)
        #expect(pkt.headroom == 20)
        #expect(pkt.totalLength == 0)
        round.endRound()
    }

    @Test func acquireStorageReturnsValidChunk() {
        let round = RoundContext()
        let storage = round.acquireStorage(minCapacity: 512)
        #expect(storage.capacity >= 512)
        #expect(storage.refCount >= 1)
        storage.release()
        round.endRound()
    }

    // MARK: - Stats

    @Test func statsAfterAllocation() {
        let round = RoundContext()
        _ = round.allocate(capacity: 1024)
        let s = round.stats
        #expect(s.allocated == 1)
        #expect(s.released == 0)
        #expect(s.retained == 0)
        round.endRound()
    }

    @Test func statsAfterDeferredRelease() {
        let round = RoundContext()
        let storage = round.acquireStorage(minCapacity: 256)
        round.deferRelease(storage)
        let s = round.stats
        #expect(s.allocated == 1)
        #expect(s.released == 1)
        round.endRound()
    }

    // MARK: - endRound

    @Test func endRoundBatchReleasesDeferredChunks() {
        let round = RoundContext()
        let storage = round.acquireStorage(minCapacity: 256)

        // Get the pool before release
        let pool = ChunkPools.select(minCapacity: 256)
        let beforeAvailable = pool.available

        round.deferRelease(storage)
        round.endRound()

        // After endRound, the chunk should be back in the pool
        #expect(pool.available == beforeAvailable + 1)
    }

    @Test func endRoundWithNoDeferredReleases() {
        let round = RoundContext()
        _ = round.allocate(capacity: 512)
        // No deferRelease calls — endRound should still work fine
        round.endRound()
    }

    @Test func multipleAllocationsAndDeferredReleases() {
        let round = RoundContext()
        let chunks = (0..<5).map { _ in round.acquireStorage(minCapacity: 128) }
        #expect(round.stats.allocated == 5)

        for chunk in chunks {
            round.deferRelease(chunk)
        }
        #expect(round.stats.released == 5)

        round.endRound()
        // All should be returned to the appropriate pool
    }

    // MARK: - Bulk allocation from pools

    @Test func allocateSelectsRightPool() {
        let round = RoundContext()
        // capacity=1500 + headroom=54 = 1554 → MSB of (1554>>6=24) = 5 → pool[5]=2048
        let pkt = round.allocate(capacity: 1500, headroom: 54)
        #expect(pkt.headroom == 54)
        #expect(pkt.tailroom >= 1500)
        round.endRound()
    }

    // MARK: - Edge cases

    @Test func emptyRoundContext() {
        let round = RoundContext()
        let s = round.stats
        #expect(s.allocated == 0)
        #expect(s.released == 0)
        #expect(s.retained == 0)
        round.endRound()
    }
}
