import Testing
@testable import SwiftNetStack

/// Tests for RoundContext: tracking allocations, deferred release, endRound recycling.
@Suite(.serialized)
struct RoundContextTests {

    // MARK: - Allocation tracking

    @Test func allocateCreatesPacketBuffer() {
        let round = RoundContext()
        let pkt = round.allocate(capacity: 100, headroom: 20)
        #expect(pkt.headroom == 20)
        #expect(pkt.totalLength == 0)
        round.endRound()
    }

    @Test func allocateSelectsRightPool() {
        let round = RoundContext()
        let pkt = round.allocate(capacity: 1500, headroom: 54)
        #expect(pkt.headroom == 54)
        #expect(pkt.tailroom >= 1500)
        round.endRound()
    }

    @Test func acquireStorageReturnsValidChunk() {
        let round = RoundContext()
        let storage = round.acquireStorage(minCapacity: 512)
        #expect(storage.capacity >= 512)
        round.endRound()
    }

    // MARK: - Stats

    @Test func statsAfterAllocation() {
        let round = RoundContext()
        _ = round.allocate(capacity: 1024)
        #expect(round.stats.allocated == 1)
        #expect(round.stats.released == 0)
        round.endRound()
    }

    @Test func statsAfterDeferredRelease() {
        let round = RoundContext()
        let storage = round.acquireStorage(minCapacity: 256)
        round.deferRelease(storage)
        #expect(round.stats.allocated == 1)
        #expect(round.stats.released == 1)
        round.endRound()
    }

    @Test func emptyRoundContext() {
        let round = RoundContext()
        #expect(round.stats.allocated == 0)
        #expect(round.stats.released == 0)
        round.endRound()
    }

    // MARK: - endRound

    @Test func endRoundRecyclesDeferredChunks() {
        let pool = ChunkPools.pool256B
        while pool.available > 0 { _ = pool.acquire() }

        let round = RoundContext()
        let chunk = round.acquireStorage(minCapacity: 256)
        round.deferRelease(chunk)
        round.endRound()

        #expect(pool.available == 1)
    }

    @Test func endRoundWithNoDeferredReleases() {
        let round = RoundContext()
        _ = round.allocate(capacity: 512)
        round.endRound()
        // Should not crash or leak
    }

    @Test func endRoundRecyclesImplicitChunks() {
        let pool = ChunkPools.pool64B
        while pool.available > 0 { _ = pool.acquire() }

        let round = RoundContext()
        do {
            _ = round.allocate(capacity: 64, headroom: 0)
        }
        round.endRound()

        #expect(pool.available == 1)
    }

    @Test func endRoundSkipsChunksWithExternalReferences() {
        let pool = ChunkPools.pool64B
        while pool.available > 0 { _ = pool.acquire() }

        let round = RoundContext()
        let pkt = round.allocate(capacity: 64, headroom: 0)

        withExtendedLifetime(pkt) {
            round.endRound()
            #expect(pool.available == 0)
        }
    }

    @Test func multipleAllocationsAndReleases() {
        let round = RoundContext()
        let chunks = (0..<5).map { _ in round.acquireStorage(minCapacity: 128) }
        #expect(round.stats.allocated == 5)

        for chunk in chunks {
            round.deferRelease(chunk)
        }
        #expect(round.stats.released == 5)
        round.endRound()
    }

    @Test func poolRecyclingWithMultipleAllocations() {
        let pool = ChunkPools.pool256B
        while pool.available > 0 { _ = pool.acquire() }

        let round = RoundContext()
        for _ in 0..<3 {
            _ = round.allocate(capacity: 200, headroom: 0)
        }
        round.endRound()

        #expect(pool.available == 3)
    }
}
