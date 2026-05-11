/// Tracks all allocations within a single deliberation round.
///
/// RoundContext is the BDP-exclusive layer that gVisor has no equivalent for —
/// gVisor doesn't know where a "round" begins or ends. It enables:
/// - Batch chunk release at round end (amortized O(1))
/// - Deterministic leak detection (explicit checkpoints)
/// - Round-scoped vs persistent lifetime distinction
///
/// Usage:
///   let round = RoundContext()
///   let pkt = round.allocate(capacity: 1500, headroom: 54)
///   // ... deliberation ...
///   round.endRound()  // batch-reclaims all round-scoped chunks
public final class RoundContext {
    private var allocatedChunks: [Storage] = []
    private var pendingReleases: [Storage] = []

    /// Monotonically increasing round number, set by the deliberation loop.
    /// Exposed for debug logging correlation — not used for allocation logic.
    public var roundNumber: UInt64 = 0

    public init() {}

    // MARK: - Allocation

    /// Acquire a Storage chunk from the appropriate pool (tracked for round-end batch release).
    public func acquireStorage(minCapacity: Int) -> Storage {
        let pool = ChunkPools.select(minCapacity: minCapacity)
        let chunk = pool.acquire()
        allocatedChunks.append(chunk)
        return chunk
    }

    /// Allocate a PacketBuffer with the given capacity and headroom.
    /// The resulting buffer is tracked by this round context.
    public func allocate(capacity: Int, headroom: Int = 0) -> PacketBuffer {
        let total = headroom + capacity
        let storage = acquireStorage(minCapacity: total)
        return PacketBuffer(storage: storage, offset: headroom, length: 0)
    }

    // MARK: - Release

    /// Defer release of a chunk to round end (batch-reclaimed).
    /// Use for round-scoped data that won't survive the round.
    public func deferRelease(_ chunk: Storage) {
        pendingReleases.append(chunk)
    }

    // MARK: - Round lifecycle

    /// End the round: batch-release all round-scoped chunks back to their pools.
    ///
    /// Two categories:
    /// 1. **Deferred releases** (`pendingReleases`): explicitly marked chunks → return to pool.
    /// 2. **Round-scoped chunks**: acquired via `acquireStorage()` and no longer referenced
    ///    outside this RoundContext → return to pool. Detected via `isKnownUniquelyReferenced`
    ///    (Swift ARC), which correctly tracks all strong references including those held by
    ///    PacketBuffer.View structs.
    ///
    /// After this call, all round-scoped Storage is back in the pools.
    /// Persistent chunks (held by transport outputs, sendBuf/recvBuf) survive
    /// because their Swift ARC references prevent recycling.
    public func endRound() {
        // Group chunks by capacity (maps 1:1 to pool) for batch release
        var byCapacity: [Int: [Storage]] = [:]

        // Phase 1: deferred releases
        for chunk in pendingReleases {
            byCapacity[chunk.capacity, default: []].append(chunk)
        }
        pendingReleases.removeAll(keepingCapacity: true)

        // Phase 2: round-scoped chunks — use Swift ARC to detect whether
        // chunks are still referenced outside this RoundContext.
        // Move chunks out of allocatedChunks first to drop one reference.
        var candidates = allocatedChunks
        allocatedChunks.removeAll(keepingCapacity: true)

        // Pop one at a time. After removal from candidates, the chunk is
        // held only by the local variable. isKnownUniquelyReferenced
        // returns true iff no other Swift ARC references exist.
        while !candidates.isEmpty {
            var chunk = candidates.removeLast()
            if isKnownUniquelyReferenced(&chunk) {
                byCapacity[chunk.capacity, default: []].append(chunk)
            }
        }

        // Batch release: single append(contentsOf:) per pool
        for (capacity, chunks) in byCapacity {
            ChunkPools.poolFor(chunkCapacity: capacity).batchRelease(chunks)
        }
    }

    // MARK: - Stats & Debug

    public var stats: (allocated: Int, released: Int) {
        return (allocatedChunks.count, pendingReleases.count)
    }

    #if DEBUG
    /// Verify no unexpected chunk leaks at round end.
    /// Returns chunks still in allocatedChunks that are held only by
    /// this RoundContext — these were allocated but never transferred
    /// to persistent state or outputs.
    public func verifyNoLeaks() -> [Storage] {
        // Pop one at a time from a copy to check uniqueness
        var remaining = allocatedChunks
        var leaks: [Storage] = []
        while !remaining.isEmpty {
            var chunk = remaining.removeLast()
            if isKnownUniquelyReferenced(&chunk) {
                leaks.append(chunk)
            }
        }
        return leaks
    }
    #endif
}

