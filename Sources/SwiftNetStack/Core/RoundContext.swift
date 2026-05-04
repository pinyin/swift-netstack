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

    /// Defer release of all chunks referenced by a PacketBuffer.
    public func deferRelease(_ pkt: consuming PacketBuffer) {
        // PacketBuffer is consumed; its views' storages will be released
        // when the struct is destroyed. But we want them batch-released.
        // Since PacketBuffer is a struct with COW, we can't easily extract
        // the views. Callers should use deferRelease(Storage) for now.
        //
        // In practice, deferRelease is for chunks that were explicitly
        // acquired via acquireStorage() and then wrapped.
        _ = pkt
    }

    // MARK: - Round lifecycle

    /// End the round: batch-release all round-scoped chunks back to their pools.
    ///
    /// Two categories:
    /// 1. **Deferred releases** (`pendingReleases`): explicitly marked chunks → return to pool.
    /// 2. **Untracked single-ref chunks**: acquired via `acquireStorage()` but never
    ///    deferRelease'd and never cloned (refCount==1) → round-scoped, return to pool.
    /// 3. **Cloned chunks** (refCount > 1): held by persistent state (sendBuf/recvBuf)
    ///    → survive the round naturally.
    ///
    /// After this call, all round-scoped Storage is back in the pools.
    /// Persistent chunks remain alive via their clone's ARC reference.
    public func endRound() {
        // Track which chunks were returned to pools to avoid double-release
        var returnedToPool = Set<ObjectIdentifier>()

        // Phase 1: deferred releases explicitly go back to pools
        for chunk in pendingReleases {
            let pool = ChunkPools.poolFor(chunkCapacity: chunk.capacity)
            pool.release(chunk)  // reset refCount to 1, append to freeList
            returnedToPool.insert(ObjectIdentifier(chunk))
        }
        pendingReleases.removeAll(keepingCapacity: true)

        // Phase 2: round-scoped chunks (refCount==1, not already pooled)
        for chunk in allocatedChunks {
            let id = ObjectIdentifier(chunk)
            if returnedToPool.contains(id) { continue }
            if chunk.refCount == 1 {
                // Only RoundContext holds this — return to pool
                let pool = ChunkPools.poolFor(chunkCapacity: chunk.capacity)
                pool.release(chunk)
            }
            // refCount > 1: someone else (sendBuf/recvBuf) cloned it — survives
        }
        allocatedChunks.removeAll(keepingCapacity: true)
    }

    // MARK: - Stats & Debug

    public var stats: (allocated: Int, released: Int, retained: Int) {
        let retained = allocatedChunks.filter { $0.refCount > 1 }.count
        return (allocatedChunks.count, pendingReleases.count, retained)
    }

    #if DEBUG
    /// Verify no unexpected chunk leaks at round end.
    /// A chunk whose refCount == 0 after release means it was allocated
    /// but neither explicitly transferred to persistent state nor released.
    public func verifyNoLeaks() -> [Storage] {
        var leaks: [Storage] = []
        for chunk in allocatedChunks {
            // refCount == 1 means only RoundContext holds a reference —
            // nobody else picked it up (no clone into sendBuf/recvBuf).
            // refCount > 1 means it was transferred to persistent state.
            if chunk.refCount == 1 && !pendingReleases.contains(where: { $0 === chunk }) {
                leaks.append(chunk)
            }
        }
        return leaks
    }
    #endif
}
