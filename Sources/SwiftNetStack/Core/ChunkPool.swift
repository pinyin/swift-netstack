/// Single-size lock-free memory pool of Storage chunks.
///
/// BDP is single-threaded, so acquire/release are plain Array operations
/// with zero synchronization overhead. Compare gVisor's sync.Pool which
/// pays atomic CAS on every get/put.
public final class ChunkPool {
    public let chunkSize: Int
    private var freeList: [Storage] = []

    public init(chunkSize: Int) {
        self.chunkSize = chunkSize
    }

    public func acquire() -> Storage {
        if let s = freeList.popLast() {
            return s
        }
        return Storage.allocate(capacity: chunkSize)
    }

    public func release(_ s: Storage) {
        #if DEBUG
        // Fill with sentinel to expose stale-data bugs (e.g. checksum over
        // uninitialized fields). Any consumer that forgets to overwrite a
        // field will see 0xCC instead of accidentally-correct zeroes.
        s.data.initializeMemory(as: UInt8.self, repeating: 0xCC, count: s.capacity)
        #endif
        freeList.append(s)
    }

    /// Amortized O(1): appends N chunks in a single array operation.
    public func batchRelease(_ chunks: [Storage]) {
        #if DEBUG
        for s in chunks {
            precondition(!freeList.contains(where: { $0 === s }),
                "ChunkPool.batchRelease: duplicate release detected (Storage \(ObjectIdentifier(s)))")
            s.data.initializeMemory(as: UInt8.self, repeating: 0xCC, count: s.capacity)
        }
        #endif
        freeList.append(contentsOf: chunks)
    }

    /// Number of chunks currently available in the pool (for debugging/stats).
    public var available: Int { freeList.count }

    /// Discard all cached chunks. Chunks already acquired by callers are unaffected.
    /// Useful for resetting pool state between test suites.
    public func drain() {
        freeList.removeAll()
    }
}

// MARK: - 11-tier pool set

/// 11 size tiers covering common network packet sizes (64B → 64KB).
///
/// Selection logic mirrors gVisor's `getChunkPool`:
///   poolIndex = MostSignificantOne64(minCapacity >> 6)
///
/// | Index | Size   | Typical use                         |
/// |-------|--------|-------------------------------------|
/// | 0     | 64 B   | ICMP echo, tiny ACK                 |
/// | 1     | 128 B  |                                     |
/// | 2     | 256 B  |                                     |
/// | 3     | 512 B  | DNS query/response                  |
/// | 4     | 1024 B | Small TCP segment                   |
/// | 5     | 2048 B | Typical TCP segment (MTU 1500)      |
/// | 6     | 4096 B |                                     |
/// | 7     | 8192 B |                                     |
/// | 8     | 16384 B| Jumbo frame (page-aligned)          |
/// | 9     | 32768 B| Page-aligned                        |
/// | 10    | 65536 B| Max chunk (page-aligned)            |
public enum ChunkPools {
    // nonisolated(unsafe): ChunkPool has mutable free-lists.
    // Safe because BDP is strictly single-threaded — no concurrent access.
    public static nonisolated(unsafe) let pool64B   = ChunkPool(chunkSize: 64)
    public static nonisolated(unsafe) let pool128B  = ChunkPool(chunkSize: 128)
    public static nonisolated(unsafe) let pool256B  = ChunkPool(chunkSize: 256)
    public static nonisolated(unsafe) let pool512B  = ChunkPool(chunkSize: 512)
    public static nonisolated(unsafe) let pool1K    = ChunkPool(chunkSize: 1024)
    public static nonisolated(unsafe) let pool2K    = ChunkPool(chunkSize: 2048)
    public static nonisolated(unsafe) let pool4K    = ChunkPool(chunkSize: 4096)
    public static nonisolated(unsafe) let pool8K    = ChunkPool(chunkSize: 8192)
    public static nonisolated(unsafe) let pool16K   = ChunkPool(chunkSize: 16384)
    public static nonisolated(unsafe) let pool32K   = ChunkPool(chunkSize: 32768)
    public static nonisolated(unsafe) let pool64K   = ChunkPool(chunkSize: 65536)

    /// All pools indexed by tier (0 = 64B, 10 = 64KB).
    public static nonisolated(unsafe) let all: [ChunkPool] = [
        pool64B, pool128B, pool256B, pool512B,
        pool1K, pool2K, pool4K, pool8K,
        pool16K, pool32K, pool64K,
    ]

    /// Select the smallest pool whose chunk size can hold `minCapacity` bytes.
    ///
    /// Uses leading-zero count to compute the pool index in O(1).
    /// Formula mirrors gVisor's getChunkPool: poolIdx = MSB(minCapacity >> 6).
    /// Clamped to [0, 10].
    public static func select(minCapacity: Int) -> ChunkPool {
        precondition(minCapacity <= 65536, "Requested capacity \(minCapacity) exceeds maximum pool size 65536")
        guard minCapacity > 64 else { return pool64B }
        let shifted = minCapacity >> 6  // baseChunkSizeLog2 = 6
        let msbOneIndexed = 64 - shifted.leadingZeroBitCount
        var poolIndex = msbOneIndexed
        // When minCapacity is an exact power of two (and > 64),
        // the pool at index-1 has chunkSize == minCapacity.
        if minCapacity.nonzeroBitCount == 1 {
            poolIndex -= 1
        }
        return all[Swift.min(poolIndex, 10)]
    }

    /// Reverse lookup: given a chunk's actual capacity, return the exact pool it came from.
    ///
    /// All standard chunk sizes are 64 << index (powers of two), so we use trailing-zero-bit count.
    /// For capacities < 64 (non-standard, heap-allocated), returns pool64B.
    ///
    /// - Precondition: `chunkCapacity` must be a standard pool size (64, 128, 256, … 65536)
    ///   or < 64. Non-standard capacities (e.g., 65, 100) map to the wrong pool.
    ///   Use `select(minCapacity:)` for new allocations — it always returns the correct pool.
    public static func poolFor(chunkCapacity: Int) -> ChunkPool {
        guard chunkCapacity > 64 else { return pool64B }
        let shifted = chunkCapacity >> 6
        let index = shifted.trailingZeroBitCount
        return all[Swift.min(index, 10)]
    }

    /// Discard all cached chunks across all 11 pools.
    /// Use in test setup to isolate tests from pool state left by previous suites.
    public static func drainAll() {
        for pool in all {
            pool.drain()
        }
    }
}
