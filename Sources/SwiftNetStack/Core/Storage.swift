import Foundation

/// Raw memory block backing PacketBuffer views.
///
/// For capacities ≥16KB, uses posix_memalign to get page-aligned memory,
/// reducing TLB miss penalty on Apple Silicon (16KB pages).
///
/// RefCount is non-atomic — BDP is single-threaded, no concurrent access.
public final class Storage {
    public let data: UnsafeMutableRawPointer
    public let capacity: Int
    public let isPageAligned: Bool

    private(set) public var refCount: Int

    private init(data: UnsafeMutableRawPointer, capacity: Int, isPageAligned: Bool) {
        self.data = data
        self.capacity = capacity
        self.isPageAligned = isPageAligned
        self.refCount = 1
    }

    public static func allocate(capacity: Int) -> Storage {
        precondition(capacity > 0, "Storage capacity must be > 0")
        if capacity >= 16384 {
            var ptr: UnsafeMutableRawPointer?
            let rc = posix_memalign(&ptr, 16384, capacity)
            precondition(rc == 0, "posix_memalign failed with \(rc)")
            return Storage(data: ptr!, capacity: capacity, isPageAligned: true)
        }
        let ptr = UnsafeMutableRawPointer.allocate(
            byteCount: capacity, alignment: MemoryLayout<UInt64>.alignment)
        return Storage(data: ptr, capacity: capacity, isPageAligned: false)
    }

    public func retain() {
        refCount += 1
    }

    /// Drops one reference. Returns true when refCount reaches zero
    /// (caller must return to pool or free memory).
    @discardableResult
    public func release() -> Bool {
        refCount -= 1
        return refCount == 0
    }

    /// Reset refCount to 1 for pool reuse. Called by ChunkPool.release()
    /// before appending to the free list.
    func resetRefCount() {
        refCount = 1
    }

    deinit {
        // Safety net: properly tracked Storage is always returned to a pool
        // and kept alive by the pool's free-list. If deinit fires, the chunk
        // was never returned to a pool — free the memory directly.
        if isPageAligned {
            free(data)
        } else {
            data.deallocate()
        }
    }
}
