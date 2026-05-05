import Foundation

/// Raw memory block backing PacketBuffer views.
///
/// For capacities ≥16KB, uses posix_memalign to get page-aligned memory,
/// reducing TLB miss penalty on Apple Silicon (16KB pages).
///
/// Lifetime is managed by Swift ARC. Chunks returned to a ChunkPool are
/// kept alive by the pool's free list. Chunks with no remaining references
/// are deallocated (freed without pool recycling).
public final class Storage {
    public let data: UnsafeMutableRawPointer
    public let capacity: Int
    public let isPageAligned: Bool

    private init(data: UnsafeMutableRawPointer, capacity: Int, isPageAligned: Bool) {
        self.data = data
        self.capacity = capacity
        self.isPageAligned = isPageAligned
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

    deinit {
        if isPageAligned {
            free(data)
        } else {
            data.deallocate()
        }
    }
}
