import Darwin

// MARK: - PacketBuffer: zero-copy data container

/// Zero-copy network packet container using struct COW semantics.
///
/// A PacketBuffer is a linked list of Views, each referencing a Storage chunk
/// through ARC. All slice/clone operations are O(1) and share underlying memory.
///
/// Mutating operations trigger copy-on-write: if a Storage has more than one
/// reference, it is cloned before modification. This is transparent to callers
/// and requires no manual retain/release — unlike gVisor's approach.
///
/// PacketBuffer is **protocol-agnostic**. It provides raw byte window operations
/// only. Protocol parsing, header construction, and checksums belong to upper layers.
public struct PacketBuffer {
    var _views: [View]

    // MARK: - View (internal)

    struct View {
        var storage: Storage  // var needed for isKnownUniquelyReferenced
        var offset: Int
        var length: Int

        var tailroom: Int { storage.capacity - offset - length }
    }

    // MARK: - Initializers

    /// Wrap an existing Storage chunk as a PacketBuffer.
    public init(storage: Storage, offset: Int, length: Int) {
        precondition(offset >= 0 && length >= 0)
        precondition(offset + length <= storage.capacity)
        self._views = [View(storage: storage, offset: offset, length: length)]
    }

    /// Allocate a new PacketBuffer from the chunk pools.
    /// - Parameters:
    ///   - capacity: Minimum payload capacity needed.
    ///   - headroom: Space reserved before the payload for protocol headers.
    public init(capacity: Int, headroom: Int = 0) {
        let total = headroom + capacity
        let pool = ChunkPools.select(minCapacity: total)
        let storage = pool.acquire()
        self._views = [View(storage: storage, offset: headroom, length: 0)]
    }

    /// Allocate from a specific pool with headroom reservation.
    public static func from(pool: ChunkPool, headroom: Int) -> PacketBuffer {
        let storage = pool.acquire()
        return PacketBuffer(
            storage: storage, offset: headroom, length: 0)
    }

    // MARK: - Queries

    public var totalLength: Int {
        _views.reduce(0) { $0 + $1.length }
    }

    public var headroom: Int {
        _views.first?.offset ?? 0
    }

    public var tailroom: Int {
        guard let last = _views.last else { return 0 }
        return last.tailroom
    }

    public var isEmpty: Bool {
        _views.allSatisfy { $0.length == 0 }
    }

    public var viewCount: Int { _views.count }

    // MARK: - Zero-copy read operations

    /// Create a new view into a subrange (zero-copy, shares Storage).
    /// Returns nil if `from + length` exceeds totalLength.
    public func slice(from start: Int, length: Int) -> PacketBuffer? {
        precondition(start >= 0 && length >= 0)
        var remaining = start
        var need = length
        var newViews: [View] = []

        for view in _views {
            if remaining >= view.length {
                remaining -= view.length
                continue
            }
            let viewStart = view.offset + remaining
            let avail = view.length - remaining
            let take = Swift.min(avail, need)
            newViews.append(View(storage: view.storage, offset: viewStart, length: take))
            need -= take
            remaining = 0
            if need == 0 { break }
        }

        guard need == 0 else { return nil }
        var pb = PacketBuffer.empty
        pb._views = newViews
        return pb
    }

    /// Access readable bytes as a contiguous buffer via a closure.
    /// If the PacketBuffer spans multiple views, they are presented sequentially.
    public func withUnsafeReadableBytes<T>(
        _ body: (UnsafeRawBufferPointer) throws -> T
    ) rethrows -> T {
        if _views.count == 1 {
            let v = _views[0]
            let ptr = v.storage.data.advanced(by: v.offset)
            return try body(UnsafeRawBufferPointer(start: ptr, count: v.length))
        }
        // Multi-view: flatten into a single contiguous buffer
        let total = totalLength
        let flat = UnsafeMutableRawBufferPointer.allocate(
            byteCount: total, alignment: MemoryLayout<UInt8>.alignment)
        defer { flat.deallocate() }
        var offset = 0
        for v in _views {
            if v.length > 0 {
                flat.baseAddress!.advanced(by: offset)
                    .copyMemory(from: v.storage.data.advanced(by: v.offset), byteCount: v.length)
                offset += v.length
            }
        }
        return try body(UnsafeRawBufferPointer(flat))
    }

    // MARK: - Mutating operations (COW)

    /// Ensure the first view's Storage is uniquely owned before modification.
    /// If shared, allocates a new Storage and copies the data.
    private mutating func makeFirstUnique() {
        guard !_views.isEmpty else { return }
        var v = _views.removeFirst()
        guard !isKnownUniquelyReferenced(&v.storage) else {
            _views.insert(v, at: 0)
            return
        }
        // COW: clone the first view's data, then recycle the old shared Storage.
        let pool = ChunkPools.select(minCapacity: v.storage.capacity)
        let newStorage = pool.acquire()
        if v.length > 0 {
            newStorage.data.copyMemory(from: v.storage.data.advanced(by: v.offset), byteCount: v.length)
        }
        _views.insert(View(storage: newStorage, offset: v.offset, length: v.length), at: 0)
        // v.storage was shared before our _views reference was dropped above.
        // After _views.insert, we no longer hold any reference via _views.
        // If v.storage is now uniquely referenced, recycle it before v goes out of scope.
        if isKnownUniquelyReferenced(&v.storage) {
            ChunkPools.poolFor(chunkCapacity: v.storage.capacity).release(v.storage)
        }
    }

    /// Ensure the last view's Storage is uniquely owned before modification.
    private mutating func makeLastUnique() {
        guard !_views.isEmpty else { return }
        var v = _views.removeLast()
        guard !isKnownUniquelyReferenced(&v.storage) else {
            _views.append(v)
            return
        }
        // COW: clone the last view's data, then recycle the old shared Storage.
        let pool = ChunkPools.select(minCapacity: v.storage.capacity)
        let newStorage = pool.acquire()
        if v.length > 0 {
            newStorage.data.copyMemory(from: v.storage.data.advanced(by: v.offset), byteCount: v.length)
        }
        _views.append(View(storage: newStorage, offset: v.offset, length: v.length))
        if isKnownUniquelyReferenced(&v.storage) {
            ChunkPools.poolFor(chunkCapacity: v.storage.capacity).release(v.storage)
        }
    }

    /// Reserve `count` bytes in headroom and return a write pointer.
    /// Triggers COW if the first view's Storage is shared.
    public mutating func prependPointer(count: Int) -> UnsafeMutableRawPointer? {
        guard count > 0, headroom >= count else { return nil }
        makeFirstUnique()
        _views[0].offset -= count
        _views[0].length += count
        return _views[0].storage.data.advanced(by: _views[0].offset)
    }

    /// Reserve `count` bytes in tailroom and return a write pointer.
    /// Triggers COW if the last view's Storage is shared.
    public mutating func appendPointer(count: Int) -> UnsafeMutableRawPointer? {
        guard count > 0, tailroom >= count else { return nil }
        makeLastUnique()
        let idx = _views.count - 1
        let ptr = _views[idx].storage.data.advanced(by: _views[idx].offset + _views[idx].length)
        _views[idx].length += count
        return ptr
    }

    /// Remove `count` bytes from the front of the buffer (zero-copy).
    /// Returns fully-consumed Storage chunks to their pool instead of letting ARC free them.
    public mutating func trimFront(_ count: Int) {
        guard count > 0 else { return }
        precondition(count <= totalLength)
        var remaining = count
        while remaining > 0, !_views.isEmpty {
            if remaining >= _views[0].length {
                remaining -= _views[0].length
                var removedStorage = _views[0].storage
                _views.removeFirst()
                // If this was the last reference, return to pool instead of freeing.
                if isKnownUniquelyReferenced(&removedStorage) {
                    ChunkPools.poolFor(chunkCapacity: removedStorage.capacity).release(removedStorage)
                }
            } else {
                _views[0].offset += remaining
                _views[0].length -= remaining
                remaining = 0
            }
        }
    }

    /// Append another PacketBuffer's views to this one (zero-copy).
    /// Both buffers share the same underlying Storage after this call.
    /// Used for TCP segment reassembly and other multi-view construction.
    public mutating func appendView(_ other: PacketBuffer) {
        if totalLength == 0 {
            _views = other._views
            return
        }
        _views.reserveCapacity(_views.count + other._views.count)
        for view in other._views where view.length > 0 {
            _views.append(view)
        }
    }

    /// Make the first `count` bytes contiguous by copying them into a new
    /// Storage chunk. Returns false if count exceeds totalLength.
    ///
    /// If the first view already contains ≥ count bytes, this is a no-op
    /// returning true. Otherwise, a new Storage is allocated and `count` bytes
    /// are linearized from successive views. Fully consumed views are released;
    /// a partially consumed last view is trimmed. Untouched views pass through.
    public mutating func pullUp(_ count: Int) -> Bool {
        guard count > 0 else { return true }
        guard totalLength >= count else { return false }

        // Already contiguous
        if let first = _views.first, first.length >= count {
            return true
        }

        let pool = ChunkPools.select(minCapacity: count)
        let newStorage = pool.acquire()

        // Copy count bytes from successive views
        var remaining = count
        var newViews: [View] = []
        var consumedStorages: [Storage] = []  // fully consumed views → may be recyclable
        var viewIndex = 0

        for i in 0..<_views.count {
            guard remaining > 0 else { break }
            let take = Swift.min(_views[i].length, remaining)
            if take > 0 {
                let dst = newStorage.data.advanced(by: count - remaining)
                dst.copyMemory(
                    from: _views[i].storage.data.advanced(by: _views[i].offset),
                    byteCount: take)
                remaining -= take
            }

            if take < _views[i].length {
                // Partially consumed: keep remainder as adjusted view
                newViews.append(View(
                    storage: _views[i].storage,
                    offset: _views[i].offset + take,
                    length: _views[i].length - take))
            } else {
                // Fully consumed: track Storage for potential recycling
                consumedStorages.append(_views[i].storage)
            }
            viewIndex = i + 1
        }

        // Untouched views pass through
        for i in viewIndex..<_views.count {
            newViews.append(_views[i])
        }

        // Prepend the merged contiguous view
        newViews.insert(View(storage: newStorage, offset: 0, length: count), at: 0)
        _views = newViews

        // Recycle fully consumed Storage chunks that are now unreferenced.
        // The old _views array held references; after replacing with newViews,
        // consumed Storages may have dropped to refcount 0.
        for var s in consumedStorages {
            if isKnownUniquelyReferenced(&s) {
                ChunkPools.poolFor(chunkCapacity: s.capacity).release(s)
            }
        }

        return true
    }

    /// Remove `count` bytes from the back of the buffer (zero-copy).
    /// Returns fully-consumed Storage chunks to their pool instead of letting ARC free them.
    public mutating func trimBack(_ count: Int) {
        guard count > 0 else { return }
        precondition(count <= totalLength)
        var remaining = count
        while remaining > 0, !_views.isEmpty {
            let lastIdx = _views.count - 1
            if remaining >= _views[lastIdx].length {
                remaining -= _views[lastIdx].length
                var removedStorage = _views[lastIdx].storage
                _views.removeLast()
                if isKnownUniquelyReferenced(&removedStorage) {
                    ChunkPools.poolFor(chunkCapacity: removedStorage.capacity).release(removedStorage)
                }
            } else {
                _views[lastIdx].length -= remaining
                remaining = 0
            }
        }
    }

    // MARK: - Scatter-gather I/O

    /// Build an iovec array for scatter-gather output via sendmsg(2).
    /// Each view maps to one iovec — zero flattening overhead.
    /// gVisor cannot do this because Go's stdlib doesn't expose writev.
    public func iovecs() -> [iovec] {
        _views.compactMap { v in
            guard v.length > 0 else { return nil }
            return iovec(
                iov_base: v.storage.data.advanced(by: v.offset),
                iov_len: v.length
            )
        }
    }


    // MARK: - Internal helpers

    internal static var empty: PacketBuffer {
        PacketBuffer(_views: [])
    }

    private init(_views: [View]) {
        self._views = _views
    }
}

// MARK: - Debug description

extension PacketBuffer: CustomStringConvertible {
    public var description: String {
        "PacketBuffer(views: \(_views.count), len: \(totalLength), headroom: \(headroom), tailroom: \(tailroom))"
    }
}
