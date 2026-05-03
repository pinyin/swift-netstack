import Foundation

// MARK: - NetBuf: Zero-copy network buffer

/// A zero-copy network buffer with headroom for prepending headers
/// and tailroom for appending payload. Multiple NetBuf instances can
/// share the same underlying storage via zero-copy slicing.
///
/// NetBuf uses a reference-class `Storage` wrapper to defeat Swift's
/// CoW semantics on `[UInt8]`, ensuring mutations through
/// `withUnsafeMutableBytes` never trigger an unexpected buffer copy.
///
/// Thread-safety: NetBuf is NOT thread-safe. It is designed for BDP's
/// single-threaded deliberation loop. No atomic operations are used.
public final class NetBuf {

    // MARK: - Storage

    /// Shared backing store. Wrapping `[UInt8]` in a reference type defeats
    /// CoW: `storage.buffer` has a single owner (the Storage instance), so
    /// `withUnsafeMutableBytes` never allocates a copy.
    public final class Storage {
        public var buffer: [UInt8]

        public init(capacity: Int) {
            self.buffer = [UInt8](repeating: 0, count: capacity)
        }
    }

    // MARK: - Properties

    private let _storage: Storage

    /// Offset of valid data within `_storage.buffer`.
    public var offset: Int

    /// Number of valid data bytes.
    public var length: Int

    /// Bytes available before `offset` (can be written via prepend).
    public var headroom: Int { offset }

    /// Bytes available after `offset + length` (can be written via append).
    public var tailroom: Int { _storage.buffer.count - offset - length }

    /// Total capacity of the backing store.
    public var totalCapacity: Int { _storage.buffer.count }

    /// Convenience: total bytes (headroom + data + tailroom).
    public var totalLength: Int { _storage.buffer.count }

    // MARK: - Initializers

    /// Create an empty buffer with reserved headroom.
    /// Data region starts at `headroom`, length is 0.
    public init(capacity: Int, headroom: Int = 0) {
        precondition(capacity >= 0 && headroom >= 0 && headroom <= capacity,
                     "NetBuf: invalid capacity=\(capacity) headroom=\(headroom)")
        self._storage = Storage(capacity: capacity)
        self.offset = headroom
        self.length = 0
    }

    /// Create a buffer by copying existing bytes, with optional headroom.
    public init(copying data: [UInt8], headroom: Int = 0) {
        let cap = headroom + data.count
        self._storage = Storage(capacity: cap)
        self.offset = headroom
        self.length = data.count
        data.withUnsafeBytes { ptr in
            _storage.buffer.withUnsafeMutableBytes { dst in
                memcpy(dst.baseAddress!.advanced(by: offset), ptr.baseAddress!, data.count)
            }
        }
    }

    /// Create a buffer by copying raw bytes, with optional headroom.
    public init(copying ptr: UnsafeRawPointer, count: Int, headroom: Int = 0) {
        let cap = headroom + count
        self._storage = Storage(capacity: cap)
        self.offset = headroom
        self.length = count
        _storage.buffer.withUnsafeMutableBytes { dst in
            memcpy(dst.baseAddress!.advanced(by: offset), ptr, count)
        }
    }

    /// Create a zero-copy view into an existing Storage.
    /// The new NetBuf shares the same backing buffer.
    public init(storage: Storage, offset: Int, length: Int) {
        precondition(offset >= 0 && length >= 0 && offset + length <= storage.buffer.count,
                     "NetBuf: invalid slice offset=\(offset) length=\(length) capacity=\(storage.buffer.count)")
        self._storage = storage
        self.offset = offset
        self.length = length
    }

    /// Empty buffer singleton.
    public static var empty: NetBuf { NetBuf(capacity: 0, headroom: 0) }

    // MARK: - Zero-Copy Slicing

    /// Create a zero-copy slice sharing the same backing storage.
    /// Returns nil if `from + count` exceeds the data region.
    public func slice(from: Int, count: Int) -> NetBuf? {
        guard from >= 0, count >= 0, from + count <= length else { return nil }
        return NetBuf(storage: _storage, offset: offset + from, length: count)
    }

    /// Create a zero-copy slice from `from` to the end of the data region.
    public func slice(from: Int) -> NetBuf? {
        guard from >= 0, from <= length else { return nil }
        return NetBuf(storage: _storage, offset: offset + from, length: length - from)
    }

    // MARK: - Prepending (consumes headroom)

    /// Copy `count` bytes from `bytes` into the headroom, expanding the data
    /// region backwards. Returns false if headroom is insufficient.
    @discardableResult
    public func prepend(bytes: UnsafeRawPointer, count: Int) -> Bool {
        guard count > 0 else { return true }
        guard count <= headroom else { return false }
        offset -= count
        length += count
        _storage.buffer.withUnsafeMutableBytes { dst in
            memcpy(dst.baseAddress!.advanced(by: offset), bytes, count)
        }
        return true
    }

    /// Copy bytes from a `[UInt8]` into the headroom.
    @discardableResult
    public func prepend(copying data: [UInt8]) -> Bool {
        data.withUnsafeBytes { prepend(bytes: $0.baseAddress!, count: data.count) }
    }

    /// Copy data from another NetBuf into the headroom.
    @discardableResult
    public func prepend(copying other: NetBuf) -> Bool {
        other.withUnsafeReadableBytes { prepend(bytes: $0.baseAddress!, count: other.length) }
    }

    // MARK: - Appending (consumes tailroom)

    /// Copy `count` bytes from `bytes` into the tailroom, expanding the data
    /// region forwards. Returns false if tailroom is insufficient.
    @discardableResult
    public func append(bytes: UnsafeRawPointer, count: Int) -> Bool {
        guard count > 0 else { return true }
        guard count <= tailroom else { return false }
        _storage.buffer.withUnsafeMutableBytes { dst in
            memcpy(dst.baseAddress!.advanced(by: offset + length), bytes, count)
        }
        length += count
        return true
    }

    /// Copy bytes from a `[UInt8]` into the tailroom.
    @discardableResult
    public func append(copying data: [UInt8]) -> Bool {
        data.withUnsafeBytes { append(bytes: $0.baseAddress!, count: data.count) }
    }

    /// Copy data from another NetBuf into the tailroom.
    @discardableResult
    public func append(copying other: NetBuf) -> Bool {
        other.withUnsafeReadableBytes { append(bytes: $0.baseAddress!, count: other.length) }
    }

    // MARK: - Pointer Access

    /// Provides a read-only pointer to the data region via a closure.
    /// The pointer is valid only within the closure body.
    public func withUnsafeReadableBytes<T>(
        _ body: (UnsafeRawBufferPointer) throws -> T
    ) rethrows -> T {
        try _storage.buffer.withUnsafeBytes { raw in
            let ptr = UnsafeRawBufferPointer(
                start: raw.baseAddress!.advanced(by: offset),
                count: length
            )
            return try body(ptr)
        }
    }

    /// Provides a mutable pointer to the data region via a closure.
    /// The pointer is valid only within the closure body.
    public func withUnsafeMutableDataBytes<T>(
        _ body: (UnsafeMutableRawBufferPointer) throws -> T
    ) rethrows -> T {
        try _storage.buffer.withUnsafeMutableBytes { raw in
            let ptr = UnsafeMutableRawBufferPointer(
                start: raw.baseAddress!.advanced(by: offset),
                count: length
            )
            return try body(ptr)
        }
    }

    /// Reserve `count` bytes of headroom and return a mutable pointer
    /// the caller writes into directly. Returns nil if headroom insufficient.
    /// After writing, the caller does NOT need to call any other method —
    /// offset and length are already adjusted.
    public func prependPointer(count: Int) -> UnsafeMutablePointer<UInt8>? {
        guard count > 0, count <= headroom else { return nil }
        offset -= count
        length += count
        return _storage.buffer.withUnsafeMutableBytes { raw in
            raw.baseAddress!.advanced(by: offset).assumingMemoryBound(to: UInt8.self)
        }
    }

    /// Reserve `count` bytes of tailroom and return a mutable pointer
    /// the caller writes into directly. Returns nil if tailroom insufficient.
    public func appendPointer(count: Int) -> UnsafeMutablePointer<UInt8>? {
        guard count > 0, count <= tailroom else { return nil }
        let ptr = _storage.buffer.withUnsafeMutableBytes { raw in
            raw.baseAddress!.advanced(by: offset + length).assumingMemoryBound(to: UInt8.self)
        }
        length += count
        return ptr
    }

    // MARK: - Modification in Place

    /// Write a single byte at a specific offset within the data region.
    public func setByte(at dataOffset: Int, _ value: UInt8) {
        guard dataOffset >= 0, dataOffset < length else { return }
        _storage.buffer.withUnsafeMutableBytes { raw in
            raw.baseAddress!.advanced(by: offset + dataOffset).storeBytes(of: value, as: UInt8.self)
        }
    }

    /// Write a UInt16 in network byte order at a specific offset within the data region.
    public func setUInt16BE(at dataOffset: Int, _ value: UInt16) {
        guard dataOffset >= 0, dataOffset + 1 < length else { return }
        _storage.buffer.withUnsafeMutableBytes { raw in
            let p = raw.baseAddress!.advanced(by: offset + dataOffset)
            p.storeBytes(of: UInt8(value >> 8), as: UInt8.self)
            p.advanced(by: 1).storeBytes(of: UInt8(value & 0xFF), as: UInt8.self)
        }
    }

    // MARK: - Conversion

    /// Copy data into a new `[UInt8]`. Prefer `withUnsafeReadableBytes` in hot paths.
    public func toArray() -> [UInt8] {
        guard length > 0 else { return [] }
        var arr = [UInt8](repeating: 0, count: length)
        arr.withUnsafeMutableBytes { dst in
            _storage.buffer.withUnsafeBytes { src in
                memcpy(dst.baseAddress!, src.baseAddress!.advanced(by: offset), length)
            }
        }
        return arr
    }

    /// Copy data into a new `Data`. Prefer `withUnsafeReadableBytes` in hot paths.
    public func toData() -> Data {
        guard length > 0 else { return Data() }
        return withUnsafeReadableBytes { Data(bytes: $0.baseAddress!, count: length) }
    }

    // MARK: - Shrink Headroom / Tailroom

    /// Reduce headroom by `amount` bytes. This logically moves the start
    /// of the available prepend space forward without copying data.
    /// Useful when headroom must be freed for other uses.
    public func shrinkHeadroom(_ amount: Int) {
        guard amount > 0, amount <= headroom else { return }
        offset -= amount
        // Data region expanded by `amount` — caller must interpret accordingly
    }
}
