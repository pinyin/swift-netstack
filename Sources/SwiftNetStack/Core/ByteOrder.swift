/// Big-endian write helpers for raw packet construction.
/// Internal: callers are protocol reply builders; not part of public API.

@inline(__always)
func writeUInt16BE(_ value: UInt16, to ptr: UnsafeMutableRawPointer) {
    ptr.storeBytes(of: value.bigEndian, as: UInt16.self)
}

@inline(__always)
func writeUInt32BE(_ value: UInt32, to ptr: UnsafeMutableRawPointer) {
    ptr.storeBytes(of: value.bigEndian, as: UInt32.self)
}
