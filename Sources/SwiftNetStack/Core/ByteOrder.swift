/// Big-endian read/write helpers for raw packet construction and parsing.

@inline(__always)
func readUInt16BE(_ ptr: UnsafeRawPointer, _ offset: Int) -> UInt16 {
    let p = ptr.assumingMemoryBound(to: UInt8.self).advanced(by: offset)
    return (UInt16(p[0]) << 8) | UInt16(p[1])
}

@inline(__always)
func readUInt32BE(_ ptr: UnsafeRawPointer, _ offset: Int) -> UInt32 {
    let p = ptr.assumingMemoryBound(to: UInt8.self).advanced(by: offset)
    return (UInt32(p[0]) << 24) | (UInt32(p[1]) << 16) | (UInt32(p[2]) << 8) | UInt32(p[3])
}

@inline(__always)
func writeUInt16BE(_ value: UInt16, to ptr: UnsafeMutableRawPointer) {
    ptr.storeBytes(of: value.bigEndian, as: UInt16.self)
}

@inline(__always)
func writeUInt32BE(_ value: UInt32, to ptr: UnsafeMutableRawPointer) {
    ptr.storeBytes(of: value.bigEndian, as: UInt32.self)
}
