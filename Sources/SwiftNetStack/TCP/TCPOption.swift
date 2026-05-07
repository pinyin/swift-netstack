/// Parsed TCP option.
public enum TCPOption: Equatable {
    case mss(UInt16)
    case unknown(kind: UInt8, data: [UInt8])

    /// Parse options from the variable-length options field.
    /// `data` is the raw bytes after the fixed 20-byte TCP header.
    static func parse(_ data: UnsafeRawBufferPointer) -> [TCPOption] {
        var options: [TCPOption] = []
        var offset = 0
        while offset < data.count {
            let kind = data[offset]
            if kind == 0 { offset += 1; continue }        // End of Option List
            if kind == 1 { offset += 1; continue }        // No-Operation
            guard offset + 1 < data.count else { break }
            let len = Int(data[offset + 1])
            if len < 2 || offset + len > data.count { break }
            if kind == 2 && len == 4 {
                let mss = (UInt16(data[offset + 2]) << 8) | UInt16(data[offset + 3])
                options.append(.mss(mss))
            } else {
                let payload = Array(data[(offset + 2)..<(offset + len)])
                options.append(.unknown(kind: kind, data: payload))
            }
            offset += len
        }
        return options
    }
}
