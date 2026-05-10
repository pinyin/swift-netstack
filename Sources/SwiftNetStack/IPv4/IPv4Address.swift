/// 4-octet IPv4 address backed by UInt32 in network byte order.
public struct IPv4Address: Equatable, Hashable, CustomStringConvertible {
    public var addr: UInt32  // network byte order

    public init(addr: UInt32) {
        self.addr = addr
    }

    /// Parse from 4 bytes at buffer start (network byte order).
    public init(_ buf: UnsafeRawBufferPointer) {
        precondition(buf.count >= 4)
        self.addr = (UInt32(buf[0]) << 24) | (UInt32(buf[1]) << 16)
                   | (UInt32(buf[2]) << 8)  |  UInt32(buf[3])
    }

    /// Create from four octets.
    public init(_ a: UInt8, _ b: UInt8, _ c: UInt8, _ d: UInt8) {
        self.addr = (UInt32(a) << 24) | (UInt32(b) << 16) | (UInt32(c) << 8) | UInt32(d)
    }

    // nonisolated(unsafe): BDP is single-threaded, no concurrent access.
    public static nonisolated(unsafe) let zero = IPv4Address(0, 0, 0, 0)

    public var description: String {
        let a = UInt8((addr >> 24) & 0xFF)
        let b = UInt8((addr >> 16) & 0xFF)
        let c = UInt8((addr >> 8) & 0xFF)
        let d = UInt8(addr & 0xFF)
        return "\(a).\(b).\(c).\(d)"
    }

    /// Write into 4 bytes at pointer (network byte order).
    public func write(to ptr: UnsafeMutableRawPointer) {
        ptr.storeBytes(of: addr.bigEndian, as: UInt32.self)
    }
}

/// IPv4 protocol numbers (subset).
public enum IPProtocol: UInt8 {
    case icmp = 1
    case tcp  = 6
    case udp  = 17
}

// MARK: - String parsing

/// Parse an IPv4 address from dotted-decimal notation (e.g. "100.64.1.1").
public func parseIPv4(_ s: String) -> IPv4Address? {
    let parts = s.split(separator: ".", omittingEmptySubsequences: false)
    guard parts.count == 4,
          let a = UInt8(parts[0]), let b = UInt8(parts[1]),
          let c = UInt8(parts[2]), let d = UInt8(parts[3]) else { return nil }
    return IPv4Address(a, b, c, d)
}

/// Parse a CIDR subnet (e.g. "100.64.1.0/24") into (network, prefixLength).
public func parseSubnet(_ s: String) -> (IPv4Address, Int)? {
    let parts = s.split(separator: "/")
    guard parts.count == 2,
          let ip = parseIPv4(String(parts[0])),
          let prefix = Int(parts[1]) else { return nil }
    return (ip, prefix)
}
