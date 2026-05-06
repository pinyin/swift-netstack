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
