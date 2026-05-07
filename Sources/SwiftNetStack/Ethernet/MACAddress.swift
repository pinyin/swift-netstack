/// 6-octet MAC address.
public struct MACAddress: Equatable, Hashable, CustomStringConvertible {
    public var octets: (UInt8, UInt8, UInt8, UInt8, UInt8, UInt8)

    public init(_ a: UInt8, _ b: UInt8, _ c: UInt8, _ d: UInt8, _ e: UInt8, _ f: UInt8) {
        self.octets = (a, b, c, d, e, f)
    }

    /// Parse from 6 bytes at buffer start.
    public init(_ buf: UnsafeRawBufferPointer) {
        precondition(buf.count >= 6)
        self.octets = (buf[0], buf[1], buf[2], buf[3], buf[4], buf[5])
    }

    // nonisolated(unsafe): BDP is single-threaded, no concurrent access.
    public static nonisolated(unsafe) let broadcast = MACAddress(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF)
    public static nonisolated(unsafe) let zero = MACAddress(0, 0, 0, 0, 0, 0)

    public static func == (lhs: MACAddress, rhs: MACAddress) -> Bool {
        lhs.octets.0 == rhs.octets.0
        && lhs.octets.1 == rhs.octets.1
        && lhs.octets.2 == rhs.octets.2
        && lhs.octets.3 == rhs.octets.3
        && lhs.octets.4 == rhs.octets.4
        && lhs.octets.5 == rhs.octets.5
    }

    public func hash(into hasher: inout Hasher) {
        let combined = (UInt64(octets.0) << 40) | (UInt64(octets.1) << 32)
                     | (UInt64(octets.2) << 24) | (UInt64(octets.3) << 16)
                     | (UInt64(octets.4) << 8)  |  UInt64(octets.5)
        hasher.combine(combined)
    }

    public var description: String {
        String(format: "%02x:%02x:%02x:%02x:%02x:%02x",
               octets.0, octets.1, octets.2, octets.3, octets.4, octets.5)
    }

    /// Write into 6 bytes at pointer.
    public func write(to ptr: UnsafeMutableRawPointer) {
        ptr.storeBytes(of: octets.0, toByteOffset: 0, as: UInt8.self)
        ptr.storeBytes(of: octets.1, toByteOffset: 1, as: UInt8.self)
        ptr.storeBytes(of: octets.2, toByteOffset: 2, as: UInt8.self)
        ptr.storeBytes(of: octets.3, toByteOffset: 3, as: UInt8.self)
        ptr.storeBytes(of: octets.4, toByteOffset: 4, as: UInt8.self)
        ptr.storeBytes(of: octets.5, toByteOffset: 5, as: UInt8.self)
    }
}

/// EtherType values (subset used by the stack).
public enum EtherType: UInt16 {
    case ipv4 = 0x0800
    case arp  = 0x0806
}
