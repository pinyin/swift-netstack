/// CIDR subnet, e.g. 100.64.1.0/24.
public struct IPv4Subnet: Equatable, CustomStringConvertible, @unchecked Sendable {
    public let network: IPv4Address
    public let prefixLength: UInt8

    public var mask: UInt32 {
        prefixLength == 0 ? 0 : ~0 << (32 - prefixLength)
    }

    public init(network: IPv4Address, prefixLength: UInt8) {
        precondition(prefixLength <= 32)
        let m: UInt32 = prefixLength == 0 ? 0 : ~0 << (32 - prefixLength)
        self.network = IPv4Address(addr: network.addr & m)
        self.prefixLength = prefixLength
    }

    public func contains(_ ip: IPv4Address) -> Bool {
        (ip.addr & mask) == (network.addr & mask)
    }

    public var broadcast: IPv4Address {
        IPv4Address(addr: network.addr | ~mask)
    }

    public var description: String {
        "\(network)/\(prefixLength)"
    }
}
