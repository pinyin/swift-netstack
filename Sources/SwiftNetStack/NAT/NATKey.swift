/// 5-tuple connection identifier for NAT connection tracking.
///
/// Uniquely identifies a proxied TCP connection by the VM-side and external-side
/// address/port pairs. Used as the dictionary key in NATTable.
public struct NATKey: Hashable, Equatable {
    public let vmIP: IPv4Address
    public let vmPort: UInt16
    public let dstIP: IPv4Address
    public let dstPort: UInt16
    public let `protocol`: IPProtocol

    public init(vmIP: IPv4Address, vmPort: UInt16, dstIP: IPv4Address, dstPort: UInt16, protocol: IPProtocol = .tcp) {
        self.vmIP = vmIP
        self.vmPort = vmPort
        self.dstIP = dstIP
        self.dstPort = dstPort
        self.protocol = `protocol`
    }
}
