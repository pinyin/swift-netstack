/// A southbound VM network endpoint.
///
/// Each VM corresponds to one vNIC fd (from VZFileHandleNetworkDevice).
/// The bridge inside the VM works in transparent mode, so container MACs
/// are visible through the vNIC. Container IPs are dynamically assigned
/// by DHCP and tracked in ARPMapping, not here.
public struct VMEndpoint {
    public let id: Int
    public let fd: Int32
    public let subnet: IPv4Subnet
    public let gateway: IPv4Address
    public let mtu: Int

    public init(id: Int, fd: Int32, subnet: IPv4Subnet, gateway: IPv4Address, mtu: Int = 1500) {
        self.id = id
        self.fd = fd
        self.subnet = subnet
        self.gateway = gateway
        self.mtu = mtu
    }
}
