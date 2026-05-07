/// Configuration for a port-forward rule: external host port → VM (IP, port).
public struct PortForwardEntry {
    public let hostPort: UInt16
    public let vmIP: IPv4Address
    public let vmPort: UInt16
    public let `protocol`: IPProtocol

    public init(hostPort: UInt16, vmIP: IPv4Address, vmPort: UInt16, protocol: IPProtocol = .tcp) {
        self.hostPort = hostPort
        self.vmIP = vmIP
        self.vmPort = vmPort
        self.protocol = `protocol`
    }
}
