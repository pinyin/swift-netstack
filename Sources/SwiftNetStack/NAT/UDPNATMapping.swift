import Darwin

/// Per-mapping UDP NAT state.
///
/// Each UDP 5-tuple mapping owns a dedicated socket. Per-mapping sockets make
/// the fd→key reverse lookup trivial and match the TCP pattern — every NAT entry
/// (TCP or UDP) maps one fd to one key.
struct UDPNATMapping {
    let key: NATKey
    let fd: Int32
    let createdAt: UInt64
    var lastActivity: UInt64
    let vmMAC: MACAddress
    let endpointID: Int
    let isInbound: Bool

    init(key: NATKey, fd: Int32, vmMAC: MACAddress, endpointID: Int, isInbound: Bool) {
        self.key = key
        self.fd = fd
        self.createdAt = UInt64(Darwin.time(nil))
        self.lastActivity = self.createdAt
        self.vmMAC = vmMAC
        self.endpointID = endpointID
        self.isInbound = isInbound
    }
}
