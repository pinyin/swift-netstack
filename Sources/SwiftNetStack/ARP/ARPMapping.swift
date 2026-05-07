import Darwin

/// One IP → MAC mapping entry.
public struct ARPEntry {
    public let ip: IPv4Address
    public let mac: MACAddress
    public let endpointID: Int

    public init(ip: IPv4Address, mac: MACAddress, endpointID: Int) {
        self.ip = ip
        self.mac = mac
        self.endpointID = endpointID
    }
}

/// IP → MAC mapping table, populated by DHCP lease allocation.
///
/// Dictionary-backed O(1) lookup by IP address. MAC→endpoint reverse lookup
/// iterates values (O(N)) since it's a rare path used only for L2 forwarding.
///
/// Proxy ARP: all intra-subnet ARP requests receive a reply with hostMAC,
/// forcing L2 traffic through the gateway.
public struct ARPMapping {
    public let hostMAC: MACAddress
    private var entries: [UInt32: ARPEntry] = [:]

    /// Build from VMEndpoint list. Gateway IPs are registered with hostMAC.
    public init(hostMAC: MACAddress, endpoints: [VMEndpoint]) {
        self.hostMAC = hostMAC
        for ep in endpoints {
            entries[ep.gateway.addr] = ARPEntry(ip: ep.gateway, mac: hostMAC, endpointID: ep.id)
        }
    }

    // MARK: - Query

    /// Look up the MAC for an IP. Returns nil if unknown.
    public func lookup(ip: IPv4Address) -> MACAddress? {
        entries[ip.addr]?.mac
    }

    /// Look up the endpoint ID for a MAC address. Returns nil if unknown.
    public func lookupEndpoint(mac: MACAddress) -> Int? {
        for entry in entries.values where entry.mac == mac {
            return entry.endpointID
        }
        return nil
    }

    /// Whether this IP is known (gateway or DHCP-leased container).
    public func isKnown(_ ip: IPv4Address) -> Bool {
        entries[ip.addr] != nil
    }

    // MARK: - Mutation

    /// Add or update an entry. Called by DHCP server on lease allocation.
    public mutating func add(ip: IPv4Address, mac: MACAddress, endpointID: Int) {
        entries[ip.addr] = ARPEntry(ip: ip, mac: mac, endpointID: endpointID)
    }

    /// Remove an entry. Called by DHCP server on lease release.
    public mutating func remove(ip: IPv4Address) {
        entries.removeValue(forKey: ip.addr)
    }

    // MARK: - Proxy ARP

    /// Process an incoming ARP request.
    /// - targetIP known → generate a proxy ARP reply (Ethernet + ARP frame) with hostMAC
    /// - targetIP unknown → return nil (silently ignore)
    public func processARPRequest(
        _ arp: ARPFrame, round: RoundContext
    ) -> PacketBuffer? {
        guard arp.operation == .request else { return nil }
        guard isKnown(arp.targetIP) else { return nil }

        var reply = round.allocate(capacity: 64, headroom: 0)
        guard let ptr = reply.appendPointer(count: 42) else { return nil }

        // Ethernet header (14 bytes)
        arp.senderMAC.write(to: ptr)                             // dst = sender
        hostMAC.write(to: ptr.advanced(by: 6))                    // src = us
        writeUInt16BE(0x0806, to: ptr.advanced(by: 12))         // EtherType = ARP

        // ARP body (28 bytes)
        let arpPtr = ptr.advanced(by: 14)
        writeUInt16BE(1, to: arpPtr)                              // htype = Ethernet
        writeUInt16BE(0x0800, to: arpPtr.advanced(by: 2))        // ptype = IPv4
        arpPtr.advanced(by: 4).storeBytes(of: UInt8(6), as: UInt8.self)  // hlen = 6
        arpPtr.advanced(by: 5).storeBytes(of: UInt8(4), as: UInt8.self)  // plen = 4
        writeUInt16BE(ARPOperation.reply.rawValue, to: arpPtr.advanced(by: 6))  // operation
        hostMAC.write(to: arpPtr.advanced(by: 8))                  // sender MAC = us
        arp.targetIP.write(to: arpPtr.advanced(by: 14))            // sender IP = target
        arp.senderMAC.write(to: arpPtr.advanced(by: 18))           // target MAC = requester
        arp.senderIP.write(to: arpPtr.advanced(by: 24))            // target IP = requester

        return reply
    }
}

