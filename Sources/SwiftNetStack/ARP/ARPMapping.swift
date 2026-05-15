import Darwin

/// One IP → MAC mapping entry.
public struct ARPEntry {
    public let ip: IPv4Address
    public let mac: MACAddress
    public let endpointID: Int
    public var createdAt: UInt64

    public init(ip: IPv4Address, mac: MACAddress, endpointID: Int) {
        self.ip = ip
        self.mac = mac
        self.endpointID = endpointID
        self.createdAt = UInt64(Darwin.time(nil))
    }

    /// Test-only init with explicit creation timestamp.
    public init(ip: IPv4Address, mac: MACAddress, endpointID: Int, createdAt: UInt64) {
        self.ip = ip
        self.mac = mac
        self.endpointID = endpointID
        self.createdAt = createdAt
    }

    /// Whether this entry has exceeded the given timeout.
    /// - Parameters:
    ///   - now: Current time in seconds since epoch (default: now).
    ///   - timeout: Maximum entry age in seconds (default: 3600 = 1 hour).
    public func isExpired(now: UInt64 = UInt64(Darwin.time(nil)), timeout: UInt64 = 3600) -> Bool {
        now < createdAt || now - createdAt > timeout
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
    private var rateLimiter = RateLimiter<MACAddress>(window: 1, maxRequests: 100)

    /// Build from VMEndpoint list. Gateway IPs are registered with hostMAC.
    public init(hostMAC: MACAddress, endpoints: [VMEndpoint]) {
        self.hostMAC = hostMAC
        for ep in endpoints {
            entries[ep.gateway.addr] = ARPEntry(ip: ep.gateway, mac: hostMAC, endpointID: ep.id)
        }
    }

    // MARK: - Query

    /// Look up the MAC for an IP. Returns nil if unknown or expired.
    public func lookup(ip: IPv4Address, now: UInt64 = UInt64(Darwin.time(nil)),
                       timeout: UInt64 = 3600) -> MACAddress? {
        guard let entry = entries[ip.addr], !entry.isExpired(now: now, timeout: timeout) else { return nil }
        return entry.mac
    }

    /// Look up the endpoint ID for a MAC address. Returns nil if unknown or expired.
    public func lookupEndpoint(mac: MACAddress, now: UInt64 = UInt64(Darwin.time(nil)),
                               timeout: UInt64 = 3600) -> Int? {
        for entry in entries.values where entry.mac == mac {
            if entry.isExpired(now: now, timeout: timeout) { return nil }
            return entry.endpointID
        }
        return nil
    }

    /// Whether this IP is known and not expired.
    public func isKnown(_ ip: IPv4Address, now: UInt64 = UInt64(Darwin.time(nil)),
                        timeout: UInt64 = 3600) -> Bool {
        guard let entry = entries[ip.addr] else { return false }
        return !entry.isExpired(now: now, timeout: timeout)
    }

    // MARK: - Mutation

    /// Add or update an entry. Called by DHCP server on lease allocation.
    public mutating func add(ip: IPv4Address, mac: MACAddress, endpointID: Int,
                              createdAt: UInt64? = nil) {
        if let ts = createdAt {
            entries[ip.addr] = ARPEntry(ip: ip, mac: mac, endpointID: endpointID, createdAt: ts)
        } else {
            entries[ip.addr] = ARPEntry(ip: ip, mac: mac, endpointID: endpointID)
        }
    }

    /// Remove expired entries. Call periodically (every ~60s).
    public mutating func reapExpired(now: UInt64 = UInt64(Darwin.time(nil)),
                                      timeout: UInt64 = 3600) {
        entries = entries.filter { !$0.value.isExpired(now: now, timeout: timeout) }
    }

    /// Remove an entry. Called by DHCP server on lease release.
    public mutating func remove(ip: IPv4Address) {
        entries.removeValue(forKey: ip.addr)
    }

    // MARK: - Proxy ARP

    /// Process an incoming ARP request, writing the reply into IOBuffer.output.
    /// Returns (header offset, header length) or nil if output is full or no reply needed.
    public mutating func processARPRequest(
        _ arp: ARPFrame, io: IOBuffer
    ) -> (hdrOfs: Int, hdrLen: Int)? {
        guard arp.operation == .request else { return nil }
        guard isKnown(arp.targetIP) else { return nil }
        guard rateLimiter.allow(arp.senderMAC) else { return nil }

        guard let ptr = io.allocOutput(42) else { return nil }
        let ofs = ptr - io.output.baseAddress!

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

        return (ofs, 42)
    }

}

