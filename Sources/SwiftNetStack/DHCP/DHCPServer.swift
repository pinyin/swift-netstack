import Darwin

/// Simplified DHCP server (RFC 2131 subset).
///
/// Handles DISCOVER → OFFER, REQUEST → ACK, RELEASE → reclaim.
/// Writes IP→MAC mappings into ARPMapping on lease allocation.
///
/// `offerTimeout`: seconds before an unconfirmed OFFER is reclaimed.
/// Set to 0 in tests to instantly expire pending offers.
public struct DHCPServer {
    private var pools: [Int: DHCPPool]   // endpointID → pool

    public init(endpoints: [VMEndpoint], offerTimeout: UInt64 = 60, leaseTime: UInt32 = 3600) {
        var pools: [Int: DHCPPool] = [:]
        for ep in endpoints {
            pools[ep.id] = DHCPPool(subnet: ep.subnet, gateway: ep.gateway, offerTimeout: offerTimeout, leaseTime: leaseTime)
        }
        self.pools = pools
    }

    /// Process a DHCP packet, writing the complete reply frame into IOBuffer.output.
    /// Returns (header offset, header length, endpointID) or nil if no reply needed.
    public mutating func process(
        packet: DHCPPacket,
        srcMAC: MACAddress,
        endpointID: Int,
        hostMAC: MACAddress,
        arpMapping: inout ARPMapping,
        io: IOBuffer
    ) -> (hdrOfs: Int, hdrLen: Int, epID: Int)? {
        guard var pool = pools[endpointID] else { return nil }

        let result: (dhcpBytes: [UInt8], yiaddr: IPv4Address)?
        switch packet.messageType {
        case .discover:
            result = handleDiscover(packet: packet, srcMAC: srcMAC, pool: &pool)
        case .request:
            result = handleRequest(packet: packet, srcMAC: srcMAC, pool: &pool,
                                   arpMapping: &arpMapping, endpointID: endpointID)
        case .release:
            handleRelease(packet: packet, srcMAC: srcMAC, pool: &pool, arpMapping: &arpMapping)
            result = nil
        default:
            result = nil
        }

        pools[endpointID] = pool
        guard let (dhcpBytes, yiaddr) = result else { return nil }

        let frameLen = 14 + 20 + 8 + dhcpBytes.count
        guard let ofs = dhcpBytes.withUnsafeBytes({ buf in
            buildUDPFrame(io: io, dstMAC: srcMAC, srcMAC: hostMAC,
                          srcIP: pool.gateway, dstIP: yiaddr,
                          srcPort: 67, dstPort: 68,
                          payloadPtr: buf.baseAddress!, payloadLen: buf.count)
        }) else { return nil }

        return (ofs, frameLen, endpointID)
    }

    // MARK: - DISCOVER

    private mutating func handleDiscover(
        packet: DHCPPacket, srcMAC: MACAddress, pool: inout DHCPPool
    ) -> ([UInt8], IPv4Address)? {
        guard let offeredIP = pool.allocate(clientMAC: srcMAC) else { return nil }
        let pkt = buildDHCPReply(messageType: .offer, xid: packet.xid,
                                  chaddr: srcMAC, yiaddr: offeredIP, pool: pool)
        return (pkt, offeredIP)
    }

    // MARK: - REQUEST

    private mutating func handleRequest(
        packet: DHCPPacket, srcMAC: MACAddress, pool: inout DHCPPool,
        arpMapping: inout ARPMapping, endpointID: Int
    ) -> ([UInt8], IPv4Address)? {
        let requestedIP: IPv4Address
        if let opt50 = packet.requestedIP, opt50 != .zero {
            requestedIP = opt50
        } else {
            return nil
        }
        if let sid = packet.serverIdentifier, sid != pool.gateway { return nil }
        guard pool.subnet.contains(requestedIP) else { return nil }
        if let existingMAC = pool.macForIP(requestedIP), existingMAC != srcMAC { return nil }
        if let pendingMAC = pool.pendingOfferMAC(for: requestedIP), pendingMAC != srcMAC { return nil }

        pool.confirm(requestedIP, mac: srcMAC)
        pool.removePendingOffer(requestedIP)
        arpMapping.add(ip: requestedIP, mac: srcMAC, endpointID: endpointID)

        let pkt = buildDHCPReply(messageType: .ack, xid: packet.xid,
                                  chaddr: srcMAC, yiaddr: requestedIP, pool: pool)
        return (pkt, requestedIP)
    }

    // MARK: - RELEASE

    private mutating func handleRelease(
        packet: DHCPPacket, srcMAC: MACAddress,
        pool: inout DHCPPool,
        arpMapping: inout ARPMapping
    ) {
        // RFC 2131: RELEASE uses ciaddr to identify the IP being released.
        let ip: IPv4Address
        if packet.ciaddr != .zero {
            ip = packet.ciaddr
        } else if let macIP = pool.ipForMAC(srcMAC) {
            // Fallback for clients that don't set ciaddr
            ip = macIP
        } else {
            return
        }
        pool.release(ip)
        pool.removePendingOffer(ip)
        arpMapping.remove(ip: ip)
    }

    // MARK: - Packet construction

    /// Build raw DHCP payload bytes (BOOTREPLY + magic cookie + options).
    private func buildDHCPReply(
        messageType: DHCPMessageType,
        xid: UInt32,
        chaddr: MACAddress,
        yiaddr: IPv4Address,
        pool: DHCPPool
    ) -> [UInt8] {
        let optionsLen =
            (2 + 1) +  // option 53: message type
            (2 + 4) +  // option 1: subnet mask
            (2 + 4) +  // option 3: router
            (2 + 4) +  // option 6: DNS
            (2 + 4) +  // option 51: lease time
            (2 + 4) +  // option 54: server ID
            1           // option 255: End
        let magicLen = 4
        let headerLen = 236
        let dhcpLen = headerLen + magicLen + optionsLen

        var buf = [UInt8](repeating: 0, count: dhcpLen)
        buf.withUnsafeMutableBytes { ptr in
            let p = ptr.baseAddress!
            p.storeBytes(of: UInt8(2), as: UInt8.self)                     // op = BOOTREPLY
            p.advanced(by: 1).storeBytes(of: UInt8(1), as: UInt8.self)   // htype = Ethernet
            p.advanced(by: 2).storeBytes(of: UInt8(6), as: UInt8.self)   // hlen
            writeUInt32BE(xid, to: p.advanced(by: 4))
            yiaddr.write(to: p.advanced(by: 16))
            pool.gateway.write(to: p.advanced(by: 20))
            chaddr.write(to: p.advanced(by: 28))

            p.advanced(by: 236).storeBytes(of: UInt8(99), as: UInt8.self)
            p.advanced(by: 237).storeBytes(of: UInt8(130), as: UInt8.self)
            p.advanced(by: 238).storeBytes(of: UInt8(83), as: UInt8.self)
            p.advanced(by: 239).storeBytes(of: UInt8(99), as: UInt8.self)

            var optOff = 240
            writeOption(53, value: [messageType.rawValue], ptr: p, offset: &optOff)
            writeOption(1, value: subnetMaskBytes(pool.subnet.mask), ptr: p, offset: &optOff)
            writeOption(3, value: pool.gateway, ptr: p, offset: &optOff)
            writeOption(6, value: pool.gateway, ptr: p, offset: &optOff)
            writeOption(51, value: pool.leaseTime, ptr: p, offset: &optOff)
            writeOption(54, value: pool.gateway, ptr: p, offset: &optOff)
            p.advanced(by: optOff).storeBytes(of: UInt8(255), as: UInt8.self)
            assert(optOff + 1 == dhcpLen,
                "DHCP option length mismatch: wrote \(optOff + 1 - 244) bytes, computed \(optionsLen)")
        }
        return buf
    }

    private func writeOption(_ code: UInt8, value: [UInt8], ptr: UnsafeMutableRawPointer, offset: inout Int) {
        ptr.advanced(by: offset).storeBytes(of: code, as: UInt8.self)
        ptr.advanced(by: offset + 1).storeBytes(of: UInt8(value.count), as: UInt8.self)
        value.withUnsafeBufferPointer { buf in
            ptr.advanced(by: offset + 2).copyMemory(from: buf.baseAddress!, byteCount: value.count)
        }
        offset += 2 + value.count
    }

    private func writeOption(_ code: UInt8, value: IPv4Address, ptr: UnsafeMutableRawPointer, offset: inout Int) {
        ptr.advanced(by: offset).storeBytes(of: code, as: UInt8.self)
        ptr.advanced(by: offset + 1).storeBytes(of: UInt8(4), as: UInt8.self)
        value.write(to: ptr.advanced(by: offset + 2))
        offset += 6
    }

    private func writeOption(_ code: UInt8, value: UInt32, ptr: UnsafeMutableRawPointer, offset: inout Int) {
        ptr.advanced(by: offset).storeBytes(of: code, as: UInt8.self)
        ptr.advanced(by: offset + 1).storeBytes(of: UInt8(4), as: UInt8.self)
        writeUInt32BE(value, to: ptr.advanced(by: offset + 2))
        offset += 6
    }

    private func subnetMaskBytes(_ mask: UInt32) -> [UInt8] {
        [UInt8((mask >> 24) & 0xFF), UInt8((mask >> 16) & 0xFF),
         UInt8((mask >> 8) & 0xFF),  UInt8(mask & 0xFF)]
    }

}

// MARK: - DHCPPool

private struct DHCPPool {
    let subnet: IPv4Subnet
    let gateway: IPv4Address
    let leaseTime: UInt32          // seconds before confirmed lease expires
    let offerTimeout: UInt64       // seconds before unconfirmed OFFER expires

    /// First allocatable IP in the subnet (network addr + 1, skipping gateway).
    private let poolStart: UInt32
    /// One past the last allocatable IP (broadcast addr).
    private let poolEnd: UInt32

    /// Pre-populated set of free IPs. Only used when poolSize ≤ 65536 (up to /16).
    /// When nil, allocation falls back to linear probing from `nextProbe`.
    private var available: Set<UInt32>?
    /// Next IP to probe for allocation (only used when available == nil).
    private var nextProbe: UInt32 = 0

    /// Confirmed leases: ip.addr → (clientMAC, deadline as seconds-since-epoch).
    private var leases: [UInt32: (mac: MACAddress, deadline: UInt64)] = [:]
    /// Reverse index for O(1) MAC→IP lookup. Maintained alongside `leases`.
    private var macToIP: [MACAddress: UInt32] = [:]
    /// Pending offers: ip.addr → (clientMAC, deadline). Dictionary for O(1) lookup.
    private var pendingOffers: [UInt32: (mac: MACAddress, deadline: UInt64)] = [:]
    /// Per-MAC rate limiter for DISCOVER floods.
    private var rateLimiter = RateLimiter<MACAddress>(window: 1, maxRequests: 5)

    init(subnet: IPv4Subnet, gateway: IPv4Address, offerTimeout: UInt64 = 60, leaseTime: UInt32 = 3600) {
        self.subnet = subnet
        self.gateway = gateway
        self.offerTimeout = offerTimeout
        self.leaseTime = leaseTime

        let netAddr = subnet.network.addr
        let bcAddr = subnet.broadcast.addr
        let gwAddr = gateway.addr
        precondition(netAddr != 0xFFFFFFFF,
            "DHCP subnet network address 255.255.255.255 is invalid")

        let start = netAddr + 1
        let end = bcAddr
        self.poolStart = start
        self.poolEnd = end

        guard start < end else {
            self.available = []
            return
        }
        let poolSize = end - start
        if poolSize <= 65536 {
            // Pre-populated set for O(1) allocation on typical /16-or-smaller subnets.
            var ips: Set<UInt32> = []
            ips.reserveCapacity(Int(poolSize))
            for i: UInt32 in 0..<poolSize {
                let addr = start + i
                if addr == gwAddr { continue }
                ips.insert(addr)
            }
            self.available = ips
        } else {
            // Subnet too large for pre-population — use linear probing.
            self.available = nil
            self.nextProbe = start == gwAddr ? start &+ 1 : start
        }
    }

    // MARK: - Time

    private static func now() -> UInt64 {
        UInt64(Darwin.time(nil))
    }

    // MARK: - Expiration

    /// Reclaim expired pending offers, returning their IPs to the available pool.
    mutating func reapExpiredOffers() {
        let currentTime = Self.now()
        var reclaimed: [UInt32] = []
        for (addr, entry) in pendingOffers {
            if entry.deadline <= currentTime { reclaimed.append(addr) }
        }
        for addr in reclaimed {
            pendingOffers.removeValue(forKey: addr)
            if available != nil { available?.insert(addr) }
        }
    }

    /// Reclaim expired confirmed leases, returning their IPs to the available pool.
    mutating func reapExpiredLeases() {
        let currentTime = Self.now()
        var reclaimed: [UInt32] = []
        for (addr, entry) in leases {
            if entry.deadline <= currentTime { reclaimed.append(addr) }
        }
        for addr in reclaimed {
            if let entry = leases.removeValue(forKey: addr) {
                macToIP.removeValue(forKey: entry.mac)
            }
            if available != nil { available?.insert(addr) }
        }
    }

    // MARK: - Pool operations

    /// Allocate a free IP for a DISCOVER. Records a pending offer with expiration.
    mutating func allocate(clientMAC: MACAddress) -> IPv4Address? {
        reapExpiredOffers()
        reapExpiredLeases()

        guard rateLimiter.allow(clientMAC) else { return nil }

        let addr: UInt32
        if var av = available {
            guard let a = av.popFirst() else { return nil }
            addr = a
            self.available = av
        } else {
            guard let found = probeFreeAddr() else { return nil }
            addr = found
        }

        let deadline = Self.now() + offerTimeout
        pendingOffers[addr] = (mac: clientMAC, deadline: deadline)

        #if DEBUG
        debugCheckPoolIntegrity()
        #endif

        return IPv4Address(addr: addr)
    }

    /// Linear-probe for an unallocated IP. Used only when the subnet is too large
    /// to pre-populate a Set (> 65536 IPs, i.e. larger than /16).
    /// Wraps around; returns nil if no free IP exists after a full scan.
    private mutating func probeFreeAddr() -> UInt32? {
        let gwAddr = gateway.addr
        var probe = nextProbe
        for _ in 0..<min(poolEnd &- poolStart, 65536) {
            if probe >= poolEnd { probe = poolStart }
            if probe == gwAddr { probe &+= 1; continue }
            if leases[probe] == nil && pendingOffers[probe] == nil {
                nextProbe = probe &+ 1
                if nextProbe >= poolEnd || nextProbe < poolStart { nextProbe = poolStart }
                return probe
            }
            probe &+= 1
        }
        return nil  // pool exhausted
    }

    /// Confirm a lease (REQUEST → ACK). Moves IP from available to leases.
    mutating func confirm(_ ip: IPv4Address, mac: MACAddress) {
        if available != nil { available?.remove(ip.addr) }
        let deadline = Self.now() + UInt64(leaseTime)
        leases[ip.addr] = (mac: mac, deadline: deadline)
        macToIP[mac] = ip.addr
    }

    /// Remove an IP from pending offers (called on REQUEST or RELEASE).
    mutating func removePendingOffer(_ ip: IPv4Address) {
        pendingOffers.removeValue(forKey: ip.addr)

        #if DEBUG
        debugCheckPoolIntegrity()
        #endif
    }

    /// Release an IP back to the pool.
    mutating func release(_ ip: IPv4Address) {
        if let entry = leases.removeValue(forKey: ip.addr) {
            macToIP.removeValue(forKey: entry.mac)
        }
        if available != nil { available?.insert(ip.addr) }
    }

    /// Get the IP leased to a given MAC, if any. O(1) via reverse index.
    func ipForMAC(_ mac: MACAddress) -> IPv4Address? {
        macToIP[mac].map { IPv4Address(addr: $0) }
    }

    /// Get the MAC that holds a lease for the given IP, if any. O(1).
    func macForIP(_ ip: IPv4Address) -> MACAddress? {
        leases[ip.addr]?.mac
    }

    /// Get the MAC for which the given IP has a pending (unconfirmed) offer, if any. O(1).
    func pendingOfferMAC(for ip: IPv4Address) -> MACAddress? {
        pendingOffers[ip.addr]?.mac
    }

    // MARK: - DEBUG integrity check

    #if DEBUG
    private func debugCheckPoolIntegrity() {
        guard available != nil else { return }  // skip for probing-based pools
        let totalTracked = available!.count + leases.count + pendingOffers.count
        let netAddr = subnet.network.addr
        let bcAddr = subnet.broadcast.addr
        let gwAddr = gateway.addr
        let start = netAddr &+ 1
        if start < bcAddr {
            let poolSize = bcAddr &- start
            let totalIPs = Int(min(poolSize, 65536))
            let gwExcluded = (gwAddr >= start && gwAddr < bcAddr) ? 1 : 0
            let expectedTotal = totalIPs - gwExcluded
            precondition(totalTracked == expectedTotal,
                "DHCP pool integrity violation: available(\(available!.count)) + leased(\(leases.count)) + pending(\(pendingOffers.count)) = \(totalTracked), expected \(expectedTotal)")
        }
    }
    #endif
}