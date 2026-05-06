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

    public init(endpoints: [VMEndpoint], offerTimeout: UInt64 = 60) {
        var pools: [Int: DHCPPool] = [:]
        for ep in endpoints {
            pools[ep.id] = DHCPPool(subnet: ep.subnet, gateway: ep.gateway, offerTimeout: offerTimeout)
        }
        self.pools = pools
    }

    /// Process a DHCP packet. Returns nil if no response is needed,
    /// or (response frame, target endpointID) to write back.
    public mutating func process(
        packet: DHCPPacket,
        srcMAC: MACAddress,
        endpointID: Int,
        arpMapping: inout ARPMapping,
        round: RoundContext
    ) -> (PacketBuffer, endpointID: Int)? {
        guard var pool = pools[endpointID] else { return nil }

        let result: PacketBuffer?
        switch packet.messageType {
        case .discover:
            result = handleDiscover(
                packet: packet, srcMAC: srcMAC,
                endpointID: endpointID, pool: &pool, round: round
            )
        case .request:
            result = handleRequest(
                packet: packet, srcMAC: srcMAC,
                endpointID: endpointID, pool: &pool,
                arpMapping: &arpMapping, round: round
            )
        case .release:
            handleRelease(packet: packet, srcMAC: srcMAC,
                          endpointID: endpointID, pool: &pool,
                          arpMapping: &arpMapping)
            result = nil
        default:
            result = nil
        }

        pools[endpointID] = pool
        if let result = result { return (result, endpointID) }
        return nil
    }

    // MARK: - DISCOVER

    private mutating func handleDiscover(
        packet: DHCPPacket, srcMAC: MACAddress,
        endpointID: Int, pool: inout DHCPPool, round: RoundContext
    ) -> PacketBuffer? {
        // Reclaim expired pending offers before allocating.
        // RFC 2131 §4.4.1: servers SHOULD reuse addresses from clients that
        // fail to complete the handshake within a reasonable time.
        pool.reapExpiredOffers()
        guard let offeredIP = pool.allocate(clientMAC: srcMAC) else { return nil }

        return buildDHCPReply(
            messageType: .offer,
            xid: packet.xid,
            chaddr: srcMAC,
            yiaddr: offeredIP,
            pool: pool,
            round: round
        )
    }

    // MARK: - REQUEST

    private mutating func handleRequest(
        packet: DHCPPacket, srcMAC: MACAddress,
        endpointID: Int, pool: inout DHCPPool,
        arpMapping: inout ARPMapping, round: RoundContext
    ) -> PacketBuffer? {
        // Determine the requested IP: use option 50 if present, else ciaddr
        let requestedIP: IPv4Address
        if let opt50 = packet.requestedIP, opt50 != .zero {
            requestedIP = opt50
        } else {
            return nil // cannot determine requested IP
        }

        // If serverIdentifier is set and not ours, this REQUEST is not for us
        if let sid = packet.serverIdentifier, sid != pool.gateway {
            return nil
        }

        // Validate requested IP belongs to this pool's subnet
        guard pool.subnet.contains(requestedIP) else { return nil }

        // Reject if requested IP is already leased to a different MAC
        if let existingMAC = pool.macForIP(requestedIP), existingMAC != srcMAC {
            return nil
        }

        // Confirm the lease
        pool.confirm(requestedIP, mac: srcMAC)
        pool.removePendingOffer(requestedIP)
        arpMapping.add(ip: requestedIP, mac: srcMAC, endpointID: endpointID)

        return buildDHCPReply(
            messageType: .ack,
            xid: packet.xid,
            chaddr: srcMAC,
            yiaddr: requestedIP,
            pool: pool,
            round: round
        )
    }

    // MARK: - RELEASE

    private mutating func handleRelease(
        packet: DHCPPacket, srcMAC: MACAddress,
        endpointID: Int, pool: inout DHCPPool,
        arpMapping: inout ARPMapping
    ) {
        // The released IP is in ciaddr for RELEASE
        // In our simplified impl, we trust the chaddr and release its lease
        if let ip = pool.ipForMAC(srcMAC) {
            pool.release(ip)
            pool.removePendingOffer(ip)
            arpMapping.remove(ip: ip)
        }
    }

    // MARK: - Packet construction

    /// Build raw DHCP payload (BOOTREPLY + magic cookie + options) only.
    /// Caller is responsible for wrapping in Ethernet/IPv4/UDP headers.
    private func buildDHCPReply(
        messageType: DHCPMessageType,
        xid: UInt32,
        chaddr: MACAddress,
        yiaddr: IPv4Address,
        pool: DHCPPool,
        round: RoundContext
    ) -> PacketBuffer? {
        let dhcpLen = 240 + 4 + 34  // header + magic + options

        var pkt = round.allocate(capacity: dhcpLen, headroom: 0)
        guard let ptr = pkt.appendPointer(count: dhcpLen) else { return nil }
        ptr.initializeMemory(as: UInt8.self, repeating: 0, count: dhcpLen)

        // DHCP header
        ptr.storeBytes(of: UInt8(2), as: UInt8.self)                     // op = BOOTREPLY
        ptr.advanced(by: 1).storeBytes(of: UInt8(1), as: UInt8.self)   // htype = Ethernet
        ptr.advanced(by: 2).storeBytes(of: UInt8(6), as: UInt8.self)   // hlen
        writeUInt32BE(xid, to: ptr.advanced(by: 4))                     // xid
        yiaddr.write(to: ptr.advanced(by: 16))                          // yiaddr
        pool.gateway.write(to: ptr.advanced(by: 20))                    // siaddr
        chaddr.write(to: ptr.advanced(by: 28))                          // chaddr

        // Magic cookie
        ptr.advanced(by: 240).storeBytes(of: UInt8(99), as: UInt8.self)
        ptr.advanced(by: 241).storeBytes(of: UInt8(130), as: UInt8.self)
        ptr.advanced(by: 242).storeBytes(of: UInt8(83), as: UInt8.self)
        ptr.advanced(by: 243).storeBytes(of: UInt8(99), as: UInt8.self)

        // Options
        var optOff = 244
        writeOption(53, value: [messageType.rawValue], ptr: ptr, offset: &optOff)
        writeOption(1, value: subnetMaskBytes(pool.subnet.mask), ptr: ptr, offset: &optOff)
        writeOption(3, value: pool.gateway, ptr: ptr, offset: &optOff)
        writeOption(6, value: pool.gateway, ptr: ptr, offset: &optOff)
        writeOption(51, value: pool.leaseTime, ptr: ptr, offset: &optOff)
        writeOption(54, value: pool.gateway, ptr: ptr, offset: &optOff)
        // Option 255: End
        ptr.advanced(by: optOff).storeBytes(of: UInt8(255), as: UInt8.self)

        return pkt
    }

    private func writeOption(_ code: UInt8, value: [UInt8], ptr: UnsafeMutableRawPointer, offset: inout Int) {
        ptr.advanced(by: offset).storeBytes(of: code, as: UInt8.self)
        ptr.advanced(by: offset + 1).storeBytes(of: UInt8(value.count), as: UInt8.self)
        for (i, b) in value.enumerated() {
            ptr.advanced(by: offset + 2 + i).storeBytes(of: b, as: UInt8.self)
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
    let leaseTime: UInt32 = 3600   // 1 hour
    let offerTimeout: UInt64       // seconds before unconfirmed OFFER expires

    private var available: Set<UInt32>
    private var leases: [UInt32: MACAddress] = [:]  // ip.addr → mac
    /// IPs allocated by DISCOVER but not yet confirmed by REQUEST.
    /// Each entry records the (address, clientMAC, deadline as seconds-since-epoch).
    private var pendingOffers: [(addr: UInt32, mac: MACAddress, deadline: UInt64)] = []

    init(subnet: IPv4Subnet, gateway: IPv4Address, offerTimeout: UInt64 = 60) {
        self.subnet = subnet
        self.gateway = gateway
        self.offerTimeout = offerTimeout

        // Available: all IPs in subnet except network, gateway, and broadcast
        let netAddr = subnet.network.addr
        let bcAddr = subnet.broadcast.addr
        let gwAddr = gateway.addr
        var ips: Set<UInt32> = []
        // Clamp pool to reasonable size (skip extremes for sanity)
        let start = max(netAddr + 1, gwAddr + 1)
        let end = bcAddr
        if start < end {
            let count = min(end - start, 65536)
            for i: UInt32 in 0..<count {
                ips.insert(start + i)
            }
        }
        self.available = ips
    }

    // MARK: - Time

    private static func now() -> UInt64 {
        UInt64(Darwin.time(nil))
    }

    // MARK: - Offer expiration

    /// Reclaim expired pending offers, returning their IPs to the available pool.
    mutating func reapExpiredOffers() {
        let currentTime = Self.now()
        var reclaimed: [UInt32] = []
        pendingOffers.removeAll { offer in
            if offer.deadline <= currentTime {
                reclaimed.append(offer.addr)
                return true
            }
            return false
        }
        for addr in reclaimed {
            available.insert(addr)
        }
    }

    // MARK: - Pool operations

    /// Allocate a free IP for a DISCOVER. Records a pending offer with expiration.
    /// Returns nil if pool exhausted.
    mutating func allocate(clientMAC: MACAddress) -> IPv4Address? {
        // Reap expired offers before every allocation attempt
        reapExpiredOffers()

        guard let addr = available.popFirst() else { return nil }

        let deadline = Self.now() + offerTimeout
        pendingOffers.append((addr: addr, mac: clientMAC, deadline: deadline))

        #if DEBUG
        // Pool integrity: the sum of available + leased + pending must be
        // invariant (total pool size minus reserved addresses).
        // This catches both leaks and double-allocations.
        debugCheckPoolIntegrity()
        #endif

        return IPv4Address(addr: addr)
    }

    /// Confirm a lease (REQUEST → ACK). Moves IP from available to leases.
    mutating func confirm(_ ip: IPv4Address, mac: MACAddress) {
        available.remove(ip.addr)
        leases[ip.addr] = mac
    }

    /// Remove an IP from pending offers (called on REQUEST or RELEASE).
    mutating func removePendingOffer(_ ip: IPv4Address) {
        pendingOffers.removeAll { $0.addr == ip.addr }

        #if DEBUG
        debugCheckPoolIntegrity()
        #endif
    }

    /// Release an IP back to the pool.
    mutating func release(_ ip: IPv4Address) {
        leases.removeValue(forKey: ip.addr)
        available.insert(ip.addr)
    }

    /// Get the IP leased to a given MAC, if any.
    func ipForMAC(_ mac: MACAddress) -> IPv4Address? {
        for (addr, m) in leases where m == mac {
            return IPv4Address(addr: addr)
        }
        return nil
    }

    /// Get the MAC that holds a lease for the given IP, if any.
    func macForIP(_ ip: IPv4Address) -> MACAddress? {
        return leases[ip.addr]
    }

    // MARK: - DEBUG integrity check

    #if DEBUG
    private func debugCheckPoolIntegrity() {
        // Pool size invariant: the total pool is all addresses from
        // (max(netAddr+1, gwAddr+1)) to broadcast, clamped to 65536.
        // available + leased + pending should sum to the initial pool size.
        let totalTracked = available.count + leases.count + pendingOffers.count
        // There's no regression in release: compute the expected total
        let netAddr = subnet.network.addr
        let bcAddr = subnet.broadcast.addr
        let gwAddr = gateway.addr
        let start = max(netAddr + 1, gwAddr + 1)
        if start < bcAddr {
            let expectedTotal = Int(min(bcAddr - start, 65536))
            precondition(totalTracked == expectedTotal,
                "DHCP pool integrity violation: available(\(available.count)) + leased(\(leases.count)) + pending(\(pendingOffers.count)) = \(totalTracked), expected \(expectedTotal)")
        }
    }
    #endif
}

// MARK: - Helpers

