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

        // Build complete Ethernet+IPv4+UDP+DHCP frame in IOBuffer.output
        let udpTotalLen = 8 + dhcpBytes.count
        let ipTotalLen = 20 + udpTotalLen
        let frameLen = 14 + ipTotalLen

        guard let ptr = io.allocOutput(frameLen) else { return nil }
        let ofs = ptr - io.output.baseAddress!

        // Ethernet
        srcMAC.write(to: ptr)
        hostMAC.write(to: ptr.advanced(by: 6))
        writeUInt16BE(EtherType.ipv4.rawValue, to: ptr.advanced(by: 12))

        // IPv4
        let ipPtr = ptr.advanced(by: ethHeaderLen)
        writeIPv4Header(to: ipPtr, totalLength: UInt16(ipTotalLen), protocol: .udp,
                        srcIP: pool.gateway, dstIP: yiaddr)

        // UDP
        let udpPtr = ipPtr.advanced(by: ipv4HeaderLen)
        writeUInt16BE(67, to: udpPtr)
        writeUInt16BE(68, to: udpPtr.advanced(by: 2))
        writeUInt16BE(UInt16(udpTotalLen), to: udpPtr.advanced(by: 4))
        writeUInt16BE(0, to: udpPtr.advanced(by: 6))

        // DHCP payload
        dhcpBytes.withUnsafeBytes { buf in
            udpPtr.advanced(by: 8).copyMemory(from: buf.baseAddress!, byteCount: buf.count)
        }

        // UDP checksum
        let ck = computeUDPChecksum(
            pseudoSrcAddr: pool.gateway, pseudoDstAddr: yiaddr,
            udpData: udpPtr, udpLen: udpTotalLen
        )
        writeUInt16BE(ck, to: udpPtr.advanced(by: 6))

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

    private var available: Set<UInt32>
    /// Confirmed leases: ip.addr → (clientMAC, deadline as seconds-since-epoch).
    private var leases: [UInt32: (mac: MACAddress, deadline: UInt64)] = [:]
    /// Reverse index for O(1) MAC→IP lookup. Maintained alongside `leases`.
    private var macToIP: [MACAddress: UInt32] = [:]
    /// Pending offers: ip.addr → (clientMAC, deadline). Dictionary for O(1) lookup.
    private var pendingOffers: [UInt32: (mac: MACAddress, deadline: UInt64)] = [:]
    /// Per-MAC rate limiter for DISCOVER floods.
    private var rateLimiter = RateLimiter(window: 1, maxRequests: 5)

    init(subnet: IPv4Subnet, gateway: IPv4Address, offerTimeout: UInt64 = 60, leaseTime: UInt32 = 3600) {
        self.subnet = subnet
        self.gateway = gateway
        self.offerTimeout = offerTimeout
        self.leaseTime = leaseTime

        // Available: all IPs in subnet except network, gateway, and broadcast
        let netAddr = subnet.network.addr
        let bcAddr = subnet.broadcast.addr
        let gwAddr = gateway.addr
        precondition(netAddr != 0xFFFFFFFF,
            "DHCP subnet network address 255.255.255.255 is invalid")
        var ips: Set<UInt32> = []
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
            available.insert(addr)
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
            available.insert(addr)
        }
    }

    // MARK: - Pool operations

    /// Allocate a free IP for a DISCOVER. Records a pending offer with expiration.
    mutating func allocate(clientMAC: MACAddress) -> IPv4Address? {
        reapExpiredOffers()
        reapExpiredLeases()

        guard rateLimiter.allow(clientMAC) else { return nil }
        guard let addr = available.popFirst() else { return nil }

        let deadline = Self.now() + offerTimeout
        pendingOffers[addr] = (mac: clientMAC, deadline: deadline)

        #if DEBUG
        debugCheckPoolIntegrity()
        #endif

        return IPv4Address(addr: addr)
    }

    /// Confirm a lease (REQUEST → ACK). Moves IP from available to leases.
    mutating func confirm(_ ip: IPv4Address, mac: MACAddress) {
        available.remove(ip.addr)
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
        available.insert(ip.addr)
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
        let totalTracked = available.count + leases.count + pendingOffers.count
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

// MARK: - Per-MAC rate limiter

/// Sliding-window rate limiter keyed by MAC address.
/// Rejects requests when `maxRequests` is exceeded within `window` seconds.
fileprivate struct RateLimiter {
    let window: UInt64
    let maxRequests: Int

    private var counters: [MACAddress: (count: Int, windowStart: UInt64)] = [:]

    init(window: UInt64, maxRequests: Int) {
        self.window = window
        self.maxRequests = maxRequests
    }
    mutating func allow(_ mac: MACAddress) -> Bool {
        let now = RateLimiter.now()
        if let entry = counters[mac] {
            if now - entry.windowStart < window {
                if entry.count >= maxRequests { return false }
                counters[mac] = (entry.count + 1, entry.windowStart)
            } else {
                counters[mac] = (1, now)
            }
        } else {
            counters[mac] = (1, now)
        }
        return true
    }

    private static func now() -> UInt64 {
        UInt64(Darwin.time(nil))
    }
}
