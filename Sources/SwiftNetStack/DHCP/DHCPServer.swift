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

    /// Process a DHCP packet. Returns nil if no response is needed,
    /// or a fully-built Ethernet frame (Ethernet + IPv4 + UDP + DHCP) to write back.
    public mutating func process(
        packet: DHCPPacket,
        srcMAC: MACAddress,
        endpointID: Int,
        hostMAC: MACAddress,
        arpMapping: inout ARPMapping,
        round: RoundContext
    ) -> (PacketBuffer, endpointID: Int)? {
        guard var pool = pools[endpointID] else {
            return nil
        }

        let result: (dhcpPayload: PacketBuffer, yiaddr: IPv4Address)?
        switch packet.messageType {
        case .discover:
            result = handleDiscover(
                packet: packet, srcMAC: srcMAC,
                endpointID: endpointID, pool: &pool, round: round
            )
            if result == nil { }
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
        if let (dhcpPayload, yiaddr) = result,
           let frame = buildDHCPFrame(
               hostMAC: hostMAC, clientMAC: srcMAC,
               gatewayIP: pool.gateway, yiaddr: yiaddr,
               dhcpPayload: dhcpPayload, round: round
           ) {
            return (frame, endpointID)
        }
        return nil
    }

    // MARK: - DISCOVER

    private mutating func handleDiscover(
        packet: DHCPPacket, srcMAC: MACAddress,
        endpointID: Int, pool: inout DHCPPool, round: RoundContext
    ) -> (PacketBuffer, IPv4Address)? {
        guard let offeredIP = pool.allocate(clientMAC: srcMAC) else {
            return nil
        }
        guard let pkt = buildDHCPReply(
            messageType: .offer,
            xid: packet.xid,
            chaddr: srcMAC,
            yiaddr: offeredIP,
            pool: pool,
            round: round
        ) else {
            return nil
        }
        return (pkt, offeredIP)
    }

    // MARK: - REQUEST

    private mutating func handleRequest(
        packet: DHCPPacket, srcMAC: MACAddress,
        endpointID: Int, pool: inout DHCPPool,
        arpMapping: inout ARPMapping, round: RoundContext
    ) -> (PacketBuffer, IPv4Address)? {
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

        // Reject if requested IP is pending-offer to a different MAC (audit #1)
        if let pendingMAC = pool.pendingOfferMAC(for: requestedIP), pendingMAC != srcMAC {
            return nil
        }

        // Confirm the lease
        pool.confirm(requestedIP, mac: srcMAC)
        pool.removePendingOffer(requestedIP)
        arpMapping.add(ip: requestedIP, mac: srcMAC, endpointID: endpointID)

        guard let pkt = buildDHCPReply(
            messageType: .ack,
            xid: packet.xid,
            chaddr: srcMAC,
            yiaddr: requestedIP,
            pool: pool,
            round: round
        ) else { return nil }
        return (pkt, requestedIP)
    }

    // MARK: - RELEASE

    private mutating func handleRelease(
        packet: DHCPPacket, srcMAC: MACAddress,
        endpointID: Int, pool: inout DHCPPool,
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

    /// Build raw DHCP payload (BOOTREPLY + magic cookie + options) only.
    /// The caller (`process()`) wraps the payload in Ethernet/IPv4/UDP headers.
    private func buildDHCPReply(
        messageType: DHCPMessageType,
        xid: UInt32,
        chaddr: MACAddress,
        yiaddr: IPv4Address,
        pool: DHCPPool,
        round: RoundContext
    ) -> PacketBuffer? {
        // Calculate total DHCP reply length from option sizes so addition/removal
        // of options cannot cause buffer overrun. The option sizes below must
        // match the writeOption calls that follow.
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
        ptr.advanced(by: 236).storeBytes(of: UInt8(99), as: UInt8.self)
        ptr.advanced(by: 237).storeBytes(of: UInt8(130), as: UInt8.self)
        ptr.advanced(by: 238).storeBytes(of: UInt8(83), as: UInt8.self)
        ptr.advanced(by: 239).storeBytes(of: UInt8(99), as: UInt8.self)

        // Options
        var optOff = 240
        writeOption(53, value: [messageType.rawValue], ptr: ptr, offset: &optOff)
        writeOption(1, value: subnetMaskBytes(pool.subnet.mask), ptr: ptr, offset: &optOff)
        writeOption(3, value: pool.gateway, ptr: ptr, offset: &optOff)
        writeOption(6, value: pool.gateway, ptr: ptr, offset: &optOff)
        writeOption(51, value: pool.leaseTime, ptr: ptr, offset: &optOff)
        writeOption(54, value: pool.gateway, ptr: ptr, offset: &optOff)
        // Option 255: End
        ptr.advanced(by: optOff).storeBytes(of: UInt8(255), as: UInt8.self)

        // Verify option size computation matched actual writes.
        // Compiled out in release; catches stale dhcpLen when options are changed.
        assert(optOff + 1 == dhcpLen,
            "DHCP option length mismatch: wrote \(optOff + 1 - 244) bytes, computed \(optionsLen)")

        return pkt
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

    // MARK: - Frame construction

    /// Wrap a raw DHCP payload in Ethernet/IPv4/UDP headers.
    ///
    /// Constructs a complete L2 frame: Ethernet (14) + IPv4 (20) + UDP (8) + DHCP payload.
    /// Uses `writeIPv4Header` for the IPv4 header and computes a valid UDP pseudo-header
    /// checksum per RFC 768.
    private func buildDHCPFrame(
        hostMAC: MACAddress,
        clientMAC: MACAddress,
        gatewayIP: IPv4Address,
        yiaddr: IPv4Address,
        dhcpPayload: PacketBuffer,
        round: RoundContext
    ) -> PacketBuffer? {
        let dhcpLen = dhcpPayload.totalLength
        let udpLen = udpHeaderLen + dhcpLen
        let ipTotalLen = ipv4HeaderLen + udpLen
        let frameLen = ethHeaderLen + ipTotalLen

        var pkt = round.allocate(capacity: frameLen, headroom: 0)
        guard let ptr = pkt.appendPointer(count: frameLen) else { return nil }

        // ── Ethernet header ──
        clientMAC.write(to: ptr)                                   // dst = client
        hostMAC.write(to: ptr.advanced(by: 6))                     // src = host
        writeUInt16BE(EtherType.ipv4.rawValue, to: ptr.advanced(by: 12))

        // ── IPv4 header (offset 14) ──
        let ipPtr = ptr.advanced(by: ethHeaderLen)
        writeIPv4Header(to: ipPtr, totalLength: UInt16(ipTotalLen), protocol: .udp,
                        srcIP: gatewayIP, dstIP: yiaddr)

        // ── UDP header (offset 34) ──
        let udpPtr = ptr.advanced(by: ethHeaderLen + ipv4HeaderLen)
        writeUInt16BE(67, to: udpPtr)                              // src port = 67
        writeUInt16BE(68, to: udpPtr.advanced(by: 2))              // dst port = 68
        writeUInt16BE(UInt16(udpLen), to: udpPtr.advanced(by: 4))
        writeUInt16BE(0, to: udpPtr.advanced(by: 6))               // checksum placeholder

        // ── DHCP payload (offset 42) ──
        dhcpPayload.withUnsafeReadableBytes { buf in
            udpPtr.advanced(by: udpHeaderLen).copyMemory(from: buf.baseAddress!, byteCount: dhcpLen)
        }

        // ── UDP checksum (RFC 768) ──
        let udpCksum = computeUDPChecksum(
            pseudoSrcAddr: gatewayIP, pseudoDstAddr: yiaddr,
            udpData: udpPtr, udpLen: udpLen
        )
        writeUInt16BE(udpCksum, to: udpPtr.advanced(by: 6))

        return pkt
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
