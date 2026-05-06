/// DHCP message type (RFC 2131, option 53).
public enum DHCPMessageType: UInt8 {
    case discover = 1
    case offer    = 2
    case request  = 3
    case decline  = 4
    case ack      = 5
    case nak      = 6
    case release  = 7
}

/// Parsed DHCP packet from UDP payload.
///
/// Extracts only the fields needed for a simplified DHCP server:
/// operation, transaction ID, client MAC, message type, and key options.
public struct DHCPPacket {
    public let op: UInt8              // 1=BOOTREQUEST, 2=BOOTREPLY
    public let xid: UInt32            // transaction ID
    public let ciaddr: IPv4Address    // client IP address (RELEASE uses this, RFC 2131)
    public let chaddr: MACAddress     // client hardware address
    public let messageType: DHCPMessageType
    public let requestedIP: IPv4Address?      // option 50
    public let serverIdentifier: IPv4Address? // option 54

    public init(op: UInt8, xid: UInt32, chaddr: MACAddress, messageType: DHCPMessageType,
                ciaddr: IPv4Address = .zero, requestedIP: IPv4Address? = nil,
                serverIdentifier: IPv4Address? = nil) {
        self.op = op; self.xid = xid; self.ciaddr = ciaddr
        self.chaddr = chaddr; self.messageType = messageType
        self.requestedIP = requestedIP; self.serverIdentifier = serverIdentifier
    }

    /// Parse from a UDP payload (PacketBuffer). Returns nil if too short or invalid.
    public static func parse(from pkt: PacketBuffer) -> DHCPPacket? {
        var pkt = pkt
        // Minimum: 240-byte fixed header + magic cookie (4) + option 53 (3) = 247
        guard pkt.totalLength >= 247 else { return nil }
        // Pull up the entire DHCP payload for single-view option scanning.
        // DHCP packets are small (typically ~300 bytes), so this copy is cheap.
        let len = pkt.totalLength
        guard pkt.pullUp(len) else { return nil }

        return pkt.withUnsafeReadableBytes { buf -> DHCPPacket? in
            let op = buf[0]
            let xid = (UInt32(buf[4]) << 24) | (UInt32(buf[5]) << 16)
                     | (UInt32(buf[6]) << 8)  |  UInt32(buf[7])
            let ciaddr = IPv4Address(UnsafeRawBufferPointer(rebasing: buf[12..<16]))
            let chaddr = MACAddress(UnsafeRawBufferPointer(rebasing: buf[28..<34]))

            // Options start at offset 240. Must begin with magic cookie.
            guard buf[240] == 99, buf[241] == 130, buf[242] == 83, buf[243] == 99 else {
                return nil // bad magic cookie
            }

            // Scan options for type 53 (DHCP message type), 50 (requested IP), 54 (server ID)
            var msgType: DHCPMessageType? = nil
            var reqIP: IPv4Address? = nil
            var serverID: IPv4Address? = nil
            var i = 244
            while i < buf.count {
                let optCode = buf[i]
                if optCode == 0 { i += 1; continue }  // Pad — skip, don't terminate (RFC 2132 §3.1)
                if optCode == 255 { break }   // End
                if i + 1 >= buf.count { break }
                let optLen = Int(buf[i + 1])
                if i + 2 + optLen > buf.count { break }

                switch optCode {
                case 53 where optLen == 1:
                    msgType = DHCPMessageType(rawValue: buf[i + 2])
                case 50 where optLen == 4:
                    reqIP = IPv4Address(UnsafeRawBufferPointer(rebasing: buf[(i+2)..<(i+6)]))
                case 54 where optLen == 4:
                    serverID = IPv4Address(UnsafeRawBufferPointer(rebasing: buf[(i+2)..<(i+6)]))
                default:
                    break
                }
                i += 2 + optLen
            }

            guard let msgType = msgType else { return nil }

            return DHCPPacket(
                op: op, xid: xid,
                chaddr: chaddr,
                messageType: msgType,
                ciaddr: ciaddr,
                requestedIP: reqIP, serverIdentifier: serverID
            )
        }
    }
}
