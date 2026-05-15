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

    /// Parse from raw bytes (UDP payload). Returns nil if too short or invalid.
    public static func parse(from ptr: UnsafeRawPointer, len: Int) -> DHCPPacket? {
        guard len >= 243 else { return nil }
        let buf = ptr.assumingMemoryBound(to: UInt8.self)
        let op = buf[0]
        guard buf[1] == 1 && buf[2] == 6 else { return nil }
        let xid = readUInt32BE(ptr, 4)
        let ciaddr = IPv4Address(UnsafeRawBufferPointer(start: ptr.advanced(by: 12), count: 4))
        let chaddr = MACAddress(UnsafeRawBufferPointer(start: ptr.advanced(by: 28), count: 6))
        guard buf[236] == 99, buf[237] == 130, buf[238] == 83, buf[239] == 99 else { return nil }
        var msgType: DHCPMessageType? = nil
        var reqIP: IPv4Address? = nil
        var serverID: IPv4Address? = nil
        var i = 240
        while i < len {
            let optCode = buf[i]
            if optCode == 0 { i += 1; continue }
            if optCode == 255 { break }
            if i + 1 >= len { break }
            let optLen = Int(buf[i + 1])
            if i + 2 + optLen > len { break }
            switch optCode {
            case 53 where optLen == 1: msgType = DHCPMessageType(rawValue: buf[i + 2])
            case 50 where optLen == 4: reqIP = IPv4Address(UnsafeRawBufferPointer(start: ptr.advanced(by: i + 2), count: 4))
            case 54 where optLen == 4: serverID = IPv4Address(UnsafeRawBufferPointer(start: ptr.advanced(by: i + 2), count: 4))
            default: break
            }
            i += 2 + optLen
        }
        guard let mt = msgType else { return nil }
        return DHCPPacket(op: op, xid: xid, chaddr: chaddr, messageType: mt,
                          ciaddr: ciaddr, requestedIP: reqIP, serverIdentifier: serverID)
    }
}
