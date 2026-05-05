/// Batch ARP request handler.
/// Processes all ARP requests for our IP in a single pass and generates reply frames.
public struct ARPHandler {

    /// Process a batch of ARP requests and generate Ethernet+ARP reply frames.
    /// Only replies to requests targeting `ourIP`. Non-matching requests are ignored.
    /// Uses `round` for reply buffer allocation.
    public static func process(
        requests: [ARPFrame],
        ourMAC: MACAddress,
        ourIP: IPv4Address,
        round: RoundContext
    ) -> [PacketBuffer] {
        var replies: [PacketBuffer] = []

        for req in requests {
            guard req.operation == .request else { continue }
            guard req.targetIP == ourIP else { continue }

            var reply = round.allocate(capacity: 64, headroom: 0)
            guard let ptr = reply.appendPointer(count: 42) else { continue }
            // (ARP reply is 28 bytes + Ethernet header 14 bytes = 42 bytes total)

            // Ethernet header
            req.senderMAC.write(to: ptr)                              // dst = sender
            ourMAC.write(to: ptr.advanced(by: 6))                     // src = us
            writeUInt16BE(0x0806, to: ptr.advanced(by: 12))            // ARP

            // ARP body
            let arpStart = ptr.advanced(by: 14)
            // hardware type: Ethernet
            writeUInt16BE(1, to: arpStart)                             // htype
            writeUInt16BE(0x0800, to: arpStart.advanced(by: 2))         // ptype
            arpStart.advanced(by: 4).storeBytes(of: UInt8(6), as: UInt8.self)   // hlen
            arpStart.advanced(by: 5).storeBytes(of: UInt8(4), as: UInt8.self)   // plen
            writeUInt16BE(ARPOperation.reply.rawValue, to: arpStart.advanced(by: 6)) // operation
            ourMAC.write(to: arpStart.advanced(by: 8))                 // sender MAC = us
            ourIP.write(to: arpStart.advanced(by: 14))                 // sender IP = us
            req.senderMAC.write(to: arpStart.advanced(by: 18))         // target MAC = requester
            req.senderIP.write(to: arpStart.advanced(by: 24))          // target IP = requester

            replies.append(reply)
        }

        return replies
    }

    @inline(__always)
    private static func writeUInt16BE(_ value: UInt16, to ptr: UnsafeMutableRawPointer) {
        ptr.storeBytes(of: value.bigEndian, as: UInt16.self)
    }
}
