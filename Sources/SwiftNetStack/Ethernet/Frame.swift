/// Parsed Ethernet II frame. The payload is a zero-copy slice of the original buffer.
public struct EthernetFrame {
    public let dstMAC: MACAddress
    public let srcMAC: MACAddress
    public let etherType: EtherType
    public let payload: PacketBuffer

    private init(dstMAC: MACAddress, srcMAC: MACAddress, etherType: EtherType, payload: PacketBuffer) {
        self.dstMAC = dstMAC
        self.srcMAC = srcMAC
        self.etherType = etherType
        self.payload = payload
    }

    /// Parse an Ethernet frame from a PacketBuffer. Returns nil if the buffer is too short
    /// or the EtherType is unrecognized.
    public static func parse(from pkt: PacketBuffer) -> EthernetFrame? {
        guard pkt.totalLength >= 14 else { return nil }

        return pkt.withUnsafeReadableBytes { buf -> EthernetFrame? in
            let dstMAC = MACAddress(buf)
            let srcMAC = MACAddress(UnsafeRawBufferPointer(rebasing: buf[6..<14]))
            let rawEtherType = (UInt16(buf[12]) << 8) | UInt16(buf[13])

            guard let etherType = EtherType(rawValue: rawEtherType) else { return nil }

            let payload = pkt.slice(from: 14, length: pkt.totalLength - 14)
            return EthernetFrame(dstMAC: dstMAC, srcMAC: srcMAC, etherType: etherType, payload: payload)
        }
    }
}
