/// ARP operation codes.
public enum ARPOperation: UInt16 {
    case request = 1
    case reply   = 2
}

/// Parsed ARP frame (Ethernet + IPv4 only).
public struct ARPFrame {
    public let hardwareType: UInt16  // 1 = Ethernet
    public let protocolType: UInt16  // 0x0800 = IPv4
    public let hardwareSize: UInt8   // 6
    public let protocolSize: UInt8   // 4
    public let operation: ARPOperation
    public let senderMAC: MACAddress
    public let senderIP: IPv4Address
    public let targetMAC: MACAddress
    public let targetIP: IPv4Address

    private init(
        hardwareType: UInt16, protocolType: UInt16,
        hardwareSize: UInt8, protocolSize: UInt8,
        operation: ARPOperation,
        senderMAC: MACAddress, senderIP: IPv4Address,
        targetMAC: MACAddress, targetIP: IPv4Address
    ) {
        self.hardwareType = hardwareType; self.protocolType = protocolType
        self.hardwareSize = hardwareSize; self.protocolSize = protocolSize
        self.operation = operation
        self.senderMAC = senderMAC; self.senderIP = senderIP
        self.targetMAC = targetMAC; self.targetIP = targetIP
    }

    /// Parse an ARP frame from raw bytes (Ethernet payload).
    /// Returns nil if the buffer is too short or fields don't match Ethernet/IPv4 ARP.
    public static func parse(from ptr: UnsafeRawPointer, len: Int) -> ARPFrame? {
        guard len >= 28 else { return nil }
        let hwType   = readUInt16BE(ptr, 0)
        let protoType = readUInt16BE(ptr, 2)
        let hwSize   = ptr.assumingMemoryBound(to: UInt8.self)[4]
        let protoSize = ptr.assumingMemoryBound(to: UInt8.self)[5]
        let rawOp    = readUInt16BE(ptr, 6)
        guard hwType == 1, protoType == 0x0800,
              hwSize == 6, protoSize == 4,
              let op = ARPOperation(rawValue: rawOp) else { return nil }
        return ARPFrame(
            hardwareType: hwType, protocolType: protoType,
            hardwareSize: hwSize, protocolSize: protoSize,
            operation: op,
            senderMAC: MACAddress(UnsafeRawBufferPointer(start: ptr.advanced(by: 8), count: 6)),
            senderIP: IPv4Address(UnsafeRawBufferPointer(start: ptr.advanced(by: 14), count: 4)),
            targetMAC: MACAddress(UnsafeRawBufferPointer(start: ptr.advanced(by: 18), count: 6)),
            targetIP: IPv4Address(UnsafeRawBufferPointer(start: ptr.advanced(by: 24), count: 4))
        )
    }

}
