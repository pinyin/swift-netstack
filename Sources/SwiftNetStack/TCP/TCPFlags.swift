/// TCP control bits (RFC 793 §3.1).
public struct TCPFlags: OptionSet, Sendable {
    public let rawValue: UInt8

    public init(rawValue: UInt8) { self.rawValue = rawValue }

    public static let fin = TCPFlags(rawValue: 0x01)
    public static let syn = TCPFlags(rawValue: 0x02)
    public static let rst = TCPFlags(rawValue: 0x04)
    public static let psh = TCPFlags(rawValue: 0x08)
    public static let ack = TCPFlags(rawValue: 0x10)
    public static let urg = TCPFlags(rawValue: 0x20)
    public static let ece = TCPFlags(rawValue: 0x40)
    public static let cwr = TCPFlags(rawValue: 0x80)
    // NS (ECN Nonce Sum, RFC 3540) is bit 0 of the data-offset byte (byte 12),
    // not part of the flags byte (byte 13). It is extracted separately during parse.

    public var isSyn: Bool { contains(.syn) }
    public var isAck: Bool { contains(.ack) }
    public var isFin: Bool { contains(.fin) }
    public var isRst: Bool { contains(.rst) }
    public var isSynAck: Bool { contains([.syn, .ack]) }
}
