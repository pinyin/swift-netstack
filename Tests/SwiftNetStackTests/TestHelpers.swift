import SwiftNetStack

extension PacketBuffer {
    static func from(bytes: [UInt8]) -> PacketBuffer {
        let s = Storage.allocate(capacity: bytes.count)
        bytes.withUnsafeBytes { buf in
            s.data.copyMemory(from: buf.baseAddress!, byteCount: bytes.count)
        }
        return PacketBuffer(storage: s, offset: 0, length: bytes.count)
    }
}
