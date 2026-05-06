import Darwin

/// Composite key identifying fragments belonging to the same datagram (RFC 791).
struct FragmentKey: Hashable {
    let srcAddr: UInt32
    let dstAddr: UInt32
    let identification: UInt16
    let `protocol`: UInt8
}

/// In-progress reassembly for one datagram.
private struct ReassemblyBuffer {
    /// Raw bytes of the first fragment's IP header (including options).
    /// nil when the first fragment (offset=0) has not yet arrived.
    var firstHeader: [UInt8]?
    /// Stored fragments: (byteOffset, data).
    var fragments: [(offset: Int, data: [UInt8])] = []
    /// Total payload length of the reassembled datagram (data after IP header).
    /// Set when MF=0 fragment arrives.
    var totalPayloadLength: Int?
    /// Deadline for expiration (seconds since epoch).
    let deadline: UInt64
}

/// IPv4 fragment reassembler — persists across BDP rounds.
///
/// Bitmap-based completeness check. Maximum datagram size is 65535 bytes,
/// so the bitmap is at most 64 KB.
public struct IPFragmentReassembler {
    private var buffers: [FragmentKey: ReassemblyBuffer] = [:]
    private let timeoutSeconds: UInt64 = 30

    /// Maximum concurrent in-progress reassemblies before new fragments are dropped.
    /// Mitigates memory exhaustion from fragment flood attacks.
    private let maxConcurrentReassemblies = 64

    public init() {}

    /// Process a single IPv4 fragment.
    ///
    /// - Parameters:
    ///   - fragment: Parsed IPv4 header of this fragment.
    ///   - rawIPPacket: The raw IPv4 packet buffer, used to copy header bytes
    ///     when this is the first fragment (offset=0).
    ///
    /// - Returns: A reassembled IPv4 packet if all fragments have arrived,
    ///   or nil if more fragments are pending.
    public mutating func process(fragment: IPv4Header, rawIPPacket: PacketBuffer) -> PacketBuffer? {
        reapExpired()

        let key = FragmentKey(
            srcAddr: fragment.srcAddr.addr,
            dstAddr: fragment.dstAddr.addr,
            identification: fragment.identification,
            protocol: fragment.protocol.rawValue
        )

        let payloadBytes = fragment.payload.withUnsafeReadableBytes { Array($0) }
        let offset = Int(fragment.fragmentOffset) * 8  // 8-byte units → bytes
        let mf = (fragment.flags & 0x01) != 0
        let headerLen = Int(fragment.ihl) * 4

        guard !payloadBytes.isEmpty else { return nil }

        // Lookup or create buffer
        var buffer: ReassemblyBuffer
        if let existing = buffers[key] {
            buffer = existing
        } else {
            guard buffers.count < maxConcurrentReassemblies else { return nil }
            // Capture IP header if this is the first fragment (offset=0);
            // otherwise fill it in when offset=0 arrives later.
            let rawHeader: [UInt8]?
            if offset == 0 {
                rawHeader = rawIPPacket.withUnsafeReadableBytes { buf in
                    Array(buf[0..<headerLen])
                }
            } else {
                rawHeader = nil
            }
            buffer = ReassemblyBuffer(
                firstHeader: rawHeader,
                deadline: UInt64(Darwin.time(nil)) + timeoutSeconds
            )
        }

        // If offset=0 arrived for an existing buffer (out-of-order), fill in the header
        if offset == 0 && buffer.firstHeader == nil {
            buffer.firstHeader = rawIPPacket.withUnsafeReadableBytes { buf in
                Array(buf[0..<headerLen])
            }
        }

        // Store this fragment's data — skip duplicates (same offset already stored)
        let isDuplicate = buffer.fragments.contains(where: { $0.offset == offset })
        if !isDuplicate {
            buffer.fragments.append((offset: offset, data: payloadBytes))
        }

        // If MF=0, compute total payload length
        if !mf {
            buffer.totalPayloadLength = offset + payloadBytes.count
        }

        // Check if reassembly is complete
        guard let firstHeader = buffer.firstHeader, let totalLen = buffer.totalPayloadLength else {
            buffers[key] = buffer
            return nil
        }

        // Build coverage bitmap
        var covered = [Bool](repeating: false, count: totalLen)
        for (off, data) in buffer.fragments {
            for i in 0..<data.count {
                let pos = off + i
                if pos < totalLen {
                    covered[pos] = true
                }
            }
        }

        guard covered.allSatisfy({ $0 }) else {
            buffers[key] = buffer
            return nil
        }

        // Reassembly complete
        buffers.removeValue(forKey: key)

        // Assemble: corrected IP header + sorted payload
        let newTotalLength = UInt16(headerLen + totalLen)
        var correctedHeader = firstHeader
        // totalLength at offset 2-3
        correctedHeader[2] = UInt8(newTotalLength >> 8)
        correctedHeader[3] = UInt8(newTotalLength & 0xFF)
        // flags+fragmentOffset at offset 6-7 → clear MF and fragmentOffset
        correctedHeader[6] = 0
        correctedHeader[7] = 0
        // Recompute checksum
        correctedHeader[10] = 0
        correctedHeader[11] = 0
        let cksum = correctedHeader.withUnsafeBytes { internetChecksum($0) }
        correctedHeader[10] = UInt8(cksum >> 8)
        correctedHeader[11] = UInt8(cksum & 0xFF)

        var fullData = correctedHeader
        let sorted = buffer.fragments.sorted { $0.offset < $1.offset }
        for (_, data) in sorted {
            fullData.append(contentsOf: data)
        }

        let s = ChunkPools.select(minCapacity: fullData.count).acquire()
        fullData.withUnsafeBytes { s.data.copyMemory(from: $0.baseAddress!, byteCount: fullData.count) }
        return PacketBuffer(storage: s, offset: 0, length: fullData.count)
    }

    /// Remove expired reassembly buffers.
    public mutating func reapExpired() {
        let now = UInt64(Darwin.time(nil))
        buffers = buffers.filter { $0.value.deadline > now }
    }
}
