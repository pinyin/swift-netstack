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
    var firstHeader: [UInt8]?
    /// Fragments received before totalPayloadLength is known (MF=0).
    var pendingFragments: [(offset: Int, data: [UInt8])] = []
    /// Output payload buffer. Allocated when totalPayloadLength is known.
    var payload: [UInt8]?
    /// Bitmap tracking which payload bytes have been filled.
    var covered: [Bool]?
    /// Total payload length of the reassembled datagram.
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
        if buffers[key] == nil {
            guard buffers.count < maxConcurrentReassemblies else { return nil }
            let rawHeader: [UInt8]?
            if offset == 0 {
                rawHeader = rawIPPacket.withUnsafeReadableBytes { buf in Array(buf[0..<headerLen]) }
            } else {
                rawHeader = nil
            }
            buffers[key] = ReassemblyBuffer(
                firstHeader: rawHeader,
                deadline: UInt64(Darwin.time(nil)) + timeoutSeconds
            )
        }

        // swiftlint:disable:next force_unwrapping
        var buffer = buffers[key]!

        // If offset=0 arrived for an existing buffer (out-of-order), fill in the header
        if offset == 0 && buffer.firstHeader == nil {
            buffer.firstHeader = rawIPPacket.withUnsafeReadableBytes { buf in Array(buf[0..<headerLen]) }
        }

        // If MF=0, set total payload length and allocate output buffer
        if !mf {
            let newTotal = offset + payloadBytes.count
            if buffer.totalPayloadLength == nil {
                buffer.totalPayloadLength = newTotal
                buffer.payload = [UInt8](repeating: 0, count: newTotal)
                buffer.covered = [Bool](repeating: false, count: newTotal)
                // Apply all previously pending fragments to the output buffer
                for (off, data) in buffer.pendingFragments {
                    applyFragment(data: data, offset: off, to: &buffer)
                }
                buffer.pendingFragments.removeAll()
            }
        }

        // Write fragment data: into output buffer if allocated, else pending
        if buffer.payload != nil {
            applyFragment(data: payloadBytes, offset: offset, to: &buffer)
        } else {
            buffer.pendingFragments.append((offset: offset, data: payloadBytes))
        }

        // Check if reassembly is complete
        guard let firstHeader = buffer.firstHeader,
              let totalLen = buffer.totalPayloadLength,
              let covered = buffer.covered,
              let payload = buffer.payload else {
            buffers[key] = buffer
            return nil
        }

        guard covered.allSatisfy({ $0 }) else {
            buffers[key] = buffer
            return nil
        }

        // Reassembly complete
        buffers.removeValue(forKey: key)

        // Assemble: corrected IP header + payload
        let newTotalLength = UInt16(headerLen + totalLen)
        var correctedHeader = firstHeader
        correctedHeader[2] = UInt8(newTotalLength >> 8)
        correctedHeader[3] = UInt8(newTotalLength & 0xFF)
        correctedHeader[6] = 0
        correctedHeader[7] = 0
        correctedHeader[10] = 0
        correctedHeader[11] = 0
        let cksum = correctedHeader.withUnsafeBytes { internetChecksum($0) }
        correctedHeader[10] = UInt8(cksum >> 8)
        correctedHeader[11] = UInt8(cksum & 0xFF)

        var fullData = correctedHeader
        fullData.append(contentsOf: payload)
        let s = ChunkPools.select(minCapacity: fullData.count).acquire()
        fullData.withUnsafeBytes { s.data.copyMemory(from: $0.baseAddress!, byteCount: fullData.count) }
        return PacketBuffer(storage: s, offset: 0, length: fullData.count)
    }

    /// Write fragment data into the output buffer, overwriting any overlapping region.
    /// RFC 791: last-received fragment wins for overlapping bytes.
    private func applyFragment(data: [UInt8], offset: Int, to buffer: inout ReassemblyBuffer) {
        guard let totalLen = buffer.totalPayloadLength else { return }
        let copyLen = min(data.count, totalLen - offset)
        guard copyLen > 0 else { return }
        buffer.payload?.replaceSubrange(offset..<(offset + copyLen), with: data[0..<copyLen])
        for i in offset..<(offset + copyLen) {
            buffer.covered?[i] = true
        }
    }

    /// Remove expired reassembly buffers.
    public mutating func reapExpired() {
        let now = UInt64(Darwin.time(nil))
        buffers = buffers.filter { $0.value.deadline > now }
    }
}
