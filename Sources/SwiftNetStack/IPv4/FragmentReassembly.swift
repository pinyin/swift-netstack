/// IPv4 fragment reassembly with bounded state and zero heap allocation in the hot path.
///
/// Uses a fixed-size array of reassembly slots (default 16). Each slot tracks one
/// in-progress reassembly identified by (srcIP, dstIP, identification, protocol).
///
/// State machine:
///   Collecting → (all fragments arrived, last has MF=0) → Complete (output returned)
///   Collecting → (timeout exceeded) → TimedOut (slot reclaimed by reapExpired)
///
/// Fragments are stored directly in IOBuffer.input frame slots — no additional copy
/// during collection. On completion, the reassembled payload is written into
/// IOBuffer.output as a contiguous buffer by copying each fragment's payload in
/// offset order.
public struct FragmentReassembly {
    public let maxReassemblies: Int

    /// Active reassembly states. nil = slot free.
    private var slots: [Slot?]

    /// Per-slot accumulated data. Once the last fragment arrives we know the total
    /// length and can validate all fragments are present.
    private struct Slot {
        var srcIP: IPv4Address
        var dstIP: IPv4Address
        var identification: UInt16
        var `protocol`: UInt8
        var createdAt: UInt64

        /// Total expected length (only known after last fragment arrives).
        var totalLen: Int = 0

        /// Fragment descriptors: (offset in bytes, payload len, input frame index).
        /// offsetBytes is relative to the unfragmented datagram (not the IP header field).
        var fragments: [(offsetBytes: Int, len: Int, frameIdx: Int, ipHdrLen: Int)] = []
        var lastFragmentSeen: Bool = false
    }

    public var activeCount: Int { slots.compactMap { $0 }.count }

    public init(maxReassemblies: Int = 16) {
        self.maxReassemblies = maxReassemblies
        self.slots = Array(repeating: nil, count: maxReassemblies)
    }

    /// Process one fragment. Returns (ptr, len) into IOBuffer.output if reassembly
    /// is complete, or nil if still collecting fragments.
    ///
    /// - Parameters:
    ///   - framePtr: Pointer to start of the Ethernet frame in IOBuffer.input.
    ///   - frameLen: Total frame length (Ethernet + IP + payload).
    ///   - frameIndex: Index of this frame in IOBuffer (for later data copy).
    ///   - identification: IPv4 identification field.
    ///   - flagsFrag: Raw 16-bit flags+fragment-offset field.
    ///   - now: Current time in seconds since epoch.
    ///   - io: IOBuffer for output allocation.
    public mutating func processFragment(
        framePtr: UnsafeMutableRawPointer, frameLen: Int, frameIndex: Int,
        identification: UInt16, flagsFrag: UInt16,
        srcIP: IPv4Address, dstIP: IPv4Address, protocol: UInt8,
        now: UInt64, io: IOBuffer,
        ipHeaderLen: Int = 20
    ) -> (ptr: UnsafeMutableRawPointer, len: Int)? {
        let mf = (flagsFrag & 0x2000) != 0
        let fragOffset = Int(flagsFrag & 0x1FFF)  // in 8-byte units
        let offsetBytes = fragOffset * 8

        // Payload starts after Ethernet (14) + actual IP header (from IHL field).
        let ipHdrLen = ipHeaderLen
        // Read totalLength from IP header to get actual datagram size
        // (frameLen may include Ethernet padding, inflating the payload).
        let ipTotalLen = Int(readUInt16BE(UnsafeRawPointer(framePtr), ethHeaderLen + 2))
        let payloadLen = ipTotalLen - ipHdrLen
        guard payloadLen > 0 else { return nil }

        // Find existing slot or allocate new one.
        let slotIdx: Int
        if let idx = findSlot(srcIP: srcIP, dstIP: dstIP,
                              identification: identification, protocol: `protocol`) {
            slotIdx = idx
        } else if let idx = allocateSlot(srcIP: srcIP, dstIP: dstIP,
                                          identification: identification,
                                          protocol: `protocol`, now: now) {
            slotIdx = idx
        } else {
            return nil  // No free slots
        }

        var slot = slots[slotIdx]!

        // RFC 1858: guard fragment offset + payload doesn't overflow.
        let newEnd32 = UInt32(offsetBytes) + UInt32(payloadLen)
        guard newEnd32 <= 65535 else { return nil }
        let newEnd = Int(newEnd32)
        for existing in slot.fragments {
            let existEnd = existing.offsetBytes + existing.len
            if offsetBytes < existEnd && newEnd > existing.offsetBytes {
                slots[slotIdx] = nil  // abort reassembly
                return nil
            }
        }

        // If this is a last fragment, guard against conflicting MF=0 fragments.
        if !mf {
            let newTotalLen = offsetBytes + payloadLen
            if slot.lastFragmentSeen {
                if newTotalLen != slot.totalLen {
                    slots[slotIdx] = nil
                    return nil
                }
            } else {
                slot.lastFragmentSeen = true
                slot.totalLen = newTotalLen
            }
        }

        slot.fragments.append((offsetBytes: offsetBytes, len: payloadLen,
                               frameIdx: frameIndex, ipHdrLen: ipHeaderLen))

        slots[slotIdx] = slot

        // Check if reassembly is complete: last fragment seen AND all bytes covered.
        guard slot.lastFragmentSeen, slot.totalLen > 0 else { return nil }

        let covered = slot.fragments.reduce(0) { $0 + $1.len }
        guard covered == slot.totalLen else { return nil }

        // Reassembly complete — allocate output buffer and copy fragment payloads.
        guard let outPtr = io.allocOutput(slot.totalLen) else { return nil }

        // Copy each fragment's payload to the correct offset in the output buffer.
        // Fragments are stored in arrival order; copy by offset position.
        // Uses per-fragment IP header length (may differ across fragments).
        for frag in slot.fragments.sorted(by: { $0.offsetBytes < $1.offsetBytes }) {
            guard frag.frameIdx >= 0 else { continue }
            let srcPtr = io.framePtr(frag.frameIdx).advanced(by: ethHeaderLen + frag.ipHdrLen)
            let dstPtr = outPtr.advanced(by: frag.offsetBytes)
            dstPtr.copyMemory(from: srcPtr, byteCount: frag.len)
        }

        slots[slotIdx] = nil  // free slot
        return (outPtr, slot.totalLen)
    }

    /// Reap expired reassemblies. Returns the number of slots freed.
    @discardableResult
    public mutating func reapExpired(now: UInt64, timeout: UInt64 = 30) -> Int {
        var reaped = 0
        for i in 0..<slots.count {
            guard let slot = slots[i] else { continue }
            if now < slot.createdAt || now - slot.createdAt > timeout {
                slots[i] = nil
                reaped += 1
            }
        }
        return reaped
    }

    // MARK: - Private

    private func findSlot(srcIP: IPv4Address, dstIP: IPv4Address,
                           identification: UInt16, protocol: UInt8) -> Int? {
        for i in 0..<slots.count {
            guard let s = slots[i] else { continue }
            if s.srcIP == srcIP, s.dstIP == dstIP,
               s.identification == identification, s.protocol == `protocol` {
                return i
            }
        }
        return nil
    }

    private mutating func allocateSlot(srcIP: IPv4Address, dstIP: IPv4Address,
                                        identification: UInt16, protocol: UInt8,
                                        now: UInt64) -> Int? {
        for i in 0..<slots.count where slots[i] == nil {
            slots[i] = Slot(srcIP: srcIP, dstIP: dstIP,
                            identification: identification, protocol: `protocol`,
                            createdAt: now)
            return i
        }
        return nil
    }
}
