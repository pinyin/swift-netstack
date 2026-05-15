import Darwin

// MARK: - TCP sanity checks (release safety net)

/// Validates a just-written TCP checksum by reading it back and comparing
/// against the computed value. Catches memory corruption and store-to-load
/// forwarding errors. Negligible overhead: one 16-bit read + compare.
///
/// Returns true if the checksum was already correct.
@inline(__always)
func sanityReadBackTCPChecksum(io: IOBuffer, hdrOfs: Int, expected: UInt16) -> Bool {
    let tcpPtr = io.output.baseAddress!.advanced(by: hdrOfs + ethHeaderLen + ipv4HeaderLen)
    let written = readUInt16BE(tcpPtr, 16)
    if written != expected {
        fputs("[SANITY] TCP checksum writeback mismatch: wrote 0x"
            + "\(String(written, radix: 16)), expected 0x\(String(expected, radix: 16)). "
            + "Fixing.\n", stderr)
        writeUInt16BE(expected, to: tcpPtr.advanced(by: 16))
        return false
    }
    return true
}

/// Full re-validation of a TCP checksum from scratch, using a different code
/// path than the production computation. Catches algorithm bugs.
/// Called on the first data segment of each connection (one-time cost),
/// plus periodically sampled (1/1024 segments) for ongoing validation.
@inline(__always)
func sanityRecomputeTCPChecksum(io: IOBuffer, hdrOfs: Int,
                                 srcIP: IPv4Address, dstIP: IPv4Address,
                                 payloadPtr: UnsafeRawPointer?, payloadLen: Int) -> Bool {
    let tcpPtr = io.output.baseAddress!.advanced(by: hdrOfs + ethHeaderLen + ipv4HeaderLen)
    let hdrLen = 20
    let totalLen = hdrLen + payloadLen
    let written = readUInt16BE(tcpPtr, 16)

    var sum = computePseudoHeaderSum(srcIP: srcIP, dstIP: dstIP,
                                      protocol: IPProtocol.tcp.rawValue, totalLen: totalLen)
    sum = checksumAdd(sum, tcpPtr, hdrLen)
    if let pp = payloadPtr, payloadLen > 0 {
        sum = checksumAdd(sum, pp, payloadLen)
    }
    let expected = finalizeChecksum(sum)

    if written != expected {
        fputs("[SANITY] TCP checksum recompute mismatch: got 0x"
            + "\(String(written, radix: 16)), expected 0x\(String(expected, radix: 16)). "
            + "Fixing.\n", stderr)
        writeUInt16BE(expected, to: tcpPtr.advanced(by: 16))
        return false
    }
    return true
}

/// Validate a TCP state transition against RFC 793 rules.
/// Logs and sends RST for invalid transitions caught in release builds.
func sanityCheckTCPStateTransition(old: TCPState, new: TCPState, flags: TCPFlags,
                                    key: String = "") -> Bool {
    // All transitions from .closed are valid (RST path, etc.)
    if old == .closed { return true }
    // SYN in listen → synReceived is the only valid start
    if old == .listen && new != .synReceived && new != .listen { return false }
    // Only valid terminations
    if new == .closed && old != .finWait1 && old != .finWait2
        && old != .lastAck && old != .established { return false }

    // State-specific rules (simplified RFC 793 subset)
    switch old {
    case .synReceived:
        if new != .synReceived && new != .established && new != .closed { return false }
    case .established:
        if new != .established && new != .closeWait && new != .finWait1 && new != .closed { return false }
    case .finWait1:
        if new != .finWait1 && new != .finWait2 && new != .closed { return false }
    case .finWait2:
        if new != .finWait2 && new != .closed { return false }
    case .closeWait:
        if new != .closeWait && new != .lastAck && new != .closed { return false }
    case .lastAck:
        if new != .lastAck && new != .closed { return false }
    default:
        break
    }
    return true
}

func logInvalidTCPTransition(old: TCPState, new: TCPState, flags: TCPFlags, key: String) {
    fputs("[SANITY] Invalid TCP state transition: \(old) → \(new) flags=\(flags.rawValue) key=\(key)\n", stderr)
}

// MARK: - Sequence number sanity

/// Prevents snd.una from rewinding (using 32-bit wrapping comparison).
/// Returns the corrected una value (clamped to the old value if rewind detected).
func sanityClampSndUna(old: UInt32, new: UInt32) -> UInt32 {
    // new is behind old in 32-bit wrap space → rewind detected
    if (new &- old) > (1 << 31) {
        return old  // clamp, don't rewind
    }
    return new
}

/// Log a sequence number regression.
func logSeqRegression(_ what: String, old: UInt32, new: UInt32) {
    fputs("[SANITY] TCP seq regression: \(what) 0x\(String(old, radix: 16))"
        + " → 0x\(String(new, radix: 16))\n", stderr)
}
