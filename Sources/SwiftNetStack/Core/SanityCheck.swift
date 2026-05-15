// MARK: - Availability guardrails for the BDP pipeline
///
/// These checks focus on *availability* over correctness:
/// a hung connection or infinite loop is worse than a RST.
/// When invariants break, the stack self-heals by resetting connections
/// rather than letting them stall forever.

import Darwin

// MARK: - Loop iteration caps

/// Max iterations for while loops that drain external data.
/// Caps prevent infinite loops if an invariant is violated
/// (e.g. sendQueue.count never drops to 0 due to a bug).
let kMaxDrainIterations = 256

/// Max segments per batched sendmsg. If iovs exceeds this, we stop
/// and retry next round to bound per-round CPU and iovec memory.
let kMaxBatchedSegments = 64

// MARK: - Per-connection stall tracking

/// Number of consecutive rounds a connection can be in `dirtyConnections`
/// without making progress before it is forcibly reset.
/// A "round without progress" means no data was sent to the VM and no
/// data was received from external for this connection.
let kMaxStallRounds = 5000

/// Extension on NATEntry for stall detection.
/// Reset when the connection makes progress (data sent or received).
/// Incremented each round the connection is dirty but idle.
extension NATEntry {
    func isStalled(nowSec: UInt64) -> Bool {
        // If the connection has active data in either direction, it's not stalled.
        let c = connection
        if c.totalQueuedBytes > 0 || c.externalSendQueued > 0 {
            return false
        }
        // synReceived with no handshake completion for 60s → stalled
        if c.state == .synReceived, nowSec - lastActivity > 60 {
            return true
        }
        return false
    }
}

// MARK: - OOO buffer stall

/// If a connection's OOO buffer exceeds this many bytes with no draining
/// for too long, the connection is considered stalled and RST.
let kOOOStallThresholdBytes = 128 * 1024  // 128 KB

// MARK: - Health logging (rate-limited to avoid log storms)

/// Rate-limited health logger. BDP is single-threaded so no concurrency concern.
nonisolated(unsafe) private var lastHealthLogSec: UInt64 = 0

func sanityLog(_ msg: String) {
    let now = UInt64(Darwin.time(nil))
    // Rate-limit to one log per second
    if now - lastHealthLogSec >= 1 {
        lastHealthLogSec = now
        fputs("[SANITY] \(msg)\n", stderr)
    }
}

// MARK: - BDP loop watchdog

/// Tracks consecutive rounds where no VM frames were read AND no external
/// data was processed. If too many such rounds pass while connections exist,
/// something is wrong (e.g. poll returning but data never processed).
struct BDPWatchdog {
    var idleRounds: Int = 0
    /// Max idle rounds before logging a warning. Does NOT restart — just alerts.
    let maxIdleRounds: Int = 3000  // ~30s at 100Hz idle poll

    mutating func tick(hadActivity: Bool, activeConnections: Int) {
        if hadActivity {
            idleRounds = 0
        } else {
            idleRounds += 1
        }
        if idleRounds > maxIdleRounds && activeConnections > 0 {
            sanityLog("BDP watchdog: \(idleRounds) idle rounds with \(activeConnections) active connections")
            idleRounds = 0  // reset to avoid log storms
        }
    }
}

// MARK: - TCP checksum read-back (negligible overhead)

/// Verifies that the checksum we just computed was correctly written to memory.
/// One 16-bit read + compare. Catches memory corruption / store-forwarding errors.
@inline(__always)
func sanityReadBackTCPChecksum(io: IOBuffer, hdrOfs: Int, expected: UInt16) {
    let tcpPtr = io.output.baseAddress!.advanced(by: hdrOfs + ethHeaderLen + ipv4HeaderLen)
    if readUInt16BE(tcpPtr, 16) != expected {
        writeUInt16BE(expected, to: tcpPtr.advanced(by: 16))
        sanityLog("TCP checksum writeback fixed")
    }
}
