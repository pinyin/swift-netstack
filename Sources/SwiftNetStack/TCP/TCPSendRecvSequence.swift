// MARK: - TCP Sequence Number Tracking

/// Sender-side sequence number tracking.
struct SendSequence {
    var nxt: UInt32    // next sequence number to assign to a new segment
    var una: UInt32    // oldest unacknowledged sequence number
    var wnd: UInt32    // peer's receive window (post-scaling, actual bytes)

    // RFC 5681 congestion control
    // Lossless link mode: virtio-net has zero congestion, so cwnd should
    // never be the limiting factor. Set to UInt32.max so min(cwnd, snd.wnd)
    // always returns snd.wnd — the receiver's window is the only limit.
    var cwnd: UInt32 = UInt32.max
    var ssthresh: UInt32 = UInt32.max  // no slow start on lossless link
    var recover: UInt32 = 0       // snd.nxt at loss detection (RFC 6675 §5)
    var inRecovery: Bool = false
    var sndUnaSendTime: UInt64 = 0  // µs timestamp when oldest in-flight segment was sent (RACK)
    var lastNonRecoveryRtxTime: UInt64 = 0  // monotonic-µs of last non-recovery retransmit
    var nonRecoveryRtxCount: UInt8 = 0      // consecutive non-recovery retransmits (escalate at 2)

    /// Bytes in flight (sent but not acknowledged).
    var bytesInFlight: UInt32 { nxt &- una }

    /// RFC 5681 cwnd growth on new ACK during normal operation (not in recovery).
    /// - Slow start: cwnd += min(bytesAcked, SMSS) while cwnd < ssthresh
    /// - Congestion avoidance: cwnd += SMSS * SMSS / cwnd per ACK
    mutating func growCwnd(bytesAcked: UInt32, smss: UInt32) {
        guard bytesAcked > 0, !inRecovery, cwnd < UInt32.max else { return }
        if cwnd < ssthresh {
            cwnd &+= Swift.min(bytesAcked, smss)
        } else {
            let inc = Swift.max(1, smss &* smss / cwnd)
            cwnd &+= inc
        }
    }

    /// RFC 5681 §5: on RTO, reduce ssthresh and collapse cwnd to Loss Window.
    mutating func resetCwndOnRTO(smss: UInt32) {
        let inflight = bytesInFlight
        ssthresh = max(inflight / 2, 2 &* smss)
        cwnd = smss
        inRecovery = false
    }
}

/// Receiver-side sequence number tracking.
struct RecvSequence {
    var nxt: UInt32    // next expected sequence number
    var initialSeq: UInt32  // initial receive sequence (for verification)
}
