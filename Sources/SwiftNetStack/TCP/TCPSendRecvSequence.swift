// MARK: - TCP Sequence Number Tracking

/// Sender-side sequence number tracking.
struct SendSequence {
    var nxt: UInt32    // next sequence number to assign to a new segment
    var una: UInt32    // oldest unacknowledged sequence number
    var wnd: UInt32    // peer's receive window (post-scaling, actual bytes)

    var sndUnaSendTime: UInt64 = 0  // µs timestamp when oldest in-flight segment was sent (RACK)
    var lastNonRecoveryRtxTime: UInt64 = 0  // monotonic-µs of last retransmit
    var nonRecoveryRtxCount: UInt8 = 0      // consecutive retransmits (escalate at 2)

    /// Bytes in flight (sent but not acknowledged).
    var bytesInFlight: UInt32 { nxt &- una }
}

/// Receiver-side sequence number tracking.
struct RecvSequence {
    var nxt: UInt32    // next expected sequence number
    var initialSeq: UInt32  // initial receive sequence (for verification)
}
