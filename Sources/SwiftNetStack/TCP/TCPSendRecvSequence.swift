// MARK: - TCP Sequence Number Tracking

/// Sender-side sequence number tracking.
struct SendSequence {
    var nxt: UInt32    // next sequence number to assign to a new segment
    var una: UInt32    // oldest unacknowledged sequence number
    var wnd: UInt32    // peer's receive window (post-scaling, actual bytes)

    var sndUnaSendTime: UInt64 = 0  // µs timestamp when oldest in-flight segment was sent (RACK)
    var lastNonRecoveryRtxTime: UInt64 = 0  // monotonic-µs of last retransmit
    var nonRecoveryRtxCount: UInt8 = 0      // consecutive retransmits (escalate at 2)

    /// Congestion window (RFC 5681). Limits in-flight data per connection.
    /// Starts at 4 segments; grows per ACK; adaptive cap prevents incast.
    var cwnd: UInt32 = 4 * 1400
    /// Slow start threshold. UInt32.max → always in slow start on reliable
    /// virtio-net links. Set lower if congestion (loss) is detected.
    var ssthresh: UInt32 = UInt32.max

    /// Bytes in flight (sent but not acknowledged).
    var bytesInFlight: UInt32 { nxt &- una }
}

/// Receiver-side sequence number tracking.
struct RecvSequence {
    var nxt: UInt32    // next expected sequence number
    var initialSeq: UInt32  // initial receive sequence (for verification)
}
