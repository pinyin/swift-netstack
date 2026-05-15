import Darwin

/// RFC 793 TCP states, reduced to 8 essential states for a NAT proxy.
/// CLOSING (simultaneous close) and TIME_WAIT are omitted — the proxy
/// sends RST for simultaneous close and skips 2MSL wait.
public enum TCPState: Equatable {
    case closed
    case listen
    case synReceived
    case established
    case finWait1
    case finWait2
    case closeWait
    case lastAck
}

/// A segment that the TCP state machine wants to send.
public struct TCPSegmentToSend {
    public let flags: TCPFlags
    public let seq: UInt32
    public let ack: UInt32
    /// Actual (logical) window we advertise to the VM.
    /// Scaled down to UInt16 for wire by the NAT table (RFC 1323).
    public let window: UInt32
    public let payload: [UInt8]?
}

/// Zero-heap-allocation result from tcpProcess. Holds 0–2 segments.
/// (Maximum is 2: data-ACK + FIN-ACK in synReceived.)
public enum TCPSegmentResult {
    case none
    case one(TCPSegmentToSend)
    case two(TCPSegmentToSend, TCPSegmentToSend)

    public var isEmpty: Bool { if case .none = self { return true }; return false }
    public var count: Int {
        switch self {
        case .none: return 0
        case .one: return 1
        case .two: return 2
        }
    }
    public var first: TCPSegmentToSend? {
        switch self {
        case .none: return nil
        case .one(let a): return a
        case .two(let a, _): return a
        }
    }
    public func forEach(_ body: (TCPSegmentToSend) -> Void) {
        switch self {
        case .none: break
        case .one(let a): body(a)
        case .two(let a, let b): body(a); body(b)
        }
    }
}

/// Process an incoming TCP segment through the finite state machine.
///
/// - Parameters:
///   - state: Current connection state.
///   - seg: TCP segment info (seq, ack, flags, window).
///   - payloadPtr: Pointer to TCP payload data, or nil if no payload.
///   - payloadLen: Length of TCP payload in bytes.
///   - snd: Sender-side sequence tracking (inout).
///   - rcv: Receiver-side sequence tracking (inout).
///   - tracer: Optional hook invoked on state transition. Called synchronously; must not block or throw.
/// - Returns: New state, segments to send in response, and (ptr, len) of data to forward to external.
func tcpProcess(
    state: TCPState,
    seg: TCPSegmentInfo,
    payloadPtr: UnsafeRawPointer?,
    payloadLen: Int,
    snd: inout SendSequence,
    rcv: inout RecvSequence,
    tracer: ((TCPState, TCPState, TCPFlags) -> Void)? = nil
) -> (newState: TCPState, toSend: TCPSegmentResult, dataPtr: UnsafeRawPointer?, dataLen: Int) {
    let result = _tcpProcessImpl(state: state, seg: seg, payloadPtr: payloadPtr,
                                 payloadLen: payloadLen, snd: &snd, rcv: &rcv)
    if result.newState != state, let tracer {
        tracer(state, result.newState, seg.flags)
    }
    return result
}

func _tcpProcessImpl(
    state: TCPState,
    seg: TCPSegmentInfo,
    payloadPtr: UnsafeRawPointer?,
    payloadLen: Int,
    snd: inout SendSequence,
    rcv: inout RecvSequence
) -> (newState: TCPState, toSend: TCPSegmentResult, dataPtr: UnsafeRawPointer?, dataLen: Int) {

    // RST immediately closes the connection, except in LISTEN (RFC 793 §3.4).
    // An RST arriving in LISTEN must be silently dropped — the sender may
    // be probing a stale half-open connection and we must not transition.
    if seg.flags.isRst {
        if state == .listen { return (.listen, .none, nil, 0) }
        return (.closed, .none, nil, 0)
    }

    switch state {
    case .closed:
        return (.closed, .none, nil, 0)

    case .listen:
        // Only respond to SYN — connection initiation from peer (VM)
        guard seg.flags.isSyn, !seg.flags.isAck else {
            return (.listen, .none, nil, 0)
        }
        let peerSeq = seg.seq
        rcv.initialSeq = peerSeq
        rcv.nxt = peerSeq &+ 1
        // Choose our ISN
        let isn = tcpGenerateISN()
        snd.una = isn
        snd.wnd = UInt32(seg.window)
        let synAck = TCPSegmentToSend(
            flags: [.syn, .ack],
            seq: isn,
            ack: rcv.nxt,
            window: 262144,
            payload: nil
        )
        snd.nxt = isn &+ 1  // SYN consumes one sequence number
        return (.synReceived, .one(synAck), nil, 0)

    case .synReceived:
        // Expecting ACK of our SYN to complete handshake.
        // May be pure ACK (outbound: VM→NAT→external) or SYN+ACK (inbound:
        // external→NAT→VM); in the SYN+ACK case record the peer's ISN.
        guard seg.flags.isAck else {
            // Bare SYN (retransmitted peer SYN) — retransmit our SYN-ACK.
            if seg.flags.isSyn {
                let synAck = TCPSegmentToSend(
                    flags: [.syn, .ack],
                    seq: snd.una,  // our ISN (SYN-ACK reuses original seq)
                    ack: rcv.nxt,
                    window: 262144,
                    payload: nil
                )
                return (.synReceived, .one(synAck), nil, 0)
            }
            return (.synReceived, .none, nil, 0)
        }
        let ack = seg.ack
        if ack == snd.nxt {
            snd.una = ack
            if seg.flags.isSyn {
                rcv.nxt = seg.seq &+ 1
            }
            // The handshake-completing ACK may carry data and/or FIN
            // (e.g. HTTP GET piggybacked on the third handshake segment).
            // Handle these so data isn't silently dropped.
            // Validate in-sequence delivery: the data/FIN seq must match rcv.nxt.
            if payloadLen > 0, seg.seq == rcv.nxt {
                rcv.nxt = rcv.nxt &+ UInt32(payloadLen)
                let ackSeg = TCPSegmentToSend(
                    flags: .ack,
                    seq: snd.nxt,
                    ack: rcv.nxt,
                    window: 262144,
                    payload: nil
                )
                if seg.flags.isFin {
                    rcv.nxt = rcv.nxt &+ 1
                    let finAck = TCPSegmentToSend(
                        flags: [.ack],
                        seq: snd.nxt,
                        ack: rcv.nxt,
                        window: 262144,
                        payload: nil
                    )
                    return (.closeWait, .two(ackSeg, finAck), payloadPtr, payloadLen)
                }
                return (.established, .one(ackSeg), payloadPtr, payloadLen)
            }
            if seg.flags.isFin, seg.seq == rcv.nxt {
                rcv.nxt = rcv.nxt &+ 1
                let ackSeg = TCPSegmentToSend(
                    flags: .ack,
                    seq: snd.nxt,
                    ack: rcv.nxt,
                    window: 262144,
                    payload: nil
                )
                return (.closeWait, .one(ackSeg), nil, 0)
            }
            return (.established, .none, nil, 0)
        }
        return (.synReceived, .none, nil, 0)

    case .established:
        // Update peer window
        snd.wnd = UInt32(seg.window)

        // Check for data — MUST validate in-sequence delivery (RFC 793 §3.3).
        // Without this check, duplicate retransmissions and out-of-order
        // segments inflate rcv.nxt and corrupt the data stream.
        if payloadLen > 0 {
            if seg.seq != rcv.nxt {
                // Out-of-order or duplicate — send dup ACK with expected seq
                let dupAck = TCPSegmentToSend(
                    flags: .ack,
                    seq: snd.nxt,
                    ack: rcv.nxt,
                    window: 262144,
                    payload: nil
                )
                return (.established, .one(dupAck), nil, 0)
            }
            rcv.nxt = rcv.nxt &+ UInt32(payloadLen)
            let ackSeg = TCPSegmentToSend(
                flags: .ack,
                seq: snd.nxt,
                ack: rcv.nxt,
                window: 262144,
                payload: nil
            )
            if seg.flags.isFin {
                // FIN must also be in-sequence (seq == rcv.nxt already checked)
                rcv.nxt = rcv.nxt &+ 1
                let finAck = TCPSegmentToSend(
                    flags: [.ack],
                    seq: snd.nxt,
                    ack: rcv.nxt,
                    window: 262144,
                    payload: nil
                )
                return (.closeWait, .two(ackSeg, finAck), payloadPtr, payloadLen)
            }
            return (.established, .one(ackSeg), payloadPtr, payloadLen)
        }

        // Pure ACK (no data) — only advance snd.una, never rewind.
        // An old/reordered ACK must not move snd.una backward.
        if seg.flags.isAck {
            let acked = seg.ack
            if acked &- snd.una < (1 << 31) { snd.una = acked }
        }

        // FIN — only process in-sequence (or ahead, which TCP permits)
        if seg.flags.isFin {
            // FIN ahead of expected seq is illegal but tolerated; just ACK
            if seg.seq != rcv.nxt {
                let dupAck = TCPSegmentToSend(
                    flags: .ack, seq: snd.nxt, ack: rcv.nxt,
                    window: 262144, payload: nil
                )
                return (.established, .one(dupAck), nil, 0)
            }
            rcv.nxt = rcv.nxt &+ 1
            let ackSeg = TCPSegmentToSend(
                flags: .ack,
                seq: snd.nxt,
                ack: rcv.nxt,
                window: 262144,
                payload: nil
            )
            return (.closeWait, .one(ackSeg), nil, 0)
        }

        return (.established, .none, nil, 0)

    case .finWait1:
        snd.wnd = UInt32(seg.window)
        if seg.flags.isAck {
            let ack = seg.ack
            if ack == snd.nxt {
                // Our FIN was ACKed
                snd.una = ack
                if seg.flags.isFin {
                    // Simultaneous — their FIN came with our FIN ACK
                    rcv.nxt = rcv.nxt &+ 1
                    let ackSeg = TCPSegmentToSend(
                        flags: .ack,
                        seq: snd.nxt,
                        ack: rcv.nxt,
                        window: 262144,
                        payload: nil
                    )
                    return (.closed, .one(ackSeg), nil, 0)
                }
                return (.finWait2, .none, nil, 0)
            }
        }
        if seg.flags.isFin {
            rcv.nxt = rcv.nxt &+ 1
            let ackSeg = TCPSegmentToSend(
                flags: .ack,
                seq: snd.nxt,
                ack: rcv.nxt,
                window: 262144,
                payload: nil
            )
            return (.closed, .one(ackSeg), nil, 0)
        }
        return (.finWait1, .none, nil, 0)

    case .finWait2:
        snd.wnd = UInt32(seg.window)

        if payloadLen > 0 && seg.seq == rcv.nxt {
            rcv.nxt = rcv.nxt &+ UInt32(payloadLen)
            if seg.flags.isFin {
                rcv.nxt = rcv.nxt &+ 1
                let ackSeg = TCPSegmentToSend(
                    flags: .ack, seq: snd.nxt, ack: rcv.nxt, window: 262144, payload: nil
                )
                return (.closed, .one(ackSeg), payloadPtr, payloadLen)
            }
            let ackSeg = TCPSegmentToSend(
                flags: .ack, seq: snd.nxt, ack: rcv.nxt, window: 262144, payload: nil
            )
            return (.finWait2, .one(ackSeg), payloadPtr, payloadLen)
        }
        if payloadLen > 0 {
            // Out-of-order or duplicate — send dup ACK
            let dupAck = TCPSegmentToSend(
                flags: .ack, seq: snd.nxt, ack: rcv.nxt,
                window: 262144, payload: nil
            )
            return (.finWait2, .one(dupAck), nil, 0)
        }
        // Pure ACK — process even though we're waiting for peer's FIN
        if seg.flags.isAck {
            let acked = seg.ack
            if acked &- snd.una < (1 << 31) { snd.una = acked }
        }
        if seg.flags.isFin {
            rcv.nxt = rcv.nxt &+ 1
            let ackSeg = TCPSegmentToSend(
                flags: .ack, seq: snd.nxt, ack: rcv.nxt, window: 262144, payload: nil
            )
            return (.closed, .one(ackSeg), nil, 0)
        }
        return (.finWait2, .none, nil, 0)

    case .closeWait:
        snd.wnd = UInt32(seg.window)

        // Validate in-sequence — same as .established
        if payloadLen > 0 && seg.seq == rcv.nxt {
            rcv.nxt = rcv.nxt &+ UInt32(payloadLen)
            let ackSeg = TCPSegmentToSend(
                flags: .ack,
                seq: snd.nxt,
                ack: rcv.nxt,
                window: 262144,
                payload: nil
            )
            return (.closeWait, .one(ackSeg), payloadPtr, payloadLen)
        }
        if payloadLen > 0 {
            // Out-of-order or duplicate — send dup ACK
            let dupAck = TCPSegmentToSend(
                flags: .ack, seq: snd.nxt, ack: rcv.nxt,
                window: 262144, payload: nil
            )
            return (.closeWait, .one(dupAck), nil, 0)
        }
        // Pure ACK — process even after peer has closed (common when
        // external→VM data is still draining past the peer's FIN).
        if seg.flags.isAck {
            let acked = seg.ack
            if acked &- snd.una < (1 << 31) { snd.una = acked }
        }
        return (.closeWait, .none, nil, 0)

    case .lastAck:
        if seg.flags.isAck {
            let ack = seg.ack
            if ack == snd.nxt {
                snd.una = ack
                return (.closed, .none, nil, 0)
            }
        }
        return (.lastAck, .none, nil, 0)
    }
}

/// Initiate an application-level close, sending FIN to the peer.
/// For .established: transitions to .finWait1.
/// For .closeWait: transitions to .lastAck.
/// For all other states: returns the same state with empty toSend.
/// Eliminates the need for callers to fabricate synthetic TCPSegmentInfo.
func tcpAppClose(
    state: TCPState,
    snd: inout SendSequence,
    rcv: inout RecvSequence
) -> (newState: TCPState, toSend: TCPSegmentResult) {
    switch state {
    case .established:
        let fin = TCPSegmentToSend(
            flags: [.fin, .ack], seq: snd.nxt, ack: rcv.nxt,
            window: 262144, payload: nil)
        snd.nxt = snd.nxt &+ 1
        return (.finWait1, .one(fin))
    case .closeWait:
        let fin = TCPSegmentToSend(
            flags: [.fin, .ack], seq: snd.nxt, ack: rcv.nxt,
            window: 262144, payload: nil)
        snd.nxt = snd.nxt &+ 1
        return (.lastAck, .one(fin))
    default:
        return (state, .none)
    }
}

/// Generate an Initial Sequence Number.
/// Uses arc4random for collision-resistant ISNs (RFC 6528 §3).
func tcpGenerateISN() -> UInt32 {
    arc4random()
}
