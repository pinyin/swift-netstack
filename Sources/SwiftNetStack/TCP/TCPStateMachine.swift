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

/// Optional tracing hook called whenever the TCP FSM changes state.
/// Signature: `(oldState, newState, triggerFlags, appClose) -> Void`.
/// Set from tests or main to visualise connection lifecycle.
///
/// The closure must not throw, block the calling thread, or capture heavy
/// state — it is invoked synchronously on every TCP state transition.
public nonisolated(unsafe) var tcpStateTransitionTracer: ((TCPState, TCPState, TCPFlags, Bool) -> Void)?

/// Process an incoming TCP segment through the finite state machine.
///
/// - Parameters:
///   - state: Current connection state.
///   - seg: TCP segment info (seq, ack, flags, window).
///   - payloadPtr: Pointer to TCP payload data, or nil if no payload.
///   - payloadLen: Length of TCP payload in bytes.
///   - snd: Sender-side sequence tracking (inout).
///   - rcv: Receiver-side sequence tracking (inout).
///   - appClose: True if the proxy application (or external side) wants to close.
/// - Returns: New state, segments to send in response, and (ptr, len) of data to forward to external.
func tcpProcess(
    state: TCPState,
    seg: TCPSegmentInfo,
    payloadPtr: UnsafeRawPointer?,
    payloadLen: Int,
    snd: inout SendSequence,
    rcv: inout RecvSequence,
    appClose: Bool
) -> (newState: TCPState, toSend: [TCPSegmentToSend], dataPtr: UnsafeRawPointer?, dataLen: Int) {
    let result = _tcpProcessImpl(state: state, seg: seg, payloadPtr: payloadPtr,
                                 payloadLen: payloadLen, snd: &snd, rcv: &rcv, appClose: appClose)
    if result.newState != state, let tracer = tcpStateTransitionTracer {
        tracer(state, result.newState, seg.flags, appClose)
    }
    return result
}

func _tcpProcessImpl(
    state: TCPState,
    seg: TCPSegmentInfo,
    payloadPtr: UnsafeRawPointer?,
    payloadLen: Int,
    snd: inout SendSequence,
    rcv: inout RecvSequence,
    appClose: Bool
) -> (newState: TCPState, toSend: [TCPSegmentToSend], dataPtr: UnsafeRawPointer?, dataLen: Int) {

    // RST immediately closes the connection, except in LISTEN (RFC 793 §3.4).
    // An RST arriving in LISTEN must be silently dropped — the sender may
    // be probing a stale half-open connection and we must not transition.
    if seg.flags.isRst {
        if state == .listen { return (.listen, [], nil, 0) }
        return (.closed, [], nil, 0)
    }

    switch state {
    case .closed:
        return (.closed, [], nil, 0)

    case .listen:
        // Only respond to SYN — connection initiation from peer (VM)
        guard seg.flags.isSyn, !seg.flags.isAck else {
            return (.listen, [], nil, 0)
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
        return (.synReceived, [synAck], nil, 0)

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
                return (.synReceived, [synAck], nil, 0)
            }
            return (.synReceived, [], nil, 0)
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
                    return (.closeWait, [ackSeg, finAck], payloadPtr, payloadLen)
                }
                return (.established, [ackSeg], payloadPtr, payloadLen)
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
                return (.closeWait, [ackSeg], nil, 0)
            }
            return (.established, [], nil, 0)
        }
        return (.synReceived, [], nil, 0)

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
                return (.established, [dupAck], nil, 0)
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
                return (.closeWait, [ackSeg, finAck], payloadPtr, payloadLen)
            }
            return (.established, [ackSeg], payloadPtr, payloadLen)
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
                return (.established, [dupAck], nil, 0)
            }
            rcv.nxt = rcv.nxt &+ 1
            let ackSeg = TCPSegmentToSend(
                flags: .ack,
                seq: snd.nxt,
                ack: rcv.nxt,
                window: 262144,
                payload: nil
            )
            return (.closeWait, [ackSeg], nil, 0)
        }

        // Application (external side) wants to close
        if appClose {
            let fin = TCPSegmentToSend(
                flags: [.fin, .ack],
                seq: snd.nxt,
                ack: rcv.nxt,
                window: 262144,
                payload: nil
            )
            snd.nxt = snd.nxt &+ 1
            return (.finWait1, [fin], nil, 0)
        }

        return (.established, [], nil, 0)

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
                    return (.closed, [ackSeg], nil, 0)
                }
                return (.finWait2, [], nil, 0)
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
            return (.closed, [ackSeg], nil, 0)
        }
        return (.finWait1, [], nil, 0)

    case .finWait2:
        snd.wnd = UInt32(seg.window)

        if payloadLen > 0 && seg.seq == rcv.nxt {
            rcv.nxt = rcv.nxt &+ UInt32(payloadLen)
            if seg.flags.isFin {
                rcv.nxt = rcv.nxt &+ 1
                let ackSeg = TCPSegmentToSend(
                    flags: .ack, seq: snd.nxt, ack: rcv.nxt, window: 262144, payload: nil
                )
                return (.closed, [ackSeg], payloadPtr, payloadLen)
            }
            let ackSeg = TCPSegmentToSend(
                flags: .ack, seq: snd.nxt, ack: rcv.nxt, window: 262144, payload: nil
            )
            return (.finWait2, [ackSeg], payloadPtr, payloadLen)
        }
        if payloadLen > 0 {
            // Out-of-order or duplicate — send dup ACK
            let dupAck = TCPSegmentToSend(
                flags: .ack, seq: snd.nxt, ack: rcv.nxt,
                window: 262144, payload: nil
            )
            return (.finWait2, [dupAck], nil, 0)
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
            return (.closed, [ackSeg], nil, 0)
        }
        return (.finWait2, [], nil, 0)

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
            // Wait for application to signal close
            if appClose {
                let fin = TCPSegmentToSend(
                    flags: [.fin, .ack],
                    seq: snd.nxt,
                    ack: rcv.nxt,
                    window: 262144,
                    payload: nil
                )
                snd.nxt = snd.nxt &+ 1
                return (.lastAck, [fin], payloadPtr, payloadLen)
            }
            return (.closeWait, [ackSeg], payloadPtr, payloadLen)
        }
        if payloadLen > 0 {
            // Out-of-order or duplicate — send dup ACK
            let dupAck = TCPSegmentToSend(
                flags: .ack, seq: snd.nxt, ack: rcv.nxt,
                window: 262144, payload: nil
            )
            return (.closeWait, [dupAck], nil, 0)
        }
        // Pure ACK — process even after peer has closed (common when
        // external→VM data is still draining past the peer's FIN).
        if seg.flags.isAck {
            let acked = seg.ack
            if acked &- snd.una < (1 << 31) { snd.una = acked }
        }
        // Wait for application to signal close
        if appClose {
            let fin = TCPSegmentToSend(
                flags: [.fin, .ack],
                seq: snd.nxt,
                ack: rcv.nxt,
                window: 262144,
                payload: nil
            )
            snd.nxt = snd.nxt &+ 1
            return (.lastAck, [fin], nil, 0)
        }
        return (.closeWait, [], nil, 0)

    case .lastAck:
        if seg.flags.isAck {
            let ack = seg.ack
            if ack == snd.nxt {
                snd.una = ack
                return (.closed, [], nil, 0)
            }
        }
        return (.lastAck, [], nil, 0)
    }
}

/// Generate an Initial Sequence Number.
/// Uses arc4random for collision-resistant ISNs (RFC 6528 §3).
func tcpGenerateISN() -> UInt32 {
    arc4random()
}
