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

/// Sender-side sequence number tracking.
struct SendSequence {
    var nxt: UInt32    // next sequence number to assign to a new segment
    var una: UInt32    // oldest unacknowledged sequence number
    var wnd: UInt16    // peer's receive window (from last segment)

    /// Bytes in flight (sent but not acknowledged).
    var bytesInFlight: UInt32 { nxt &- una }
}

/// Receiver-side sequence number tracking.
struct RecvSequence {
    var nxt: UInt32    // next expected sequence number
    var initialSeq: UInt32  // initial receive sequence (for verification)
}

/// A segment that the TCP state machine wants to send.
public struct TCPSegmentToSend {
    public let flags: TCPFlags
    public let seq: UInt32
    public let ack: UInt32
    public let window: UInt16
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
///   - segment: Parsed TCP header from the received segment.
///   - snd: Sender-side sequence tracking (inout).
///   - rcv: Receiver-side sequence tracking (inout).
///   - appClose: True if the proxy application (or external side) wants to close.
/// - Returns: New state, segments to send in response, and data to forward to the external side.
func tcpProcess(
    state: TCPState,
    segment: TCPHeader,
    snd: inout SendSequence,
    rcv: inout RecvSequence,
    appClose: Bool
) -> (newState: TCPState, toSend: [TCPSegmentToSend], dataToExternal: [UInt8]?) {
    let result = _tcpProcessImpl(state: state, segment: segment,
                                 snd: &snd, rcv: &rcv, appClose: appClose)
    if result.newState != state, let tracer = tcpStateTransitionTracer {
        tracer(state, result.newState, segment.flags, appClose)
    }
    return result
}

func _tcpProcessImpl(
    state: TCPState,
    segment: TCPHeader,
    snd: inout SendSequence,
    rcv: inout RecvSequence,
    appClose: Bool
) -> (newState: TCPState, toSend: [TCPSegmentToSend], dataToExternal: [UInt8]?) {

    // RST always immediately closes, regardless of state
    if segment.flags.isRst {
        return (.closed, [], nil)
    }

    switch state {
    case .closed:
        return (.closed, [], nil)

    case .listen:
        // Only respond to SYN — connection initiation from peer (VM)
        guard segment.flags.isSyn, !segment.flags.isAck else {
            return (.listen, [], nil)
        }
        let peerSeq = segment.sequenceNumber
        rcv.initialSeq = peerSeq
        rcv.nxt = peerSeq &+ 1
        // Choose our ISN
        let isn = tcpGenerateISN()
        snd.una = isn
        snd.wnd = segment.window
        let synAck = TCPSegmentToSend(
            flags: [.syn, .ack],
            seq: isn,
            ack: rcv.nxt,
            window: 65535,
            payload: nil
        )
        snd.nxt = isn &+ 1  // SYN consumes one sequence number
        return (.synReceived, [synAck], nil)

    case .synReceived:
        // Expecting ACK of our SYN to complete handshake.
        // May be pure ACK (outbound: VM→NAT→external) or SYN+ACK (inbound:
        // external→NAT→VM); in the SYN+ACK case record the peer's ISN.
        guard segment.flags.isAck else {
            return (.synReceived, [], nil)
        }
        let ack = segment.acknowledgmentNumber
        if ack == snd.nxt {
            snd.una = ack
            if segment.flags.isSyn {
                rcv.nxt = segment.sequenceNumber &+ 1
            }
            // The handshake-completing ACK may carry data and/or FIN
            // (e.g. HTTP GET piggybacked on the third handshake segment).
            // Handle these so data isn't silently dropped.
            let dataLen = segment.payload.totalLength
            if dataLen > 0 {
                let data: [UInt8]? = segment.payload.withUnsafeReadableBytes {
                    Array(UnsafeBufferPointer(start: $0.baseAddress!.assumingMemoryBound(to: UInt8.self), count: dataLen))
                }
                rcv.nxt = rcv.nxt &+ UInt32(dataLen)
                let ackSeg = TCPSegmentToSend(
                    flags: .ack,
                    seq: snd.nxt,
                    ack: rcv.nxt,
                    window: 65535,
                    payload: nil
                )
                if segment.flags.isFin {
                    rcv.nxt = rcv.nxt &+ 1
                    let finAck = TCPSegmentToSend(
                        flags: [.ack],
                        seq: snd.nxt,
                        ack: rcv.nxt,
                        window: 65535,
                        payload: nil
                    )
                    return (.closeWait, [ackSeg, finAck], data)
                }
                return (.established, [ackSeg], data)
            }
            if segment.flags.isFin {
                rcv.nxt = rcv.nxt &+ 1
                let ackSeg = TCPSegmentToSend(
                    flags: .ack,
                    seq: snd.nxt,
                    ack: rcv.nxt,
                    window: 65535,
                    payload: nil
                )
                return (.closeWait, [ackSeg], nil)
            }
            return (.established, [], nil)
        }
        return (.synReceived, [], nil)

    case .established:
        // Update peer window
        snd.wnd = segment.window

        // Check for data
        let dataLen = segment.payload.totalLength

        if dataLen > 0 {
            let data: [UInt8]? = segment.payload.withUnsafeReadableBytes {
                Array(UnsafeBufferPointer(start: $0.baseAddress!.assumingMemoryBound(to: UInt8.self), count: dataLen))
            }
            rcv.nxt = rcv.nxt &+ UInt32(dataLen)
            let ackSeg = TCPSegmentToSend(
                flags: .ack,
                seq: snd.nxt,
                ack: rcv.nxt,
                window: 65535,
                payload: nil
            )
            if segment.flags.isFin {
                rcv.nxt = rcv.nxt &+ 1
                let finAck = TCPSegmentToSend(
                    flags: [.ack],
                    seq: snd.nxt,
                    ack: rcv.nxt,
                    window: 65535,
                    payload: nil
                )
                return (.closeWait, [ackSeg, finAck], data)
            }
            return (.established, [ackSeg], data)
        }

        // Pure ACK (no data)
        if segment.flags.isAck {
            snd.una = segment.acknowledgmentNumber
        }

        // FIN
        if segment.flags.isFin {
            rcv.nxt = rcv.nxt &+ 1
            let ackSeg = TCPSegmentToSend(
                flags: .ack,
                seq: snd.nxt,
                ack: rcv.nxt,
                window: 65535,
                payload: nil
            )
            return (.closeWait, [ackSeg], nil)
        }

        // Application (external side) wants to close
        if appClose {
            let fin = TCPSegmentToSend(
                flags: [.fin, .ack],
                seq: snd.nxt,
                ack: rcv.nxt,
                window: 65535,
                payload: nil
            )
            snd.nxt = snd.nxt &+ 1
            return (.finWait1, [fin], nil)
        }

        return (.established, [], nil)

    case .finWait1:
        snd.wnd = segment.window
        if segment.flags.isAck {
            let ack = segment.acknowledgmentNumber
            if ack == snd.nxt {
                // Our FIN was ACKed
                snd.una = ack
                if segment.flags.isFin {
                    // Simultaneous — their FIN came with our FIN ACK
                    rcv.nxt = rcv.nxt &+ 1
                    let ackSeg = TCPSegmentToSend(
                        flags: .ack,
                        seq: snd.nxt,
                        ack: rcv.nxt,
                        window: 65535,
                        payload: nil
                    )
                    return (.closed, [ackSeg], nil)
                }
                return (.finWait2, [], nil)
            }
        }
        if segment.flags.isFin {
            rcv.nxt = rcv.nxt &+ 1
            let ackSeg = TCPSegmentToSend(
                flags: .ack,
                seq: snd.nxt,
                ack: rcv.nxt,
                window: 65535,
                payload: nil
            )
            return (.closed, [ackSeg], nil)
        }
        return (.finWait1, [], nil)

    case .finWait2:
        snd.wnd = segment.window
        let dataLen = segment.payload.totalLength
        if dataLen > 0 {
            let data: [UInt8]? = segment.payload.withUnsafeReadableBytes {
                Array(UnsafeBufferPointer(start: $0.baseAddress!.assumingMemoryBound(to: UInt8.self), count: dataLen))
            }
            rcv.nxt = rcv.nxt &+ UInt32(dataLen)
            if segment.flags.isFin {
                rcv.nxt = rcv.nxt &+ 1
                let ackSeg = TCPSegmentToSend(
                    flags: .ack, seq: snd.nxt, ack: rcv.nxt, window: 65535, payload: nil
                )
                return (.closed, [ackSeg], data)
            }
            let ackSeg = TCPSegmentToSend(
                flags: .ack, seq: snd.nxt, ack: rcv.nxt, window: 65535, payload: nil
            )
            return (.finWait2, [ackSeg], data)
        }
        if segment.flags.isFin {
            rcv.nxt = rcv.nxt &+ 1
            let ackSeg = TCPSegmentToSend(
                flags: .ack, seq: snd.nxt, ack: rcv.nxt, window: 65535, payload: nil
            )
            return (.closed, [ackSeg], nil)
        }
        return (.finWait2, [], nil)

    case .closeWait:
        snd.wnd = segment.window
        let dataLen = segment.payload.totalLength
        var data: [UInt8]? = nil
        if dataLen > 0 {
            data = segment.payload.withUnsafeReadableBytes {
                Array(UnsafeBufferPointer(start: $0.baseAddress!.assumingMemoryBound(to: UInt8.self), count: dataLen))
            }
            rcv.nxt = rcv.nxt &+ UInt32(dataLen)
        }
        // Wait for application to signal close
        if appClose {
            let fin = TCPSegmentToSend(
                flags: [.fin, .ack],
                seq: snd.nxt,
                ack: rcv.nxt,
                window: 65535,
                payload: nil
            )
            snd.nxt = snd.nxt &+ 1
            return (.lastAck, [fin], data)
        }
        return (.closeWait, [], data)

    case .lastAck:
        if segment.flags.isAck {
            let ack = segment.acknowledgmentNumber
            if ack == snd.nxt {
                snd.una = ack
                return (.closed, [], nil)
            }
        }
        return (.lastAck, [], nil)
    }
}

/// Generate an Initial Sequence Number.
/// Uses arc4random for collision-resistant ISNs (RFC 6528 §3).
func tcpGenerateISN() -> UInt32 {
    arc4random()
}
