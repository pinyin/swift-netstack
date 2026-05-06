import Darwin

/// Batch frame reader — reads all available Ethernet frames from a file descriptor
/// into pool-allocated PacketBuffers.
///
/// Sets O_NONBLOCK on the fd before draining so the read loop exits via EAGAIN
/// rather than blocking. Each frame gets its own pool-allocated chunk; all
/// allocations are tracked by the provided RoundContext for batch release.
///
/// Uses recvmsg() with MSG_TRUNC detection to avoid silently accepting
/// truncated datagrams (same approach as PollingTransport).
public struct FrameReader {
    public let mtu: Int
    private let maxPackets: Int

    public init(mtu: Int = 1500, maxPackets: Int = 256) {
        self.mtu = mtu
        self.maxPackets = maxPackets
    }

    /// Read all available frames from `fd` until EAGAIN, error, or budget.
    public func readAllFrames(from fd: Int32, round: RoundContext) -> [PacketBuffer] {
        // Ensure non-blocking so we drain-and-exit rather than hang
        let flags = fcntl(fd, F_GETFL, 0)
        if flags >= 0 {
            _ = fcntl(fd, F_SETFL, flags | O_NONBLOCK)
        }

        var frames: [PacketBuffer] = []
        frames.reserveCapacity(maxPackets)

        while frames.count < maxPackets {
            var pkt = round.allocate(capacity: mtu, headroom: 0)
            guard let ptr = pkt.appendPointer(count: mtu) else { break }

            var iov = iovec(iov_base: ptr, iov_len: mtu)
            var msg = msghdr(msg_name: nil, msg_namelen: 0, msg_iov: &iov, msg_iovlen: 1, msg_control: nil, msg_controllen: 0, msg_flags: 0)
            let n = Darwin.recvmsg(fd, &msg, 0)
            if n <= 0 { break }

            // Detect truncated datagrams: kernel sets MSG_TRUNC in msg_flags
            // when the datagram exceeds the receive buffer.
            if msg.msg_flags & Int32(MSG_TRUNC) != 0 {
                continue  // silently drop truncated frame
            }

            if n < mtu {
                pkt.trimBack(mtu - n)
            }
            frames.append(pkt)
        }

        return frames
    }
}
