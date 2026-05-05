import Darwin

/// Batch frame reader — reads all available Ethernet frames from a file descriptor
/// into pool-allocated PacketBuffers.
///
/// Sets O_NONBLOCK on the fd before draining so the read loop exits via EAGAIN
/// rather than blocking. Each frame gets its own pool-allocated chunk; all
/// allocations are tracked by the provided RoundContext for batch release.
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

            let n = Darwin.read(fd, ptr, mtu)
            if n <= 0 { break }

            if n < mtu {
                pkt.trimBack(mtu - n)
            }
            frames.append(pkt)
        }

        return frames
    }
}
