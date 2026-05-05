import Darwin

/// Batch frame reader — reads all available Ethernet frames from a file descriptor
/// into pool-allocated PacketBuffers.
///
/// BDP optimization: instead of reading one frame per event-loop iteration,
/// `readAllFrames` drains the socket in a tight loop. All chunks are tracked
/// by the provided RoundContext for batch release at round end.
public struct FrameReader {
    public let mtu: Int

    public init(mtu: Int = 1500) {
        self.mtu = mtu
    }

    /// Read all available frames from `fd` until `read()` returns ≤ 0 (EAGAIN or error).
    /// Each frame gets its own pool-allocated chunk. All allocations are tracked
    /// in `round` and batch-released at `round.endRound()`.
    public func readAllFrames(from fd: Int32, round: RoundContext) -> [PacketBuffer] {
        var frames: [PacketBuffer] = []

        while true {
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
