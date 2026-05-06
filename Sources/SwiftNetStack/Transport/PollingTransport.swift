import Darwin

// MARK: - Socket buffer sizing

/// Apple recommends SO_RCVBUF = 4 × SO_SNDBUF for datagram sockets.
/// QEMU benchmarks (2025) confirm 1 MiB / 4 MiB gives optimal throughput
/// on macOS AF_UNIX sockets — 11.4× faster, 8.3× lower CPU vs defaults.
private let kSocketSendBufferSize: Int = 1 * 1024 * 1024       // 1 MiB
private let kSocketRecvBufferSize: Int = 4 * kSocketSendBufferSize  // 4 MiB

/// Maximum packets drained from a single fd per poll() wakeup.
/// Prevents unbounded allocation under VM packet flood.
private let kMaxPacketsPerRead: Int = 256

/// Maximum queued pending writes before oldest entries are dropped.
private let kMaxPendingWrites: Int = 1024

/// Configure a file descriptor for non-blocking batch I/O.
///
/// Sets O_NONBLOCK so the drain loop in `readPackets` can read all
/// available datagrams until EAGAIN. Also increases socket buffer sizes
/// to prevent datagram loss under VM packet bursts.
private func configureNetworkFD(_ fd: Int32) {
    // ── Non-blocking ──
    let flags = fcntl(fd, F_GETFL, 0)
    if flags >= 0 {
        _ = fcntl(fd, F_SETFL, flags | O_NONBLOCK)
    }

    // ── Socket buffer sizing (best-effort, non-fatal) ──
    var sndSize = kSocketSendBufferSize
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndSize, socklen_t(MemoryLayout<Int>.size))

    var rcvSize = kSocketRecvBufferSize
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvSize, socklen_t(MemoryLayout<Int>.size))
}

/// Production transport using poll() + read() + sendmsg().
///
/// Southbound only: VM endpoint fds from VZFileHandleNetworkDeviceAttachment
/// (AF_UNIX SOCK_DGRAM). Each fd delivers raw Ethernet frames as individual
/// datagrams — one `read()` = one frame. Fds are configured O_NONBLOCK so
/// the drain loop can batch-read all pending datagrams per poll() wakeup.
///
/// No TUN fd — this library runs within sandbox constraints. Northbound
/// routing (NAT) will use a userspace UDP socket, deferred to a later phase.
///
/// Read phase: poll() blocks on all VM fds → read ready fds until EAGAIN →
/// collect frames tagged with endpointID.
///
/// Write phase: group by endpointID → sendmsg(MSG_DONTWAIT) per datagram.
/// EAGAIN → internal pending queue, retried on next poll writability.
public struct PollingTransport: Transport {
    private var endpointsByFD: [Int32: VMEndpoint]
    private var fdByEndpointID: [Int: Int32]
    private var mtuByFD: [Int32: Int]
    private var pendingWrites: [(endpointID: Int, packet: PacketBuffer)] = []

    public init(endpoints: [VMEndpoint]) {
        var byFD: [Int32: VMEndpoint] = [:]
        var fdByEP: [Int: Int32] = [:]
        var mtu: [Int32: Int] = [:]
        for ep in endpoints {
            byFD[ep.fd] = ep
            fdByEP[ep.id] = ep.fd
            mtu[ep.fd] = ep.mtu
            configureNetworkFD(ep.fd)
        }
        self.endpointsByFD = byFD
        self.fdByEndpointID = fdByEP
        self.mtuByFD = mtu
    }

    // MARK: - Read

    public mutating func readPackets(round: RoundContext) -> [(endpointID: Int, packet: PacketBuffer)] {
        // ── Build pollfd array ──
        var fds: [Int32] = []
        var pollfds: [pollfd] = []

        for (fd, ep) in endpointsByFD {
            fds.append(fd)
            var events = Int16(POLLIN)
            if pendingWrites.contains(where: { $0.endpointID == ep.id }) {
                events |= Int16(POLLOUT)
            }
            pollfds.append(pollfd(fd: fd, events: events, revents: 0))
        }

        // ── Block until data or pending write becomes ready ──
        let rc = Darwin.poll(&pollfds, UInt32(pollfds.count), -1)
        guard rc > 0 else { return [] }

        // ── Purge dead fds (POLLNVAL, POLLERR, POLLHUP) ──
        for (i, pfd) in pollfds.enumerated() {
            let badMask = Int16(POLLNVAL | POLLERR | POLLHUP)
            guard pfd.revents & badMask != 0 else { continue }
            let fd = fds[i]
            if let ep = endpointsByFD.removeValue(forKey: fd) {
                fdByEndpointID.removeValue(forKey: ep.id)
            }
            mtuByFD.removeValue(forKey: fd)
        }

        // ── Retry pending writes on writable fds ──
        retryPendingWrites(pollfds: pollfds, fds: fds)

        // ── Read from readable fds ──
        var frames: [(endpointID: Int, packet: PacketBuffer)] = []
        frames.reserveCapacity(kMaxPacketsPerRead)

        for (i, pfd) in pollfds.enumerated() where pfd.revents & Int16(POLLIN) != 0 {
            let fd = fds[i]
            guard let ep = endpointsByFD[fd] else { continue }

            while frames.count < kMaxPacketsPerRead {
                var pkt = round.allocate(capacity: ep.mtu, headroom: 0)
                guard let ptr = pkt.appendPointer(count: ep.mtu) else { break }
                let n = Darwin.read(fd, ptr, ep.mtu)
                if n <= 0 { break }
                if n < ep.mtu { pkt.trimBack(ep.mtu - n) }
                frames.append((ep.id, pkt))
            }
        }

        return frames
    }

    // MARK: - Write

    public mutating func writePackets(_ packets: [(endpointID: Int, packet: PacketBuffer)]) {
        for (epID, pkt) in packets {
            guard let fd = fdByEndpointID[epID] else {
                continue
            }

            let written = pkt.sendmsg(to: fd, flags: Int32(MSG_DONTWAIT))
            if written < 0 {
                if errno == EAGAIN {
                    pendingWrites.append((epID, pkt))
                    if pendingWrites.count > kMaxPendingWrites {
                        pendingWrites.removeFirst(pendingWrites.count - kMaxPendingWrites)
                    }
                } else {
                    logWriteError("writePackets", fd: fd, epID: epID)
                }
            }
        }
    }

    // MARK: - Pending retry

    private mutating func retryPendingWrites(pollfds: [pollfd], fds: [Int32]) {
        guard !pendingWrites.isEmpty else { return }

        var writableFDs = Set<Int32>()
        for (i, pfd) in pollfds.enumerated() where pfd.revents & Int16(POLLOUT) != 0 {
            writableFDs.insert(fds[i])
        }

        var remaining: [(endpointID: Int, packet: PacketBuffer)] = []
        for (epID, pkt) in pendingWrites {
            guard let fd = fdByEndpointID[epID] else {
                continue
            }
            guard writableFDs.contains(fd) else {
                remaining.append((epID, pkt))
                continue
            }

            let written = pkt.sendmsg(to: fd, flags: Int32(MSG_DONTWAIT))
            if written < 0 {
                if errno == EAGAIN {
                    remaining.append((epID, pkt))
                } else {
                    logWriteError("retryPendingWrites", fd: fd, epID: epID)
                }
            }
        }
        pendingWrites = remaining
    }
}

// MARK: - Debug write error logging (H1 audit reproduction)

/// H1 (audit): Non-EAGAIN write errors (EPIPE, ECONNRESET, EBADF) are silently
/// discarded in production. This DEBUG-only logger surfaces them on stderr
/// so test runs and development catch them.
private func logWriteError(_ context: String, fd: Int32, epID: Int) {
    #if DEBUG
    let msg = "\(context): sendmsg(fd=\(fd), ep=\(epID))"
        + " failed (\(errno)) — packet silently dropped\n"
    _ = msg.withCString { Darwin.write(STDERR_FILENO, $0, strlen($0)) }
    #endif
}
