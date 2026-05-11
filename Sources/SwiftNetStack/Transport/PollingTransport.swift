import Darwin

// MARK: - Socket buffer sizing

private let kSocketSendBufferSize: Int = 1 * 1024 * 1024
private let kSocketRecvBufferSize: Int = 4 * kSocketSendBufferSize
private let kMaxPacketsPerRead: Int = 256
private let kMaxPendingWrites: Int = 1024

private func configureNetworkFD(_ fd: Int32) {
    let flags = fcntl(fd, F_GETFL, 0)
    if flags >= 0 { _ = fcntl(fd, F_SETFL, flags | O_NONBLOCK) }
    var sndSize = kSocketSendBufferSize
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndSize, socklen_t(MemoryLayout<Int>.size))
    var rcvSize = kSocketRecvBufferSize
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvSize, socklen_t(MemoryLayout<Int>.size))
}

// MARK: - External FD kind

/// How Transport should read data from an external FD when poll reports it ready.
public enum ExternalFDKind {
    case stream        // TCP: recv() into buffer
    case datagram      // UDP: recvfrom() with source address
    case rawDatagram   // DNS upstream: recvfrom() without source
}

// MARK: - Transport result

/// All data read by a single Transport.readPackets() call.
public struct TransportResult {
    public var vmFrames: [(endpointID: Int, packet: PacketBuffer)] = []
    public var streamReads: [(fd: Int32, data: PacketBuffer)] = []
    public var streamAccepts: [(listenerFD: Int32, newFD: Int32, remoteAddr: sockaddr_in)] = []
    public var streamHangup: [Int32] = []
    public var datagramReads: [(fd: Int32, data: PacketBuffer, from: sockaddr_in)] = []
    public var rawDatagramReads: [(fd: Int32, data: PacketBuffer)] = []
    public var streamConnects: [Int32] = []
    public var deadFDs: [Int32] = []
}

// MARK: - PollingTransport

/// Complete I/O layer — polls, reads, and writes ALL file descriptors.
///
/// VM endpoints are fixed at init. External FDs (NAT, DNS) are registered
/// at runtime via `registerFD` / `unregisterFD`. Transport owns the full
/// pollfd set — `readPackets` needs no external parameters.
///
/// Write methods cover all FD types: VM frames go through `writePackets` with
/// pending-write retry; external writes go through `writeStream` / `writeDatagram`.
public struct PollingTransport {
    private var endpointsByFD: [Int32: VMEndpoint]
    private var fdByEndpointID: [Int: Int32]
    private var pendingWrites: [(endpointID: Int, packet: PacketBuffer)] = []
    private var externalFDs: [(fd: Int32, events: Int16, kind: ExternalFDKind)] = []
    private let shutdownFD: Int32?
    private let onShutdown: (() -> Void)?
    public var pollTimeout: Int32
    public var stats: TransportStats

    public init(endpoints: [VMEndpoint], shutdownFD: Int32? = nil, onShutdown: (() -> Void)? = nil, pollTimeout: Int32 = 100) {
        var byFD: [Int32: VMEndpoint] = [:]
        var fdByEP: [Int: Int32] = [:]
        for ep in endpoints {
            byFD[ep.fd] = ep
            fdByEP[ep.id] = ep.fd
            configureNetworkFD(ep.fd)
        }
        self.endpointsByFD = byFD
        self.fdByEndpointID = fdByEP
        self.shutdownFD = shutdownFD
        self.onShutdown = onShutdown
        self.pollTimeout = pollTimeout
        self.stats = TransportStats()
    }

    // MARK: - External FD registration

    /// Register an external FD for polling. Safe to call multiple times
    /// with updated events — replaces any previous registration for this fd.
    public mutating func registerFD(_ fd: Int32, events: Int16, kind: ExternalFDKind) {
        if let idx = externalFDs.firstIndex(where: { $0.fd == fd }) {
            externalFDs[idx] = (fd, events, kind)
        } else {
            externalFDs.append((fd, events, kind))
        }
    }

    /// Remove an external FD from the poll set.
    public mutating func unregisterFD(_ fd: Int32) {
        externalFDs.removeAll { $0.fd == fd }
    }

    /// Update poll events for an already-registered external FD.
    /// Preserves the existing FD kind. No-op if the FD is not registered.
    public mutating func setFDEvents(_ fd: Int32, events: Int16) {
        guard let idx = externalFDs.firstIndex(where: { $0.fd == fd }) else { return }
        externalFDs[idx].events = events
    }

    /// Bulk-register external FDs (used for initial sync of listener FDs).
    public mutating func registerFDs(_ fds: [(fd: Int32, events: Int16, kind: ExternalFDKind)]) {
        for (fd, events, kind) in fds {
            registerFD(fd, events: events, kind: kind)
        }
    }

    // MARK: - Read (unified poll + read all)

    /// Single poll() over ALL FDs, then read data from every ready FD.
    /// VM FDs → Ethernet frames. External FDs → typed data based on their kind.
    public mutating func readPackets(round: RoundContext) -> TransportResult {
        var result = TransportResult()

        // ── Build pollfd array: VM endpoints → external FDs → shutdown ──
        var fds: [Int32] = []
        var pollfds: [pollfd] = []
        let endpointCount = endpointsByFD.count
        let pendingEndpointIDs = Set(pendingWrites.map { $0.endpointID })
        for (fd, ep) in endpointsByFD {
            fds.append(fd)
            var events = Int16(POLLIN)
            if pendingEndpointIDs.contains(ep.id) { events |= Int16(POLLOUT) }
            pollfds.append(pollfd(fd: fd, events: events, revents: 0))
        }

        for (fd, ev, _) in externalFDs {
            fds.append(fd)
            pollfds.append(pollfd(fd: fd, events: ev, revents: 0))
        }

        var shutdownIdx: Int?
        if let sfd = shutdownFD {
            shutdownIdx = pollfds.count
            fds.append(sfd)
            pollfds.append(pollfd(fd: sfd, events: Int16(POLLIN), revents: 0))
        }

        // ── Block until activity ──
        stats.pollCalls += 1
        let rc = Darwin.poll(&pollfds, UInt32(pollfds.count), pollTimeout)
        if rc == 0 { stats.pollTimeouts += 1 }
        guard rc > 0 else { return result }

        // ── Shutdown ──
        if let idx = shutdownIdx, pollfds[idx].revents & Int16(POLLIN) != 0 {
            var buf: UInt8 = 0
            _ = Darwin.read(shutdownFD!, &buf, 1)
            onShutdown?()
            return result
        }

        // ── Purge dead VM endpoint fds ──
        for i in 0..<endpointCount {
            let rev = pollfds[i].revents
            guard rev & Int16(POLLNVAL | POLLERR | POLLHUP) != 0 else { continue }
            let fd = fds[i]
            if let ep = endpointsByFD.removeValue(forKey: fd) {
                fdByEndpointID.removeValue(forKey: ep.id)
            }
        }

        // ── Retry pending writes on writable VM fds ──
        retryPendingWrites(pollfds: pollfds, fds: fds)

        // ── Read from ready external FDs ──
        for i in endpointCount..<(endpointCount + externalFDs.count) {
            let rev = pollfds[i].revents
            guard rev != 0 else { continue }
            let fd = fds[i]
            let kind = externalFDs[i - endpointCount].kind

            // Errors
            if rev & Int16(POLLERR | POLLNVAL) != 0 {
                result.deadFDs.append(fd)
                continue
            }
            if rev & Int16(POLLHUP) != 0 && rev & Int16(POLLIN) == 0 {
                if kind == .stream { result.streamHangup.append(fd) }
                else { result.deadFDs.append(fd) }
                continue
            }

            // POLLOUT on stream sockets → connect completed
            if kind == .stream && rev & Int16(POLLOUT) != 0 {
                result.streamConnects.append(fd)
            }

            // Read data
            if rev & Int16(POLLIN) != 0 {
                switch kind {
                case .stream:
                    var isListener = false
                    while true {
                        var buf = round.allocate(capacity: 65536, headroom: 0)
                        guard let ptr = buf.appendPointer(count: 65536) else { break }
                        stats.recvCalls += 1
                        let n = Darwin.recv(fd, ptr, 65536, 0)
                        if n > 0 {
                            buf.trimBack(65536 - n)
                            result.streamReads.append((fd, buf))
                        } else if n == 0 {
                            result.streamHangup.append(fd)
                            break
                        } else {
                            if errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR { break }
                            if errno == ENOTCONN { isListener = true; break }
                            result.deadFDs.append(fd)
                            break
                        }
                    }
                    if isListener {
                        while true {
                            var clientAddr = sockaddr_in()
                            var addrLen = socklen_t(MemoryLayout<sockaddr_in>.size)
                            let newFD = withUnsafeMutablePointer(to: &clientAddr) {
                                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                                    Darwin.accept(fd, $0, &addrLen)
                                }
                            }
                            if newFD >= 0 {
                                let flags = fcntl(newFD, F_GETFL, 0)
                                if flags >= 0 { _ = fcntl(newFD, F_SETFL, flags | O_NONBLOCK) }
                                result.streamAccepts.append((listenerFD: fd, newFD: newFD, remoteAddr: clientAddr))
                            } else {
                                if errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR { break }
                                break
                            }
                        }
                    }
                case .datagram:
                    while true {
                        var buf = round.allocate(capacity: 65536, headroom: 0)
                        guard let ptr = buf.appendPointer(count: 65536) else { break }
                        var srcAddr = sockaddr_in()
                        var srcLen = socklen_t(MemoryLayout<sockaddr_in>.size)
                        stats.recvfromCalls += 1
                        let n = withUnsafeMutablePointer(to: &srcAddr) {
                            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                                Darwin.recvfrom(fd, ptr, 65536, 0, $0, &srcLen)
                            }
                        }
                        if n > 0 {
                            buf.trimBack(65536 - n)
                            result.datagramReads.append((fd, buf, srcAddr))
                        } else {
                            if n < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR {
                                result.deadFDs.append(fd)
                            }
                            break
                        }
                    }
                case .rawDatagram:
                    while true {
                        var buf = round.allocate(capacity: 4096, headroom: 0)
                        guard let ptr = buf.appendPointer(count: 4096) else { break }
                        let n = Darwin.recvfrom(fd, ptr, 4096, 0, nil, nil)
                        if n > 0 {
                            buf.trimBack(4096 - n)
                            result.rawDatagramReads.append((fd, buf))
                        } else {
                            if n < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR {
                                result.deadFDs.append(fd)
                            }
                            break
                        }
                    }
                }
            }
        }

        // ── Auto-unregister dead/hung external FDs ──
        let deadSet = Set(result.deadFDs).union(result.streamHangup)
        if !deadSet.isEmpty {
            externalFDs.removeAll { deadSet.contains($0.fd) }
        }

        // ── Read from readable VM fds ──
        for i in 0..<endpointCount where pollfds[i].revents & Int16(POLLIN) != 0 {
            let fd = fds[i]
            guard let ep = endpointsByFD[fd] else { continue }

            while result.vmFrames.count < kMaxPacketsPerRead {
                var pkt = round.allocate(capacity: ep.mtu, headroom: 0)
                guard let ptr = pkt.appendPointer(count: ep.mtu) else { break }
                var iov = iovec(iov_base: ptr, iov_len: ep.mtu)
                var msg = msghdr(msg_name: nil, msg_namelen: 0, msg_iov: &iov, msg_iovlen: 1, msg_control: nil, msg_controllen: 0, msg_flags: 0)
                stats.recvmsgCalls += 1
                let n = Darwin.recvmsg(fd, &msg, 0)
                if n <= 0 { break }
                if msg.msg_flags & Int32(MSG_TRUNC) != 0 { continue }
                if n < ep.mtu { pkt.trimBack(ep.mtu - n) }
                result.vmFrames.append((ep.id, pkt))
            }
        }

        return result
    }

    // MARK: - Write (VM endpoints)

    public mutating func writePackets(_ packets: [(endpointID: Int, packet: PacketBuffer)]) {
        for (epID, pkt) in packets {
            guard let fd = fdByEndpointID[epID] else { continue }
            if sendPacket(pkt, to: fd, flags: Int32(MSG_DONTWAIT)) < 0 {
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

    // MARK: - Write (external FDs)

    /// Send data on a stream (TCP) socket. Returns bytes written or -1.
    @discardableResult
    public mutating func writeStream(_ data: PacketBuffer, to fd: Int32) -> Int {
        sendPacket(data, to: fd, flags: 0)
    }

    /// Send a datagram on a UDP socket. Returns bytes written or -1.
    @discardableResult
    public mutating func writeDatagram(_ data: PacketBuffer, to fd: Int32, addr: sockaddr_in) -> Int {
        var iov = data.iovecs()
        guard !iov.isEmpty else { return 0 }
        var sa = addr
        return iov.withUnsafeMutableBufferPointer { iovPtr in
            var msg = msghdr(
                msg_name: &sa, msg_namelen: socklen_t(MemoryLayout<sockaddr_in>.size),
                msg_iov: iovPtr.baseAddress, msg_iovlen: Int32(iovPtr.count),
                msg_control: nil, msg_controllen: 0, msg_flags: 0
            )
            return Darwin.sendmsg(fd, &msg, 0)
        }
    }

    /// Send a datagram on a connected socket (no destination address).
    @discardableResult
    public mutating func writeDatagram(_ data: PacketBuffer, to fd: Int32) -> Int {
        sendPacket(data, to: fd, flags: 0)
    }

    // MARK: - Internal scatter-gather send

    private mutating func sendPacket(_ pkt: PacketBuffer, to fd: Int32, flags: Int32) -> Int {
        var iov = pkt.iovecs()
        guard !iov.isEmpty else { return 0 }
        stats.sendmsgCalls += 1
        stats.sendBytes += UInt64(pkt.totalLength)
        return iov.withUnsafeMutableBufferPointer { iovPtr in
            var msg = msghdr(
                msg_name: nil, msg_namelen: 0,
                msg_iov: iovPtr.baseAddress, msg_iovlen: Int32(iovPtr.count),
                msg_control: nil, msg_controllen: 0, msg_flags: 0
            )
            return Darwin.sendmsg(fd, &msg, flags)
        }
    }

    // MARK: - Pending write retry

    private mutating func retryPendingWrites(pollfds: [pollfd], fds: [Int32]) {
        guard !pendingWrites.isEmpty else { return }
        var writableFDs = Set<Int32>()
        for (i, pfd) in pollfds.enumerated() where pfd.revents & Int16(POLLOUT) != 0 {
            writableFDs.insert(fds[i])
        }
        var remaining: [(endpointID: Int, packet: PacketBuffer)] = []
        for (epID, pkt) in pendingWrites {
            guard let fd = fdByEndpointID[epID], writableFDs.contains(fd) else {
                remaining.append((epID, pkt)); continue
            }
            if sendPacket(pkt, to: fd, flags: Int32(MSG_DONTWAIT)) < 0 {
                if errno == EAGAIN { remaining.append((epID, pkt)) }
                else { logWriteError("retryPendingWrites", fd: fd, epID: epID) }
            }
        }
        pendingWrites = remaining
    }
}

// MARK: - Debug

private func logWriteError(_ context: String, fd: Int32, epID: Int) {
    #if DEBUG
    let msg = "\(context): sendmsg(fd=\(fd), ep=\(epID)) failed (\(errno)) — packet silently dropped\n"
    _ = msg.withCString { Darwin.write(STDERR_FILENO, $0, strlen($0)) }
    #endif
}
