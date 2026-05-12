import Darwin

// MARK: - Socket buffer sizing

private let kSocketSendBufferSize: Int = 1 * 1024 * 1024
private let kSocketRecvBufferSize: Int = 4 * kSocketSendBufferSize

private func configureNetworkFD(_ fd: Int32) {
    let flags = fcntl(fd, F_GETFL, 0)
    if flags >= 0 { _ = fcntl(fd, F_SETFL, flags | O_NONBLOCK) }
    var sndSize = kSocketSendBufferSize
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndSize, socklen_t(MemoryLayout<Int>.size))
    var rcvSize = kSocketRecvBufferSize
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvSize, socklen_t(MemoryLayout<Int>.size))
    var one: Int32 = 1
    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size))
}

// MARK: - External FD kind

public enum ExternalFDKind {
    case stream
    case datagram
    case rawDatagram
}

// MARK: - Transport result

/// All data read by a single readPackets() call.
public struct TransportResult {
    public var streamReads: [(fd: Int32, data: [UInt8])] = []
    public var streamAccepts: [(listenerFD: Int32, newFD: Int32, remoteAddr: sockaddr_in)] = []
    public var streamHangup: [Int32] = []
    public var streamConnects: [Int32] = []
    public var datagramReads: [(fd: Int32, data: [UInt8], from: sockaddr_in)] = []
    public var rawDatagramReads: [(fd: Int32, data: [UInt8])] = []
    public var deadFDs: [Int32] = []
}

// MARK: - PollingTransport

public struct PollingTransport {
    private var endpointsByFD: [Int32: VMEndpoint]
    private var fdByEndpointID: [Int: Int32]
    private var externalFDs: [(fd: Int32, events: Int16, kind: ExternalFDKind)] = []
    private let shutdownFD: Int32?
    private let onShutdown: (() -> Void)?
    public var pollTimeout: Int32
    public var stats: TransportStats

    // MARK: - Endpoint fd lookup

    public func fdForEndpoint(_ id: Int) -> Int32? {
        fdByEndpointID[id]
    }

    public init(endpoints: [VMEndpoint], shutdownFD: Int32? = nil,
                onShutdown: (() -> Void)? = nil, pollTimeout: Int32 = 100) {
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

    public mutating func registerFD(_ fd: Int32, events: Int16, kind: ExternalFDKind) {
        if let idx = externalFDs.firstIndex(where: { $0.fd == fd }) {
            externalFDs[idx] = (fd, events, kind)
        } else {
            externalFDs.append((fd, events, kind))
        }
    }

    public mutating func unregisterFD(_ fd: Int32) {
        externalFDs.removeAll { $0.fd == fd }
    }

    public mutating func setFDEvents(_ fd: Int32, events: Int16) {
        guard let idx = externalFDs.firstIndex(where: { $0.fd == fd }) else { return }
        externalFDs[idx].events = events
    }

    public mutating func registerFDs(_ fds: [(fd: Int32, events: Int16, kind: ExternalFDKind)]) {
        for (fd, events, kind) in fds { registerFD(fd, events: events, kind: kind) }
    }

    // MARK: - Read (unified poll + read all)

    public mutating func readPackets(io: IOBuffer) -> TransportResult {
        var result = TransportResult()
        io.frameCount = 0

        // ── Build pollfd array ──
        var fds: [Int32] = []
        var pollfds: [pollfd] = []
        let endpointCount = endpointsByFD.count

        for (fd, _) in endpointsByFD {
            fds.append(fd)
            pollfds.append(pollfd(fd: fd, events: Int16(POLLIN), revents: 0))
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

        // ── Read external FDs ──
        for i in endpointCount..<(endpointCount + externalFDs.count) {
            let rev = pollfds[i].revents
            guard rev != 0 else { continue }
            let fd = fds[i]
            let kind = externalFDs[i - endpointCount].kind

            if rev & Int16(POLLERR | POLLNVAL) != 0 {
                result.deadFDs.append(fd); continue
            }
            if rev & Int16(POLLHUP) != 0 && rev & Int16(POLLIN) == 0 {
                if kind == .stream { result.streamHangup.append(fd) }
                else { result.deadFDs.append(fd) }
                continue
            }
            if kind == .stream && rev & Int16(POLLOUT) != 0 {
                result.streamConnects.append(fd)
            }

            if rev & Int16(POLLIN) != 0 {
                switch kind {
                case .stream:
                    var isListener = false
                    while true {
                        var buf = [UInt8](repeating: 0, count: 65536)
                        stats.recvCalls += 1
                        let n = buf.withUnsafeMutableBytes {
                            Darwin.recv(fd, $0.baseAddress!, 65536, 0)
                        }
                        if n > 0 {
                            buf.removeLast(65536 - n)
                            result.streamReads.append((fd, buf))
                        } else if n == 0 {
                            result.streamHangup.append(fd); break
                        } else {
                            if errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR { break }
                            if errno == ENOTCONN { isListener = true; break }
                            result.deadFDs.append(fd); break
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
                        var buf = [UInt8](repeating: 0, count: 65536)
                        var srcAddr = sockaddr_in()
                        var srcLen = socklen_t(MemoryLayout<sockaddr_in>.size)
                        stats.recvfromCalls += 1
                        let n = buf.withUnsafeMutableBytes { ptr in
                            withUnsafeMutablePointer(to: &srcAddr) {
                                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                                    Darwin.recvfrom(fd, ptr.baseAddress!, 65536, 0, $0, &srcLen)
                                }
                            }
                        }
                        if n > 0 {
                            buf.removeLast(65536 - n)
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
                        var buf = [UInt8](repeating: 0, count: 4096)
                        let n = buf.withUnsafeMutableBytes {
                            Darwin.recvfrom(fd, $0.baseAddress!, 4096, 0, nil, nil)
                        }
                        if n > 0 {
                            buf.removeLast(4096 - n)
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

        // ── Read VM fds directly into IOBuffer.input ──
        let mtu = io.mtu
        for i in 0..<endpointCount where pollfds[i].revents & Int16(POLLIN) != 0 {
            let fd = fds[i]
            guard let ep = endpointsByFD[fd] else { continue }

            while io.frameCount < io.maxFrames {
                let idx = io.frameCount
                let ptr = io.framePtr(idx)
                var iov = iovec(iov_base: ptr, iov_len: mtu)
                var msg = msghdr(msg_name: nil, msg_namelen: 0,
                                 msg_iov: &iov, msg_iovlen: 1,
                                 msg_control: nil, msg_controllen: 0, msg_flags: 0)
                stats.recvmsgCalls += 1
                let n = Darwin.recvmsg(fd, &msg, 0)
                if n <= 0 { break }
                if msg.msg_flags & Int32(MSG_TRUNC) != 0 { continue }
                io.frameLengths[idx] = n
                io.frameEndpointIDs[idx] = ep.id
                io.frameCount += 1
            }
        }

        return result
    }

    // MARK: - Write (VM endpoints)

    /// Write output frames from an OutBatch. Iterates by subscript, constructing
    /// iovecs from IOBuffer.output header area + IOBuffer.input payload area.
    public mutating func writeBatch(_ batch: OutBatch, io: IOBuffer) {
        for i in 0..<batch.count {
            guard let fd = fdByEndpointID[batch.epIDs[i]] else { continue }
            let hdrPtr = io.output.baseAddress! + batch.hdrOfs[i]
            let hdrLen = batch.hdrLen[i]

            if batch.payOfs[i] >= 0, batch.payLen[i] > 0 {
                var iov0 = iovec(iov_base: UnsafeMutableRawPointer(mutating: hdrPtr), iov_len: hdrLen)
                let payBase = batch.payBase[i] ?? io.input.baseAddress!
                let payPtr = payBase + batch.payOfs[i]
                var iov1 = iovec(iov_base: UnsafeMutableRawPointer(mutating: payPtr), iov_len: batch.payLen[i])
                var iovs: [iovec] = [iov0, iov1]
                _ = iovs.withUnsafeMutableBufferPointer { iovPtr in
                    var msg = msghdr(msg_name: nil, msg_namelen: 0,
                                     msg_iov: iovPtr.baseAddress, msg_iovlen: 2,
                                     msg_control: nil, msg_controllen: 0, msg_flags: 0)
                    stats.sendmsgCalls += 1
                    stats.sendBytes += UInt64(hdrLen + batch.payLen[i])
                    let r = Darwin.sendmsg(fd, &msg, Int32(MSG_DONTWAIT | MSG_NOSIGNAL))
                    if r < 0, errno != EAGAIN, errno != ENOBUFS {
                        fputs("[POLL-WRITE] sendmsg(iov) fd=\(fd) failed: errno=\(errno) hdrLen=\(hdrLen) payLen=\(batch.payLen[i])\n", stderr)
                    }
                    return r
                }
            } else {
                var iov = iovec(iov_base: UnsafeMutableRawPointer(mutating: hdrPtr), iov_len: hdrLen)
                var msg = msghdr(msg_name: nil, msg_namelen: 0,
                                 msg_iov: &iov, msg_iovlen: 1,
                                 msg_control: nil, msg_controllen: 0, msg_flags: 0)
                stats.sendmsgCalls += 1
                stats.sendBytes += UInt64(hdrLen)
                let r = Darwin.sendmsg(fd, &msg, Int32(MSG_DONTWAIT | MSG_NOSIGNAL))
                if r < 0, errno != EAGAIN, errno != ENOBUFS {
                    fputs("[POLL-WRITE] sendmsg fd=\(fd) failed: errno=\(errno) hdrLen=\(hdrLen)\n", stderr)
                }
                _ = r
            }
        }
    }

    /// Write a single TCP frame directly (no OutBatch intermediate).
    /// Called from NATTable for inline writes during processTCPRound.
    @discardableResult
    public mutating func writeSingleFrame(
        endpointID: Int, io: IOBuffer,
        hdrOfs: Int, hdrLen: Int,
        payPtr: UnsafeRawPointer?, payLen: Int
    ) -> Bool {
        guard let fd = fdByEndpointID[endpointID] else { return false }
        let hdrPtr = io.output.baseAddress! + hdrOfs
        if let payPtr, payLen > 0 {
            var iov0 = iovec(iov_base: UnsafeMutableRawPointer(mutating: hdrPtr), iov_len: hdrLen)
            var iov1 = iovec(iov_base: UnsafeMutableRawPointer(mutating: payPtr), iov_len: payLen)
            var iovs: [iovec] = [iov0, iov1]
            var ok = false
            _ = iovs.withUnsafeMutableBufferPointer { iovPtr in
                var msg = msghdr(msg_name: nil, msg_namelen: 0,
                                 msg_iov: iovPtr.baseAddress, msg_iovlen: 2,
                                 msg_control: nil, msg_controllen: 0, msg_flags: 0)
                stats.sendmsgCalls += 1
                stats.sendBytes += UInt64(hdrLen + payLen)
                ok = Darwin.sendmsg(fd, &msg, Int32(MSG_DONTWAIT | MSG_NOSIGNAL)) >= 0
            }
            return ok
        } else {
            var iov = iovec(iov_base: UnsafeMutableRawPointer(mutating: hdrPtr), iov_len: hdrLen)
            var msg = msghdr(msg_name: nil, msg_namelen: 0,
                             msg_iov: &iov, msg_iovlen: 1,
                             msg_control: nil, msg_controllen: 0, msg_flags: 0)
            stats.sendmsgCalls += 1
            stats.sendBytes += UInt64(hdrLen)
            return Darwin.sendmsg(fd, &msg, Int32(MSG_DONTWAIT | MSG_NOSIGNAL)) >= 0
        }
    }

    // MARK: - Write (external FDs)

    @discardableResult
    public mutating func writeStream(_ data: [UInt8], to fd: Int32) -> Int {
        guard !data.isEmpty else { return 0 }
        stats.sendmsgCalls += 1
        stats.sendBytes += UInt64(data.count)
        return data.withUnsafeBytes { ptr in
            Darwin.send(fd, ptr.baseAddress!, data.count, Int32(MSG_NOSIGNAL))
        }
    }

    @discardableResult
    public mutating func writeDatagram(_ data: [UInt8], to fd: Int32, addr: sockaddr_in) -> Int {
        guard !data.isEmpty else { return 0 }
        var sa = addr
        stats.sendmsgCalls += 1
        stats.sendBytes += UInt64(data.count)
        return data.withUnsafeBytes { ptr in
            var iov = iovec(iov_base: UnsafeMutableRawPointer(mutating: ptr.baseAddress!), iov_len: data.count)
            var msg = msghdr(
                msg_name: &sa, msg_namelen: socklen_t(MemoryLayout<sockaddr_in>.size),
                msg_iov: &iov, msg_iovlen: 1,
                msg_control: nil, msg_controllen: 0, msg_flags: 0
            )
            return Darwin.sendmsg(fd, &msg, 0)
        }
    }

    @discardableResult
    public mutating func writeDatagram(_ data: [UInt8], to fd: Int32) -> Int {
        guard !data.isEmpty else { return 0 }
        stats.sendmsgCalls += 1
        stats.sendBytes += UInt64(data.count)
        return data.withUnsafeBytes { ptr in
            Darwin.send(fd, ptr.baseAddress!, data.count, 0)
        }
    }
}
