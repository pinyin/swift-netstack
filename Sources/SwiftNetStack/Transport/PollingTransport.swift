import Darwin

// MARK: - Socket buffer sizing

/// SO_RCVBUF for virtio-net VM endpoint fds.
/// Large enough to absorb TCP recovery bursts without bufferbloat.
/// SO_SNDBUF is left at OS default — the BDP poll loop is tight enough
/// that a large send buffer only hides backpressure.
private let kVNicRecvBufferSize: Int = 4 * 1024 * 1024

private func configureNetworkFD(_ fd: Int32) {
    let flags = fcntl(fd, F_GETFL, 0)
    if flags >= 0 { _ = fcntl(fd, F_SETFL, flags | O_NONBLOCK) }
    var rcvSize = kVNicRecvBufferSize
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
    /// Zero-copy stream reads: fd → bytesRead. Data was recv'd directly into
    /// the connection's sendQueue buffer, avoiding copies.
    public var zeroCopyReads: [(fd: Int32, bytesRead: Int)] = []
    /// Flat buffer backing streamReads offsets (fallback when no recv target).
    public var streamDataBuffer: [UInt8] = []
    /// Stream reads as (fd, offset, len) into streamDataBuffer (fallback).
    public var streamReads: [(fd: Int32, offset: Int, len: Int)] = []
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

    /// Per-fd direct-recv targets. When a stream fd has a target, readPackets
    /// recvs directly into that buffer (zero-copy), eliminating recvScratch
    /// and streamDataBuffer copies. Capacity reserved at init — no allocs in
    /// the hot path.
    private var recvTargetFDs: [Int32] = []
    private var recvTargetBufs: [UnsafeMutableRawPointer] = []
    private var recvTargetCaps: [Int] = []

    /// Reusable recv scratch buffer — used as fallback when no recv target.
    private var recvScratch: [UInt8]

    // MARK: - Endpoint fd lookup

    public func fdForEndpoint(_ id: Int) -> Int32? {
        fdByEndpointID[id]
    }

    // MARK: - Zero-copy recv targets

    /// Register a direct-recv buffer for a stream fd. During readPackets,
    /// data is recv'd directly into this buffer (zero-copy), skipping
    /// recvScratch and streamDataBuffer.
    public mutating func setRecvTarget(fd: Int32, buffer: UnsafeMutableRawPointer, capacity: Int) {
        if let idx = recvTargetFDs.firstIndex(of: fd) {
            recvTargetBufs[idx] = buffer
            recvTargetCaps[idx] = capacity
        } else {
            recvTargetFDs.append(fd)
            recvTargetBufs.append(buffer)
            recvTargetCaps.append(capacity)
        }
    }

    /// Remove all recv targets (call after each round).
    public mutating func clearRecvTargets() {
        recvTargetFDs.removeAll(keepingCapacity: true)
        recvTargetBufs.removeAll(keepingCapacity: true)
        recvTargetCaps.removeAll(keepingCapacity: true)
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
        recvTargetFDs.reserveCapacity(256)
        recvTargetBufs.reserveCapacity(256)
        recvTargetCaps.reserveCapacity(256)
        self.recvScratch = [UInt8](repeating: 0, count: 65536)
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
                    // Zero-copy path: recv directly into the connection's sendQueue.
                    // Advance buffer pointer after each recv to avoid overwriting.
                    if let tIdx = recvTargetFDs.firstIndex(of: fd) {
                        var totalRead = 0
                        while true {
                            let cap = recvTargetCaps[tIdx]
                            guard cap > 0 else { break }
                            let buf = recvTargetBufs[tIdx].advanced(by: totalRead)
                            stats.recvCalls += 1
                            let n = Darwin.recv(fd, buf, cap, 0)
                            if n > 0 {
                                totalRead += n
                                recvTargetCaps[tIdx] = cap - n
                            } else if n == 0 {
                                result.streamHangup.append(fd); break
                            } else {
                                if errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR { break }
                                if errno == ENOTCONN { isListener = true; break }
                                result.deadFDs.append(fd); break
                            }
                        }
                        if totalRead > 0 {
                            result.zeroCopyReads.append((fd, totalRead))
                        }
                    } else {
                        // Fallback: recv into scratch buffer
                        while true {
                            let n = recvScratch.withUnsafeMutableBytes {
                                stats.recvCalls += 1
                                return Darwin.recv(fd, $0.baseAddress!, 65536, 0)
                            }
                            if n > 0 {
                                let off = result.streamDataBuffer.count
                                result.streamDataBuffer.append(contentsOf: recvScratch[0..<n])
                                result.streamReads.append((fd, off, n))
                            } else if n == 0 {
                                result.streamHangup.append(fd); break
                            } else {
                                if errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR { break }
                                if errno == ENOTCONN { isListener = true; break }
                                result.deadFDs.append(fd); break
                            }
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
                        var srcAddr = sockaddr_in()
                        var srcLen = socklen_t(MemoryLayout<sockaddr_in>.size)
                        let n = recvScratch.withUnsafeMutableBytes { ptr in
                            stats.recvfromCalls += 1
                            return withUnsafeMutablePointer(to: &srcAddr) {
                                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                                    Darwin.recvfrom(fd, ptr.baseAddress!, 65536, 0, $0, &srcLen)
                                }
                            }
                        }
                        if n > 0 {
                            result.datagramReads.append((fd, Array(recvScratch[0..<n]), srcAddr))
                        } else {
                            if n < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR {
                                result.deadFDs.append(fd)
                            }
                            break
                        }
                    }
                case .rawDatagram:
                    while true {
                        let n = recvScratch.withUnsafeMutableBytes {
                            Darwin.recvfrom(fd, $0.baseAddress!, 4096, 0, nil, nil)
                        }
                        if n > 0 {
                            result.rawDatagramReads.append((fd, Array(recvScratch[0..<n])))
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
                stats.recvmsgCalls += 1
                let (n, msgFlags) = withUnsafeMutablePointer(to: &iov) { iovPtr in
                    var msg = msghdr(msg_name: nil, msg_namelen: 0,
                                     msg_iov: iovPtr, msg_iovlen: 1,
                                     msg_control: nil, msg_controllen: 0, msg_flags: 0)
                    return (Darwin.recvmsg(fd, &msg, 0), msg.msg_flags)
                }
                if n <= 0 { break }
                if msgFlags & Int32(MSG_TRUNC) != 0 { continue }
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
                let iov0 = iovec(iov_base: UnsafeMutableRawPointer(mutating: hdrPtr), iov_len: hdrLen)
                let payBase = batch.payBase[i] ?? io.input.baseAddress!
                let payPtr = payBase + batch.payOfs[i]
                let iov1 = iovec(iov_base: UnsafeMutableRawPointer(mutating: payPtr), iov_len: batch.payLen[i])
                var iovs = (iov0, iov1)
                _ = withUnsafeMutableBytes(of: &iovs) { buf in
                    var msg = msghdr(msg_name: nil, msg_namelen: 0,
                                     msg_iov: buf.baseAddress!.assumingMemoryBound(to: iovec.self), msg_iovlen: 2,
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
                stats.sendmsgCalls += 1
                stats.sendBytes += UInt64(hdrLen)
                let r = withUnsafeMutablePointer(to: &iov) { iovPtr in
                    var msg = msghdr(msg_name: nil, msg_namelen: 0,
                                     msg_iov: iovPtr, msg_iovlen: 1,
                                     msg_control: nil, msg_controllen: 0, msg_flags: 0)
                    return Darwin.sendmsg(fd, &msg, Int32(MSG_DONTWAIT | MSG_NOSIGNAL))
                }
                if r < 0, errno != EAGAIN, errno != ENOBUFS {
                    fputs("[POLL-WRITE] sendmsg fd=\(fd) failed: errno=\(errno) hdrLen=\(hdrLen)\n", stderr)
                }
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
            let iov0 = iovec(iov_base: UnsafeMutableRawPointer(mutating: hdrPtr), iov_len: hdrLen)
            let iov1 = iovec(iov_base: UnsafeMutableRawPointer(mutating: payPtr), iov_len: payLen)
            var iovs = (iov0, iov1)
            var ok = false
            withUnsafeMutableBytes(of: &iovs) { buf in
                var msg = msghdr(msg_name: nil, msg_namelen: 0,
                                 msg_iov: buf.baseAddress!.assumingMemoryBound(to: iovec.self), msg_iovlen: 2,
                                 msg_control: nil, msg_controllen: 0, msg_flags: 0)
                stats.sendmsgCalls += 1
                stats.sendBytes += UInt64(hdrLen + payLen)
                ok = Darwin.sendmsg(fd, &msg, Int32(MSG_DONTWAIT | MSG_NOSIGNAL)) >= 0
            }
            return ok
        } else {
            var iov = iovec(iov_base: UnsafeMutableRawPointer(mutating: hdrPtr), iov_len: hdrLen)
            stats.sendmsgCalls += 1
            stats.sendBytes += UInt64(hdrLen)
            return withUnsafeMutablePointer(to: &iov) { iovPtr in
                var msg = msghdr(msg_name: nil, msg_namelen: 0,
                                 msg_iov: iovPtr, msg_iovlen: 1,
                                 msg_control: nil, msg_controllen: 0, msg_flags: 0)
                return Darwin.sendmsg(fd, &msg, Int32(MSG_DONTWAIT | MSG_NOSIGNAL)) >= 0
            }
        }
    }

    // MARK: - Write (external FDs)

    @discardableResult
    public mutating func writeStream(_ ptr: UnsafeRawPointer, _ len: Int, to fd: Int32) -> Int {
        guard len > 0 else { return 0 }
        stats.sendmsgCalls += 1
        stats.sendBytes += UInt64(len)
        return Darwin.send(fd, ptr, len, Int32(MSG_NOSIGNAL))
    }

    @discardableResult
    public mutating func writeDatagram(_ ptr: UnsafeRawPointer, _ len: Int, to fd: Int32, addr: sockaddr_in) -> Int {
        guard len > 0 else { return 0 }
        var sa = addr
        stats.sendmsgCalls += 1
        stats.sendBytes += UInt64(len)
        var iov = iovec(iov_base: UnsafeMutableRawPointer(mutating: ptr), iov_len: len)
        return withUnsafeMutableBytes(of: &sa) { saBuf in
            withUnsafeMutablePointer(to: &iov) { iovPtr in
                var msg = msghdr(
                    msg_name: saBuf.baseAddress, msg_namelen: socklen_t(MemoryLayout<sockaddr_in>.size),
                    msg_iov: iovPtr, msg_iovlen: 1,
                    msg_control: nil, msg_controllen: 0, msg_flags: 0
                )
                return Darwin.sendmsg(fd, &msg, Int32(MSG_NOSIGNAL))
            }
        }
    }

    @discardableResult
    public mutating func writeDatagram(_ ptr: UnsafeRawPointer, _ len: Int, to fd: Int32) -> Int {
        guard len > 0 else { return 0 }
        stats.sendmsgCalls += 1
        stats.sendBytes += UInt64(len)
        return Darwin.send(fd, ptr, len, Int32(MSG_NOSIGNAL))
    }
}
