import Foundation
import Darwin

// MARK: - NAT Entry

final class NATEntry {
    let key: Tuple
    let extIP: UInt32
    let extPort: UInt16

    var hostFD: Int32 = -1
    var hostClosed: Bool = false
    var vmClosed: Bool = false
    var deferredClose: Bool = false

    weak var vmConn: TCPConn?

    init(key: Tuple, extIP: UInt32, extPort: UInt16) {
        self.key = key
        self.extIP = extIP
        self.extPort = extPort
    }
}

// MARK: - Pending Dial

final class PendingDial: @unchecked Sendable {
    let entry: NATEntry
    let seg: TCPSegment
    var result: (fd: Int32, error: Error?)?

    init(entry: NATEntry, seg: TCPSegment) {
        self.entry = entry
        self.seg = seg
    }
}

// MARK: - NAT Table

final class NATTable {
    var entries: [Tuple: NATEntry] = [:]
    var pendingDials: [PendingDial] = []
    var tcpState: TCPState?
    let hostBuf: [UInt8]

    init() {
        hostBuf = [UInt8](repeating: 0, count: 262144)
    }

    func intercept(_ seg: TCPSegment, tcpState: TCPState) -> Bool {
        self.tcpState = tcpState
        let tuple = seg.tuple.reversed()

        if let entry = entries[tuple] {
            entry.vmConn?.pendingSegs.append(seg)
            return true
        }

        if seg.header.isSYN() && !seg.header.isACK() {
            let entry = NATEntry(key: tuple, extIP: seg.tuple.dstIP, extPort: seg.tuple.dstPort)
            entry.vmConn = tcpState.createExternalConn(tuple: tuple, irs: seg.header.seqNum,
                                                         window: seg.header.windowSize, rawSeg: seg.raw)
            entries[tuple] = entry
            pendingDials.append(PendingDial(entry: entry, seg: seg))
            return true
        }

        return false
    }

    // MARK: - Poll Dials

    func pollDials() {
        var remaining: [PendingDial] = []
        for pd in pendingDials {
            if pd.result == nil {
                startDial(pd)
            }
            if let result = pd.result {
                if let error = result.error {
                    NSLog("NAT: dial %@:%d failed: %@",
                          ipString(pd.entry.extIP), pd.entry.extPort, error.localizedDescription)
                    pd.entry.vmClosed = true
                } else {
                    pd.entry.hostFD = result.fd
                }
            } else {
                remaining.append(pd)
            }
        }
        pendingDials = remaining
    }

    private func startDial(_ pd: PendingDial) {
        let addr = "\(ipString(pd.entry.extIP)):\(pd.entry.extPort)"
        let capturePD = pd
        Task { @Sendable in
            let result = await NATTable.doDial(addr: addr)
            capturePD.result = result
        }
    }

    private static func doDial(addr: String) async -> (fd: Int32, error: Error?)? {
        let parts = addr.split(separator: ":")
        guard parts.count == 2, let port = UInt16(parts[1]) else { return nil }
        let host = String(parts[0])

        return await withCheckedContinuation { continuation in
            DispatchQueue.global().async {
                var hints = addrinfo()
                hints.ai_family = AF_INET
                hints.ai_socktype = SOCK_STREAM

                var result: UnsafeMutablePointer<addrinfo>?
                let err = getaddrinfo(host, String(port), &hints, &result)
                guard err == 0, let info = result else {
                    continuation.resume(returning: (fd: -1, error: nil))
                    return
                }
                defer { freeaddrinfo(result) }

                let fd = socket(info.pointee.ai_family, info.pointee.ai_socktype, info.pointee.ai_protocol)
                guard fd >= 0 else {
                    continuation.resume(returning: (fd: -1, error: nil))
                    return
                }

                // Set send timeout for blocking connect
                var tv = timeval(tv_sec: 30, tv_usec: 0)
                setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))

                let connectResult = connect(fd, info.pointee.ai_addr, info.pointee.ai_addrlen)
                if connectResult < 0 {
                    let savedErrno = errno
                    close(fd)
                    continuation.resume(returning: (fd: -1, error: NSError(domain: NSPOSIXErrorDomain, code: Int(savedErrno))))
                    return
                }

                // Set non-blocking after connect
                let flags = fcntl(fd, F_GETFL, 0)
                _ = fcntl(fd, F_SETFL, flags | O_NONBLOCK)

                // Reset socket timeout to 0 (no timeout)
                var noTimeout = timeval(tv_sec: 0, tv_usec: 0)
                setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &noTimeout, socklen_t(MemoryLayout<timeval>.size))

                continuation.resume(returning: (fd: fd, error: nil))
            }
        }
    }

    // MARK: - Poll Reads

    func pollReads() {
        for (_, entry) in entries {
            guard entry.hostFD >= 0, !entry.hostClosed else {
                if entry.hostClosed && entry.deferredClose, let conn = entry.vmConn, conn.sendAvail == 0 {
                    entry.deferredClose = false
                    if let ts = tcpState { ts.appClose(tuple: conn.tuple) }
                }
                continue
            }
            readHost(entry)
        }
    }

    func poll() {
        pollDials()
        pollReads()
    }

    // MARK: - Proxy VM → Host

    func proxyVMToHost() {
        for (_, entry) in entries {
            guard entry.hostFD >= 0, !entry.hostClosed, let conn = entry.vmConn else { continue }
            writeHost(entry)
        }
    }

    // MARK: - Cleanup

    func cleanup() {
        for (key, entry) in entries {
            if !entry.vmClosed, let conn = entry.vmConn, conn.isFinReceived() {
                entry.vmClosed = true
            }
            if entry.hostClosed && entry.vmClosed {
                if entry.hostFD >= 0 { close(entry.hostFD) }
                entries[key] = nil
            }
        }
    }

    func count() -> Int { entries.count }

    // MARK: - Host I/O

    private func readHost(_ entry: NATEntry) {
        guard let conn = entry.vmConn else { return }

        let space = conn.sendSpace
        if space == 0 { return }

        var buf = hostBuf
        if space < buf.count { buf = Array(buf[0..<space]) }

        let bufCount = buf.count
        let n = buf.withUnsafeMutableBytes { ptr in
            Darwin.read(entry.hostFD, ptr.baseAddress!, bufCount)
        }

        if n < 0 {
            if errno == EAGAIN || errno == EWOULDBLOCK { return }
            entry.hostClosed = true
            maybeClose(entry)
            return
        }
        if n == 0 {
            entry.hostClosed = true
            maybeClose(entry)
            return
        }

        _ = conn.writeSendBuf(Array(buf[0..<n]))
    }

    private func maybeClose(_ entry: NATEntry) {
        guard let conn = entry.vmConn else { return }
        if conn.sendAvail > 0 {
            entry.deferredClose = true
            return
        }
        tcpState?.appClose(tuple: conn.tuple)
    }

    private func writeHost(_ entry: NATEntry) {
        guard let conn = entry.vmConn else { return }
        let data = conn.peekRecvData()
        guard !data.isEmpty else { return }

        let n = data.withUnsafeBytes { ptr in
            Darwin.write(entry.hostFD, ptr.baseAddress!, data.count)
        }

        if n > 0 {
            conn.consumeRecvData(n)
        }
        if n < 0 {
            entry.hostClosed = true
            return
        }
        if n == data.count && conn.recvAvail > 0 {
            let more = conn.peekRecvData()
            if !more.isEmpty {
                let n2 = more.withUnsafeBytes { ptr in
                    Darwin.write(entry.hostFD, ptr.baseAddress!, more.count)
                }
                if n2 > 0 { conn.consumeRecvData(n2) }
                if n2 < 0 { entry.hostClosed = true }
            }
        }
    }
}
