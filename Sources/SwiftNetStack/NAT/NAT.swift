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

    // Strong reference: TCPConn lifetime is tied to NAT entry, not just TCPState dictionaries.
    var vmConn: TCPConn?

    init(key: Tuple, extIP: UInt32, extPort: UInt16) {
        self.key = key
        self.extIP = extIP
        self.extPort = extPort
    }
}

// MARK: - Pending Dial

final class PendingDial {
    let entry: NATEntry
    let seg: TCPSegment
    var result: (fd: Int32, error: Error?)?
    var connectFD: Int32 = -1

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
    var hostBuf: [UInt8]

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

    // MARK: - Poll Dials (non-blocking connect)

    func pollDials() {
        var remaining: [PendingDial] = []

        for pd in pendingDials {
            // Start dial if not yet initiated
            if pd.connectFD < 0 && pd.result == nil {
                startDial(pd)
            }

            // Check non-blocking connect status
            if pd.connectFD >= 0 && pd.result == nil {
                var err: Int32 = 0
                var len = socklen_t(MemoryLayout<Int32>.size)
                let ret = getsockopt(pd.connectFD, SOL_SOCKET, SO_ERROR, &err, &len)
                if ret == 0 && err == 0 {
                    // Connect succeeded
                    pd.result = (fd: pd.connectFD, error: nil)
                } else if ret < 0 || (err != 0 && err != EINPROGRESS) {
                    // Connect failed
                    close(pd.connectFD)
                    let code = err != 0 ? err : Int32(ret)
                    pd.result = (fd: -1, error: NSError(domain: NSPOSIXErrorDomain, code: Int(code)))
                }
                // else: still EINPROGRESS, keep polling
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
        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_addr.s_addr = pd.entry.extIP.bigEndian
        addr.sin_port = pd.entry.extPort.bigEndian

        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else {
            pd.result = (fd: -1, error: NSError(domain: NSPOSIXErrorDomain, code: Int(errno)))
            return
        }

        // Set non-blocking for EINPROGRESS connect
        let flags = fcntl(fd, F_GETFL, 0)
        _ = fcntl(fd, F_SETFL, flags | O_NONBLOCK)

        let ret = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                connect(fd, sockPtr, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }

        if ret < 0 && errno != EINPROGRESS {
            let savedErrno = errno
            close(fd)
            pd.result = (fd: -1, error: NSError(domain: NSPOSIXErrorDomain, code: Int(savedErrno)))
            return
        }

        pd.connectFD = fd
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
            guard entry.hostFD >= 0, !entry.hostClosed, entry.vmConn != nil else { continue }
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

        let readMax = min(space, hostBuf.count)
        let n = hostBuf.withUnsafeMutableBytes { ptr in
            Darwin.read(entry.hostFD, ptr.baseAddress!, readMax)
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

        _ = hostBuf.withUnsafeBytes { ptr in
            conn.writeSendBuf(ptr: ptr.baseAddress!, count: n)
        }
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
            if errno == EAGAIN || errno == EWOULDBLOCK { return }
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
                if n2 < 0 {
                    if errno == EAGAIN || errno == EWOULDBLOCK { return }
                    entry.hostClosed = true
                }
            }
        }
    }
}
