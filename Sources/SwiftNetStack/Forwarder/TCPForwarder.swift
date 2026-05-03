import Foundation
import Darwin

// MARK: - Forwarder Entry

final class ForwarderEntry {
    var hostFD: Int32 = -1
    var vmConn: TCPConn?
    let vmAddr: String
    var hostClosed: Bool = false
    var vmClosed: Bool = false
    var deferredClose: Bool = false

    init(vmAddr: String) {
        self.vmAddr = vmAddr
    }
}

// MARK: - Forwarder Mapping

public struct ForwarderMapping {
    public let hostPort: UInt16
    public let vmIP: UInt32
    public let vmPort: UInt16

    public init(hostPort: UInt16, vmIP: UInt32, vmPort: UInt16) {
        self.hostPort = hostPort
        self.vmIP = vmIP
        self.vmPort = vmPort
    }
}

// MARK: - Forwarder

final class Forwarder {
    let gatewayIP: UInt32
    var mappings: [UInt16: ForwarderMapping] = [:]
    var listeners: [UInt16: Int32] = [:]
    var entries: [Int32: ForwarderEntry] = [:]
    var nextPort: UInt32 = 0
    var tcpState: TCPState?
    let hostBuf: [UInt8]

    init(gatewayIP: UInt32, mappings: [ForwarderMapping]) {
        self.gatewayIP = gatewayIP
        self.hostBuf = [UInt8](repeating: 0, count: 262144)

        for m in mappings {
            self.mappings[m.hostPort] = m
            let fd = setupListener(m.hostPort)
            if fd >= 0 {
                listeners[m.hostPort] = fd
            }
        }
    }

    private func setupListener(_ port: UInt16) -> Int32 {
        var hints = addrinfo()
        hints.ai_family = AF_INET
        hints.ai_socktype = SOCK_STREAM
        hints.ai_flags = AI_PASSIVE

        var result: UnsafeMutablePointer<addrinfo>?
        let err = getaddrinfo(nil, String(port), &hints, &result)
        guard err == 0, let info = result else { return -1 }
        defer { freeaddrinfo(result) }

        let fd = socket(info.pointee.ai_family, info.pointee.ai_socktype, info.pointee.ai_protocol)
        guard fd >= 0 else { return -1 }

        var on: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, socklen_t(MemoryLayout<Int32>.size))

        var flags = fcntl(fd, F_GETFL, 0)
        _ = fcntl(fd, F_SETFL, flags | O_NONBLOCK)

        guard bind(fd, info.pointee.ai_addr, info.pointee.ai_addrlen) >= 0 else {
            close(fd)
            return -1
        }
        guard listen(fd, 128) >= 0 else {
            close(fd)
            return -1
        }

        return fd
    }

    // MARK: - Poll Accept

    func pollAccept(tcpState: TCPState) {
        self.tcpState = tcpState
        for (hostPort, fd) in listeners {
            while true {
                var addr = sockaddr_in()
                var addrLen = socklen_t(MemoryLayout<sockaddr_in>.size)
                let clientFD = withUnsafeMutablePointer(to: &addr) { ptr in
                    ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockAddrPtr in
                        accept(fd, sockAddrPtr, &addrLen)
                    }
                }

                guard clientFD >= 0 else { break }

                var flags = fcntl(clientFD, F_GETFL, 0)
                _ = fcntl(clientFD, F_SETFL, flags | O_NONBLOCK)

                guard let (vmTuple, vmAddr) = createVMTuple(hostPort: hostPort) else {
                    close(clientFD)
                    continue
                }

                let vmConn = tcpState.activeOpen(tuple: vmTuple, vmWindow: 65535)
                let entry = ForwarderEntry(vmAddr: vmAddr)
                entry.hostFD = clientFD
                entry.vmConn = vmConn
                entries[clientFD] = entry
            }
        }
    }

    func poll() {
        for (_, entry) in entries {
            guard entry.hostFD >= 0 else { continue }
            if entry.hostClosed {
                if entry.deferredClose, let conn = entry.vmConn, conn.sendAvail == 0 {
                    entry.deferredClose = false
                    tcpState?.appClose(tuple: conn.tuple)
                }
                if !entry.deferredClose, !entry.vmClosed, let conn = entry.vmConn {
                    tcpState?.appClose(tuple: conn.tuple)
                }
                continue
            }
            readHost(entry)
        }
    }

    func proxyVMToHost() {
        for (_, entry) in entries {
            guard !entry.hostClosed, let conn = entry.vmConn else { continue }
            writeHost(entry)
        }
    }

    func cleanup() {
        for (fd, entry) in entries {
            if !entry.vmClosed, let conn = entry.vmConn, conn.isFinReceived() {
                entry.vmClosed = true
            }
            if !entry.vmClosed, let conn = entry.vmConn, entry.hostClosed, let ts = tcpState {
                if !ts.hasConn(conn.tuple) { entry.vmClosed = true }
            }
            if entry.hostClosed && entry.vmClosed {
                if entry.hostFD >= 0 { close(entry.hostFD) }
                entries[fd] = nil
            }
        }
    }

    func count() -> Int { entries.count }

    // MARK: - VM Tuple

    private func createVMTuple(hostPort: UInt16) -> (Tuple, String)? {
        guard let m = mappings[hostPort] else { return nil }
        nextPort = nextPort &+ 1
        let gwPort = UInt16(32768 + (nextPort % 28231))
        let vmAddr = "\(ipString(m.vmIP)):\(m.vmPort)"
        let tuple = Tuple(srcIP: gatewayIP, dstIP: m.vmIP, srcPort: gwPort, dstPort: m.vmPort)
        return (tuple, vmAddr)
    }

    // MARK: - I/O

    private func readHost(_ entry: ForwarderEntry) {
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

    private func maybeClose(_ entry: ForwarderEntry) {
        guard let conn = entry.vmConn else { return }
        if conn.sendAvail > 0 {
            entry.deferredClose = true
            return
        }
        tcpState?.appClose(tuple: conn.tuple)
    }

    private func writeHost(_ entry: ForwarderEntry) {
        guard let conn = entry.vmConn else { return }
        let data = conn.peekRecvData()
        guard !data.isEmpty else { return }

        let n = data.withUnsafeBytes { ptr in
            Darwin.write(entry.hostFD, ptr.baseAddress!, data.count)
        }

        if n > 0 { conn.consumeRecvData(n) }
        if n < 0 { entry.hostClosed = true; return }

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
