import Foundation
import Darwin
@testable import SwiftNetStack

// MARK: - TCP Echo Server for NAT testing

/// A background TCP echo server that accepts one connection,
/// echoes all received data, waits for EOF, then closes.
/// Runs on a Foundation `Thread` (blocking I/O).
final class TCPEchoServer {
    let port: UInt16
    private let serverFD: Int32
    private var receivedData: [UInt8] = []
    private var eofSeen = false
    private var finished = false
    private let lock = NSLock()

    /// Try to create an echo server, retrying up to 3 times with increasing delays
    /// if the OS is temporarily out of resources (e.g. ephemeral ports in TIME_WAIT).
    static func make() -> TCPEchoServer? {
        for attempt in 0..<3 {
            if let server = TCPEchoServer() { return server }
            if attempt < 2 { Thread.sleep(forTimeInterval: Double(attempt + 1) * 0.05) }
        }
        return nil
    }

    private init?() {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else {
            fputs("TCPEchoServer: socket() failed: \(errno) \(String(cString: strerror(errno)))\n", stderr)
            return nil
        }

        var reuse: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, socklen_t(MemoryLayout<Int32>.size))

        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = 0
        addr.sin_addr.s_addr = INADDR_ANY.bigEndian

        let bound = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard bound >= 0 else {
            fputs("TCPEchoServer: bind() failed: \(errno) \(String(cString: strerror(errno)))\n", stderr)
            close(fd); return nil
        }
        guard Darwin.listen(fd, 1) >= 0 else {
            fputs("TCPEchoServer: listen() failed: \(errno) \(String(cString: strerror(errno)))\n", stderr)
            close(fd); return nil
        }

        var boundAddr = sockaddr_in()
        var len = socklen_t(MemoryLayout<sockaddr_in>.size)
        withUnsafeMutablePointer(to: &boundAddr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &len) }
        }

        self.serverFD = fd
        self.port = boundAddr.sin_port.bigEndian

        // Strong self keeps the server alive until the thread exits.
        Thread.detachNewThread { [self] in
            run()
        }
    }

    private func run() {
        defer { close(serverFD) }

        var clientAddr = sockaddr_in()
        var addrLen = socklen_t(MemoryLayout<sockaddr_in>.size)
        let conn = withUnsafeMutablePointer(to: &clientAddr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.accept(serverFD, $0, &addrLen)
            }
        }
        guard conn >= 0 else {
            lock.lock(); finished = true; lock.unlock()
            return
        }

        var buf = [UInt8](repeating: 0, count: 65536)
        var allData: [UInt8] = []

        // Read first batch
        let nr = Darwin.read(conn, &buf, buf.count)
        if nr > 0 {
            allData = Array(buf[0..<nr])
            // Echo back
            _ = Darwin.write(conn, allData, allData.count)
        }

        // Read more until EOF
        while true {
            let n = Darwin.read(conn, &buf, buf.count)
            if n > 0 {
                allData.append(contentsOf: buf[0..<n])
                _ = Darwin.write(conn, buf, n)
            } else if n == 0 {
                lock.lock()
                eofSeen = true
                lock.unlock()
                break
            } else {
                break
            }
        }
        close(conn)

        lock.lock()
        receivedData = allData
        finished = true
        lock.unlock()
    }

    var data: [UInt8] {
        lock.lock(); defer { lock.unlock() }
        return receivedData
    }

    var isFinished: Bool {
        lock.lock(); defer { lock.unlock() }
        return finished
    }

    var sawEOF: Bool {
        lock.lock(); defer { lock.unlock() }
        return eofSeen
    }

    func waitDone(timeout: TimeInterval = 5.0) {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if isFinished { return }
            Thread.sleep(forTimeInterval: 0.01)
        }
    }

    deinit {
        // serverFD lifetime is managed by the background thread's defer block.
        // shutdown unblocks a stuck accept() so the thread can exit cleanly.
        shutdown(serverFD, SHUT_RDWR)
    }
}
