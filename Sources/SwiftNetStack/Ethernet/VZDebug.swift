import Foundation
import Darwin

// MARK: - VZDebug Connection

public final class VZDebugConn {
    private let fd: Int32
    private var buf: [UInt8]
    private var firstFrame: Frame?

    public convenience init(fd: Int32) {
        self.init(fd: fd, firstFrame: nil)
    }

    init(fd: Int32, firstFrame: Frame? = nil) {
        self.fd = fd
        self.buf = [UInt8](repeating: 0, count: 65536)
        self.firstFrame = firstFrame
    }

    deinit {
        close(fd)
    }

    // MARK: - Listen

    static func listen(socketPath: String) -> VZDebugConn? {
        unlink(socketPath)

        let fd = socket(AF_UNIX, SOCK_DGRAM, 0)
        guard fd >= 0 else { return nil }

        // Set buffer sizes: 1MB send, 4MB recv
        var sndBuf: Int32 = 1 * 1024 * 1024
        var rcvBuf: Int32 = 4 * 1024 * 1024
        setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndBuf, socklen_t(MemoryLayout<Int32>.size))
        setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvBuf, socklen_t(MemoryLayout<Int32>.size))

        // Keep blocking for initial VFKT handshake (vz-debug connects after we bind)

        // Bind
        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        socketPath.utf8CString.withUnsafeBytes { ptr in
            let count = min(ptr.count, MemoryLayout.size(ofValue: addr.sun_path))
            withUnsafeMutableBytes(of: &addr.sun_path) { pathPtr in
                pathPtr.copyMemory(from: UnsafeRawBufferPointer(rebasing: ptr[0..<count]))
            }
        }
        let addrLen = socklen_t(MemoryLayout<sockaddr_un>.size)

        let bindResult = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                Darwin.bind(fd, sockPtr, addrLen)
            }
        }
        guard bindResult >= 0 else {
            close(fd)
            return nil
        }

        // Read first datagram to discover remote address
        var readBuf = [UInt8](repeating: 0, count: 65536)
        var remoteAddr = sockaddr_un()
        var remoteAddrLen = socklen_t(MemoryLayout<sockaddr_un>.size)

        let n = withUnsafeMutablePointer(to: &remoteAddr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                recvfrom(fd, &readBuf, readBuf.count, 0, sockPtr, &remoteAddrLen)
            }
        }

        guard n >= 0 else {
            close(fd)
            return nil
        }

        // Check for VFKT handshake
        if n >= 4, String(bytes: readBuf[0..<4], encoding: .utf8) == "VFKT" {
            // Read next datagram
            let n2 = withUnsafeMutablePointer(to: &remoteAddr) { ptr in
                ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                    recvfrom(fd, &readBuf, readBuf.count, 0, sockPtr, &remoteAddrLen)
                }
            }
            guard n2 >= 0 else {
                close(fd)
                return nil
            }
            readBuf = Array(readBuf[0..<n2])
        } else {
            readBuf = Array(readBuf[0..<n])
        }

        // Connect to remote address for bidirectional datagram I/O
        let connectResult = withUnsafePointer(to: &remoteAddr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                Darwin.connect(fd, sockPtr, remoteAddrLen)
            }
        }
        if connectResult < 0 {
            close(fd)
            return nil
        }

        // Set non-blocking now that handshake is complete
        let flags = fcntl(fd, F_GETFL, 0)
        _ = fcntl(fd, F_SETFL, flags | O_NONBLOCK)

        let firstFrame = Frame.parse(readBuf)
        return VZDebugConn(fd: fd, firstFrame: firstFrame)
    }

    // MARK: - Read/Write

    func readFrame() -> Frame? {
        if let f = firstFrame {
            firstFrame = nil
            return f
        }

        let n = Darwin.read(fd, &buf, buf.count)
        if n < 0 {
            if errno == EAGAIN || errno == EWOULDBLOCK { return nil }
            return nil
        }
        if n == 0 { return nil }

        // One copy into Data; downstream parsing uses zero-copy Data slices
        let frameData = Data(bytes: buf, count: n)
        return Frame.parse(frameData)
    }

    func readAllFrames() -> [Frame] {
        var frames: [Frame] = []
        while let frame = readFrame() {
            frames.append(frame)
        }
        return frames
    }

    func write(frame: Frame) -> Error? {
        let data = frame.serialize()
        let result = data.withUnsafeBytes { ptr in
            Darwin.write(fd, ptr.baseAddress!, data.count)
        }
        if result < 0 {
            return NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
        }
        return nil
    }

    func write(netBuf: NetBuf) -> Error? {
        return netBuf.withUnsafeReadableBytes { ptr in
            guard let base = ptr.baseAddress else {
                return NSError(domain: NSPOSIXErrorDomain, code: Int(ENOMEM))
            }
            let result = Darwin.write(fd, base, netBuf.length)
            if result < 0 {
                return NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
            }
            return nil
        }
    }

    // MARK: - Poll

    /// Wait for readable data on the socket.
    /// - Parameter timeout: seconds to wait; 0 = non-blocking check.
    /// - Returns: true if data is available to read, false on timeout.
    func waitForData(timeout: TimeInterval) -> Bool {
        var pfd = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
        let timeoutMs = Int32(timeout * 1000)
        let ret = poll(&pfd, 1, timeoutMs)
        return ret > 0 && (pfd.revents & Int16(POLLIN)) != 0
    }

    // MARK: - Loopback for Testing

    static func newLoopbackPair() -> (VZDebugConn, VZDebugConn)? {
        var fds: [Int32] = [0, 0]
        let result = socketpair(AF_UNIX, SOCK_DGRAM, 0, &fds)
        guard result >= 0 else { return nil }

        // Increase socket buffer sizes to handle batch testing without ENOBUFS
        var bufSize: Int32 = 4_194_304  // 4 MB
        _ = setsockopt(fds[0], SOL_SOCKET, SO_SNDBUF, &bufSize, socklen_t(MemoryLayout<Int32>.size))
        _ = setsockopt(fds[0], SOL_SOCKET, SO_RCVBUF, &bufSize, socklen_t(MemoryLayout<Int32>.size))
        _ = setsockopt(fds[1], SOL_SOCKET, SO_SNDBUF, &bufSize, socklen_t(MemoryLayout<Int32>.size))
        _ = setsockopt(fds[1], SOL_SOCKET, SO_RCVBUF, &bufSize, socklen_t(MemoryLayout<Int32>.size))

        let flags0 = fcntl(fds[0], F_GETFL, 0)
        _ = fcntl(fds[0], F_SETFL, flags0 | O_NONBLOCK)

        let flags1 = fcntl(fds[1], F_GETFL, 0)
        _ = fcntl(fds[1], F_SETFL, flags1 | O_NONBLOCK)

        let a = VZDebugConn(fd: fds[0])
        let b = VZDebugConn(fd: fds[1])
        return (a, b)
    }
}
