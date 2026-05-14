import Darwin

/// Set O_NONBLOCK on a socket file descriptor.
func setNonBlocking(_ fd: Int32) {
    let flags = fcntl(fd, F_GETFL, 0)
    if flags >= 0 { _ = fcntl(fd, F_SETFL, flags | O_NONBLOCK) }
}

/// Set SO_SNDBUF and SO_RCVBUF on an external-facing socket.
/// Larger buffers absorb TCP recovery bursts from lossy links,
/// preventing receive-window collapse under chaos.
func setSocketBuffers(_ fd: Int32, sndBytes: Int = 1_048_576, rcvBytes: Int = 4_194_304) {
    var s = sndBytes
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &s, socklen_t(MemoryLayout<Int>.size))
    var r = rcvBytes
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &r, socklen_t(MemoryLayout<Int>.size))
}

/// Create a pair of connected AF_UNIX SOCK_DGRAM sockets, both non-blocking.
public func makeSocketPair() -> (Int32, Int32) {
    var fds: [Int32] = [0, 0]
    guard socketpair(AF_UNIX, SOCK_DGRAM, 0, &fds) == 0 else {
        fatalError("socketpair: \(String(cString: strerror(errno)))")
    }
    for fd in fds {
        setNonBlocking(fd)
    }
    return (fds[0], fds[1])
}
