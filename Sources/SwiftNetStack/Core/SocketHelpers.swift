import Darwin

/// Set O_NONBLOCK on a socket file descriptor.
func setNonBlocking(_ fd: Int32) {
    let flags = fcntl(fd, F_GETFL, 0)
    if flags >= 0 { _ = fcntl(fd, F_SETFL, flags | O_NONBLOCK) }
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
