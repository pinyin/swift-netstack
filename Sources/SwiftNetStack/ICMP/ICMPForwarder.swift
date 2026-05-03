import Foundation
import Darwin

// MARK: - ICMP Reply

struct ICMPReply {
    let srcIP: UInt32
    let dstIP: UInt32
    let id: UInt16
    let seq: UInt16
    let payload: [UInt8]
}

// MARK: - ICMP Forwarder

final class ICMPForwarder {
    private var sockFD: Int32 = -1
    private var pending: [UInt32: (srcIP: UInt32, dstIP: UInt32, id: UInt16, seq: UInt16, createdAt: Date)] = [:]
    private var replies: [ICMPReply] = []

    init?() {
        let fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP)
        guard fd >= 0 else { return nil }

        var flags = fcntl(fd, F_GETFL, 0)
        _ = fcntl(fd, F_SETFL, flags | O_NONBLOCK)

        // Set receive timeout for non-blocking behavior
        var tv = timeval(tv_sec: 0, tv_usec: 100)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))

        self.sockFD = fd
    }

    deinit {
        if sockFD >= 0 { close(sockFD) }
    }

    // MARK: - Forward

    func forward(srcIP: UInt32, dstIP: UInt32, id: UInt16, seq: UInt16, payload: [UInt8]) {
        let icmpData = buildICMPEchoRequest(id: id, seq: seq, payload: payload)

        var dst = sockaddr_in()
        dst.sin_family = sa_family_t(AF_INET)
        dst.sin_addr.s_addr = dstIP.bigEndian

        icmpData.withUnsafeBytes { buf in
            withUnsafePointer(to: &dst) { ptr in
                ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                    _ = sendto(sockFD, buf.baseAddress!, icmpData.count, 0,
                              sockPtr, socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }
        }

        let key = (UInt32(id) << 16) | UInt32(seq)
        pending[key] = (srcIP, dstIP, id, seq, Date())
    }

    // MARK: - Poll

    func poll() {
        var buf = [UInt8](repeating: 0, count: 1500)
        let bufSize = buf.count

        while true {
            let n = buf.withUnsafeMutableBytes { ptr in
                recvfrom(sockFD, ptr.baseAddress!, bufSize, 0, nil, nil)
            }

            if n < 0 {
                if errno == EAGAIN || errno == EWOULDBLOCK { break }
                break // real error, stop polling
            }

            // On macOS, SOCK_DGRAM+IPPROTO_ICMP returns the full IP header.
            // Parse the IP header length (IHL) to find where the ICMP header begins.
            let ipHdrLen = Int(buf[0] & 0x0F) * 4
            guard ipHdrLen >= 20, n >= ipHdrLen + 8 else { continue }

            let icmpType = buf[ipHdrLen]
            guard icmpType == 0 else { continue } // Echo Reply (type 0)

            let id = UInt16(buf[ipHdrLen + 4]) << 8 | UInt16(buf[ipHdrLen + 5])
            let seq = UInt16(buf[ipHdrLen + 6]) << 8 | UInt16(buf[ipHdrLen + 7])

            let key = (UInt32(id) << 16) | UInt32(seq)
            guard let p = pending[key] else { continue }
            pending[key] = nil

            let payloadStart = ipHdrLen + 8
            let payloadLen = n - payloadStart
            let payload = payloadLen > 0 ? Array(buf[payloadStart..<n]) : []

            replies.append(ICMPReply(
                srcIP: p.dstIP, dstIP: p.srcIP,
                id: p.id, seq: p.seq, payload: payload
            ))
        }
    }

    func consumeReplies() -> [ICMPReply] {
        let out = replies
        replies = []
        return out
    }

    func cleanup(timeout: TimeInterval) {
        let now = Date()
        for (key, p) in pending {
            if now.timeIntervalSince(p.createdAt) > timeout {
                pending[key] = nil
            }
        }
    }
}

// MARK: - Build ICMP Echo Request

func buildICMPEchoRequest(id: UInt16, seq: UInt16, payload: [UInt8]) -> [UInt8] {
    var buf = [UInt8](repeating: 0, count: 8 + payload.count)
    buf[0] = 8 // Echo Request
    buf[1] = 0 // Code
    // buf[2..<4] = checksum (computed below)
    buf[4] = UInt8(id >> 8); buf[5] = UInt8(id & 0xFF)
    buf[6] = UInt8(seq >> 8); buf[7] = UInt8(seq & 0xFF)
    for i in 0..<payload.count { buf[8 + i] = payload[i] }

    let cs = ipChecksum(buf)
    buf[2] = UInt8(cs >> 8); buf[3] = UInt8(cs & 0xFF)
    return buf
}

func buildICMPReplyData(id: UInt16, seq: UInt16, payload: [UInt8]) -> [UInt8] {
    var buf = [UInt8](repeating: 0, count: 8 + payload.count)
    buf[0] = 0 // Echo Reply
    buf[1] = 0 // Code
    buf[4] = UInt8(id >> 8); buf[5] = UInt8(id & 0xFF)
    buf[6] = UInt8(seq >> 8); buf[7] = UInt8(seq & 0xFF)
    for i in 0..<payload.count { buf[8 + i] = payload[i] }

    let cs = ipChecksum(buf)
    buf[2] = UInt8(cs >> 8); buf[3] = UInt8(cs & 0xFF)
    return buf
}
