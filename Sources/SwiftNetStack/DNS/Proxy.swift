import Foundation
import Darwin

let dnsPort: UInt16 = 53

// MARK: - Pending DNS Query

private final class PendingDNSQuery {
    let srcIP: UInt32
    let dstIP: UInt32
    let srcPort: UInt16
    let dstPort: UInt16
    let query: Data
    var fd: Int32 = -1
    var sentAt: Date = Date()

    init(srcIP: UInt32, dstIP: UInt32, srcPort: UInt16, dstPort: UInt16, query: Data) {
        self.srcIP = srcIP
        self.dstIP = dstIP
        self.srcPort = srcPort
        self.dstPort = dstPort
        self.query = query
    }
}

// MARK: - DNS Proxy

final class DNSProxy {
    private(set) var upstream: String
    let listenIP: UInt32

    private var nextID: UInt64 = 0
    private var pendingQueries: [UInt64: PendingDNSQuery] = [:]
    private var ready: [UDPDatagram] = []
    private var inFlightIDs: Set<UInt64> = []

    // Pre-resolved upstream sockaddr for non-blocking sendto
    private var upstreamAddr: sockaddr_in?

    init(listenIP: UInt32, upstreamAddr: String) {
        self.listenIP = listenIP
        if !upstreamAddr.isEmpty {
            self.upstream = upstreamAddr
        } else {
            self.upstream = DNSProxy.readSystemDNS()
        }
        resolveUpstreamAddr()
    }

    func handler() -> UDPHandler {
        return { [weak self] dg in
            self?.enqueue(dg)
            return []
        }
    }

    func set(upstream addr: String) {
        upstream = addr
        resolveUpstreamAddr()
    }

    // MARK: - Upstream Address Resolution

    private func resolveUpstreamAddr() {
        guard !upstream.isEmpty else {
            upstreamAddr = nil
            return
        }
        let parts = upstream.split(separator: ":")
        guard parts.count == 2, let port = UInt16(parts[1]) else {
            upstreamAddr = nil
            return
        }
        let host = String(parts[0])

        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_port = port.bigEndian

        let ret = host.withCString { cstr in
            inet_pton(AF_INET, cstr, &addr.sin_addr)
        }
        guard ret == 1 else {
            upstreamAddr = nil
            return
        }
        upstreamAddr = addr
    }

    // MARK: - Enqueue (non-blocking)

    private func enqueue(_ dg: UDPDatagram) {
        guard let upstreamAddr = self.upstreamAddr else {
            if let resp = servfail(dg) { ready.append(resp) }
            return
        }

        let fd = socket(AF_INET, SOCK_DGRAM, 0)
        guard fd >= 0 else {
            if let resp = servfail(dg) { ready.append(resp) }
            return
        }

        let flags = fcntl(fd, F_GETFL, 0)
        _ = fcntl(fd, F_SETFL, flags | O_NONBLOCK)

        // Allocate an ID, skipping in-flight IDs on wrap
        var id = nextID
        while inFlightIDs.contains(id) {
            id = id &+ 1
        }
        nextID = id &+ 1
        inFlightIDs.insert(id)

        let pq = PendingDNSQuery(
            srcIP: dg.srcIP, dstIP: dg.dstIP,
            srcPort: dg.srcPort, dstPort: dg.dstPort,
            query: dg.payload
        )
        pq.fd = fd
        pq.sentAt = Date()
        pendingQueries[id] = pq

        // Non-blocking send on UDP socket
        var addr = upstreamAddr
        dg.payload.withUnsafeBytes { buf in
            withUnsafePointer(to: &addr) { ptr in
                ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                    _ = sendto(fd, buf.baseAddress!, dg.payload.count, 0,
                              sockPtr, socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }
        }
    }

    // MARK: - Poll (non-blocking)

    func poll() {
        var completed: [UInt64] = []

        for (id, pq) in pendingQueries {
            guard pq.fd >= 0 else {
                completed.append(id)
                continue
            }

            var recvBuf = [UInt8](repeating: 0, count: 1500)
            let n = recvBuf.withUnsafeMutableBytes { buf in
                recvfrom(pq.fd, buf.baseAddress!, 1500, 0, nil, nil)
            }

            if n > 0 {
                let resp = UDPDatagram(
                    srcIP: pq.dstIP, dstIP: pq.srcIP,
                    srcPort: dnsPort, dstPort: pq.srcPort,
                    payload: Data(recvBuf[0..<n])
                )
                ready.append(resp)
                completed.append(id)
                close(pq.fd)
            } else if n < 0 && errno != EAGAIN && errno != EWOULDBLOCK {
                // Socket error
                let sfDg = UDPDatagram(
                    srcIP: pq.dstIP, dstIP: pq.srcIP,
                    srcPort: dnsPort, dstPort: pq.srcPort,
                    payload: pq.query
                )
                if let sf = servfail(sfDg) { ready.append(sf) }
                completed.append(id)
                close(pq.fd)
            } else if Date().timeIntervalSince(pq.sentAt) > 5.0 {
                // Timeout after 5 seconds
                let sfDg = UDPDatagram(
                    srcIP: pq.dstIP, dstIP: pq.srcIP,
                    srcPort: dnsPort, dstPort: pq.srcPort,
                    payload: pq.query
                )
                if let sf = servfail(sfDg) { ready.append(sf) }
                completed.append(id)
                close(pq.fd)
            }
        }

        for id in completed {
            pendingQueries[id] = nil
            inFlightIDs.remove(id)
        }
    }

    func consumeResponses() -> [UDPDatagram] {
        let out = ready
        ready = []
        return out
    }

    // MARK: - SERVFAIL

    private func servfail(_ dg: UDPDatagram) -> UDPDatagram? {
        guard dg.payload.count >= 4 else { return nil }
        var resp = [UInt8](dg.payload)
        resp[2] = 0x81
        resp[3] = 0x82
        return UDPDatagram(
            srcIP: dg.dstIP, dstIP: dg.srcIP,
            srcPort: dnsPort, dstPort: dg.srcPort,
            payload: Data(resp)
        )
    }

    static func readSystemDNS() -> String {
        guard let data = try? String(contentsOfFile: "/etc/resolv.conf", encoding: .utf8) else {
            return ""
        }
        for line in data.split(separator: "\n") {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.hasPrefix("nameserver ") {
                let ip = String(trimmed.dropFirst("nameserver ".count)).trimmingCharacters(in: .whitespaces)
                let parts = ip.split(separator: ".").compactMap { UInt8($0) }
                if parts.count == 4 { return "\(ip):53" }
            }
        }
        return ""
    }
}
