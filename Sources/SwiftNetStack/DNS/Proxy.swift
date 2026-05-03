import Foundation
import Darwin

let dnsPort: UInt16 = 53

// MARK: - Pending DNS Query

private final class PendingDNSQuery: @unchecked Sendable {
    let srcIP: UInt32
    let dstIP: UInt32
    let srcPort: UInt16
    let dstPort: UInt16
    let query: [UInt8]
    var result: UDPDatagram??

    init(srcIP: UInt32, dstIP: UInt32, srcPort: UInt16, dstPort: UInt16, query: [UInt8]) {
        self.srcIP = srcIP
        self.dstIP = dstIP
        self.srcPort = srcPort
        self.dstPort = dstPort
        self.query = query
        self.result = .none
    }
}

// MARK: - DNS Proxy

final class DNSProxy {
    private(set) var upstream: String
    let listenIP: UInt32

    private var nextID: UInt64 = 0
    private var pendingQueries: [UInt64: PendingDNSQuery] = [:]
    private var ready: [UDPDatagram] = []

    init(listenIP: UInt32, upstreamAddr: String) {
        self.listenIP = listenIP
        if !upstreamAddr.isEmpty {
            self.upstream = upstreamAddr
        } else {
            self.upstream = DNSProxy.readSystemDNS()
        }
    }

    func handler() -> UDPHandler {
        return { [weak self] dg in
            self?.enqueue(dg)
            return []
        }
    }

    func set(upstream addr: String) { upstream = addr }

    // MARK: - Enqueue

    private func enqueue(_ dg: UDPDatagram) {
        guard !upstream.isEmpty else {
            if let resp = servfail(dg) { ready.append(resp) }
            return
        }

        let id = nextID
        nextID += 1

        let pq = PendingDNSQuery(
            srcIP: dg.srcIP, dstIP: dg.dstIP,
            srcPort: dg.srcPort, dstPort: dg.dstPort,
            query: dg.payload
        )
        pendingQueries[id] = pq

        let upstreamAddr = self.upstream
        let queryData = dg.payload

        let capturePQ = pq
        Task { @Sendable in
            let result = await DNSProxy.resolveUpstream(
                upstream: upstreamAddr, query: queryData,
                dstIP: capturePQ.dstIP, srcIP: capturePQ.srcIP, srcPort: capturePQ.srcPort
            )
            capturePQ.result = .some(result)
        }
    }

    // MARK: - Async Resolution

    private static func resolveUpstream(
        upstream: String, query: [UInt8],
        dstIP: UInt32, srcIP: UInt32, srcPort: UInt16
    ) async -> UDPDatagram? {
        let parts = upstream.split(separator: ":")
        guard parts.count == 2, let port = UInt16(parts[1]) else { return nil }
        let host = String(parts[0])

        return await withCheckedContinuation { continuation in
            DispatchQueue.global().async {
                var hints = addrinfo()
                hints.ai_family = AF_INET
                hints.ai_socktype = SOCK_DGRAM

                var result: UnsafeMutablePointer<addrinfo>?
                let err = getaddrinfo(host, String(port), &hints, &result)
                guard err == 0, let info = result else {
                    continuation.resume(returning: nil)
                    return
                }
                defer { freeaddrinfo(result) }

                let fd = socket(info.pointee.ai_family, info.pointee.ai_socktype, info.pointee.ai_protocol)
                guard fd >= 0 else {
                    continuation.resume(returning: nil)
                    return
                }
                defer { close(fd) }

                var tv = timeval(tv_sec: 2, tv_usec: 0)
                setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))

                query.withUnsafeBytes { buf in
                    _ = sendto(fd, buf.baseAddress!, query.count, 0,
                               info.pointee.ai_addr, info.pointee.ai_addrlen)
                }

                var recvBuf = [UInt8](repeating: 0, count: 1500)
                let n = recvBuf.withUnsafeMutableBytes { buf in
                    recvfrom(fd, buf.baseAddress!, 1500, 0, nil, nil)
                }

                guard n > 0 else {
                    continuation.resume(returning: nil)
                    return
                }

                let resp = UDPDatagram(
                    srcIP: dstIP, dstIP: srcIP,
                    srcPort: dnsPort, dstPort: srcPort,
                    payload: Array(recvBuf[0..<n])
                )
                continuation.resume(returning: resp)
            }
        }
    }

    // MARK: - Poll

    func poll() {
        for (id, pq) in pendingQueries {
            guard let result = pq.result else { continue }
            pendingQueries[id] = nil
            if let resp = result {
                ready.append(resp)
            } else {
                let sfDg = UDPDatagram(
                    srcIP: pq.dstIP, dstIP: pq.srcIP,
                    srcPort: dnsPort, dstPort: pq.srcPort,
                    payload: pq.query
                )
                if let sf = servfail(sfDg) { ready.append(sf) }
            }
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
        var resp = dg.payload
        resp[2] = 0x81
        resp[3] = 0x82
        return UDPDatagram(
            srcIP: dg.dstIP, dstIP: dg.srcIP,
            srcPort: dnsPort, dstPort: dg.srcPort,
            payload: resp
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
