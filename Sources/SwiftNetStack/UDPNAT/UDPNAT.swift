import Foundation
import Darwin

// MARK: - UDP NAT Key

struct UDPNATKey: Hashable {
    let srcIP: UInt32
    let dstIP: UInt32
    let srcPort: UInt16
    let dstPort: UInt16
}

// MARK: - UDP NAT Entry

final class UDPNATEntry {
    let key: UDPNATKey
    var hostFD: Int32 = -1
    var egressQ: [UDPDatagram] = []
    var ingressQ: [UDPDatagram] = []
    var lastActive: Date = Date()
    var closed: Bool = false
    let maxPayload = 65507

    init(key: UDPNATKey) {
        self.key = key
    }
}

// MARK: - UDP NAT Table

final class UDPNATTable {
    var entries: [UDPNATKey: UDPNATEntry] = [:]
    private var readBuf: [UInt8]

    init() {
        readBuf = [UInt8](repeating: 0, count: 65536)
    }

    func intercept(_ dg: UDPDatagram) -> Bool {
        let key = UDPNATKey(srcIP: dg.srcIP, dstIP: dg.dstIP,
                            srcPort: dg.srcPort, dstPort: dg.dstPort)

        if let entry = entries[key] {
            entry.egressQ.append(dg)
            entry.lastActive = Date()
            return true
        }

        // Create new UDP socket
        let fd = socket(AF_INET, SOCK_DGRAM, 0)
        guard fd >= 0 else { return true }

        let flags = fcntl(fd, F_GETFL, 0)
        _ = fcntl(fd, F_SETFL, flags | O_NONBLOCK)

        // Connect to destination
        var dst = sockaddr_in()
        dst.sin_family = sa_family_t(AF_INET)
        dst.sin_addr.s_addr = dg.dstIP.bigEndian
        dst.sin_port = dg.dstPort.bigEndian

        let connectResult = withUnsafePointer(to: &dst) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                connect(fd, sockPtr, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        if connectResult < 0 {
            close(fd)
            return true
        }

        let entry = UDPNATEntry(key: key)
        entry.hostFD = fd
        entry.egressQ = [dg]
        entries[key] = entry
        return true
    }

    // MARK: - Poll

    func poll() {
        for (_, entry) in entries {
            guard !entry.closed, entry.hostFD >= 0 else { continue }
            readHost(entry)
        }
    }

    // MARK: - Flush Egress

    func flushEgress() {
        for (_, entry) in entries {
            guard !entry.closed, !entry.egressQ.isEmpty else { continue }
            writeHost(entry)
        }
    }

    // MARK: - Deliver to VM

    func deliverToVM() -> [UDPDatagram] {
        var all: [UDPDatagram] = []
        for (_, entry) in entries {
            all.append(contentsOf: entry.ingressQ)
            entry.ingressQ = []
        }
        return all
    }

    // MARK: - Cleanup

    func cleanup(now: Date) {
        for (key, entry) in entries {
            if entry.closed || now.timeIntervalSince(entry.lastActive) > 90 {
                if entry.hostFD >= 0 { close(entry.hostFD) }
                entries[key] = nil
            }
        }
    }

    func count() -> Int { entries.count }

    // MARK: - I/O

    private func readHost(_ entry: UDPNATEntry) {
        let readMax = min(entry.maxPayload, readBuf.count)
        let n = readBuf.withUnsafeMutableBytes { ptr in
            Darwin.read(entry.hostFD, ptr.baseAddress!, readMax)
        }

        if n < 0 {
            if errno == EAGAIN || errno == EWOULDBLOCK { return }
            entry.closed = true
            return
        }
        if n == 0 { return }

        entry.lastActive = Date()

        let ingress = UDPDatagram(
            srcIP: entry.key.dstIP, dstIP: entry.key.srcIP,
            srcPort: entry.key.dstPort, dstPort: entry.key.srcPort,
            payload: Data(readBuf[0..<n])
        )
        entry.ingressQ.append(ingress)
    }

    private func writeHost(_ entry: UDPNATEntry) {
        for dg in entry.egressQ {
            let n = dg.payload.withUnsafeBytes { ptr in
                Darwin.write(entry.hostFD, ptr.baseAddress!, dg.payload.count)
            }
            if n < 0 {
                entry.closed = true
                return
            }
            entry.lastActive = Date()
        }
        entry.egressQ = []
    }
}
