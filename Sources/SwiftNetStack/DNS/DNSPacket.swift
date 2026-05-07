import Darwin

/// A parsed DNS question (from the Question section).
public struct DNSQuestion {
    public let name: String       // normalised: lowercase, trailing dot stripped
    public let type: UInt16       // 1 = A
    public let `class`: UInt16    // 1 = IN
}

/// Minimal DNS packet parser and reply builder.
///
/// Only handles the first question in the Question section.  Compression
/// pointers in the query QNAME are rejected (real VM resolvers send
/// uncompressed single questions).
public enum DNSPacket {

    // MARK: - Parse

    /// Parse a DNS query from raw UDP payload bytes.
    /// Returns `nil` for malformed or unsupported queries.
    public static func parse(from payload: PacketBuffer) -> (txID: UInt16, question: DNSQuestion)? {
        guard payload.totalLength >= 12 else { return nil }
        return payload.withUnsafeReadableBytes { buf in
            guard let base = buf.baseAddress else { return nil }

            let txID = readUInt16BE(base, 0)
            let flags = readUInt16BE(base, 2)
            let qdcount = readUInt16BE(base, 4)

            // QR must be 0 (query); only standard queries (opcode 0) are handled.
            guard (flags & 0x8000) == 0 else { return nil }       // QR=0
            guard (flags & 0x7800) == 0 else { return nil }       // OPCODE=0
            guard qdcount >= 1 else { return nil }

            // Parse the first QNAME
            guard let (name, bytesUsed) = parseQName(from: buf, startOffset: 12) else { return nil }
            let qOffset = 12 + bytesUsed
            guard qOffset + 4 <= buf.count else { return nil }

            let qtype  = readUInt16BE(base, qOffset)
            let qclass = readUInt16BE(base, qOffset + 2)

            // Only IN (1) class is supported
            guard qclass == 1 else { return nil }

            return (txID, DNSQuestion(name: name, type: qtype, class: qclass))
        }
    }

    // MARK: - Build replies

    /// Build an A-record reply packet (raw bytes in a PacketBuffer).
    public static func buildAReply(
        txID: UInt16,
        question: DNSQuestion,
        ip: IPv4Address,
        ttl: UInt32 = 300,
        round: RoundContext
    ) -> PacketBuffer? {
        // Re-encode the QNAME as labels
        let qnameLabels = encodeQName(question.name)

        // Header (12) + Question (qnameLabels + 4) + Answer (qnameLabels + 14)
        // Answer: NAME(qnameLabels) + TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2) + RDATA(4)
        let answerLen = qnameLabels.count + 14
        let questionLen = qnameLabels.count + 4
        let totalLen = 12 + questionLen + answerLen

        var pkt = round.allocate(capacity: totalLen, headroom: 0)
        guard let ptr = pkt.appendPointer(count: totalLen) else { return nil }

        // Header
        writeUInt16BE(txID, to: ptr)                           // Transaction ID
        writeUInt16BE(0x8180, to: ptr.advanced(by: 2))         // Flags: QR=1, RD=1, RA=0
        writeUInt16BE(0, to: ptr.advanced(by: 4))               // QDCOUNT (set below)
        writeUInt16BE(1, to: ptr.advanced(by: 6))               // ANCOUNT = 1
        writeUInt16BE(0, to: ptr.advanced(by: 8))               // NSCOUNT
        writeUInt16BE(0, to: ptr.advanced(by: 10))              // ARCOUNT

        // Question section (starts at offset 12)
        var off = 12
        ptr.advanced(by: off).copyMemory(from: qnameLabels, byteCount: qnameLabels.count)
        off += qnameLabels.count
        writeUInt16BE(question.type, to: ptr.advanced(by: off)); off += 2
        writeUInt16BE(question.class, to: ptr.advanced(by: off)); off += 2

        // Answer section
        ptr.advanced(by: off).copyMemory(from: qnameLabels, byteCount: qnameLabels.count)
        off += qnameLabels.count
        writeUInt16BE(1, to: ptr.advanced(by: off)); off += 2     // TYPE=A
        writeUInt16BE(1, to: ptr.advanced(by: off)); off += 2     // CLASS=IN
        writeUInt32BE(ttl, to: ptr.advanced(by: off)); off += 4   // TTL
        writeUInt16BE(4, to: ptr.advanced(by: off)); off += 2     // RDLENGTH=4
        ip.write(to: ptr.advanced(by: off))                       // RDATA (4 bytes)

        // Fix-up QDCOUNT to 1
        writeUInt16BE(1, to: ptr.advanced(by: 4))

        return pkt
    }

    /// Build an NXDOMAIN reply (RCODE=3, no answer records).
    public static func buildNXDOMAIN(
        txID: UInt16,
        question: DNSQuestion,
        round: RoundContext
    ) -> PacketBuffer? {
        let qnameLabels = encodeQName(question.name)
        let totalLen = 12 + qnameLabels.count + 4

        var pkt = round.allocate(capacity: totalLen, headroom: 0)
        guard let ptr = pkt.appendPointer(count: totalLen) else { return nil }

        // Header
        writeUInt16BE(txID, to: ptr)                           // Transaction ID
        writeUInt16BE(0x8183, to: ptr.advanced(by: 2))         // Flags: QR=1, RD=1, RA=0, RCODE=3
        writeUInt16BE(1, to: ptr.advanced(by: 4))               // QDCOUNT
        writeUInt16BE(0, to: ptr.advanced(by: 6))               // ANCOUNT
        writeUInt16BE(0, to: ptr.advanced(by: 8))               // NSCOUNT
        writeUInt16BE(0, to: ptr.advanced(by: 10))              // ARCOUNT

        // Question section
        var off = 12
        ptr.advanced(by: off).copyMemory(from: qnameLabels, byteCount: qnameLabels.count)
        off += qnameLabels.count
        writeUInt16BE(question.type, to: ptr.advanced(by: off)); off += 2
        writeUInt16BE(question.class, to: ptr.advanced(by: off))

        return pkt
    }

    // MARK: - Internal helpers

    /// Parse a DNS QNAME starting at `startOffset`.
    /// Returns the normalised name (lowercase, no trailing dot) and byte count consumed.
    /// Rejects compression pointers (0xC0xx) in queries.
    static func parseQName(
        from buf: UnsafeRawBufferPointer,
        startOffset: Int
    ) -> (name: String, bytesConsumed: Int)? {
        var labels: [String] = []
        var offset = startOffset

        while offset < buf.count {
            let len = buf[offset]
            if len == 0 { offset += 1; break }                // root label
            if len & 0xC0 == 0xC0 { return nil }              // reject compression pointer
            if len > 63 { return nil }                         // invalid label length
            offset += 1
            guard offset + Int(len) <= buf.count else { return nil }
            guard let label = String(
                bytes: buf[offset..<(offset + Int(len))],
                encoding: .ascii
            ) else { return nil }
            labels.append(label.lowercased())
            offset += Int(len)
        }

        guard !labels.isEmpty else { return nil }
        return (labels.joined(separator: "."), offset - startOffset)
    }

    /// Encode a dot-separated hostname into DNS label format.
    static func encodeQName(_ name: String) -> [UInt8] {
        var result: [UInt8] = []
        let stripped = name.hasSuffix(".") ? String(name.dropLast()) : name
        for label in stripped.split(separator: ".") {
            let bytes = Array(label.utf8)
            result.append(UInt8(bytes.count))
            result.append(contentsOf: bytes)
        }
        result.append(0)  // root label terminator
        return result
    }
}

// MARK: - Raw byte readers

private func readUInt16BE(_ base: UnsafeRawPointer, _ offset: Int) -> UInt16 {
    let ptr = base.assumingMemoryBound(to: UInt8.self).advanced(by: offset)
    return (UInt16(ptr[0]) << 8) | UInt16(ptr[1])
}
