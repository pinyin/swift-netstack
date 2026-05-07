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

    // MARK: - DNS protocol constants

    private enum Flag {
        static let qrMask: UInt16       = 0x8000
        static let opcodeMask: UInt16   = 0x7800
        static let compression: UInt8   = 0xC0
        static let query: UInt16        = 0x0100  // RD=1
        static let reply: UInt16        = 0x8180  // QR=1, RD=1, RCODE=0
        static let nxdomain: UInt16     = 0x8183  // QR=1, RD=1, RCODE=3
    }

    private enum RRType  { static let a: UInt16 = 1 }
    private enum RRClass { static let `in`: UInt16 = 1 }
    private static let rdLengthIPv4: UInt16 = 4

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
            guard (flags & Flag.qrMask) == 0 else { return nil }
            guard (flags & Flag.opcodeMask) == 0 else { return nil }
            guard qdcount >= 1 else { return nil }

            // Parse the first QNAME
            guard let (name, bytesUsed) = parseQName(from: buf, startOffset: 12) else { return nil }
            let qOffset = 12 + bytesUsed
            guard qOffset + 4 <= buf.count else { return nil }

            let qtype  = readUInt16BE(base, qOffset)
            let qclass = readUInt16BE(base, qOffset + 2)

            guard qclass == RRClass.in else { return nil }

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
        writeUInt16BE(Flag.reply, to: ptr.advanced(by: 2))     // Flags: QR=1, RD=1
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
        writeUInt16BE(RRType.a, to: ptr.advanced(by: off)); off += 2
        writeUInt16BE(RRClass.in, to: ptr.advanced(by: off)); off += 2
        writeUInt32BE(ttl, to: ptr.advanced(by: off)); off += 4   // TTL
        writeUInt16BE(rdLengthIPv4, to: ptr.advanced(by: off)); off += 2
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
        writeUInt16BE(Flag.nxdomain, to: ptr.advanced(by: 2))  // Flags: QR=1, RD=1, RCODE=3
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

    /// Build a DNS query for upstream forwarding (RD=1, standard query).
    public static func buildQuery(
        txID: UInt16,
        question: DNSQuestion,
        round: RoundContext
    ) -> PacketBuffer? {
        let qnameLabels = encodeQName(question.name)
        let totalLen = 12 + qnameLabels.count + 4

        var pkt = round.allocate(capacity: totalLen, headroom: 0)
        guard let ptr = pkt.appendPointer(count: totalLen) else { return nil }

        writeUInt16BE(txID, to: ptr)                           // Transaction ID
        writeUInt16BE(Flag.query, to: ptr.advanced(by: 2))     // Flags: RD=1
        writeUInt16BE(1, to: ptr.advanced(by: 4))               // QDCOUNT = 1
        writeUInt16BE(0, to: ptr.advanced(by: 6))               // ANCOUNT
        writeUInt16BE(0, to: ptr.advanced(by: 8))               // NSCOUNT
        writeUInt16BE(0, to: ptr.advanced(by: 10))              // ARCOUNT

        var off = 12
        ptr.advanced(by: off).copyMemory(from: qnameLabels, byteCount: qnameLabels.count)
        off += qnameLabels.count
        writeUInt16BE(question.type, to: ptr.advanced(by: off)); off += 2
        writeUInt16BE(question.class, to: ptr.advanced(by: off))

        return pkt
    }

    /// Parse a DNS response from upstream. Returns the transaction ID and the
    /// first question found. Returns nil if not a valid response.
    public static func parseResponse(from payload: PacketBuffer) -> (txID: UInt16, question: DNSQuestion)? {
        guard payload.totalLength >= 12 else { return nil }
        return payload.withUnsafeReadableBytes { buf in
            guard let base = buf.baseAddress else { return nil }

            let txID = readUInt16BE(base, 0)
            let flags = readUInt16BE(base, 2)
            let qdcount = readUInt16BE(base, 4)

            // QR must be 1 (response)
            guard (flags & Flag.qrMask) != 0 else { return nil }
            guard qdcount >= 1 else { return nil }

            guard let (name, bytesUsed) = parseQName(from: buf, startOffset: 12) else { return nil }
            let qOffset = 12 + bytesUsed
            guard qOffset + 4 <= buf.count else { return nil }

            let qtype  = readUInt16BE(base, qOffset)
            let qclass = readUInt16BE(base, qOffset + 2)

            return (txID, DNSQuestion(name: name, type: qtype, class: qclass))
        }
    }

    /// Extract the first A record (IPv4) from a DNS response.
    /// Walks past the question section and answer header to find RDATA.
    public static func extractFirstA(from payload: PacketBuffer) -> IPv4Address? {
        guard payload.totalLength >= 12 else { return nil }
        return payload.withUnsafeReadableBytes { buf in
            guard let base = buf.baseAddress else { return nil }

            let ancount = readUInt16BE(base, 6)
            guard ancount >= 1 else { return nil }

            // Skip past the header (12) and question section
            var off = 12
            for _ in 0..<Int(readUInt16BE(base, 4)) {  // QDCOUNT
                guard let (_, consumed) = parseQName(from: buf, startOffset: off) else { return nil }
                off += consumed + 4  // QNAME + QTYPE + QCLASS
            }

            // Walk each answer looking for TYPE=A (1)
            for _ in 0..<Int(ancount) {
                guard off + 10 <= buf.count else { return nil }
                // Answer NAME (may use compression pointers)
                let nameOff = off
                var nameLen = 0
                if buf[nameOff] & Flag.compression == Flag.compression {
                    nameLen = 2  // compression pointer
                } else {
                    guard let (_, consumed) = parseQName(from: buf, startOffset: nameOff) else { return nil }
                    nameLen = consumed
                }
                off = nameOff + nameLen

                guard off + 10 <= buf.count else { return nil }
                let atype  = readUInt16BE(base, off); off += 2
                let aclass = readUInt16BE(base, off); off += 2
                off += 4  // TTL
                let rdlen  = readUInt16BE(base, off); off += 2
                if atype == RRType.a, aclass == RRClass.in, rdlen == rdLengthIPv4, off + 4 <= buf.count {
                    let a = buf[off]
                    let b = buf[off + 1]
                    let c = buf[off + 2]
                    let d = buf[off + 3]
                    return IPv4Address(a, b, c, d)
                }
                off += Int(rdlen)
            }
            return nil
        }
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
            if len & Flag.compression == Flag.compression { return nil }              // reject compression pointer
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
