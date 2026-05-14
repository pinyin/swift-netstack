import Darwin

// MARK: - Per-round I/O buffer (fixed size, zero allocs after init)

public final class IOBuffer {
    public let input: UnsafeMutableRawBufferPointer
    public let output: UnsafeMutableRawBufferPointer
    public let maxFrames: Int
    public let mtu: Int
    public private(set) var outputUsed: Int = 0

    public let frameLengths: UnsafeMutableBufferPointer<Int>
    public let frameEndpointIDs: UnsafeMutableBufferPointer<Int>
    public var frameCount: Int = 0

    public init(maxFrames: Int, mtu: Int) {
        self.maxFrames = maxFrames
        self.mtu = mtu
        self.input = UnsafeMutableRawBufferPointer.allocate(
            byteCount: maxFrames * mtu, alignment: 64)
        self.output = UnsafeMutableRawBufferPointer.allocate(
            byteCount: maxFrames * mtu, alignment: 64)
        self.frameLengths = UnsafeMutableBufferPointer<Int>.allocate(capacity: maxFrames)
        self.frameEndpointIDs = UnsafeMutableBufferPointer<Int>.allocate(capacity: maxFrames)
        self.frameLengths.initialize(repeating: 0)
        self.frameEndpointIDs.initialize(repeating: 0)
    }

    /// Base pointer for non-frame payload references (e.g. DNS queries).
    public var inputBase: UnsafeMutableRawPointer { input.baseAddress! }

    public func framePtr(_ i: Int) -> UnsafeMutableRawPointer {
        input.baseAddress!.advanced(by: i * mtu)
    }

    public func allocOutput(_ count: Int) -> UnsafeMutableRawPointer? {
        guard outputUsed + count <= output.count else { return nil }
        let ptr = output.baseAddress!.advanced(by: outputUsed)
        outputUsed += count
        return ptr
    }

    public func reset() { frameCount = 0; outputUsed = 0 }

    deinit {
        input.deallocate()
        output.deallocate()
        frameLengths.deallocate()
        frameEndpointIDs.deallocate()
    }
}

// MARK: - TCP segment info (FSM input)

public struct TCPSegmentInfo {
    public var seq: UInt32
    public var ack: UInt32
    public var flags: TCPFlags
    public var window: UInt16
    /// Window scale shift from SYN option (RFC 1323). 0 if not present.
    public var peerWindowScale: UInt8

    // RFC 2018 SACK — parsed from SACK option (kind=5)
    public var sackOK: Bool = false
    public var sackBlockCount: UInt8 = 0
    public var sackL0: UInt32 = 0; public var sackL1: UInt32 = 0; public var sackL2: UInt32 = 0; public var sackL3: UInt32 = 0
    public var sackR0: UInt32 = 0; public var sackR1: UInt32 = 0; public var sackR2: UInt32 = 0; public var sackR3: UInt32 = 0

    // RFC 7323 Timestamps — parsed from TSopt (kind=8)
    public var tsOK: Bool = false
    public var tsval: UInt32 = 0
    public var tsecr: UInt32 = 0

    public init(seq: UInt32, ack: UInt32, flags: TCPFlags, window: UInt16,
                peerWindowScale: UInt8 = 0) {
        self.seq = seq; self.ack = ack; self.flags = flags; self.window = window
        self.peerWindowScale = peerWindowScale
    }
}

// MARK: - Pre-allocated SoA buffers for parsing output

/// Holds all parse-output arrays. One-time allocation at init, zero allocs per round.
/// Uses UnsafeMutableBufferPointer — no ARC, no CoW, no reallocation.
public final class ParseOutput {
    public let maxFrames: Int

    // ── TCP ──
    public let tcpKeys: UnsafeMutableBufferPointer<NATKey>
    public let tcpSegs: UnsafeMutableBufferPointer<TCPSegmentInfo>
    public let tcpPayloadOfs: UnsafeMutableBufferPointer<Int>
    public let tcpPayloadLen: UnsafeMutableBufferPointer<Int>
    public let tcpEndpointIDs: UnsafeMutableBufferPointer<Int>
    public let tcpSrcMACs: UnsafeMutableBufferPointer<MACAddress>
    public var tcpCount: Int = 0

    // ── ARP ──
    public let arpEndpointIDs: UnsafeMutableBufferPointer<Int>
    public let arpFrames: UnsafeMutableBufferPointer<ARPFrame>
    public var arpCount: Int = 0

    // ── ICMP Echo ──
    public let icmpEchoEndpointIDs: UnsafeMutableBufferPointer<Int>
    public let icmpEchoSrcMACs: UnsafeMutableBufferPointer<MACAddress>
    public let icmpEchoSrcIPs: UnsafeMutableBufferPointer<IPv4Address>
    public let icmpEchoDstIPs: UnsafeMutableBufferPointer<IPv4Address>
    public let icmpEchoIDs: UnsafeMutableBufferPointer<UInt16>
    public let icmpEchoSeqNums: UnsafeMutableBufferPointer<UInt16>
    public let icmpEchoPayloadOfs: UnsafeMutableBufferPointer<Int>
    public let icmpEchoPayloadLen: UnsafeMutableBufferPointer<Int>
    /// Pre-computed one's complement sum of ICMP echo payload (RFC 792).
    /// Computed once during parse, folded with header checksum during build.
    public let icmpEchoPayloadSum: UnsafeMutableBufferPointer<UInt32>
    public var icmpEchoCount: Int = 0

    // ── ICMP Unreachable ──
    public let unreachEndpointIDs: UnsafeMutableBufferPointer<Int>
    public let unreachSrcMACs: UnsafeMutableBufferPointer<MACAddress>
    public let unreachGatewayIPs: UnsafeMutableBufferPointer<IPv4Address>
    public let unreachClientIPs: UnsafeMutableBufferPointer<IPv4Address>
    public let unreachRawOfs: UnsafeMutableBufferPointer<Int>
    public let unreachRawLen: UnsafeMutableBufferPointer<Int>
    /// ICMP code per unreachable entry (2=Protocol, 3=Port, 4=Frag Needed).
    public let unreachCodes: UnsafeMutableBufferPointer<UInt8>
    /// ICMP type per unreachable entry (3=Dest Unreachable, 11=Time Exceeded).
    public let unreachTypes: UnsafeMutableBufferPointer<UInt8>
    public var unreachCount: Int = 0

    // ── UDP ──
    public let udpEndpointIDs: UnsafeMutableBufferPointer<Int>
    public let udpSrcMACs: UnsafeMutableBufferPointer<MACAddress>
    public let udpSrcIPs: UnsafeMutableBufferPointer<IPv4Address>
    public let udpDstIPs: UnsafeMutableBufferPointer<IPv4Address>
    public let udpSrcPorts: UnsafeMutableBufferPointer<UInt16>
    public let udpDstPorts: UnsafeMutableBufferPointer<UInt16>
    public let udpPayloadOfs: UnsafeMutableBufferPointer<Int>
    public let udpPayloadLen: UnsafeMutableBufferPointer<Int>
    public var udpCount: Int = 0

    // ── DNS ──
    public let dnsEndpointIDs: UnsafeMutableBufferPointer<Int>
    public let dnsSrcMACs: UnsafeMutableBufferPointer<MACAddress>
    public let dnsSrcIPs: UnsafeMutableBufferPointer<IPv4Address>
    public let dnsDstIPs: UnsafeMutableBufferPointer<IPv4Address>
    public let dnsSrcPorts: UnsafeMutableBufferPointer<UInt16>
    public let dnsPayloadOfs: UnsafeMutableBufferPointer<Int>
    public let dnsPayloadLen: UnsafeMutableBufferPointer<Int>
    public var dnsCount: Int = 0

    // ── IPv4 Fragment ──
    public let fragmentEndpointIDs: UnsafeMutableBufferPointer<Int>
    public let fragmentSrcMACs: UnsafeMutableBufferPointer<MACAddress>
    public let fragmentSrcIPs: UnsafeMutableBufferPointer<IPv4Address>
    public let fragmentDstIPs: UnsafeMutableBufferPointer<IPv4Address>
    public let fragmentIdentifications: UnsafeMutableBufferPointer<UInt16>
    public let fragmentFlagsFrags: UnsafeMutableBufferPointer<UInt16>
    public let fragmentProtocols: UnsafeMutableBufferPointer<UInt8>
    public let fragmentFrameIdxs: UnsafeMutableBufferPointer<Int>
    public let fragmentFrameLens: UnsafeMutableBufferPointer<Int>
    public var fragmentCount: Int = 0

    // ── DHCP ──
    public let dhcpEndpointIDs: UnsafeMutableBufferPointer<Int>
    public let dhcpSrcMACs: UnsafeMutableBufferPointer<MACAddress>
    public let dhcpPackets: UnsafeMutableBufferPointer<DHCPPacket>
    public var dhcpCount: Int = 0

    public init(maxFrames: Int) {
        self.maxFrames = maxFrames
        let n = maxFrames

        tcpKeys = .allocate(capacity: n)
        tcpSegs = .allocate(capacity: n)
        tcpPayloadOfs = .allocate(capacity: n)
        tcpPayloadLen = .allocate(capacity: n)
        tcpEndpointIDs = .allocate(capacity: n)
        tcpSrcMACs = .allocate(capacity: n)

        arpEndpointIDs = .allocate(capacity: n)
        arpFrames = .allocate(capacity: n)

        icmpEchoEndpointIDs = .allocate(capacity: n)
        icmpEchoSrcMACs = .allocate(capacity: n)
        icmpEchoSrcIPs = .allocate(capacity: n)
        icmpEchoDstIPs = .allocate(capacity: n)
        icmpEchoIDs = .allocate(capacity: n)
        icmpEchoSeqNums = .allocate(capacity: n)
        icmpEchoPayloadOfs = .allocate(capacity: n)
        icmpEchoPayloadLen = .allocate(capacity: n)
        icmpEchoPayloadSum = .allocate(capacity: n)

        unreachEndpointIDs = .allocate(capacity: n)
        unreachSrcMACs = .allocate(capacity: n)
        unreachGatewayIPs = .allocate(capacity: n)
        unreachClientIPs = .allocate(capacity: n)
        unreachRawOfs = .allocate(capacity: n)
        unreachRawLen = .allocate(capacity: n)
        unreachCodes = .allocate(capacity: n)
        unreachTypes = .allocate(capacity: n)

        udpEndpointIDs = .allocate(capacity: n)
        udpSrcMACs = .allocate(capacity: n)
        udpSrcIPs = .allocate(capacity: n)
        udpDstIPs = .allocate(capacity: n)
        udpSrcPorts = .allocate(capacity: n)
        udpDstPorts = .allocate(capacity: n)
        udpPayloadOfs = .allocate(capacity: n)
        udpPayloadLen = .allocate(capacity: n)

        dnsEndpointIDs = .allocate(capacity: n)
        dnsSrcMACs = .allocate(capacity: n)
        dnsSrcIPs = .allocate(capacity: n)
        dnsDstIPs = .allocate(capacity: n)
        dnsSrcPorts = .allocate(capacity: n)
        dnsPayloadOfs = .allocate(capacity: n)
        dnsPayloadLen = .allocate(capacity: n)

        fragmentEndpointIDs = .allocate(capacity: n)
        fragmentSrcMACs = .allocate(capacity: n)
        fragmentSrcIPs = .allocate(capacity: n)
        fragmentDstIPs = .allocate(capacity: n)
        fragmentIdentifications = .allocate(capacity: n)
        fragmentFlagsFrags = .allocate(capacity: n)
        fragmentProtocols = .allocate(capacity: n)
        fragmentFrameIdxs = .allocate(capacity: n)
        fragmentFrameLens = .allocate(capacity: n)

        dhcpEndpointIDs = .allocate(capacity: n)
        dhcpSrcMACs = .allocate(capacity: n)
        dhcpPackets = .allocate(capacity: n)
    }

    /// Zero all counters. No memory ops — just integer writes.
    public func reset() {
        tcpCount = 0; arpCount = 0; icmpEchoCount = 0; unreachCount = 0
        udpCount = 0; dnsCount = 0; dhcpCount = 0; fragmentCount = 0
    }

    deinit {
        tcpKeys.deallocate()
        tcpSegs.deallocate()
        tcpPayloadOfs.deallocate()
        tcpPayloadLen.deallocate()
        tcpEndpointIDs.deallocate()
        tcpSrcMACs.deallocate()
        arpEndpointIDs.deallocate()
        arpFrames.deallocate()
        icmpEchoEndpointIDs.deallocate()
        icmpEchoSrcMACs.deallocate()
        icmpEchoSrcIPs.deallocate()
        icmpEchoDstIPs.deallocate()
        icmpEchoIDs.deallocate()
        icmpEchoSeqNums.deallocate()
        icmpEchoPayloadOfs.deallocate()
        icmpEchoPayloadLen.deallocate()
        icmpEchoPayloadSum.deallocate()
        unreachEndpointIDs.deallocate()
        unreachSrcMACs.deallocate()
        unreachGatewayIPs.deallocate()
        unreachClientIPs.deallocate()
        unreachRawOfs.deallocate()
        unreachRawLen.deallocate()
        unreachCodes.deallocate()
        unreachTypes.deallocate()
        udpEndpointIDs.deallocate()
        udpSrcMACs.deallocate()
        udpSrcIPs.deallocate()
        udpDstIPs.deallocate()
        udpSrcPorts.deallocate()
        udpDstPorts.deallocate()
        udpPayloadOfs.deallocate()
        udpPayloadLen.deallocate()
        dnsEndpointIDs.deallocate()
        dnsSrcMACs.deallocate()
        dnsSrcIPs.deallocate()
        dnsDstIPs.deallocate()
        dnsSrcPorts.deallocate()
        dnsPayloadOfs.deallocate()
        dnsPayloadLen.deallocate()
        fragmentEndpointIDs.deallocate()
        fragmentSrcMACs.deallocate()
        fragmentSrcIPs.deallocate()
        fragmentDstIPs.deallocate()
        fragmentIdentifications.deallocate()
        fragmentFlagsFrags.deallocate()
        fragmentProtocols.deallocate()
        fragmentFrameIdxs.deallocate()
        fragmentFrameLens.deallocate()

        dhcpEndpointIDs.deallocate()
        dhcpSrcMACs.deallocate()
        dhcpPackets.deallocate()
    }
}

// MARK: - Output frame tracking (pre-allocated, SoA)

public final class OutBatch {
    public let maxFrames: Int
    public let hdrOfs: UnsafeMutableBufferPointer<Int>
    public let hdrLen: UnsafeMutableBufferPointer<Int>
    public let payOfs: UnsafeMutableBufferPointer<Int>
    public let payLen: UnsafeMutableBufferPointer<Int>
    public let epIDs: UnsafeMutableBufferPointer<Int>
    /// Per-frame payload base override. nil means use IOBuffer.input.
    /// Set to SendQueue.buf.baseAddress for TCP data segments.
    public let payBase: UnsafeMutableBufferPointer<UnsafeMutableRawPointer?>
    public var count: Int = 0

    public init(maxFrames: Int) {
        self.maxFrames = maxFrames
        hdrOfs = .allocate(capacity: maxFrames)
        hdrLen = .allocate(capacity: maxFrames)
        payOfs = .allocate(capacity: maxFrames)
        payLen = .allocate(capacity: maxFrames)
        epIDs = .allocate(capacity: maxFrames)
        payBase = .allocate(capacity: maxFrames)
        payBase.initialize(repeating: nil)
    }

    public func reset() { count = 0 }

    deinit {
        hdrOfs.deallocate()
        hdrLen.deallocate()
        payOfs.deallocate()
        payLen.deallocate()
        epIDs.deallocate()
        payBase.deallocate()
    }
}

// MARK: - Send queue (pre-allocated linear buffer)

/// Per-connection byte queue. One allocation at init, zero allocs in hot path.
/// Data is always contiguous — compaction happens only on wrap, O(bytes) memmove.
public struct SendQueue {
    public let buf: UnsafeMutableRawBufferPointer
    public let capacity: Int
    public var readPos: Int = 0
    public var writePos: Int = 0

    public var count: Int { writePos - readPos }
    public var isEmpty: Bool { count == 0 }

    public init(capacity: Int) {
        self.capacity = capacity
        self.buf = UnsafeMutableRawBufferPointer.allocate(byteCount: capacity, alignment: 64)
    }

    /// Enqueue from a pointer. Compact on wrap. Returns bytes actually enqueued.
    @discardableResult
    public mutating func enqueue(_ src: UnsafeRawPointer, _ len: Int) -> Int {
        let space = capacity - count
        let n = Swift.min(len, space)
        guard n > 0 else { return 0 }
        if readPos > 0 && writePos + n > capacity {
            let cnt = count
            if cnt > 0 {
                buf.baseAddress!.copyMemory(from: buf.baseAddress! + readPos, byteCount: cnt)
            }
            writePos = cnt
            readPos = 0
        }
        (buf.baseAddress! + writePos).copyMemory(from: src, byteCount: n)
        writePos += n
        return n
    }

    /// Peek up to `max` bytes from the front. Always contiguous.
    public func peek(max len: Int) -> (ptr: UnsafeRawPointer, len: Int)? {
        let n = Swift.min(count, len)
        guard n > 0 else { return nil }
        return (UnsafeRawPointer(buf.baseAddress! + readPos), n)
    }

    /// Discard `len` bytes from the front.
    public mutating func dequeue(_ len: Int) {
        let n = Swift.min(len, count)
        readPos += n
        if readPos > 16384 || readPos * 2 >= writePos && writePos > 16384 {
            let cnt = count
            if cnt > 0 {
                buf.baseAddress!.copyMemory(from: buf.baseAddress! + readPos, byteCount: cnt)
            }
            writePos = cnt
            readPos = 0
        }
    }

    public func free() { buf.deallocate() }
}
