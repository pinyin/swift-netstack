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

    public init(seq: UInt32, ack: UInt32, flags: TCPFlags, window: UInt16,
                peerWindowScale: UInt8 = 0) {
        self.seq = seq; self.ack = ack; self.flags = flags; self.window = window
        self.peerWindowScale = peerWindowScale
    }
}

// MARK: - Per-protocol parsed frame types (dense struct arrays)

public struct ARPParsedFrame {
    public var endpointID: Int
    public var frame: ARPFrame
}

public struct DHCPParsedFrame {
    public var endpointID: Int
    public var srcMAC: MACAddress
    public var packet: DHCPPacket
}

public struct DNSParsedFrame {
    public var endpointID: Int
    public var srcMAC: MACAddress
    public var srcIP: IPv4Address
    public var dstIP: IPv4Address
    public var srcPort: UInt16
    public var payloadOfs: Int
    public var payloadLen: Int
}

public struct ICMPEchoParsedFrame {
    public var endpointID: Int
    public var srcMAC: MACAddress
    public var srcIP: IPv4Address
    public var dstIP: IPv4Address
    public var identifier: UInt16
    public var sequenceNumber: UInt16
    public var payloadOfs: Int
    public var payloadLen: Int
    public var payloadSum: UInt32
}

public struct ICMPUnreachParsedFrame {
    public var endpointID: Int
    public var srcMAC: MACAddress
    public var gatewayIP: IPv4Address
    public var clientIP: IPv4Address
    public var rawOfs: Int
    public var rawLen: Int
    public var code: UInt8
    public var type: UInt8
}

public struct FragmentParsedFrame {
    public var endpointID: Int
    public var srcMAC: MACAddress
    public var srcIP: IPv4Address
    public var dstIP: IPv4Address
    public var identification: UInt16
    public var flagsFrag: UInt16
    public var ipProtocol: UInt8
    public var frameIdx: Int
    public var frameLen: Int
    public var ipHeaderLen: Int
}

public struct UDPParsedFrame {
    public var endpointID: Int
    public var srcMAC: MACAddress
    public var srcIP: IPv4Address
    public var dstIP: IPv4Address
    public var srcPort: UInt16
    public var dstPort: UInt16
    public var payloadOfs: Int
    public var payloadLen: Int
    public var ipHeaderLen: Int
}

// MARK: - Protocol-grouped parse output

/// TCP keeps internal SoA — processed column-by-column in processTCPRound.
/// Class (not struct) so ParseOutput can use `let` — avoids Swift exclusivity
/// checking overhead on `var` struct properties in the hot path.
public final class TCPParseGroup {
    public let keys: UnsafeMutableBufferPointer<NATKey>
    public let segs: UnsafeMutableBufferPointer<TCPSegmentInfo>
    public let payloadOfs: UnsafeMutableBufferPointer<Int>
    public let payloadLen: UnsafeMutableBufferPointer<Int>
    public let endpointIDs: UnsafeMutableBufferPointer<Int>
    public let srcMACs: UnsafeMutableBufferPointer<MACAddress>
    public let capacity: Int
    public var count: Int = 0

    public init(capacity: Int) {
        self.capacity = capacity
        keys = .allocate(capacity: capacity)
        segs = .allocate(capacity: capacity)
        payloadOfs = .allocate(capacity: capacity)
        payloadLen = .allocate(capacity: capacity)
        endpointIDs = .allocate(capacity: capacity)
        srcMACs = .allocate(capacity: capacity)
    }

    public func deinitAll() {
        keys.deallocate()
        segs.deallocate()
        payloadOfs.deallocate()
        payloadLen.deallocate()
        endpointIDs.deallocate()
        srcMACs.deallocate()
    }
}

/// Dense-struct-array group for protocols processed as whole frames.
public final class UDPParseGroup {
    public let frames: UnsafeMutableBufferPointer<UDPParsedFrame>
    public let capacity: Int
    public var count: Int = 0

    public init(capacity: Int) {
        self.capacity = capacity
        frames = .allocate(capacity: capacity)
    }
    public func deinitAll() { frames.deallocate() }
}

public final class DNSParseGroup {
    public let frames: UnsafeMutableBufferPointer<DNSParsedFrame>
    public let capacity: Int
    public var count: Int = 0

    public init(capacity: Int) {
        self.capacity = capacity
        frames = .allocate(capacity: capacity)
    }
    public func deinitAll() { frames.deallocate() }
}

public final class ICMPEchoParseGroup {
    public let frames: UnsafeMutableBufferPointer<ICMPEchoParsedFrame>
    public let capacity: Int
    public var count: Int = 0

    public init(capacity: Int) {
        self.capacity = capacity
        frames = .allocate(capacity: capacity)
    }
    public func deinitAll() { frames.deallocate() }
}

public final class ICMPUnreachParseGroup {
    public let frames: UnsafeMutableBufferPointer<ICMPUnreachParsedFrame>
    public let capacity: Int
    public var count: Int = 0

    public init(capacity: Int) {
        self.capacity = capacity
        frames = .allocate(capacity: capacity)
    }
    public func deinitAll() { frames.deallocate() }
}

public final class FragmentParseGroup {
    public let frames: UnsafeMutableBufferPointer<FragmentParsedFrame>
    public let capacity: Int
    public var count: Int = 0

    public init(capacity: Int) {
        self.capacity = capacity
        frames = .allocate(capacity: capacity)
    }
    public func deinitAll() { frames.deallocate() }
}

public final class ARPParseGroup {
    public let frames: UnsafeMutableBufferPointer<ARPParsedFrame>
    public let capacity: Int
    public var count: Int = 0

    public init(capacity: Int) {
        self.capacity = capacity
        frames = .allocate(capacity: capacity)
    }
    public func deinitAll() { frames.deallocate() }
}

public final class DHCPParseGroup {
    public let frames: UnsafeMutableBufferPointer<DHCPParsedFrame>
    public let capacity: Int
    public var count: Int = 0

    public init(capacity: Int) {
        self.capacity = capacity
        frames = .allocate(capacity: capacity)
    }
    public func deinitAll() { frames.deallocate() }
}

// MARK: - Parse output (owns all protocol groups)

public final class ParseOutput {
    public let tcp: TCPParseGroup
    public let udp: UDPParseGroup
    public let dns: DNSParseGroup
    public let icmpEcho: ICMPEchoParseGroup
    public let unreach: ICMPUnreachParseGroup
    public let fragment: FragmentParseGroup
    public let arp: ARPParseGroup
    public let dhcp: DHCPParseGroup

    public init(maxFrames: Int = 256) {
        let n = maxFrames
        tcp      = TCPParseGroup(capacity: n)
        udp      = UDPParseGroup(capacity: max(32, n / 8))
        dns      = DNSParseGroup(capacity: max(32, n / 8))
        icmpEcho = ICMPEchoParseGroup(capacity: max(8, n / 32))
        unreach  = ICMPUnreachParseGroup(capacity: max(16, n / 16))
        fragment = FragmentParseGroup(capacity: max(16, n / 16))
        arp      = ARPParseGroup(capacity: max(8, n / 32))
        dhcp     = DHCPParseGroup(capacity: max(4, n / 64))
    }

    public func reset() {
        tcp.count = 0
        udp.count = 0
        dns.count = 0
        icmpEcho.count = 0
        unreach.count = 0
        fragment.count = 0
        arp.count = 0
        dhcp.count = 0
    }

    deinit {
        tcp.deinitAll()
        udp.deinitAll()
        dns.deinitAll()
        icmpEcho.deinitAll()
        unreach.deinitAll()
        fragment.deinitAll()
        arp.deinitAll()
        dhcp.deinitAll()
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
                memmove(buf.baseAddress!, buf.baseAddress! + readPos, cnt)
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
                memmove(buf.baseAddress!, buf.baseAddress! + readPos, cnt)
            }
            writePos = cnt
            readPos = 0
        }
    }

    public func free() { buf.deallocate() }
}
