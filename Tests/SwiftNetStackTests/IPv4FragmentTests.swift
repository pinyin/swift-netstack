import Testing
@testable import SwiftNetStack
import Darwin

// MARK: - IPv4 Fragment Detection

@Test func fragmentDetection_mfFlagPreventsTransportDispatch() {
    let io = IOBuffer(maxFrames: 4, mtu: 2048)
    let out = ParseOutput()
    let fwd = OutBatch(maxFrames: 4)
    let hostMAC = MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF)
    let arp = ARPMapping(hostMAC: hostMAC, endpoints: [])

    // Write Ethernet + IPv4 fragment (MF=1, offset=0) into frame 0
    let ptr = io.framePtr(0)
    writeTestIPv4Frame(
        to: ptr, dstMAC: hostMAC, srcMAC: MACAddress(0x11, 0x22, 0x33, 0x44, 0x55, 0x66),
        id: 0x1234, mf: true, offset: 0,
        srcIP: IPv4Address(10, 0, 0, 1), dstIP: IPv4Address(10, 0, 0, 2),
        protocol: 6, payloadLen: 20
    )
    io.frameLengths[0] = ethHeaderLen + ipv4HeaderLen + 20
    io.frameEndpointIDs[0] = 0
    io.frameCount = 1

    parseAllFrames(io: io, out: out, hostMAC: hostMAC, arpMapping: arp, fwdBatch: fwd)

    // Fragment should NOT reach TCP
    #expect(out.tcp.count == 0, "MF=1 packet not handed to TCP")
    // Fragment should be recorded
    #expect(out.fragment.count == 1, "fragment tracked in ParseOutput")
}

@Test func fragmentDetection_nonZeroOffsetPreventsTransportDispatch() {
    let io = IOBuffer(maxFrames: 4, mtu: 2048)
    let out = ParseOutput()
    let fwd = OutBatch(maxFrames: 4)
    let hostMAC = MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF)
    let arp = ARPMapping(hostMAC: hostMAC, endpoints: [])

    let ptr = io.framePtr(0)
    writeTestIPv4Frame(
        to: ptr, dstMAC: hostMAC, srcMAC: MACAddress(0x11, 0x22, 0x33, 0x44, 0x55, 0x66),
        id: 0x5678, mf: false, offset: 100,  // offset 100*8 = 800 bytes
        srcIP: IPv4Address(10, 0, 0, 1), dstIP: IPv4Address(10, 0, 0, 2),
        protocol: 17, payloadLen: 20
    )
    io.frameLengths[0] = ethHeaderLen + ipv4HeaderLen + 20
    io.frameEndpointIDs[0] = 0
    io.frameCount = 1

    parseAllFrames(io: io, out: out, hostMAC: hostMAC, arpMapping: arp, fwdBatch: fwd)

    #expect(out.udp.count == 0, "offset>0 packet not handed to UDP")
    #expect(out.fragment.count == 1, "fragment tracked in ParseOutput")
}

@Test func fragmentDetection_nonFragmentedStillWorks() {
    // Regression: non-fragmented packets should still work normally
    let io = IOBuffer(maxFrames: 4, mtu: 2048)
    let out = ParseOutput()
    let fwd = OutBatch(maxFrames: 4)
    let hostMAC = MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF)
    let arp = ARPMapping(hostMAC: hostMAC, endpoints: [])

    let payloadLen = 20
    let ptr = io.framePtr(0)
    writeTestIPv4Frame(
        to: ptr, dstMAC: hostMAC, srcMAC: MACAddress(0x11, 0x22, 0x33, 0x44, 0x55, 0x66),
        id: 0x42, mf: false, offset: 0,  // non-fragmented
        srcIP: IPv4Address(10, 0, 0, 1), dstIP: IPv4Address(10, 0, 0, 2),
        protocol: 17, payloadLen: payloadLen
    )
    // Write a valid minimal UDP header so parseOneUDP accepts it.
    // UDP hdr: srcPort=1234, dstPort=5678, length=payloadLen, checksum=0
    let udpPtr = ptr.advanced(by: ethHeaderLen + ipv4HeaderLen)
    writeUInt16BE(1234, to: udpPtr)
    writeUInt16BE(5678, to: udpPtr.advanced(by: 2))
    writeUInt16BE(UInt16(payloadLen), to: udpPtr.advanced(by: 4))
    writeUInt16BE(0, to: udpPtr.advanced(by: 6))

    io.frameLengths[0] = ethHeaderLen + ipv4HeaderLen + payloadLen
    io.frameEndpointIDs[0] = 0
    io.frameCount = 1

    parseAllFrames(io: io, out: out, hostMAC: hostMAC, arpMapping: arp, fwdBatch: fwd)

    #expect(out.udp.count == 1, "non-fragmented packet reaches UDP parser")
    #expect(out.fragment.count == 0, "no fragments for non-fragmented packet")
}

// MARK: - Fragment Reassembly State Machine

@Test func fragmentReassembly_twoFragments_reassembles() {
    var reassembly = FragmentReassembly(maxReassemblies: 8)
    let io = IOBuffer(maxFrames: 8, mtu: 2048)

    // Fragment 1: offset=0, MF=1, 16 bytes (non-last must be multiple of 8)
    let ptr0 = io.framePtr(0)
    writeTestIPv4Frame(
        to: ptr0, dstMAC: MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF),
        srcMAC: MACAddress(0x11, 0x22, 0x33, 0x44, 0x55, 0x66),
        id: 0x42, mf: true, offset: 0,
        srcIP: IPv4Address(10, 0, 0, 1), dstIP: IPv4Address(10, 0, 0, 2),
        protocol: 6, payloadLen: 16
    )
    io.frameLengths[0] = ethHeaderLen + ipv4HeaderLen + 16
    io.frameEndpointIDs[0] = 0

    // Fragment 2: offset=2 (16 bytes), MF=0, 14 bytes (last fragment)
    let ptr1 = io.framePtr(1)
    writeTestIPv4Frame(
        to: ptr1, dstMAC: MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF),
        srcMAC: MACAddress(0x11, 0x22, 0x33, 0x44, 0x55, 0x66),
        id: 0x42, mf: false, offset: 2,  // byte offset = 2*8 = 16
        srcIP: IPv4Address(10, 0, 0, 1), dstIP: IPv4Address(10, 0, 0, 2),
        protocol: 6, payloadLen: 14
    )
    io.frameLengths[1] = ethHeaderLen + ipv4HeaderLen + 14
    io.frameEndpointIDs[1] = 0

    // Process fragment 1
    let r1 = reassembly.processFragment(
        framePtr: ptr0, frameLen: io.frameLengths[0], frameIndex: 0,
        identification: 0x42, flagsFrag: 0x2000,
        srcIP: IPv4Address(10, 0, 0, 1), dstIP: IPv4Address(10, 0, 0, 2),
        protocol: 6, now: 0, io: io
    )
    #expect(r1 == nil, "first fragment: still collecting")

    // Process fragment 2
    let r2 = reassembly.processFragment(
        framePtr: ptr1, frameLen: io.frameLengths[1], frameIndex: 1,
        identification: 0x42, flagsFrag: 0x0002,  // offset=2, MF=0
        srcIP: IPv4Address(10, 0, 0, 1), dstIP: IPv4Address(10, 0, 0, 2),
        protocol: 6, now: 0, io: io
    )
    #expect(r2 != nil, "last fragment: reassembly complete")
    if let r2 {
        #expect(r2.len == 30, "total reassembled length = 16+14 = 30")
    }
}

@Test func fragmentReassembly_contentIsCopiedCorrectly() {
    var reassembly = FragmentReassembly(maxReassemblies: 8)
    let io = IOBuffer(maxFrames: 8, mtu: 2048)

    // Fragment 1: offset=0, MF=1, 16 bytes filled with 0xAA
    let ptr0 = io.framePtr(0)
    writeTestIPv4Frame(
        to: ptr0, dstMAC: MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF),
        srcMAC: MACAddress(0x11, 0x22, 0x33, 0x44, 0x55, 0x66),
        id: 0x77, mf: true, offset: 0,
        srcIP: IPv4Address(10, 0, 0, 1), dstIP: IPv4Address(10, 0, 0, 2),
        protocol: 6, payloadLen: 16
    )
    let pay0 = ptr0.advanced(by: ethHeaderLen + ipv4HeaderLen)
    pay0.initializeMemory(as: UInt8.self, repeating: 0xAA, count: 16)
    io.frameLengths[0] = ethHeaderLen + ipv4HeaderLen + 16
    io.frameEndpointIDs[0] = 0

    // Fragment 2: offset=2 (16 bytes), MF=0, 14 bytes filled with 0xBB
    let ptr1 = io.framePtr(1)
    writeTestIPv4Frame(
        to: ptr1, dstMAC: MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF),
        srcMAC: MACAddress(0x11, 0x22, 0x33, 0x44, 0x55, 0x66),
        id: 0x77, mf: false, offset: 2,
        srcIP: IPv4Address(10, 0, 0, 1), dstIP: IPv4Address(10, 0, 0, 2),
        protocol: 6, payloadLen: 14
    )
    let pay1 = ptr1.advanced(by: ethHeaderLen + ipv4HeaderLen)
    pay1.initializeMemory(as: UInt8.self, repeating: 0xBB, count: 14)
    io.frameLengths[1] = ethHeaderLen + ipv4HeaderLen + 14
    io.frameEndpointIDs[1] = 0

    // Process fragment 1
    _ = reassembly.processFragment(
        framePtr: ptr0, frameLen: io.frameLengths[0], frameIndex: 0,
        identification: 0x77, flagsFrag: 0x2000,
        srcIP: IPv4Address(10, 0, 0, 1), dstIP: IPv4Address(10, 0, 0, 2),
        protocol: 6, now: 0, io: io
    )

    // Process fragment 2 → reassembly complete
    let r2 = reassembly.processFragment(
        framePtr: ptr1, frameLen: io.frameLengths[1], frameIndex: 1,
        identification: 0x77, flagsFrag: 0x0002,
        srcIP: IPv4Address(10, 0, 0, 1), dstIP: IPv4Address(10, 0, 0, 2),
        protocol: 6, now: 0, io: io
    )
    #expect(r2 != nil, "reassembly complete")
    if let r2 {
        #expect(r2.len == 30, "total length = 30")
        let outBuf = UnsafeRawBufferPointer(start: r2.ptr, count: r2.len)
        // First 16 bytes should be 0xAA (fragment 1)
        for i in 0..<16 {
            #expect(outBuf[i] == 0xAA, "byte \(i) is from fragment 1")
        }
        // Last 14 bytes should be 0xBB (fragment 2)
        for i in 16..<30 {
            #expect(outBuf[i] == 0xBB, "byte \(i) is from fragment 2")
        }
    }
}

@Test func fragmentReassembly_timeoutCleansUp() {
    var reassembly = FragmentReassembly(maxReassemblies: 4)
    let io = IOBuffer(maxFrames: 4, mtu: 2048)

    let ptr = io.framePtr(0)
    writeTestIPv4Frame(
        to: ptr, dstMAC: MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF),
        srcMAC: MACAddress(0x11, 0x22, 0x33, 0x44, 0x55, 0x66),
        id: 0x99, mf: true, offset: 0,
        srcIP: IPv4Address(10, 0, 0, 1), dstIP: IPv4Address(10, 0, 0, 2),
        protocol: 6, payloadLen: 100
    )
    io.frameLengths[0] = ethHeaderLen + ipv4HeaderLen + 100
    io.frameEndpointIDs[0] = 0

    _ = reassembly.processFragment(
        framePtr: ptr, frameLen: io.frameLengths[0], frameIndex: 0,
        identification: 0x99, flagsFrag: 0x2000,
        srcIP: IPv4Address(10, 0, 0, 1), dstIP: IPv4Address(10, 0, 0, 2),
        protocol: 6, now: 0, io: io
    )

    // Reap expired entries (timeout=30, now=31)
    let reaped = reassembly.reapExpired(now: 31, timeout: 30)
    #expect(reaped > 0, "at least one reassembly reaped on timeout")
    #expect(reassembly.activeCount == 0, "all reassemblies cleaned up")
}

@Test func fragmentOffsetParsing() {
    // MF=1, offset=0
    let f1 = fragmentOffset(from: 0x2000)
    #expect(f1.mf == true)
    #expect(f1.offset == 0)

    // MF=0, offset=20 (20*8=160 bytes → 160/8=20 in field)
    let f2 = fragmentOffset(from: 0x0014)
    #expect(f2.mf == false)
    #expect(f2.offset == 20)

    // MF=0, offset=0 (normal non-fragmented with DF=1)
    let f3 = fragmentOffset(from: 0x4000)
    #expect(f3.mf == false)
    #expect(f3.offset == 0)
}

// MARK: - Fragment overlap / duplicate detection (Fix 3)

@Test func fragmentReassembly_overlappingFragments_aborted() {
    var reassembly = FragmentReassembly(maxReassemblies: 8)
    let io = IOBuffer(maxFrames: 8, mtu: 2048)

    // Fragment 1: offset=0, MF=1, 16 bytes
    let ptr0 = io.framePtr(0)
    writeTestIPv4Frame(
        to: ptr0, dstMAC: MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF),
        srcMAC: MACAddress(0x11, 0x22, 0x33, 0x44, 0x55, 0x66),
        id: 0x42, mf: true, offset: 0,
        srcIP: IPv4Address(10, 0, 0, 1), dstIP: IPv4Address(10, 0, 0, 2),
        protocol: 6, payloadLen: 16
    )
    io.frameLengths[0] = ethHeaderLen + ipv4HeaderLen + 16
    io.frameEndpointIDs[0] = 0

    // Fragment 2: offset=0 (overlapping start), MF=0, 12 bytes — overlaps [0,16) with [0,12)
    let ptr1 = io.framePtr(1)
    writeTestIPv4Frame(
        to: ptr1, dstMAC: MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF),
        srcMAC: MACAddress(0x11, 0x22, 0x33, 0x44, 0x55, 0x66),
        id: 0x42, mf: false, offset: 0,
        srcIP: IPv4Address(10, 0, 0, 1), dstIP: IPv4Address(10, 0, 0, 2),
        protocol: 6, payloadLen: 12
    )
    io.frameLengths[1] = ethHeaderLen + ipv4HeaderLen + 12
    io.frameEndpointIDs[1] = 0

    _ = reassembly.processFragment(
        framePtr: ptr0, frameLen: io.frameLengths[0], frameIndex: 0,
        identification: 0x42, flagsFrag: 0x2000,
        srcIP: IPv4Address(10, 0, 0, 1), dstIP: IPv4Address(10, 0, 0, 2),
        protocol: 6, now: 0, io: io
    )

    let r2 = reassembly.processFragment(
        framePtr: ptr1, frameLen: io.frameLengths[1], frameIndex: 1,
        identification: 0x42, flagsFrag: 0x0000,
        srcIP: IPv4Address(10, 0, 0, 1), dstIP: IPv4Address(10, 0, 0, 2),
        protocol: 6, now: 0, io: io
    )
    #expect(r2 == nil, "overlapping fragment must abort reassembly")
}

@Test func fragmentReassembly_duplicateFragment_aborted() {
    var reassembly = FragmentReassembly(maxReassemblies: 8)
    let io = IOBuffer(maxFrames: 8, mtu: 2048)

    // Fragment 1: offset=0, MF=1, 16 bytes
    let ptr0 = io.framePtr(0)
    writeTestIPv4Frame(
        to: ptr0, dstMAC: MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF),
        srcMAC: MACAddress(0x11, 0x22, 0x33, 0x44, 0x55, 0x66),
        id: 0x99, mf: true, offset: 0,
        srcIP: IPv4Address(10, 0, 0, 1), dstIP: IPv4Address(10, 0, 0, 2),
        protocol: 6, payloadLen: 16
    )
    io.frameLengths[0] = ethHeaderLen + ipv4HeaderLen + 16
    io.frameEndpointIDs[0] = 0

    // Fragment 2: exact duplicate of fragment 1
    let ptr1 = io.framePtr(1)
    writeTestIPv4Frame(
        to: ptr1, dstMAC: MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF),
        srcMAC: MACAddress(0x11, 0x22, 0x33, 0x44, 0x55, 0x66),
        id: 0x99, mf: true, offset: 0,
        srcIP: IPv4Address(10, 0, 0, 1), dstIP: IPv4Address(10, 0, 0, 2),
        protocol: 6, payloadLen: 16
    )
    io.frameLengths[1] = ethHeaderLen + ipv4HeaderLen + 16
    io.frameEndpointIDs[1] = 0

    _ = reassembly.processFragment(
        framePtr: ptr0, frameLen: io.frameLengths[0], frameIndex: 0,
        identification: 0x99, flagsFrag: 0x2000,
        srcIP: IPv4Address(10, 0, 0, 1), dstIP: IPv4Address(10, 0, 0, 2),
        protocol: 6, now: 0, io: io
    )

    let r2 = reassembly.processFragment(
        framePtr: ptr1, frameLen: io.frameLengths[1], frameIndex: 1,
        identification: 0x99, flagsFrag: 0x2000,
        srcIP: IPv4Address(10, 0, 0, 1), dstIP: IPv4Address(10, 0, 0, 2),
        protocol: 6, now: 0, io: io
    )
    #expect(r2 == nil, "duplicate fragment must abort reassembly")
}

@Test func fragmentReassembly_conflictingLastFragment_aborted() {
    var reassembly = FragmentReassembly(maxReassemblies: 8)
    let io = IOBuffer(maxFrames: 8, mtu: 2048)

    // Fragment 1: MF=0, offset=2 (16 bytes), sets totalLen=16+8=24
    let ptr0 = io.framePtr(0)
    writeTestIPv4Frame(
        to: ptr0, dstMAC: MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF),
        srcMAC: MACAddress(0x11, 0x22, 0x33, 0x44, 0x55, 0x66),
        id: 0x77, mf: false, offset: 2,
        srcIP: IPv4Address(10, 0, 0, 1), dstIP: IPv4Address(10, 0, 0, 2),
        protocol: 6, payloadLen: 8
    )
    io.frameLengths[0] = ethHeaderLen + ipv4HeaderLen + 8
    io.frameEndpointIDs[0] = 0

    // Fragment 2: MF=0, offset=3 (24 bytes), different totalLen=24+10=34
    let ptr1 = io.framePtr(1)
    writeTestIPv4Frame(
        to: ptr1, dstMAC: MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF),
        srcMAC: MACAddress(0x11, 0x22, 0x33, 0x44, 0x55, 0x66),
        id: 0x77, mf: false, offset: 3,
        srcIP: IPv4Address(10, 0, 0, 1), dstIP: IPv4Address(10, 0, 0, 2),
        protocol: 6, payloadLen: 10
    )
    io.frameLengths[1] = ethHeaderLen + ipv4HeaderLen + 10
    io.frameEndpointIDs[1] = 0

    _ = reassembly.processFragment(
        framePtr: ptr0, frameLen: io.frameLengths[0], frameIndex: 0,
        identification: 0x77, flagsFrag: 0x0002,
        srcIP: IPv4Address(10, 0, 0, 1), dstIP: IPv4Address(10, 0, 0, 2),
        protocol: 6, now: 0, io: io
    )

    let r2 = reassembly.processFragment(
        framePtr: ptr1, frameLen: io.frameLengths[1], frameIndex: 1,
        identification: 0x77, flagsFrag: 0x0003,
        srcIP: IPv4Address(10, 0, 0, 1), dstIP: IPv4Address(10, 0, 0, 2),
        protocol: 6, now: 0, io: io
    )
    #expect(r2 == nil, "conflicting MF=0 fragment must abort reassembly")
}

// MARK: - IHL > 5 fragment reassembly (Fix 2)

@Test func fragmentReassembly_ipOptionsHeader_respectsIHL() {
    var reassembly = FragmentReassembly(maxReassemblies: 8)
    let io = IOBuffer(maxFrames: 4, mtu: 2048)

    // Build a fragment with IP options (IHL=6, 24-byte header).
    // Fragment 1: offset=0, MF=1, 16 bytes payload
    let ptr0 = io.framePtr(0)
    // Ethernet
    let dstMAC = MACAddress(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF)
    let srcMAC = MACAddress(0x11, 0x22, 0x33, 0x44, 0x55, 0x66)
    dstMAC.write(to: ptr0)
    srcMAC.write(to: ptr0.advanced(by: 6))
    writeUInt16BE(0x0800, to: ptr0.advanced(by: 12))
    // IPv4 with IHL=6 (24 bytes): version=4, IHL=6 → 0x46
    let ipPtr0 = ptr0.advanced(by: ethHeaderLen)
    let totalLen = UInt16(24 + 16)  // header(24) + payload(16) = 40
    ipPtr0.storeBytes(of: UInt8(0x46), as: UInt8.self)  // IHL=6
    ipPtr0.advanced(by: 1).storeBytes(of: UInt8(0), as: UInt8.self)
    writeUInt16BE(totalLen, to: ipPtr0.advanced(by: 2))
    writeUInt16BE(0x1234, to: ipPtr0.advanced(by: 4))
    writeUInt16BE(0x2000, to: ipPtr0.advanced(by: 6))  // MF=1, offset=0
    ipPtr0.advanced(by: 8).storeBytes(of: UInt8(64), as: UInt8.self)
    ipPtr0.advanced(by: 9).storeBytes(of: UInt8(6), as: UInt8.self)  // TCP
    writeUInt16BE(0, to: ipPtr0.advanced(by: 10))  // checksum placeholder
    IPv4Address(10, 0, 0, 1).write(to: ipPtr0.advanced(by: 12))
    IPv4Address(10, 0, 0, 2).write(to: ipPtr0.advanced(by: 16))
    // 4-byte IP option (padding)
    ipPtr0.advanced(by: 20).storeBytes(of: UInt32(0), as: UInt32.self)
    let ck0 = internetChecksum(UnsafeRawBufferPointer(start: ipPtr0, count: 24))
    writeUInt16BE(ck0, to: ipPtr0.advanced(by: 10))
    // Payload at offset 14+24=38
    let pay0 = ptr0.advanced(by: ethHeaderLen + 24)
    pay0.initializeMemory(as: UInt8.self, repeating: 0xCC, count: 16)
    io.frameLengths[0] = ethHeaderLen + 24 + 16
    io.frameEndpointIDs[0] = 0

    // Fragment 2: offset=2 (16 bytes), MF=0, 12 bytes
    let ptr1 = io.framePtr(1)
    dstMAC.write(to: ptr1)
    srcMAC.write(to: ptr1.advanced(by: 6))
    writeUInt16BE(0x0800, to: ptr1.advanced(by: 12))
    let ipPtr1 = ptr1.advanced(by: ethHeaderLen)
    let totalLen2 = UInt16(24 + 12)
    ipPtr1.storeBytes(of: UInt8(0x46), as: UInt8.self)  // IHL=6
    ipPtr1.advanced(by: 1).storeBytes(of: UInt8(0), as: UInt8.self)
    writeUInt16BE(totalLen2, to: ipPtr1.advanced(by: 2))
    writeUInt16BE(0x1234, to: ipPtr1.advanced(by: 4))
    writeUInt16BE(0x0002, to: ipPtr1.advanced(by: 6))  // MF=0, offset=2
    ipPtr1.advanced(by: 8).storeBytes(of: UInt8(64), as: UInt8.self)
    ipPtr1.advanced(by: 9).storeBytes(of: UInt8(6), as: UInt8.self)
    writeUInt16BE(0, to: ipPtr1.advanced(by: 10))
    IPv4Address(10, 0, 0, 1).write(to: ipPtr1.advanced(by: 12))
    IPv4Address(10, 0, 0, 2).write(to: ipPtr1.advanced(by: 16))
    ipPtr1.advanced(by: 20).storeBytes(of: UInt32(0), as: UInt32.self)
    let ck1 = internetChecksum(UnsafeRawBufferPointer(start: ipPtr1, count: 24))
    writeUInt16BE(ck1, to: ipPtr1.advanced(by: 10))
    let pay1 = ptr1.advanced(by: ethHeaderLen + 24)
    pay1.initializeMemory(as: UInt8.self, repeating: 0xDD, count: 12)
    io.frameLengths[1] = ethHeaderLen + 24 + 12
    io.frameEndpointIDs[1] = 0

    // Process with ipHeaderLen=24
    _ = reassembly.processFragment(
        framePtr: ptr0, frameLen: io.frameLengths[0], frameIndex: 0,
        identification: 0x1234, flagsFrag: 0x2000,
        srcIP: IPv4Address(10, 0, 0, 1), dstIP: IPv4Address(10, 0, 0, 2),
        protocol: 6, now: 0, io: io,
        ipHeaderLen: 24
    )

    let r2 = reassembly.processFragment(
        framePtr: ptr1, frameLen: io.frameLengths[1], frameIndex: 1,
        identification: 0x1234, flagsFrag: 0x0002,
        srcIP: IPv4Address(10, 0, 0, 1), dstIP: IPv4Address(10, 0, 0, 2),
        protocol: 6, now: 0, io: io,
        ipHeaderLen: 24
    )
    #expect(r2 != nil, "fragments with IP options (IHL=6) must reassemble")
    if let r2 {
        #expect(r2.len == 28, "total reassembled length = 16+12 = 28")
        let buf = UnsafeRawBufferPointer(start: r2.ptr, count: r2.len)
        for i in 0..<16 { #expect(buf[i] == 0xCC, "byte \(i) from fragment 1") }
        for i in 16..<28 { #expect(buf[i] == 0xDD, "byte \(i) from fragment 2") }
    }
}

// MARK: - Helpers

/// (mf: Bool, offset: Int) — offset in 8-byte units as stored in the IP header field.
private struct FragInfo {
    let mf: Bool
    let offset: Int  // in 8-byte units
}

/// Extract MF flag and fragment offset from the raw 16-bit flags+fragment-offset field.
private func fragmentOffset(from raw: UInt16) -> FragInfo {
    FragInfo(
        mf: (raw & 0x2000) != 0,
        offset: Int(raw & 0x1FFF)
    )
}

/// Write a minimal Ethernet+IPv4 frame to `ptr`. Payload data is left as whatever is in the buffer.
/// `offset` is in 8-byte units (as stored in the IP fragment offset field).
private func writeTestIPv4Frame(
    to ptr: UnsafeMutableRawPointer,
    dstMAC: MACAddress, srcMAC: MACAddress,
    id: UInt16, mf: Bool, offset: Int,
    srcIP: IPv4Address, dstIP: IPv4Address,
    protocol ipProto: UInt8, payloadLen: Int
) {
    // Ethernet
    dstMAC.write(to: ptr)
    srcMAC.write(to: ptr.advanced(by: 6))
    writeUInt16BE(0x0800, to: ptr.advanced(by: 12))

    // IPv4
    let totalLen = UInt16(ipv4HeaderLen + payloadLen)
    let ipPtr = ptr.advanced(by: ethHeaderLen)
    var flagsFrag: UInt16 = UInt16(offset) & 0x1FFF
    if mf { flagsFrag |= 0x2000 }

    ipPtr.storeBytes(of: UInt8(0x45), as: UInt8.self)  // version=4, IHL=5
    ipPtr.advanced(by: 1).storeBytes(of: UInt8(0), as: UInt8.self)  // DSCP+ECN
    writeUInt16BE(totalLen, to: ipPtr.advanced(by: 2))
    writeUInt16BE(id, to: ipPtr.advanced(by: 4))
    writeUInt16BE(flagsFrag, to: ipPtr.advanced(by: 6))
    ipPtr.advanced(by: 8).storeBytes(of: UInt8(64), as: UInt8.self)  // TTL
    ipPtr.advanced(by: 9).storeBytes(of: ipProto, toByteOffset: 0, as: UInt8.self)
    writeUInt16BE(0, to: ipPtr.advanced(by: 10))  // checksum placeholder
    srcIP.write(to: ipPtr.advanced(by: 12))
    dstIP.write(to: ipPtr.advanced(by: 16))
    let ck = internetChecksum(UnsafeRawBufferPointer(start: ipPtr, count: 20))
    writeUInt16BE(ck, to: ipPtr.advanced(by: 10))
}
