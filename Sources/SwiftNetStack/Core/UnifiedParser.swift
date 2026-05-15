import Darwin

// MARK: - Unified single-pass parser

/// Parse all frames in IOBuffer.input into protocol-grouped parse output.
///
/// For each frame, the parser reads Ethernet/IPv4/transport headers directly from
/// the raw pointer and writes categorized results into per-protocol groups.
/// TCP uses internal SoA (column-by-column access in processTCPRound).
/// All other protocols use dense struct arrays (whole-frame processing).
///
/// L2-forwarded frames (dstMAC is another VM endpoint) are added to `fwdBatch`
/// for immediate writing by the caller.
public func parseAllFrames(
    io: IOBuffer,
    out: ParseOutput,
    hostMAC: MACAddress,
    arpMapping: ARPMapping,
    fwdBatch: OutBatch
) {
    out.reset()
    fwdBatch.reset()
    let mtu = io.mtu

    for i in 0..<io.frameCount {
        let ptr = io.framePtr(i)
        let len = io.frameLengths[i]
        let epID = io.frameEndpointIDs[i]

        guard len >= 14 else { continue }

        // ── Ethernet ──
        let dstMAC = MACAddress(UnsafeRawBufferPointer(start: ptr, count: 6))
        let srcMAC = MACAddress(UnsafeRawBufferPointer(start: ptr.advanced(by: 6), count: 6))
        let etherTypeRaw = readUInt16BE(ptr, 12)

        // ── MAC filter ──
        if dstMAC != hostMAC && dstMAC != .broadcast {
            if let dstEp = arpMapping.lookupEndpoint(mac: dstMAC), dstEp != epID {
                // IPv4 L2 forwarding: decrement TTL before forwarding.
                if etherTypeRaw == 0x0800 {
                    let ipPtr = ptr.advanced(by: ethHeaderLen)
                    let ttlOK = decrementTTL(at: ipPtr)
                    if !ttlOK {
                        // TTL expired → ICMP Time Exceeded (Type 11 Code 0)
                        let srcAddr = IPv4Address(UnsafeRawBufferPointer(start: ipPtr.advanced(by: 12), count: 4))
                        let dstAddr = IPv4Address(UnsafeRawBufferPointer(start: ipPtr.advanced(by: 16), count: 4))
                        let idx = out.unreach.count
                        guard idx < out.unreach.capacity else { continue }
                        out.unreach.frames[idx] = ICMPUnreachParsedFrame(
                            endpointID: epID, srcMAC: srcMAC, gatewayIP: dstAddr, clientIP: srcAddr,
                            rawOfs: i * mtu + ethHeaderLen, rawLen: len - ethHeaderLen,
                            code: 0, type: 11)
                        out.unreach.count += 1
                        continue
                    }
                }
                let idx = fwdBatch.count
                guard idx < fwdBatch.maxFrames else { continue }
                fwdBatch.hdrOfs[idx] = i * mtu
                fwdBatch.hdrLen[idx] = len
                fwdBatch.payOfs[idx] = -1
                fwdBatch.payLen[idx] = 0
                fwdBatch.epIDs[idx] = dstEp
                fwdBatch.count += 1
            }
            continue
        }

        switch etherTypeRaw {
        case 0x0806:  // ARP
            parseOneARP(ptr: ptr.advanced(by: 14), len: len - 14,
                        epID: epID, out: out)

        case 0x0800:  // IPv4
            parseOneIPv4(framePtr: ptr, frameLen: len, frameIdx: i,
                         mtu: mtu, epID: epID, srcMAC: srcMAC, out: out)

        default:
            break
        }
    }
}

// MARK: - Per-protocol inline parsers (no allocs)

@inline(__always)
private func parseOneARP(
    ptr: UnsafeMutableRawPointer, len: Int, epID: Int, out: ParseOutput
) {
    guard let arp = ARPFrame.parse(from: UnsafeRawPointer(ptr), len: len) else { return }
    let idx = out.arp.count
    guard idx < out.arp.capacity else { return }
    out.arp.frames[idx] = ARPParsedFrame(endpointID: epID, frame: arp)
    out.arp.count += 1
}

@inline(__always)
private func parseOneIPv4(
    framePtr: UnsafeMutableRawPointer, frameLen: Int, frameIdx: Int,
    mtu: Int, epID: Int, srcMAC: MACAddress, out: ParseOutput
) {
    let ipOfs = ethHeaderLen  // 14
    guard frameLen >= ipOfs + 20 else { return }

    let ipPtr = framePtr.advanced(by: ipOfs)
    let ipBuf = UnsafeRawPointer(ipPtr).assumingMemoryBound(to: UInt8.self)

    let versionIHL = ipBuf[0]
    guard versionIHL >> 4 == 4 else { return }
    let ihl = Int(versionIHL & 0x0F)
    guard ihl >= 5, frameLen >= ipOfs + ihl * 4 else { return }

    let totalLength = Int(readUInt16BE(ipPtr, 2))
    let flagsFrag = readUInt16BE(ipPtr, 6)
    guard flagsFrag & 0x8000 == 0 else { return }  // reserved bit
    let rawProtocol = ipBuf[9]

    let srcAddr = IPv4Address(UnsafeRawBufferPointer(start: ipPtr.advanced(by: 12), count: 4))
    let dstAddr = IPv4Address(UnsafeRawBufferPointer(start: ipPtr.advanced(by: 16), count: 4))

    // Fragment detection: MF=1 (0x2000) or offset>0 (0x1FFF)
    let isFragment = (flagsFrag & 0x3FFF) != 0
    if isFragment {
        let idx = out.fragment.count
        guard idx < out.fragment.capacity else { return }
        out.fragment.frames[idx] = FragmentParsedFrame(
            endpointID: epID, srcMAC: srcMAC, srcIP: srcAddr, dstIP: dstAddr,
            identification: readUInt16BE(ipPtr, 4), flagsFrag: flagsFrag,
            ipProtocol: rawProtocol, frameIdx: frameIdx, frameLen: frameLen,
            ipHeaderLen: ihl * 4)
        out.fragment.count += 1
        return
    }

    let ipHeaderLen = ihl * 4
    let ipPayloadOfs = ipOfs + ipHeaderLen
    let ipPayloadLen = min(totalLength - ipHeaderLen, frameLen - ipPayloadOfs)
    guard ipPayloadLen >= 0 else { return }

    let baseOfs = frameIdx * mtu

    switch rawProtocol {
    case 1:  // ICMP
        parseOneICMP(ptr: framePtr.advanced(by: ipPayloadOfs), len: ipPayloadLen,
                     epID: epID, srcMAC: srcMAC, srcIP: srcAddr, dstIP: dstAddr,
                     baseOfs: baseOfs, ipPayloadOfs: ipPayloadOfs, out: out)

    case 6:  // TCP
        parseOneTCP(ptr: framePtr.advanced(by: ipPayloadOfs), len: ipPayloadLen,
                    epID: epID, srcMAC: srcMAC, srcIP: srcAddr, dstIP: dstAddr,
                    baseOfs: baseOfs, ipPayloadOfs: ipPayloadOfs, out: out)

    case 17: // UDP
        parseOneUDP(ptr: framePtr.advanced(by: ipPayloadOfs), len: ipPayloadLen,
                    epID: epID, srcMAC: srcMAC, srcIP: srcAddr, dstIP: dstAddr,
                    baseOfs: baseOfs, ipPayloadOfs: ipPayloadOfs,
                    ipHeaderLen: ipHeaderLen, out: out)

    default:
        // Unknown protocol → ICMP unreachable
        let idx = out.unreach.count
        guard idx < out.unreach.capacity else { return }
        out.unreach.frames[idx] = ICMPUnreachParsedFrame(
            endpointID: epID, srcMAC: srcMAC, gatewayIP: dstAddr, clientIP: srcAddr,
            rawOfs: baseOfs + ipOfs, rawLen: frameLen - ipOfs,
            code: 2, type: 3)
        out.unreach.count += 1
    }
}

@inline(__always)
private func parseOneICMP(
    ptr: UnsafeMutableRawPointer, len: Int,
    epID: Int, srcMAC: MACAddress, srcIP: IPv4Address, dstIP: IPv4Address,
    baseOfs: Int, ipPayloadOfs: Int, out: ParseOutput
) {
    guard len >= 8 else { return }
    let icmpBuf = UnsafeRawPointer(ptr).assumingMemoryBound(to: UInt8.self)
    let icmpType = icmpBuf[0]
    let icmpCode = icmpBuf[1]
    let identifier = readUInt16BE(ptr, 4)
    let sequenceNumber = readUInt16BE(ptr, 6)

    if icmpType == 8, icmpCode == 0 {
        let idx = out.icmpEcho.count
        guard idx < out.icmpEcho.capacity else { return }
        let totalPayloadOfs = baseOfs + ipPayloadOfs
        out.icmpEcho.frames[idx] = ICMPEchoParsedFrame(
            endpointID: epID, srcMAC: srcMAC, srcIP: srcIP, dstIP: dstIP,
            identifier: identifier, sequenceNumber: sequenceNumber,
            payloadOfs: totalPayloadOfs + 8, payloadLen: len - 8,
            payloadSum: checksumAdd(0, UnsafeRawPointer(ptr.advanced(by: 8)), len - 8))
        out.icmpEcho.count += 1
    }
    // Non-echo ICMP is silently ignored
}

@inline(__always)
private func parseOneTCP(
    ptr: UnsafeMutableRawPointer, len: Int,
    epID: Int, srcMAC: MACAddress, srcIP: IPv4Address, dstIP: IPv4Address,
    baseOfs: Int, ipPayloadOfs: Int, out: ParseOutput
) {
    guard len >= 20 else { return }
    let tcpBuf = UnsafeRawPointer(ptr).assumingMemoryBound(to: UInt8.self)

    let srcPort = readUInt16BE(ptr, 0)
    let dstPort = readUInt16BE(ptr, 2)
    let seqNum  = readUInt32BE(ptr, 4)
    let ackNum  = readUInt32BE(ptr, 8)

    let dataOff = tcpBuf[12] >> 4
    guard dataOff >= 5, dataOff <= 15 else { return }
    let tcpHeaderLen = Int(dataOff) * 4
    guard len >= tcpHeaderLen else { return }

    let flags = TCPFlags(rawValue: tcpBuf[13])
    let window = readUInt16BE(ptr, 14)

    var peerWindowScale: UInt8 = 0

    if tcpHeaderLen > 20 {
        var optOfs = 20
        while optOfs < tcpHeaderLen {
            let kind = tcpBuf[optOfs]
            if kind == 0 { break }
            if kind == 1 { optOfs += 1; continue }
            if optOfs + 1 >= tcpHeaderLen { break }
            let optLen = Int(tcpBuf[optOfs + 1])
            if optLen < 2 || optOfs + optLen > tcpHeaderLen { break }

            if flags.isSyn, kind == 3, optLen == 3 {  // WSCALE
                peerWindowScale = min(tcpBuf[optOfs + 2], 14)
            }

            optOfs += optLen
        }
    }

    let idx = out.tcp.count
    guard idx < out.tcp.capacity else { return }

    out.tcp.keys[idx] = NATKey(vmIP: srcIP, vmPort: srcPort,
                               dstIP: dstIP, dstPort: dstPort, protocol: .tcp)
    out.tcp.segs[idx] = TCPSegmentInfo(seq: seqNum, ack: ackNum,
                                        flags: flags, window: window,
                                        peerWindowScale: peerWindowScale)
    out.tcp.payloadOfs[idx] = baseOfs + ipPayloadOfs + tcpHeaderLen
    out.tcp.payloadLen[idx] = len - tcpHeaderLen
    out.tcp.endpointIDs[idx] = epID
    out.tcp.srcMACs[idx] = srcMAC
    out.tcp.count += 1
}

@inline(__always)
private func parseOneUDP(
    ptr: UnsafeMutableRawPointer, len: Int,
    epID: Int, srcMAC: MACAddress, srcIP: IPv4Address, dstIP: IPv4Address,
    baseOfs: Int, ipPayloadOfs: Int, ipHeaderLen: Int, out: ParseOutput
) {
    guard len >= 8 else { return }

    let srcPort = readUInt16BE(ptr, 0)
    let dstPort = readUInt16BE(ptr, 2)
    let udpLength = Int(readUInt16BE(ptr, 4))
    let udpLen = min(udpLength, len)
    guard udpLen >= 8 else { return }

    let totalPayloadOfs = baseOfs + ipPayloadOfs
    let payloadLen = udpLen - 8

    // Dispatch by port
    if dstPort == 67 || srcPort == 67 {
        // DHCP
        guard let dhcp = DHCPPacket.parse(from: UnsafeRawPointer(ptr.advanced(by: 8)),
                                           len: payloadLen) else { return }
        let idx = out.dhcp.count
        guard idx < out.dhcp.capacity else { return }
        out.dhcp.frames[idx] = DHCPParsedFrame(endpointID: epID, srcMAC: srcMAC, packet: dhcp)
        out.dhcp.count += 1
    } else if dstPort == 53 {
        // DNS
        let idx = out.dns.count
        guard idx < out.dns.capacity else { return }
        out.dns.frames[idx] = DNSParsedFrame(
            endpointID: epID, srcMAC: srcMAC, srcIP: srcIP, dstIP: dstIP,
            srcPort: srcPort, payloadOfs: totalPayloadOfs + 8, payloadLen: payloadLen)
        out.dns.count += 1
    } else {
        // Generic UDP
        let idx = out.udp.count
        guard idx < out.udp.capacity else { return }
        out.udp.frames[idx] = UDPParsedFrame(
            endpointID: epID, srcMAC: srcMAC, srcIP: srcIP, dstIP: dstIP,
            srcPort: srcPort, dstPort: dstPort,
            payloadOfs: totalPayloadOfs + 8, payloadLen: payloadLen,
            ipHeaderLen: ipHeaderLen)
        out.udp.count += 1
    }
}
