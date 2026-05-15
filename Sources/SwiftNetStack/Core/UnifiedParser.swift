import Darwin

// MARK: - Unified single-pass parser

/// Parse all frames in IOBuffer.input into ParseOutput SoA arrays.
/// Replaces the old 5-phase parse (Ethernet → dispatch → IPv4 → ARP → transport).
///
/// For each frame, the parser reads Ethernet/IPv4/transport headers directly from
/// the raw pointer and writes categorized results into ParseOutput arrays. No
/// intermediate allocations, no PacketBuffer, no per-frame heap objects.
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
                        let ihl = Int(ipPtr.load(fromByteOffset: 0, as: UInt8.self) & 0x0F)
                        let srcAddr = IPv4Address(UnsafeRawBufferPointer(start: ipPtr.advanced(by: 12), count: 4))
                        let dstAddr = IPv4Address(UnsafeRawBufferPointer(start: ipPtr.advanced(by: 16), count: 4))
                        let idx = out.unreachCount
                        if idx < out.maxFrames {
                            out.unreachEndpointIDs[idx] = epID
                            out.unreachSrcMACs[idx] = srcMAC
                            out.unreachGatewayIPs[idx] = dstAddr
                            out.unreachClientIPs[idx] = srcAddr
                            out.unreachRawOfs[idx] = i * mtu + ethHeaderLen
                            out.unreachRawLen[idx] = len - ethHeaderLen
                            out.unreachCodes[idx] = 0    // Time Exceeded
                            out.unreachTypes[idx] = 11   // Type 11
                            out.unreachCount += 1
                        }
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
    let idx = out.arpCount
    guard idx < out.maxFrames else { return }
    out.arpEndpointIDs[idx] = epID
    out.arpFrames[idx] = arp
    out.arpCount += 1
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
        let idx = out.fragmentCount
        guard idx < out.maxFrames else { return }
        out.fragmentEndpointIDs[idx] = epID
        out.fragmentSrcMACs[idx] = srcMAC
        out.fragmentSrcIPs[idx] = srcAddr
        out.fragmentDstIPs[idx] = dstAddr
        out.fragmentIdentifications[idx] = readUInt16BE(ipPtr, 4)
        out.fragmentFlagsFrags[idx] = flagsFrag
        out.fragmentProtocols[idx] = rawProtocol
        out.fragmentFrameIdxs[idx] = frameIdx
        out.fragmentFrameLens[idx] = frameLen
        out.fragmentIPHeaderLens[idx] = ihl * 4
        out.fragmentCount += 1
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
        let idx = out.unreachCount
        guard idx < out.maxFrames else { return }
        out.unreachEndpointIDs[idx] = epID
        out.unreachSrcMACs[idx] = srcMAC
        out.unreachGatewayIPs[idx] = dstAddr
        out.unreachClientIPs[idx] = srcAddr
        out.unreachRawOfs[idx] = baseOfs + ipOfs
        out.unreachRawLen[idx] = frameLen - ipOfs
        out.unreachCodes[idx] = 2   // Protocol Unreachable
        out.unreachTypes[idx] = 3   // Destination Unreachable
        out.unreachCount += 1
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
        let idx = out.icmpEchoCount
        guard idx < out.maxFrames else { return }
        let totalPayloadOfs = baseOfs + ipPayloadOfs
        out.icmpEchoEndpointIDs[idx] = epID
        out.icmpEchoSrcMACs[idx] = srcMAC
        out.icmpEchoSrcIPs[idx] = srcIP
        out.icmpEchoDstIPs[idx] = dstIP
        out.icmpEchoIDs[idx] = identifier
        out.icmpEchoSeqNums[idx] = sequenceNumber
        out.icmpEchoPayloadOfs[idx] = totalPayloadOfs + 8
        out.icmpEchoPayloadLen[idx] = len - 8
        out.icmpEchoPayloadSum[idx] = checksumAdd(0, UnsafeRawPointer(ptr.advanced(by: 8)), len - 8)
        out.icmpEchoCount += 1
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

    let idx = out.tcpCount
    guard idx < out.maxFrames else { return }

    out.tcpKeys[idx] = NATKey(vmIP: srcIP, vmPort: srcPort,
                               dstIP: dstIP, dstPort: dstPort, protocol: .tcp)
    out.tcpSegs[idx] = TCPSegmentInfo(seq: seqNum, ack: ackNum,
                                        flags: flags, window: window,
                                        peerWindowScale: peerWindowScale)
    out.tcpPayloadOfs[idx] = baseOfs + ipPayloadOfs + tcpHeaderLen
    out.tcpPayloadLen[idx] = len - tcpHeaderLen
    out.tcpEndpointIDs[idx] = epID
    out.tcpSrcMACs[idx] = srcMAC
    out.tcpCount += 1
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
        let idx = out.dhcpCount
        guard idx < out.maxFrames else { return }
        out.dhcpEndpointIDs[idx] = epID
        out.dhcpSrcMACs[idx] = srcMAC
        out.dhcpPackets[idx] = dhcp
        out.dhcpCount += 1
    } else if dstPort == 53 {
        // DNS
        let idx = out.dnsCount
        guard idx < out.maxFrames else { return }
        out.dnsEndpointIDs[idx] = epID
        out.dnsSrcMACs[idx] = srcMAC
        out.dnsSrcIPs[idx] = srcIP
        out.dnsDstIPs[idx] = dstIP
        out.dnsSrcPorts[idx] = srcPort
        out.dnsPayloadOfs[idx] = totalPayloadOfs + 8
        out.dnsPayloadLen[idx] = payloadLen
        out.dnsCount += 1
    } else {
        // Generic UDP
        let idx = out.udpCount
        guard idx < out.maxFrames else { return }
        out.udpEndpointIDs[idx] = epID
        out.udpSrcMACs[idx] = srcMAC
        out.udpSrcIPs[idx] = srcIP
        out.udpDstIPs[idx] = dstIP
        out.udpSrcPorts[idx] = srcPort
        out.udpDstPorts[idx] = dstPort
        out.udpPayloadOfs[idx] = totalPayloadOfs + 8
        out.udpPayloadLen[idx] = payloadLen
        out.udpIPHeaderLens[idx] = ipHeaderLen
        out.udpCount += 1
    }
}
