/// Result of one-pass frame classification.
/// Frames are parsed and categorized by EtherType and IP protocol.
public struct ClassifiedFrames {
    public var arp: [(EthernetFrame, ARPFrame)] = []
    public var ipv4ICMP: [(EthernetFrame, IPv4Header)] = []
    public var ipv4TCP: [(EthernetFrame, IPv4Header)] = []
    public var ipv4UDP: [(EthernetFrame, IPv4Header)] = []
    public var ipv4Unknown: [(EthernetFrame, IPv4Header)] = []
    public var unknown: [PacketBuffer] = []

    /// Total number of classified frames across all categories.
    public var totalCount: Int {
        arp.count + ipv4ICMP.count + ipv4TCP.count
        + ipv4UDP.count + ipv4Unknown.count + unknown.count
    }

    public init() {}
}

/// BDP phase-separated frame classification.
///
/// Stateless utility: takes raw PacketBuffers, returns parsed+classified frames.
/// Unlike `bdpRound`, this function does NOT track endpoint IDs — it is suitable
/// for off-path analysis, testing, and contexts where endpoint routing isn't
/// needed. The production data path uses `bdpRound` directly so it can tag each
/// frame with its source endpoint for reply routing.
///
/// Instead of per-packet parse→classify→dispatch (which interleaves Ethernet,
/// IPv4, and ARP code within the same loop body), this splits processing into
/// four distinct phases. Each phase keeps a single code path in L1 cache:
///
///   Phase 1: Parse ALL Ethernet headers  (EthernetFrame.parse, ~15 insns)
///   Phase 2: MAC filter + EtherType dispatch  (branch logic only)
///   Phase 3: Parse ALL IPv4 headers     (IPv4Header.parse, ~25 insns)
///   Phase 4: Parse ALL ARP frames       (ARPFrame.parse, ~20 insns)
///
/// When TCP/ICMP handling is added (much larger code footprint), this
/// separation prevents I-cache thrashing that a single-pass loop would cause.
public func classifyFrames(
    _ frames: [PacketBuffer],
    hostMAC: MACAddress
) -> ClassifiedFrames {
    var result = ClassifiedFrames()

    // Phase 1: Parse all Ethernet headers
    var ethParsed: [(pkt: PacketBuffer, eth: EthernetFrame)] = []
    for pkt in frames {
        if let eth = EthernetFrame.parse(from: pkt) {
            ethParsed.append((pkt, eth))
        } else {
            result.unknown.append(pkt)
        }
    }

    // Phase 2: MAC filter + EtherType classification
    var arpInput: [(pkt: PacketBuffer, eth: EthernetFrame)] = []
    var ipv4Input: [(pkt: PacketBuffer, eth: EthernetFrame)] = []
    for (pkt, eth) in ethParsed {
        guard eth.dstMAC == hostMAC || eth.dstMAC == .broadcast else {
            result.unknown.append(pkt)
            continue
        }
        switch eth.etherType {
        case .arp:  arpInput.append((pkt, eth))
        case .ipv4: ipv4Input.append((pkt, eth))
        @unknown default: result.unknown.append(pkt)
        }
    }

    // Phase 3: Parse all IPv4 headers + checksum verification + protocol dispatch
    for (pkt, eth) in ipv4Input {
        guard let ip = IPv4Header.parse(from: eth.payload), ip.verifyChecksum() else {
            result.unknown.append(pkt)
            continue
        }
        switch ip.protocol {
        case .icmp: result.ipv4ICMP.append((eth, ip))
        case .tcp:  result.ipv4TCP.append((eth, ip))
        case .udp:  result.ipv4UDP.append((eth, ip))
        default:    result.ipv4Unknown.append((eth, ip))
        }
    }

    // Phase 4: Parse all ARP frames
    for (pkt, eth) in arpInput {
        if let arp = ARPFrame.parse(from: eth.payload) {
            result.arp.append((eth, arp))
        } else {
            result.unknown.append(pkt)
        }
    }

    return result
}
