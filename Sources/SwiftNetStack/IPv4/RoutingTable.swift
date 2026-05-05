/// Result of a routing table lookup.
public enum RouteResult: Equatable {
    case direct(Int)     // Directly attached → VM endpoint ID
    case `default`       // NAT outbound (userspace, deferred)
}

/// Longest-prefix-match routing table.
///
/// Semi-static: updated when VMs are added/removed, read-only at runtime.
/// Linear scan over subnets (N ≤ dozens), selecting the longest matching prefix.
public struct RoutingTable {
    private var entries: [(subnet: IPv4Subnet, endpointID: Int)] = []

    public init() {}

    /// Add a subnet route. Replaces existing entry for the same subnet.
    public mutating func addSubnet(_ subnet: IPv4Subnet, endpointID: Int) {
        if let idx = entries.firstIndex(where: { $0.subnet == subnet }) {
            entries[idx] = (subnet, endpointID)
        } else {
            entries.append((subnet, endpointID))
        }
    }

    /// Remove a subnet route.
    public mutating func removeSubnet(_ subnet: IPv4Subnet) {
        entries.removeAll(where: { $0.subnet == subnet })
    }

    /// Longest prefix match. Returns .direct(endpointID) for a matching subnet,
    /// or .default if no subnet matches.
    public func lookup(_ ip: IPv4Address) -> RouteResult {
        var best: (prefixLength: UInt8, endpointID: Int)? = nil
        for (subnet, endpointID) in entries {
            guard subnet.contains(ip) else { continue }
            if best == nil || subnet.prefixLength > best!.prefixLength {
                best = (subnet.prefixLength, endpointID)
            }
        }
        if let best = best {
            return .direct(best.endpointID)
        }
        return .default
    }
}
