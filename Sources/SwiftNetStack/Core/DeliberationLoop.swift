/// Persistent deliberation loop — the library entry point for callers.
///
/// Owns the long-lived protocol state (ARP table, DHCP leases, routing) and
/// exposes `runOneRound(transport:)` to execute one BDP deliberation cycle.
/// The caller drives the loop (e.g. via RunLoop timer or dedicated DispatchQueue)
/// and owns all file descriptors — DeliberationLoop never creates fds, never
/// touches TUN devices, and runs entirely within sandbox constraints.
///
/// Usage:
///   var loop = DeliberationLoop(endpoints: [vm1, vm2], ourMAC: myMAC)
///   var transport = PollingTransport(endpoints: [vm1, vm2])
///   while running {
///       loop.runOneRound(transport: &transport)
///   }
public struct DeliberationLoop {
    public let ourMAC: MACAddress
    public var arpMapping: ARPMapping
    public var dhcpServer: DHCPServer
    public let routingTable: RoutingTable

    public init(endpoints: [VMEndpoint], ourMAC: MACAddress) {
        self.ourMAC = ourMAC
        self.arpMapping = ARPMapping(ourMAC: ourMAC, endpoints: endpoints)
        self.dhcpServer = DHCPServer(endpoints: endpoints)
        self.routingTable = RoutingTable()
    }

    /// Execute one BDP deliberation round.
    ///
    /// Creates a round-scoped `RoundContext`, calls `bdpRound`, and returns
    /// the number of reply packets written to the transport.
    @discardableResult
    public mutating func runOneRound(transport: inout Transport) -> Int {
        let round = RoundContext()
        let replyCount = bdpRound(
            transport: &transport,
            arpMapping: &arpMapping,
            dhcpServer: &dhcpServer,
            routingTable: routingTable,
            round: round
        )
        return replyCount
    }
}
