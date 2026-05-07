/// Persistent deliberation loop — the library entry point for callers.
///
/// Owns the long-lived protocol state (ARP table, DHCP leases, routing) and
/// exposes `runOneRound(transport:)` to execute one BDP deliberation cycle.
/// The caller drives the loop (e.g. via RunLoop timer or dedicated DispatchQueue)
/// and owns all file descriptors — DeliberationLoop never creates fds, never
/// touches TUN devices, and runs entirely within sandbox constraints.
///
/// Usage:
///   var loop = DeliberationLoop(endpoints: [vm1, vm2], hostMAC: myMAC)
///   var transport = PollingTransport(endpoints: [vm1, vm2])
///   while running {
///       loop.runOneRound(transport: &transport)
///   }
public struct DeliberationLoop {
    public let hostMAC: MACAddress
    public var arpMapping: ARPMapping
    public var dhcpServer: DHCPServer
    public let routingTable: RoutingTable
    public var socketRegistry: SocketRegistry
    public var ipFragmentReassembler: IPFragmentReassembler
    public var natTable: NATTable
    public var dnsServer: DNSServer

    public init(endpoints: [VMEndpoint], hostMAC: MACAddress, portForwards: [PortForwardEntry] = [], hosts: [String: IPv4Address] = [:]) {
        self.hostMAC = hostMAC
        self.arpMapping = ARPMapping(hostMAC: hostMAC, endpoints: endpoints)
        self.dhcpServer = DHCPServer(endpoints: endpoints)
        self.routingTable = RoutingTable()
        self.socketRegistry = SocketRegistry()
        self.ipFragmentReassembler = IPFragmentReassembler()
        self.natTable = NATTable(portForwards: portForwards)
        self.dnsServer = DNSServer(hosts: hosts)
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
            dnsServer: &dnsServer,
            routingTable: routingTable,
            socketRegistry: &socketRegistry,
            ipFragmentReassembler: &ipFragmentReassembler,
            natTable: &natTable,
            round: round
        )
        return replyCount
    }
}
