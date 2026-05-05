import Testing
@testable import SwiftNetStack

@Suite(.serialized)
struct RoutingTableTests {

    @Test func emptyTableReturnsDefault() {
        let table = RoutingTable()
        #expect(table.lookup(IPv4Address(10, 0, 0, 1)) == .default)
        #expect(table.lookup(IPv4Address(192, 168, 1, 1)) == .default)
    }

    @Test func addSubnetAndLookupExactMatch() {
        var table = RoutingTable()
        let subnet = IPv4Subnet(network: IPv4Address(100, 64, 1, 0), prefixLength: 24)
        table.addSubnet(subnet, endpointID: 5)

        #expect(table.lookup(IPv4Address(100, 64, 1, 50)) == .direct(5))
        #expect(table.lookup(IPv4Address(100, 64, 1, 1)) == .direct(5))
        #expect(table.lookup(IPv4Address(100, 64, 1, 254)) == .direct(5))
    }

    @Test func lookupNonMatchingIPReturnsDefault() {
        var table = RoutingTable()
        table.addSubnet(IPv4Subnet(network: IPv4Address(100, 64, 1, 0), prefixLength: 24), endpointID: 1)

        #expect(table.lookup(IPv4Address(100, 64, 2, 1)) == .default)
        #expect(table.lookup(IPv4Address(192, 168, 1, 1)) == .default)
    }

    @Test func longestPrefixMatch() {
        var table = RoutingTable()
        // Broader route
        table.addSubnet(IPv4Subnet(network: IPv4Address(10, 0, 0, 0), prefixLength: 8), endpointID: 1)
        // More specific route
        table.addSubnet(IPv4Subnet(network: IPv4Address(10, 1, 0, 0), prefixLength: 16), endpointID: 2)

        // IP in both subnets → should match the longer prefix
        #expect(table.lookup(IPv4Address(10, 1, 2, 3)) == .direct(2))
        // IP only in /8
        #expect(table.lookup(IPv4Address(10, 2, 0, 1)) == .direct(1))
        // IP in neither
        #expect(table.lookup(IPv4Address(192, 168, 1, 1)) == .default)
    }

    @Test func addSubnetReplacesExisting() {
        var table = RoutingTable()
        let subnet = IPv4Subnet(network: IPv4Address(100, 64, 0, 0), prefixLength: 16)
        table.addSubnet(subnet, endpointID: 1)
        #expect(table.lookup(IPv4Address(100, 64, 1, 1)) == .direct(1))

        table.addSubnet(subnet, endpointID: 2)
        #expect(table.lookup(IPv4Address(100, 64, 1, 1)) == .direct(2))
    }

    @Test func removeSubnetRemovesRoute() {
        var table = RoutingTable()
        let subnet = IPv4Subnet(network: IPv4Address(100, 64, 1, 0), prefixLength: 24)
        table.addSubnet(subnet, endpointID: 3)
        #expect(table.lookup(IPv4Address(100, 64, 1, 50)) == .direct(3))

        table.removeSubnet(subnet)
        #expect(table.lookup(IPv4Address(100, 64, 1, 50)) == .default)
    }

    @Test func removeUnknownSubnetIsNoop() {
        var table = RoutingTable()
        table.addSubnet(IPv4Subnet(network: IPv4Address(10, 0, 0, 0), prefixLength: 8), endpointID: 1)

        table.removeSubnet(IPv4Subnet(network: IPv4Address(192, 168, 0, 0), prefixLength: 16))
        #expect(table.lookup(IPv4Address(10, 1, 1, 1)) == .direct(1))
    }

    @Test func multipleSubnetsDifferentEndpoints() {
        var table = RoutingTable()
        table.addSubnet(IPv4Subnet(network: IPv4Address(100, 64, 1, 0), prefixLength: 24), endpointID: 10)
        table.addSubnet(IPv4Subnet(network: IPv4Address(100, 64, 2, 0), prefixLength: 24), endpointID: 20)
        table.addSubnet(IPv4Subnet(network: IPv4Address(10, 0, 0, 0), prefixLength: 8), endpointID: 30)

        #expect(table.lookup(IPv4Address(100, 64, 1, 50)) == .direct(10))
        #expect(table.lookup(IPv4Address(100, 64, 2, 50)) == .direct(20))
        #expect(table.lookup(IPv4Address(10, 99, 99, 99)) == .direct(30))
        #expect(table.lookup(IPv4Address(192, 168, 1, 1)) == .default)
    }
}
