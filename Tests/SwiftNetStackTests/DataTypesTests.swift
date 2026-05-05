import Testing
@testable import SwiftNetStack

/// Tests for MACAddress, EtherType, IPv4Address, IPProtocol, IPv4Subnet, VMEndpoint.
/// These are pure value types with no internal dependencies.
@Suite(.serialized)
struct DataTypesTests {

    // MARK: - MACAddress

    @Test func macAddressFromOctets() {
        let mac = MACAddress(0x00, 0x11, 0x22, 0x33, 0x44, 0x55)
        #expect(mac.octets == (0x00, 0x11, 0x22, 0x33, 0x44, 0x55))
    }

    @Test func macAddressFromBuffer() {
        let bytes: [UInt8] = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]
        let mac = bytes.withUnsafeBytes { MACAddress($0) }
        #expect(mac.octets == (0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF))
    }

    @Test func macAddressEquality() {
        let a = MACAddress(1, 2, 3, 4, 5, 6)
        let b = MACAddress(1, 2, 3, 4, 5, 6)
        let c = MACAddress(0xFF, 2, 3, 4, 5, 6)
        #expect(a == b)
        #expect(a != c)
    }

    @Test func macAddressBroadcastAndZero() {
        #expect(MACAddress.broadcast == MACAddress(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF))
        #expect(MACAddress.zero == MACAddress(0, 0, 0, 0, 0, 0))
    }

    @Test func macAddressWriteRoundTrip() {
        let mac = MACAddress(0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE)
        var buf = [UInt8](repeating: 0, count: 6)
        buf.withUnsafeMutableBytes { mac.write(to: $0.baseAddress!) }
        #expect(buf == [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE])
    }

    @Test func macAddressDescription() {
        let mac = MACAddress(0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E)
        #expect(mac.description == "00:1a:2b:3c:4d:5e")
    }

    // MARK: - IPv4Address

    @Test func ipv4AddressFromOctets() {
        let ip = IPv4Address(192, 168, 1, 1)
        #expect(ip.description == "192.168.1.1")
    }

    @Test func ipv4AddressFromUInt32() {
        let ip = IPv4Address(addr: 0xC0A80101)
        #expect(ip.description == "192.168.1.1")
    }

    @Test func ipv4AddressFromBuffer() {
        let bytes: [UInt8] = [10, 0, 0, 1]
        let ip = bytes.withUnsafeBytes { IPv4Address($0) }
        #expect(ip.addr == 0x0A000001)
        #expect(ip.description == "10.0.0.1")
    }

    @Test func ipv4AddressEquality() {
        let a = IPv4Address(10, 0, 0, 1)
        let b = IPv4Address(10, 0, 0, 1)
        let c = IPv4Address(10, 0, 0, 2)
        #expect(a == b)
        #expect(a != c)
    }

    @Test func ipv4AddressZero() {
        #expect(IPv4Address.zero == IPv4Address(0, 0, 0, 0))
        #expect(IPv4Address.zero.addr == 0)
    }

    @Test func ipv4AddressWriteRoundTrip() {
        let ip = IPv4Address(172, 16, 0, 1)
        var buf = [UInt8](repeating: 0, count: 4)
        buf.withUnsafeMutableBytes { ip.write(to: $0.baseAddress!) }
        #expect(buf == [172, 16, 0, 1])
    }

    @Test func ipv4AddressDescriptionFormat() {
        #expect(IPv4Address(0, 0, 0, 0).description == "0.0.0.0")
        #expect(IPv4Address(255, 255, 255, 255).description == "255.255.255.255")
    }

    // MARK: - IPv4Subnet

    @Test func subnetContainsIP() {
        let subnet = IPv4Subnet(network: IPv4Address(192, 168, 1, 0), prefixLength: 24)
        #expect(subnet.contains(IPv4Address(192, 168, 1, 1)))
        #expect(subnet.contains(IPv4Address(192, 168, 1, 254)))
    }

    @Test func subnetExcludesOutsideIP() {
        let subnet = IPv4Subnet(network: IPv4Address(192, 168, 1, 0), prefixLength: 24)
        #expect(!subnet.contains(IPv4Address(192, 168, 2, 1)))
        #expect(!subnet.contains(IPv4Address(10, 0, 0, 1)))
    }

    @Test func subnetContainsNetworkAndBroadcast() {
        let subnet = IPv4Subnet(network: IPv4Address(10, 0, 0, 0), prefixLength: 24)
        #expect(subnet.contains(IPv4Address(10, 0, 0, 0)))
        #expect(subnet.contains(IPv4Address(10, 0, 0, 255)))
    }

    @Test func subnetBroadcastAddress() {
        let subnet = IPv4Subnet(network: IPv4Address(192, 168, 1, 0), prefixLength: 24)
        #expect(subnet.broadcast == IPv4Address(192, 168, 1, 255))
    }

    @Test func subnetBroadcastForSlash32() {
        let subnet = IPv4Subnet(network: IPv4Address(10, 0, 0, 1), prefixLength: 32)
        #expect(subnet.broadcast == IPv4Address(10, 0, 0, 1))
    }

    @Test func subnetBroadcastForSlashZero() {
        let subnet = IPv4Subnet(network: IPv4Address(0, 0, 0, 0), prefixLength: 0)
        #expect(subnet.broadcast == IPv4Address(255, 255, 255, 255))
    }

    @Test func subnetMaskForVariousPrefixLengths() {
        #expect(IPv4Subnet(network: .zero, prefixLength: 0).mask == 0x00000000)
        #expect(IPv4Subnet(network: .zero, prefixLength: 8).mask == 0xFF000000)
        #expect(IPv4Subnet(network: .zero, prefixLength: 16).mask == 0xFFFF0000)
        #expect(IPv4Subnet(network: .zero, prefixLength: 24).mask == 0xFFFFFF00)
        #expect(IPv4Subnet(network: .zero, prefixLength: 32).mask == 0xFFFFFFFF)
    }

    @Test func subnetEquality() {
        let a = IPv4Subnet(network: IPv4Address(10, 0, 0, 0), prefixLength: 24)
        let b = IPv4Subnet(network: IPv4Address(10, 0, 0, 0), prefixLength: 24)
        let c = IPv4Subnet(network: IPv4Address(10, 0, 0, 0), prefixLength: 16)
        #expect(a == b)
        #expect(a != c)
    }

    @Test func subnetDescription() {
        let subnet = IPv4Subnet(network: IPv4Address(192, 168, 1, 0), prefixLength: 24)
        #expect(subnet.description == "192.168.1.0/24")
    }

    // MARK: - VMEndpoint

    @Test func vmEndpointDefaultMTU() {
        let ep = VMEndpoint(
            id: 0, fd: 42,
            subnet: IPv4Subnet(network: IPv4Address(10, 0, 0, 0), prefixLength: 24),
            gateway: IPv4Address(10, 0, 0, 1)
        )
        #expect(ep.mtu == 1500)
    }

    @Test func vmEndpointCustomMTU() {
        let ep = VMEndpoint(
            id: 1, fd: 99,
            subnet: IPv4Subnet(network: IPv4Address(172, 16, 0, 0), prefixLength: 16),
            gateway: IPv4Address(172, 16, 0, 1),
            mtu: 9000
        )
        #expect(ep.mtu == 9000)
        #expect(ep.id == 1)
        #expect(ep.fd == 99)
    }

    // MARK: - Enum raw values

    @Test func etherTypeRawValues() {
        #expect(EtherType.arp.rawValue == 0x0806)
        #expect(EtherType.ipv4.rawValue == 0x0800)
    }

    @Test func ipProtocolRawValues() {
        #expect(IPProtocol.icmp.rawValue == 1)
        #expect(IPProtocol.tcp.rawValue == 6)
        #expect(IPProtocol.udp.rawValue == 17)
    }

    @Test func arpOperationRawValues() {
        #expect(ARPOperation.request.rawValue == 1)
        #expect(ARPOperation.reply.rawValue == 2)
    }

    @Test func dhcpMessageTypeRawValues() {
        #expect(DHCPMessageType.discover.rawValue == 1)
        #expect(DHCPMessageType.offer.rawValue == 2)
        #expect(DHCPMessageType.request.rawValue == 3)
        #expect(DHCPMessageType.ack.rawValue == 5)
        #expect(DHCPMessageType.release.rawValue == 7)
    }
}
