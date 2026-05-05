import Testing
@testable import SwiftNetStack

@Suite(.serialized)
struct InMemoryTransportTests {

    @Test func readPacketsReturnsPreFilledInputs() {
        let round = RoundContext()
        var pkt = PacketBuffer(capacity: 100)
        _ = pkt.appendPointer(count: 10)

        var transport = InMemoryTransport(inputs: [(endpointID: 1, packet: pkt)])
        let result = transport.readPackets(round: round)

        #expect(result.count == 1)
        #expect(result[0].endpointID == 1)
        #expect(result[0].packet.totalLength == 10)
    }

    @Test func readPacketsReturnsEmptyWhenNoInputs() {
        let round = RoundContext()
        var transport = InMemoryTransport()
        let result = transport.readPackets(round: round)
        #expect(result.isEmpty)
    }

    @Test func writePacketsAppendsToOutputs() {
        var transport = InMemoryTransport()
        var pkt = PacketBuffer(capacity: 100)
        _ = pkt.appendPointer(count: 10)

        transport.writePackets([(endpointID: 1, packet: pkt)])
        #expect(transport.outputs.count == 1)
        #expect(transport.outputs[0].endpointID == 1)
    }

    @Test func multipleWritesAccumulate() {
        var transport = InMemoryTransport()

        var pkt1 = PacketBuffer(capacity: 100)
        _ = pkt1.appendPointer(count: 5)
        var pkt2 = PacketBuffer(capacity: 100)
        _ = pkt2.appendPointer(count: 10)

        transport.writePackets([(endpointID: 1, packet: pkt1)])
        transport.writePackets([(endpointID: 2, packet: pkt2)])

        #expect(transport.outputs.count == 2)
    }

    @Test func outputEndpointsTracksUniqueEndpoints() {
        var transport = InMemoryTransport()

        var pkt1 = PacketBuffer(capacity: 100)
        _ = pkt1.appendPointer(count: 5)
        var pkt2 = PacketBuffer(capacity: 100)
        _ = pkt2.appendPointer(count: 5)

        transport.writePackets([
            (endpointID: 1, packet: pkt1),
            (endpointID: 2, packet: pkt2),
            (endpointID: 1, packet: pkt1),  // duplicate endpoint
        ])

        #expect(transport.outputEndpoints == Set([1, 2]))
    }

    @Test func emptyTransportHasEmptyOutputEndpoints() {
        let transport = InMemoryTransport()
        #expect(transport.outputEndpoints.isEmpty)
    }

    @Test func readPacketsMultipleEndpoints() {
        let round = RoundContext()
        var pkt1 = PacketBuffer(capacity: 100)
        _ = pkt1.appendPointer(count: 5)
        var pkt2 = PacketBuffer(capacity: 100)
        _ = pkt2.appendPointer(count: 10)

        var transport = InMemoryTransport(inputs: [
            (endpointID: 1, packet: pkt1),
            (endpointID: 2, packet: pkt2),
        ])
        let result = transport.readPackets(round: round)

        #expect(result.count == 2)
        #expect(result[0].endpointID == 1)
        #expect(result[1].endpointID == 2)
    }
}
