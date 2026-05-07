import Testing
import Darwin
import Foundation
@testable import SwiftNetStack

@Suite(.serialized)
struct DebugToolsTests {

    // MARK: - PCAP writer

    @Test func pcapWriterCreatesValidFile() {
        let path = "/tmp/test-pcap-\(UUID().uuidString).pcap"
        defer { unlink(path) }

        let writer = PCAPWriter()
        #expect(writer.start(path: path) == true)

        // Write a minimal Ethernet frame (14-byte header + padding)
        var frame: [UInt8] = [
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  // dst MAC (broadcast)
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55,  // src MAC
            0x08, 0x00,                              // EtherType IPv4
        ]
        frame.append(contentsOf: [UInt8](repeating: 0, count: 46)) // pad to 60 bytes

        let storage = Storage.allocate(capacity: frame.count)
        frame.withUnsafeBytes { storage.data.copyMemory(from: $0.baseAddress!, byteCount: frame.count) }
        let pkt = PacketBuffer(storage: storage, offset: 0, length: frame.count)
        writer.write(packet: pkt)
        writer.close()

        // Verify pcap file structure
        guard let fh = fopen(path, "rb") else {
            Issue.record("failed to open pcap file")
            return
        }
        defer { fclose(fh) }

        // Global header: 24 bytes
        var magic: UInt32 = 0
        #expect(fread(&magic, 4, 1, fh) == 1)
        #expect(magic == 0xa1b2_c3d4, "bad magic: \(String(magic, radix: 16))")

        fseek(fh, 20, SEEK_SET)  // skip to linktype
        var linktype: UInt32 = 0
        #expect(fread(&linktype, 4, 1, fh) == 1)
        #expect(linktype == 1, "expected LINKTYPE_ETHERNET (1), got \(linktype)")

        // Packet header: 16 bytes
        var pktHdr = pcaprec_hdr_for_test(ts_sec: 0, ts_usec: 0, incl_len: 0, orig_len: 0)
        #expect(fread(&pktHdr, MemoryLayout<pcaprec_hdr_for_test>.size, 1, fh) == 1)
        #expect(pktHdr.incl_len == 60)
        #expect(pktHdr.orig_len == 60)

        // Packet data: 60 bytes
        var pktData = [UInt8](repeating: 0, count: 60)
        #expect(fread(&pktData, 60, 1, fh) == 1)
        #expect(pktData[0..<14] == frame[0..<14])
    }

    @Test func pcapWriterRawWriteCapturesData() {
        let path = "/tmp/test-pcap-raw-\(UUID().uuidString).pcap"
        defer { unlink(path) }

        let writer = PCAPWriter()
        #expect(writer.start(path: path) == true)

        let raw: [UInt8] = [0x01, 0x02, 0x03, 0x04]
        raw.withUnsafeBufferPointer { writer.write(raw: $0.baseAddress!, length: raw.count) }
        writer.close()

        guard let fh = fopen(path, "rb") else { Issue.record("failed to open"); return }
        defer { fclose(fh) }
        fseek(fh, 0, SEEK_END)
        // 24 global header + 16 packet header + 4 data = 44
        #expect(ftell(fh) == 44, "expected 44 bytes, got \(ftell(fh))")
    }

    // MARK: - FSM transition tracer

    @Test func fsmTracerCalledOnStateTransition() {
        var transitions: [(from: TCPState, to: TCPState)] = []

        tcpStateTransitionTracer = { from, to, _, _ in
            transitions.append((from, to))
        }
        defer { tcpStateTransitionTracer = nil }

        var snd = SendSequence(nxt: 1000, una: 1000, wnd: 65535)
        var rcv = RecvSequence(nxt: 0, initialSeq: 0)

        // Create a SYN segment
        let synPkt = makeTCPSegment(flags: .syn, seq: 0, ack: 0)
        let (st1, _, _) = tcpProcess(state: .listen, segment: synPkt, snd: &snd, rcv: &rcv, appClose: false)
        #expect(st1 == .synReceived)
        #expect(transitions.count == 1)
        #expect(transitions[0].from == .listen)
        #expect(transitions[0].to == .synReceived)

        // Complete handshake with ACK
        let ackPkt = makeTCPSegment(flags: .ack, seq: 1, ack: snd.nxt)
        let (st2, _, _) = tcpProcess(state: .synReceived, segment: ackPkt, snd: &snd, rcv: &rcv, appClose: false)
        #expect(st2 == .established)
        #expect(transitions.count == 2)
        #expect(transitions[1].from == .synReceived)
        #expect(transitions[1].to == .established)
    }

    @Test func fsmTracerNotCalledWhenStateUnchanged() {
        var callCount = 0
        tcpStateTransitionTracer = { _, _, _, _ in callCount += 1 }
        defer { tcpStateTransitionTracer = nil }

        var snd = SendSequence(nxt: 1000, una: 1000, wnd: 65535)
        var rcv = RecvSequence(nxt: 0, initialSeq: 0)

        // Pure ACK on listen should keep state unchanged
        let ackPkt = makeTCPSegment(flags: .ack, seq: 1, ack: 1000)
        let (st, _, _) = tcpProcess(state: .listen, segment: ackPkt, snd: &snd, rcv: &rcv, appClose: false)
        #expect(st == .listen)
        #expect(callCount == 0)
    }

    @Test func fsmTracerCapturesCloseWaitTransition() {
        var transitions: [(from: TCPState, to: TCPState)] = []
        tcpStateTransitionTracer = { from, to, _, _ in
            transitions.append((from, to))
        }
        defer { tcpStateTransitionTracer = nil }

        var snd = SendSequence(nxt: 1001, una: 1001, wnd: 65535)
        var rcv = RecvSequence(nxt: 1, initialSeq: 0)

        // VM sends FIN → established → closeWait
        let finPkt = makeTCPSegment(flags: [.ack, .fin], seq: 1, ack: 1001)
        let (st, _, _) = tcpProcess(state: .established, segment: finPkt, snd: &snd, rcv: &rcv, appClose: false)
        #expect(st == .closeWait)
        #expect(transitions.count == 1)
        #expect(transitions[0].from == .established)
        #expect(transitions[0].to == .closeWait)
    }
}

// MARK: - Helpers

private struct pcaprec_hdr_for_test {
    var ts_sec: UInt32
    var ts_usec: UInt32
    var incl_len: UInt32
    var orig_len: UInt32
}

private func makeTCPSegment(flags: TCPFlags, seq: UInt32, ack: UInt32) -> TCPHeader {
    let bytes = makeRawTCPBytes(flags: flags, seq: seq, ack: ack)
    let storage = Storage.allocate(capacity: bytes.count)
    bytes.withUnsafeBytes { storage.data.copyMemory(from: $0.baseAddress!, byteCount: bytes.count) }
    let pkt = PacketBuffer(storage: storage, offset: 0, length: bytes.count)
    return TCPHeader.parse(from: pkt,
                           pseudoSrcAddr: IPv4Address(10, 0, 0, 1),
                           pseudoDstAddr: IPv4Address(10, 0, 0, 2))!
}

private func makeRawTCPBytes(flags: TCPFlags, seq: UInt32, ack: UInt32) -> [UInt8] {
    var bytes = [UInt8](repeating: 0, count: 20)
    bytes[12] = 0x50  // data offset = 5
    bytes[13] = flags.rawValue
    bytes[4] = UInt8((seq >> 24) & 0xFF); bytes[5] = UInt8((seq >> 16) & 0xFF)
    bytes[6] = UInt8((seq >> 8) & 0xFF); bytes[7] = UInt8(seq & 0xFF)
    bytes[8] = UInt8((ack >> 24) & 0xFF); bytes[9] = UInt8((ack >> 16) & 0xFF)
    bytes[10] = UInt8((ack >> 8) & 0xFF); bytes[11] = UInt8(ack & 0xFF)
    return bytes
}
