import Testing
import Darwin
@testable import SwiftNetStack

@Suite(.serialized)
struct FrameReaderTests {

    /// Create a SOCK_DGRAM socketpair, write data to one end, read from the other.
    private func makeSocketPair() -> (readFD: Int32, writeFD: Int32)? {
        var fds: [Int32] = [-1, -1]
        let rc = socketpair(AF_UNIX, SOCK_DGRAM, 0, &fds)
        guard rc == 0 else { return nil }
        return (fds[0], fds[1])
    }

    // MARK: - Single frame

    @Test func readsSingleFrame() {
        guard let (readFD, writeFD) = makeSocketPair() else {
            Issue.record("socketpair failed: \(errno)")
            return
        }
        defer { close(readFD); close(writeFD) }

        let data: [UInt8] = Array(0..<100).map { UInt8($0) }
        let written = data.withUnsafeBytes { Darwin.write(writeFD, $0.baseAddress!, data.count) }
        #expect(written == 100)

        let reader = FrameReader(mtu: 1500)
        let round = RoundContext()
        let frames = reader.readAllFrames(from: readFD, round: round)

        #expect(frames.count == 1)
        guard frames.count == 1 else { return }
        #expect(frames[0].totalLength == 100)
        frames[0].withUnsafeReadableBytes { buf in
            #expect(Array(buf) == data)
        }
    }

    // MARK: - Multiple frames

    @Test func readsMultipleFrames() {
        guard let (readFD, writeFD) = makeSocketPair() else {
            Issue.record("socketpair failed: \(errno)")
            return
        }
        defer { close(readFD); close(writeFD) }

        let data1: [UInt8] = [1, 2, 3, 4, 5]
        let data2: [UInt8] = [10, 20, 30]
        let data3: [UInt8] = [100, 200]

        data1.withUnsafeBytes { _ = Darwin.write(writeFD, $0.baseAddress!, data1.count) }
        data2.withUnsafeBytes { _ = Darwin.write(writeFD, $0.baseAddress!, data2.count) }
        data3.withUnsafeBytes { _ = Darwin.write(writeFD, $0.baseAddress!, data3.count) }

        let reader = FrameReader(mtu: 1500, maxPackets: 256)
        let round = RoundContext()
        let frames = reader.readAllFrames(from: readFD, round: round)

        #expect(frames.count == 3)
        guard frames.count == 3 else { return }

        frames[0].withUnsafeReadableBytes { #expect(Array($0) == data1) }
        frames[1].withUnsafeReadableBytes { #expect(Array($0) == data2) }
        frames[2].withUnsafeReadableBytes { #expect(Array($0) == data3) }
    }

    // MARK: - Max packets budget

    @Test func respectsMaxPacketsBudget() {
        guard let (readFD, writeFD) = makeSocketPair() else {
            Issue.record("socketpair failed: \(errno)")
            return
        }
        defer { close(readFD); close(writeFD) }

        // Write 5 frames
        let data: [UInt8] = [1, 2, 3]
        for _ in 0..<5 {
            data.withUnsafeBytes { _ = Darwin.write(writeFD, $0.baseAddress!, data.count) }
        }

        let reader = FrameReader(mtu: 1500, maxPackets: 3)
        let round = RoundContext()
        let frames = reader.readAllFrames(from: readFD, round: round)

        #expect(frames.count == 3)
    }

    // MARK: - Empty fd

    @Test func emptyFDReturnsEmptyArray() {
        guard let (readFD, writeFD) = makeSocketPair() else {
            Issue.record("socketpair failed: \(errno)")
            return
        }
        defer { close(readFD); close(writeFD) }

        let reader = FrameReader()
        let round = RoundContext()
        let frames = reader.readAllFrames(from: readFD, round: round)

        #expect(frames.isEmpty)
    }

    // MARK: - Frame shorter than MTU

    @Test func frameShorterThanMTUIsTrimmed() {
        guard let (readFD, writeFD) = makeSocketPair() else {
            Issue.record("socketpair failed: \(errno)")
            return
        }
        defer { close(readFD); close(writeFD) }

        let data: [UInt8] = [0xAA, 0xBB, 0xCC]
        data.withUnsafeBytes { _ = Darwin.write(writeFD, $0.baseAddress!, data.count) }

        let reader = FrameReader(mtu: 1500)
        let round = RoundContext()
        let frames = reader.readAllFrames(from: readFD, round: round)

        #expect(frames.count == 1)
        guard frames.count == 1 else { return }
        #expect(frames[0].totalLength == 3)
        // tailroom should reflect trim
        #expect(frames[0].tailroom >= 1500 - 3 - frames[0].headroom)
    }

    // MARK: - Default init values

    @Test func defaultMTUIs1500() {
        let reader = FrameReader()
        #expect(reader.mtu == 1500)
    }

    @Test func customMTU() {
        let reader = FrameReader(mtu: 9000)
        #expect(reader.mtu == 9000)
    }
}
