import Testing
@testable import SwiftNetStack

/// Golden-vector tests for internetChecksum (RFC 1071).
@Suite(.serialized)
struct ChecksumTests {

    // MARK: - RFC 1071 Section 3: Numerical Example

    @Test func rfc1071NumericalExample() {
        let bytes: [UInt8] = [0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7]
        let cksum = bytes.withUnsafeBytes { internetChecksum($0) }
        #expect(cksum == 0x220D)
    }

    @Test func rfc1071OddLength() {
        let bytes: [UInt8] = [0x00, 0x01, 0xf2]
        let cksum = bytes.withUnsafeBytes { internetChecksum($0) }
        #expect(cksum == 0x0DFE)
    }

    // MARK: - Edge cases

    @Test func checksumOfAllZerosIsFFFF() {
        let buf = [UInt8](repeating: 0, count: 20)
        let c = buf.withUnsafeBytes { internetChecksum($0) }
        #expect(c == 0xFFFF)
    }

    @Test func checksumOfEmptyIsFFFF() {
        let buf: [UInt8] = []
        let c = buf.withUnsafeBytes { internetChecksum($0) }
        #expect(c == 0xFFFF)
    }

    // MARK: - Verification round-trip

    @Test func checksumVerificationYieldsZero() {
        var bytes: [UInt8] = [
            0x45, 0x00, 0x00, 0x14,
            0x00, 0x00, 0x00, 0x00,
            0x40, 0x11, 0x00, 0x00,
            0xC0, 0xA8, 0x01, 0x01,
            0xC0, 0xA8, 0x01, 0x02,
        ]
        let cksum = bytes.withUnsafeBytes { internetChecksum($0) }
        bytes[10] = UInt8(cksum >> 8)
        bytes[11] = UInt8(cksum & 0xFF)

        let verify = bytes.withUnsafeBytes { internetChecksum($0) }
        #expect(verify == 0x0000)
    }

    // MARK: - gVisor golden vectors

    @Test func gvisorOneOddView() {
        let bytes: [UInt8] = [1, 9, 0, 5, 4]
        let cksum = bytes.withUnsafeBytes { internetChecksum($0) }
        #expect(cksum == ~UInt16(1294))
    }

    @Test func gvisorOneEvenView() {
        let bytes: [UInt8] = [1, 9, 0, 5]
        let cksum = bytes.withUnsafeBytes { internetChecksum($0) }
        #expect(cksum == ~UInt16(270))
    }

    @Test func gvisorTwoEvenViews() {
        let bytes: [UInt8] = [98, 1, 9, 0, 9, 0, 5, 4]
        let cksum = bytes.withUnsafeBytes { internetChecksum($0) }
        #expect(cksum == ~UInt16(30981))
    }

    @Test func gvisorThreeViews() {
        let bytes: [UInt8] = [
            77, 11, 33, 0, 55, 44,
            98, 1, 9, 0, 5, 4,
            4, 3, 7, 1, 2, 123, 99,
        ]
        let cksum = bytes.withUnsafeBytes { internetChecksum($0) }
        #expect(cksum == ~UInt16(34236))
    }
}
