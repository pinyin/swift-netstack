import Darwin
import Foundation

/// Writes Ethernet frames to a standard `.pcap` file for inspection with
/// Wireshark / tcpdump.
///
/// Integration point: call `write(packet:)` for every frame that enters or
/// leaves the BDP pipeline.  The file is written incrementally — no in-memory
/// buffering beyond the kernel page cache.
///
/// Thread safety: this class is **not** thread-safe.  All writes must be
/// serialised by the caller (BDP is single-threaded by design, so this is
/// naturally satisfied).
public final class PCAPWriter {

    // MARK: - Public API

    public init() {}

    /// Open the output file and write the pcap global header.
    /// Returns `true` on success.
    @discardableResult
    public func start(path: String) -> Bool {
        let fd = Darwin.open(path, O_WRONLY | O_CREAT | O_TRUNC, 0o644)
        guard fd >= 0 else { return false }
        self.fd = fd
        writeGlobalHeader()
        return true
    }

    /// Write a single contiguous Ethernet frame to the capture.
    public func writeRaw(framePtr: UnsafeMutableRawPointer, len: Int) {
        guard fd >= 0, len > 0 else { return }
        write(raw: framePtr.assumingMemoryBound(to: UInt8.self), length: len)
    }

    /// Write a split frame (header + payload from separate buffers) to the capture.
    /// Copies both parts into a stack buffer then writes as a single record.
    public func writeRawSplit(hdr: UnsafeMutableRawPointer, hdrLen: Int,
                               pay: UnsafeMutableRawPointer, payLen: Int) {
        guard fd >= 0 else { return }
        let total = hdrLen + payLen
        guard total > 0 else { return }
        // Stack-allocate for small frames (typical MTU is 1500)
        var buf = [UInt8](repeating: 0, count: total)
        buf.withUnsafeMutableBytes { ptr in
            ptr.baseAddress!.copyMemory(from: hdr, byteCount: hdrLen)
            ptr.baseAddress!.advanced(by: hdrLen).copyMemory(from: pay, byteCount: payLen)
        }
        buf.withUnsafeBytes { ptr in
            write(raw: ptr.baseAddress!.assumingMemoryBound(to: UInt8.self), length: total)
        }
    }

    /// Legacy PacketBuffer-based write (kept for source compatibility).
    @available(*, deprecated, message: "Use writeRaw or writeRawSplit")
    public func write(packet: PacketBuffer) {
        guard fd >= 0 else { return }
        packet.withUnsafeReadableBytes { ptr in
            write(raw: ptr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                  length: ptr.count)
        }
    }

    /// Append a raw byte range to the capture.
    public func write(raw: UnsafePointer<UInt8>, length: Int) {
        guard fd >= 0, length > 0 else { return }

        var tv = timeval()
        gettimeofday(&tv, nil)

        var header = pcaprec_hdr(
            ts_sec: UInt32(tv.tv_sec),
            ts_usec: UInt32(tv.tv_usec),
            incl_len: UInt32(length),
            orig_len: UInt32(length)
        )

        let hdrWritten = withUnsafeBytes(of: &header) { hdrBuf in
            Darwin.write(fd, hdrBuf.baseAddress!, hdrBuf.count)
        }
        guard hdrWritten == MemoryLayout<pcaprec_hdr>.size else { return }

        _ = Darwin.write(fd, raw, length)
    }

    /// Flush buffered data to disk and close the file.
    public func close() {
        guard fd >= 0 else { return }
        Darwin.close(fd)
        fd = -1
    }

    deinit { close() }

    // MARK: - Private

    private var fd: Int32 = -1

    private func writeGlobalHeader() {
        var hdr = pcap_hdr_t(
            magic_number: 0xa1b2_c3d4,
            version_major: 2,
            version_minor: 4,
            thiszone: 0,
            sigfigs: 0,
            snaplen: 65535,
            network: 1                  // LINKTYPE_ETHERNET
        )
        _ = withUnsafeBytes(of: &hdr) { hdrBuf in
            Darwin.write(fd, hdrBuf.baseAddress!, hdrBuf.count)
        }
    }
}

// MARK: - pcap on-disk structures

private struct pcap_hdr_t {
    var magic_number: UInt32
    var version_major: UInt16
    var version_minor: UInt16
    var thiszone: Int32
    var sigfigs: UInt32
    var snaplen: UInt32
    var network: UInt32
}

private struct pcaprec_hdr {
    var ts_sec: UInt32
    var ts_usec: UInt32
    var incl_len: UInt32
    var orig_len: UInt32
}
