// MARK: - RFC 2018 SACK scoreboard (inline, zero heap allocation)

/// Fixed-capacity SACK scoreboard — 4 blocks max, no heap allocation.
/// Blocks are sorted by left edge (ascending).
struct SACKScoreboard {
    var count: UInt8 = 0
    var l0: UInt32 = 0; var l1: UInt32 = 0; var l2: UInt32 = 0; var l3: UInt32 = 0
    var r0: UInt32 = 0; var r1: UInt32 = 0; var r2: UInt32 = 0; var r3: UInt32 = 0

    private func leftAt(_ i: Int) -> UInt32 {
        switch i {
        case 0: return l0; case 1: return l1
        case 2: return l2; case 3: return l3
        default: return 0
        }
    }
    private func rightAt(_ i: Int) -> UInt32 {
        switch i {
        case 0: return r0; case 1: return r1
        case 2: return r2; case 3: return r3
        default: return 0
        }
    }
    private mutating func setAt(_ i: Int, _ l: UInt32, _ r: UInt32) {
        switch i {
        case 0: l0 = l; r0 = r
        case 1: l1 = l; r1 = r
        case 2: l2 = l; r2 = r
        case 3: l3 = l; r3 = r
        default: break
        }
    }

    // MARK: - Recording

    /// Record a newly received out-of-order data block.
    mutating func record(_ left: UInt32, _ right: UInt32) {
        guard right > left else { return }
        let n = Int(count)

        // Try to merge with an existing block
        for i in 0..<n {
            let bl = leftAt(i), br = rightAt(i)
            if left <= br && right >= bl {
                setAt(i, min(bl, left), max(br, right))
                mergeAdjacent()
                return
            }
        }

        // Insert new block, maintaining sort by left edge
        if n < 4 {
            var ins = 0
            while ins < n && leftAt(ins) < left { ins += 1 }
            var j = n - 1
            while j >= ins { setAt(j + 1, leftAt(j), rightAt(j)); j -= 1 }
            setAt(ins, left, right)
            count = UInt8(n + 1)
        } else if left > leftAt(0) {
            // Full — discard oldest (lowest left edge), insert newer
            var ins = 1
            while ins < 4 && leftAt(ins) < left { ins += 1 }
            var j = 1
            while j < ins { setAt(j - 1, leftAt(j), rightAt(j)); j += 1 }
            setAt(ins - 1, left, right)
        }
    }

    // MARK: - Merging

    private mutating func mergeAdjacent() {
        var n = Int(count)
        var i = 0
        while i < n - 1 {
            if rightAt(i) >= leftAt(i + 1) {
                setAt(i, leftAt(i), max(rightAt(i), rightAt(i + 1)))
                var j = i + 1
                while j < n - 1 { setAt(j, leftAt(j + 1), rightAt(j + 1)); j += 1 }
                n -= 1
                count = UInt8(n)
            } else { i += 1 }
        }
    }

    // MARK: - Queries

    /// Call `body` for each block, most recent first (RFC 2018 order).
    func forEachBlock(_ body: (UInt32, UInt32) -> Void) {
        let n = Int(count)
        var i = n - 1
        while i >= 0 { body(leftAt(i), rightAt(i)); i -= 1 }
    }

    func isSacked(_ seq: UInt32) -> Bool {
        let n = Int(count)
        for i in 0..<n where seq >= leftAt(i) && seq < rightAt(i) { return true }
        return false
    }

    /// Total bytes in SACK blocks that overlap [from, to).
    func totalSackedBytes(from: UInt32, to: UInt32) -> UInt32 {
        guard to > from else { return 0 }
        let n = Int(count)
        var total: UInt32 = 0
        for i in 0..<n {
            let l = leftAt(i), r = rightAt(i)
            let overlapStart = Swift.max(l, from)
            let overlapEnd = Swift.min(r, to)
            if overlapEnd > overlapStart {
                total &+= overlapEnd &- overlapStart
            }
        }
        return total
    }

    /// Left edge of the first SACK block at or after `seq`, or nil if none.
    func firstSackedAfter(from seq: UInt32) -> UInt32? {
        let n = Int(count)
        var result: UInt32? = nil
        for i in 0..<n {
            let l = leftAt(i)
            if l >= seq, result == nil || l < result! { result = l }
        }
        return result
    }

    // MARK: - SACK option building

    /// Build SACK option bytes (kind=5, len=2+8*N, N blocks) for TCP header.
    /// Returns empty array when no blocks are recorded.
    /// - Parameter limit: Maximum number of blocks to include. Default 4 uses all blocks.
    func buildSACKOption(limit: Int = 4) -> [UInt8] {
        let n = min(Int(count), limit)
        guard n > 0 else { return [] }
        let optLen = 2 + n * 8
        var opt = [UInt8](repeating: 0, count: optLen)
        opt[0] = 5  // SACK kind
        opt[1] = UInt8(optLen)
        // RFC 2018: blocks in most-recent-first order
        for i in 0..<n {
            let base = 2 + i * 8
            let bi = n - 1 - i  // most recent first
            writeUInt32BE(leftAt(bi), to: &opt[base])
            writeUInt32BE(rightAt(bi), to: &opt[base + 4])
        }
        return opt
    }

    // MARK: - Maintenance

    /// Remove blocks fully before `seq` (acknowledged data).
    mutating func ackThrough(_ seq: UInt32) {
        let n = Int(count)
        var start = 0
        while start < n && leftAt(start) < seq { start += 1 }
        guard start > 0 else { return }
        let remaining = n - start
        for i in 0..<remaining { setAt(i, leftAt(start + i), rightAt(start + i)) }
        for i in remaining..<n { setAt(i, 0, 0) }
        count = UInt8(remaining)
    }

    mutating func clear() { count = 0; l0 = 0; r0 = 0; l1 = 0; r1 = 0; l2 = 0; r2 = 0; l3 = 0; r3 = 0 }
}
