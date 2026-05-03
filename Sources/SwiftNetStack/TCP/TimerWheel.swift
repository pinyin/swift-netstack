import Foundation

// MARK: - TimerWheel

struct SlotEntry {
    let tuple: Tuple
    let tick: Int64
}

final class TimerWheel {
    private var slots: [[SlotEntry]]
    let slotSize: Int64 // nanoseconds per slot
    let numSlots: Int
    private var cursor: Int = 0
    private var lastTick: Int64

    init(slotSizeNs: Int64, numSlots: Int) {
        self.slotSize = slotSizeNs
        self.numSlots = numSlots
        self.slots = [[SlotEntry]](repeating: [], count: numSlots)
        self.lastTick = Int64(Date().timeIntervalSince1970 * 1e9) / slotSizeNs
    }

    func advance(now: Date) -> Int64 {
        Int64(now.timeIntervalSince1970 * 1e9) / slotSize
    }

    func schedule(tuple: Tuple, tick: Int64) {
        var slot = Int(tick % Int64(numSlots))
        if slot < 0 { slot += numSlots }
        slots[slot].append(SlotEntry(tuple: tuple, tick: tick))
    }

    func expired(currentTick: Int64) -> [Tuple] {
        guard currentTick > lastTick else { return [] }

        var expired: [Tuple] = []

        // If we skipped a full wheel cycle (e.g. sleep/wake >30s),
        // scan all slots to avoid losing timers permanently.
        if currentTick - lastTick >= Int64(numSlots) {
            for slot in 0..<numSlots {
                var remaining: [SlotEntry] = []
                for entry in slots[slot] {
                    if entry.tick <= currentTick {
                        expired.append(entry.tuple)
                    } else {
                        remaining.append(entry)
                    }
                }
                slots[slot] = remaining
            }
        } else {
            let start = Int(lastTick % Int64(numSlots))
            let end = Int(currentTick % Int64(numSlots))

            var i = start + 1
            while true {
                let slot = i % numSlots
                var remaining: [SlotEntry] = []
                for entry in slots[slot] {
                    if entry.tick <= currentTick {
                        expired.append(entry.tuple)
                    } else {
                        remaining.append(entry)
                    }
                }
                slots[slot] = remaining
                if slot == end { break }
                i += 1
            }
        }

        lastTick = currentTick
        return expired
    }
}
