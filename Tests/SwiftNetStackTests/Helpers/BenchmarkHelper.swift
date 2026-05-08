import Foundation

struct ThroughputBenchmark {
    let bytesTransferred: Int
    let duration: Duration
    let roundCount: Int

    var mbps: Double {
        guard duration > .zero else { return 0 }
        let seconds = Double(duration.components.seconds)
            + Double(duration.components.attoseconds) / 1e18
        return Double(bytesTransferred) * 8 / seconds / 1_000_000
    }

    /// Measure throughput by running BDP rounds until `condition` returns false.
    /// Each call to `condition` should run one or more rounds and return
    /// (keepGoing: Bool, bytesThisBatch: Int).
    static func measure(
        rounds: () -> (keepGoing: Bool, bytesThisBatch: Int)
    ) -> ThroughputBenchmark {
        let clock = ContinuousClock()
        var totalBytes = 0
        var roundCount = 0

        let elapsed = clock.measure {
            while true {
                let (keepGoing, bytes) = rounds()
                totalBytes += bytes
                roundCount += 1
                if !keepGoing { break }
            }
        }

        return ThroughputBenchmark(
            bytesTransferred: totalBytes,
            duration: elapsed,
            roundCount: roundCount
        )
    }
}
