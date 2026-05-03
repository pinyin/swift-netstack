import Foundation

// MARK: - FlowStats

// All counters are accessed exclusively from the deliberation loop thread.
// No lock is needed.

final class FlowStats {
    // Stage 1: readHost (forwarder / NAT)
    var fwdReadCalls: Int64 = 0
    var fwdReadBytes: Int64 = 0
    var fwdReadEAGAIN: Int64 = 0
    var fwdBufFull: Int64 = 0
    var fwdBufBytes: Int64 = 0

    // Stage 2: sendDataAndAcks (TCP deliberation)
    var tcpDataSegs: Int64 = 0
    var tcpDataBytes: Int64 = 0
    var tcpAckOnly: Int64 = 0
    var tcpNoSend: Int64 = 0
    var tcpInFlight: Int64 = 0
    var tcpCanSend: Int64 = 0

    // Stage 3: output to vz-debug (sendSegment)
    var outSegs: Int64 = 0
    var outBytes: Int64 = 0
    var outARPMiss: Int64 = 0
    var outBufFull: Int64 = 0
    var outCSError: Int64 = 0

    private var tickCount: Int = 0
    private var lastPrintTick: Int = 0

    nonisolated(unsafe) static let global = FlowStats()

    func printIfDue() {
        tickCount += 1
        guard tickCount - lastPrintTick >= 1000 else { return }
        print()
        lastPrintTick = tickCount
    }

    func print() {
        let fwdCalls = fwdReadCalls; fwdReadCalls = 0
        let fwdBytes = fwdReadBytes; fwdReadBytes = 0
        let fwdEAGAIN = fwdReadEAGAIN; fwdReadEAGAIN = 0
        let fwdFull = fwdBufFull; fwdBufFull = 0
        let fwdBufB = fwdBufBytes; fwdBufBytes = 0
        let tcpSegs = tcpDataSegs; tcpDataSegs = 0
        let tcpBytes = tcpDataBytes; tcpDataBytes = 0
        let tcpAck = tcpAckOnly; tcpAckOnly = 0
        let tcpNone = tcpNoSend; tcpNoSend = 0
        let tcpInf = tcpInFlight; tcpInFlight = 0
        let tcpCan = tcpCanSend; tcpCanSend = 0
        let oSegs = outSegs; outSegs = 0
        let oBytes = outBytes; outBytes = 0
        let oArp = outARPMiss; outARPMiss = 0
        let oFull = outBufFull; outBufFull = 0
        let oCs = outCSError; outCSError = 0

        NSLog("DEBUG STATS (1s window): " +
              "read={calls:\(fwdCalls) bytes:\(fwdBytes) eagain:\(fwdEAGAIN) full:\(fwdFull) bufb:\(fwdBufB)} " +
              "tcp={segs:\(tcpSegs) bytes:\(tcpBytes) ack:\(tcpAck) nosend:\(tcpNone) inflight:\(tcpInf) cansnd:\(tcpCan)} " +
              "out={segs:\(oSegs) bytes:\(oBytes) arpmiss:\(oArp) buffull:\(oFull) cserr:\(oCs)}")
    }
}
