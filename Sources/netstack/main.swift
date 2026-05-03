import Foundation
import SwiftNetStack

// MARK: - Argument Parsing

func parseArgs() -> (stackConfig: StackConfig, tcpConfig: TCPConfig) {
    var socketPath = "/tmp/bdp-stack.sock"
    var gatewayIPStr = "192.168.65.1"
    var gatewayMACStr = "5a:94:ef:e4:0c:ee"
    var subnetCIDR = "192.168.65.0/24"
    var bpt: TimeInterval = 0.001
    var mtu = 1500
    var bufSize = 524288
    var debug = false
    var forwardArgs: [String] = []

    let args = CommandLine.arguments
    var i = 1
    while i < args.count {
        switch args[i] {
        case "--socket": i += 1; socketPath = args[i]
        case "--gateway-ip": i += 1; gatewayIPStr = args[i]
        case "--gateway-mac": i += 1; gatewayMACStr = args[i]
        case "--subnet": i += 1; subnetCIDR = args[i]
        case "--bpt": i += 1; bpt = TimeInterval(args[i]) ?? 0.001
        case "--mtu": i += 1; mtu = Int(args[i]) ?? 1500
        case "--buf-size": i += 1; bufSize = Int(args[i]) ?? 524288
        case "--debug": debug = true
        default: forwardArgs.append(args[i])
        }
        i += 1
    }

    // Parse gateway MAC
    let macParts = gatewayMACStr.split(separator: ":").compactMap { UInt8($0, radix: 16) }
    let gatewayMAC = macParts.count == 6 ? Data(macParts) : Data([0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xee])

    let gatewayIP = ipToUInt32(gatewayIPStr)

    // Parse port forwards: hostPort:vmIP:vmPort
    var portForwards: [ForwarderMapping] = []
    for arg in forwardArgs {
        let parts = arg.split(separator: ":")
        guard parts.count == 3,
              let hostPort = UInt16(parts[0]),
              let vmPort = UInt16(parts[2]) else {
            NSLog("invalid forward spec %@ (expected hostPort:vmIP:vmPort)", arg)
            continue
        }
        let vmIP = ipToUInt32(String(parts[1]))
        portForwards.append(ForwarderMapping(hostPort: hostPort, vmIP: vmIP, vmPort: vmPort))
    }

    var stackCfg = StackConfig()
    stackCfg.socketPath = socketPath
    stackCfg.gatewayMAC = gatewayMAC
    stackCfg.gatewayIP = gatewayIP
    stackCfg.subnetCIDR = subnetCIDR
    stackCfg.mtu = mtu
    stackCfg.bpt = bpt
    stackCfg.tcpBufSize = bufSize
    stackCfg.portForwards = portForwards
    stackCfg.debug = debug

    var tcpCfg = TCPConfig.defaultConfig()
    tcpCfg.listenPort = 0
    tcpCfg.gatewayIP = gatewayIP
    tcpCfg.bufferSize = bufSize
    tcpCfg.mtu = mtu - 20
    tcpCfg.bpt = bpt

    return (stackCfg, tcpCfg)
}

// MARK: - Main

let (stackCfg, tcpCfg) = parseArgs()
let tcpState = TCPState(cfg: tcpCfg)
let stack = Stack(cfg: stackCfg, tcpState: tcpState)

// Handle signals
let signalQueue = DispatchQueue(label: "signal")
signal(SIGINT, SIG_IGN)
signal(SIGTERM, SIG_IGN)

let sigSrc = DispatchSource.makeSignalSource(signal: SIGINT, queue: signalQueue)
sigSrc.setEventHandler {
    NSLog("Received SIGINT, shutting down")
    exit(0)
}
sigSrc.resume()

let sigTermSrc = DispatchSource.makeSignalSource(signal: SIGTERM, queue: signalQueue)
sigTermSrc.setEventHandler {
    NSLog("Received SIGTERM, shutting down")
    exit(0)
}
sigTermSrc.resume()

NSLog("BDP netstack starting: %@ on %@ (BPT=%.3fms)",
      ipString(stackCfg.gatewayIP), stackCfg.socketPath, stackCfg.bpt * 1000)

do {
    try stack.run()
} catch {
    NSLog("netstack error: %@", error.localizedDescription)
    exit(1)
}
