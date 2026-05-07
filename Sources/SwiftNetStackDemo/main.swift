import Darwin
import Foundation
import Virtualization
import SwiftNetStack

// MARK: - Logging

func logDate() -> String {
    let f = DateFormatter()
    f.dateFormat = "yyyy/MM/dd HH:mm:ss"
    return f.string(from: Date())
}

func log(_ msg: String) {
    fputs("\(logDate()) \(msg)\n", stderr)
    fflush(stderr)
}

func die(_ msg: String) -> Never {
    fputs("FATAL: \(logDate()) \(msg)\n", stderr)
    fflush(stderr)
    exit(1)
}

func hexDump(_ pkt: PacketBuffer, label: String, maxLen: Int = 64) {
    pkt.withUnsafeReadableBytes { buf in
        let n = min(buf.count, maxLen)
        let hex = (0..<n).map { String(format: "%02x", buf[$0]) }.joined(separator: " ")
        log("\(label) len=\(buf.count): \(hex)")
    }
}

// MARK: - Socket helpers

func makeSocketPair() -> (Int32, Int32) {
    var fds: [Int32] = [0, 0]
    guard socketpair(AF_UNIX, SOCK_DGRAM, 0, &fds) == 0 else {
        die("socketpair: \(String(cString: strerror(errno)))")
    }
    for fd in fds {
        let flags = fcntl(fd, F_GETFL, 0)
        guard flags >= 0 else { die("fcntl(F_GETFL): \(String(cString: strerror(errno)))") }
        guard fcntl(fd, F_SETFL, flags | O_NONBLOCK) >= 0 else {
            die("fcntl(F_SETFL): \(String(cString: strerror(errno)))")
        }
    }
    return (fds[0], fds[1])
}

// MARK: - Shutdown flag (reference type for cross-boundary signalling)

final class ShutdownFlag: @unchecked Sendable {
    var isSet: Bool = false
}

// MARK: - Frame stats (reference type to survive any Transport boxing)

final class FrameStats: @unchecked Sendable {
    var rx: UInt64 = 0
    var tx: UInt64 = 0
}

// MARK: - VZ Transport

/// Transport that reads raw Ethernet frames from a VZFileHandleNetworkDevice
/// socket pair, plus a shutdown fd that wakes poll() for clean exit.
struct VZTransport: Transport {
    let endpointID: Int
    let vmFD: Int32
    let shutdownFD: Int32
    let shutdownFlag: ShutdownFlag
    let stats: FrameStats
    let mtu: Int
    private let maxPackets: Int = 256

    init(endpointID: Int, vmFD: Int32, shutdownFD: Int32, shutdownFlag: ShutdownFlag, stats: FrameStats, mtu: Int = 1500) {
        self.endpointID = endpointID
        self.vmFD = vmFD
        self.shutdownFD = shutdownFD
        self.shutdownFlag = shutdownFlag
        self.stats = stats
        self.mtu = mtu

        var sndSize: Int = 1 * 1024 * 1024
        setsockopt(vmFD, SOL_SOCKET, SO_SNDBUF, &sndSize, socklen_t(MemoryLayout<Int>.size))
        var rcvSize: Int = 4 * 1024 * 1024
        setsockopt(vmFD, SOL_SOCKET, SO_RCVBUF, &rcvSize, socklen_t(MemoryLayout<Int>.size))
    }

    mutating func readPackets(round: RoundContext) -> [(endpointID: Int, packet: PacketBuffer)] {
        var pollfds: [pollfd] = [
            pollfd(fd: vmFD, events: Int16(POLLIN), revents: 0),
            pollfd(fd: shutdownFD, events: Int16(POLLIN), revents: 0),
        ]

        let rc = Darwin.poll(&pollfds, UInt32(pollfds.count), -1)
        guard rc > 0 else { return [] }

        // Shutdown signal — drain the byte, set flag, return empty
        if pollfds[1].revents & Int16(POLLIN) != 0 {
            var buf: UInt8 = 0
            _ = Darwin.read(shutdownFD, &buf, 1)
            shutdownFlag.isSet = true
            return []
        }

        // Check for dead VM fd
        if pollfds[0].revents & Int16(POLLNVAL | POLLERR | POLLHUP) != 0 {
            return []
        }

        guard pollfds[0].revents & Int16(POLLIN) != 0 else { return [] }

        var frames: [(endpointID: Int, packet: PacketBuffer)] = []
        frames.reserveCapacity(maxPackets)

        while frames.count < maxPackets {
            var pkt = round.allocate(capacity: mtu, headroom: 0)
            guard let ptr = pkt.appendPointer(count: mtu) else { break }

            var iov = iovec(iov_base: ptr, iov_len: mtu)
            var msg = msghdr(msg_name: nil, msg_namelen: 0, msg_iov: &iov, msg_iovlen: 1, msg_control: nil, msg_controllen: 0, msg_flags: 0)
            let n = Darwin.recvmsg(vmFD, &msg, 0)
            if n <= 0 { break }
            if n < mtu { pkt.trimBack(mtu - n) }
            frames.append((endpointID, pkt))
            stats.rx += 1
            if stats.rx <= 5 {
                hexDump(pkt, label: "RX[\(stats.rx)]")
            }
        }

        return frames
    }

    mutating func writePackets(_ packets: [(endpointID: Int, packet: PacketBuffer)]) {
        for (_, pkt) in packets {
            let n = pkt.sendmsg(to: vmFD, flags: Int32(MSG_DONTWAIT))
            if n < 0 {
                log("VZTransport.writePackets: sendmsg failed errno=\(errno) \(String(cString: strerror(errno)))")
            } else if stats.tx < 5 {
                hexDump(pkt, label: "TX[\(stats.tx)]")
            }
            stats.tx += 1
        }
    }
}

// MARK: - VM Delegate

final class VMDelegate: NSObject, VZVirtualMachineDelegate {
    let onStop: (any Error) -> Void
    init(onStop: @escaping (any Error) -> Void) { self.onStop = onStop }
    func virtualMachine(_ vm: VZVirtualMachine, didStopWithError error: any Error) {
        onStop(error)
    }
}

// MARK: - VM Builder

enum BootMode {
    case linux(kernel: String, initrd: String, cmdline: String)
    case efi(disk: String, efiStore: String)
}

struct VMConfig {
    let boot: BootMode
    let cpus: Int
    let memory: Int
    let mac: String
}

func buildVM(_ cfg: VMConfig) throws -> (VZVirtualMachine, Int32) {
    let (vzFd, bridgeFd) = makeSocketPair()
    let vzFH = FileHandle(fileDescriptor: vzFd, closeOnDealloc: false)
    let netAttachment = VZFileHandleNetworkDeviceAttachment(fileHandle: vzFH)
    let netDevice = VZVirtioNetworkDeviceConfiguration()
    netDevice.attachment = netAttachment
    netDevice.macAddress = VZMACAddress(string: cfg.mac)!

    let bootLoader: VZBootLoader
    var storageDevices: [VZStorageDeviceConfiguration] = []

    switch cfg.boot {
    case .linux(let kernel, let initrd, let cmdline):
        let kernelURL = URL(fileURLWithPath: kernel)
        let initrdURL = URL(fileURLWithPath: initrd)
        guard FileManager.default.fileExists(atPath: kernel) else {
            throw NSError(domain: "SwiftNetStackDemo", code: 1,
                userInfo: [NSLocalizedDescriptionKey: "kernel not found: \(kernel)"])
        }
        guard FileManager.default.fileExists(atPath: initrd) else {
            throw NSError(domain: "SwiftNetStackDemo", code: 2,
                userInfo: [NSLocalizedDescriptionKey: "initrd not found: \(initrd)"])
        }
        let lb = VZLinuxBootLoader(kernelURL: kernelURL)
        lb.initialRamdiskURL = initrdURL
        lb.commandLine = cmdline
        bootLoader = lb

    case .efi(let disk, let efiStore):
        let diskURL = URL(fileURLWithPath: disk)
        guard FileManager.default.fileExists(atPath: disk) else {
            throw NSError(domain: "SwiftNetStackDemo", code: 1,
                userInfo: [NSLocalizedDescriptionKey: "disk not found: \(disk)"])
        }
        let diskAttachment = try VZDiskImageStorageDeviceAttachment(url: diskURL, readOnly: false)
        storageDevices.append(VZVirtioBlockDeviceConfiguration(attachment: diskAttachment))

        let efiURL = URL(fileURLWithPath: efiStore)
        let efiStoreObj: VZEFIVariableStore
        if FileManager.default.fileExists(atPath: efiStore) {
            efiStoreObj = VZEFIVariableStore(url: efiURL)
        } else {
            efiStoreObj = try VZEFIVariableStore(creatingVariableStoreAt: efiURL, options: [])
        }
        let el = VZEFIBootLoader()
        el.variableStore = efiStoreObj
        bootLoader = el
    }

    // Console → stdin/stdout so we can interact with the VM
    let consoleAttachment = VZFileHandleSerialPortAttachment(
        fileHandleForReading: FileHandle.standardInput,
        fileHandleForWriting: FileHandle.standardOutput
    )
    let serialPort = VZVirtioConsoleDeviceSerialPortConfiguration()
    serialPort.attachment = consoleAttachment

    let config = VZVirtualMachineConfiguration()
    config.platform = VZGenericPlatformConfiguration()
    config.bootLoader = bootLoader
    config.cpuCount = cfg.cpus
    config.memorySize = UInt64(cfg.memory) * 1024 * 1024
    config.networkDevices = [netDevice]
    config.storageDevices = storageDevices
    config.serialPorts = [serialPort]

    try config.validate()
    log("VZ config validated: cpus=\(cfg.cpus) mem=\(cfg.memory)MB mac=\(cfg.mac)")

    let vm = VZVirtualMachine(configuration: config)
    return (vm, bridgeFd)
}

// MARK: - Args

struct Args {
    // Linux boot
    var kernel = ""
    var initrd = ""
    var cmdline = "console=hvc0 init=/init loglevel=4 panic=10"
    // EFI boot
    var disk = ""
    var efiStore = ""
    // Common
    var cpus = 2
    var memory = 1024
    var mac = "72:20:43:51:64:01"
    var subnet = "100.64.1.0/24"
    var gateway = "100.64.1.1"
    var hosts: [(String, String)] = []
}

func parseArgs() -> Args? {
    let argv = CommandLine.arguments
    var args = Args()
    var i = 1
    while i < argv.count {
        switch argv[i] {
        case "--kernel":      args.kernel = argv[i + 1]; i += 2
        case "--initrd":      args.initrd = argv[i + 1]; i += 2
        case "--cmdline":     args.cmdline = argv[i + 1]; i += 2
        case "--disk":        args.disk = argv[i + 1]; i += 2
        case "--efi-store":   args.efiStore = argv[i + 1]; i += 2
        case "--cpus":        args.cpus = Int(argv[i + 1]) ?? 2; i += 2
        case "--memory":      args.memory = Int(argv[i + 1]) ?? 1024; i += 2
        case "--mac":         args.mac = argv[i + 1]; i += 2
        case "--subnet":      args.subnet = argv[i + 1]; i += 2
        case "--gateway":     args.gateway = argv[i + 1]; i += 2
        case "--host":
            let parts = argv[i + 1].split(separator: ":", maxSplits: 1)
            if parts.count == 2 {
                args.hosts.append((String(parts[0]), String(parts[1])))
            }
            i += 2
        default:
            fputs("Unknown arg: \(argv[i])\n", stderr)
            return nil
        }
    }
    let hasLinux = !args.kernel.isEmpty
    let hasEFI = !args.disk.isEmpty && !args.efiStore.isEmpty
    guard hasLinux || hasEFI else { return nil }
    return args
}

// MARK: - IP address parsing

func parseIPv4(_ s: String) -> IPv4Address? {
    let parts = s.split(separator: ".", omittingEmptySubsequences: false)
    guard parts.count == 4,
          let a = UInt8(parts[0]), let b = UInt8(parts[1]),
          let c = UInt8(parts[2]), let d = UInt8(parts[3]) else { return nil }
    return IPv4Address(a, b, c, d)
}

func parseSubnet(_ s: String) -> (IPv4Address, Int)? {
    let parts = s.split(separator: "/")
    guard parts.count == 2,
          let ip = parseIPv4(String(parts[0])),
          let prefix = Int(parts[1]) else { return nil }
    return (ip, prefix)
}

// MARK: - Run BDP loop

func runBDPLoop(
    endpoint: VMEndpoint,
    hostMAC: MACAddress,
    hosts: [String: IPv4Address],
    shutdownFD: Int32,
    shutdownFlag: ShutdownFlag,
    stats: FrameStats
) {
    var transport: any Transport = VZTransport(
        endpointID: endpoint.id,
        vmFD: endpoint.fd,
        shutdownFD: shutdownFD,
        shutdownFlag: shutdownFlag,
        stats: stats,
        mtu: endpoint.mtu
    )
    var loop = DeliberationLoop(
        endpoints: [endpoint],
        hostMAC: hostMAC,
        hosts: hosts
    )

    var roundCount: UInt64 = 0
    var totalReplies: UInt64 = 0

    while !shutdownFlag.isSet {
        let n = loop.runOneRound(transport: &transport)
        roundCount += 1
        totalReplies += UInt64(max(0, n))
        if n > 0 {
            log("BDP round \(roundCount): replies=\(n) rx=\(stats.rx) tx=\(stats.tx)")
        } else if roundCount <= 3 || roundCount % 100 == 0 {
            log("BDP round \(roundCount): idle (rx=\(stats.rx) tx=\(stats.tx))")
        }
    }

    log("BDP loop exited: rounds=\(roundCount) replies=\(totalReplies) rx_frames=\(stats.rx) tx_frames=\(stats.tx)")
}

// MARK: - Entry point

let usage = """
    Usage:
      Linux boot:
        SwiftNetStackDemo --kernel <path> --initrd <path> [--cmdline \"...\"] \\
                          [--cpus N] [--memory MB] [--mac MAC] \\
                          [--subnet CIDR] [--gateway IP] [--host name:IP]
      EFI boot:
        SwiftNetStackDemo --disk <path> --efi-store <path> \\
                          [--cpus N] [--memory MB] [--mac MAC] \\
                          [--subnet CIDR] [--gateway IP] [--host name:IP]

    Boots a Linux VM with VZFileHandleNetworkDevice networking backed by the
    SwiftNetStack BDP pipeline (ARP, DHCP, DNS, NAT, TCP).
    """

guard let args = parseArgs() else {
    fputs(usage, stderr)
    exit(1)
}

guard let (subnetIP, prefixLen) = parseSubnet(args.subnet) else {
    die("invalid subnet: \(args.subnet)")
}
guard let gatewayIP = parseIPv4(args.gateway) else {
    die("invalid gateway: \(args.gateway)")
}

var hosts: [String: IPv4Address] = [:]
for (name, ipStr) in args.hosts {
    guard let ip = parseIPv4(ipStr) else {
        die("invalid IP for host \(name): \(ipStr)")
    }
    hosts[name] = ip
}

let subnet = IPv4Subnet(network: subnetIP, prefixLength: UInt8(prefixLen))
let hostMAC = MACAddress(0x00, 0x11, 0x22, 0x33, 0x44, 0x55)

let bootMode: BootMode
if !args.kernel.isEmpty {
    bootMode = .linux(kernel: args.kernel, initrd: args.initrd, cmdline: args.cmdline)
    log("SwiftNetStackDemo: boot=linux kernel=\(args.kernel) initrd=\(args.initrd)")
} else {
    bootMode = .efi(disk: args.disk, efiStore: args.efiStore)
    log("SwiftNetStackDemo: boot=efi disk=\(args.disk) efi=\(args.efiStore)")
}
log("SwiftNetStackDemo: cpus=\(args.cpus) mem=\(args.memory)MB mac=\(args.mac)")
log("SwiftNetStackDemo: subnet=\(args.subnet) gateway=\(args.gateway)")
if !hosts.isEmpty {
    log("SwiftNetStackDemo: hosts=\(hosts.map { "\($0.key)→\($0.value)" }.joined(separator: ", "))")
}

let (vm, bridgeFd): (VZVirtualMachine, Int32)
do {
    (vm, bridgeFd) = try buildVM(VMConfig(
        boot: bootMode, cpus: args.cpus, memory: args.memory, mac: args.mac
    ))
} catch {
    die("build VM: \(error)")
}

let (shutdownRead, shutdownWrite) = makeSocketPair()
let shutdownFlag = ShutdownFlag()
let stats = FrameStats()
let endpoint = VMEndpoint(id: 1, fd: bridgeFd, subnet: subnet, gateway: gatewayIP, mtu: 1500)

// Capture by copy to avoid actor isolation issues
let _endpoint = endpoint
let _hostMAC = hostMAC
let _hosts = hosts
let _shutdownRead = shutdownRead
let _shutdownFlag = shutdownFlag
let _stats = stats

let bdpQueue = DispatchQueue(label: "bdp.loop", qos: .userInitiated)
bdpQueue.async {
    runBDPLoop(
        endpoint: _endpoint,
        hostMAC: _hostMAC,
        hosts: _hosts,
        shutdownFD: _shutdownRead,
        shutdownFlag: _shutdownFlag,
        stats: _stats
    )
}

let vmDelegate = VMDelegate { error in
    log("VM stopped: \(error)")
    var one: UInt8 = 1
    _ = Darwin.write(shutdownWrite, &one, 1)
    CFRunLoopStop(CFRunLoopGetMain())
}
vm.delegate = vmDelegate

vm.start { result in
    switch result {
    case .success:
        log("VM started, state=\(vm.state.rawValue)")
    case .failure(let error):
        log("VM start failed: \(error)")
        var one: UInt8 = 1
        _ = Darwin.write(shutdownWrite, &one, 1)
        exit(1)
    }
}

log("SwiftNetStackDemo: running, BDP loop active on bdp.loop queue")
CFRunLoopRun()

close(shutdownWrite)
close(shutdownRead)
close(bridgeFd)
log("SwiftNetStackDemo: exiting")
exit(0)
