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
    var kernel = ""
    var initrd = ""
    var cmdline = "console=hvc0 init=/init loglevel=4 panic=10"
    var disk = ""
    var efiStore = ""
    var cpus = 2
    var memory = 1024
    var mac = "72:20:43:51:64:01"
    var subnet = "100.64.1.0/24"
    var gateway = "100.64.1.1"
    var hosts: [(String, String)] = []
    var upstreamDNS = ""
    var pcapPath = ""
    var mtu = 1500
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
        case "--dns":        args.upstreamDNS = argv[i + 1]; i += 2
        case "--mtu":        args.mtu = Int(argv[i + 1]) ?? 1500; i += 2
        case "--pcap":       args.pcapPath = argv[i + 1]; i += 2
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

// MARK: - Entry point

let usage = """
    Usage:
      Linux boot:
        SwiftNetStackDemo --kernel <path> --initrd <path> [--cmdline \"...\"] \\
                          [--cpus N] [--memory MB] [--mac MAC] \\
                          [--subnet CIDR] [--gateway IP] [--dns IP] [--host name:IP] \\
                          [--mtu N] [--pcap <path>]
      EFI boot:
        SwiftNetStackDemo --disk <path> --efi-store <path> \\
                          [--cpus N] [--memory MB] [--mac MAC] \\
                          [--subnet CIDR] [--gateway IP] [--dns IP] [--host name:IP] \\
                          [--mtu N] [--pcap <path>]

    Boots a Linux VM with VZFileHandleNetworkDevice networking backed by the
    SwiftNetStack BDP pipeline (ARP, DHCP, DNS, NAT, TCP).
    --pcap <path>  Write VM↔NAT Ethernet frames to a .pcap file for Wireshark.
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
let endpoint = VMEndpoint(id: 1, fd: bridgeFd, subnet: subnet, gateway: gatewayIP, mtu: args.mtu)

let upstreamDNS: IPv4Address? = args.upstreamDNS.isEmpty ? nil : parseIPv4(args.upstreamDNS)
if !args.upstreamDNS.isEmpty && upstreamDNS == nil {
    log("WARNING: invalid upstream DNS address: \(args.upstreamDNS), DNS forwarding disabled")
}

// Start the BDP pipeline on a dedicated background queue.
let bdpQueue = DispatchQueue(label: "bdp.loop", qos: .userInitiated)
bdpQueue.async {
    var shutdown = false
    var transport = PollingTransport(
        endpoints: [endpoint],
        shutdownFD: shutdownRead,
        onShutdown: { shutdown = true },
        pollTimeout: 100
    )
    var loop = DeliberationLoop(
        endpoints: [endpoint],
        hostMAC: hostMAC,
        hosts: hosts,
        upstreamDNS: upstreamDNS
    )

    if !args.pcapPath.isEmpty {
        let pw = PCAPWriter()
        if pw.start(path: args.pcapPath) {
            loop.pcapWriter = pw
            log("PCAP capture enabled: \(args.pcapPath)")
        } else {
            log("WARNING: failed to open pcap file: \(args.pcapPath)")
        }
    }

    let rounds = loop.run(transport: &transport, while: { !shutdown })
    log("BDP loop exited: rounds=\(rounds)")
}

// VM lifecycle — write shutdown signal on stop, drain the main run loop
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
