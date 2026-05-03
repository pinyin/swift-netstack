import Darwin
import Foundation
import Virtualization

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

func connectUnixSocket(remotePath: String, localPath: String) -> Int32 {
    let fd = socket(AF_UNIX, SOCK_DGRAM, 0)
    guard fd >= 0 else {
        die("socket: \(String(cString: strerror(errno)))")
    }

    // Bind to a local address so bdp-netstack can connect back for writes.
    // bdp-netstack's ListenVFKit calls ReadFromUnix to get our address,
    // then connect()s back to it for sending frames.
    let sunPathLen = MemoryLayout.size(ofValue: sockaddr_un().sun_path)
    var localAddr = sockaddr_un()
    localAddr.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
    localAddr.sun_family = sa_family_t(AF_UNIX)
    _ = withUnsafeMutablePointer(to: &localAddr.sun_path) { ptr in
        ptr.withMemoryRebound(to: CChar.self, capacity: sunPathLen) { sunPath in
            localPath.withCString { cstr in
                strlcpy(sunPath, cstr, sunPathLen)
            }
        }
    }
    unlink(localPath)
    let bindRet = withUnsafePointer(to: &localAddr) { ptr in
        ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
            Darwin.bind(fd, sa, UInt32(MemoryLayout<sockaddr_un>.size))
        }
    }
    if bindRet != 0 {
        close(fd)
        die("bind to \(localPath): \(String(cString: strerror(errno)))")
    }

    // Connect to bdp-netstack
    var remoteAddr = sockaddr_un()
    remoteAddr.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
    remoteAddr.sun_family = sa_family_t(AF_UNIX)
    _ = withUnsafeMutablePointer(to: &remoteAddr.sun_path) { ptr in
        ptr.withMemoryRebound(to: CChar.self, capacity: sunPathLen) { sunPath in
            remotePath.withCString { cstr in
                strlcpy(sunPath, cstr, sunPathLen)
            }
        }
    }
    let ret = withUnsafePointer(to: &remoteAddr) { ptr in
        ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
            Darwin.connect(fd, sa, UInt32(MemoryLayout<sockaddr_un>.size))
        }
    }
    if ret != 0 {
        close(fd)
        die("connect to \(remotePath): \(String(cString: strerror(errno)))")
    }
    let flags = fcntl(fd, F_GETFL, 0)
    guard flags >= 0 else { die("fcntl(F_GETFL) after connect: \(String(cString: strerror(errno)))") }
    guard fcntl(fd, F_SETFL, flags | O_NONBLOCK) >= 0 else {
        die("fcntl(F_SETFL) after connect: \(String(cString: strerror(errno)))")
    }
    return fd
}

// MARK: - Frame parsing

func parseFrame(_ data: Data) -> String {
    guard data.count >= 14 else {
        let hex = data.prefix(min(data.count, 32)).map { String(format: "%02x", $0) }.joined()
        return "<\(data.count)B: \(hex)>"
    }
    let dstMac = data[0..<6].map { String(format: "%02x", $0) }.joined(separator: ":")
    let srcMac = data[6..<12].map { String(format: "%02x", $0) }.joined(separator: ":")
    let etherType = (UInt16(data[12]) << 8) | UInt16(data[13])
    let typeStr: String
    switch etherType {
    case 0x0800: typeStr = "IPv4"
    case 0x0806: typeStr = "ARP"
    case 0x86DD: typeStr = "IPv6"
    default: typeStr = String(format: "0x%04x", etherType)
    }

    var info = ""
    if etherType == 0x0806, data.count >= 42 {
        let op = (UInt16(data[20]) << 8) | UInt16(data[21])
        let sip = "\(data[28]).\(data[29]).\(data[30]).\(data[31])"
        let tip = "\(data[38]).\(data[39]).\(data[40]).\(data[41])"
        info = " ARP \(op == 1 ? "REQ" : (op == 2 ? "REPLY" : "op=\(op)")) \(sip)→\(tip)"
    } else if etherType == 0x0800, data.count >= 34 {
        let ihl = Int(data[14] & 0x0f) * 4
        let tp = 14 + ihl  // transport start (after Ethernet + IP headers)
        guard data.count >= tp else { return "IPv4 short hdr" }
        let proto = data[23]
        let srcIP = "\(data[26]).\(data[27]).\(data[28]).\(data[29])"
        let dstIP = "\(data[30]).\(data[31]).\(data[32]).\(data[33])"
        switch proto {
        case 6 where data.count >= tp + 20:
            let tcpHdrLen = Int((data[tp + 12] >> 4)) * 4
            let realHdrEnd = tp + tcpHdrLen
            guard data.count >= realHdrEnd else { break }
            let srcPort = Int((UInt16(data[tp]) << 8) | UInt16(data[tp + 1]))
            let dstPort = Int((UInt16(data[tp + 2]) << 8) | UInt16(data[tp + 3]))
            let seq = (UInt32(data[tp + 4]) << 24) | (UInt32(data[tp + 5]) << 16) | (UInt32(data[tp + 6]) << 8) | UInt32(data[tp + 7])
            let ack = (UInt32(data[tp + 8]) << 24) | (UInt32(data[tp + 9]) << 16) | (UInt32(data[tp + 10]) << 8) | UInt32(data[tp + 11])
            let flags = data[tp + 13]
            var fl: [String] = []
            if flags & 0x02 != 0 { fl.append("SYN") }
            if flags & 0x10 != 0 { fl.append("ACK") }
            if flags & 0x01 != 0 { fl.append("FIN") }
            if flags & 0x04 != 0 { fl.append("RST") }
            if flags & 0x08 != 0 { fl.append("PSH") }
            let payloadLen = data.count - realHdrEnd
            info = " TCP \(srcPort)→\(dstPort) \(fl.joined(separator: "+")) seq=\(seq) ack=\(ack) pay=\(payloadLen)"
        case 17 where data.count >= tp + 8:
            let srcPort = Int((UInt16(data[tp]) << 8) | UInt16(data[tp + 1]))
            let dstPort = Int((UInt16(data[tp + 2]) << 8) | UInt16(data[tp + 3]))
            info = " UDP \(srcPort)→\(dstPort)"
        case 1 where data.count >= tp + 4:
            let t = data[tp]
            info = " ICMP \(t == 8 ? "EchoReq" : t == 0 ? "EchoReply" : "t=\(t)")"
        default:
            info = " P\(proto) \(srcIP)→\(dstIP)"
        }
    }
    return "\(dstMac)←\(srcMac) \(typeStr)\(info) len=\(data.count)"
}

// MARK: - Network Bridge (VZ socketpair ↔ BDP unixgram socket)

final class NetworkBridge {
    private let vzFd: Int32      // our end of the socketpair (reads from VZ, writes to VZ)
    private let bdpFd: Int32     // connected to bdp-netstack's unixgram socket
    private let report: (String) -> Void
    private let queue = DispatchQueue(label: "net.bridge", qos: .userInitiated)
    private var vzSource: DispatchSourceRead?
    private var bdpSource: DispatchSourceRead?
    var frameCount: Int = 0
    var byteCount: UInt64 = 0

    init(vzFd: Int32, bdpSocketPath: String, report: @escaping (String) -> Void) {
        self.vzFd = vzFd
        let localPath = bdpSocketPath + ".bridge-\(getpid())"
        self.bdpFd = connectUnixSocket(remotePath: bdpSocketPath, localPath: localPath)
        self.report = report

        // Send VFKT magic
        let vfkt: [UInt8] = [0x56, 0x46, 0x4b, 0x54] // "VFKT"
        let w = Darwin.write(bdpFd, vfkt, 4)
        if w != 4 {
            report("BRIDGE: WARNING VFKT write returned \(w) errno=\(errno)")
        }
        report("BRIDGE: sent VFKT to \(bdpSocketPath) bdpFd=\(bdpFd) vzFd=\(vzFd)")

        vzSource = DispatchSource.makeReadSource(fileDescriptor: vzFd, queue: queue)
        bdpSource = DispatchSource.makeReadSource(fileDescriptor: bdpFd, queue: queue)

        vzSource!.setEventHandler { [weak self] in
            self?.forward(from: "VM→BDP", readFd: self?.vzFd ?? -1, writeFd: self?.bdpFd ?? -1)
        }
        bdpSource!.setEventHandler { [weak self] in
            self?.forward(from: "BDP→VM", readFd: self?.bdpFd ?? -1, writeFd: self?.vzFd ?? -1)
        }

        vzSource!.setCancelHandler { [weak self] in
            if let fd = self?.vzFd, fd >= 0 { close(fd) }
        }
        bdpSource!.setCancelHandler { [weak self] in
            if let fd = self?.bdpFd, fd >= 0 { close(fd) }
        }

        vzSource!.resume()
        bdpSource!.resume()
        report("BRIDGE: forwarding started")
    }

    func stop() {
        vzSource?.cancel()
        bdpSource?.cancel()
    }

    private func forward(from dir: String, readFd: Int32, writeFd: Int32) {
        var buf = [UInt8](repeating: 0, count: 65536)
        let n = Darwin.read(readFd, &buf, buf.count)
        if n > 0 {
            frameCount += 1
            byteCount += UInt64(n)
            let data = Data(buf.prefix(n))
            report("NET #\(frameCount) \(dir) \(parseFrame(data))")
            data.withUnsafeBytes { ptr in
                _ = Darwin.write(writeFd, ptr.baseAddress!, n)
            }
        } else if n < 0 && errno != EAGAIN && errno != EWOULDBLOCK {
            report("BRIDGE: \(dir) read err: \(String(cString: strerror(errno)))")
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

struct VMConfig {
    let disk: String
    let cpus: Int
    let memory: Int      // MB
    let mac: String
    let consoleLog: String
    let efiStore: String
}

func buildVM(_ cfg: VMConfig) throws -> (VZVirtualMachine, Int32) {
    // Network: socketpair → one end to VZ, return the other for the bridge
    let (vzFd, bridgeFd) = makeSocketPair()
    let vzFH = FileHandle(fileDescriptor: vzFd, closeOnDealloc: false)
    let netAttachment = VZFileHandleNetworkDeviceAttachment(fileHandle: vzFH)
    let netDevice = VZVirtioNetworkDeviceConfiguration()
    netDevice.attachment = netAttachment
    netDevice.macAddress = VZMACAddress(string: cfg.mac)!

    // Storage
    let diskURL = URL(fileURLWithPath: cfg.disk)
    guard FileManager.default.fileExists(atPath: cfg.disk) else {
        throw NSError(domain: "vz-debug", code: 1, userInfo: [NSLocalizedDescriptionKey: "disk not found: \(cfg.disk)"])
    }
    let diskAttachment = try VZDiskImageStorageDeviceAttachment(url: diskURL, readOnly: false)
    let storageDevice = VZVirtioBlockDeviceConfiguration(attachment: diskAttachment)

    // EFI
    let efiURL = URL(fileURLWithPath: cfg.efiStore)
    let efiStoreObj: VZEFIVariableStore
    if FileManager.default.fileExists(atPath: cfg.efiStore) {
        efiStoreObj = VZEFIVariableStore(url: efiURL)
    } else {
        efiStoreObj = try VZEFIVariableStore(creatingVariableStoreAt: efiURL, options: [])
    }
    let bootLoader = VZEFIBootLoader()
    bootLoader.variableStore = efiStoreObj

    // Serial console
    FileManager.default.createFile(atPath: cfg.consoleLog, contents: nil)
    let consoleFH = try FileHandle(forWritingTo: URL(fileURLWithPath: cfg.consoleLog))
    let nullFH = FileHandle(forReadingAtPath: "/dev/null")!
    let consoleAttachment = VZFileHandleSerialPortAttachment(
        fileHandleForReading: nullFH,
        fileHandleForWriting: consoleFH
    )
    let serialPort = VZVirtioConsoleDeviceSerialPortConfiguration()
    serialPort.attachment = consoleAttachment

    // Assemble
    let config = VZVirtualMachineConfiguration()
    config.platform = VZGenericPlatformConfiguration()
    config.bootLoader = bootLoader
    config.cpuCount = cfg.cpus
    config.memorySize = UInt64(cfg.memory) * 1024 * 1024
    config.networkDevices = [netDevice]
    config.storageDevices = [storageDevice]
    config.serialPorts = [serialPort]

    try config.validate()
    log("VZ config validated: cpus=\(cfg.cpus) mem=\(cfg.memory)MB mac=\(cfg.mac)")
    log("VZ limits: cpu[\(VZVirtualMachineConfiguration.minimumAllowedCPUCount)..\(VZVirtualMachineConfiguration.maximumAllowedCPUCount)] mem[\(VZVirtualMachineConfiguration.minimumAllowedMemorySize / 1024 / 1024)..\(VZVirtualMachineConfiguration.maximumAllowedMemorySize / 1024 / 1024)]MB")

    let vm = VZVirtualMachine(configuration: config)
    return (vm, bridgeFd)
}

// MARK: - Args

struct Args {
    var disk = ""
    var socket = ""
    var consoleLog = ""
    var efiStore = ""
    var cpus = 2
    var memory = 2048
    var mac = "5a:94:ef:e4:0c:ef"
}

func parseArgs() -> Args? {
    let argv = CommandLine.arguments
    var args = Args()
    var i = 1
    while i < argv.count {
        switch argv[i] {
        case "--disk":        args.disk = argv[i + 1]; i += 2
        case "--socket":      args.socket = argv[i + 1]; i += 2
        case "--console-log": args.consoleLog = argv[i + 1]; i += 2
        case "--efi-store":   args.efiStore = argv[i + 1]; i += 2
        case "--cpus":        args.cpus = Int(argv[i + 1]) ?? 2; i += 2
        case "--memory":      args.memory = Int(argv[i + 1]) ?? 2048; i += 2
        case "--mac":         args.mac = argv[i + 1]; i += 2
        default:
            fputs("Unknown arg: \(argv[i])\n", stderr)
            return nil
        }
    }
    guard !args.disk.isEmpty, !args.socket.isEmpty,
          !args.consoleLog.isEmpty, !args.efiStore.isEmpty else { return nil }
    return args
}

// MARK: - Entry point

let usage = """
    Usage: vz-debug --disk <path> --socket <path> --console-log <path> --efi-store <path> \\
                    [--cpus N] [--memory MB] [--mac MAC]
    """

guard let args = parseArgs() else {
    fputs(usage, stderr)
    exit(1)
}

log("vz-debug: disk=\(args.disk) socket=\(args.socket) cpus=\(args.cpus) mem=\(args.memory)MB mac=\(args.mac)")
log("vz-debug: console=\(args.consoleLog) efi=\(args.efiStore)")

// Build VM (returns the bridge-side fd)
let (vm, bridgeFd): (VZVirtualMachine, Int32)
do {
    (vm, bridgeFd) = try buildVM(VMConfig(
        disk: args.disk, cpus: args.cpus, memory: args.memory,
        mac: args.mac, consoleLog: args.consoleLog, efiStore: args.efiStore
    ))
} catch {
    die("build VM: \(error)")
}

// Start bridge (connects to bdp-netstack, sends VFKT, begins forwarding)
let bridge = NetworkBridge(vzFd: bridgeFd, bdpSocketPath: args.socket, report: log)

// VM delegate (strong reference kept in vmDelegate)
let vmDelegate = VMDelegate { error in
    bridge.stop()
    let s = bridge.frameCount
    let b = bridge.byteCount
    log("VM stopped. Bridge forwarded \(s) frames, \(b) bytes.")
    CFRunLoopStop(CFRunLoopGetMain())
}
vm.delegate = vmDelegate

// Start VM using completion handler (avoids async/await + run loop conflict)
vm.start { result in
    switch result {
    case .success:
        log("VM started, state=\(vm.state.rawValue)")
    case .failure(let error):
        log("VM start failed: \(error)")
        bridge.stop()
        exit(1)
    }
}

log("vz-debug: VM running, waiting for exit...")
CFRunLoopRun()
log("vz-debug: exiting")
exit(0)
