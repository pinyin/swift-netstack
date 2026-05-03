import Foundation
import Virtualization

// MARK: - VM Configuration

public struct VZVMConfig {
    public let disk: String
    public let cpus: Int
    public let memory: Int      // MB
    public let mac: String
    public let consoleLog: String
    public let efiStore: String

    public init(disk: String, cpus: Int, memory: Int, mac: String, consoleLog: String, efiStore: String) {
        self.disk = disk
        self.cpus = cpus
        self.memory = memory
        self.mac = mac
        self.consoleLog = consoleLog
        self.efiStore = efiStore
    }
}

// MARK: - Socket Helpers

public func VZMakeSocketPair() -> (Int32, Int32) {
    var fds: [Int32] = [0, 0]
    guard socketpair(AF_UNIX, SOCK_DGRAM, 0, &fds) == 0 else {
        fatalError("socketpair: \(String(cString: strerror(errno)))")
    }
    for fd in fds {
        let flags = fcntl(fd, F_GETFL, 0)
        guard flags >= 0 else { fatalError("fcntl(F_GETFL): \(String(cString: strerror(errno)))") }
        guard fcntl(fd, F_SETFL, flags | O_NONBLOCK) >= 0 else {
            fatalError("fcntl(F_SETFL): \(String(cString: strerror(errno)))")
        }
    }
    return (fds[0], fds[1])
}

public func VZConnectUnixSocket(remotePath: String, localPath: String) -> Int32 {
    let fd = socket(AF_UNIX, SOCK_DGRAM, 0)
    guard fd >= 0 else {
        fatalError("socket: \(String(cString: strerror(errno)))")
    }

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
        fatalError("bind to \(localPath): \(String(cString: strerror(errno)))")
    }

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
        fatalError("connect to \(remotePath): \(String(cString: strerror(errno)))")
    }
    let flags = fcntl(fd, F_GETFL, 0)
    guard flags >= 0 else { fatalError("fcntl(F_GETFL) after connect: \(String(cString: strerror(errno)))") }
    guard fcntl(fd, F_SETFL, flags | O_NONBLOCK) >= 0 else {
        fatalError("fcntl(F_SETFL) after connect: \(String(cString: strerror(errno)))")
    }
    return fd
}

// MARK: - Network Bridge

public final class VZNetworkBridge {
    private let vzFd: Int32
    private let bdpFd: Int32
    private let report: (String) -> Void
    private let queue = DispatchQueue(label: "net.bridge", qos: .userInitiated)
    private var vzSource: DispatchSourceRead?
    private var bdpSource: DispatchSourceRead?
    public var frameCount: Int = 0
    public var byteCount: UInt64 = 0

    public init(vzFd: Int32, bdpSocketPath: String, report: @escaping (String) -> Void) {
        self.vzFd = vzFd
        let localPath = bdpSocketPath + ".bridge-\(getpid())"
        self.bdpFd = VZConnectUnixSocket(remotePath: bdpSocketPath, localPath: localPath)
        self.report = report

        // Send VFKT handshake
        let vfkt: [UInt8] = [0x56, 0x46, 0x4b, 0x54]
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

    public func stop() {
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
            report("NET #\(frameCount) \(dir)")
            data.withUnsafeBytes { ptr in
                _ = Darwin.write(writeFd, ptr.baseAddress!, n)
            }
        } else if n < 0 && errno != EAGAIN && errno != EWOULDBLOCK {
            report("BRIDGE: \(dir) read err: \(String(cString: strerror(errno)))")
        }
    }
}

// MARK: - VM Delegate

public final class VZVMDelegate: NSObject, VZVirtualMachineDelegate {
    private let onStop: (any Error) -> Void
    public init(onStop: @escaping (any Error) -> Void) { self.onStop = onStop }
    public func virtualMachine(_ vm: VZVirtualMachine, didStopWithError error: any Error) {
        onStop(error)
    }
}

// MARK: - VM Builder

public func VZBuildVM(_ cfg: VZVMConfig) throws -> (VZVirtualMachine, Int32) {
    let (vzFd, bridgeFd) = VZMakeSocketPair()
    let vzFH = FileHandle(fileDescriptor: vzFd, closeOnDealloc: false)
    let netAttachment = VZFileHandleNetworkDeviceAttachment(fileHandle: vzFH)
    let netDevice = VZVirtioNetworkDeviceConfiguration()
    netDevice.attachment = netAttachment
    netDevice.macAddress = VZMACAddress(string: cfg.mac)!

    let diskURL = URL(fileURLWithPath: cfg.disk)
    guard FileManager.default.fileExists(atPath: cfg.disk) else {
        throw NSError(domain: "vz-debug", code: 1, userInfo: [NSLocalizedDescriptionKey: "disk not found: \(cfg.disk)"])
    }
    let diskAttachment = try VZDiskImageStorageDeviceAttachment(url: diskURL, readOnly: false)
    let storageDevice = VZVirtioBlockDeviceConfiguration(attachment: diskAttachment)

    let efiURL = URL(fileURLWithPath: cfg.efiStore)
    let efiStoreObj: VZEFIVariableStore
    if FileManager.default.fileExists(atPath: cfg.efiStore) {
        efiStoreObj = VZEFIVariableStore(url: efiURL)
    } else {
        efiStoreObj = try VZEFIVariableStore(creatingVariableStoreAt: efiURL, options: [])
    }
    let bootLoader = VZEFIBootLoader()
    bootLoader.variableStore = efiStoreObj

    FileManager.default.createFile(atPath: cfg.consoleLog, contents: nil)
    let consoleFH = try FileHandle(forWritingTo: URL(fileURLWithPath: cfg.consoleLog))
    let nullFH = FileHandle(forReadingAtPath: "/dev/null")!
    let consoleAttachment = VZFileHandleSerialPortAttachment(
        fileHandleForReading: nullFH, fileHandleForWriting: consoleFH
    )
    let serialPort = VZVirtioConsoleDeviceSerialPortConfiguration()
    serialPort.attachment = consoleAttachment

    let config = VZVirtualMachineConfiguration()
    config.platform = VZGenericPlatformConfiguration()
    config.bootLoader = bootLoader
    config.cpuCount = cfg.cpus
    config.memorySize = UInt64(cfg.memory) * 1024 * 1024
    config.networkDevices = [netDevice]
    config.storageDevices = [storageDevice]
    config.serialPorts = [serialPort]

    try config.validate()
    let vm = VZVirtualMachine(configuration: config)
    return (vm, bridgeFd)
}
