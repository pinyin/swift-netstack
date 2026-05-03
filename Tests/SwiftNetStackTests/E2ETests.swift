import Foundation
import Testing
import Virtualization
@testable import SwiftNetStack

// MARK: - E2E Test Configuration

struct E2EConfig {
    static let diskPath: String = {
        if let env = ProcessInfo.processInfo.environment["E2E_DISK"] { return env }
        return "/Users/pinyin/tmp/bdp-netstack-image-arm64/disk.raw"
    }()

    static let sshKeyPath: String = {
        if let env = ProcessInfo.processInfo.environment["E2E_SSH_KEY"] { return env }
        return "/Users/pinyin/developer/POC/bdp-netstack/test/image/test_key"
    }()

    static let efiStorePath = "/tmp/vz-e2e-efi.bin"
    static let consoleLogPath = "/tmp/vz-e2e-console.log"

    static let guestIP = ipToUInt32("192.168.65.2")
    static let sshHostPort: UInt16 = 2223
    static let sshGuestPort: UInt16 = 22

    static var diskAvailable: Bool {
        FileManager.default.fileExists(atPath: diskPath)
    }

    static var sshKeyAvailable: Bool {
        FileManager.default.fileExists(atPath: sshKeyPath)
    }
}

// MARK: - Running flag

final class E2ERunningFlag: @unchecked Sendable {
    var value: Bool = true
}

// MARK: - E2E Helper (synchronous)

func runE2ETest(_ body: (Stack, VZVirtualMachine) throws -> Void) {
    guard E2EConfig.diskAvailable else {
        Issue.record("Disk image not found at \(E2EConfig.diskPath). Set E2E_DISK env var.")
        return
    }
    guard E2EConfig.sshKeyAvailable else {
        Issue.record("SSH key not found at \(E2EConfig.sshKeyPath). Set E2E_SSH_KEY env var.")
        return
    }

    unlink(E2EConfig.efiStorePath)
    unlink(E2EConfig.consoleLogPath)

    // Build VM
    let vmCfg = VZVMConfig(
        disk: E2EConfig.diskPath,
        cpus: 2,
        memory: 2048,
        mac: "5a:94:ef:e4:0c:ef",
        consoleLog: E2EConfig.consoleLogPath,
        efiStore: E2EConfig.efiStorePath
    )
    let vm: VZVirtualMachine
    let bridgeFd: Int32
    do {
        (vm, bridgeFd) = try VZBuildVM(vmCfg)
    } catch {
        Issue.record("VZBuildVM failed: \(error)")
        return
    }

    // Wrap bridgeFd in VZDebugConn and inject into Stack
    let conn = VZDebugConn(fd: bridgeFd)

    var stackCfg = StackConfig.defaultConfig()
    stackCfg.socketPath = ""
    stackCfg.portForwards = [
        ForwarderMapping(
            hostPort: E2EConfig.sshHostPort,
            vmIP: E2EConfig.guestIP,
            vmPort: E2EConfig.sshGuestPort
        )
    ]

    let tcpState = TCPState(cfg: TCPConfig.defaultConfig())
    let stack = Stack(cfg: stackCfg, tcpState: tcpState)
    stack.setConn(conn)

    // Deliberation loop in background
    let runningFlag = E2ERunningFlag()
    let deliberationQueue = DispatchQueue(label: "e2e.deliberation", qos: .userInitiated)

    deliberationQueue.async {
        while runningFlag.value {
            stack.deliberate(now: Date())
            Thread.sleep(forTimeInterval: 0.001)
        }
    }

    // VM delegate
    let delegate = VZVMDelegate { error in
        print("E2E: VM stopped with error: \(error)")
        runningFlag.value = false
    }
    vm.delegate = delegate

    // Start VM
    let vmStarted = DispatchSemaphore(value: 0)
    var vmStartError: (any Error)?

    vm.start { result in
        switch result {
        case .success:
            print("E2E: VM started successfully")
        case .failure(let error):
            print("E2E: VM start failed: \(error)")
            vmStartError = error
        }
        vmStarted.signal()
    }

    if vmStarted.wait(timeout: .now() + 30) == .timedOut {
        Issue.record("VM start timed out")
        runningFlag.value = false
        return
    }

    if let error = vmStartError {
        Issue.record("VM start failed: \(error)")
        runningFlag.value = false
        return
    }

    // Wait for SSH
    guard waitForSSH(host: "127.0.0.1", port: E2EConfig.sshHostPort, timeout: 120) else {
        Issue.record("SSH did not become available on port \(E2EConfig.sshHostPort) within timeout")
        stopVM(vm)
        runningFlag.value = false
        return
    }

    do {
        try body(stack, vm)
    } catch {
        Issue.record("E2E test body threw: \(error)")
    }

    // Cleanup
    stopVM(vm)
    runningFlag.value = false
    Thread.sleep(forTimeInterval: 0.1)
}

func stopVM(_ vm: VZVirtualMachine) {
    if vm.state == .running || vm.state == .starting {
        do {
            try vm.requestStop()
        } catch {
            print("E2E: requestStop failed: \(error)")
        }
    }
}

// MARK: - SSH Helpers (synchronous)

func waitForSSH(host: String, port: UInt16, timeout: Int) -> Bool {
    let deadline = Date().addingTimeInterval(TimeInterval(timeout))
    while Date() < deadline {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/ssh")
        task.arguments = [
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "ConnectTimeout=5",
            "-o", "BatchMode=yes",
            "-i", E2EConfig.sshKeyPath,
            "-p", "\(port)",
            "root@\(host)",
            "echo ok"
        ]
        task.standardOutput = FileHandle.nullDevice
        task.standardError = FileHandle.nullDevice

        do {
            try task.run()
            task.waitUntilExit()
            if task.terminationStatus == 0 {
                return true
            }
        } catch {
            // SSH not ready yet
        }

        Thread.sleep(forTimeInterval: 2)
    }
    return false
}

func sshExec(_ cmd: String, port: UInt16 = E2EConfig.sshHostPort) throws -> (exitCode: Int32, stdout: String, stderr: String) {
    let task = Process()
    task.executableURL = URL(fileURLWithPath: "/usr/bin/ssh")
    task.arguments = [
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "ConnectTimeout=10",
        "-o", "BatchMode=yes",
        "-i", E2EConfig.sshKeyPath,
        "-p", "\(port)",
        "root@127.0.0.1",
        cmd
    ]

    let outPipe = Pipe()
    let errPipe = Pipe()
    task.standardOutput = outPipe
    task.standardError = errPipe

    try task.run()
    task.waitUntilExit()

    let outData = outPipe.fileHandleForReading.readDataToEndOfFile()
    let errData = errPipe.fileHandleForReading.readDataToEndOfFile()

    return (
        task.terminationStatus,
        String(data: outData, encoding: .utf8) ?? "",
        String(data: errData, encoding: .utf8) ?? ""
    )
}

// MARK: - E2E Tests

@Test func testE2ESSHEcho() throws {
    guard E2EConfig.diskAvailable else {
        print("SKIP: disk image not available")
        return
    }

    runE2ETest { stack, vm in
        let (exit, stdout, _) = try sshExec("echo hello-from-e2e")
        #expect(exit == 0, "SSH echo should succeed")
        #expect(stdout.trimmingCharacters(in: .whitespacesAndNewlines) == "hello-from-e2e")
    }
}

@Test func testE2EDNSResolution() throws {
    guard E2EConfig.diskAvailable else {
        print("SKIP: disk image not available")
        return
    }

    runE2ETest { stack, vm in
        let (_, stdout, _) = try sshExec("cat /etc/resolv.conf")
        #expect(stdout.contains("192.168.65.1"), "DNS should point to gateway IP")
    }
}

@Test func testE2EVMHasNetwork() throws {
    guard E2EConfig.diskAvailable else {
        print("SKIP: disk image not available")
        return
    }

    runE2ETest { stack, vm in
        let (exit, stdout, _) = try sshExec("ip addr show eth0 2>/dev/null || ip addr show enp0s1 2>/dev/null || echo NO_IFACE")
        #expect(exit == 0)
        #expect(!stdout.contains("NO_IFACE"), "VM should have a network interface")
        #expect(stdout.contains("192.168.65"), "VM should have an IP in the gateway subnet")
    }
}
