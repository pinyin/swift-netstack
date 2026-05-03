import Foundation
import Virtualization
import SwiftNetStack

// MARK: - E2E Configuration

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
}

// MARK: - Running flag

final class RunningFlag: @unchecked Sendable {
    var value: Bool = true
}

// MARK: - Helpers

func stopVM(_ vm: VZVirtualMachine) {
    if vm.state == .running || vm.state == .starting {
        do { try vm.requestStop() } catch {
            fputs("E2E: requestStop failed: \(error)\n", stderr)
        }
    }
}

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
            if task.terminationStatus == 0 { return true }
        } catch { }

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

// MARK: - Test Runner

func runE2ETests() -> Int32 {
    guard FileManager.default.fileExists(atPath: E2EConfig.diskPath) else {
        fputs("E2E: disk not found at \(E2EConfig.diskPath)\n", stderr)
        return 1
    }
    guard FileManager.default.fileExists(atPath: E2EConfig.sshKeyPath) else {
        fputs("E2E: SSH key not found at \(E2EConfig.sshKeyPath)\n", stderr)
        return 1
    }

    unlink(E2EConfig.efiStorePath)
    unlink(E2EConfig.consoleLogPath)

    // Build VM
    let vmCfg = VZVMConfig(
        disk: E2EConfig.diskPath,
        cpus: 2, memory: 2048,
        mac: "5a:94:ef:e4:0c:ef",
        consoleLog: E2EConfig.consoleLogPath,
        efiStore: E2EConfig.efiStorePath
    )
    let vm: VZVirtualMachine
    let bridgeFd: Int32
    do {
        (vm, bridgeFd) = try VZBuildVM(vmCfg)
    } catch {
        fputs("E2E: VZBuildVM failed: \(error)\n", stderr)
        return 1
    }
    fputs("E2E: VM built successfully\n", stderr)

    // Create Stack
    let conn = VZDebugConn(fd: bridgeFd)
    var stackCfg = StackConfig.defaultConfig()
    stackCfg.socketPath = ""
    stackCfg.portForwards = [
        ForwarderMapping(hostPort: E2EConfig.sshHostPort, vmIP: E2EConfig.guestIP, vmPort: E2EConfig.sshGuestPort)
    ]
    let tcpState = TCPState(cfg: TCPConfig.defaultConfig())
    let stack = Stack(cfg: stackCfg, tcpState: tcpState)
    stack.setConn(conn)

    // Deliberation loop
    let runningFlag = RunningFlag()
    let deliberationQueue = DispatchQueue(label: "e2e.deliberation", qos: .userInitiated)
    deliberationQueue.async {
        while runningFlag.value {
            stack.deliberate(now: Date())
            Thread.sleep(forTimeInterval: 0.001)
        }
    }

    // VM delegate
    let delegate = VZVMDelegate { error in
        fputs("E2E: VM stopped with error: \(error)\n", stderr)
        runningFlag.value = false
    }
    vm.delegate = delegate

    // Start VM using run loop (completion handler requires run loop to fire)
    var vmStarted = false
    var vmStartError: (any Error)?
    vm.start { result in
        switch result {
        case .success: fputs("E2E: VM started\n", stderr)
        case .failure(let e): fputs("E2E: VM start failed: \(e)\n", stderr); vmStartError = e
        }
        vmStarted = true
    }

    let vmStartDeadline = Date().addingTimeInterval(30)
    while !vmStarted && Date() < vmStartDeadline {
        RunLoop.current.run(until: Date().addingTimeInterval(0.1))
    }
    if !vmStarted {
        fputs("E2E: VM start timed out\n", stderr)
        runningFlag.value = false
        return 1
    }
    if let error = vmStartError {
        fputs("E2E: VM start error: \(error)\n", stderr)
        runningFlag.value = false
        return 1
    }

    // Wait for SSH
    fputs("E2E: waiting for SSH...\n", stderr)
    guard waitForSSH(host: "127.0.0.1", port: E2EConfig.sshHostPort, timeout: 120) else {
        fputs("E2E: SSH not available within timeout\n", stderr)
        stopVM(vm)
        runningFlag.value = false
        return 1
    }
    fputs("E2E: SSH is available\n", stderr)

    var passed = 0
    var failed = 0

    // Test 1: SSH echo
    fputs("\n=== Test 1: SSH Echo ===\n", stderr)
    do {
        let (exit, stdout, _) = try sshExec("echo hello-from-e2e")
        if exit == 0 && stdout.trimmingCharacters(in: .whitespacesAndNewlines) == "hello-from-e2e" {
            fputs("  PASS\n", stderr); passed += 1
        } else {
            fputs("  FAIL: exit=\(exit) stdout='\(stdout)'\n", stderr); failed += 1
        }
    } catch {
        fputs("  FAIL: \(error)\n", stderr); failed += 1
    }

    // Test 2: DNS resolution
    fputs("=== Test 2: DNS ===\n", stderr)
    do {
        let (_, stdout, _) = try sshExec("cat /etc/resolv.conf")
        if stdout.contains("192.168.65.1") {
            fputs("  PASS\n", stderr); passed += 1
        } else {
            fputs("  FAIL: resolv.conf='\(stdout)'\n", stderr); failed += 1
        }
    } catch {
        fputs("  FAIL: \(error)\n", stderr); failed += 1
    }

    // Test 3: Network interface
    fputs("=== Test 3: Network Interface ===\n", stderr)
    do {
        let (exit, stdout, _) = try sshExec("ip addr show eth0 2>/dev/null || ip addr show enp0s1 2>/dev/null || echo NO_IFACE")
        if exit == 0 && !stdout.contains("NO_IFACE") && stdout.contains("192.168.65") {
            fputs("  PASS\n", stderr); passed += 1
        } else {
            fputs("  FAIL: stdout='\(stdout)'\n", stderr); failed += 1
        }
    } catch {
        fputs("  FAIL: \(error)\n", stderr); failed += 1
    }

    // Cleanup
    stopVM(vm)
    runningFlag.value = false
    Thread.sleep(forTimeInterval: 0.1)

    fputs("\n=== Results: \(passed) passed, \(failed) failed ===\n", stderr)
    return failed == 0 ? 0 : 1
}

// MARK: - Entry point

fputs("e2e-runner: starting E2E tests\n", stderr)
let exitCode = runE2ETests()
fputs("e2e-runner: exiting with code \(exitCode)\n", stderr)
exit(exitCode)
