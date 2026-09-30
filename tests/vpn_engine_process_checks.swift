import Darwin
import Foundation


@main enum VPNEngineProcessChecks {
    static func fail(_ message: String) -> Never {
        FileHandle.standardError.write(Data((message + "\n").utf8)); exit(90)
    }

    static let expectedArguments = [
        "vpn-engine", "--config", "/dev/fd/21", "--route-noexec", "--ifconfig-noexec",
        "--script-security", "1", "--auth-nocache", "--route-nopull"
    ]

    static func child() -> Never {
        guard CommandLine.arguments == expectedArguments else { exit(41) }
        // dyld/libSystem may synthesize this one process-local value even when
        // posix_spawn receives an empty envp. No parent value may survive.
        let environment = ProcessInfo.processInfo.environment
        guard environment.keys.allSatisfy({ $0 == "__CF_USER_TEXT_ENCODING" }) else { exit(42) }
        var bytes = [UInt8](repeating: 0, count: 4096)
        let count = read(21, &bytes, bytes.count)
        guard count > 0 else { exit(43) }
        for descriptor in 3...20 where fcntl(Int32(descriptor), F_GETFD) != -1 { exit(44) }
        for descriptor in 22...128 where fcntl(Int32(descriptor), F_GETFD) != -1 { exit(45) }
        let command = String(decoding: bytes.prefix(count), as: UTF8.self)
        if command.hasPrefix("record-ignore:") || command.hasPrefix("record-sleep:") {
            let path = String(command.split(separator: ":", maxSplits: 1)[1])
            let descriptor = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0o600)
            guard descriptor >= 0 else { exit(46) }
            let value = Data("\(getpid())".utf8)
            let written = value.withUnsafeBytes { write(descriptor, $0.baseAddress, $0.count) }
            close(descriptor); guard written == value.count else { exit(47) }
            if command.hasPrefix("record-ignore:") { signal(SIGTERM, SIG_IGN) }
            while true { pause() }
        }
        if command.hasPrefix("ignore") {
            signal(SIGTERM, SIG_IGN)
            while true { pause() }
        }
        if command.hasPrefix("sleep") { while true { pause() } }
        exit(23)
    }

    static func profile(_ directory: String, contents: String) -> Int32 {
        let path = URL(fileURLWithPath: directory).appendingPathComponent(UUID().uuidString).path
        let descriptor = open(path, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0o600)
        guard descriptor >= 0 else { fail("profile open") }
        let data = Data(contents.utf8)
        let written = data.withUnsafeBytes { write(descriptor, $0.baseAddress, $0.count) }
        guard written == data.count, lseek(descriptor, 0, SEEK_SET) == 0 else { fail("profile write") }
        return descriptor
    }

    static func selection(counter: UnsafeMutablePointer<Int>) -> VPNEngineExecutableSelection {
        VPNEngineExecutableSelection.test {
            counter.pointee += 1
            return open(CommandLine.arguments[0], O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
        }
    }

    static func requireNoChildren() {
        var status: Int32 = 0
        guard waitpid(-1, &status, WNOHANG) == -1, errno == ECHILD else {
            fail("supervisor not reaped")
        }
    }

    static func main() throws {
        if let status = VPNEngineSupervisorEntry.runIfRequested(arguments: CommandLine.arguments) {
            exit(status)
        }
        // posix_spawn gives the child this fixed argv, so this branch is
        // distinguishable without a test-only flag leaking into production.
        if CommandLine.arguments.first == "vpn-engine" { child() }
        guard CommandLine.arguments.count == 3 else { fail("usage") }
        let test = CommandLine.arguments[1], folder = CommandLine.arguments[2]
        var validations = 0

        switch test {
        case "exit":
            let config = profile(folder, contents: "exit"); defer { close(config) }
            let process = try VPNEngineProcess.start(selection: selection(counter: &validations),
                                                     protectedProfileDescriptor: config)
            guard validations == 1 else { fail("validation count") }
            let final = try process.wait(timeoutMilliseconds: 2_000)
            guard final == .exited(23) else { fail("exit status \(final)") }
            guard try process.state() == .exited(23) else { fail("stable status") }
            requireNoChildren()
            print("passed")
        case "term":
            let config = profile(folder, contents: "sleep"); defer { close(config) }
            let process = try VPNEngineProcess.start(selection: selection(counter: &validations),
                                                     protectedProfileDescriptor: config)
            guard try process.stop(graceMilliseconds: 500) == .signalled(SIGTERM) else { fail("term") }
            requireNoChildren()
            print("passed")
        case "timeout":
            let config = profile(folder, contents: "sleep"); defer { close(config) }
            let process = try VPNEngineProcess.start(selection: selection(counter: &validations),
                                                     protectedProfileDescriptor: config)
            guard try process.wait(timeoutMilliseconds: 2) == .running else { fail("timeout") }
            _ = try process.stop(graceMilliseconds: 500)
            print("passed")
        case "kill":
            let config = profile(folder, contents: "ignore"); defer { close(config) }
            let process = try VPNEngineProcess.start(selection: selection(counter: &validations),
                                                     protectedProfileDescriptor: config)
            usleep(100_000)
            let final = try process.stop(graceMilliseconds: 10)
            guard final == .signalled(SIGKILL) else { fail("kill \(final)") }
            requireNoChildren()
            print("passed")
        case "eof-controller":
            let pidFile = URL(fileURLWithPath: folder).appendingPathComponent("engine.pid").path
            let supervisorFile = URL(fileURLWithPath: folder)
                .appendingPathComponent("supervisor.pid").path
            let config = profile(folder, contents: "record-ignore:\(pidFile)"); defer { close(config) }
            let process = try VPNEngineProcess.start(selection: selection(counter: &validations),
                                                     protectedProfileDescriptor: config)
            let supervisorDescriptor = open(supervisorFile,
                O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0o600)
            guard supervisorDescriptor >= 0 else { fail("supervisor pid open") }
            let supervisorData = Data("\(process.testSupervisorPID)".utf8)
            let supervisorWritten = supervisorData.withUnsafeBytes {
                write(supervisorDescriptor, $0.baseAddress, $0.count)
            }
            close(supervisorDescriptor)
            guard supervisorWritten == supervisorData.count else { fail("supervisor pid write") }
            for _ in 0..<2_000 {
                if access(pidFile, F_OK) == 0 { _exit(0) }
                guard try process.state() == .running else { fail("child exited before eof") }
                usleep(1_000)
            }
            fail("child pid unavailable")
        case "profile":
            let path = URL(fileURLWithPath: folder).appendingPathComponent("bad-profile").path
            let config = open(path, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0o644)
            guard config >= 0 else { fail("bad profile open") }; defer { close(config) }
            _ = write(config, "x", 1)
            do {
                _ = try VPNEngineProcess.start(selection: selection(counter: &validations),
                                               protectedProfileDescriptor: config)
                fail("bad profile accepted")
            } catch VPNEngineProcessError.invalidProfile {
                guard validations == 0 else { fail("engine validated before profile") }
                print("rejected")
            }
        case "validation":
            let config = profile(folder, contents: "exit"); defer { close(config) }
            let rejected = VPNEngineExecutableSelection.test { throw VPNEngineProcessError.validationFailed }
            do {
                _ = try VPNEngineProcess.start(selection: rejected, protectedProfileDescriptor: config)
                fail("validation accepted")
            } catch VPNEngineProcessError.validationFailed { print("rejected") }
        default: fail("unknown")
        }
    }
}
