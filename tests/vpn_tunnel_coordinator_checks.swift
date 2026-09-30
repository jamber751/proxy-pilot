import Darwin
import Foundation

enum CoordinatorCheckError: Error { case failed(String) }
final class Counter { var value = 0 }

@main enum VPNTunnelCoordinatorChecks {
    static func fail(_ message: String) -> Never {
        FileHandle.standardError.write(Data((message + "\n").utf8)); exit(90)
    }

    static func readLine(_ socket: Int32) -> String? {
        var bytes = [UInt8]()
        while bytes.count < 256 {
            var byte: UInt8 = 0
            let count = recv(socket, &byte, 1, 0)
            if count <= 0 { return nil }
            if byte == 10 { return String(bytes: bytes, encoding: .utf8) }
            bytes.append(byte)
        }
        return nil
    }

    static func sendLine(_ socket: Int32, _ line: String) {
        let bytes = Array((line + "\n").utf8)
        _ = bytes.withUnsafeBytes { send(socket, $0.baseAddress, bytes.count, MSG_NOSIGNAL) }
    }

    static func child() -> Never {
        let arguments = CommandLine.arguments
        guard let configIndex = arguments.firstIndex(of: "--config"),
              configIndex + 1 < arguments.count, arguments[configIndex + 1] == "/dev/fd/21",
              let managementIndex = arguments.firstIndex(of: "--management"),
              managementIndex + 2 < arguments.count,
              arguments[managementIndex + 2] == "unix",
              arguments.contains("--management-hold"),
              arguments.contains("--management-query-passwords"),
              arguments.contains("--route-noexec"), arguments.contains("--ifconfig-noexec"),
              !arguments.contains("hold release") else { exit(41) }
        var profileBytes = [UInt8](repeating: 0, count: 64)
        let profileCount = read(21, &profileBytes, profileBytes.count)
        guard profileCount > 0 else { exit(42) }
        let behavior = String(decoding: profileBytes.prefix(profileCount), as: UTF8.self)
        if behavior == "no-socket" { while true { pause() } }

        let path = arguments[managementIndex + 1]
        let listener = socket(AF_UNIX, SOCK_STREAM, 0)
        guard listener >= 0 else { exit(43) }
        var address = sockaddr_un()
        let pathBytes = Array(path.utf8) + [0]
        guard pathBytes.count <= MemoryLayout.size(ofValue: address.sun_path) else { exit(44) }
        address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        address.sun_family = sa_family_t(AF_UNIX)
        withUnsafeMutableBytes(of: &address.sun_path) { $0.copyBytes(from: pathBytes) }
        let bound = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(listener, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard bound == 0, listen(listener, 1) == 0 else { exit(45) }
        let client = accept(listener, nil, nil)
        guard client >= 0 else { exit(46) }
        sendLine(client, ">INFO:fake")
        sendLine(client, ">HOLD:Waiting for hold release")
        while let command = readLine(client) {
            switch command {
            case "state on":
                if behavior == "credential" {
                    sendLine(client, ">PASSWORD:Need 'Auth' username/password SC:OTP")
                } else if behavior == "reject" {
                    sendLine(client, "ERROR: rejected")
                } else {
                    sendLine(client, "SUCCESS: state notifications enabled")
                }
            case "state":
                if behavior == "connected" {
                    sendLine(client, "1,CONNECTED,redacted,10.8.0.2,203.0.113.9,443")
                } else {
                    sendLine(client, "1,WAIT,redacted,,,,")
                }
                sendLine(client, "END")
                if behavior == "observe" {
                    sendLine(client, ">STATE:2,RECONNECTING,redacted,,,,")
                }
            case "signal SIGTERM":
                sendLine(client, "SUCCESS: signal")
                close(client); close(listener); exit(0)
            case "hold release": exit(47)
            default: exit(48)
            }
        }
        close(client); close(listener); exit(0)
    }

    static func directory(_ path: String) -> Int32 {
        let descriptor = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
        guard descriptor >= 0 else { fail("directory") }
        return descriptor
    }

    static func profile(_ folder: String, behavior: String) -> (String, () throws -> Int32) {
        let path = URL(fileURLWithPath: folder).appendingPathComponent("profile").path
        let descriptor = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0o600)
        guard descriptor >= 0 else { fail("profile") }
        let data = Data(behavior.utf8)
        let count = data.withUnsafeBytes { write(descriptor, $0.baseAddress, $0.count) }
        close(descriptor)
        guard count == data.count else { fail("profile write") }
        return (String(repeating: "a", count: 64), {
            let opened = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
            guard opened >= 0 else { throw CoordinatorCheckError.failed("profile open") }
            return opened
        })
    }

    static func coordinator(folder: String, behavior: String,
                            blocker: VPNTunnelCoordinatorBlocker? = nil,
                            counter: Counter) throws -> VPNTunnelCoordinator {
        let dir = directory(folder); defer { close(dir) }
        let value = profile(folder, behavior: behavior)
        let selection = VPNEngineExecutableSelection.test {
            counter.value += 1
            return open(CommandLine.arguments[0], O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
        }
        return try VPNTunnelCoordinator(testDirectory: dir, selection: selection,
            profileDigest: value.0, openProfile: { _ in try value.1() }, blocker: blocker)
    }

    static func assertClean(_ folder: String) {
        let names = (try? FileManager.default.contentsOfDirectory(atPath: folder)) ?? []
        guard !names.contains(where: { $0.hasSuffix(".sock") }) else { fail("socket leaked") }
    }

    static func main() throws {
        if let status = VPNEngineSupervisorEntry.runIfRequested(arguments: CommandLine.arguments) {
            exit(status)
        }
        if CommandLine.arguments.first == "vpn-engine" { child() }
        guard CommandLine.arguments.count == 3 else { fail("usage") }
        let test = CommandLine.arguments[1], folder = CommandLine.arguments[2]
        let counter = Counter()
        switch test {
        case "lifecycle":
            let tunnel = try coordinator(folder: folder, behavior: "normal", counter: counter)
            guard try tunnel.start() == .managementReady(generation: 1, state: .waiting),
                  tunnel.readiness() == .managementReady(generation: 1, state: .waiting),
                  try tunnel.start() == .blocked(.alreadyRunning), counter.value == 1 else {
                fail("lifecycle readiness")
            }
            guard tunnel.stop() == .stopped(generation: 1) else { fail("stop") }
            assertClean(folder); print("passed")
        case "internal-connected":
            let tunnel = try coordinator(folder: folder, behavior: "connected", counter: counter)
            guard try tunnel.start() == .managementReady(generation: 1, state: .connected) else {
                fail("management observation")
            }
            _ = tunnel.stop(); assertClean(folder); print("passed")
        case "observe":
            let tunnel = try coordinator(folder: folder, behavior: "observe", counter: counter)
            guard try tunnel.start() == .managementReady(generation: 1, state: .waiting),
                  try tunnel.observe() == .managementReady(generation: 1, state: .reconnecting) else {
                fail("state observation")
            }
            _ = tunnel.stop(); assertClean(folder); print("passed")
        case "credential":
            let tunnel = try coordinator(folder: folder, behavior: "credential", counter: counter)
            guard try tunnel.start() == .blocked(.credentialRequired(.staticChallenge)) else {
                fail("credential blocker")
            }
            assertClean(folder); print("blocked")
        case "plan-blocked":
            let tunnel = try coordinator(folder: folder, behavior: "normal",
                blocker: .credentialRequired(.usernameAndPassword), counter: counter)
            guard try tunnel.start() == .blocked(.credentialRequired(.usernameAndPassword)),
                  counter.value == 0 else { fail("plan blocker") }
            assertClean(folder); print("blocked")
        case "reject":
            let tunnel = try coordinator(folder: folder, behavior: "reject", counter: counter)
            do { _ = try tunnel.start(); fail("rejection accepted") }
            catch { guard tunnel.readiness() == .failed(generation: 1) else { fail("failed state") } }
            assertClean(folder); print("rejected")
        case "timeout":
            let tunnel = try coordinator(folder: folder, behavior: "no-socket", counter: counter)
            let start = clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW)
            do { _ = try tunnel.start(timeoutMilliseconds: 100); fail("timeout accepted") }
            catch {
                let elapsed = (clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW) - start) / 1_000_000
                guard elapsed < 1_000, tunnel.readiness() == .failed(generation: 1) else { fail("timeout bound") }
            }
            assertClean(folder); print("timed out")
        default: fail("unknown")
        }
    }
}
