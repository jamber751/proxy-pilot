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

    static func markRelease(_ managementPath: String) {
        let folder = URL(fileURLWithPath: managementPath).deletingLastPathComponent()
        let path = folder.appendingPathComponent("hold-release.trace").path
        let fd = open(path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0o600)
        guard fd >= 0 else { exit(49) }
        var byte: UInt8 = 49
        guard write(fd, &byte, 1) == 1, fsync(fd) == 0 else { close(fd); exit(50) }
        close(fd)
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
              arguments.contains("--route-noexec"), !arguments.contains("--ifconfig-noexec"),
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
        if behavior != "no-hold" { sendLine(client, ">HOLD:Waiting for hold release") }
        while let command = readLine(client) {
            switch command {
            case "state on":
                if behavior == "multi-key-auth" {
                    sendLine(client, ">PASSWORD:Need 'Private Key' password")
                } else if behavior == "multi-auth-key" {
                    sendLine(client, ">PASSWORD:Need 'Auth' username/password")
                } else if behavior == "credential" {
                    sendLine(client, ">PASSWORD:Need 'Auth' username/password SC:OTP")
                } else if behavior == "reject" {
                    sendLine(client, "ERROR: rejected")
                } else {
                    sendLine(client, "SUCCESS: state notifications enabled")
                }
            case "state":
                if behavior == "pre-reconnect" {
                    sendLine(client, ">STATE:1,RECONNECTING,redacted,,,,")
                }
                sendLine(client, "1,WAIT,redacted,,,,")
                sendLine(client, "END")
            case "hold release":
                markRelease(path)
                switch behavior {
                case "multi-auth-key-after-hold":
                    sendLine(client, "SUCCESS: hold released")
                    sendLine(client, ">PASSWORD:Need 'Auth' username/password")
                case "credential-after":
                    sendLine(client, ">PASSWORD:Need 'Auth' username/password")
                case "hold-after": sendLine(client, ">HOLD:Waiting again")
                case "reconnect": sendLine(client, ">STATE:2,RECONNECTING,redacted,,,,")
                case "exiting": sendLine(client, ">STATE:2,EXITING,redacted,,,,")
                case "timeout-after": sendLine(client, "SUCCESS: hold released")
                default:
                    sendLine(client, "SUCCESS: hold released")
                    sendLine(client, ">STATE:2,CONNECTED,redacted,10.8.0.2,203.0.113.9,443,192.0.2.10,54321")
                    if behavior == "observe" {
                        sendLine(client, ">STATE:3,RECONNECTING,redacted,,,,")
                    } else if behavior == "observe-wait" {
                        sendLine(client, ">STATE:3,WAIT,redacted,,,,")
                    }
                }
            case "signal SIGTERM":
                sendLine(client, "SUCCESS: signal")
                close(client); close(listener); exit(0)
            default:
                if command.hasPrefix("username \"Auth\"") {
                    sendLine(client, "SUCCESS: username accepted")
                } else if command.hasPrefix("password \"Auth\"") {
                    sendLine(client, "SUCCESS: password accepted")
                    if behavior == "multi-auth-key" || behavior == "multi-auth-key-after-hold" {
                        sendLine(client, ">PASSWORD:Need 'Private Key' password")
                    }
                } else if command.hasPrefix("password \"Private Key\"") {
                    sendLine(client, "SUCCESS: private key accepted")
                    if behavior == "multi-key-auth" {
                        sendLine(client, ">PASSWORD:Need 'Auth' username/password")
                    } else if behavior == "multi-auth-key-after-hold" {
                        sendLine(client, ">STATE:2,CONNECTED,redacted,10.8.0.2,203.0.113.9,443,192.0.2.10,54321")
                    }
                } else { exit(48) }
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
                            counter: Counter,
                            activateAndInstallRoutes: @escaping
                                (VPNTunnelBootstrapProof) throws -> Void = { _ in },
                            prepareRoutesForProcessStop: @escaping () throws -> Void = {},
                            credentials: VPNTunnelCredentialCallbacks? = nil) throws
        -> VPNTunnelCoordinator {
        let dir = directory(folder); defer { close(dir) }
        let value = profile(folder, behavior: behavior)
        let selection = VPNEngineExecutableSelection.test {
            counter.value += 1
            return open(CommandLine.arguments[0], O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
        }
        var captures = 0
        let releaseTrace = URL(fileURLWithPath: folder).appendingPathComponent("hold-release.trace").path
        return try VPNTunnelCoordinator(testDirectory: dir, selection: selection,
            profileDigest: value.0, openProfile: { _ in try value.1() }, captureInterfaces: {
                captures += 1
                if captures == 1 {
                    guard !FileManager.default.fileExists(atPath: releaseTrace) else {
                        throw CoordinatorCheckError.failed("baseline after release")
                    }
                    return try VPNKernelInterfaceSnapshot(interfaces: [])
                }
                guard FileManager.default.fileExists(atPath: releaseTrace) else {
                    throw CoordinatorCheckError.failed("after before release")
                }
                if behavior == "missing-interface" {
                    return try VPNKernelInterfaceSnapshot(interfaces: [])
                }
                guard captures == 2 else {
                    throw CoordinatorCheckError.failed("unexpected interface recapture")
                }
                let local = try OpenVPNIPAddress(parsing: "10.8.0.2", family: .ipv4)
                let first = try VPNKernelInterfaceRecord(index: 31, name: "utun30", isUp: true,
                    isRunning: true, isPointToPoint: true, addresses: [local])
                if behavior == "ambiguous-interface" {
                    let second = try VPNKernelInterfaceRecord(index: 32, name: "utun31", isUp: true,
                        isRunning: true, isPointToPoint: true, addresses: [local])
                    return try VPNKernelInterfaceSnapshot(interfaces: [first, second])
                }
                return try VPNKernelInterfaceSnapshot(interfaces: [first])
            }, blocker: blocker, activateAndInstallRoutes: activateAndInstallRoutes,
            prepareRoutesForProcessStop: prepareRoutesForProcessStop,
            credentials: credentials)
    }

    static func credentialFixture(_ folder: String) throws
        -> (VPNTunnelStateStore, VPNTunnelCredentialCallbacks) {
        let fd = directory(folder); defer { close(fd) }
        let state = try VPNTunnelStateStore(trustedDirectoryDescriptor: fd)
        let resource = try VPNResource(address: "10.44.0.0/16")
        let authentication = try VPNAuthentication(mode: .password, login: "employee")
        let spec = try VPNApplicationSpec(revision: 1,
            profileSHA256: String(repeating: "a", count: 64), resources: [resource],
            corporateDNS: [], authentication: authentication)
        let application = VPNValidatedApplication(spec: spec,
            requiresVPNCredentials: true, requiresPrivateKeyPassword: true)
        _ = try state.stage(application)
        _ = try state.beginConnect()
        let callbacks = VPNTunnelCredentialCallbacks(issue: { generation, prompt in
            let snapshot = try state.load()
            guard let binding = snapshot.attempt, binding.generation == generation else {
                throw CoordinatorCheckError.failed("attempt binding")
            }
            let kind: VPNCredentialKind
            switch prompt {
            case .privateKeyPassphrase: kind = .privateKeyPassword
            case .usernameAndPassword: kind = .vpnPassword
            case .staticChallenge: throw VPNTunnelCoordinatorError.unsupportedCredentialPrompt
            }
            return (try state.issueChallenge(binding: binding, kind: kind), application)
        }, claim: { try state.claimCredential($0) }, complete: { binding in
            let snapshot = try state.completeCredentialPrompt(binding: binding)
            return snapshot.issuedCredentialKinds.contains(.privateKeyPassword)
                && snapshot.issuedCredentialKinds.contains(.vpnPassword)
        }, outstanding: { generation in
            let snapshot = try state.load()
            guard snapshot.generation == generation,
                  let binding = snapshot.attempt else {
                throw CoordinatorCheckError.failed("outstanding binding")
            }
            return (binding.application.requiresPrivateKeyPassword
                    && !snapshot.issuedCredentialKinds.contains(.privateKeyPassword))
                || (binding.application.requiresVPNCredentials
                    && !snapshot.issuedCredentialKinds.contains(.vpnPassword))
        }, fail: { _ = try? state.failCurrent() })
        return (state, callbacks)
    }

    static func response(_ challenge: VPNCredentialChallenge,
                         _ value: String) throws -> VPNCredentialResponse {
        try VPNCredentialResponse(challenge: challenge, secret: Data(value.utf8))
    }

    static func assertOneRelease(_ folder: String) {
        let path = URL(fileURLWithPath: folder).appendingPathComponent("hold-release.trace").path
        guard let bytes = try? Data(contentsOf: URL(fileURLWithPath: path)), bytes.count == 1 else {
            fail("hold release count")
        }
    }

    static func assertNoRelease(_ folder: String) {
        let path = URL(fileURLWithPath: folder).appendingPathComponent("hold-release.trace").path
        guard !FileManager.default.fileExists(atPath: path) else { fail("unexpected hold release") }
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
        guard CommandLine.arguments.count >= 3 else { fail("usage") }
        let test = CommandLine.arguments[1], folder = CommandLine.arguments[2]
        let counter = Counter()
        switch test {
        case "redacted-diagnostics":
            let secret = "NEVER-LOG-OTP-PASSWORD-PROFILE"
            guard VPNStartupDiagnostics.category(CoordinatorCheckError.failed(secret)) == "unclassified",
                  VPNStartupDiagnostics.category(VPNEngineProcessError.spawnFailed(13)) == "engine-spawn-13",
                  VPNStartupDiagnostics.category(OpenVPNManagementParseError.malformed) == "management-protocol",
                  VPNStartupDiagnostics.category(OpenVPNManagementClientError.timeout) == "management-timeout",
                  VPNStartupDiagnostics.category(OpenVPNHeldCredentialExchangeError.engineRejectedCredential) == "credential-rejected",
                  VPNStartupDiagnostics.category(VPNTunnelStateStoreError.stale) == "attempt-stale" else {
                fail("diagnostic allowlist")
            }
            print("diagnostics redacted")
        case "lifecycle":
            let tunnel = try coordinator(folder: folder, behavior: "normal", counter: counter)
            guard case .bootstrapReady(let proof) = try tunnel.start(),
                  proof.generation == 1, proof.tunnel.name == "utun30",
                  tunnel.readiness() == .bootstrapReady(proof),
                  try tunnel.start() == .blocked(.alreadyRunning), counter.value == 1 else {
                fail("lifecycle readiness")
            }
            assertOneRelease(folder)
            guard try tunnel.stop() == .stopped(generation: 1) else { fail("stop") }
            assertClean(folder); print("passed")
        case "route-lifecycle":
            let installed = Counter(), prepared = Counter()
            let tunnel = try coordinator(folder: folder, behavior: "normal", counter: counter,
                activateAndInstallRoutes: { proof in
                    guard proof.generation == 1, prepared.value == 0 else {
                        throw CoordinatorCheckError.failed("route install order")
                    }
                    installed.value += 1
                }, prepareRoutesForProcessStop: {
                    guard installed.value == 1 else {
                        throw CoordinatorCheckError.failed("cleanup before install")
                    }
                    prepared.value += 1
                })
            guard case .bootstrapReady = try tunnel.start(), installed.value == 1,
                  prepared.value == 0,
                  try tunnel.stop() == .stopped(generation: 1), prepared.value == 1 else {
                fail("route lifecycle")
            }
            assertClean(folder); print("routes ordered")
        case "route-cleanup-blocked":
            let attempts = Counter()
            let tunnel = try coordinator(folder: folder, behavior: "normal", counter: counter,
                prepareRoutesForProcessStop: {
                    attempts.value += 1
                    if attempts.value == 1 {
                        throw CoordinatorCheckError.failed("cleanup blocked")
                    }
                })
            guard case .bootstrapReady(let proof) = try tunnel.start() else { fail("bootstrap") }
            do { _ = try tunnel.stop(); fail("cleanup bypassed") }
            catch CoordinatorCheckError.failed("cleanup blocked") {}
            catch { fail("wrong cleanup error") }
            guard tunnel.readiness() == .bootstrapReady(proof), attempts.value == 1,
                  try tunnel.stop() == .stopped(generation: 1), attempts.value == 2 else {
                fail("cleanup fail closed")
            }
            assertClean(folder); print("cleanup blocked safely")
        case "route-install-failure":
            let prepared = Counter()
            let tunnel = try coordinator(folder: folder, behavior: "normal", counter: counter,
                activateAndInstallRoutes: { _ in
                    throw CoordinatorCheckError.failed("install failed")
                }, prepareRoutesForProcessStop: { prepared.value += 1 })
            do { _ = try tunnel.start(); fail("route failure accepted") }
            catch CoordinatorCheckError.failed("install failed") {}
            catch { fail("wrong install error") }
            guard tunnel.readiness() == .failed(generation: 1), prepared.value == 1 else {
                fail("route failure cleanup")
            }
            assertClean(folder); print("install rolled back")
        case "observe-state":
            let behavior = CommandLine.arguments.count > 3 ? CommandLine.arguments[3] : ""
            let tunnel = try coordinator(folder: folder, behavior: behavior, counter: counter)
            guard case .bootstrapReady = try tunnel.start(),
                  try tunnel.observe() == .failed(generation: 1) else { fail("reconnect accepted") }
            assertOneRelease(folder); assertClean(folder); print("failed closed")
        case "credential":
            let tunnel = try coordinator(folder: folder, behavior: "credential", counter: counter)
            guard try tunnel.start() == .blocked(.credentialRequired(.staticChallenge)) else {
                fail("credential blocker")
            }
            assertClean(folder); print("blocked")
        case "multi-credential":
            let behavior = CommandLine.arguments.count > 3
                ? CommandLine.arguments[3] : "multi-key-auth"
            let fixture = try credentialFixture(folder)
            let prepared = Counter()
            let tunnel = try coordinator(folder: folder, behavior: behavior, counter: counter,
                prepareRoutesForProcessStop: { prepared.value += 1 },
                credentials: fixture.1)
            let firstKind: OpenVPNCredentialKind = behavior == "multi-key-auth"
                ? .privateKeyPassphrase : .usernameAndPassword
            guard try tunnel.start() == .blocked(.credentialRequired(firstKind)),
                  tunnel.ownsProcess(), let first = try fixture.0.load().challenge else {
                fail("first prompt was not parked")
            }
            var firstResponse = try response(first, "first-secret")
            let secondKind: OpenVPNCredentialKind = behavior == "multi-key-auth"
                ? .usernameAndPassword : .privateKeyPassphrase
            guard try tunnel.submitCredential(&firstResponse)
                    == .blocked(.credentialRequired(secondKind)),
                  firstResponse.secret.isEmpty,
                  let second = try fixture.0.load().challenge,
                  second.identifier != first.identifier,
                  second.generation == first.generation else {
                fail("second prompt was not exact and fresh")
            }
            var secondResponse = try response(second, "second-secret")
            guard case .bootstrapReady = try tunnel.submitCredential(&secondResponse),
                  secondResponse.secret.isEmpty, prepared.value == 0 else {
                fail("credential bootstrap")
            }
            assertOneRelease(folder)
            _ = try tunnel.stop()
            guard prepared.value == 1 else { fail("route cleanup ordering") }
            let persisted = try Data(contentsOf: URL(fileURLWithPath: folder)
                .appendingPathComponent(VPNTunnelStateStore.name))
            guard !String(decoding: persisted, as: UTF8.self).contains("secret") else {
                fail("secret persisted")
            }
            assertClean(folder); print("multi prompt passed")
        case "static-credential":
            let fixture = try credentialFixture(folder)
            let prepared = Counter()
            let tunnel = try coordinator(folder: folder, behavior: "credential", counter: counter,
                prepareRoutesForProcessStop: { prepared.value += 1 },
                credentials: fixture.1)
            do { _ = try tunnel.start(); fail("static challenge accepted") }
            catch VPNTunnelCoordinatorError.unsupportedCredentialPrompt { }
            catch { fail("wrong static challenge error") }
            guard !tunnel.ownsProcess(), prepared.value == 1,
                  try fixture.0.load().phase == .failed else {
                fail("static challenge did not fail closed")
            }
            assertNoRelease(folder); assertClean(folder); print("static rejected")
        case "stale-credential":
            let fixture = try credentialFixture(folder)
            let prepared = Counter()
            let tunnel = try coordinator(folder: folder, behavior: "multi-key-auth",
                counter: counter, prepareRoutesForProcessStop: { prepared.value += 1 },
                credentials: fixture.1)
            guard try tunnel.start() == .blocked(.credentialRequired(.privateKeyPassphrase)),
                  let issued = try fixture.0.load().challenge else { fail("missing challenge") }
            let stale = VPNCredentialChallenge(generation: issued.generation,
                kind: issued.kind)
            var response = try response(stale, "stale-secret")
            do { _ = try tunnel.submitCredential(&response); fail("stale credential accepted") }
            catch VPNTunnelCoordinatorError.invalidState { }
            catch { fail("wrong stale error") }
            guard response.secret.isEmpty, !tunnel.ownsProcess(), prepared.value == 1,
                  try fixture.0.load().phase == .failed else {
                fail("stale credential did not fail closed")
            }
            assertNoRelease(folder); assertClean(folder); print("stale rejected")
        case "post-release-failure":
            let behavior = CommandLine.arguments.count > 3 ? CommandLine.arguments[3] : ""
            let tunnel = try coordinator(folder: folder, behavior: behavior, counter: counter)
            do {
                let result = try tunnel.start(timeoutMilliseconds: 150)
                if behavior == "credential-after" {
                    guard result == .blocked(.credentialRequired(.usernameAndPassword)) else {
                        fail("post release credential accepted")
                    }
                } else { fail("unsafe bootstrap accepted") }
            } catch {
                guard tunnel.readiness() == .failed(generation: 1) else { fail("failed state") }
            }
            assertOneRelease(folder); assertClean(folder); print("failed closed")
        case "interface-failure":
            let behavior = CommandLine.arguments.count > 3 ? CommandLine.arguments[3] : ""
            let tunnel = try coordinator(folder: folder, behavior: behavior, counter: counter)
            do { _ = try tunnel.start(timeoutMilliseconds: 150); fail("interface ambiguity accepted") }
            catch { guard tunnel.readiness() == .failed(generation: 1) else { fail("failed state") } }
            assertOneRelease(folder); assertClean(folder); print("failed closed")
        case "precondition-failure":
            let behavior = CommandLine.arguments.count > 3 ? CommandLine.arguments[3] : ""
            let tunnel = try coordinator(folder: folder, behavior: behavior, counter: counter)
            do { _ = try tunnel.start(); fail("unsafe held state accepted") }
            catch { guard tunnel.readiness() == .failed(generation: 1) else { fail("failed state") } }
            assertNoRelease(folder); assertClean(folder); print("failed closed")
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
