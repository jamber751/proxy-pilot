import CryptoKit
import Darwin
import Foundation

// Unprivileged test adapter only. No launchd labels, system paths, profiles or
// VPN operations. Python bounds the whole process and owns disposable storage.
enum FixtureFailure: Error { case injected }
final class FixtureRuntime: VPNActivationRuntime {
    let directory: URL
    let mode: String
    var process: Process?
    var stopCount = 0
    var onStop: (() throws -> Void)?
    var onStart: (() throws -> Void)?
    init(directory: URL, mode: String) { self.directory = directory; self.mode = mode }
    deinit { cleanup() }
    func cleanup() {
        if let process = process, process.isRunning { process.terminate(); process.waitUntilExit() }
        process = nil
    }
    func stopAndDrain(deadline: UInt64) throws {
        stopCount += 1
        print("stop:\(stopCount)"); fflush(stdout)
        if mode == "crash-before-commit" { _exit(86) }
        if mode == "stop-fails" { throw FixtureFailure.injected }
        cleanup()
        if stopCount == 1 { try onStop?() }
        if mode == "cleanup-fails", stopCount == 2 { throw FixtureFailure.injected }
    }
    func startIdleAndConnect(_ deployment: VPNAuthorizedDeployment, deadline: UInt64) throws -> Int32 {
        print("start:\(deployment.release.sequence)"); fflush(stdout)
        if mode == "crash-after-commit" { _exit(86) }
        let endpoint = directory.appendingPathComponent("s").path
        // Only this harness-owned short private socket path is ever removed.
        unlink(endpoint)
        let child = Process()
        let output = Pipe(), errors = Pipe()
        child.executableURL = directory.appendingPathComponent(deployment.helperFileName)
        let response = ["readiness-fails", "cleanup-fails"].contains(mode) ? "sequence" : "valid"
        child.arguments = ["serve", endpoint, response]
        child.standardOutput = output; child.standardError = errors
        try child.run()
        process = child
        guard output.fileHandleForReading.readData(ofLength: 10) == Data("listening\n".utf8) else {
            throw FixtureFailure.injected
        }
        if mode == "start-fails" { throw FixtureFailure.injected }
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        let bytes = Array(endpoint.utf8) + [0]
        guard bytes.count <= MemoryLayout.size(ofValue: address.sun_path) else { throw FixtureFailure.injected }
        withUnsafeMutableBytes(of: &address.sun_path) { $0.copyBytes(from: bytes) }
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        let result = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
        }
        guard result == 0 else { close(fd); throw FixtureFailure.injected }
        do { try onStart?() } catch { close(fd); throw error }
        return fd
    }
}

@main
enum VPNActivationChecks {
    static func main() {
        guard geteuid() != 0 else { exit(77) }
        let args = CommandLine.arguments
        guard args.count == 7, let expected = UInt64(args[5]) else { exit(64) }
        var status: Int32 = 0
        do {
            let key = try Curve25519.Signing.PrivateKey(rawRepresentation: Data(repeating: 0x42, count: 32))
            let authority = try VPNReleaseAuthority(trustedPublicKey: key.publicKey.rawRepresentation, minimumSequence: 1, supportedProtocol: 1)
            let fd = open(args[2], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard fd >= 0 else { exit(77) }
            let store: VPNReleaseStore
            do { store = try VPNReleaseStore(trustedDirectoryDescriptor: fd, authority: authority) }
            catch { close(fd); throw error }
            close(fd)
            if args[1] == "load" { print("selected:\(try store.loadDeployment().release.sequence)"); return }
            let budgetDirectory = open(args[2], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard budgetDirectory >= 0 else { exit(77) }
            let budget = try VPNActivationBudget(trustedDirectoryDescriptor: budgetDirectory)
            close(budgetDirectory)
            if args[1] == "budget" {
                let state = try budget.snapshot()
                print("budget:\(state.desired ? "on" : "off") failures:\(state.failures)")
                return
            }
            let payload = try Data(contentsOf: URL(fileURLWithPath: args[3]))
            let helper = try Data(contentsOf: URL(fileURLWithPath: args[4]))
            var signature = try key.signature(for: VPNReleaseAuthority.signatureDomain + payload)
            if args[6] == "bad-signature" { signature[0] ^= 1 }
            if args[1] == "seed" {
                _ = try store.bootstrapDeployment(payload: payload, signature: signature, helper: helper, trustedOwnerUserID: geteuid())
                print("selected:\(try store.loadDeployment().release.sequence)"); return
            }
            let owned = open(args[2], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard owned >= 0 else { exit(77) }
            let lease: VPNLifecycleLease
            do { lease = try VPNLifecycleOwnership.acquire(inTrustedDirectory: owned) }
            catch { close(owned); print("ownership:\(error)"); exit(78) }
            close(owned)
            let runtime = FixtureRuntime(directory: URL(fileURLWithPath: args[2]), mode: args[6])
            let coordinator = VPNActivationCoordinator(store: store, runtime: runtime, lease: lease, budget: budget)
            // Replaces the lock the way a second supervisor's provisioning would:
            // our descriptor stays open, but the directory names another file.
            let breakLease = {
                let directory = URL(fileURLWithPath: args[2])
                let lock = directory.appendingPathComponent("lifecycle.lock")
                try FileManager.default.moveItem(at: lock, to: directory.appendingPathComponent("moved.lock"))
                guard FileManager.default.createFile(atPath: lock.path, contents: nil,
                                                     attributes: [.posixPermissions: 0o600]) else {
                    throw FixtureFailure.injected
                }
            }
            if args[6] == "lose-before-stop" { try breakLease() }
            if args[6] == "lose-after-stop" { runtime.onStop = breakLease }
            if args[6] == "lose-after-start" { runtime.onStart = breakLease }
            if args[6] == "reentrant" {
                runtime.onStop = {
                    do { _ = try coordinator.recoverSelected(intent: .explicit); throw FixtureFailure.injected }
                    catch VPNActivationCoordinatorError.busy { print("busy") }
                }
            }
            if ["stale-after-stop", "selection-race"].contains(args[6]) {
                let advance = {
                    let current = try store.loadDeployment()
                    let text = String(data: payload, encoding: .utf8)!
                    let sequenceLine = text.components(separatedBy: "\n").first { $0.hasPrefix("sequence=") }!
                    let next = Data(text.replacingOccurrences(of: sequenceLine, with: "sequence=12").utf8)
                    _ = try store.commitDeployment(payload: next, signature: key.signature(for: VPNReleaseAuthority.signatureDomain + next),
                                                   helper: helper, expectedSequence: current.release.sequence)
                }
                if args[6] == "stale-after-stop" { runtime.onStop = advance } else { runtime.onStart = advance }
            }
            if args[6] == "tamper-after-stop" {
                runtime.onStop = {
                    let candidate = try authority.verify(payload: payload, signature: signature, previous: nil)
                    let url = runtime.directory.appendingPathComponent(candidate.helperArtifactName)
                    try Data("tampered fixture".utf8).write(to: url)
                }
            }
            #if VPN_RELEASE_STORE_TESTING
            if args[6] == "crash-selector" {
                VPNReleaseStore.checkpoint = { if $0 == "release.json:after-rename" { _exit(86) } }
            }
            #endif
            defer { runtime.cleanup(); runtime.onStop = nil; runtime.onStart = nil }
            let intent: VPNActivationIntent = args[1].hasSuffix("-auto") ? .automatic : .explicit
            do {
                if args[1] == "turn-off" {
                    try coordinator.turnOff()
                    print("turned-off")
                    exit(0)
                }
                let ready: VPNHelperReady
                if args[1].hasPrefix("recover") { ready = try coordinator.recoverSelected(intent: intent) }
                else { ready = try coordinator.update(payload: payload, signature: signature, helper: helper,
                                                      expectedSequence: expected, intent: intent) }
                print("ready:\(ready.release.sequence)")
            } catch let denied as VPNActivationBudgetError {
                print("budget:\(denied)")
                status = 79
            } catch let failure as VPNActivationFailure {
                print("failure:\(failure.phase) cleanup:\(failure.cleanupConfirmed)")
                status = 77
            } catch VPNActivationCoordinatorError.ownershipLost {
                print("ownership:lost")
                status = 78
            }
        } catch { print("rejected:\(error)"); status = 77 }
        exit(status)
    }
}
