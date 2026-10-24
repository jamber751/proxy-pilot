// Synthetic installed child only. No system service or network is touched.
import CryptoKit
import Darwin
import Dispatch
import Foundation

@main enum VPNInstalledUpdateResultChecks {
    static func main() throws {
        let a = CommandLine.arguments
        if a.count == 2, a[1] == "guards" {
            precondition(VPNInstalledUpdateResultEntry.runIfRequested(arguments: ["app", VPNInstalledUpdateResultEntry.argument]) == 77)
            precondition(VPNInstalledUpdateResultEntry.runIfRequested(arguments: ["app", VPNInstalledUpdateResultEntry.argument, "extra"]) == 64)
            do { try VPNLaunchdRuntime.requireSystemStopped(deadline: DispatchTime.now().uptimeNanoseconds + 1_000_000_000); exit(66) }
            catch VPNLaunchdError.requiresRoot {}
            print("guarded"); return
        }
        guard a.count == 8 || a.count == 11 else { exit(64) }
        let key = try Curve25519.Signing.PrivateKey(rawRepresentation: Data(repeating: 0x42, count: 32))
        let helper = a.count == 11 ? try Data(contentsOf: URL(fileURLWithPath: a[8])) : Data("inert helper".utf8)
        let sha = SHA256.hash(data: helper).map { String(format: "%02x", $0) }.joined()
        let payload = Data("""
        format=1
        product=kz.documentolog.proxypilot
        sequence=141
        version=1.7.0
        protocol=1
        app-arm64=\(a[3])
        app-x86_64=\(a[4])
        helper-arm64=\(a.count == 11 ? a[9] : String(repeating: "33", count: 20))
        helper-x86_64=\(a.count == 11 ? a[10] : String(repeating: "44", count: 20))
        helper-sha256=\(sha)
        helper-bytes=\(helper.count)

        """.utf8)
        let authority = try VPNReleaseAuthority(trustedPublicKey: key.publicKey.rawRepresentation,
            minimumSequence: 1, supportedProtocol: 1)
        let release = try authority.verify(payload: payload,
            signature: key.signature(for: VPNReleaseAuthority.signatureDomain + payload), previous: nil)
        let apps = open(a[2], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard apps >= 0 else { exit(65) }
        defer { close(apps) }
        if a[1].hasPrefix("observation-") {
            let url = URL(fileURLWithPath: a[2]).deletingLastPathComponent().appendingPathComponent("observation-store")
            try FileManager.default.createDirectory(at: url, withIntermediateDirectories: false,
                                                    attributes: [.posixPermissions: 0o700])
            let service = open(url.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard service >= 0 else { exit(65) }; defer { close(service) }
            let store = try VPNReleaseStore(trustedDirectoryDescriptor: service, authority: authority)
            _ = try store.bootstrapDeployment(payload: payload,
                signature: key.signature(for: VPNReleaseAuthority.signatureDomain + payload),
                helper: helper, trustedOwnerUserID: geteuid())
            try VPNActivationBudget(trustedDirectoryDescriptor: service).recordManualOff()
            let lock = openat(service, "release.lock", O_RDWR | O_NOFOLLOW | O_CLOEXEC)
            guard lock >= 0 else { exit(65) }
            let released = DispatchSemaphore(value: 0)
            let releaseGate = DispatchSemaphore(value: 0)
            var scheduled = false
            func holdThenRelease(milliseconds: Int) throws {
                guard !scheduled, flock(lock, LOCK_EX | LOCK_NB) == 0 else { throw VPNInstalledUpdateResultError.invalidState }
                scheduled = true
                DispatchQueue.global().async {
                    // Release only after the observer has actually encountered
                    // this held lock, not merely after a scheduler-dependent delay.
                    if releaseGate.wait(timeout: .now() + 2) == .success {
                        usleep(useconds_t(milliseconds * 1000))
                    }
                    flock(lock, LOCK_UN); released.signal()
                }
            }
            defer {
                if scheduled { _ = released.wait(timeout: .now() + 2) }
                close(lock)
            }
            if a[1] == "observation-busy-release" { try holdThenRelease(milliseconds: 75) }
            if a[1] == "observation-busy-deadline" { try holdThenRelease(milliseconds: 200) }
            let selectedURL = url.appendingPathComponent("release.json")
            let before = try Data(contentsOf: selectedURL)
            var attempts = 0, busy = 0, captures = 0, identities = 0, runtime = 0
            let started = DispatchTime.now().uptimeNanoseconds
            do {
                let result = try VPNInstalledUpdateObservation.run(
                    deadline: started + UInt64(a[7])! * 1_000_000, onBusy: {
                        busy += 1
                        if busy == 1 { releaseGate.signal() }
                    }) { () throws -> Int32 in
                    attempts += 1
                    let snapshot = try VPNInstalledUpdateResultSnapshot.capture(service: service, store: store)
                    captures += 1
                    if a[1] == "observation-changed" { throw VPNInstalledUpdateResultError.changed }
                    if a[1] == "observation-unsafe" { throw VPNReleaseStoreError.unsafeStorage }
                    let installed = try VPNInstalledApplication.testInspect(inApplicationsDirectory: apps, release: snapshot.selected.release)
                    try installed.revalidate()
                    identities += 1
                    if a[1] == "observation-wrong-identity" {
                        // The fixture driver really is a different executable
                        // inode from the signed installed synthetic child.
                        try installed.validateProcess(getpid())
                        throw VPNInstalledUpdateResultError.invalidState
                    }
                    if a[1] == "observation-late-busy-identity", identities == 2 {
                        throw VPNPeerAuthenticationError.denied
                    }
                    // No system runtime is called. Count this synthetic positive
                    // to prove it is discarded on a late Store busy result.
                    runtime += 1
                    if a[1].hasPrefix("observation-late-busy"), runtime == 1 {
                        try holdThenRelease(milliseconds: 75)
                    }
                    try snapshot.validate(service: service, store: store)
                    return VPNInstalledUpdateResultEntry.remainedOffStatus
                }
                guard result == VPNInstalledUpdateResultEntry.remainedOffStatus else { exit(66) }
                if a[1] == "observation-busy-release" {
                    guard attempts >= 2, busy >= 1, captures == 1, identities == 1, runtime == 1 else { exit(66) }
                } else if a[1] == "observation-late-busy" {
                    guard attempts >= 2, busy >= 1, captures == 2, identities == 2, runtime == 2 else { exit(66) }
                } else { exit(66) }
            } catch VPNInstalledUpdateResultError.deadlineExceeded {
                guard a[1] == "observation-busy-deadline", busy >= 1, captures == 0,
                      DispatchTime.now().uptimeNanoseconds - started < 500_000_000 else { exit(66) }
            } catch VPNInstalledUpdateResultError.changed {
                guard a[1] == "observation-changed", attempts == 1, busy == 0, runtime == 0 else { exit(66) }
            } catch VPNReleaseStoreError.unsafeStorage {
                guard a[1] == "observation-unsafe", attempts == 1, busy == 0, runtime == 0 else { exit(66) }
            } catch VPNInstalledApplicationError.wrongProcess {
                guard a[1] == "observation-wrong-identity", attempts == 1, busy == 0, runtime == 0 else { exit(66) }
            } catch VPNPeerAuthenticationError.denied {
                guard a[1] == "observation-late-busy-identity", captures == 2, identities == 2,
                      busy >= 1, runtime == 1 else { exit(66) }
            } catch { print("rejected:\(error)"); exit(77) }
            if scheduled { _ = released.wait(timeout: .now() + 2); scheduled = false }
            guard try Data(contentsOf: selectedURL) == before,
                  try store.loadUpdateJournal() == nil,
                  try store.loadUpdateCleanupReceipt() == nil else { exit(66) }
            print("observation-complete")
            return
        }
        do {
            let installed = try VPNInstalledApplication.testInspect(inApplicationsDirectory: apps, release: release)
            var checks = 0
            let outcome = try VPNRescueInstalledResultVerifier.testObserve(installed: installed, release: release,
                desired: a[5] == "on", failures: Int(a[6])!,
                deadline: DispatchTime.now().uptimeNanoseconds + UInt64(a[7])! * 1_000_000,
                validate: {
                    checks += 1
                    if checks == 2, a[1] == "deny-before-resume" { throw VPNInstalledUpdateResultError.changed }
                    if checks == 2, a[1] == "mutate-before-resume" {
                        try Data("tampered".utf8).write(to: URL(fileURLWithPath: a[2] + "/ProxyPilot.app/Contents/Resources/data.txt"))
                    }
                })
            print("\(outcome)")
        } catch { print("rejected:\(error)"); exit(77) }
    }
}
