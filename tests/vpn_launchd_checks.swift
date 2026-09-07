import CryptoKit
import Darwin
import Dispatch
import Foundation

// Drives the real launchd adapter through the real coordinator, in the current
// user's own launchd domain with a disposable label. No root, no system domain,
// no /Library/LaunchDaemons, no VPN profile and no network configuration.
@main
enum VPNLaunchdChecks {
    static func deadline(_ seconds: UInt64) -> UInt64 { DispatchTime.now().uptimeNanoseconds + seconds * 1_000_000_000 }

    static func main() {
        guard geteuid() != 0 else { exit(77) }
        let args = CommandLine.arguments
        guard args.count == 8, let expected = UInt64(args[5]) else { exit(64) }
        let storagePath = args[2], label = args[6], plists = URL(fileURLWithPath: args[7], isDirectory: true)
        var status: Int32 = 0
        do {
            let fd = open(storagePath, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard fd >= 0 else { exit(77) }
            defer { close(fd) }
            if args[1] == "system" {
                // The production entry must refuse before touching anything.
                do { _ = try VPNLaunchdRuntime.system(storageDirectory: fd); print("system:accepted") }
                catch { print("system:\(error)") }
                exit(0)
            }
            let key = try Curve25519.Signing.PrivateKey(rawRepresentation: Data(repeating: 0x42, count: 32))
            let authority = try VPNReleaseAuthority(trustedPublicKey: key.publicKey.rawRepresentation,
                                                    minimumSequence: 1, supportedProtocol: 1)
            let store = try VPNReleaseStore(trustedDirectoryDescriptor: fd, authority: authority)
            if args[1] == "load" { print("selected:\(try store.loadDeployment().release.sequence)"); return }
            let runtime = try VPNLaunchdRuntime.testUserDomain(label: label, plistDirectory: plists, storageDirectory: fd)
            if args[1] == "stop" {
                do { try runtime.stopAndDrain(deadline: deadline(20)); print("stopped") }
                catch { print("stop:\(error)"); status = 77 }
                exit(status)
            }
            let payload = try Data(contentsOf: URL(fileURLWithPath: args[3]))
            let helper = try Data(contentsOf: URL(fileURLWithPath: args[4]))
            let signature = try key.signature(for: VPNReleaseAuthority.signatureDomain + payload)
            if args[1] == "seed" {
                _ = try store.bootstrapDeployment(payload: payload, signature: signature,
                                                  helper: helper, trustedOwnerUserID: geteuid())
                print("selected:\(try store.loadDeployment().release.sequence)"); return
            }
            let owned = open(storagePath, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard owned >= 0 else { exit(77) }
            let lease: VPNLifecycleLease
            do { lease = try VPNLifecycleOwnership.acquire(inTrustedDirectory: owned) }
            catch { close(owned); print("ownership:\(error)"); exit(78) }
            close(owned)
            let budgetDirectory = open(storagePath, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard budgetDirectory >= 0 else { exit(77) }
            let budget = try VPNActivationBudget(trustedDirectoryDescriptor: budgetDirectory)
            close(budgetDirectory)
            let coordinator = VPNActivationCoordinator(store: store, runtime: runtime, lease: lease, budget: budget)
            do {
                let ready = args[1] == "recover" ? try coordinator.recoverSelected(intent: .explicit)
                    : try coordinator.update(payload: payload, signature: signature,
                                             helper: helper, expectedSequence: expected, intent: .explicit)
                print("ready:\(ready.release.sequence)")
            } catch let failure as VPNActivationFailure {
                print("failure:\(failure.phase) cleanup:\(failure.cleanupConfirmed)")
                status = 77
            }
        } catch { print("rejected:\(error)"); status = 77 }
        exit(status)
    }
}
