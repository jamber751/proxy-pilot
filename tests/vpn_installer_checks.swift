import CryptoKit
import Darwin
import Dispatch
import Foundation

// Drives the installation sequence in a disposable base directory and the user's
// own launchd domain. No root, no /Library, no system domain, no VPN operation.
// The fixture key is disposable; production must embed its own trusted key.
@main
enum VPNInstallerChecks {
    private final class BoundaryRuntime: VPNActivationRuntime {
        enum Mode { case real(VPNLaunchdRuntime), stopThenFail(VPNLaunchdRuntime), fail, loseLease(Int32) }
        let mode: Mode
        init(_ mode: Mode) { self.mode = mode }
        func stopAndDrain(deadline: UInt64) throws {
            switch mode {
            case .real(let runtime): try runtime.stopAndDrain(deadline: deadline)
            case .stopThenFail(let runtime):
                try runtime.stopAndDrain(deadline: deadline)
                throw VPNLaunchdError.cleanupNotConfirmed
            case .fail: throw VPNLaunchdError.cleanupNotConfirmed
            case .loseLease(let directory):
                guard unlinkat(directory, VPNLifecycleLease.lockName, 0) == 0 else {
                    throw VPNLaunchdError.unsafeStorage
                }
                let replacement = openat(directory, VPNLifecycleLease.lockName,
                    O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0o600)
                guard replacement >= 0 else { throw VPNLaunchdError.unsafeStorage }
                close(replacement)
            }
        }
        func startIdleAndConnect(_ deployment: VPNAuthorizedDeployment, deadline: UInt64) throws -> Int32 {
            throw VPNLaunchdError.launchFailed
        }
    }

    static func main() {
        guard geteuid() != 0 else { exit(77) }
        let args = CommandLine.arguments
        guard [8, 9, 10].contains(args.count), let expected = UInt64(args[5]) else { exit(64) }
        let base = open(args[2], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard base >= 0 else { exit(77) }
        defer { close(base) }
        var status: Int32 = 0
        do {
            let key = try Curve25519.Signing.PrivateKey(rawRepresentation: Data(repeating: 0x42, count: 32))
            let authority = try VPNReleaseAuthority.engineCandidateAuthority(
                trustedPublicKey: key.publicKey.rawRepresentation, minimumSequence: 1)
            let payload = try Data(contentsOf: URL(fileURLWithPath: args[3]))
            let helper = try Data(contentsOf: URL(fileURLWithPath: args[4]))
            let preparing = args[1].hasPrefix("prepare")
            let engineIndex = preparing ? (args.count == 10 ? 9 : nil) : (args.count == 9 ? 8 : nil)
            let engine = try engineIndex.map { try Data(contentsOf: URL(fileURLWithPath: args[$0])) }
            var signature = try key.signature(for: VPNReleaseAuthority.signatureDomain + payload)
            if args[1].hasSuffix("-bad-signature") { signature[0] ^= 1 }
            let label = args[6], plists = URL(fileURLWithPath: args[7], isDirectory: true)
            if args[1].hasPrefix("journal-") {
                let directory = try VPNDirectoryProvisioner.openBelowTrustedBase(base, create: false)
                defer { close(directory) }
                let store = try VPNReleaseStore(trustedDirectoryDescriptor: directory, authority: authority)
                #if VPN_INSTALLER_TESTING
                if args[1].hasPrefix("journal-test-") {
                    guard let journal = try store.loadUpdateJournal() else {
                        throw VPNReleaseStoreError.invalidUpdateJournal
                    }
                    if args[1] == "journal-test-select" {
                        let result = try store.selectUpdateCandidate(
                            transactionID: journal.transactionID, expectedRevision: journal.revision)
                        print("journal:\(result.phase.rawValue):\(result.revision)")
                    } else if args[1] == "journal-test-complete" {
                        let result = try store.completeUpdateJournal(
                            transactionID: journal.transactionID, expectedRevision: journal.revision)
                        print("journal:\(result.phase.rawValue):\(result.revision)")
                    } else if args[1] == "journal-test-retire-completed" {
                        try store.retireUpdateJournal(
                            transactionID: journal.transactionID, expectedRevision: journal.revision)
                        print("journal:retired")
                    } else {
                        throw VPNReleaseStoreError.invalidUpdateJournal
                    }
                    return
                }
                #endif
                // Even absent/corrupt records must reach the installer wrapper;
                // do not let this fixture become the gate under test.
                let journal = (try? store.loadUpdateJournal()) ?? nil
                let action: VPNInstaller.JointUpdateSourceAction
                if args[1].contains("cancel") { action = .cancel }
                else if args[1].contains("retire") { action = .retireCancelled }
                else { action = .beginReplacement }
                let actualID = journal?.transactionID ?? UUID()
                let actualRevision = journal?.revision ?? 0
                let transactionID = args[1].contains("wrong-uuid") ? UUID() : actualID
                let revision = args[1].contains("wrong-revision") ? actualRevision &+ 1 : actualRevision
                let result = try VPNInstaller.testManagePreparedJointUpdate(action,
                    transactionID: transactionID, expectedRevision: revision,
                    authority: authority, base: base) { trustedDirectory in
                        let marker = URL(fileURLWithPath: args[2]).appendingPathComponent("runtime-built")
                        try Data("built".utf8).write(to: marker)
                        if args[1].contains("fail-stop") { return BoundaryRuntime(.fail) }
                        if args[1].contains("lose-lease") { return BoundaryRuntime(.loseLease(trustedDirectory)) }
                        let runtime = try VPNLaunchdRuntime.testUserDomain(label: label,
                            plistDirectory: plists, storageDirectory: trustedDirectory)
                        if args[1].contains("stop-then-fail") { return BoundaryRuntime(.stopThenFail(runtime)) }
                        return BoundaryRuntime(.real(runtime))
                    }
                if let result = result { print("journal:\(result.phase.rawValue):\(result.revision)") }
                else { print("journal:retired") }
                return
            }
            if preparing {
                let transition = try Data(contentsOf: URL(fileURLWithPath: args[8]))
                var transitionSignature = try key.signature(for: VPNReleaseAuthority.updateTransitionDomain + transition)
                if args[1].hasSuffix("-bad-edge") { transitionSignature[0] ^= 1 }
                let journal = try VPNInstaller.testPrepareJointUpdate(
                    payload: payload, signature: signature, helper: helper, engine: engine,
                    transitionPayload: transition, transitionSignature: transitionSignature,
                    authority: authority, expectedSequence: expected, base: base)
                print("prepared:\(journal.previous.release.sequence)->\(journal.candidate.release.sequence) phase:\(journal.phase.rawValue)")
                return
            }
            if args[1] == "probe" {
                let directory = try VPNDirectoryProvisioner.openBelowTrustedBase(base, create: false)
                defer { close(directory) }
                let store = try VPNReleaseStore(trustedDirectoryDescriptor: directory, authority: authority)
                let selected = try store.loadDeployment()
                let socket = try VPNEndpointDirectory.connect(directory: directory, owner: geteuid(), shared: false,
                    deadline: DispatchTime.now().uptimeNanoseconds + 2_000_000_000)
                let ready = try VPNHelperReadiness.testProbe(takingSocket: socket, release: selected.release)
                print("ready:\(ready.release.sequence)")
                return
            }
            if args[1] == "root-entry" {
                // The production entries must refuse before touching anything.
                do { _ = try VPNInstaller.install(payload: payload, signature: signature, helper: helper,
                                                  authority: authority, trustedOwnerUserID: 0)
                     print("root-entry:accepted") }
                catch { print("root-entry:\(error)") }
                exit(0)
            }
            if args[1] == "enumerate-removable" {
                let directory = try VPNDirectoryProvisioner.openBelowTrustedBase(base, create: false)
                defer { close(directory) }
                let shared = fcntl(directory, F_DUPFD_CLOEXEC, 0)
                guard shared >= 0, let stream = fdopendir(shared) else { exit(77) }
                while readdir(stream) != nil { }
                closedir(stream)
                let first = try VPNInstaller.testRemovableNames(directory: directory)
                let second = try VPNInstaller.testRemovableNames(directory: directory)
                print("enumerated:\(first.count):\(second.count)")
                exit(0)
            }
            if args[1] == "uninstall" {
                try VPNInstaller.testUninstall(base: base, label: label, plistDirectory: plists)
                print("uninstalled")
                exit(0)
            }
            let ready: VPNHelperReady
            if args[1].hasPrefix("install") {
                ready = try VPNInstaller.testInstall(payload: payload, signature: signature, helper: helper, engine: engine,
                                                     authority: authority, base: base, label: label,
                                                     plistDirectory: plists)
            } else {
                ready = try VPNInstaller.testUpdate(payload: payload, signature: signature, helper: helper, engine: engine,
                                                    authority: authority, expectedSequence: expected,
                                                    intent: .explicit, base: base, label: label,
                                                    plistDirectory: plists)
            }
            print("ready:\(ready.release.sequence)")
        } catch { print("rejected:\(error)"); status = 77 }
        exit(status)
    }
}
