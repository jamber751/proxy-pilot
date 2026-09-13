import CryptoKit
import Darwin
import Dispatch
import Foundation

@main enum VPNJointReplacementChecks {
    final class Runtime: VPNActivationRuntime {
        let mode: String, service: Int32, appPath: String
        init(_ mode: String, _ service: Int32, _ appPath: String) { self.mode = mode; self.service = service; self.appPath = appPath }
        func stopAndDrain(deadline: UInt64) throws {
            try Data("drained".utf8).write(to: URL(fileURLWithPath: appPath + "/drain-marker"))
            if mode == "drain-fail" { throw VPNLaunchdError.cleanupNotConfirmed }
            if mode == "lose-lease" { _ = unlinkat(service, VPNLifecycleLease.lockName, 0) }
            if mode == "corrupt-journal" {
                let fd = openat(service, "update.json", O_WRONLY | O_TRUNC | O_NOFOLLOW | O_CLOEXEC)
                if fd >= 0 { _ = write(fd, "bad", 3); close(fd) }
            }
            if mode == "mutate-tree" {
                try Data("changed".utf8).write(to: URL(fileURLWithPath: appPath + "/candidate/ProxyPilot.app/Contents/Resources/data.txt"))
            }
            if mode == "executor-corrupt" {
                try Data("changed".utf8).write(to: URL(fileURLWithPath: appPath + "/executor/ProxyPilot.app/Contents/Resources/data.txt"))
            }
            if mode == "executor-replace" {
                guard rename(appPath + "/executor", appPath + "/executor-displaced") == 0,
                      mkdir(appPath + "/executor", 0o700) == 0 else { throw VPNLaunchdError.unsafeStorage }
            }
        }
        func startIdleAndConnect(_ deployment: VPNAuthorizedDeployment, deadline: UInt64) throws -> Int32 {
            try? Data("started".utf8).write(to: URL(fileURLWithPath: appPath + "/start-marker"))
            throw VPNLaunchdError.launchFailed
        }
    }

    static func main() throws {
        let a = CommandLine.arguments
        guard a.count == 11 else { exit(64) }
        let operation = a[1], support = a[2], apps = a[3]
        let key = try Curve25519.Signing.PrivateKey(rawRepresentation: Data(repeating: 0x42, count: 32))
        let authority = try VPNReleaseAuthority(trustedPublicKey: key.publicKey.rawRepresentation, minimumSequence: 1, supportedProtocol: 1)
        let helper = try Data(contentsOf: URL(fileURLWithPath: a[4]))
        func manifest(_ sequence: UInt64, _ version: String, _ arm: String, _ intel: String) -> Data {
            let sha = SHA256.hash(data: helper).map { String(format: "%02x", $0) }.joined()
            return Data("""
            format=1
            product=kz.documentolog.proxypilot
            sequence=\(sequence)
            version=\(version)
            protocol=1
            app-arm64=\(arm)
            app-x86_64=\(intel)
            helper-arm64=\(a[9])
            helper-x86_64=\(a[10])
            helper-sha256=\(sha)
            helper-bytes=\(helper.count)

            """.utf8)
        }
        let ap = manifest(10, "1.6.0", a[5], a[6]), bp = manifest(11, "1.7.0", a[7], a[8])
        let asig = try key.signature(for: VPNReleaseAuthority.signatureDomain + ap)
        let bsig = try key.signature(for: VPNReleaseAuthority.signatureDomain + bp)
        let av = try authority.verify(payload: ap, signature: asig, previous: nil)
        _ = try authority.verify(payload: bp, signature: bsig, previous: av)
        func hex(_ d: Data) -> String { SHA256.hash(data: d).map { String(format: "%02x", $0) }.joined() }
        let edge = Data("format=1\nproduct=kz.documentolog.proxypilot\nfrom-sequence=10\nfrom-sha256=\(hex(ap))\nto-sequence=11\nto-sha256=\(hex(bp))\n".utf8)
        let edgeSig = try key.signature(for: VPNReleaseAuthority.updateTransitionDomain + edge)
        let base = open(support, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        let appFD = open(apps, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard base >= 0, appFD >= 0 else { exit(65) }
        defer { close(base); close(appFD) }
        do {
            if operation.hasPrefix("setup") {
                let service = try VPNDirectoryProvisioner.openBelowTrustedBase(base, create: true)
                defer { close(service) }
                let store = try VPNReleaseStore(trustedDirectoryDescriptor: service, authority: authority)
                _ = try store.bootstrapDeployment(payload: ap, signature: asig, helper: helper, trustedOwnerUserID: geteuid())
                let journal = try store.prepareUpdateJournal(payload: bp, signature: bsig, helper: helper,
                    transitionPayload: edge, transitionSignature: edgeSig, expectedSequence: 10)
                var result = journal
                if operation != "setup-prepared" { result = try store.markUpdateReplacementPending(transactionID: journal.transactionID, expectedRevision: 0) }
                if operation == "setup-selected" { result = try store.selectUpdateCandidate(transactionID: result.transactionID, expectedRevision: 1) }
                let budget = try VPNActivationBudget(trustedDirectoryDescriptor: service)
                try budget.recordManualOff()
                print("setup:\(result.transactionID.uuidString):\(result.revision)")
                return
            }
            let service = try VPNDirectoryProvisioner.openBelowTrustedBase(base, create: false)
            defer { close(service) }
            let store = try VPNReleaseStore(trustedDirectoryDescriptor: service, authority: authority)
            let journal = try store.loadUpdateJournal()!
            if operation.hasPrefix("raw-after-executor-") {
                let outcome = try VPNProtectedApplicationSwap.testExchange(
                    inTrustedDirectory: appFD, previous: journal.previous.release,
                    candidate: journal.candidate.release, transition: journal.transition,
                    requireProtectedExecutor: true, checkpoint: { point in
                        guard point == "afterExchange" else { return }
                        if operation == "raw-after-executor-corrupt" {
                            try Data("changed".utf8).write(to: URL(fileURLWithPath:
                                apps + "/executor/ProxyPilot.app/Contents/Resources/data.txt"))
                        } else if operation == "raw-after-executor-replace" {
                            guard rename(apps + "/executor", apps + "/executor-displaced") == 0,
                                  mkdir(apps + "/executor", 0o700) == 0 else {
                                throw VPNLaunchdError.unsafeStorage
                            }
                        }
                    })
                print("raw-result:\(outcome == .exchanged ? "exchanged" : "already")")
                return
            }
            var held: VPNLifecycleLease?
            if operation == "service-busy" { held = try VPNLifecycleOwnership.acquire(inTrustedDirectory: service) }
            if operation == "namespace-busy" { held = try VPNLifecycleOwnership.acquire(inTrustedDirectory: appFD) }
            defer { held?.release() }
            let id = operation == "wrong-uuid" ? UUID() : journal.transactionID
            let revision = operation == "wrong-revision" ? journal.revision + 1 : journal.revision
            let outcome: VPNProtectedApplicationSwap.Outcome
            if operation == "production" {
                outcome = try VPNJointApplicationReplacement.exchangePreparedCopies(
                    applicationDirectory: appFD, transactionID: id, expectedRevision: revision, authority: authority)
            } else {
                outcome = try VPNJointApplicationReplacement.testExchangePreparedCopies(
                    applicationDirectory: appFD, transactionID: id, expectedRevision: revision,
                    authority: authority, base: base) { directory in
                        try Data("factory".utf8).write(to: URL(fileURLWithPath: apps + "/factory-marker"))
                        return Runtime(operation, directory, apps)
                    }
            }
            let fresh = try store.loadUpdateJournal()!
            let selected = try store.loadDeployment()
            print("result:\(outcome == .exchanged ? "exchanged" : "already"):phase=\(fresh.phase.rawValue):revision=\(fresh.revision):selected=\(selected.release.sequence)")
        } catch { print("rejected:\(error)"); exit(77) }
    }
}
