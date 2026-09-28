import CryptoKit
import Darwin
import Foundation

@main enum VPNJointUpdateCleanupChecks {
    static func main() {
        do {
            let a = CommandLine.arguments
            guard a.count == 10 else { exit(64) }
            let service = open(a[2], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            let update = open(a[3], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            let retired = open(a[4], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            let applications = open(a[5], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard service >= 0, update >= 0, retired >= 0, applications >= 0 else { exit(77) }
            defer { close(service); close(update); close(retired); close(applications) }
            let key = try Curve25519.Signing.PrivateKey(rawRepresentation: Data(repeating: 0x42, count: 32))
            let authority = try VPNReleaseAuthority(trustedPublicKey: key.publicKey.rawRepresentation,
                                                    minimumSequence: 1, supportedProtocol: 1)
            let ap = try Data(contentsOf: URL(fileURLWithPath: a[6]))
            let bp = try Data(contentsOf: URL(fileURLWithPath: a[7]))
            let helper = try Data(contentsOf: URL(fileURLWithPath: a[8]))
            let asig = try key.signature(for: VPNReleaseAuthority.signatureDomain + ap)
            let bsig = try key.signature(for: VPNReleaseAuthority.signatureDomain + bp)
            let av = try authority.verify(payload: ap, signature: asig, previous: nil)
            let bv = try authority.verify(payload: bp, signature: bsig, previous: av)
            func hex(_ data: Data) -> String { data.map { String(format: "%02x", $0) }.joined() }
            let edge = Data(("format=1\nproduct=kz.documentolog.proxypilot\n" +
                "from-sequence=\(av.sequence)\nfrom-sha256=\(hex(Data(SHA256.hash(data: ap))))\n" +
                "to-sequence=\(bv.sequence)\nto-sha256=\(hex(Data(SHA256.hash(data: bp))))\n").utf8)
            let edgeSignature = try key.signature(for: VPNReleaseAuthority.updateTransitionDomain + edge)
            let store = try VPNReleaseStore(trustedDirectoryDescriptor: service, authority: authority)
            if a[1] == "setup-preparation" {
                _ = try store.bootstrapDeployment(payload: ap, signature: asig,
                                                  helper: helper,
                                                  trustedOwnerUserID: geteuid())
                let preparation = try store.beginUpdatePreparation(
                    payload: bp, signature: bsig, helper: helper,
                    transitionPayload: edge, transitionSignature: edgeSignature,
                    expectedSequence: av.sequence)
                print(preparation.transactionID.uuidString.lowercased())
                return
            }
            if a[1] == "cleanup-preparation" || a[1].hasPrefix("preparation-crash:") {
                if a[1].hasPrefix("preparation-crash:") {
                    let wanted = String(a[1].dropFirst("preparation-crash:".count))
                    VPNJointUpdateCleanup.checkpoint = { if $0 == wanted { _exit(86) } }
                }
                let lease = try VPNLifecycleOwnership.acquire(inTrustedDirectory: service)
                defer { lease.release() }
                try VPNJointUpdateCleanup.testCompletePreparation(
                    service: service, update: update, retirement: retired,
                    authority: authority, lease: lease)
                print("preparation-clean")
                return
            }
            if a[1] == "prepare-next" {
                let journal = try store.prepareUpdateJournal(
                    payload: bp, signature: bsig, helper: helper,
                    transitionPayload: edge, transitionSignature: edgeSignature,
                    expectedSequence: av.sequence)
                print("next:\(journal.candidate.release.sequence)")
                return
            }
            if a[1] == "setup" || a[1] == "setup-cancelled" {
                _ = try store.bootstrapDeployment(payload: ap, signature: asig, helper: helper,
                                                  trustedOwnerUserID: geteuid())
                var journal = try store.prepareUpdateJournal(
                    payload: bp, signature: bsig, helper: helper,
                    transitionPayload: edge, transitionSignature: edgeSignature,
                    expectedSequence: av.sequence)
                if a[1] == "setup-cancelled" {
                    journal = try store.cancelUpdateJournal(
                        transactionID: journal.transactionID, expectedRevision: journal.revision)
                    print(journal.transactionID.uuidString.lowercased())
                    return
                }
                journal = try store.markUpdateReplacementPending(
                    transactionID: journal.transactionID, expectedRevision: journal.revision)
                journal = try store.selectUpdateCandidate(
                    transactionID: journal.transactionID, expectedRevision: journal.revision)
                journal = try store.completeUpdateJournal(
                    transactionID: journal.transactionID, expectedRevision: journal.revision)
                try store.retireUpdateJournal(transactionID: journal.transactionID,
                                              expectedRevision: journal.revision)
                print(journal.transactionID.uuidString.lowercased())
                return
            }
            if a[1].hasPrefix("crash:") {
                let wanted = String(a[1].dropFirst(6))
                VPNJointUpdateCleanup.checkpoint = { if $0 == wanted { _exit(86) } }
            }
            if a[1] == "cleanup-cancelled" || a[1] == "uninstall-cleanup-cancelled"
                || a[1].hasPrefix("cancel-crash:") {
                if a[1].hasPrefix("cancel-crash:") {
                    let wanted = String(a[1].dropFirst("cancel-crash:".count))
                    VPNJointUpdateCleanup.checkpoint = { if $0 == wanted { _exit(86) } }
                }
                guard let journal = try store.loadUpdateJournal() else { exit(77) }
                let lease = try VPNLifecycleOwnership.acquire(inTrustedDirectory: service)
                defer { lease.release() }
                if a[1] == "uninstall-cleanup-cancelled" {
                    try VPNJointUpdateCleanup.testCompleteAll(
                        service: service, update: update, retirement: retired,
                        applications: applications, authority: authority, lease: lease)
                } else {
                    try VPNJointUpdateCleanup.testCompleteCancelled(
                        service: service, update: update, retirement: retired,
                        applications: applications, authority: authority,
                        transactionID: journal.transactionID, lease: lease)
                }
                print("cancel-clean")
                return
            }
            try VPNJointUpdateCleanup.testComplete(
                service: service, update: update, retirement: retired,
                applications: applications, authority: authority)
            print("clean")
        } catch {
            print("rejected:\(error)")
            exit(77)
        }
    }
}
