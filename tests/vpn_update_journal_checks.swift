import CryptoKit
import Darwin
import Foundation

@main
enum VPNUpdateJournalChecks {
    static func main() {
        do {
            let a = CommandLine.arguments
            guard a.count == 10, let revision = UInt64(a[9]) else { exit(64) }
            let key = try Curve25519.Signing.PrivateKey(rawRepresentation: Data(repeating: 0x42, count: 32))
            let authority = try VPNReleaseAuthority(trustedPublicKey: key.publicKey.rawRepresentation,
                                                    minimumSequence: 1, supportedProtocol: 1)
            let fd = open(a[2], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard fd >= 0 else { exit(77) }
            let store = try VPNReleaseStore(trustedDirectoryDescriptor: fd, authority: authority)
            close(fd)
            #if VPN_RELEASE_STORE_TESTING
            VPNReleaseStore.checkpoint = { if $0 == a[7] { _exit(86) } }
            #endif
            let ap = try Data(contentsOf: URL(fileURLWithPath: a[3]))
            let bp = try Data(contentsOf: URL(fileURLWithPath: a[4]))
            let ah = try Data(contentsOf: URL(fileURLWithPath: a[5]))
            let bh = try Data(contentsOf: URL(fileURLWithPath: a[6]))
            let asig = try key.signature(for: VPNReleaseAuthority.signatureDomain + ap)
            let bsig = try key.signature(for: VPNReleaseAuthority.signatureDomain + bp)
            let av = try authority.verify(payload: ap, signature: asig, previous: nil)
            let bv = try authority.verify(payload: bp, signature: bsig, previous: av)
            func hex(_ d: Data) -> String { d.map { String(format: "%02x", $0) }.joined() }
            let transition = Data(("format=1\nproduct=kz.documentolog.proxypilot\n" +
                "from-sequence=\(av.sequence)\nfrom-sha256=\(hex(Data(SHA256.hash(data: ap))))\n" +
                "to-sequence=\(bv.sequence)\nto-sha256=\(hex(Data(SHA256.hash(data: bp))))\n").utf8)
            var tsig = try key.signature(for: VPNReleaseAuthority.updateTransitionDomain + transition)
            let id = UUID(uuidString: a[8])
            func show(_ s: VPNUpdateJournalSnapshot) {
                print("journal=\(s.phase.rawValue) revision=\(s.revision) recovery=\(s.recovery.rawValue) id=\(s.transactionID.uuidString) selected=\((try? store.loadDeployment().release.sequence) ?? 0)")
            }
            switch a[1] {
            case "bootstrap":
                let s = try store.bootstrapDeployment(payload: ap, signature: asig, helper: ah, trustedOwnerUserID: 501)
                print("sequence=\(s.release.sequence)")
            case "prepare", "bad-edge":
                if a[1] == "bad-edge" { tsig[0] ^= 1 }
                show(try store.prepareUpdateJournal(payload: bp, signature: bsig, helper: bh,
                    transitionPayload: transition, transitionSignature: tsig, expectedSequence: 10))
            case "load":
                if let s = try store.loadUpdateJournal() { show(s) } else { print("journal=none") }
            case "load-selected":
                print("selected=\(try store.loadDeployment().release.sequence)")
            case "load-cleanup":
                if let s = try store.loadUpdateCleanupReceipt() {
                    print("cleanup=\(s.phase.rawValue) revision=\(s.revision) id=\(s.transactionID.uuidString) owner=\(s.ownerUserID) previous=\(s.previous.release.sequence) selected=\(s.candidate.release.sequence) cleanupPhase=\(s.cleanupPhase.rawValue)")
                } else { print("cleanup=none") }
            case "cleanup-app":
                let s = try store.advanceUpdateCleanupReceipt(transactionID: id!, expectedPhase: .pending, to: .applicationRetired)
                print("cleanup=\(s.cleanupPhase.rawValue)")
            case "cleanup-update":
                let s = try store.advanceUpdateCleanupReceipt(transactionID: id!, expectedPhase: .applicationRetired, to: .updateRetired)
                print("cleanup=\(s.cleanupPhase.rawValue)")
            case "cleanup-retire":
                try store.retireUpdateCleanupReceipt(transactionID: id!); print("cleanup=none")
            case "pending": show(try store.markUpdateReplacementPending(transactionID: id!, expectedRevision: revision))
            case "select": show(try store.selectUpdateCandidate(transactionID: id!, expectedRevision: revision))
            case "complete": show(try store.completeUpdateJournal(transactionID: id!, expectedRevision: revision))
            case "cancel": show(try store.cancelUpdateJournal(transactionID: id!, expectedRevision: revision))
            case "cancel-app": show(try store.advanceCancelledUpdateCleanup(
                transactionID: id!, expectedRevision: revision,
                expectedPhase: .cancelled, to: .cancellationApplicationRetired))
            case "cancel-update": show(try store.advanceCancelledUpdateCleanup(
                transactionID: id!, expectedRevision: revision,
                expectedPhase: .cancellationApplicationRetired,
                to: .cancellationUpdateRetired))
            case "cancel-gc":
                show(try store.authorizeCancelledUpdateCleanupGC(
                    transactionID: id!, expectedRevision: revision,
                    roots: [
                        VPNUpdateCleanupRootIdentity(name: "candidate", device: 1, inode: 2),
                        VPNUpdateCleanupRootIdentity(name: "current", device: 1, inode: 1),
                    ]))
            case "retire": try store.retireUpdateJournal(transactionID: id!, expectedRevision: revision); print("journal=none")
            case "ordinary-commit":
                _ = try store.commitDeployment(payload: bp, signature: bsig, helper: bh, expectedSequence: 10)
            case "ordinary-prepare":
                _ = try store.prepareDeployment(payload: bp, signature: bsig, helper: bh, expectedSequence: 10)
            case "metadata-accept":
                _ = try store.accept(payload: bp, signature: bsig, expectedSequence: 10)
            case "old-token":
                let token = try store.prepareDeployment(payload: bp, signature: bsig, helper: bh, expectedSequence: 10)
                _ = try store.prepareUpdateJournal(payload: bp, signature: bsig, helper: bh,
                    transitionPayload: transition, transitionSignature: tsig, expectedSequence: 10)
                _ = try store.commitPreparedDeployment(token)
            case "bootstrap-again":
                _ = try store.bootstrapDeployment(payload: ap, signature: asig, helper: ah, trustedOwnerUserID: 501)
            default: exit(64)
            }
        } catch {
            print("rejected:\(error)")
            exit(77)
        }
    }
}
