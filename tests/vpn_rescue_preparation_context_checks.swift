import CryptoKit
import Darwin
import Foundation

@main enum VPNRescuePreparationContextChecks {
    static func main() throws {
        let a = CommandLine.arguments
        guard a.count == 8 else { exit(64) }
        let operation = a[1]
        let key = try Curve25519.Signing.PrivateKey(rawRepresentation: Data(repeating: 0x42, count: 32))
        let authority = try VPNReleaseAuthority(trustedPublicKey: key.publicKey.rawRepresentation,
                                                minimumSequence: 1, supportedProtocol: 1)
        let ap = try Data(contentsOf: URL(fileURLWithPath: a[4]))
        var bp = try Data(contentsOf: URL(fileURLWithPath: a[5]))
        if operation == "wrong-edge" {
            bp = Data(String(decoding: bp, as: UTF8.self).replacingOccurrences(of: "sequence=20\n", with: "sequence=21\n").utf8)
        }
        let asig = try key.signature(for: VPNReleaseAuthority.signatureDomain + ap)
        let bsig = try key.signature(for: VPNReleaseAuthority.signatureDomain + bp)
        let previous = try authority.verify(payload: ap, signature: asig, previous: nil)
        let candidate = try authority.verify(payload: bp, signature: bsig, previous: previous)
        func hex(_ bytes: Data) -> String { bytes.map { String(format: "%02x", $0) }.joined() }
        let edge = Data("format=1\nproduct=kz.documentolog.proxypilot\nfrom-sequence=\(previous.sequence)\nfrom-sha256=\(hex(Data(SHA256.hash(data: ap))))\nto-sequence=\(candidate.sequence)\nto-sha256=\(hex(Data(SHA256.hash(data: bp))))\n".utf8)
        let edgeSig = try key.signature(for: VPNReleaseAuthority.updateTransitionDomain + edge)
        let description = try VPNRescuePreparationAuthorization.encode(previousManifest: ap, candidateManifest: bp,
            transitionPayload: edge, rescueArtifact: Data("fixture".utf8),
            arm64CDHash: Data(repeating: 1, count: 20), intelCDHash: Data(repeating: 2, count: 20))
        let authorization = try VPNRescuePreparationAuthorization.verify(payload: description,
            signature: key.signature(for: VPNReleaseAuthority.rescuePreparationAuthorizationDomain + description),
            authority: authority, previous: previous, previousPayload: ap, previousSignature: asig,
            candidatePayload: bp, candidateSignature: bsig, transitionPayload: edge, transitionSignature: edgeSig)
        let service = open(a[2], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        let other = open(a[3], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard service >= 0, other >= 0 else { exit(65) }
        defer { close(service); close(other) }
        let store = try VPNReleaseStore(trustedDirectoryDescriptor: service, authority: authority)
        let lease = try operation == "runtime-lease"
            ? VPNLifecycleOwnership.acquireRuntime(inTrustedDirectory: service)
            : VPNLifecycleOwnership.acquire(inTrustedDirectory: operation == "foreign-lease" ? other : service)
        defer { lease.release() }
        let helper = try Data(contentsOf: URL(fileURLWithPath: a[7]))
        func begin() throws -> VPNUpdatePreparationSnapshot {
            try store.beginUpdatePreparation(payload: bp, signature: bsig, helper: helper,
                transitionPayload: edge, transitionSignature: edgeSig, expectedSequence: previous.sequence)
        }
        if operation.hasPrefix("staging") || operation.hasPrefix("conversion") {
            let staged = try begin()
            if operation.hasPrefix("conversion") {
                let preparationURL = URL(fileURLWithPath: a[2]).appendingPathComponent("preparation.json")
                let saved = try Data(contentsOf: preparationURL)
                _ = try store.commitUpdatePreparation(transactionID: staged.transactionID, helper: helper)
                // Recreate the exact durable crash window after journal commit,
                // before preparation unlink; only synthetic temporary state.
                try saved.write(to: preparationURL)
                precondition(chmod(preparationURL.path, 0o600) == 0)
            }
        }
        func snapshot() throws -> [String: Data] {
            let root = URL(fileURLWithPath: a[2])
            var result: [String: Data] = [:]
            for name in try FileManager.default.contentsOfDirectory(atPath: a[2]) {
                var value = stat()
                precondition(fstatat(service, name, &value, AT_SYMLINK_NOFOLLOW) == 0)
                let metadata = "\(value.st_ino):\(value.st_mode):\(value.st_uid):\(value.st_gid):\(value.st_mtimespec.tv_sec):\(value.st_mtimespec.tv_nsec)\n"
                result[name] = Data(metadata.utf8) + (try Data(contentsOf: root.appendingPathComponent(name)))
            }
            return result
        }
        func readOnly(_ action: () throws -> Void) throws {
            let before = try snapshot()
            do {
                try action()
                let after = try snapshot()
                precondition(after == before, "gate changed storage")
            } catch {
                let after = try snapshot()
                precondition(after == before, "rejected gate changed storage")
                throw error
            }
        }
        func edit(_ name: String, _ transform: (inout [String: Any]) -> Void) throws {
            let url = URL(fileURLWithPath: a[2]).appendingPathComponent(name)
            var record = try JSONSerialization.jsonObject(with: Data(contentsOf: url)) as! [String: Any]
            transform(&record)
            try JSONSerialization.data(withJSONObject: record, options: .sortedKeys).write(to: url)
            precondition(chmod(url.path, 0o600) == 0)
        }
        do {
            if operation == "released-before" { lease.release() }
            if operation == "missing-store-lock" { precondition(unlinkat(service, "release.lock", 0) == 0) }
            if operation == "conversion-mismatched-id" {
                try edit("preparation.json") { $0["transactionID"] = UUID().uuidString }
            }
            if operation == "staging-foreign-owner" {
                try edit("preparation.json") { $0["owner"] = 502 }
            }
            if operation == "staging-gc" {
                let preparation = try store.loadUpdatePreparation()!
                _ = try store.authorizeUpdatePreparationCleanup(transactionID: preparation.transactionID, roots: [])
            }
            var captured: VPNRescuePreparationContext?
            try readOnly {
                captured = try VPNRescuePreparationContext.capture(authorization: authorization, candidate: candidate, transition: try authority.verifyUpdateTransition(payload: edge, signature: edgeSig, previous: previous, candidatePayload: bp, candidateSignature: bsig), store: store, lease: lease)
            }
            let context = captured!
            precondition(context.ownerUserID == 501)
            precondition(context.previous.release.sequence == 10 && context.candidate.sequence == 20)
            switch operation {
            case "advance-clean": _ = try begin()
            case "staging-new-id", "conversion-new-id":
                try edit("preparation.json") { $0["transactionID"] = UUID().uuidString }
            case "staging-delete": precondition(unlinkat(service, "preparation.json", 0) == 0)
            case "conversion-finish":
                let preparation = try store.loadUpdatePreparation()!
                _ = try store.commitUpdatePreparation(transactionID: preparation.transactionID, helper: helper)
            case "release-after": lease.release()
            case "replace-lease":
                precondition(renameat(service, "lifecycle.lock", service, "old-lifecycle.lock") == 0)
                let replacement = openat(service, "lifecycle.lock", O_CREAT | O_EXCL | O_WRONLY, 0o600)
                precondition(replacement >= 0); close(replacement)
            case "new-transaction": try edit("update.json") { $0["transactionID"] = UUID().uuidString }
            case "new-revision": try edit("update.json") { $0["revision"] = 2 }
            case "new-owner":
                try edit("release.json") { $0["owner"] = 502 }
                try edit("update.json") { $0["owner"] = 502 }
            case "select-after":
                let journal = try store.loadUpdateJournal()!
                _ = try store.markUpdateReplacementPending(transactionID: journal.transactionID, expectedRevision: journal.revision)
            case "delete-journal": precondition(unlinkat(service, "update.json", 0) == 0)
            case "unsafe-directory": precondition(fchmod(service, 0o755) == 0)
            default: break
            }
            try readOnly { try context.validate() }
            let state: String
            switch context.state {
            case .clean: state = "clean"
            case .staging: state = "staging"
            case .prepared: state = "prepared"
            case .conversionPending: state = "conversionPending"
            }
            print("validated:\(state)")
        } catch {
            print("rejected:\(error)")
            exit(77)
        }
    }
}
