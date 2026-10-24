import CryptoKit
import Darwin
import Foundation

@main enum VPNRescueCleanupChecks {
    static func main() {
        do {
            let a = CommandLine.arguments
            guard a.count == 13 else { exit(64) }
            let service = open(a[2], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            let update = open(a[3], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            let retired = open(a[4], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            let applications = open(a[5], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            let rescue = open(a[9], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard service >= 0, update >= 0, retired >= 0, applications >= 0 else { exit(65) }
            defer { close(service); close(update); close(retired); close(applications); if rescue >= 0 { close(rescue) } }
            let key = try Curve25519.Signing.PrivateKey(rawRepresentation: Data(repeating: 0x42, count: 32))
            let authority = try VPNReleaseAuthority(trustedPublicKey: key.publicKey.rawRepresentation,
                minimumSequence: 1, supportedProtocol: 1)
            let ap = try Data(contentsOf: URL(fileURLWithPath: a[6]))
            let bp = try Data(contentsOf: URL(fileURLWithPath: a[7]))
            let helper = try Data(contentsOf: URL(fileURLWithPath: a[8]))
            func sign(_ bytes: Data) throws -> Data { try key.signature(for: VPNReleaseAuthority.signatureDomain + bytes) }
            let asig = try sign(ap), bsig = try sign(bp)
            let av = try authority.verify(payload: ap, signature: asig, previous: nil)
            let bv = try authority.verify(payload: bp, signature: bsig, previous: av)
            func hex(_ data: Data) -> String { data.map { String(format: "%02x", $0) }.joined() }
            func edge(_ payload: Data, _ sequence: UInt64) -> Data {
                Data("format=1\nproduct=kz.documentolog.proxypilot\nfrom-sequence=\(av.sequence)\nfrom-sha256=\(hex(Data(SHA256.hash(data: ap))))\nto-sequence=\(sequence)\nto-sha256=\(hex(Data(SHA256.hash(data: payload))))\n".utf8)
            }
            let transition = edge(bp, bv.sequence)
            let tsig = try key.signature(for: VPNReleaseAuthority.updateTransitionDomain + transition)
            let store = try VPNReleaseStore(trustedDirectoryDescriptor: service, authority: authority)
            if a[1] == "setup" {
                _ = try store.bootstrapDeployment(payload: ap, signature: asig, helper: helper, trustedOwnerUserID: 501)
                var journal = try store.prepareUpdateJournal(payload: bp, signature: bsig, helper: helper,
                    transitionPayload: transition, transitionSignature: tsig, expectedSequence: av.sequence)
                journal = try store.markUpdateReplacementPending(transactionID: journal.transactionID, expectedRevision: journal.revision)
                journal = try store.selectUpdateCandidate(transactionID: journal.transactionID, expectedRevision: journal.revision)
                journal = try store.completeUpdateJournal(transactionID: journal.transactionID, expectedRevision: journal.revision)
                try store.retireUpdateJournal(transactionID: journal.transactionID, expectedRevision: journal.revision)
                print(journal.transactionID.uuidString.lowercased()); return
            }
            func decode(_ value: String) -> Data {
                var bytes = Data(); var cursor = value.startIndex
                while cursor < value.endIndex {
                    let end = value.index(cursor, offsetBy: 2)
                    bytes.append(UInt8(value[cursor..<end], radix: 16)!); cursor = end
                }
                return bytes
            }
            let artifact = try Data(contentsOf: URL(fileURLWithPath: a[10]))
            func authorization(wrong: Bool) throws -> VerifiedVPNRescueAuthorization {
                let payload = wrong ? Data(String(decoding: bp, as: UTF8.self)
                    .replacingOccurrences(of: "sequence=11\n", with: "sequence=12\n").utf8) : bp
                let signedEdge = edge(payload, wrong ? 12 : bv.sequence)
                let encoded = try VPNRescueAuthorization.encode(previousManifest: ap, candidateManifest: payload,
                    transitionPayload: signedEdge, rescueArtifact: artifact,
                    arm64CDHash: decode(a[11]), intelCDHash: decode(a[12]))
                return try VPNRescueAuthorization.verify(payload: encoded,
                    signature: key.signature(for: VPNReleaseAuthority.rescueAuthorizationDomain + encoded),
                    authority: authority, previous: av, previousPayload: ap, previousSignature: asig,
                    candidatePayload: payload, candidateSignature: sign(payload), transitionPayload: signedEdge,
                    transitionSignature: key.signature(for: VPNReleaseAuthority.updateTransitionDomain + signedEdge))
            }
            let valid = try authorization(wrong: false)
            let live = try VPNRescueExecutor.testInspect(inTrustedDirectory: rescue,
                authorization: authorization(wrong: a[1] == "wrong-live-edge"))
            let lease = try VPNLifecycleOwnership.acquire(inTrustedDirectory: service)
            defer { lease.release() }
            let context = try VPNRescueCleanupContext.capture(authorization:
                a[1] == "wrong-context-edge" ? authorization(wrong: true) : valid, store: store, lease: lease)
            func replaceUUID() {
                let url = URL(fileURLWithPath: a[2] + "/cleanup.json")
                var receipt = try! JSONSerialization.jsonObject(with: Data(contentsOf: url)) as! [String: Any]
                var journal = receipt["journal"] as! [String: Any]
                journal["transactionID"] = UUID().uuidString; receipt["journal"] = journal
                try! JSONSerialization.data(withJSONObject: receipt, options: .sortedKeys).write(to: url)
            }
            if a[1] == "stale-uuid" { replaceUUID() }
            if a[1] == "expired-lease" { lease.release() }
            if a[1] == "changed-live-executor" { precondition(fchmodat(rescue, "vpn-rescue", 0o600, 0) == 0) }
            VPNJointUpdateCleanup.checkpoint = { point in
                if a[1] == "crash:" + point { _exit(86) }
                if a[1] == "receipt-drift-before-gc", point == "gc:after-authorize" { replaceUUID() }
                if a[1] == "lease-drift-during-gc", point == "gc:after-child" { lease.release() }
            }
            var target = service
            if a[1] == "foreign-store" {
                let foreign = URL(fileURLWithPath: a[2]).deletingLastPathComponent().appendingPathComponent("foreign")
                try FileManager.default.copyItem(atPath: a[2], toPath: foreign.path)
                target = open(foreign.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            }
            defer { if target != service { close(target) } }
            let otherLease = try a[1] == "wrong-held-lease"
                ? VPNLifecycleOwnership.acquireRuntime(inTrustedDirectory: service) : nil
            defer { otherLease?.release() }
            let result = try VPNJointUpdateCleanup.testCompleteRescue(service: target, update: update,
                retirement: retired, applications: applications, authority: authority,
                lease: otherLease ?? lease, context: context, executor: live)
            switch result { case .retiredAuthenticatedReceipt: print("retired-authenticated-receipt") }
        } catch { print("rejected:\(error)"); exit(77) }
    }
}
