// Disposable root VM fixture only; all keys and services below are synthetic.
import CryptoKit
import Darwin
import Foundation

@main enum VPNRescuePendingCoordinatorChecks {
    enum Injected: Error { case denied, interrupted }
    static func hex(_ data: Data) -> String { data.map { String(format: "%02x", $0) }.joined() }
    static func decode(_ value: String) -> Data {
        var output = Data(); var cursor = value.startIndex
        while cursor < value.endIndex {
            let next = value.index(cursor, offsetBy: 2)
            output.append(UInt8(value[cursor..<next], radix: 16)!); cursor = next
        }
        return output
    }
    static func main() throws {
        let args = CommandLine.arguments
        guard args.count == 16 else { exit(64) }
        let operation = args[1], basePath = args[2], destinationPath = args[3]
        let key = try Curve25519.Signing.PrivateKey(rawRepresentation: Data(repeating: 0x42, count: 32))
        let authority = try VPNReleaseAuthority(trustedPublicKey: key.publicKey.rawRepresentation,
                                                minimumSequence: 1, supportedProtocol: 1)
        let helper = try Data(contentsOf: URL(fileURLWithPath: args[13]))
        func manifest(_ sequence: Int, _ version: String, _ arm: String, _ intel: String) -> Data {
            Data("""
            format=1
            product=kz.documentolog.proxypilot
            sequence=\(sequence)
            version=\(version)
            protocol=1
            app-arm64=\(arm)
            app-x86_64=\(intel)
            helper-arm64=\(args[14])
            helper-x86_64=\(args[15])
            helper-sha256=\(hex(Data(SHA256.hash(data: helper))))
            helper-bytes=\(helper.count)

            """.utf8)
        }
        let a = manifest(137, "1.6.0", args[8], args[9])
        let b = manifest(139, "1.7.0", args[10], args[11])
        func releaseSignature(_ bytes: Data) throws -> Data { try key.signature(for: VPNReleaseAuthority.signatureDomain + bytes) }
        let aSig = try releaseSignature(a), bSig = try releaseSignature(b)
        let previous = try authority.verify(payload: a, signature: aSig, previous: nil)
        func edge(_ bytes: Data, sequence: Int) -> Data {
            Data("format=1\nproduct=kz.documentolog.proxypilot\nfrom-sequence=137\nfrom-sha256=\(hex(Data(SHA256.hash(data: a))))\nto-sequence=\(sequence)\nto-sha256=\(hex(Data(SHA256.hash(data: bytes))))\n".utf8)
        }
        let transitionBytes = edge(b, sequence: 139)
        let transitionSignature = try key.signature(for: VPNReleaseAuthority.updateTransitionDomain + transitionBytes)
        let rescueCandidate = b
        let rescueEdge = transitionBytes
        let artifact = try Data(contentsOf: URL(fileURLWithPath: args[5]))
        let tokenBytes = try VPNRescueAuthorization.encode(previousManifest: a,
            candidateManifest: rescueCandidate, transitionPayload: rescueEdge, rescueArtifact: artifact,
            arm64CDHash: decode(args[6]), intelCDHash: decode(args[7]))
        let token = try VPNRescueAuthorization.verify(payload: tokenBytes,
            signature: key.signature(for: VPNReleaseAuthority.rescueAuthorizationDomain + tokenBytes),
            authority: authority, previous: previous, previousPayload: a, previousSignature: aSig,
            candidatePayload: rescueCandidate, candidateSignature: releaseSignature(rescueCandidate),
            transitionPayload: rescueEdge,
            transitionSignature: key.signature(for: VPNReleaseAuthority.updateTransitionDomain + rescueEdge))
        let base = open(basePath, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        let destination = open(destinationPath, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        let rescue = open(args[4], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard base >= 0, destination >= 0, rescue >= 0 else { exit(65) }
        defer { close(base); close(destination); close(rescue) }
        let service = open(args[12], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard service >= 0 else { exit(65) }
        defer { close(service) }
        let store = try VPNReleaseStore(trustedDirectoryDescriptor: service, authority: authority)
        let lease = try VPNLifecycleOwnership.acquire(inTrustedDirectory: service)
        defer { lease.release() }
        if operation == "setup" {
            _ = try store.bootstrapDeployment(payload: a, signature: aSig, helper: helper, trustedOwnerUserID: 501)
            let prepared = try store.prepareUpdateJournal(payload: b, signature: bSig, helper: helper,
                transitionPayload: transitionBytes, transitionSignature: transitionSignature, expectedSequence: 137)
            _ = try store.markUpdateReplacementPending(transactionID: prepared.transactionID, expectedRevision: prepared.revision)
            print("setup"); return
        }
        var trace: [String] = []
        func stale() throws {
            let url = URL(fileURLWithPath: args[12]).appendingPathComponent("update.json")
            var record = try JSONSerialization.jsonObject(with: Data(contentsOf: url)) as! [String: Any]
            record["revision"] = 2
            try JSONSerialization.data(withJSONObject: record, options: .sortedKeys).write(to: url)
            precondition(chmod(url.path, 0o600) == 0)
        }
        do {
            let proof = try VPNRescueExecutor.testInspect(inTrustedDirectory: rescue, authorization: token)
            let context = try VPNRescueJournalContext.capture(authorization: token, store: store, lease: lease)
            if operation == "stale-before" { try stale() }
            let result = try VPNRescuePendingCoordinator.testRun(context: context, executor: proof,
                inTrustedDirectory: base, destination: destination,
                armCandidateRecovery: {
                    trace.append("arm")
                    if operation == "arm-failure" { throw Injected.denied }
                    if operation == "stale-after-arm" { try stale() }
                }, drainPreviousService: {
                    trace.append("drain")
                    if operation == "drain-failure" { throw Injected.denied }
                    if operation == "stale-after-drain" { try stale() }
                }, checkpoint: { point in
                    if point == "afterExchange" {
                        trace.append("exchange")
                        if operation == "after-exchange-failure" { throw Injected.interrupted }
                        if operation == "stale-after-exchange" { try stale() }
                    }
                })
            print("\(result == .exchanged ? "exchanged" : "alreadyExchanged"):trace=\(trace.joined(separator: ","))")
        } catch {
            print("rejected:\(error):trace=\(trace.joined(separator: ","))")
            exit(77)
        }
    }
}
