import CryptoKit
import Darwin
import Foundation

// Test-only fixture signer and disk coordinator. No launchd or subprocess start.
// This public deterministic key seed MUST NOT be used by a real installer.
@main
enum VPNDeploymentChecks {
    static func main() {
        do {
            let args = CommandLine.arguments
            guard [7, 8].contains(args.count), let expected = UInt64(args[5]) else { exit(64) }
            let key = try Curve25519.Signing.PrivateKey(rawRepresentation: Data(repeating: 0x42, count: 32))
            let authority = try VPNReleaseAuthority.engineCandidateAuthority(
                trustedPublicKey: key.publicKey.rawRepresentation, minimumSequence: 1)
            let descriptor = open(args[2], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard descriptor >= 0 else { exit(77) }
            let store: VPNReleaseStore
            do { store = try VPNReleaseStore(trustedDirectoryDescriptor: descriptor, authority: authority) }
            catch { close(descriptor); throw error }
            close(descriptor)
            #if VPN_RELEASE_STORE_TESTING
            VPNReleaseStore.checkpoint = { point in
                let artifactCheckpoint = ["helper", "engine"].contains(where: {
                    args[6] == $0 + ":after-rename" && point.hasPrefix($0 + "-") && point.hasSuffix(":after-rename")
                })
                if point == args[6] || artifactCheckpoint {
                    _exit(86)
                }
            }
            #endif
            if args[1] == "load" {
                let selected = try store.loadDeployment()
                print("sequence=\(selected.release.sequence) owner=\(selected.ownerUserID) artifact=\(selected.helperFileName) engine=\(selected.engineFileName ?? "none")")
                return
            }
            // Only harness-created disposable fixture paths reach this branch.
            let payload = try Data(contentsOf: URL(fileURLWithPath: args[3]))
            let helper = try Data(contentsOf: URL(fileURLWithPath: args[4]))
            let engine = args.count == 8 ? try Data(contentsOf: URL(fileURLWithPath: args[7])) : nil
            var signature = try key.signature(for: VPNReleaseAuthority.signatureDomain + payload)
            if args[1] == "bad-signature" { signature[0] ^= 1 }
            switch args[1] {
            case "bootstrap":
                _ = try store.bootstrapDeployment(payload: payload, signature: signature, helper: helper, engine: engine, trustedOwnerUserID: 501)
            case "commit", "bad-signature":
                _ = try store.commitDeployment(payload: payload, signature: signature, helper: helper, engine: engine, expectedSequence: expected)
            case "prepare-commit", "tamper-prepared-engine":
                let prepared = try store.prepareDeployment(payload: payload, signature: signature, helper: helper,
                                                             engine: engine, expectedSequence: expected)
                if args[1] == "tamper-prepared-engine", let name = prepared.candidate.engineFileName {
                    try Data("changed after prepare".utf8).write(to: URL(fileURLWithPath: args[2]).appendingPathComponent(name))
                }
                _ = try store.commitPreparedDeployment(prepared)
            case "metadata-only":
                _ = try store.accept(payload: payload, signature: signature, expectedSequence: expected)
            case "bootstrap-metadata":
                _ = try store.bootstrap(payload: payload, signature: signature, trustedOwnerUserID: 501)
                print("metadata-only")
                return
            default: exit(64)
            }
            let selected = try store.loadDeployment()
            print("sequence=\(selected.release.sequence) owner=\(selected.ownerUserID) artifact=\(selected.helperFileName) engine=\(selected.engineFileName ?? "none")")
        } catch {
            print("rejected:\(error)")
            exit(77)
        }
    }
}
