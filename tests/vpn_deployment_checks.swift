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
            guard args.count == 7, let expected = UInt64(args[5]) else { exit(64) }
            let key = try Curve25519.Signing.PrivateKey(rawRepresentation: Data(repeating: 0x42, count: 32))
            let authority = try VPNReleaseAuthority(trustedPublicKey: key.publicKey.rawRepresentation,
                                                    minimumSequence: 1, supportedProtocol: 1)
            let descriptor = open(args[2], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard descriptor >= 0 else { exit(77) }
            let store: VPNReleaseStore
            do { store = try VPNReleaseStore(trustedDirectoryDescriptor: descriptor, authority: authority) }
            catch { close(descriptor); throw error }
            close(descriptor)
            #if VPN_RELEASE_STORE_TESTING
            VPNReleaseStore.checkpoint = { point in
                if point == args[6] || (args[6] == "helper:after-rename" && point.hasPrefix("helper-") && point.hasSuffix(":after-rename")) {
                    _exit(86)
                }
            }
            #endif
            if args[1] == "load" {
                let selected = try store.loadDeployment()
                print("sequence=\(selected.release.sequence) owner=\(selected.ownerUserID) artifact=\(selected.helperFileName)")
                return
            }
            // Only harness-created disposable fixture paths reach this branch.
            let payload = try Data(contentsOf: URL(fileURLWithPath: args[3]))
            let helper = try Data(contentsOf: URL(fileURLWithPath: args[4]))
            var signature = try key.signature(for: VPNReleaseAuthority.signatureDomain + payload)
            if args[1] == "bad-signature" { signature[0] ^= 1 }
            switch args[1] {
            case "bootstrap":
                _ = try store.bootstrapDeployment(payload: payload, signature: signature, helper: helper, trustedOwnerUserID: 501)
            case "commit", "bad-signature":
                _ = try store.commitDeployment(payload: payload, signature: signature, helper: helper, expectedSequence: expected)
            case "metadata-only":
                _ = try store.accept(payload: payload, signature: signature, expectedSequence: expected)
            case "bootstrap-metadata":
                _ = try store.bootstrap(payload: payload, signature: signature, trustedOwnerUserID: 501)
                print("metadata-only")
                return
            default: exit(64)
            }
            let selected = try store.loadDeployment()
            print("sequence=\(selected.release.sequence) owner=\(selected.ownerUserID) artifact=\(selected.helperFileName)")
        } catch {
            print("rejected:\(error)")
            exit(77)
        }
    }
}
