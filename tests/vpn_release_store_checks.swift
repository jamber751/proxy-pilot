import CryptoKit
import Darwin
import Foundation

// Disposable fixture authority only. Its intentionally public constant seed
// enables separate crash/restart processes to use the same test authority.
// Never used by the application, installer or release signing pipeline.
@main
enum VPNReleaseStoreChecks {
    static func main() {
        do {
            let args = CommandLine.arguments
            guard args.count == 6, let sequence = UInt64(args[3]), let expected = UInt64(args[4]) else { exit(64) }
            let key = try Curve25519.Signing.PrivateKey(rawRepresentation: Data(repeating: args[1] == "wrong-key" ? 0x43 : 0x42, count: 32))
            let authority = try VPNReleaseAuthority(trustedPublicKey: key.publicKey.rawRepresentation,
                                                    minimumSequence: 1, supportedProtocol: 1)
            let descriptor = open(args[2], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard descriptor >= 0 else { exit(77) }
            let store: VPNReleaseStore
            do { store = try VPNReleaseStore(trustedDirectoryDescriptor: descriptor, authority: authority) }
            catch { close(descriptor); throw error }
            close(descriptor) // The store must retain its own close-on-exec fd.
            #if VPN_RELEASE_STORE_TESTING
            VPNReleaseStore.checkpoint = { if $0 == args[5] { _exit(86) } }
            #endif
            let appHash = String(repeating: args[1] == "conflict" ? "ab" : "11", count: 20)
            let payload = Data(([
                "format=1", "product=kz.documentolog.proxypilot", "sequence=\(sequence)",
                "version=1.6.0", "protocol=1", "app-arm64=\(appHash)",
                "app-x86_64=\(String(repeating: "22", count: 20))",
                "helper-arm64=\(String(repeating: "33", count: 20))",
                "helper-x86_64=\(String(repeating: "44", count: 20))",
                "helper-sha256=\(String(repeating: "55", count: 32))", "helper-bytes=1", ""
            ].joined(separator: "\n")).utf8)
            var signature = try key.signature(for: VPNReleaseAuthority.signatureDomain + payload)
            if args[1] == "invalid-update" { signature[0] ^= 1 }
            let state: VPNAuthorizedRelease
            switch args[1] {
            case "bootstrap": state = try store.bootstrap(payload: payload, signature: signature, trustedOwnerUserID: 501)
            case "upgrade", "invalid-update", "conflict": state = try store.accept(payload: payload, signature: signature, expectedSequence: expected)
            case "load", "wrong-key": state = try store.load()
            default: exit(64)
            }
            print("sequence=\(state.release.sequence) owner=\(state.ownerUserID)")
        } catch {
            print("rejected:\(error)")
            exit(77)
        }
    }
}
