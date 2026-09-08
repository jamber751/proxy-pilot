import CryptoKit
import Darwin
import Foundation

// Thin launcher around the production listener, used both by the listener tests
// and by launchd. It reads the authenticated selection from protected storage,
// serves the readiness handshake and does nothing else: no privileged operation,
// no profile, no routes, no DNS. The trusted key here is a disposable fixture
// key; production must embed its own and must not read trust from storage.
@main
enum VPNHelperService {
    static func main() {
        let args = CommandLine.arguments
        guard (3...5).contains(args.count), ["serve", "seed"].contains(args[1]) else { exit(64) }
        let ready = args.count < 4 || args[3] != "not-ready"
        let directory = open(args[2], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard directory >= 0 else { exit(70) }
        do {
            let key = try Curve25519.Signing.PrivateKey(rawRepresentation: Data(repeating: 0x42, count: 32))
            let authority = try VPNReleaseAuthority(trustedPublicKey: key.publicKey.rawRepresentation,
                                                    minimumSequence: 1, supportedProtocol: 1)
            let store = try VPNReleaseStore(trustedDirectoryDescriptor: directory, authority: authority)
            if args[1] == "seed" {
                guard args.count == 5 else { exit(64) }
                let payload = try Data(contentsOf: URL(fileURLWithPath: args[3]))
                let helper = try Data(contentsOf: URL(fileURLWithPath: args[4]))
                let signature = try key.signature(for: VPNReleaseAuthority.signatureDomain + payload)
                let seeded = try store.bootstrapDeployment(payload: payload, signature: signature,
                                                           helper: helper, trustedOwnerUserID: geteuid())
                print("selected:\(seeded.release.sequence)")
                exit(0)
            }
            let deployment = try store.loadDeployment()
            let listener: VPNHelperListener
            #if VPN_HELPER_LISTENER_TESTING
            if args.count >= 4, args[3] == "installer-test" {
                listener = try VPNHelperListener.testBindInstaller(inTrustedDirectory: directory, release: deployment.release,
                                                                   ownerUserID: deployment.ownerUserID)
            } else {
                var endpoint: Int32?
                if args.count == 5, args[3] == "shared" {
                    endpoint = open(args[4], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
                }
                defer { if let endpoint = endpoint { close(endpoint) } }
                listener = try VPNHelperListener.bind(inTrustedDirectory: directory, release: deployment.release,
                                                      ownerUserID: deployment.ownerUserID, endpointDirectory: endpoint)
            }
            #else
            listener = try VPNHelperListener.bind(inTrustedDirectory: directory, release: deployment.release,
                                                  ownerUserID: deployment.ownerUserID)
            #endif
            print("listening"); fflush(stdout)
            while true { _ = try? listener.serveOnce(isReady: { ready }) }
        } catch {
            FileHandle.standardError.write(Data("service:\(error)\n".utf8))
            exit(71)
        }
    }
}
