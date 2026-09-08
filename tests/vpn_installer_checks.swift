import CryptoKit
import Darwin
import Dispatch
import Foundation

// Drives the installation sequence in a disposable base directory and the user's
// own launchd domain. No root, no /Library, no system domain, no VPN operation.
// The fixture key is disposable; production must embed its own trusted key.
@main
enum VPNInstallerChecks {
    static func main() {
        guard geteuid() != 0 else { exit(77) }
        let args = CommandLine.arguments
        guard args.count == 8, let expected = UInt64(args[5]) else { exit(64) }
        let base = open(args[2], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard base >= 0 else { exit(77) }
        defer { close(base) }
        var status: Int32 = 0
        do {
            let key = try Curve25519.Signing.PrivateKey(rawRepresentation: Data(repeating: 0x42, count: 32))
            let authority = try VPNReleaseAuthority(trustedPublicKey: key.publicKey.rawRepresentation,
                                                    minimumSequence: 1, supportedProtocol: 1)
            let payload = try Data(contentsOf: URL(fileURLWithPath: args[3]))
            let helper = try Data(contentsOf: URL(fileURLWithPath: args[4]))
            var signature = try key.signature(for: VPNReleaseAuthority.signatureDomain + payload)
            if args[1].hasSuffix("-bad-signature") { signature[0] ^= 1 }
            let label = args[6], plists = URL(fileURLWithPath: args[7], isDirectory: true)
            if args[1] == "probe" {
                let directory = try VPNDirectoryProvisioner.openBelowTrustedBase(base, create: false)
                defer { close(directory) }
                let store = try VPNReleaseStore(trustedDirectoryDescriptor: directory, authority: authority)
                let selected = try store.loadDeployment()
                let socket = try VPNEndpointDirectory.connect(directory: directory, owner: geteuid(), shared: false,
                    deadline: DispatchTime.now().uptimeNanoseconds + 2_000_000_000)
                let ready = try VPNHelperReadiness.testProbe(takingSocket: socket, release: selected.release)
                print("ready:\(ready.release.sequence)")
                return
            }
            if args[1] == "root-entry" {
                // The production entries must refuse before touching anything.
                do { _ = try VPNInstaller.install(payload: payload, signature: signature, helper: helper,
                                                  authority: authority, trustedOwnerUserID: 0)
                     print("root-entry:accepted") }
                catch { print("root-entry:\(error)") }
                exit(0)
            }
            if args[1] == "uninstall" {
                try VPNInstaller.testUninstall(base: base, label: label, plistDirectory: plists)
                print("uninstalled")
                exit(0)
            }
            let ready: VPNHelperReady
            if args[1].hasPrefix("install") {
                ready = try VPNInstaller.testInstall(payload: payload, signature: signature, helper: helper,
                                                     authority: authority, base: base, label: label,
                                                     plistDirectory: plists)
            } else {
                ready = try VPNInstaller.testUpdate(payload: payload, signature: signature, helper: helper,
                                                    authority: authority, expectedSequence: expected,
                                                    intent: .explicit, base: base, label: label,
                                                    plistDirectory: plists)
            }
            print("ready:\(ready.release.sequence)")
        } catch { print("rejected:\(error)"); status = 77 }
        exit(status)
    }
}
