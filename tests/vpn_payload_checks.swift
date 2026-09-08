import CryptoKit
import Darwin
import Foundation

@main enum PayloadChecks {
    static func main() {
        guard geteuid() != 0 else { exit(77) }
        let args = CommandLine.arguments
        guard args.count >= 3 else { exit(64) }
        do {
            let directory = URL(fileURLWithPath: args[2], isDirectory: true)
            let key = try Curve25519.Signing.PrivateKey(rawRepresentation: Data(repeating: 0x42, count: 32))
            if args[1] == "sign" {
                let data = try Data(contentsOf: directory.appendingPathComponent("vpn-release.manifest"))
                let signature = try key.signature(for: VPNReleaseAuthority.signatureDomain + data)
                try Data((signature.base64EncodedString() + "\n").utf8)
                    .write(to: directory.appendingPathComponent("vpn-release.sig"))
            } else if args[1] == "verify", args.count == 4 {
                let authority = try VPNReleaseAuthority(trustedPublicKey: key.publicKey.rawRepresentation,
                                                        minimumSequence: 1, supportedProtocol: 1)
                _ = try VPNInstallationPayload.load(directory: directory, version: args[3], authority: authority)
                print("verified")
            } else { exit(64) }
        } catch { print("rejected:\(error)"); exit(77) }
    }
}
