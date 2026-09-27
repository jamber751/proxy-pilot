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
            } else if args[1] == "sign-release", args.count == 4 {
                let data = try Data(contentsOf: URL(fileURLWithPath: args[2]))
                let signature = try key.signature(for: VPNReleaseAuthority.signatureDomain + data)
                try Data((signature.base64EncodedString() + "\n").utf8)
                    .write(to: URL(fileURLWithPath: args[3]))
            } else if args[1] == "sign-joint" {
                let previous = try Data(contentsOf:
                    directory.appendingPathComponent("vpn-previous-release.manifest"))
                let previousSignature = try key.signature(
                    for: VPNReleaseAuthority.signatureDomain + previous)
                try Data((previousSignature.base64EncodedString() + "\n").utf8)
                    .write(to: directory.appendingPathComponent("vpn-previous-release.sig"))
                let candidate = try Data(contentsOf:
                    directory.appendingPathComponent("vpn-release.manifest"))
                let candidateSignature = try key.signature(
                    for: VPNReleaseAuthority.signatureDomain + candidate)
                try Data((candidateSignature.base64EncodedString() + "\n").utf8)
                    .write(to: directory.appendingPathComponent("vpn-release.sig"))
                func sequence(_ data: Data) throws -> UInt64 {
                    guard let text = String(data: data, encoding: .utf8),
                          let row = text.split(separator: "\n").first(where: {
                            $0.hasPrefix("sequence=")
                          }), let value = UInt64(row.dropFirst("sequence=".count)) else {
                        throw VPNInstallationPayloadError.unsafePackage
                    }
                    return value
                }
                func hex(_ data: Data) -> String {
                    SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
                }
                let edge = Data(("format=1\nproduct=kz.documentolog.proxypilot\n"
                    + "from-sequence=\(try sequence(previous))\nfrom-sha256=\(hex(previous))\n"
                    + "to-sequence=\(try sequence(candidate))\nto-sha256=\(hex(candidate))\n").utf8)
                let edgeSignature = try key.signature(
                    for: VPNReleaseAuthority.updateTransitionDomain + edge)
                try edge.write(to: directory.appendingPathComponent("vpn-update-transition"))
                try Data((edgeSignature.base64EncodedString() + "\n").utf8)
                    .write(to: directory.appendingPathComponent("vpn-update-transition.sig"))
            } else if args[1] == "verify", args.count == 4 {
                let authority = try VPNReleaseAuthority(trustedPublicKey: key.publicKey.rawRepresentation,
                                                        minimumSequence: 1, supportedProtocol: 1)
                _ = try VPNInstallationPayload.load(directory: directory, version: args[3], authority: authority)
                print("verified")
            } else if args[1] == "verify-joint", args.count == 4 {
                let authority = try VPNReleaseAuthority(
                    trustedPublicKey: key.publicKey.rawRepresentation,
                    minimumSequence: 1, supportedProtocol: 1)
                let payload = try VPNJointUpdatePayload.load(
                    directory: directory, version: args[3], authority: authority)
                print("verified:\(payload.previous.sequence)->\(payload.candidate.release.sequence)")
            } else { exit(64) }
        } catch { print("rejected:\(error)"); exit(77) }
    }
}
