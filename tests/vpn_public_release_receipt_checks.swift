import CryptoKit
import Darwin
import Foundation

@main enum VPNPublicReleaseReceiptChecks {
    static func main() throws {
        let mode = CommandLine.arguments[1]
        let directory = open(CommandLine.arguments[2],
            O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard directory >= 0 else { exit(70) }
        defer { close(directory) }
        let key = Curve25519.Signing.PrivateKey()
        let authority = try VPNReleaseAuthority(
            trustedPublicKey: key.publicKey.rawRepresentation,
            minimumSequence: 1, supportedProtocol: 1)
        let payload = Data(([
            "format=1", "product=kz.documentolog.proxypilot", "sequence=9",
            "version=1.6.0", "protocol=1",
            "app-arm64=\(String(repeating: "11", count: 20))",
            "app-x86_64=\(String(repeating: "22", count: 20))",
            "helper-arm64=\(String(repeating: "33", count: 20))",
            "helper-x86_64=\(String(repeating: "44", count: 20))",
            "helper-sha256=\(String(repeating: "55", count: 32))",
            "helper-bytes=1", ""
        ].joined(separator: "\n")).utf8)
        var signature = try key.signature(
            for: VPNReleaseAuthority.signatureDomain + payload)
        if mode == "bad-signature" { signature[0] ^= 1 }
        try VPNPublicReleaseReceipt.publish(ownerUserID: 501, payload: payload,
            signature: signature, inTrustedDirectory: directory)
        if mode == "wrong-mode" {
            guard fchmodat(directory, VPNPublicReleaseReceipt.fileName, 0o600, 0) == 0 else { exit(71) }
        }
        do {
            let receipt = try VPNPublicReleaseReceipt.load(
                inTrustedDirectory: directory, expectedFileOwner: geteuid(),
                authority: authority)
            guard mode == "roundtrip", receipt.ownerUserID == 501,
                  receipt.payload == payload, receipt.signature == signature,
                  receipt.release.sequence == 9 else { exit(72) }
            print("receipt verified")
        } catch {
            guard mode != "roundtrip" else { throw error }
            print("receipt rejected")
        }
    }
}
