import CryptoKit
import Darwin
import Foundation

@main enum VPNLegacySourceCloneChecks {
    enum Injected: Error { case stopped }
    static func main() throws {
        let args = CommandLine.arguments
        guard args.count == 6 else { exit(64) }
        let key = try Curve25519.Signing.PrivateKey(rawRepresentation: Data(repeating: 0x42, count: 32))
        let helper = Data("inert helper".utf8)
        let hash = SHA256.hash(data: helper).map { String(format: "%02x", $0) }.joined()
        let payload = Data("""
        format=1
        product=kz.documentolog.proxypilot
        sequence=137
        version=1.6.0
        protocol=1
        app-arm64=\(args[4])
        app-x86_64=\(args[5])
        helper-arm64=\(String(repeating: "33", count: 20))
        helper-x86_64=\(String(repeating: "44", count: 20))
        helper-sha256=\(hash)
        helper-bytes=\(helper.count)

        """.utf8)
        let authority = try VPNReleaseAuthority(trustedPublicKey: key.publicKey.rawRepresentation,
                                                minimumSequence: 1, supportedProtocol: 1)
        let release = try authority.verify(payload: payload,
            signature: key.signature(for: VPNReleaseAuthority.signatureDomain + payload), previous: nil)
        let source = open(args[2], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        let destination = open(args[3], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard source >= 0, destination >= 0 else { exit(65) }
        defer { close(source); close(destination) }
        do {
            try VPNLegacySourceClone.testPrepare(source: source, destination: destination,
                release: release, authorizedOwner: args[1] == "invalid-owner" ? 0 : 501,
                checkpoint: { point in
                    if args[1] == "stop-after-clone", point == "afterClone" { throw Injected.stopped }
                    if args[1] == "stop-mid-owner", point == "afterOwnershipChange" { throw Injected.stopped }
                    if args[1] == "tamper-copy", point == "afterClone" {
                        try Data("tampered".utf8).write(to: URL(fileURLWithPath:
                            args[3] + "/ProxyPilot.app/Contents/Resources/data.txt"))
                    }
                })
            print("prepared")
        } catch { print("rejected:\(error)"); exit(77) }
    }
}
