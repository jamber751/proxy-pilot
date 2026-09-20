import CryptoKit
import Darwin
import Foundation

@main enum VPNExecutorProvisioningChecks {
    enum Injected: Error { case failure }
    static let helper = Data("inert helper".utf8)

    static func release(arm: String, intel: String) throws -> VerifiedVPNRelease {
        let key = Curve25519.Signing.PrivateKey()
        let sha = SHA256.hash(data: helper).map { String(format: "%02x", $0) }.joined()
        let payload = Data("""
        format=1
        product=kz.documentolog.proxypilot
        sequence=10
        version=1.6.0
        protocol=1
        app-arm64=\(arm)
        app-x86_64=\(intel)
        helper-arm64=\(String(repeating: "33", count: 20))
        helper-x86_64=\(String(repeating: "44", count: 20))
        helper-sha256=\(sha)
        helper-bytes=\(helper.count)

        """.utf8)
        let signature = try key.signature(for: VPNReleaseAuthority.signatureDomain + payload)
        let authority = try VPNReleaseAuthority(trustedPublicKey: key.publicKey.rawRepresentation,
                                                minimumSequence: 1, supportedProtocol: 1)
        return try authority.verify(payload: payload, signature: signature, previous: nil)
    }

    static func main() throws {
        let arguments = CommandLine.arguments
        guard arguments.count == 5 else { exit(64) }
        let operation = arguments[1], path = arguments[2]
        let candidate = try release(arm: arguments[3], intel: arguments[4])
        let base = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard base >= 0 else { exit(65) }
        defer { close(base) }
        var held: VPNLifecycleLease?
        if operation == "busy" { held = try VPNLifecycleOwnership.acquire(inTrustedDirectory: base) }
        defer { held?.release() }
        do {
            let outcome: VPNReplacementExecutorProvisioner.Outcome
            if operation == "production" {
                outcome = try VPNReplacementExecutorProvisioner.prepare(
                    inTrustedDirectory: base, release: candidate)
            } else {
                outcome = try VPNReplacementExecutorProvisioner.testPrepare(
                    inTrustedDirectory: base, release: candidate) { point in
                        if operation == "throw-after-clone", point == "afterClone" { throw Injected.failure }
                        if operation == "throw-before-publish", point == "beforePublish" { throw Injected.failure }
                        if operation == "throw-after-publish", point == "afterPublish" { throw Injected.failure }
                        if operation == "tamper-copy", point == "afterClone" {
                            try Data("changed".utf8).write(to: URL(fileURLWithPath:
                                path + "/.executor.preparing/ProxyPilot.app/Contents/Resources/data.txt"))
                        }
                        if operation == "tamper-source", point == "beforePublish" {
                            try Data("changed".utf8).write(to: URL(fileURLWithPath:
                                path + "/current/ProxyPilot.app/Contents/Resources/data.txt"))
                        }
                        if operation == "extra-source", point == "beforePublish" {
                            try Data("extra".utf8).write(to: URL(fileURLWithPath: path + "/current/extra"))
                        }
                        if operation == "extra-copy", point == "afterClone" {
                            try Data("extra".utf8).write(to: URL(fileURLWithPath:
                                path + "/.executor.preparing/extra"))
                        }
                    }
            }
            let name: String
            switch outcome {
            case .prepared: name = "prepared"
            case .recoveredPrepared: name = "recoveredPrepared"
            case .alreadyPrepared: name = "alreadyPrepared"
            }
            print(name)
        } catch {
            print("rejected:\(error)")
            exit(77)
        }
    }
}
