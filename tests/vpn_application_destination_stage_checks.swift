import CryptoKit
import Darwin
import Foundation

@main enum VPNApplicationDestinationStageChecks {
    enum Injected: Error { case failure }
    static let helper = Data("inert helper".utf8)

    static func release(arm: String, intel: String) throws -> VerifiedVPNRelease {
        let key = Curve25519.Signing.PrivateKey()
        let sha = SHA256.hash(data: helper).map { String(format: "%02x", $0) }.joined()
        let payload = Data("""
        format=1
        product=kz.documentolog.proxypilot
        sequence=11
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
        guard arguments.count == 6 else { exit(64) }
        let operation = arguments[1]
        let basePath = arguments[2], destinationPath = arguments[3]
        let verified = try release(arm: arguments[4], intel: arguments[5])
        let base = open(basePath, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        let destination = open(destinationPath, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard base >= 0, destination >= 0 else { exit(65) }
        defer { close(base); close(destination) }
        var held: VPNLifecycleLease?
        if operation == "busy" { held = try VPNLifecycleOwnership.acquire(inTrustedDirectory: base) }
        defer { held?.release() }
        do {
            let outcome: VPNApplicationDestinationStage.Outcome
            if operation == "production" {
                outcome = try VPNApplicationDestinationStage.prepare(
                    inTrustedDirectory: base, release: verified)
            } else {
                outcome = try VPNApplicationDestinationStage.testPrepare(
                    inTrustedDirectory: base, destination: destination, release: verified) { point in
                        if operation == "throw-after-clone", point == "afterClone" {
                            throw Injected.failure
                        }
                        if operation == "tamper-source", point == "beforeCommit" {
                            try Data("changed".utf8).write(to: URL(fileURLWithPath:
                                basePath + "/current/ProxyPilot.app/Contents/Resources/data.txt"))
                        }
                        if operation == "tamper-stage", point == "afterClone" {
                            try Data("changed".utf8).write(to: URL(fileURLWithPath:
                                destinationPath + "/.ProxyPilot.vpn-update/ProxyPilot.app/Contents/Resources/data.txt"))
                        }
                        if operation == "extra-stage", point == "afterClone" {
                            try Data("extra".utf8).write(to: URL(fileURLWithPath:
                                destinationPath + "/.ProxyPilot.vpn-update/extra"))
                        }
                    }
            }
            print(outcome == .staged ? "staged" : "alreadyStaged")
        } catch {
            print("rejected:\(error)")
            exit(77)
        }
    }
}
