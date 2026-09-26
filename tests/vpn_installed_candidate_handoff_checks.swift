import CryptoKit
import Darwin
import Foundation

@main enum VPNInstalledCandidateHandoffChecks {
    enum Injected: Error { case changed }
    static func main() throws {
        let arguments = CommandLine.arguments
        if arguments.count == 2,
           arguments[1] == VPNInstalledCandidateHandoff.childArgument {
            let policy = try VPNPeerAuthentication.testCurrentPolicy(userID: geteuid())
            exit(VPNInstalledCandidateHandoff.runChildIfRequested(
                arguments: arguments, selfPolicy: policy, parentPolicy: policy,
                validatePending: {}, validateSelected: {}) ?? 64)
        }
        guard arguments.count == 5 else { exit(64) }
        let key = try Curve25519.Signing.PrivateKey(rawRepresentation: Data(repeating: 0x42, count: 32))
        let authority = try VPNReleaseAuthority(trustedPublicKey: key.publicKey.rawRepresentation,
                                                minimumSequence: 1, supportedProtocol: 1)
        let helper = Data("inert helper".utf8)
        let sha = SHA256.hash(data: helper).map { String(format: "%02x", $0) }.joined()
        let payload = Data("""
        format=1
        product=kz.documentolog.proxypilot
        sequence=11
        version=1.7.0
        protocol=1
        app-arm64=\(arguments[3])
        app-x86_64=\(arguments[4])
        helper-arm64=\(String(repeating: "33", count: 20))
        helper-x86_64=\(String(repeating: "44", count: 20))
        helper-sha256=\(sha)
        helper-bytes=\(helper.count)

        """.utf8)
        let signature = try key.signature(for: VPNReleaseAuthority.signatureDomain + payload)
        let release = try authority.verify(payload: payload, signature: signature, previous: nil)
        let destination = open(arguments[2], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard destination >= 0 else { exit(65) }
        defer { close(destination) }
        do {
            let installed = try VPNInstalledApplication.testInspect(
                inApplicationsDirectory: destination, release: release)
            var checks = 0
            var selected = false
            try VPNInstalledCandidateHandoff.testProve(
                installed: installed, release: release,
                validatePending: {
                    checks += 1
                    if arguments[1] == "context-change", checks == 3 { throw Injected.changed }
                    guard !selected else { throw Injected.changed }
                }, commitSelection: {
                    if arguments[1] == "commit-failure" { throw Injected.changed }
                    guard !selected else { throw Injected.changed }
                    selected = true
                }, validateSelected: {
                    checks += 1
                    if arguments[1] == "selected-change" { throw Injected.changed }
                    guard selected else { throw Injected.changed }
                })
            print("ready:\(checks):selected=\(selected)")
        } catch {
            print("rejected:\(error)")
            exit(77)
        }
    }
}
