import CryptoKit
import Darwin
import Foundation

// Fixture-only key and release. This harness never runs or installs the app.
@main enum VPNStagedApplicationChecks {
    static let helper = Data("inert helper".utf8)

    static func release(arm: String, intel: String, version: String) throws -> VerifiedVPNRelease {
        let key = Curve25519.Signing.PrivateKey()
        let sha = SHA256.hash(data: helper).map { String(format: "%02x", $0) }.joined()
        let payload = Data("""
        format=1
        product=kz.documentolog.proxypilot
        sequence=10
        version=\(version)
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

    static func directory(_ path: String) -> Int32 {
        let fd = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        precondition(fd >= 0); return fd
    }

    static func expect(_ name: String, _ action: () throws -> Void) {
        do { try action(); fatalError("expected \(name)") }
        catch { precondition(String(describing: error) == name, "expected \(name), got \(error)") }
    }

    static func main() throws {
        guard CommandLine.arguments.count >= 6 else { exit(64) }
        let operation = CommandLine.arguments[1], path = CommandLine.arguments[2]
        let candidate = try release(arm: CommandLine.arguments[3], intel: CommandLine.arguments[4],
                                    version: CommandLine.arguments[5])
        let expected = CommandLine.arguments.count == 7 ? CommandLine.arguments[6] : nil
        let fd = directory(path); defer { close(fd) }
        let action = {
            switch operation {
            case "inspect":
                let receipt = try VPNStagedApplication.inspect(inTrustedDirectory: fd, release: candidate)
                precondition(receipt.matchesRelease(candidate))
                let other = try release(arm: CommandLine.arguments[3], intel: CommandLine.arguments[4], version: "9.9.9")
                precondition(!receipt.matchesRelease(other))
            case "revalidate":
                let receipt = try VPNStagedApplication.inspect(inTrustedDirectory: fd, release: candidate)
                try VPNStagedApplication.revalidate(receipt, inTrustedDirectory: fd)
            case "inspect-installed":
                let receipt = try VPNStagedApplication.inspectInstalled(
                    inApplicationsDirectory: fd, ownerUserID: geteuid(),
                    productionParent: false, release: candidate)
                precondition(receipt.matchesRelease(candidate))
                try VPNStagedApplication.revalidate(receipt, inTrustedDirectory: fd)
            case "wrong-installed-owner":
                _ = try VPNStagedApplication.inspectInstalled(
                    inApplicationsDirectory: fd, ownerUserID: geteuid() &+ 1,
                    productionParent: false, release: candidate)
            case "protected-parent-distinct-content-owner":
                try VPNStagedApplication.testProtectedParent(
                    inTrustedDirectory: fd, contentOwnerUserID: geteuid() &+ 1)
            case "resource-after":
                let receipt = try VPNStagedApplication.inspect(inTrustedDirectory: fd, release: candidate)
                try Data("changed".utf8).write(to: URL(fileURLWithPath: path + "/ProxyPilot.app/Contents/Resources/data.txt"))
                try VPNStagedApplication.revalidate(receipt, inTrustedDirectory: fd)
            case "bundle-after":
                let receipt = try VPNStagedApplication.inspect(inTrustedDirectory: fd, release: candidate)
                precondition(rename(path + "/ProxyPilot.app", path + "/moved.app") == 0)
                precondition(rename(path + "/Replacement.app", path + "/ProxyPilot.app") == 0)
                try VPNStagedApplication.revalidate(receipt, inTrustedDirectory: fd)
            case "parent-after":
                let receipt = try VPNStagedApplication.inspect(inTrustedDirectory: fd, release: candidate)
                let replacement = path + ".replacement"; precondition(mkdir(replacement, 0o700) == 0)
                precondition(rename(path + "/Replacement.app", replacement + "/ProxyPilot.app") == 0)
                let otherFD = directory(replacement); defer { close(otherFD) }
                try VPNStagedApplication.revalidate(receipt, inTrustedDirectory: otherFD)
            default: fatalError("bad operation")
            }
        }
        if let expected { expect(expected, action) } else { try action() }
    }
}
