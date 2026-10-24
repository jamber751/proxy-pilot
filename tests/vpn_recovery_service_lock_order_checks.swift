import CryptoKit
import Darwin
import Foundation

/// Ordinary-user temporary-store regression. No ServiceMain, launchd, root,
/// profile, network, installer, or Keychain operation is used by this program.
@main enum VPNRecoveryServiceLockOrderChecks {
    enum Unexpected: Error { case runtime }
    static func hex(_ bytes: Data) -> String { bytes.map { String(format: "%02x", $0) }.joined() }
    static func main() throws {
        let args = CommandLine.arguments
        guard args.count == 5, getuid() == geteuid(), getuid() >= 500,
              args[4] == "clean" || args[4] == "malformed" else { exit(64) }
        let directory = open(args[1], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard directory >= 0 else { exit(65) }
        defer { close(directory) }
        let key = try Curve25519.Signing.PrivateKey(rawRepresentation: Data(repeating: 0x42, count: 32))
        let authority = try VPNReleaseAuthority(trustedPublicKey: key.publicKey.rawRepresentation,
                                               minimumSequence: 1, supportedProtocol: 1)
        let bytes = try Data(contentsOf: URL(fileURLWithPath: args[0]))
        let payload = Data("""
        format=1
        product=kz.documentolog.proxypilot
        sequence=10
        version=1.6.0
        protocol=1
        app-arm64=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
        app-x86_64=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
        helper-arm64=\(args[2])
        helper-x86_64=\(args[3])
        helper-sha256=\(hex(Data(SHA256.hash(data: bytes))))
        helper-bytes=\(bytes.count)

        """.utf8)
        let store = try VPNReleaseStore(trustedDirectoryDescriptor: directory, authority: authority)
        _ = try store.bootstrapDeployment(payload: payload,
            signature: key.signature(for: VPNReleaseAuthority.signatureDomain + payload),
            helper: bytes, trustedOwnerUserID: geteuid())
        if args[4] == "malformed" {
            try Data("not JSON; must not be read while lifecycle is busy".utf8)
                .write(to: URL(fileURLWithPath: args[1]).appendingPathComponent("release.json"))
        }
        let held = try VPNLifecycleOwnership.acquire(inTrustedDirectory: directory)
        defer { held.release() }
        guard unlinkat(directory, "release.lock", 0) == 0 else { exit(65) }
        func snapshot() throws -> [String: String] {
            let base = URL(fileURLWithPath: args[1], isDirectory: true)
            var result: [String: String] = [:]
            for name in try FileManager.default.contentsOfDirectory(atPath: args[1]) where name != "release.lock" {
                var facts = stat()
                guard fstatat(directory, name, &facts, AT_SYMLINK_NOFOLLOW) == 0,
                      facts.st_mode & S_IFMT == S_IFREG else { exit(65) }
                result[name] = "\(facts.st_dev):\(facts.st_ino):\(facts.st_uid):\(facts.st_mode):\(facts.st_nlink):"
                    + hex(Data(SHA256.hash(data: try Data(contentsOf: base.appendingPathComponent(name)))))
            }
            return result
        }
        let before = try snapshot()
        var callbackInvoked = false
        let status = VPNSelectedCandidateRecoveryDaemonEntry.testRunIfRequested(
            arguments: [args[0], VPNRecoveryLaunchdJob.recoveryArgument, VPNRecoveryLaunchdJob.storagePath],
            directory: directory, authority: authority, applicationsDirectory: directory,
            runtime: { _ in callbackInvoked = true; throw Unexpected.runtime },
            completeCleanup: { _, _ in callbackInvoked = true; throw Unexpected.runtime },
            removeRecoveryJob: { _, _ in callbackInvoked = true; throw Unexpected.runtime })
        var named = stat()
        let lockPresent = fstatat(directory, "release.lock", &named, AT_SYMLINK_NOFOLLOW) == 0
        let unchanged = try snapshot() == before
        print("status:\(status ?? -1) releaseLock:\(lockPresent ? "present" : "absent") state:\(unchanged ? "unchanged" : "changed") callbacks:\(callbackInvoked ? "called" : "none")")
    }
}
