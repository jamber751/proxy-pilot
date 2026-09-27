import CryptoKit
import Darwin
import Foundation

// The production daemon lifecycle with ONLY path/authority/UID boundaries
// substituted. Never root, never /Library, no VPN or real release keys.
@main enum DaemonFixture {
    static func main() {
        guard getuid() != 0, getuid() == geteuid() else { exit(77) }
        do {
            let args = CommandLine.arguments
            if args.count == 2, args[1] == "system" {
                try VPNHelperDaemon.runSystem(arguments: [args[0], "serve", VPNHelperDaemon.storagePath])
                exit(1)
            }
            guard args.count == 3, args[1] == "serve" else { exit(64) }
            let directory = open(args[2], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard directory >= 0 else { exit(77) }
            defer { close(directory) }
            let key = try Curve25519.Signing.PrivateKey(rawRepresentation: Data(repeating: 0x42, count: 32))
            let authority = try VPNReleaseAuthority.engineCandidateAuthority(
                trustedPublicKey: key.publicKey.rawRepresentation, minimumSequence: 1)
            try VPNHelperDaemon.testServe(
                directory: directory, endpoint: directory, shared: false,
                authority: authority,
                recoveryCleanup: {
                    do {
                        let unexpected = try VPNLifecycleOwnership.acquire(
                            inTrustedDirectory: directory)
                        unexpected.release()
                        throw VPNHelperDaemonError.selectionChanged
                    } catch VPNLifecycleOwnershipError.busy {
                        // Cleanup must be serialized with the next updater.
                    }
                    guard unlinkat(directory, "recovery-cleanup-marker", 0) == 0
                            || errno == ENOENT else {
                        throw VPNHelperDaemonError.selectionChanged
                    }
                })
        } catch { print("rejected:\(error)"); exit(77) }
    }
}
