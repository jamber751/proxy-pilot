import CryptoKit
import Darwin
import Foundation

// Disposable unprivileged static checker. Signs only the supplied test manifest
// with a fresh in-memory key; never runs the artifact, contacts a service or uses
// a release key. Not a production installation or signing entry point.
@main enum EngineArtifactChecks {
    static func main() {
        let args = CommandLine.arguments
        guard geteuid() != 0, args.count == 3 else { exit(64) }
        do {
            let payload = try Data(contentsOf: URL(fileURLWithPath: args[1]))
            let key = Curve25519.Signing.PrivateKey()
            let authority = try VPNReleaseAuthority.engineCandidateAuthority(
                trustedPublicKey: key.publicKey.rawRepresentation, minimumSequence: 1)
            let signature = try key.signature(for: VPNReleaseAuthority.signatureDomain + payload)
            let release = try authority.verify(payload: payload, signature: signature, previous: nil)
            let file = open(args[2], O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
            guard file >= 0 else { throw VPNReleaseAuthorizationError.invalidEngineArtifact }
            defer { close(file) }
            var info = stat()
            guard fstat(file, &info) == 0, info.st_mode & S_IFMT == S_IFREG,
                  info.st_uid == geteuid(), info.st_nlink == 1, info.st_mode & 0o7022 == 0,
                  info.st_size > 0, info.st_size <= VPNReleaseAuthority.maximumEngineBytes else {
                throw VPNReleaseAuthorizationError.invalidEngineArtifact
            }
            let bytes = try Data(contentsOf: URL(fileURLWithPath: args[2]))
            try VPNEngineArtifact.validate(protectedFile: file, data: bytes, release: release)
            print("engine verified; never executed")
        } catch { print("rejected:\(error)"); exit(77) }
    }
}
