import CryptoKit
import Darwin
import Foundation

@main enum VPNExecutorHandoffChecks {
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

    static func marker(_ base: Int32, _ request: VPNExecutorHandoffRequest) throws {
        let descriptor = openat(base, "handoff-marker", O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0o600)
        guard descriptor >= 0 else { throw Injected.failure }
        defer { close(descriptor) }
        let value = Data("\(request.transactionID.uuidString) \(request.expectedRevision)\n".utf8)
        guard value.withUnsafeBytes({ write(descriptor, $0.baseAddress, $0.count) }) == value.count,
              fsync(descriptor) == 0 else { throw Injected.failure }
    }

    static func main() throws {
        let arguments = CommandLine.arguments
        let ownPolicy = try VPNPeerAuthentication.testCurrentPolicy(userID: geteuid())
        if let status = VPNReplacementExecutorHandoff.runChildIfRequested(
            arguments: arguments, selfPolicy: ownPolicy, parentPolicy: ownPolicy,
            operation: { request, base in
                try marker(base, request)
                if request.expectedRevision == 99 { throw Injected.failure }
                return request.expectedRevision == 2 ? .alreadyExchanged : .exchanged
            }) {
            exit(status)
        }

        guard arguments.count == 5 else { exit(64) }
        let operation = arguments[1], path = arguments[2]
        let verified = try release(arm: arguments[3], intel: arguments[4])
        let base = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard base >= 0 else { exit(65) }
        defer { close(base) }
        do {
            if operation == "production" {
                _ = try VPNReplacementExecutorHandoff.launchPrepared(
                    inTrustedDirectory: base, release: verified,
                    request: VPNExecutorHandoffRequest(transactionID: UUID(), expectedRevision: 1),
                    childPolicy: ownPolicy, parentPolicy: ownPolicy)
                fatalError("production launch unexpectedly succeeded")
            }
            var held: VPNLifecycleLease?
            if operation == "busy" { held = try VPNLifecycleOwnership.acquire(inTrustedDirectory: base) }
            defer { held?.release() }
            _ = try VPNReplacementExecutorProvisioner.testPrepare(
                inTrustedDirectory: base, release: verified)
            if operation == "tamper-before-launch" {
                try Data("changed".utf8).write(to: URL(fileURLWithPath:
                    path + "/executor/ProxyPilot.app/Contents/Resources/data.txt"))
            }
            let revision: UInt64 = operation == "child-failure" ? 99 :
                (operation == "already" ? 2 : 1)
            let transaction = UUID(uuidString: "7BB17D0B-AE44-4B16-A9F8-C202E4A64983")!
            let policy: VPNPeerPolicy
            let wrongPolicy = try VPNPeerPolicy(userID: geteuid() &+ 1,
                                                signingIdentifier: "kz.documentolog.proxypilot",
                                                codeDirectoryHashes: Set([Data(repeating: 0, count: 20)]))
            if operation == "wrong-peer" {
                policy = wrongPolicy
            } else { policy = ownPolicy }
            let outcome = try VPNReplacementExecutorHandoff.testLaunchPrepared(
                inTrustedDirectory: base, release: verified,
                request: VPNExecutorHandoffRequest(transactionID: transaction,
                                                   expectedRevision: revision),
                childPolicy: policy,
                parentPolicy: operation == "wrong-parent" ? wrongPolicy : ownPolicy) { point in
                    if operation == "tamper-after-ready", point == "childReady" {
                        try Data("changed".utf8).write(to: URL(fileURLWithPath:
                            path + "/executor/ProxyPilot.app/Contents/Resources/data.txt"))
                    }
                }
            switch outcome {
            case .exchanged: print("exchanged")
            case .alreadyExchanged: print("alreadyExchanged")
            }
        } catch {
            print("rejected:\(error)")
            exit(77)
        }
    }
}
