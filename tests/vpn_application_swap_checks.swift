import CryptoKit
import Darwin
import Foundation

@main enum VPNApplicationSwapChecks {
    enum Injected: Error { case failure }
    static func main() throws {
        let args = CommandLine.arguments
        guard args.count == 7 else { exit(64) }
        let key = Curve25519.Signing.PrivateKey()
        let authority = try VPNReleaseAuthority(trustedPublicKey: key.publicKey.rawRepresentation,
                                               minimumSequence: 1, supportedProtocol: 1)
        func release(_ sequence: Int, _ version: String, _ arm: String, _ intel: String) throws -> (Data, Data, VerifiedVPNRelease) {
            let payload = Data("""
            format=1
            product=kz.documentolog.proxypilot
            sequence=\(sequence)
            version=\(version)
            protocol=1
            app-arm64=\(arm)
            app-x86_64=\(intel)
            helper-arm64=\(String(repeating: "33", count: 20))
            helper-x86_64=\(String(repeating: "44", count: 20))
            helper-sha256=\(String(repeating: "55", count: 32))
            helper-bytes=1

            """.utf8)
            let signature = try key.signature(for: VPNReleaseAuthority.signatureDomain + payload)
            return (payload, signature, try authority.verify(payload: payload, signature: signature, previous: nil))
        }
        let operation = args[1], path = args[2]
        let previous = try release(10, "1.6.0", args[3], args[4])
        let candidate = try release(11, operation == "identical" ? "1.6.0" : "1.7.0", args[5], args[6])
        let edgeCandidate = operation == "wrong-edge" ? try release(12, "1.8.0", args[5], args[6]) : candidate
        func hex(_ data: Data) -> String { SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() }
        let edge = Data("""
        format=1
        product=kz.documentolog.proxypilot
        from-sequence=10
        from-sha256=\(hex(previous.0))
        to-sequence=\(edgeCandidate.2.sequence)
        to-sha256=\(hex(edgeCandidate.0))

        """.utf8)
        let signature = try key.signature(for: VPNReleaseAuthority.updateTransitionDomain + edge)
        let transition = try authority.verifyUpdateTransition(payload: edge, signature: signature,
            previous: previous.2, candidatePayload: edgeCandidate.0, candidateSignature: edgeCandidate.1)
        let base = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard base >= 0 else { exit(65) }
        defer { close(base) }
        var held: VPNLifecycleLease?
        if operation == "busy" { held = try VPNLifecycleOwnership.acquire(inTrustedDirectory: base) }
        defer { held?.release() }
        do {
            let result: VPNProtectedApplicationSwap.Outcome
            if operation == "production" {
                result = try VPNProtectedApplicationSwap.exchange(inTrustedDirectory: base,
                    previous: previous.2, candidate: candidate.2, transition: transition)
            } else {
                result = try VPNProtectedApplicationSwap.testExchange(inTrustedDirectory: base,
                    previous: previous.2, candidate: candidate.2, transition: transition) { point in
                    if operation == "throw-before", point == "beforeExchange" { throw Injected.failure }
                    if operation == "throw-after", point == "afterExchange" { throw Injected.failure }
                    if operation == "throw-sync", point == "afterSync" { throw Injected.failure }
                    if operation == "crash-after", point == "afterExchange" { _exit(91) }
                    if operation == "lose-lock", point == "beforeExchange" {
                        precondition(unlinkat(base, "lifecycle.lock", 0) == 0)
                    }
                    if operation == "unsafe-base", point == "beforeExchange" { precondition(fchmod(base, 0o777) == 0) }
                    if operation == "tamper-before", point == "beforeExchange" {
                        try Data("changed".utf8).write(to: URL(fileURLWithPath: path + "/candidate/ProxyPilot.app/Contents/Resources/data.txt"))
                    }
                    if operation == "tamper-after", point == "afterExchange" {
                        try Data("changed".utf8).write(to: URL(fileURLWithPath: path + "/current/ProxyPilot.app/Contents/Resources/data.txt"))
                    }
                }
            }
            print(result == .exchanged ? "exchanged" : "alreadyExchanged")
        } catch {
            FileHandle.standardError.write(Data("\(String(reflecting: type(of: error))):\(error)\n".utf8))
            print("rejected:\(error)")
        }
    }
}
