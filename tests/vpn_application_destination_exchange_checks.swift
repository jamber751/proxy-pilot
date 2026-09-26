import CryptoKit
import Darwin
import Foundation

@main enum VPNApplicationDestinationExchangeChecks {
    enum Injected: Error { case failure }
    static let helper = Data("inert helper".utf8)

    static func main() throws {
        let a = CommandLine.arguments
        guard a.count == 8 else { exit(64) }
        let operation = a[1], basePath = a[2], destinationPath = a[3]
        let key = try Curve25519.Signing.PrivateKey(rawRepresentation: Data(repeating: 0x42, count: 32))
        let authority = try VPNReleaseAuthority(trustedPublicKey: key.publicKey.rawRepresentation,
                                                minimumSequence: 1, supportedProtocol: 1)
        func manifest(_ sequence: UInt64, _ version: String, _ arm: String, _ intel: String) -> Data {
            let sha = SHA256.hash(data: helper).map { String(format: "%02x", $0) }.joined()
            return Data("""
            format=1
            product=kz.documentolog.proxypilot
            sequence=\(sequence)
            version=\(version)
            protocol=1
            app-arm64=\(arm)
            app-x86_64=\(intel)
            helper-arm64=\(String(repeating: "33", count: 20))
            helper-x86_64=\(String(repeating: "44", count: 20))
            helper-sha256=\(sha)
            helper-bytes=\(helper.count)

            """.utf8)
        }
        let ap = manifest(10, "1.6.0", a[4], a[5])
        let bp = manifest(11, "1.7.0", a[6], a[7])
        let asig = try key.signature(for: VPNReleaseAuthority.signatureDomain + ap)
        let bsig = try key.signature(for: VPNReleaseAuthority.signatureDomain + bp)
        let av = try authority.verify(payload: ap, signature: asig, previous: nil)
        func hex(_ data: Data) -> String { data.map { String(format: "%02x", $0) }.joined() }
        let edge = Data("format=1\nproduct=kz.documentolog.proxypilot\nfrom-sequence=10\nfrom-sha256=\(hex(Data(SHA256.hash(data: ap))))\nto-sequence=11\nto-sha256=\(hex(Data(SHA256.hash(data: bp))))\n".utf8)
        let edgeSignature = try key.signature(for: VPNReleaseAuthority.updateTransitionDomain + edge)
        let bv = try authority.verify(payload: bp, signature: bsig, previous: av)
        let transition = try authority.verifyUpdateTransition(payload: edge,
            signature: edgeSignature, previous: av, candidatePayload: bp, candidateSignature: bsig)
        let base = open(basePath, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        let destination = open(destinationPath, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard base >= 0, destination >= 0 else { exit(65) }
        defer { close(base); close(destination) }
        var held: VPNLifecycleLease?
        if operation == "busy" { held = try VPNLifecycleOwnership.acquire(inTrustedDirectory: base) }
        defer { held?.release() }
        do {
            let outcome: VPNApplicationDestinationExchange.Outcome
            if operation == "production" {
                outcome = try VPNApplicationDestinationExchange.exchange(
                    inTrustedDirectory: base, previous: av,
                    previousOwnerUserID: geteuid(), candidate: bv,
                    transition: transition, authorizeMutation: {})
            } else {
                outcome = try VPNApplicationDestinationExchange.testExchange(
                    inTrustedDirectory: base, destination: destination,
                    previous: av, previousOwnerUserID: geteuid(), candidate: bv,
                    transition: transition,
                    authorizeMutation: {
                        if operation == "authorization-failure" { throw Injected.failure }
                        if operation == "mutate-installed" {
                            try Data("changed".utf8).write(to: URL(fileURLWithPath:
                                destinationPath + "/ProxyPilot.app/Contents/Resources/data.txt"))
                        }
                    },
                    checkpoint: { point in
                        if operation == "after-exchange-failure", point == "afterExchange" {
                            throw Injected.failure
                        }
                        if operation == "mutate-stage", point == "beforeExchange" {
                            try Data("changed".utf8).write(to: URL(fileURLWithPath:
                                destinationPath + "/.ProxyPilot.vpn-update/ProxyPilot.app/Contents/Resources/data.txt"))
                        }
                    })
            }
            print(outcome == .exchanged ? "exchanged" : "alreadyExchanged")
        } catch {
            print("rejected:\(error)")
            exit(77)
        }
    }
}
