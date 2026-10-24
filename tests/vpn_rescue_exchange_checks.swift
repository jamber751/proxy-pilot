import CryptoKit
import Darwin
import Foundation

@main enum VPNRescueExchangeChecks {
    enum Injected: Error { case denied, interrupted }
    static func hex(_ data: Data) -> String { data.map { String(format: "%02x", $0) }.joined() }
    static func decode(_ value: String) -> Data {
        var output = Data(); var cursor = value.startIndex
        while cursor < value.endIndex {
            let next = value.index(cursor, offsetBy: 2)
            output.append(UInt8(value[cursor..<next], radix: 16)!); cursor = next
        }
        return output
    }
    static func main() throws {
        let args = CommandLine.arguments
        guard args.count == 12 else { exit(64) }
        let operation = args[1], basePath = args[2], destinationPath = args[3]
        let key = try Curve25519.Signing.PrivateKey(rawRepresentation: Data(repeating: 0x42, count: 32))
        let authority = try VPNReleaseAuthority(trustedPublicKey: key.publicKey.rawRepresentation,
                                                minimumSequence: 1, supportedProtocol: 1)
        let helper = Data("inert helper".utf8)
        func manifest(_ sequence: Int, _ version: String, _ arm: String, _ intel: String) -> Data {
            Data("""
            format=1
            product=kz.documentolog.proxypilot
            sequence=\(sequence)
            version=\(version)
            protocol=1
            app-arm64=\(arm)
            app-x86_64=\(intel)
            helper-arm64=\(String(repeating: "33", count: 20))
            helper-x86_64=\(String(repeating: "44", count: 20))
            helper-sha256=\(hex(Data(SHA256.hash(data: helper))))
            helper-bytes=\(helper.count)

            """.utf8)
        }
        let a = manifest(137, "1.6.0", args[8], args[9])
        let b = manifest(139, "1.7.0", args[10], args[11])
        func releaseSignature(_ bytes: Data) throws -> Data { try key.signature(for: VPNReleaseAuthority.signatureDomain + bytes) }
        let aSig = try releaseSignature(a), bSig = try releaseSignature(b)
        let previous = try authority.verify(payload: a, signature: aSig, previous: nil)
        let candidate = try authority.verify(payload: b, signature: bSig, previous: previous)
        func edge(_ bytes: Data, sequence: Int) -> Data {
            Data("format=1\nproduct=kz.documentolog.proxypilot\nfrom-sequence=137\nfrom-sha256=\(hex(Data(SHA256.hash(data: a))))\nto-sequence=\(sequence)\nto-sha256=\(hex(Data(SHA256.hash(data: bytes))))\n".utf8)
        }
        let transitionBytes = edge(b, sequence: 139)
        let transitionSignature = try key.signature(for: VPNReleaseAuthority.updateTransitionDomain + transitionBytes)
        let transition = try authority.verifyUpdateTransition(payload: transitionBytes,
            signature: transitionSignature, previous: previous, candidatePayload: b, candidateSignature: bSig)
        let rescueSequence = operation == "wrong-edge" ? 140 : 139
        let rescueCandidate = manifest(rescueSequence, "1.7.0", args[10], args[11])
        let rescueEdge = edge(rescueCandidate, sequence: rescueSequence)
        let artifact = try Data(contentsOf: URL(fileURLWithPath: args[5]))
        let tokenBytes = try VPNRescueAuthorization.encode(previousManifest: a,
            candidateManifest: rescueCandidate, transitionPayload: rescueEdge, rescueArtifact: artifact,
            arm64CDHash: decode(args[6]), intelCDHash: decode(args[7]))
        let token = try VPNRescueAuthorization.verify(payload: tokenBytes,
            signature: key.signature(for: VPNReleaseAuthority.rescueAuthorizationDomain + tokenBytes),
            authority: authority, previous: previous, previousPayload: a, previousSignature: aSig,
            candidatePayload: rescueCandidate, candidateSignature: releaseSignature(rescueCandidate),
            transitionPayload: rescueEdge,
            transitionSignature: key.signature(for: VPNReleaseAuthority.updateTransitionDomain + rescueEdge))
        let base = open(basePath, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        let destination = open(destinationPath, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        let rescue = open(args[4], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard base >= 0, destination >= 0, rescue >= 0 else { exit(65) }
        defer { close(base); close(destination); close(rescue) }
        var callbacks = 0
        do {
            let proof = try VPNRescueExecutor.testInspect(inTrustedDirectory: rescue, authorization: token)
            let authorize: () throws -> Void = {
                callbacks += 1
                if operation == "authorization-failure" { throw Injected.denied }
                if operation == "mutate-installed" {
                    try Data("changed".utf8).write(to: URL(fileURLWithPath:
                        destinationPath + "/ProxyPilot.app/Contents/Resources/data.txt"))
                }
                if operation == "mutate-frozen-executor" {
                    try Data("changed".utf8).write(to: URL(fileURLWithPath:
                        basePath + "/executor/ProxyPilot.app/Contents/Resources/data.txt"))
                }
            }
            let result: VPNApplicationDestinationExchange.Outcome
            if operation == "ordinary-role" {
                result = try VPNApplicationDestinationExchange.testExchange(
                    inTrustedDirectory: base, destination: destination, previous: previous,
                    previousOwnerUserID: 501, candidate: candidate, transition: transition,
                    requireExecutor: true, authorizeMutation: authorize)
            } else {
                result = try VPNApplicationDestinationExchange.testRescueExchange(
                    inTrustedDirectory: base, destination: destination, previous: previous,
                    previousOwnerUserID: 501, candidate: candidate, transition: transition,
                    executor: proof, authorizeMutation: authorize,
                    checkpoint: { point in
                        if operation == "after-exchange-failure", point == "afterExchange" {
                            throw Injected.interrupted
                        }
                        if operation == "before-exchange-failure", point == "beforeExchange" {
                            throw Injected.interrupted
                        }
                    })
            }
            print("\(result == .exchanged ? "exchanged" : "alreadyExchanged"):auth=\(callbacks)")
        } catch {
            print("rejected:\(error):auth=\(callbacks)")
            exit(77)
        }
    }
}
