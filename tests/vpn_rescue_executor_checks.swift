import CryptoKit
import Darwin
import Foundation

@main enum VPNRescueExecutorChecks {
    static func hex(_ bytes: Data) -> String { bytes.map { String(format: "%02x", $0) }.joined() }
    static func decode(_ text: String) -> Data {
        var result = Data(); var cursor = text.startIndex
        while cursor < text.endIndex {
            let next = text.index(cursor, offsetBy: 2)
            result.append(UInt8(text[cursor..<next], radix: 16)!)
            cursor = next
        }
        return result
    }
    static func main() throws {
        let args = CommandLine.arguments
        guard args.count == 6 else { exit(64) }
        let operation = args[1], root = args[2]
        let artifact = try Data(contentsOf: URL(fileURLWithPath: args[3]))
        let arm = decode(args[4]), intel = decode(args[5])
        let key = try Curve25519.Signing.PrivateKey(rawRepresentation: Data(repeating: 0x42, count: 32))
        let authority = try VPNReleaseAuthority(trustedPublicKey: key.publicKey.rawRepresentation,
                                                minimumSequence: 1, supportedProtocol: 1)
        let helper = Data("inert helper".utf8)
        func manifest(_ sequence: Int) -> Data {
            Data("""
            format=1
            product=kz.documentolog.proxypilot
            sequence=\(sequence)
            version=1.6.0
            protocol=1
            app-arm64=\(String(repeating: "11", count: 20))
            app-x86_64=\(String(repeating: "22", count: 20))
            helper-arm64=\(String(repeating: "33", count: 20))
            helper-x86_64=\(String(repeating: "44", count: 20))
            helper-sha256=\(hex(Data(SHA256.hash(data: helper))))
            helper-bytes=\(helper.count)

            """.utf8)
        }
        let a = manifest(137), b = manifest(139)
        let aSig = try key.signature(for: VPNReleaseAuthority.signatureDomain + a)
        let bSig = try key.signature(for: VPNReleaseAuthority.signatureDomain + b)
        let previous = try authority.verify(payload: a, signature: aSig, previous: nil)
        let edge = Data("format=1\nproduct=kz.documentolog.proxypilot\nfrom-sequence=137\nfrom-sha256=\(hex(Data(SHA256.hash(data: a))))\nto-sequence=139\nto-sha256=\(hex(Data(SHA256.hash(data: b))))\n".utf8)
        let edgeSig = try key.signature(for: VPNReleaseAuthority.updateTransitionDomain + edge)
        let payload = try VPNRescueAuthorization.encode(previousManifest: a, candidateManifest: b,
            transitionPayload: edge, rescueArtifact: artifact, arm64CDHash: arm, intelCDHash: intel)
        let signature = try key.signature(for: VPNReleaseAuthority.rescueAuthorizationDomain + payload)
        let authorization = try VPNRescueAuthorization.verify(payload: payload, signature: signature,
            authority: authority, previous: previous, previousPayload: a, previousSignature: aSig,
            candidatePayload: b, candidateSignature: bSig, transitionPayload: edge, transitionSignature: edgeSig)
        let directory = open(root, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard directory >= 0 else { exit(65) }
        defer { close(directory) }
        do {
            if operation == "live" {
                let proof = try VPNRescueExecutor.testInspect(inTrustedDirectory: directory, authorization: authorization)
                precondition(proof.authorization.matchesSource(previous))
                try proof.revalidate()
                print("live")
            } else {
                let proof = try VPNRescueArtifactObservation.testInspect(inTrustedDirectory: directory,
                                                                        authorization: authorization)
                if operation == "chmod-after" {
                    guard chmod(root + "/vpn-rescue", 0o755) == 0 else { exit(66) }
                }
                if operation == "rebind-after" {
                    guard rename(root + "/vpn-rescue", root + ".retired") == 0 else { exit(66) }
                    try FileManager.default.copyItem(atPath: args[3], toPath: root + "/vpn-rescue")
                }
                try proof.revalidate()
                print("static")
            }
        } catch {
            print("rejected:\(error)")
            exit(77)
        }
    }
}
