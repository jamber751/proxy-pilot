import CryptoKit
import Darwin
import Foundation

/// Synthetic package signer only. Never opens a Keychain or starts any artifact.
@main enum VPNRescueInstallationPayloadChecks {
    static func hex(_ data: Data) -> String { data.map { String(format: "%02x", $0) }.joined() }
    static func main() {
        guard geteuid() != 0 else { exit(77) }
        let a = CommandLine.arguments
        guard a.count >= 3 else { exit(64) }
        do {
            let key = try Curve25519.Signing.PrivateKey(rawRepresentation: Data(repeating: 0x42, count: 32))
            let authority = try VPNReleaseAuthority(trustedPublicKey: key.publicKey.rawRepresentation,
                minimumSequence: 1, supportedProtocol: 1)
            let root = URL(fileURLWithPath: a[2], isDirectory: true)
            if a[1].hasPrefix("fixture") {
                guard a.count == 9 || a.count == 11 else { exit(64) }
                let metadata = root.appendingPathComponent("Metadata")
                let candidate = root.appendingPathComponent("Candidate")
                let artifact = try Data(contentsOf: root.appendingPathComponent("Executable/vpn-rescue"))
                let helper = try Data(contentsOf: candidate.appendingPathComponent("vpn-helper"))
                func put(_ directory: URL, _ name: String, _ value: Data) throws {
                    let url = directory.appendingPathComponent(name)
                    try value.write(to: url); guard chmod(url.path, 0o600) == 0 else { exit(65) }
                }
                func signed(_ directory: URL, _ name: String, _ bytes: Data, domain: Data) throws {
                    try put(directory, name, bytes)
                    try put(directory, name + ".sig", Data((try key.signature(for: domain + bytes).base64EncodedString() + "\n").utf8))
                }
                func manifest(_ sequence: Int, version: String, arm: String, intel: String, engine: Bool = false) throws -> Data {
                    var text = "format=\(engine ? 2 : 1)\nproduct=kz.documentolog.proxypilot\nsequence=\(sequence)\nversion=\(version)\nprotocol=1\napp-arm64=\(arm)\napp-x86_64=\(intel)\nhelper-arm64=\(a[5])\nhelper-x86_64=\(a[6])\nhelper-sha256=\(hex(Data(SHA256.hash(data: helper))))\nhelper-bytes=\(helper.count)\n"
                    if engine {
                        let bytes = try Data(contentsOf: candidate.appendingPathComponent("vpn-engine"))
                        text += "engine-version=2.7.7\nengine-crypto-version=3.5.8\nengine-arm64=\(a[9])\nengine-x86_64=\(a[10])\nengine-sha256=\(hex(Data(SHA256.hash(data: bytes))))\nengine-bytes=\(bytes.count)\n"
                    }
                    return Data(text.utf8)
                }
                func edge(_ previous: Data, _ next: Data, from: Int, to: Int) -> Data {
                    Data("format=1\nproduct=kz.documentolog.proxypilot\nfrom-sequence=\(from)\nfrom-sha256=\(hex(Data(SHA256.hash(data: previous))))\nto-sequence=\(to)\nto-sha256=\(hex(Data(SHA256.hash(data: next))))\n".utf8)
                }
                func decode(_ text: String) -> Data {
                    let bytes = Array(text.utf8)
                    func digit(_ value: UInt8) -> UInt8 { value <= 57 ? value - 48 : value - 87 }
                    return Data(stride(from: 0, to: bytes.count, by: 2).map { digit(bytes[$0]) * 16 + digit(bytes[$0 + 1]) })
                }
                let original = try manifest(137, version: "1.6.0", arm: String(repeating: "11", count: 20), intel: String(repeating: "22", count: 20))
                let intermediate = try manifest(139, version: "1.7.0", arm: String(repeating: "55", count: 20), intel: String(repeating: "66", count: 20))
                let final = try manifest(141, version: "1.8.0", arm: a[3], intel: a[4], engine: a.count == 11)
                let first = a[1] == "fixture-cross-first" ? edge(original, final, from: 137, to: 141)
                    : edge(original, intermediate, from: 137, to: 139)
                let second = edge(intermediate, final, from: 139, to: 141)
                try signed(metadata, "source-release.manifest", original, domain: VPNReleaseAuthority.signatureDomain)
                // The fixed manifest signature filename intentionally omits '.manifest'.
                try FileManager.default.moveItem(at: metadata.appendingPathComponent("source-release.manifest.sig"),
                                                to: metadata.appendingPathComponent("source-release.sig"))
                try signed(metadata, "first-transition", first, domain: VPNReleaseAuthority.updateTransitionDomain)
                try signed(candidate, "vpn-previous-release.manifest", intermediate, domain: VPNReleaseAuthority.signatureDomain)
                try FileManager.default.moveItem(at: candidate.appendingPathComponent("vpn-previous-release.manifest.sig"),
                                                to: candidate.appendingPathComponent("vpn-previous-release.sig"))
                try signed(candidate, "vpn-release.manifest", final, domain: VPNReleaseAuthority.signatureDomain)
                try FileManager.default.moveItem(at: candidate.appendingPathComponent("vpn-release.manifest.sig"),
                                                to: candidate.appendingPathComponent("vpn-release.sig"))
                try signed(candidate, "vpn-update-transition", second, domain: VPNReleaseAuthority.updateTransitionDomain)
                let arm = decode(a[7]), intel = decode(a[8])
                let finishFirst = try VPNRescueAuthorization.encode(previousManifest: original,
                    candidateManifest: intermediate, transitionPayload: first, rescueArtifact: artifact,
                    arm64CDHash: arm, intelCDHash: intel)
                let finishSecond = try VPNRescueAuthorization.encode(previousManifest: intermediate,
                    candidateManifest: final, transitionPayload: second,
                    rescueArtifact: a[1] == "fixture-wrong-second-artifact" ? Data("other".utf8) : artifact,
                    arm64CDHash: arm, intelCDHash: intel)
                let prepare = a[1] == "fixture-finish-as-start" ? finishSecond
                    : try VPNRescuePreparationAuthorization.encode(previousManifest: intermediate,
                        candidateManifest: final, transitionPayload: second, rescueArtifact: artifact,
                        arm64CDHash: a[1] == "fixture-wrong-start-pin" ? Data(repeating: 9, count: 20) : arm,
                        intelCDHash: intel)
                try signed(metadata, "finish-first", finishFirst, domain: VPNReleaseAuthority.rescueAuthorizationDomain)
                try signed(metadata, "prepare-second", prepare, domain: VPNReleaseAuthority.rescuePreparationAuthorizationDomain)
                try signed(metadata, "finish-second", finishSecond, domain: VPNReleaseAuthority.rescueAuthorizationDomain)
                print("fixture"); return
            }
            let directory = open(root.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard directory >= 0 else { exit(65) }
            defer { close(directory) }
            let payload = try VPNRescueInstallationPayload.load(inTrustedDirectory: directory, authority: authority)
            if a[1] == "replace-metadata" || a[1] == "replace-executable" || a[1] == "replace-candidate" {
                let name = a[1] == "replace-metadata" ? "Metadata" : a[1] == "replace-executable" ? "Executable" : "Candidate"
                let old = root.deletingLastPathComponent().appendingPathComponent("old-" + name)
                try FileManager.default.moveItem(at: root.appendingPathComponent(name), to: old)
                try FileManager.default.copyItem(at: old, to: root.appendingPathComponent(name))
            } else if a[1] == "change-sidecar" {
                try Data("changed".utf8).write(to: root.appendingPathComponent("Metadata/finish-first"))
            } else if a[1] == "change-app" {
                try Data("changed".utf8).write(to: root.appendingPathComponent("Candidate/ProxyPilot.app/Contents/Resources/data.txt"))
            } else if a[1] == "change-artifact" {
                let file = try FileHandle(forWritingTo: root.appendingPathComponent("Executable/vpn-rescue"))
                try file.seekToEnd(); try file.write(contentsOf: Data("changed".utf8)); try file.close()
            }
            try payload.revalidate()
            let candidate = try payload.duplicateCandidateDirectory(), executable = try payload.duplicateExecutableDirectory()
            close(candidate); close(executable)
            print("verified:\(payload.source.sequence)->\(payload.intermediate.sequence)->\(payload.second.candidate.release.sequence)")
        } catch { print("rejected:\(error)"); exit(77) }
    }
}
