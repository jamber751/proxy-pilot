import CryptoKit
import Darwin
import Foundation

/// Synthetic release producer and fixed-state VM seeder. Never uses a Keychain.
/// Only the `seed` operation writes system state, under explicit disposable CI
/// guards. A is never launched: its helper authorization reuses frozen B bytes.
@main enum VPNRescueSystemSeed {
    static func hex(_ data: Data) -> String { data.map { String(format: "%02x", $0) }.joined() }
    static func main() throws {
        let args = CommandLine.arguments
        guard args.count >= 2 else { exit(64) }
        let key = try Curve25519.Signing.PrivateKey(rawRepresentation: Data(repeating: 0x42, count: 32))
        if args[1] == "public" { print(key.publicKey.rawRepresentation.base64EncodedString()); return }
        let authority = try VPNReleaseAuthority(trustedPublicKey: key.publicKey.rawRepresentation,
                                               minimumSequence: 1, supportedProtocol: 1)
        if args[1] == "cleanup-endpoint" {
            guard args.count == 2, getuid() == 0, geteuid() == 0,
                  ProcessInfo.processInfo.environment["GITHUB_ACTIONS"] == "true",
                  ProcessInfo.processInfo.environment["PROXYPILOT_VM_SYSTEM_RESCUE_TESTS"] == "1" else { exit(77) }
            try VPNEndpointDirectory.removeSystem()
            print("Removed own validated empty public endpoint"); return
        }
        guard args.count >= 3 else { exit(64) }
        let base = URL(fileURLWithPath: args[2], isDirectory: true)
        if args[1] == "materials" {
            guard getuid() != 0, args.count == 3 else { exit(77) }
            let input = try JSONSerialization.jsonObject(with: Data(contentsOf: base.appendingPathComponent("input.json"))) as! [String: String]
            let helperB = try Data(contentsOf: URL(fileURLWithPath: input["helperB"]!))
            let helperC = try Data(contentsOf: URL(fileURLWithPath: input["helperC"]!))
            func manifest(_ sequence: Int, _ version: String, _ prefix: String, _ helper: Data,
                          _ helperPrefix: String, engine: Bool = false) throws -> Data {
                var text = "format=\(engine ? 2 : 1)\nproduct=kz.documentolog.proxypilot\nsequence=\(sequence)\nversion=\(version)\nprotocol=1\napp-arm64=\(input[prefix + "-arm64"]!)\napp-x86_64=\(input[prefix + "-x86_64"]!)\nhelper-arm64=\(input[helperPrefix + "-arm64"]!)\nhelper-x86_64=\(input[helperPrefix + "-x86_64"]!)\nhelper-sha256=\(hex(Data(SHA256.hash(data: helper))))\nhelper-bytes=\(helper.count)\n"
                if engine {
                    let bytes = try Data(contentsOf: URL(fileURLWithPath: input["engineB"]!))
                    text += "engine-version=2.7.7\nengine-crypto-version=3.5.8\nengine-arm64=\(input["engineB-arm64"]!)\nengine-x86_64=\(input["engineB-x86_64"]!)\nengine-sha256=\(hex(Data(SHA256.hash(data: bytes))))\nengine-bytes=\(bytes.count)\n"
                }
                return Data(text.utf8)
            }
            func signed(_ directory: URL, _ name: String, _ signatureName: String,
                        _ bytes: Data, _ domain: Data) throws {
                try bytes.write(to: directory.appendingPathComponent(name))
                try Data((try key.signature(for: domain + bytes).base64EncodedString() + "\n").utf8)
                    .write(to: directory.appendingPathComponent(signatureName))
            }
            func edge(_ source: Data, _ target: Data, _ from: Int, _ to: Int) -> Data {
                Data("format=1\nproduct=kz.documentolog.proxypilot\nfrom-sequence=\(from)\nfrom-sha256=\(hex(Data(SHA256.hash(data: source))))\nto-sequence=\(to)\nto-sha256=\(hex(Data(SHA256.hash(data: target))))\n".utf8)
            }
            let sourceSequence = Int(input["sourceSequence"] ?? "137")!
            let a = try manifest(sourceSequence, "1.6.0", "appA", helperB, "helperB", engine: true)
            let b = try manifest(139, "1.7.0", "appB", helperB, "helperB", engine: true)
            let c = try manifest(141, "1.8.0", "appC", helperC, "helperC", engine: true)
            // Fail before writing material if production monotonic-component or
            // exact-edge policy rejects any synthetic release in this chain.
            func releaseSignature(_ bytes: Data) throws -> Data {
                try key.signature(for: VPNReleaseAuthority.signatureDomain + bytes)
            }
            let verifiedA = try authority.verify(payload: a, signature: releaseSignature(a), previous: nil)
            let verifiedB = try authority.verify(payload: b, signature: releaseSignature(b), previous: verifiedA)
            _ = try authority.verify(payload: c, signature: releaseSignature(c), previous: verifiedB)
            for (source, target, from, to, previous) in [(a, b, sourceSequence, 139, verifiedA), (b, c, 139, 141, verifiedB)] {
                let transition = edge(source, target, from, to)
                _ = try authority.verifyUpdateTransition(payload: transition,
                    signature: key.signature(for: VPNReleaseAuthority.updateTransitionDomain + transition),
                    previous: previous, candidatePayload: target, candidateSignature: releaseSignature(target))
            }
            let candidate = base.appendingPathComponent("CandidateStage/Payload")
            try signed(base, "source-release.manifest", "source-release.sig", a, VPNReleaseAuthority.signatureDomain)
            try signed(base, "first-transition", "first-transition.sig", edge(a, b, sourceSequence, 139), VPNReleaseAuthority.updateTransitionDomain)
            try signed(candidate, "vpn-previous-release.manifest", "vpn-previous-release.sig", b, VPNReleaseAuthority.signatureDomain)
            try signed(candidate, "vpn-release.manifest", "vpn-release.sig", c, VPNReleaseAuthority.signatureDomain)
            try signed(candidate, "vpn-update-transition", "vpn-update-transition.sig", edge(b, c, 139, 141), VPNReleaseAuthority.updateTransitionDomain)
            print("Synthetic materials prepared"); return
        }
        guard args[1] == "seed", args.count == 5, getuid() == 0, geteuid() == 0,
              ProcessInfo.processInfo.environment["GITHUB_ACTIONS"] == "true",
              ProcessInfo.processInfo.environment["PROXYPILOT_VM_SYSTEM_RESCUE_TESTS"] == "1",
              let owner = UInt32(args[3]), owner >= 500, owner != UInt32.max,
              args[4] == "on" || args[4] == "off" else { exit(77) }
        let candidate = base.appendingPathComponent("CandidateStage/Payload")
        let a = try Data(contentsOf: base.appendingPathComponent("source-release.manifest"))
        let aSig = try signature(base.appendingPathComponent("source-release.sig"))
        let b = try Data(contentsOf: candidate.appendingPathComponent("vpn-previous-release.manifest"))
        let bSig = try signature(candidate.appendingPathComponent("vpn-previous-release.sig"))
        let first = try Data(contentsOf: base.appendingPathComponent("first-transition"))
        let firstSig = try signature(base.appendingPathComponent("first-transition.sig"))
        let input = try JSONSerialization.jsonObject(with: Data(contentsOf: base.appendingPathComponent("input.json"))) as! [String: String]
        let helper = try Data(contentsOf: URL(fileURLWithPath: input["helperB"]!))
        let engine = try Data(contentsOf: URL(fileURLWithPath: input["engineB"]!))
        let service = try VPNDirectoryProvisioner.openSystemDirectory(create: false)
        defer { close(service) }
        let lease = try VPNLifecycleOwnership.acquire(inTrustedDirectory: service)
        defer { lease.release() }
        let store = try VPNReleaseStore(trustedDirectoryDescriptor: service, authority: authority)
        _ = try store.bootstrapDeployment(payload: a, signature: aSig, helper: helper, engine: engine, trustedOwnerUserID: owner)
        let journal = try store.prepareUpdateJournal(payload: b, signature: bSig, helper: helper, engine: engine,
            transitionPayload: first, transitionSignature: firstSig, expectedSequence: 137)
        _ = try store.markUpdateReplacementPending(transactionID: journal.transactionID, expectedRevision: 0)
        if args[4] == "off" { try VPNActivationBudget(trustedDirectoryDescriptor: service).recordManualOff() }
        print("Seeded exact pending137to139 without destination stage")
    }

    private static func signature(_ url: URL) throws -> Data {
        let text = try String(contentsOf: url, encoding: .utf8)
        guard let signature = Data(base64Encoded: text.trimmingCharacters(in: .newlines)), signature.count == 64 else { exit(65) }
        return signature
    }
}
