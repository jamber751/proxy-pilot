import CryptoKit
import Darwin
import Foundation

@main enum VPNTunnelStateChecks {
    static func require(_ value: @autoclosure () -> Bool, _ message: String) throws {
        guard value() else { throw NSError(domain: message, code: 1) }
    }

    static func spec(_ revision: UInt64, byte: UInt8,
                     mode: VPNAuthenticationMode = .certificate) throws -> VPNApplicationSpec {
        let resource = try VPNResource(address: revision == 1 ? "10.10.0.0/16" : "10.20.0.0/16")
        let authentication = try VPNAuthentication(mode: mode,
            login: mode == .certificate ? nil : "employee")
        return try VPNApplicationSpec(revision: revision,
            profileSHA256: String(repeating: String(format: "%02x", byte), count: 32),
            resources: [resource], corporateDNS: ["10.0.0.53"], authentication: authentication)
    }

    static func openDirectory(_ path: String) -> Int32 {
        open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
    }

    static func transactions(_ path: String) throws {
        let fd = openDirectory(path); guard fd >= 0 else { throw VPNTunnelStateStoreError.unsafeStorage }
        defer { close(fd) }
        let store = try VPNTunnelStateStore(trustedDirectoryDescriptor: fd)
        let first = VPNValidatedApplication(spec: try spec(1, byte: 0x11),
                                            requiresVPNCredentials: false,
                                            requiresPrivateKeyPassword: false)
        _ = try store.stage(first)
        _ = try store.acknowledgeApplied(revision: 1)
        let second = VPNValidatedApplication(spec: try spec(2, byte: 0x22, mode: .password),
                                             requiresVPNCredentials: true,
                                             requiresPrivateKeyPassword: false)
        let staged = try store.stage(second)
        try require(staged.active?.spec.revision == 1 && staged.pending?.spec.revision == 2,
                    "active and pending must remain distinct")
        try require(staged.active?.spec.profileSHA256 != staged.pending?.spec.profileSHA256,
                    "profile digests must remain distinct")
        let stale = VPNValidatedApplication(spec: try spec(1, byte: 0x44),
                                            requiresVPNCredentials: false,
                                            requiresPrivateKeyPassword: false)
        do { _ = try store.stage(stale); throw VPNTunnelStateStoreError.invalidState }
        catch VPNTunnelStateStoreError.stale { }
        let waiting = try store.beginConnect(challengeKind: .vpnPassword)
        guard let challenge = waiting.challenge else { throw VPNTunnelStateStoreError.invalidState }
        var response = try VPNCredentialResponse(challenge: challenge,
            secret: Data("SECRET-MUST-NOT-PERSIST".utf8)).encoded()
        let decoded = try VPNCredentialResponse.decode(response)
        _ = try store.consume(decoded.challenge)
        response.resetBytes(in: 0..<response.count)
        do { _ = try store.consume(challenge); throw VPNTunnelStateStoreError.invalidState }
        catch VPNTunnelStateStoreError.stale { }
        let restartedAttempt = try store.beginConnect(challengeKind: .vpnPassword)
        let late = restartedAttempt.challenge!
        let reopened = try VPNTunnelStateStore(trustedDirectoryDescriptor: fd)
        _ = try reopened.invalidateChallengeAfterRestart()
        do { _ = try reopened.consume(late); throw VPNTunnelStateStoreError.invalidState }
        catch VPNTunnelStateStoreError.stale { }
        let bytes = try Data(contentsOf: URL(fileURLWithPath: path).appendingPathComponent(VPNTunnelStateStore.name))
        try require(!String(decoding: bytes, as: UTF8.self).contains("SECRET-MUST-NOT-PERSIST"), "secret persisted")
        let final = try store.load()
        try require(final.phase == .failed && final.challenge == nil && final.generation == 3,
                    "challenge was not consumed exactly once")
        print("transaction checks passed")
    }

    static func canonical(_ path: String) throws {
        let value = try spec(1, byte: 0x33)
        let encoded = try value.encoded()
        let decoded = try VPNApplicationSpec.decodeCanonical(encoded)
        try require(decoded == value, "canonical round trip")
        var object = try JSONSerialization.jsonObject(with: encoded) as! [String: Any]
        object["unknown"] = true
        let unknown = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
        var rejected = false
        do { _ = try VPNApplicationSpec.decodeCanonical(unknown) } catch { rejected = true }
        try require(rejected, "unknown field accepted")
        let spaced = Data((String(data: encoded, encoding: .utf8)! + "\n").utf8)
        rejected = false
        do { _ = try VPNApplicationSpec.decodeCanonical(spaced) } catch { rejected = true }
        try require(rejected, "noncanonical bytes accepted")
        rejected = false
        do {
            _ = try VPNApplicationSpec(revision: 0, profileSHA256: String(repeating: "a", count: 64),
                                       resources: value.resources, corporateDNS: [], authentication: value.authentication)
        } catch { rejected = true }
        try require(rejected, "zero revision accepted")
        print("canonical checks passed")
    }

    static func security(_ path: String, mode: String) throws {
        let state = URL(fileURLWithPath: path).appendingPathComponent(VPNTunnelStateStore.name).path
        if mode == "corrupt" { try Data("{}".utf8).write(to: URL(fileURLWithPath: state)); chmod(state, 0o600) }
        if mode == "mode" { try Data("{}".utf8).write(to: URL(fileURLWithPath: state)); chmod(state, 0o644) }
        if mode == "link" { symlink("target", state) }
        let fd = openDirectory(path); defer { if fd >= 0 { close(fd) } }
        var rejected = false
        do {
            let store = try VPNTunnelStateStore(trustedDirectoryDescriptor: fd)
            _ = try store.load()
        } catch { rejected = true }
        try require(rejected, "unsafe state accepted")
        print("security rejected")
    }

    static func vault(_ path: String) throws {
        let fd = openDirectory(path); defer { close(fd) }
        let vault = try VPNProfileVault(trustedDirectoryDescriptor: fd)
        let data = Data("normalized profile".utf8)
        let digest = try vault.save(data)
        let loaded = try vault.load(digest: digest)
        try require(loaded == data, "digest load")
        let addressed = URL(fileURLWithPath: path).appendingPathComponent(VPNProfileVault.fileName(digest: digest))
        let attributes = try FileManager.default.attributesOfItem(atPath: addressed.path)
        try require((attributes[.posixPermissions] as? NSNumber)?.intValue == 0o600, "profile mode")
        let protected = try vault.openValidated(digest: digest)
        var protectedBytes = [UInt8](repeating: 0, count: data.count)
        let protectedCount = read(protected, &protectedBytes, protectedBytes.count)
        close(protected)
        try require(protectedCount == data.count && Data(protectedBytes) == data,
                    "validated profile descriptor")
        try Data("tampered profile".utf8).write(to: addressed)
        chmod(addressed.path, 0o600)
        var rejected = false
        do { _ = try vault.openValidated(digest: digest) } catch { rejected = true }
        try require(rejected, "digest-addressed profile tampering accepted")
        print("vault checks passed")
    }

    static func main() throws {
        guard CommandLine.arguments.count == 3 else { exit(64) }
        switch CommandLine.arguments[1] {
        case "transactions": try transactions(CommandLine.arguments[2])
        case "canonical": try canonical(CommandLine.arguments[2])
        case "vault": try vault(CommandLine.arguments[2])
        default: try security(CommandLine.arguments[2], mode: CommandLine.arguments[1])
        }
    }
}
