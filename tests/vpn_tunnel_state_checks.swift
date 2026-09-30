import CryptoKit
import Darwin
import Foundation

@main enum VPNTunnelStateChecks {
    enum LegacyPhase: String, Codable { case off, pending, connecting, needsCredential, failed }
    struct LegacySnapshot: Codable {
        let schemaVersion: Int
        let generation: UInt64
        let desiredEnabled: Bool
        let phase: LegacyPhase
        let active: VPNValidatedApplication?
        let pending: VPNValidatedApplication?
        let challenge: VPNCredentialChallenge?
    }

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
                                             requiresPrivateKeyPassword: true)
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
        let binding = try store.beginConnect()
        try require(binding.generation == 1 && binding.application == second,
                    "attempt was not bound to the complete pending application")
        let activated = try store.activateForRouting(binding)
        let activeState = try store.load()
        try require(activated == second && activeState.active == second
                    && activeState.pending == nil && activeState.attempt == binding
                    && activeState.phase == .connecting,
                    "exact pending application was not activated for routing")
        _ = try store.activateForRouting(binding)
        let foreignBinding = VPNConnectAttemptBinding(generation: binding.generation,
                                                      application: first)
        do { _ = try store.activateForRouting(foreignBinding)
            throw VPNTunnelStateStoreError.invalidState }
        catch VPNTunnelStateStoreError.stale { }
        let keyChallenge = try store.issueChallenge(binding: binding, kind: .privateKeyPassword)
        let claimedKey = try store.claimCredential(keyChallenge)
        let claimedState = try store.load()
        try require(claimedKey == binding && claimedState.phase == .authenticating,
                    "private-key challenge was not claimed atomically")
        do { _ = try store.claimCredential(keyChallenge); throw VPNTunnelStateStoreError.invalidState }
        catch VPNTunnelStateStoreError.stale { }
        _ = try store.completeCredentialPrompt(binding: binding)
        do {
            _ = try store.issueChallenge(binding: binding, kind: .privateKeyPassword)
            throw VPNTunnelStateStoreError.invalidState
        } catch VPNTunnelStateStoreError.stale { }
        let challenge = try store.issueChallenge(binding: binding, kind: .vpnPassword)
        let staleBinding = VPNConnectAttemptBinding(generation: binding.generation,
            application: first)
        do { _ = try store.issueChallenge(binding: staleBinding, kind: .vpnPassword)
            throw VPNTunnelStateStoreError.invalidState }
        catch VPNTunnelStateStoreError.stale { }
        var response = try VPNCredentialResponse(challenge: challenge,
            secret: Data("SECRET-MUST-NOT-PERSIST".utf8)).encoded()
        let decoded = try VPNCredentialResponse.decode(response)
        let wrongUUID = VPNCredentialChallenge(generation: challenge.generation,
            kind: challenge.kind)
        do { _ = try store.claimCredential(wrongUUID); throw VPNTunnelStateStoreError.invalidState }
        catch VPNTunnelStateStoreError.stale { }
        let wrongGeneration = VPNCredentialChallenge(generation: challenge.generation + 1,
            identifier: challenge.identifier, kind: challenge.kind)
        do { _ = try store.claimCredential(wrongGeneration); throw VPNTunnelStateStoreError.invalidState }
        catch VPNTunnelStateStoreError.stale { }
        let wrongKind = VPNCredentialChallenge(generation: challenge.generation,
            identifier: challenge.identifier, kind: .privateKeyPassword)
        do { _ = try store.claimCredential(wrongKind); throw VPNTunnelStateStoreError.invalidState }
        catch VPNTunnelStateStoreError.stale { }
        let claimedPassword = try store.claimCredential(decoded.challenge)
        try require(claimedPassword == binding, "credential returned a different attempt binding")
        response.resetBytes(in: 0..<response.count)
        do { _ = try store.claimCredential(challenge); throw VPNTunnelStateStoreError.invalidState }
        catch VPNTunnelStateStoreError.stale { }
        _ = try store.completeCredentialPrompt(binding: binding)
        do { _ = try store.issueChallenge(binding: binding, kind: .vpnPassword)
            throw VPNTunnelStateStoreError.invalidState }
        catch VPNTunnelStateStoreError.stale { }
        let connected = try store.markConnected(binding)
        try require(connected.phase == .connected && connected.desiredEnabled
                    && connected.active == binding.application
                    && connected.pending == nil && connected.attempt == binding,
                    "verified route attempt was not published as connected")
        do { _ = try store.beginConnect(); throw VPNTunnelStateStoreError.invalidState }
        catch VPNTunnelStateStoreError.invalidState { }
        _ = try store.cancelAttempt(binding)
        do { _ = try store.completeCredentialPrompt(binding: binding)
            throw VPNTunnelStateStoreError.invalidState }
        catch VPNTunnelStateStoreError.stale { }
        let bytes = try Data(contentsOf: URL(fileURLWithPath: path).appendingPathComponent(VPNTunnelStateStore.name))
        try require(!String(decoding: bytes, as: UTF8.self).contains("SECRET-MUST-NOT-PERSIST"), "secret persisted")
        let final = try store.load()
        try require(final.phase == .off && final.challenge == nil && final.attempt == nil
                    && final.generation == 2 && final.issuedCredentialKinds.isEmpty,
                    "cancel did not retire the exact attempt")
        print("transaction checks passed")
    }

    static func makeStore(_ path: String, _ name: String) throws -> (VPNTunnelStateStore, Int32) {
        let child = URL(fileURLWithPath: path).appendingPathComponent(name).path
        guard mkdir(child, 0o700) == 0 else { throw VPNTunnelStateStoreError.unsafeStorage }
        let fd = openDirectory(child)
        guard fd >= 0 else { throw VPNTunnelStateStoreError.unsafeStorage }
        return (try VPNTunnelStateStore(trustedDirectoryDescriptor: fd), fd)
    }

    static func recovery(_ path: String) throws {
        let application = VPNValidatedApplication(spec: try spec(1, byte: 0x55, mode: .password),
            requiresVPNCredentials: true, requiresPrivateKeyPassword: true)

        for phase in ["connecting", "needs", "authenticating"] {
            let (store, fd) = try makeStore(path, phase); defer { close(fd) }
            _ = try store.stage(application)
            let binding = try store.beginConnect()
            var challenge: VPNCredentialChallenge?
            if phase != "connecting" {
                challenge = try store.issueChallenge(binding: binding, kind: .privateKeyPassword)
            }
            if phase == "authenticating" { _ = try store.claimCredential(challenge!) }
            let recovered = try store.recoverInterruptedAttemptAfterRestart()
            try require(recovered.phase == .failed && recovered.desiredEnabled
                        && recovered.generation == binding.generation + 1
                        && recovered.challenge == nil && recovered.attempt == nil,
                        "\(phase) did not recover fail-closed")
            if let challenge {
                do { _ = try store.claimCredential(challenge)
                    throw VPNTunnelStateStoreError.invalidState }
                catch VPNTunnelStateStoreError.stale { }
            }
            do { _ = try store.completeCredentialPrompt(binding: binding)
                throw VPNTunnelStateStoreError.invalidState }
            catch VPNTunnelStateStoreError.stale { }
        }

        let (connectedStore, connectedFD) = try makeStore(path, "connected")
        defer { close(connectedFD) }
        let certificate = VPNValidatedApplication(spec: try spec(2, byte: 0x77),
            requiresVPNCredentials: false, requiresPrivateKeyPassword: false)
        _ = try connectedStore.stage(certificate)
        let connectedBinding = try connectedStore.beginConnect()
        _ = try connectedStore.activateForRouting(connectedBinding)
        _ = try connectedStore.markConnected(connectedBinding)
        let recoveredConnected = try connectedStore.recoverInterruptedAttemptAfterRestart()
        try require(recoveredConnected.phase == .failed
                    && recoveredConnected.generation == connectedBinding.generation + 1
                    && recoveredConnected.attempt == nil,
                    "connected state survived daemon restart without fresh route proof")
        print("recovery checks passed")
    }

    static func migration(_ path: String) throws {
        let application = VPNValidatedApplication(spec: try spec(1, byte: 0x66),
            requiresVPNCredentials: false, requiresPrivateKeyPassword: false)
        let legacy = LegacySnapshot(schemaVersion: 1, generation: 8,
            desiredEnabled: true, phase: .connecting, active: application,
            pending: nil, challenge: nil)
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
        let state = URL(fileURLWithPath: path).appendingPathComponent(VPNTunnelStateStore.name)
        try encoder.encode(legacy).write(to: state); chmod(state.path, 0o600)
        let fd = openDirectory(path); defer { close(fd) }
        let store = try VPNTunnelStateStore(trustedDirectoryDescriptor: fd)
        let migrated = try store.load()
        try require(migrated.schemaVersion == 2 && migrated.phase == .failed
                    && migrated.generation == 9 && migrated.attempt == nil,
                    "legacy interrupted attempt was not migrated fail-closed")
        let disk = try Data(contentsOf: state)
        let canonical = try migrated.encoded()
        try require(disk == canonical, "migration was not canonicalized atomically")
        print("migration checks passed")
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
        case "recovery": try recovery(CommandLine.arguments[2])
        case "migration": try migration(CommandLine.arguments[2])
        case "canonical": try canonical(CommandLine.arguments[2])
        case "vault": try vault(CommandLine.arguments[2])
        default: try security(CommandLine.arguments[2], mode: CommandLine.arguments[1])
        }
    }
}
