import Darwin
import Foundation

enum VPNTunnelStateStoreError: Error { case unsafeStorage, invalidState, stale, writeFailed }

enum VPNTunnelPhase: String, Codable {
    case off, pending, connecting, needsCredential, authenticating, failed
}

struct VPNValidatedApplication: Codable, Equatable {
    let spec: VPNApplicationSpec
    let requiresVPNCredentials: Bool
    let requiresPrivateKeyPassword: Bool

    func validate() throws {
        try spec.validate()
        guard requiresVPNCredentials == (spec.authentication.mode != .certificate)
        else { throw VPNTunnelStateStoreError.invalidState }
    }
}

/// Exact, non-secret authority for one connection attempt. A caller must carry
/// this whole value across asynchronous engine prompts so a newly staged
/// application can never be substituted into an older attempt.
struct VPNConnectAttemptBinding: Codable, Equatable {
    let generation: UInt64
    let application: VPNValidatedApplication

    func validate() throws {
        guard generation > 0 else { throw VPNTunnelStateStoreError.invalidState }
        try application.validate()
    }
}

struct VPNTunnelSnapshot: Codable, Equatable {
    let schemaVersion: Int
    let generation: UInt64
    let desiredEnabled: Bool
    let phase: VPNTunnelPhase
    let active: VPNValidatedApplication?
    let pending: VPNValidatedApplication?
    let challenge: VPNCredentialChallenge?
    let attempt: VPNConnectAttemptBinding?
    let issuedCredentialKinds: [VPNCredentialKind]

    init(schemaVersion: Int, generation: UInt64, desiredEnabled: Bool,
         phase: VPNTunnelPhase, active: VPNValidatedApplication?,
         pending: VPNValidatedApplication?, challenge: VPNCredentialChallenge?,
         attempt: VPNConnectAttemptBinding? = nil,
         issuedCredentialKinds: [VPNCredentialKind] = []) {
        self.schemaVersion = schemaVersion
        self.generation = generation
        self.desiredEnabled = desiredEnabled
        self.phase = phase
        self.active = active
        self.pending = pending
        self.challenge = challenge
        self.attempt = attempt
        self.issuedCredentialKinds = issuedCredentialKinds
    }

    func validate() throws {
        guard schemaVersion == 2 else { throw VPNTunnelStateStoreError.invalidState }
        try active?.validate(); try pending?.validate()
        try attempt?.validate()
        let attemptPhase = phase == .connecting || phase == .needsCredential || phase == .authenticating
        guard active != nil || pending != nil || (!desiredEnabled && phase == .off),
              challenge == nil || (phase == .needsCredential && challenge?.generation == generation),
              phase != .needsCredential || challenge != nil,
              phase != .authenticating || challenge == nil,
              attemptPhase == (attempt != nil),
              attempt?.generation == generation || attempt == nil,
              attempt.map({ (pending ?? active) == $0.application }) ?? true,
              issuedCredentialKinds.count <= 2,
              Set(issuedCredentialKinds.map(\.rawValue)).count == issuedCredentialKinds.count,
              issuedCredentialKinds.allSatisfy({ $0 == .privateKeyPassword || $0 == .vpnPassword }),
              attempt != nil || issuedCredentialKinds.isEmpty,
              challenge.map({ issuedCredentialKinds.contains($0.kind) }) ?? true,
              phase != .off || (!desiredEnabled && attempt == nil && issuedCredentialKinds.isEmpty),
              phase != .failed || (challenge == nil && attempt == nil && issuedCredentialKinds.isEmpty)
        else { throw VPNTunnelStateStoreError.invalidState }
    }

    func encoded() throws -> Data {
        try validate()
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
        return try encoder.encode(self)
    }
}

private enum VPNLegacyTunnelPhase: String, Codable {
    case off, pending, connecting, needsCredential, failed
}

/// Schema 1 is accepted only in its exact canonical representation. Any
/// interrupted operation is migrated to `failed` with its challenge burned.
private struct VPNLegacyTunnelSnapshot: Codable {
    let schemaVersion: Int
    let generation: UInt64
    let desiredEnabled: Bool
    let phase: VPNLegacyTunnelPhase
    let active: VPNValidatedApplication?
    let pending: VPNValidatedApplication?
    let challenge: VPNCredentialChallenge?

    func encoded() throws -> Data {
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
        return try encoder.encode(self)
    }

    func migrate() throws -> VPNTunnelSnapshot {
        guard schemaVersion == 1 else { throw VPNTunnelStateStoreError.invalidState }
        try active?.validate(); try pending?.validate()
        guard active != nil || pending != nil || (!desiredEnabled && phase == .off),
              challenge == nil || (phase == .needsCredential && challenge?.generation == generation),
              phase != .needsCredential || challenge != nil,
              phase != .off || !desiredEnabled
        else { throw VPNTunnelStateStoreError.invalidState }
        let interrupted = phase == .connecting || phase == .needsCredential
        guard !interrupted || generation < UInt64.max else {
            throw VPNTunnelStateStoreError.invalidState
        }
        return VPNTunnelSnapshot(schemaVersion: 2,
            generation: interrupted ? generation + 1 : generation,
            desiredEnabled: desiredEnabled,
            phase: interrupted ? .failed : VPNTunnelPhase(rawValue: phase.rawValue)!,
            active: active, pending: pending, challenge: nil)
    }
}

/// Durable, root-private intent and transaction state. It never stores secrets
/// and has no `connected` phase until a future engine/route/DNS coordinator can
/// prove that state. Active and pending configurations are retained separately.
final class VPNTunnelStateStore {
    static let name = "tunnel-state.json"
    private static let maximumBytes = 512 * 1024
    private var directory: Int32
    private let owner = geteuid()

    init(trustedDirectoryDescriptor: Int32) throws {
        directory = fcntl(trustedDirectoryDescriptor, F_DUPFD_CLOEXEC, 0)
        guard directory >= 0 else { throw VPNTunnelStateStoreError.unsafeStorage }
        do { try checkDirectory() }
        catch { close(directory); directory = -1; throw error }
    }

    deinit { if directory >= 0 { close(directory) } }

    func load() throws -> VPNTunnelSnapshot {
        try checkDirectory()
        guard let data = try read() else {
            return VPNTunnelSnapshot(schemaVersion: 2, generation: 0, desiredEnabled: false,
                                     phase: .off, active: nil, pending: nil, challenge: nil)
        }
        do {
            let value = try JSONDecoder().decode(VPNTunnelSnapshot.self, from: data)
            try value.validate()
            guard try value.encoded() == data else { throw VPNTunnelStateStoreError.invalidState }
            return value
        } catch {
            do {
                let legacy = try JSONDecoder().decode(VPNLegacyTunnelSnapshot.self, from: data)
                guard try legacy.encoded() == data else { throw VPNTunnelStateStoreError.invalidState }
                let migrated = try legacy.migrate()
                try write(migrated)
                return migrated
            } catch { throw VPNTunnelStateStoreError.invalidState }
        }
    }

    @discardableResult
    func stage(_ application: VPNValidatedApplication) throws -> VPNTunnelSnapshot {
        try application.validate()
        let old = try load()
        guard old.phase != .connecting, old.phase != .needsCredential,
              old.phase != .authenticating else { throw VPNTunnelStateStoreError.invalidState }
        if old.pending == application || old.active == application { return old }
        let latest = max(old.active?.spec.revision ?? 0, old.pending?.spec.revision ?? 0)
        guard application.spec.revision > latest else { throw VPNTunnelStateStoreError.stale }
        let next = VPNTunnelSnapshot(schemaVersion: 2, generation: old.generation,
            desiredEnabled: false, phase: .pending, active: old.active,
            pending: application, challenge: nil)
        try write(next); return next
    }

    /// Future tunnel code may call this only after engine, route and DNS proof.
    /// Stage A deliberately exposes no IPC operation which can reach it.
    @discardableResult
    func acknowledgeApplied(revision: UInt64) throws -> VPNTunnelSnapshot {
        let old = try load()
        guard let pending = old.pending, pending.spec.revision == revision else {
            throw VPNTunnelStateStoreError.stale
        }
        let next = VPNTunnelSnapshot(schemaVersion: 2, generation: old.generation,
            desiredEnabled: old.desiredEnabled, phase: old.desiredEnabled ? .connecting : .off,
            active: pending, pending: nil, challenge: nil,
            attempt: old.desiredEnabled
                ? VPNConnectAttemptBinding(generation: old.generation, application: pending) : nil,
            issuedCredentialKinds: old.desiredEnabled ? old.issuedCredentialKinds : [])
        try write(next); return next
    }

    /// Starts one exact attempt. The selected application is copied into the
    /// durable binding so later staging cannot change what the engine may use.
    @discardableResult
    func beginConnect() throws -> VPNConnectAttemptBinding {
        let old = try load()
        guard let application = old.pending ?? old.active,
              old.phase != .connecting, old.phase != .needsCredential,
              old.phase != .authenticating, old.generation < UInt64.max else {
            throw VPNTunnelStateStoreError.invalidState
        }
        let generation = old.generation + 1
        let binding = VPNConnectAttemptBinding(generation: generation, application: application)
        let next = VPNTunnelSnapshot(schemaVersion: 2, generation: generation,
            desiredEnabled: true, phase: .connecting,
            active: old.active, pending: old.pending, challenge: nil, attempt: binding)
        try write(next); return binding
    }

    /// Promotes the exact pending application selected by this attempt before
    /// route installation. This is configuration activation only: the phase
    /// remains `connecting` and it is never a public Connected proof.
    @discardableResult
    func activateForRouting(_ binding: VPNConnectAttemptBinding) throws
        -> VPNValidatedApplication {
        try binding.validate()
        let old = try load()
        guard old.desiredEnabled, old.phase == .connecting,
              old.attempt == binding, old.generation == binding.generation else {
            throw VPNTunnelStateStoreError.stale
        }
        if old.pending == nil {
            guard old.active == binding.application else {
                throw VPNTunnelStateStoreError.stale
            }
            return binding.application
        }
        guard old.pending == binding.application else {
            throw VPNTunnelStateStoreError.stale
        }
        let next = VPNTunnelSnapshot(schemaVersion: 2, generation: old.generation,
            desiredEnabled: true, phase: .connecting, active: binding.application,
            pending: nil, challenge: nil, attempt: binding,
            issuedCredentialKinds: old.issuedCredentialKinds)
        try write(next)
        return binding.application
    }

    /// Issues each credential kind at most once for this exact attempt.
    @discardableResult
    func issueChallenge(binding: VPNConnectAttemptBinding,
                        kind: VPNCredentialKind) throws -> VPNCredentialChallenge {
        let old = try load()
        guard old.phase == .connecting, old.attempt == binding,
              !old.issuedCredentialKinds.contains(kind),
              (kind == .privateKeyPassword && binding.application.requiresPrivateKeyPassword)
                || (kind == .vpnPassword && binding.application.requiresVPNCredentials)
        else { throw VPNTunnelStateStoreError.stale }
        let challenge = VPNCredentialChallenge(generation: binding.generation, kind: kind)
        let next = VPNTunnelSnapshot(schemaVersion: 2, generation: old.generation,
            desiredEnabled: true, phase: .needsCredential, active: old.active,
            pending: old.pending, challenge: challenge, attempt: binding,
            issuedCredentialKinds: old.issuedCredentialKinds + [kind])
        try write(next); return challenge
    }

    /// Burns the exact UUID/generation/kind before any transient secret is
    /// inspected and returns the immutable application binding to the caller.
    @discardableResult
    func claimCredential(_ challenge: VPNCredentialChallenge) throws
        -> VPNConnectAttemptBinding {
        let old = try load()
        guard old.phase == .needsCredential, old.challenge == challenge,
              let binding = old.attempt,
              challenge.generation == binding.generation,
              old.issuedCredentialKinds.contains(challenge.kind)
        else { throw VPNTunnelStateStoreError.stale }
        let next = VPNTunnelSnapshot(schemaVersion: 2, generation: old.generation,
            desiredEnabled: true, phase: .authenticating, active: old.active,
            pending: old.pending, challenge: nil, attempt: binding,
            issuedCredentialKinds: old.issuedCredentialKinds)
        try write(next); return binding
    }

    /// Called only after the engine accepted or completed the current prompt.
    /// Another required, not-yet-issued kind may then be requested.
    @discardableResult
    func completeCredentialPrompt(binding: VPNConnectAttemptBinding) throws
        -> VPNTunnelSnapshot {
        let old = try load()
        guard old.phase == .authenticating, old.attempt == binding else {
            throw VPNTunnelStateStoreError.stale
        }
        let next = VPNTunnelSnapshot(schemaVersion: 2, generation: old.generation,
            desiredEnabled: true, phase: .connecting, active: old.active,
            pending: old.pending, challenge: nil, attempt: binding,
            issuedCredentialKinds: old.issuedCredentialKinds)
        try write(next); return next
    }

    /// Compatibility shim for the existing listener until it adopts the
    /// explicit prompt callbacks. It still uses the durable one-shot machine.
    @discardableResult
    func beginConnect(challengeKind: VPNCredentialKind?) throws -> VPNTunnelSnapshot {
        let binding = try beginConnect()
        if let kind = challengeKind { _ = try issueChallenge(binding: binding, kind: kind) }
        return try load()
    }

    @discardableResult
    func consume(_ challenge: VPNCredentialChallenge) throws -> VPNTunnelSnapshot {
        _ = try claimCredential(challenge)
        // The legacy listener has no engine-prompt completion callback yet.
        // Preserve its fail-closed behavior instead of leaving a credential in
        // an apparently usable authenticating state.
        return try failCurrent()
    }

    @discardableResult
    func cancel(_ challenge: VPNCredentialChallenge) throws -> VPNTunnelSnapshot {
        let old = try load()
        guard old.challenge == challenge, old.generation < UInt64.max else {
            throw VPNTunnelStateStoreError.stale
        }
        let next = VPNTunnelSnapshot(schemaVersion: 2, generation: old.generation + 1,
            desiredEnabled: false, phase: .off, active: old.active, pending: old.pending,
            challenge: nil)
        try write(next); return next
    }

    @discardableResult
    func cancelAttempt(_ binding: VPNConnectAttemptBinding) throws -> VPNTunnelSnapshot {
        let old = try load()
        guard old.attempt == binding, old.generation < UInt64.max else {
            throw VPNTunnelStateStoreError.stale
        }
        let next = VPNTunnelSnapshot(schemaVersion: 2, generation: old.generation + 1,
            desiredEnabled: false, phase: .off, active: old.active, pending: old.pending,
            challenge: nil)
        try write(next); return next
    }

    /// A challenge belongs to one daemon lifetime. A restart advances the
    /// generation before accepting owner commands, so a captured late response
    /// cannot cross a crash/relaunch boundary.
    @discardableResult
    func recoverInterruptedAttemptAfterRestart() throws -> VPNTunnelSnapshot {
        let old = try load()
        guard old.phase == .connecting || old.phase == .needsCredential
                || old.phase == .authenticating else { return old }
        guard old.generation < UInt64.max else { throw VPNTunnelStateStoreError.invalidState }
        let next = VPNTunnelSnapshot(schemaVersion: 2, generation: old.generation + 1,
            desiredEnabled: old.desiredEnabled, phase: .failed, active: old.active,
            pending: old.pending, challenge: nil)
        try write(next); return next
    }

    @discardableResult
    func invalidateChallengeAfterRestart() throws -> VPNTunnelSnapshot {
        try recoverInterruptedAttemptAfterRestart()
    }

    @discardableResult
    func failCurrent() throws -> VPNTunnelSnapshot {
        let old = try load()
        guard old.desiredEnabled else { throw VPNTunnelStateStoreError.stale }
        let next = VPNTunnelSnapshot(schemaVersion: 2, generation: old.generation,
            desiredEnabled: true, phase: .failed, active: old.active, pending: old.pending,
            challenge: nil)
        try write(next); return next
    }

    @discardableResult
    func disconnect() throws -> VPNTunnelSnapshot {
        let old = try load()
        guard old.generation < UInt64.max else { throw VPNTunnelStateStoreError.invalidState }
        let next = VPNTunnelSnapshot(schemaVersion: 2, generation: old.generation + 1,
            desiredEnabled: false, phase: .off,
            active: old.active, pending: old.pending, challenge: nil)
        try write(next); return next
    }

    private func read() throws -> Data? {
        let file = openat(directory, Self.name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard file >= 0 else {
            guard errno == ENOENT else { throw VPNTunnelStateStoreError.unsafeStorage }
            return nil
        }
        defer { close(file) }
        try checkFile(file)
        var data = Data(), buffer = [UInt8](repeating: 0, count: 4096)
        while true {
            let count = Darwin.read(file, &buffer, buffer.count)
            if count < 0, errno == EINTR { continue }
            guard count >= 0 else { throw VPNTunnelStateStoreError.invalidState }
            if count == 0 { return data }
            guard data.count + count <= Self.maximumBytes else { throw VPNTunnelStateStoreError.invalidState }
            data.append(contentsOf: buffer.prefix(count))
        }
    }

    private func write(_ value: VPNTunnelSnapshot) throws {
        let data = try value.encoded()
        guard data.count <= Self.maximumBytes else { throw VPNTunnelStateStoreError.invalidState }
        let temporary = ".tunnel-state-\(UUID().uuidString).tmp"
        let file = openat(directory, temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard file >= 0 else { throw VPNTunnelStateStoreError.writeFailed }
        defer { close(file); unlinkat(directory, temporary, 0) }
        try checkFile(file)
        try data.withUnsafeBytes { bytes in
            var offset = 0
            while offset < bytes.count {
                let count = Darwin.write(file, bytes.baseAddress!.advanced(by: offset), bytes.count - offset)
                if count < 0, errno == EINTR { continue }
                guard count > 0 else { throw VPNTunnelStateStoreError.writeFailed }
                offset += count
            }
        }
        guard fsync(file) == 0, renameat(directory, temporary, directory, Self.name) == 0,
              fsync(directory) == 0 else { throw VPNTunnelStateStoreError.writeFailed }
    }

    private func checkDirectory() throws {
        var info = stat()
        guard geteuid() == owner, fstat(directory, &info) == 0,
              info.st_mode & S_IFMT == S_IFDIR, info.st_nlink > 0,
              info.st_uid == owner, info.st_mode & 0o7777 == 0o700 else {
            throw VPNTunnelStateStoreError.unsafeStorage
        }
    }

    private func checkFile(_ file: Int32) throws {
        var info = stat()
        guard fstat(file, &info) == 0, info.st_mode & S_IFMT == S_IFREG,
              info.st_nlink == 1, info.st_uid == owner, info.st_mode & 0o7777 == 0o600 else {
            throw VPNTunnelStateStoreError.unsafeStorage
        }
    }
}
