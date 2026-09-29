import Darwin
import Foundation

enum VPNTunnelStateStoreError: Error { case unsafeStorage, invalidState, stale, writeFailed }

enum VPNTunnelPhase: String, Codable {
    case off, pending, connecting, needsCredential, failed
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

struct VPNTunnelSnapshot: Codable, Equatable {
    let schemaVersion: Int
    let generation: UInt64
    let desiredEnabled: Bool
    let phase: VPNTunnelPhase
    let active: VPNValidatedApplication?
    let pending: VPNValidatedApplication?
    let challenge: VPNCredentialChallenge?

    func validate() throws {
        guard schemaVersion == 1 else { throw VPNTunnelStateStoreError.invalidState }
        try active?.validate(); try pending?.validate()
        guard active != nil || pending != nil || (!desiredEnabled && phase == .off),
              challenge == nil || (phase == .needsCredential && challenge?.generation == generation),
              phase != .needsCredential || challenge != nil,
              phase != .off || !desiredEnabled
        else { throw VPNTunnelStateStoreError.invalidState }
    }

    func encoded() throws -> Data {
        try validate()
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
        return try encoder.encode(self)
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
            return VPNTunnelSnapshot(schemaVersion: 1, generation: 0, desiredEnabled: false,
                                     phase: .off, active: nil, pending: nil, challenge: nil)
        }
        do {
            let value = try JSONDecoder().decode(VPNTunnelSnapshot.self, from: data)
            try value.validate()
            guard try value.encoded() == data else { throw VPNTunnelStateStoreError.invalidState }
            return value
        } catch { throw VPNTunnelStateStoreError.invalidState }
    }

    @discardableResult
    func stage(_ application: VPNValidatedApplication) throws -> VPNTunnelSnapshot {
        try application.validate()
        let old = try load()
        if old.pending == application || old.active == application { return old }
        let latest = max(old.active?.spec.revision ?? 0, old.pending?.spec.revision ?? 0)
        guard application.spec.revision > latest else { throw VPNTunnelStateStoreError.stale }
        let next = VPNTunnelSnapshot(schemaVersion: 1, generation: old.generation,
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
        let next = VPNTunnelSnapshot(schemaVersion: 1, generation: old.generation,
            desiredEnabled: old.desiredEnabled, phase: old.desiredEnabled ? .connecting : .off,
            active: pending, pending: nil, challenge: nil)
        try write(next); return next
    }

    @discardableResult
    func beginConnect(challengeKind: VPNCredentialKind?) throws -> VPNTunnelSnapshot {
        let old = try load()
        guard old.pending != nil || old.active != nil, old.generation < UInt64.max else {
            throw VPNTunnelStateStoreError.invalidState
        }
        let generation = old.generation + 1
        let challenge = challengeKind.map { VPNCredentialChallenge(generation: generation, kind: $0) }
        let next = VPNTunnelSnapshot(schemaVersion: 1, generation: generation,
            desiredEnabled: true, phase: challenge == nil ? .connecting : .needsCredential,
            active: old.active, pending: old.pending, challenge: challenge)
        try write(next); return next
    }

    /// Invalidates the challenge before a transient secret can be used.
    @discardableResult
    func consume(_ challenge: VPNCredentialChallenge) throws -> VPNTunnelSnapshot {
        let old = try load()
        guard old.challenge == challenge else { throw VPNTunnelStateStoreError.stale }
        let next = VPNTunnelSnapshot(schemaVersion: 1, generation: old.generation,
            desiredEnabled: true, phase: .failed, active: old.active, pending: old.pending,
            challenge: nil)
        try write(next); return next
    }

    @discardableResult
    func cancel(_ challenge: VPNCredentialChallenge) throws -> VPNTunnelSnapshot {
        let old = try load()
        guard old.challenge == challenge, old.generation < UInt64.max else {
            throw VPNTunnelStateStoreError.stale
        }
        let next = VPNTunnelSnapshot(schemaVersion: 1, generation: old.generation + 1,
            desiredEnabled: false, phase: .off, active: old.active, pending: old.pending,
            challenge: nil)
        try write(next); return next
    }

    /// A challenge belongs to one daemon lifetime. A restart advances the
    /// generation before accepting owner commands, so a captured late response
    /// cannot cross a crash/relaunch boundary.
    @discardableResult
    func invalidateChallengeAfterRestart() throws -> VPNTunnelSnapshot {
        let old = try load()
        guard old.challenge != nil else { return old }
        guard old.generation < UInt64.max else { throw VPNTunnelStateStoreError.invalidState }
        let next = VPNTunnelSnapshot(schemaVersion: 1, generation: old.generation + 1,
            desiredEnabled: old.desiredEnabled, phase: .failed, active: old.active,
            pending: old.pending, challenge: nil)
        try write(next); return next
    }

    @discardableResult
    func failCurrent() throws -> VPNTunnelSnapshot {
        let old = try load()
        guard old.desiredEnabled else { throw VPNTunnelStateStoreError.stale }
        let next = VPNTunnelSnapshot(schemaVersion: 1, generation: old.generation,
            desiredEnabled: true, phase: .failed, active: old.active, pending: old.pending,
            challenge: nil)
        try write(next); return next
    }

    @discardableResult
    func disconnect() throws -> VPNTunnelSnapshot {
        let old = try load()
        guard old.generation < UInt64.max else { throw VPNTunnelStateStoreError.invalidState }
        let next = VPNTunnelSnapshot(schemaVersion: 1, generation: old.generation + 1,
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
