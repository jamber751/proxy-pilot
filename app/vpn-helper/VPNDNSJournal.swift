import Darwin
import Foundation

enum VPNDNSJournalError: Error, Equatable {
    case unsafeStorage, missing, alreadyExists, invalidState, stale, writeFailed, removeFailed
}

enum VPNDNSJournalPhase: String, Codable { case planned, installing, applied, removing, retired }
enum VPNDNSJournalAction: String, Codable { case install, remove }

struct VPNDNSJournalOperation: Codable, Equatable {
    let action: VPNDNSJournalAction
    let scope: VPNDNSResolverScope
}

/// Durable ownership intent only. A future scoped-resolver adapter must verify
/// its exact observed state before resolving either checkpoint.
struct VPNDNSJournalSnapshot: Codable, Equatable {
    static let schema = 1
    let schemaVersion: Int
    let plan: VPNDNSPlan
    let phase: VPNDNSJournalPhase
    let applied: [VPNDNSResolverScope]
    let operation: VPNDNSJournalOperation?

    func validate() throws {
        guard schemaVersion == Self.schema else { throw VPNDNSJournalError.invalidState }
        try plan.validate()
        guard applied == Array(plan.scopes.prefix(applied.count)) else {
            throw VPNDNSJournalError.invalidState
        }
        switch phase {
        case .planned:
            guard applied.isEmpty, operation == nil else { throw VPNDNSJournalError.invalidState }
        case .installing:
            guard applied.count < plan.scopes.count else { throw VPNDNSJournalError.invalidState }
            if let operation {
                guard operation.action == .install,
                      operation.scope == plan.scopes[applied.count] else {
                    throw VPNDNSJournalError.invalidState
                }
            }
        case .applied:
            guard applied == plan.scopes, operation == nil else {
                throw VPNDNSJournalError.invalidState
            }
        case .removing:
            guard !applied.isEmpty else { throw VPNDNSJournalError.invalidState }
            if let operation {
                guard operation.action == .remove, operation.scope == applied.last else {
                    throw VPNDNSJournalError.invalidState
                }
            }
        case .retired:
            guard applied.isEmpty, operation == nil else { throw VPNDNSJournalError.invalidState }
        }
    }
}

final class VPNDNSJournal {
    static let name = "dns-journal.json"
    static let maximumBytes = 1024 * 1024
    private var directory: Int32
    private let owner = geteuid()

    init(trustedDirectoryDescriptor: Int32) throws {
        directory = fcntl(trustedDirectoryDescriptor, F_DUPFD_CLOEXEC, 64)
        guard directory >= 0 else { throw VPNDNSJournalError.unsafeStorage }
        do { try checkDirectory() }
        catch { close(directory); directory = -1; throw error }
    }

    deinit { if directory >= 0 { close(directory) } }

    func load() throws -> VPNDNSJournalSnapshot {
        guard let data = try read() else { throw VPNDNSJournalError.missing }
        return try decode(data)
    }

    @discardableResult
    func create(_ plan: VPNDNSPlan) throws -> VPNDNSJournalSnapshot {
        try plan.validate()
        guard try read() == nil else { throw VPNDNSJournalError.alreadyExists }
        let value = VPNDNSJournalSnapshot(schemaVersion: VPNDNSJournalSnapshot.schema,
            plan: plan, phase: .planned, applied: [], operation: nil)
        try write(value)
        return value
    }

    @discardableResult
    func beginInstall(_ scope: VPNDNSResolverScope, generation: UInt64,
                      revision: UInt64) throws -> VPNDNSJournalSnapshot {
        let old = try bound(generation: generation, revision: revision)
        guard [.planned, .installing].contains(old.phase), old.operation == nil,
              old.applied.count < old.plan.scopes.count,
              old.plan.scopes[old.applied.count] == scope else {
            throw VPNDNSJournalError.invalidState
        }
        let next = VPNDNSJournalSnapshot(schemaVersion: VPNDNSJournalSnapshot.schema,
            plan: old.plan, phase: .installing, applied: old.applied,
            operation: VPNDNSJournalOperation(action: .install, scope: scope))
        try write(next)
        return next
    }

    @discardableResult
    func resolveInstall(_ scope: VPNDNSResolverScope, present: Bool,
                        generation: UInt64, revision: UInt64) throws -> VPNDNSJournalSnapshot {
        let old = try bound(generation: generation, revision: revision)
        guard old.phase == .installing,
              old.operation == VPNDNSJournalOperation(action: .install, scope: scope) else {
            throw VPNDNSJournalError.stale
        }
        var applied = old.applied
        if present { applied.append(scope) }
        let phase: VPNDNSJournalPhase = applied == old.plan.scopes ? .applied : .installing
        let next = VPNDNSJournalSnapshot(schemaVersion: VPNDNSJournalSnapshot.schema,
            plan: old.plan, phase: phase, applied: applied, operation: nil)
        try write(next)
        return next
    }

    @discardableResult
    func abandonUnapplied(generation: UInt64, revision: UInt64) throws
        -> VPNDNSJournalSnapshot {
        let old = try bound(generation: generation, revision: revision)
        guard [.planned, .installing].contains(old.phase), old.applied.isEmpty,
              old.operation == nil else { throw VPNDNSJournalError.invalidState }
        let next = VPNDNSJournalSnapshot(schemaVersion: VPNDNSJournalSnapshot.schema,
            plan: old.plan, phase: .retired, applied: [], operation: nil)
        try write(next)
        return next
    }

    @discardableResult
    func beginRemove(_ scope: VPNDNSResolverScope, generation: UInt64,
                     revision: UInt64) throws -> VPNDNSJournalSnapshot {
        let old = try bound(generation: generation, revision: revision)
        guard [.installing, .applied, .removing].contains(old.phase), old.operation == nil,
              old.applied.last == scope else { throw VPNDNSJournalError.invalidState }
        let next = VPNDNSJournalSnapshot(schemaVersion: VPNDNSJournalSnapshot.schema,
            plan: old.plan, phase: .removing, applied: old.applied,
            operation: VPNDNSJournalOperation(action: .remove, scope: scope))
        try write(next)
        return next
    }

    @discardableResult
    func resolveRemove(_ scope: VPNDNSResolverScope, present: Bool,
                       generation: UInt64, revision: UInt64) throws -> VPNDNSJournalSnapshot {
        let old = try bound(generation: generation, revision: revision)
        guard old.phase == .removing,
              old.operation == VPNDNSJournalOperation(action: .remove, scope: scope) else {
            throw VPNDNSJournalError.stale
        }
        var applied = old.applied
        if !present { applied.removeLast() }
        let phase: VPNDNSJournalPhase = applied.isEmpty ? .retired : .removing
        let next = VPNDNSJournalSnapshot(schemaVersion: VPNDNSJournalSnapshot.schema,
            plan: old.plan, phase: phase, applied: applied, operation: nil)
        try write(next)
        return next
    }

    func retireAndRemove(generation: UInt64, revision: UInt64) throws {
        let expected = try bound(generation: generation, revision: revision)
        guard expected.phase == .retired, expected.applied.isEmpty,
              expected.operation == nil else { throw VPNDNSJournalError.invalidState }
        let file = openat(directory, Self.name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard file >= 0 else { throw VPNDNSJournalError.removeFailed }
        defer { close(file) }
        try checkFile(file)
        var named = stat(), opened = stat()
        guard fstat(file, &opened) == 0,
              fstatat(directory, Self.name, &named, AT_SYMLINK_NOFOLLOW) == 0,
              named.st_dev == opened.st_dev, named.st_ino == opened.st_ino,
              lseek(file, 0, SEEK_SET) == 0,
              try decode(readFile(file)) == expected,
              unlinkat(directory, Self.name, 0) == 0,
              fsync(directory) == 0 else { throw VPNDNSJournalError.removeFailed }
    }

    private func bound(generation: UInt64, revision: UInt64) throws -> VPNDNSJournalSnapshot {
        let value = try load()
        guard generation > 0, revision > 0,
              value.plan.generation == generation, value.plan.revision == revision else {
            throw VPNDNSJournalError.stale
        }
        return value
    }

    private func decode(_ data: Data) throws -> VPNDNSJournalSnapshot {
        guard !data.isEmpty, data.count <= Self.maximumBytes,
              let value = try? JSONDecoder().decode(VPNDNSJournalSnapshot.self, from: data) else {
            throw VPNDNSJournalError.invalidState
        }
        try value.validate()
        guard try encode(value) == data else { throw VPNDNSJournalError.invalidState }
        return value
    }

    private func encode(_ value: VPNDNSJournalSnapshot) throws -> Data {
        try value.validate()
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let data = try encoder.encode(value)
        guard data.count <= Self.maximumBytes else { throw VPNDNSJournalError.invalidState }
        return data
    }

    private func read() throws -> Data? {
        try checkDirectory()
        let file = openat(directory, Self.name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard file >= 0 else {
            guard errno == ENOENT else { throw VPNDNSJournalError.unsafeStorage }
            return nil
        }
        defer { close(file) }
        try checkFile(file)
        return try readFile(file)
    }

    private func readFile(_ file: Int32) throws -> Data {
        var data = Data(), buffer = [UInt8](repeating: 0, count: 4096)
        while true {
            let count = Darwin.read(file, &buffer, buffer.count)
            if count < 0, errno == EINTR { continue }
            guard count >= 0, data.count + max(0, count) <= Self.maximumBytes else {
                throw VPNDNSJournalError.invalidState
            }
            if count == 0 { return data }
            data.append(contentsOf: buffer.prefix(count))
        }
    }

    private func write(_ value: VPNDNSJournalSnapshot) throws {
        let data = try encode(value)
        let temporary = ".dns-journal-\(UUID().uuidString).tmp"
        let file = openat(directory, temporary,
            O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard file >= 0 else { throw VPNDNSJournalError.writeFailed }
        defer { close(file); unlinkat(directory, temporary, 0) }
        try checkFile(file)
        try data.withUnsafeBytes { bytes in
            var offset = 0
            while offset < bytes.count {
                let count = Darwin.write(file, bytes.baseAddress!.advanced(by: offset),
                                         bytes.count - offset)
                if count < 0, errno == EINTR { continue }
                guard count > 0 else { throw VPNDNSJournalError.writeFailed }
                offset += count
            }
        }
        guard fsync(file) == 0,
              renameat(directory, temporary, directory, Self.name) == 0,
              fsync(directory) == 0 else { throw VPNDNSJournalError.writeFailed }
    }

    private func checkDirectory() throws {
        var info = stat()
        guard directory >= 0, geteuid() == owner,
              fstat(directory, &info) == 0, info.st_mode & S_IFMT == S_IFDIR,
              info.st_uid == owner, info.st_nlink > 0,
              info.st_mode & 0o7777 == 0o700 else {
            throw VPNDNSJournalError.unsafeStorage
        }
    }

    private func checkFile(_ file: Int32) throws {
        var info = stat()
        guard fstat(file, &info) == 0, info.st_mode & S_IFMT == S_IFREG,
              info.st_uid == owner, info.st_nlink == 1,
              info.st_mode & 0o7777 == 0o600 else {
            throw VPNDNSJournalError.unsafeStorage
        }
    }
}
