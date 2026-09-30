import Foundation
import Darwin

struct VPNSnapshot: Codable, Equatable, CustomDebugStringConvertible {
    let configuration: VPNConfiguration
    let profileContents: Data?
    let suggestedDNS: [String]
    let suggestedResources: [VPNResource]
    let hasIgnoredProfileRoutes: Bool
    var debugDescription: String { "VPNSnapshot(revision: \(configuration.revision), contents: redacted)" }

    func inspectProfile() throws -> VPNImportedProfile? {
        guard let name = configuration.profileName else {
            guard profileContents == nil else { throw VPNValidationError.invalidConfiguration }
            return nil
        }
        guard let contents = profileContents else { throw VPNValidationError.invalidConfiguration }
        return try VPNProfileImporter.inspect(data: contents, name: name)
    }

    fileprivate func validate() throws {
        try configuration.validate()
        let profile = try inspectProfile()
        var dnsCheck = VPNConfiguration()
        try dnsCheck.setDNS(suggestedDNS)
        for resource in suggestedResources { try resource.validate() }
        guard dnsCheck.corporateDNS == suggestedDNS,
              suggestedResources.count <= 1000,
              Set(suggestedResources.map { $0.address }).count == suggestedResources.count,
              Set(suggestedResources.map { $0.id }).count == suggestedResources.count,
              suggestedResources.allSatisfy({ $0.kind != .domain }),
              configuration.profileName != nil || (suggestedDNS.isEmpty && suggestedResources.isEmpty && !hasIgnoredProfileRoutes),
              (profile?.supports(authentication: configuration.authentication) ?? (configuration.authentication == nil))
        else { throw VPNValidationError.invalidConfiguration }
    }
}

struct VPNStoredState: Codable, Equatable {
    let schemaVersion: Int
    let saved: VPNSnapshot
    let applied: VPNSnapshot?
    var hasPendingChanges: Bool { applied?.configuration.revision != saved.configuration.revision }

    fileprivate func validate() throws {
        guard schemaVersion == 1 else { throw VPNValidationError.invalidConfiguration }
        try saved.validate()
        if let applied = applied {
            try applied.validate()
            guard applied.configuration.desiredEnabled, applied.configuration.revision <= saved.configuration.revision,
                  saved.configuration.profileName != nil,
                  applied.configuration.revision != saved.configuration.revision || applied == saved
            else { throw VPNValidationError.invalidConfiguration }
        }
    }
}

/// Unprivileged user storage, never a trusted input to a root helper.
/// No default live path: previews/tests must explicitly supply an isolated folder.
/// Profile bytes (including inline keys) stay in a 0600 file inside a 0700 folder;
/// passwords are not part of this schema. Root operations must revalidate separately.
final class VPNStore {
    let directory: URL
    private let filename = "state.json"
    private let maximumBytes = 8 * 1_048_576

    init(directory: URL) { self.directory = directory }

    func load() throws -> VPNStoredState? {
        var attributes = stat()
        if lstat(directory.path, &attributes) != 0 {
            if errno == ENOENT { return nil }
            throw VPNValidationError.storageUnavailable
        }
        return try withLock(create: false) { try readState(directory: $0) }
    }

    /// Explicit expected revision prevents two editors from overwriting each other.
    /// Replacement import and settings commit atomically; applied settings survive.
    @discardableResult
    func save(_ configuration: VPNConfiguration, importing profile: VPNImportedProfile? = nil,
              expectedRevision: UInt64?) throws -> VPNStoredState {
        try configuration.validate()
        return try withLock(create: true) { descriptor in
            let previous = try readState(directory: descriptor)
            guard previous?.saved.configuration.revision == expectedRevision,
                  configuration.revision > (expectedRevision ?? 0) else { throw VPNValidationError.staleRevision }
            let contents: Data?
            if let profile = profile {
                guard profile.name == configuration.profileName else { throw VPNValidationError.invalidConfiguration }
                // Do not carry login/persistence consent to different profile
                // bytes through a direct store call, even with the same name.
                // Import the replacement with a cleared selection first.
                if let oldContents = previous?.saved.profileContents,
                   oldContents != profile.protectedContents,
                   configuration.authentication != nil {
                    throw VPNValidationError.invalidConfiguration
                }
                contents = profile.protectedContents
            } else if configuration.profileName != nil {
                guard previous?.saved.configuration.profileName == configuration.profileName else { throw VPNValidationError.missingProfile }
                contents = previous?.saved.profileContents
            } else { contents = nil }
            let keepsProfile = configuration.profileName != nil
            let snapshot = VPNSnapshot(configuration: configuration, profileContents: contents,
                                       suggestedDNS: keepsProfile ? (profile?.suggestedDNS ?? previous?.saved.suggestedDNS ?? []) : [],
                                       suggestedResources: keepsProfile ? (profile?.suggestedResources ?? previous?.saved.suggestedResources ?? []) : [],
                                       hasIgnoredProfileRoutes: keepsProfile ? (profile?.hasIgnoredRoutes ?? previous?.saved.hasIgnoredProfileRoutes ?? false) : false)
            let next = VPNStoredState(schemaVersion: 1, saved: snapshot, applied: previous?.applied)
            try next.validate()
            try writeState(next, directory: descriptor)
            return next
        }
    }

    /// Only a future controller's verified tunnel/route/DNS acknowledgement may
    /// call this. Saving settings or finding an OpenVPN process is not sufficient.
    func acknowledgeApplied(revision: UInt64) throws {
        try withLock(create: false) { descriptor in
            guard let current = try readState(directory: descriptor),
                  current.saved.configuration.revision == revision,
                  current.saved.configuration.desiredEnabled else { throw VPNValidationError.staleRevision }
            try writeState(VPNStoredState(schemaVersion: 1, saved: current.saved, applied: current.saved), directory: descriptor)
        }
    }

    /// Retain the applied snapshot until all owned network state is cleaned up.
    func acknowledgeStopped(revision: UInt64) throws {
        try withLock(create: false) { descriptor in
            guard let current = try readState(directory: descriptor) else { return }
            guard current.applied == nil || current.applied?.configuration.revision == revision
            else { throw VPNValidationError.staleRevision }
            try writeState(VPNStoredState(schemaVersion: 1, saved: current.saved, applied: nil), directory: descriptor)
        }
    }

    private func withLock<T>(create: Bool, _ operation: (Int32) throws -> T) throws -> T {
        let path = directory.standardizedFileURL.path
        guard directory.isFileURL, path != "/", path != NSHomeDirectory() else { throw VPNValidationError.storageUnavailable }
        if create {
            do { try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700]) }
            catch { throw VPNValidationError.storageUnavailable }
        }
        let descriptor = open(directory.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else { throw VPNValidationError.storageUnavailable }
        defer { close(descriptor) }
        var attributes = stat()
        guard fstat(descriptor, &attributes) == 0, attributes.st_uid == geteuid(), attributes.st_mode & 0o777 == 0o700
        else { throw VPNValidationError.storageUnavailable }
        let lock = openat(descriptor, "state.lock", O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK, 0o600)
        guard lock >= 0 else { throw VPNValidationError.storageUnavailable }
        defer { close(lock) }
        try checkPrivateFile(lock)
        guard flock(lock, LOCK_EX | LOCK_NB) == 0 else { throw VPNValidationError.storageUnavailable }
        defer { flock(lock, LOCK_UN) }
        return try operation(descriptor)
    }

    private func checkPrivateFile(_ descriptor: Int32) throws {
        var attributes = stat()
        guard fstat(descriptor, &attributes) == 0, attributes.st_mode & S_IFMT == S_IFREG,
              attributes.st_uid == geteuid(), attributes.st_nlink == 1, attributes.st_mode & 0o777 == 0o600
        else { throw VPNValidationError.storageUnavailable }
    }

    private func readState(directory: Int32) throws -> VPNStoredState? {
        let file = openat(directory, filename, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard file >= 0 else {
            if errno == ENOENT { return nil }
            throw VPNValidationError.storageUnavailable
        }
        defer { close(file) }
        try checkPrivateFile(file)
        var data = Data(), buffer = [UInt8](repeating: 0, count: 16384)
        while true {
            let count = read(file, &buffer, buffer.count)
            if count < 0 { if errno == EINTR { continue }; throw VPNValidationError.storageUnavailable }
            if count == 0 { break }
            guard data.count + count <= maximumBytes else { throw VPNValidationError.invalidConfiguration }
            data.append(contentsOf: buffer.prefix(count))
        }
        do {
            let stored = try JSONDecoder().decode(VPNStoredState.self, from: data)
            try stored.validate()
            return stored
        } catch { throw VPNValidationError.invalidConfiguration }
    }

    private func writeState(_ state: VPNStoredState, directory: Int32) throws {
        let data: Data
        do { data = try JSONEncoder().encode(state) } catch { throw VPNValidationError.storageUnavailable }
        guard data.count <= maximumBytes else { throw VPNValidationError.storageUnavailable }
        let temporary = ".state-\(UUID().uuidString).tmp"
        let file = openat(directory, temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard file >= 0 else { throw VPNValidationError.storageUnavailable }
        defer { close(file); unlinkat(directory, temporary, 0) }
        try checkPrivateFile(file)
        try data.withUnsafeBytes { bytes in
            var offset = 0
            while offset < bytes.count {
                let count = write(file, bytes.baseAddress!.advanced(by: offset), bytes.count - offset)
                if count < 0, errno == EINTR { continue }
                guard count > 0 else { throw VPNValidationError.storageUnavailable }
                offset += count
            }
        }
        guard fsync(file) == 0, renameat(directory, temporary, directory, filename) == 0 else { throw VPNValidationError.storageUnavailable }
        // Commit already happened: a directory fsync failure must not be reported
        // as an unchanged configuration. Atomic replacement is the save boundary.
        _ = fsync(directory)
    }
}
