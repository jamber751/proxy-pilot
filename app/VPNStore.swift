import Foundation
import Darwin
import CryptoKit

/// Non-secret item identity. Each explicit grant has a different UUID, even
/// when the same profile/login is re-authorized after revocation.
struct VPNPasswordReference: Codable, Equatable, CustomDebugStringConvertible {
    let itemID: UUID
    let profileSHA256: String
    let login: String
    var debugDescription: String { "VPNPasswordReference(redacted)" }

    fileprivate func validate() throws {
        guard profileSHA256.utf8.count == 64,
              profileSHA256.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }),
              try VPNAuthentication(mode: .password, login: login).login == login
        else { throw VPNValidationError.invalidConfiguration }
    }

    fileprivate func matches(_ snapshot: VPNSnapshot) -> Bool {
        guard let auth = snapshot.configuration.authentication,
              auth.mode == .password, auth.credentialPersistence == .keychain,
              auth.login == login, let contents = snapshot.profileContents else { return false }
        return Self.digest(contents) == profileSHA256
    }

    fileprivate static func digest(_ bytes: Data) -> String {
        SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined()
    }
}

/// Observed origin, not an immutable database UUID or proof of global absence.
struct VPNPasswordBackendLocator: Codable, Equatable, CustomStringConvertible, CustomDebugStringConvertible {
    enum Kind: String, Codable { case legacyKeychain }
    let kind: Kind
    let path: String
    /// Unsigned widening of UInt32(bitPattern: Darwin stat.st_dev).
    let device: UInt64
    let inode: UInt64
    let ownerUID: UInt32
    let birthSeconds: Int64
    let birthNanoseconds: UInt32
    var description: String { "VPNPasswordBackendLocator(redacted)" }
    var debugDescription: String { description }

    func validate() throws {
        let parts = path.split(separator: "/", omittingEmptySubsequences: false)
        guard path.utf8.count <= 1023, path.hasPrefix("/"), parts.count > 1,
              parts.dropFirst().allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." }),
              path.unicodeScalars.allSatisfy({ !CharacterSet.controlCharacters.contains($0) }),
              device <= UInt64(UInt32.max), inode > 0, ownerUID != UInt32.max,
              birthSeconds >= 0, birthNanoseconds < 1_000_000_000
        else { throw VPNValidationError.invalidConfiguration }
    }
}

struct VPNPasswordItemLocator: Codable, Equatable, CustomStringConvertible, CustomDebugStringConvertible {
    static let maximumPersistentReferenceBytes = 4096
    let persistentReference: Data
    let origin: VPNPasswordBackendLocator
    var description: String { "VPNPasswordItemLocator(redacted)" }
    var debugDescription: String { description }
    func validate() throws {
        guard !persistentReference.isEmpty,
              persistentReference.count <= Self.maximumPersistentReferenceBytes
        else { throw VPNValidationError.invalidConfiguration }
        try origin.validate()
    }
}

enum VPNPasswordWriteState: String, Codable { case notIssued, pending, settled, noItem }

struct VPNPasswordSlot: Codable, Equatable, CustomStringConvertible, CustomDebugStringConvertible {
    let reference: VPNPasswordReference
    var writeState: VPNPasswordWriteState
    var locator: VPNPasswordItemLocator? = nil
    var description: String { "VPNPasswordSlot(redacted)" }
    var debugDescription: String { description }
    fileprivate func validate() throws {
        try reference.validate()
        if writeState == .settled {
            guard let locator else { throw VPNValidationError.invalidConfiguration }
            try locator.validate()
        } else if locator != nil { throw VPNValidationError.invalidConfiguration }
    }
    fileprivate mutating func complete(_ outcome: VPNPasswordAddOutcome) throws {
        guard writeState == .pending else { throw VPNValidationError.staleRevision }
        switch outcome {
        case .added(let captured):
            try captured.validate(); locator = captured; writeState = .settled
        case .definitelyNoIO: writeState = .noItem
        case .indeterminate: throw VPNValidationError.staleRevision
        }
        try validate()
    }
}

/// Trusted authenticated completion only. definitelyNoIO proves mutation was
/// NEVER issued; generic API errors, lost acknowledgment and client death do not.
enum VPNPasswordAddOutcome: Equatable, CustomStringConvertible, CustomDebugStringConvertible {
    case added(VPNPasswordItemLocator), definitelyNoIO, indeterminate
    var description: String { "VPNPasswordAddOutcome(redacted)" }
    var debugDescription: String { description }
}

/// Only positive deletion of the exact verified item can acknowledge removal.
enum VPNPasswordDeleteOutcome: Equatable { case deleted, notFound, unavailable, indeterminate }

struct VPNPasswordLedger: Codable, Equatable {
    static let maximumPendingDeletions = 64
    var active: VPNPasswordSlot?
    var pendingDeletion: [VPNPasswordSlot]

    init(active: VPNPasswordSlot? = nil, pendingDeletion: [VPNPasswordSlot] = []) {
        self.active = active; self.pendingDeletion = pendingDeletion
    }

    fileprivate func validate(saved: VPNSnapshot) throws {
        guard pendingDeletion.count <= Self.maximumPendingDeletions,
              Set(pendingDeletion.map { $0.reference.itemID }).count == pendingDeletion.count,
              active.map({ value in !pendingDeletion.contains(where: { $0.reference.itemID == value.reference.itemID }) }) ?? true
        else { throw VPNValidationError.invalidConfiguration }
        for slot in pendingDeletion { try slot.validate() }
        if let active {
            try active.validate()
            guard active.reference.matches(saved) else { throw VPNValidationError.invalidConfiguration }
        }
    }

    fileprivate mutating func reconcile(saved: VPNSnapshot) throws {
        if let previous = active, !previous.reference.matches(saved) {
            if previous.writeState == .notIssued || previous.writeState == .noItem {
                active = nil
                try validate(saved: saved)
                return
            }
            guard pendingDeletion.count < Self.maximumPendingDeletions else {
                throw VPNValidationError.storageUnavailable
            }
            pendingDeletion.append(previous); active = nil
        }
        try validate(saved: saved)
    }
}

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
    let passwordLedger: VPNPasswordLedger
    var hasPendingChanges: Bool { applied?.configuration.revision != saved.configuration.revision }

    fileprivate func validate() throws {
        guard schemaVersion == 4 else { throw VPNValidationError.invalidConfiguration }
        try saved.validate()
        try passwordLedger.validate(saved: saved)
        if let applied = applied {
            try applied.validate()
            guard applied.configuration.desiredEnabled, applied.configuration.revision <= saved.configuration.revision,
                  saved.configuration.profileName != nil,
                  applied.configuration.revision != saved.configuration.revision || applied == saved
            else { throw VPNValidationError.invalidConfiguration }
        }
    }

    init(saved: VPNSnapshot, applied: VPNSnapshot?, passwordLedger: VPNPasswordLedger = VPNPasswordLedger()) {
        schemaVersion = 4; self.saved = saved; self.applied = applied; self.passwordLedger = passwordLedger
    }

    private enum CodingKeys: String, CodingKey { case schemaVersion, saved, applied, passwordLedger }
    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let version = try container.decode(Int.self, forKey: .schemaVersion)
        guard (1...4).contains(version) else { throw VPNValidationError.invalidConfiguration }
        saved = try container.decode(VPNSnapshot.self, forKey: .saved)
        applied = try container.decodeIfPresent(VPNSnapshot.self, forKey: .applied)
        if version == 1 {
            // No VPN password backend existed in schema1. Consent alone must
            // not invent a credential identity or search for a legacy secret.
            guard !container.contains(.passwordLedger) else { throw VPNValidationError.invalidConfiguration }
            passwordLedger = VPNPasswordLedger()
        } else if version == 2 {
            // Schema2 had no durable write-once status. Never infer that a
            // repeated/unfinished backend mutation cannot still create an item.
            let legacy = try container.decode(LegacyPasswordLedger.self, forKey: .passwordLedger)
            passwordLedger = VPNPasswordLedger(
                active: legacy.active.map { VPNPasswordSlot(reference: $0, writeState: .pending) },
                pendingDeletion: legacy.pendingDeletion.map { VPNPasswordSlot(reference: $0, writeState: .pending) })
        } else if version == 3 {
            let legacy = try container.decode(LegacySchema3Ledger.self, forKey: .passwordLedger)
            passwordLedger = VPNPasswordLedger(
                active: legacy.active.map { VPNPasswordSlot(reference: $0.reference, writeState: .pending) },
                pendingDeletion: legacy.pendingDeletion.map { VPNPasswordSlot(reference: $0.reference, writeState: .pending) })
        } else {
            passwordLedger = try container.decode(VPNPasswordLedger.self, forKey: .passwordLedger)
        }
        schemaVersion = 4
    }

    private struct LegacyPasswordLedger: Decodable {
        let active: VPNPasswordReference?
        let pendingDeletion: [VPNPasswordReference]
    }
    private struct LegacySchema3Ledger: Decodable {
        struct Slot: Decodable {
            enum State: String, Decodable { case notIssued, pending, settled }
            let reference: VPNPasswordReference
            let writeState: State
        }
        let active: Slot?
        let pendingDeletion: [Slot]
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
    #if VPN_PASSWORD_LEDGER_TESTING
    var testRejectNextPendingDirectorySync = false
    var testRejectNextWriteAfterRename = false
    #endif

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
            var ledger = previous?.passwordLedger ?? VPNPasswordLedger()
            try ledger.reconcile(saved: snapshot)
            let next = VPNStoredState(saved: snapshot, applied: previous?.applied, passwordLedger: ledger)
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
            try writeState(VPNStoredState(saved: current.saved, applied: current.saved,
                                          passwordLedger: current.passwordLedger), directory: descriptor)
        }
    }

    /// Retain the applied snapshot until all owned network state is cleaned up.
    func acknowledgeStopped(revision: UInt64) throws {
        try withLock(create: false) { descriptor in
            guard let current = try readState(directory: descriptor) else { return }
            guard current.applied == nil || current.applied?.configuration.revision == revision
            else { throw VPNValidationError.staleRevision }
            try writeState(VPNStoredState(saved: current.saved, applied: nil,
                                          passwordLedger: current.passwordLedger), directory: descriptor)
        }
    }

    /// Explicit save opt-in only. Does not store a password or claim it exists.
    /// A missing item always remains a manual-input fallback for a later adapter.
    func grantPasswordPersistence(expectedRevision: UInt64) throws -> VPNPasswordReference {
        try withLock(create: false) { descriptor in
            guard let current = try readState(directory: descriptor),
                  current.saved.configuration.revision == expectedRevision else { throw VPNValidationError.staleRevision }
            let snapshot = current.saved
            guard let auth = snapshot.configuration.authentication, auth.mode == .password,
                  auth.credentialPersistence == .keychain, let login = auth.login,
                  let contents = snapshot.profileContents else { throw VPNValidationError.invalidConfiguration }
            if let existing = current.passwordLedger.active {
                guard existing.writeState == .notIssued else { throw VPNValidationError.staleRevision }
                return existing.reference
            }
            let reference = VPNPasswordReference(itemID: UUID(), profileSHA256: VPNPasswordReference.digest(contents), login: login)
            var ledger = current.passwordLedger
            ledger.active = VPNPasswordSlot(reference: reference, writeState: .notIssued)
            let next = VPNStoredState(saved: snapshot, applied: current.applied, passwordLedger: ledger)
            try next.validate(); try writeState(next, directory: descriptor)
            return reference
        }
    }

    /// A new explicit confirmed save always uses a fresh item identity. The
    /// expected active reference prevents a stale editor replacing a newer grant
    /// even when configuration revision did not change between two grants.
    func createPasswordSaveGrant(expectedRevision: UInt64,
                                 expectedActive: VPNPasswordReference?) throws -> VPNPasswordReference {
        try withLock(create: false) { descriptor in
            guard let current = try readState(directory: descriptor),
                  current.saved.configuration.revision == expectedRevision,
                  current.passwordLedger.active?.reference == expectedActive else { throw VPNValidationError.staleRevision }
            let snapshot = current.saved
            guard let auth = snapshot.configuration.authentication, auth.mode == .password,
                  auth.credentialPersistence == .keychain, let login = auth.login,
                  let contents = snapshot.profileContents else { throw VPNValidationError.invalidConfiguration }
            var ledger = current.passwordLedger
            if let old = ledger.active, old.writeState != .notIssued && old.writeState != .noItem {
                guard ledger.pendingDeletion.count < VPNPasswordLedger.maximumPendingDeletions else {
                    throw VPNValidationError.storageUnavailable
                }
                ledger.pendingDeletion.append(old)
            }
            let reference = VPNPasswordReference(itemID: UUID(), profileSHA256: VPNPasswordReference.digest(contents), login: login)
            ledger.active = VPNPasswordSlot(reference: reference, writeState: .notIssued)
            let next = VPNStoredState(saved: snapshot, applied: current.applied, passwordLedger: ledger)
            try next.validate(); try writeState(next, directory: descriptor)
            return reference
        }
    }

    /// Trusted adapter seam: callback must be silent, bounded and non-reentrant.
    /// Reads require settled state. A pending add is not retried or inferred
    /// settled from an item lookup, a delay, or an item-not-found result.
    /// No credential bytes enter this store or its serialized state.
    func readPassword<T>(reference: VPNPasswordReference, expectedRevision: UInt64,
                         silently read: (VPNPasswordReference, VPNPasswordItemLocator) throws -> T) throws -> T {
        try withLock(create: false) { descriptor in
            let current = try requireActivePassword(reference: reference, expectedRevision: expectedRevision, directory: descriptor)
            guard let slot = current.passwordLedger.active, slot.writeState == .settled,
                  let locator = slot.locator else { throw VPNValidationError.staleRevision }
            return try read(reference, locator)
        }
    }

    /// Persist pending BEFORE issuing the one permitted add. A crash before GO
    /// is intentionally indistinguishable from a lost acknowledgement. The
    /// callback must never issue Add twice, Update, or delete-and-reinsert.
    @discardableResult
    func addPasswordOnce(reference: VPNPasswordReference, expectedRevision: UInt64,
                         silently add: (VPNPasswordReference) throws -> VPNPasswordAddOutcome) throws -> VPNPasswordAddOutcome {
        try withLock(create: false) { descriptor in
            let current = try requireActivePassword(reference: reference, expectedRevision: expectedRevision, directory: descriptor)
            guard current.passwordLedger.active?.writeState == .notIssued else { throw VPNValidationError.staleRevision }
            var ledger = current.passwordLedger
            ledger.active?.writeState = .pending
            let pending = VPNStoredState(saved: current.saved, applied: current.applied, passwordLedger: ledger)
            try pending.validate()
            try writeState(pending, directory: descriptor, requireDirectorySync: true)
            let outcome = try add(reference)
            if outcome != .indeterminate {
                try ledger.active?.complete(outcome)
                let next = VPNStoredState(saved: current.saved, applied: current.applied, passwordLedger: ledger)
                try next.validate()
                // A write error after atomic rename can still leave valid
                // settled metadata committed. Never attempt a rollback; a fresh
                // read may observe either pending or settled with its locator.
                try writeState(next, directory: descriptor)
            }
            return outcome
        }
    }

    private func requireActivePassword(reference: VPNPasswordReference, expectedRevision: UInt64,
                                       directory: Int32) throws -> VPNStoredState {
        guard let current = try readState(directory: directory),
              current.saved.configuration.revision == expectedRevision,
              current.passwordLedger.active?.reference == reference,
              reference.matches(current.saved) else { throw VPNValidationError.staleRevision }
        return current
    }

    /// Trusted late receipt seam only. A future coordinator authenticates a
    /// DEFINITE worker completion before calling; a read witness is insufficient.
    /// Exact old queued identity may settle without touching the new active slot.
    func completePasswordAdd(reference: VPNPasswordReference, outcome: VPNPasswordAddOutcome) throws {
        try withLock(create: false) { descriptor in
            guard let current = try readState(directory: descriptor) else { throw VPNValidationError.staleRevision }
            var ledger = current.passwordLedger
            if ledger.active?.reference == reference, ledger.active?.writeState == .pending {
                try ledger.active?.complete(outcome)
            } else if let index = ledger.pendingDeletion.firstIndex(where: { $0.reference == reference && $0.writeState == .pending }) {
                try ledger.pendingDeletion[index].complete(outcome)
            } else { throw VPNValidationError.staleRevision }
            let next = VPNStoredState(saved: current.saved, applied: current.applied, passwordLedger: ledger)
            try next.validate(); try writeState(next, directory: descriptor)
        }
    }

    /// NotFound is not deletion proof. Only a positive exact-item deletion may
    /// acknowledge this locator. A crash after deletion but before acknowledgment
    /// can leave a pending obligation even if later lookup returns NotFound.
    func deletePendingPassword(reference: VPNPasswordReference,
                               silently delete: (VPNPasswordReference, VPNPasswordItemLocator) throws -> VPNPasswordDeleteOutcome) throws {
        try withLock(create: false) { descriptor in
            guard let current = try readState(directory: descriptor),
                  let slot = current.passwordLedger.pendingDeletion.first(where: { $0.reference == reference }),
                  slot.writeState != .pending else { throw VPNValidationError.staleRevision }
            if slot.writeState == .settled {
                guard let locator = slot.locator,
                      try delete(reference, locator) == .deleted else { throw VPNValidationError.storageUnavailable }
            }
            var ledger = current.passwordLedger
            ledger.pendingDeletion.removeAll { $0.reference == reference }
            let next = VPNStoredState(saved: current.saved, applied: current.applied, passwordLedger: ledger)
            try next.validate(); try writeState(next, directory: descriptor)
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

    private func writeState(_ state: VPNStoredState, directory: Int32,
                            requireDirectorySync: Bool = false) throws {
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
        #if VPN_PASSWORD_LEDGER_TESTING
        if testRejectNextWriteAfterRename {
            testRejectNextWriteAfterRename = false
            throw VPNValidationError.storageUnavailable
        }
        #endif
        // Ordinary configuration saves retain their existing rename boundary.
        // An add may start ONLY after syncing its pending intent directory;
        // failure can leave pending committed, but must never dispatch backend IO.
        var directorySync = fsync(directory)
        #if VPN_PASSWORD_LEDGER_TESTING
        if requireDirectorySync && testRejectNextPendingDirectorySync {
            testRejectNextPendingDirectorySync = false
            directorySync = -1
        }
        #endif
        if requireDirectorySync && directorySync != 0 { throw VPNValidationError.storageUnavailable }
    }
}
