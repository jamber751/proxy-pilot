import Darwin
import Foundation

enum VPNUpdateBrokerTransactionStoreError: Error, Equatable {
    case unsafeStorage
    case invalidIdentity
    case invalidState
    case staleRevision
    case busy
    case writeFailed
    case commitUncertain
}

/// Durable broker progress, not permission to perform the represented action.
/// Values are ordered so recovery can reject a phase rollback.
enum VPNUpdateBrokerTransactionPhase: UInt16, Equatable {
    case accepted = 1
    case authorized = 2
    case prepared = 3
    case handoffStarted = 4
    case handoffComplete = 5
    case rotatingBroker = 6
    case complete = 7
    case failed = 8
}

enum VPNUpdateBrokerRecoveryState: UInt16, Equatable {
    case inboxRetained = 1
    case journalRetained = 2
    case executorCommitted = 3
    case complete = 4
    case failed = 5
}

enum VPNUpdateBrokerRotationState: UInt16, Equatable {
    case notStarted = 1
    case pending = 2
    case complete = 3
}

/// Numeric projection of the signed update journal. `phase` deliberately has a
/// closed vocabulary instead of serializing the journal's strings.
enum VPNUpdateBrokerJournalPhase: UInt16, Equatable {
    case prepared = 1
    case replacementPending = 2
    case selected = 3
    case completed = 4
    case cancelled = 5
    case cancellationApplicationRetired = 6
    case cancellationUpdateRetired = 7
    case cancellationGCAuthorized = 8
}

struct VPNUpdateBrokerJournalReference: Equatable {
    let transactionID: UUID
    let revision: UInt64
    let phase: VPNUpdateBrokerJournalPhase
}

struct VPNUpdateBrokerTransactionSnapshot: Equatable {
    let identity: Data
    let fromSequence: UInt64
    let toSequence: UInt64
    let phase: VPNUpdateBrokerTransactionPhase
    let revision: UInt64
    let journal: VPNUpdateBrokerJournalReference?
    let recovery: VPNUpdateBrokerRecoveryState
    let rotation: VPNUpdateBrokerRotationState
}

/// One crash-durable broker transaction in an already-open private directory.
///
/// This receipt is only a recovery index. It is NEVER authorization. Before
/// resuming any privileged step, the broker must reopen and revalidate the exact
/// retained SHA-256 inbox and, when present, the signed update journal named by
/// `journal`. A receipt without that authenticated evidence must fail closed.
final class VPNUpdateBrokerTransactionStore {
    static let fileName = "update-broker-transaction.bin"
    private static let lockName = "update-broker-transaction.lock"
    private static let temporaryName = ".update-broker-transaction.tmp"
    private static let byteCount = 128
    private static let magic: UInt64 = 0x5050_4254_0000_0001
    private static let format: UInt16 = 1
    private static let journalFlag: UInt32 = 1

    #if VPN_UPDATE_BROKER_TRANSACTION_STORE_TESTING
    static var checkpoint: ((String) throws -> Void)?
    #endif

    private var directory: Int32
    private let owner: uid_t

    init(trustedDirectoryDescriptor: Int32) throws {
        owner = geteuid()
        directory = fcntl(trustedDirectoryDescriptor, F_DUPFD_CLOEXEC, 0)
        guard directory >= 0 else {
            throw VPNUpdateBrokerTransactionStoreError.unsafeStorage
        }
        do { try checkDirectory() }
        catch { close(directory); directory = -1; throw error }
    }

    deinit { if directory >= 0 { close(directory) } }

    func load() throws -> VPNUpdateBrokerTransactionSnapshot? {
        try withLock { try readUnlocked() }
    }

    /// Starts the sole transaction. An exact retry gets the original snapshot;
    /// another candidate never replaces it and is reported as busy.
    @discardableResult
    func begin(identity: Data, fromSequence: UInt64, toSequence: UInt64) throws
        -> VPNUpdateBrokerTransactionSnapshot {
        guard identity.count == 32 else {
            throw VPNUpdateBrokerTransactionStoreError.invalidIdentity
        }
        guard fromSequence > 0, toSequence > fromSequence else {
            throw VPNUpdateBrokerTransactionStoreError.invalidState
        }
        return try withLock {
            if let current = try readUnlocked() {
                guard current.identity == identity else {
                    throw VPNUpdateBrokerTransactionStoreError.busy
                }
                guard current.fromSequence == fromSequence,
                      current.toSequence == toSequence else {
                    throw VPNUpdateBrokerTransactionStoreError.invalidState
                }
                return current
            }
            let initial = VPNUpdateBrokerTransactionSnapshot(
                identity: identity, fromSequence: fromSequence,
                toSequence: toSequence, phase: .accepted, revision: 1,
                journal: nil, recovery: .inboxRetained,
                rotation: .notStarted)
            try replace(with: encode(initial))
            return initial
        }
    }

    /// Advances one authenticated candidate. Repeating the exact desired state
    /// is idempotent, including after an uncertain post-rename crash.
    @discardableResult
    func advance(identity: Data, expectedRevision: UInt64,
                 phase: VPNUpdateBrokerTransactionPhase,
                 journal: VPNUpdateBrokerJournalReference?,
                 recovery: VPNUpdateBrokerRecoveryState,
                 rotation: VPNUpdateBrokerRotationState) throws
        -> VPNUpdateBrokerTransactionSnapshot {
        guard identity.count == 32 else {
            throw VPNUpdateBrokerTransactionStoreError.invalidIdentity
        }
        return try withLock {
            guard let current = try readUnlocked() else {
                throw VPNUpdateBrokerTransactionStoreError.invalidState
            }
            guard current.identity == identity else {
                throw VPNUpdateBrokerTransactionStoreError.busy
            }
            if current.phase == phase, current.journal == journal,
               current.recovery == recovery, current.rotation == rotation {
                return current
            }
            guard current.revision == expectedRevision else {
                throw VPNUpdateBrokerTransactionStoreError.staleRevision
            }
            guard legalAdvance(from: current, phase: phase, journal: journal,
                               recovery: recovery, rotation: rotation),
                  current.revision < UInt64.max else {
                throw VPNUpdateBrokerTransactionStoreError.invalidState
            }
            let next = VPNUpdateBrokerTransactionSnapshot(
                identity: current.identity,
                fromSequence: current.fromSequence,
                toSequence: current.toSequence, phase: phase,
                revision: current.revision + 1, journal: journal,
                recovery: recovery, rotation: rotation)
            try replace(with: encode(next))
            return next
        }
    }

    /// Forgets only an exact terminal receipt after its inbox was retired. The
    /// bounded public status remains available independently for the client.
    func retireCompleted(identity: Data, expectedRevision: UInt64) throws {
        guard identity.count == 32 else {
            throw VPNUpdateBrokerTransactionStoreError.invalidIdentity
        }
        try withLock {
            guard let current = try readUnlocked(),
                  current.identity == identity,
                  current.revision == expectedRevision,
                  current.phase == .complete,
                  current.recovery == .complete,
                  current.rotation == .complete else {
                throw VPNUpdateBrokerTransactionStoreError.invalidState
            }
            guard unlinkat(directory, Self.fileName, 0) == 0,
                  fsync(directory) == 0 else {
                throw VPNUpdateBrokerTransactionStoreError.commitUncertain
            }
        }
    }

    private func legalAdvance(from current: VPNUpdateBrokerTransactionSnapshot,
                              phase: VPNUpdateBrokerTransactionPhase,
                              journal: VPNUpdateBrokerJournalReference?,
                              recovery: VPNUpdateBrokerRecoveryState,
                              rotation: VPNUpdateBrokerRotationState) -> Bool {
        if current.phase == .complete || current.phase == .failed { return false }
        if phase != .failed && phase.rawValue < current.phase.rawValue { return false }
        if recovery.rawValue < current.recovery.rawValue,
           recovery != .failed { return false }
        if rotation.rawValue < current.rotation.rawValue { return false }
        if let old = current.journal {
            guard let journal, journal.transactionID == old.transactionID,
                  journal.revision >= old.revision else { return false }
            if journal.revision == old.revision && journal.phase != old.phase { return false }
        }
        if phase.rawValue >= VPNUpdateBrokerTransactionPhase.prepared.rawValue,
           phase != .failed, journal == nil { return false }
        if phase == .complete {
            guard recovery == .complete, rotation == .complete else { return false }
        }
        if phase == .failed && recovery != .failed { return false }
        return true
    }

    private func withLock<T>(_ body: () throws -> T) throws -> T {
        try checkDirectory()
        let lock = openat(directory, Self.lockName,
            O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK, 0o600)
        guard lock >= 0 else {
            throw VPNUpdateBrokerTransactionStoreError.unsafeStorage
        }
        defer { close(lock) }
        try checkFile(lock)
        guard flock(lock, LOCK_EX | LOCK_NB) == 0 else {
            throw VPNUpdateBrokerTransactionStoreError.busy
        }
        defer { _ = flock(lock, LOCK_UN) }
        return try body()
    }

    private func readUnlocked() throws -> VPNUpdateBrokerTransactionSnapshot? {
        try checkDirectory()
        let file = openat(directory, Self.fileName,
            O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard file >= 0 else {
            if errno == ENOENT { return nil }
            throw VPNUpdateBrokerTransactionStoreError.unsafeStorage
        }
        defer { close(file) }
        try checkFile(file)
        var attributes = stat()
        guard fstat(file, &attributes) == 0,
              attributes.st_size == Self.byteCount else {
            throw VPNUpdateBrokerTransactionStoreError.invalidState
        }
        var bytes = [UInt8](repeating: 0, count: Self.byteCount)
        var offset = 0
        while offset < bytes.count {
            let count = bytes.withUnsafeMutableBytes { buffer in
                Darwin.read(file, buffer.baseAddress!.advanced(by: offset),
                            buffer.count - offset)
            }
            if count < 0, errno == EINTR { continue }
            guard count > 0 else {
                throw VPNUpdateBrokerTransactionStoreError.invalidState
            }
            offset += count
        }
        var extra: UInt8 = 0
        guard Darwin.read(file, &extra, 1) == 0 else {
            throw VPNUpdateBrokerTransactionStoreError.invalidState
        }
        return try decode(bytes)
    }

    private func replace(with bytes: [UInt8]) throws {
        // A real process death before rename leaves this fixed private scratch
        // name behind. Under the transaction lock, discard only that exact
        // non-authoritative name so retries cannot accumulate or deadlock on it.
        if unlinkat(directory, Self.temporaryName, 0) != 0 && errno != ENOENT {
            throw VPNUpdateBrokerTransactionStoreError.writeFailed
        }
        let file = openat(directory, Self.temporaryName,
            O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard file >= 0 else {
            throw VPNUpdateBrokerTransactionStoreError.writeFailed
        }
        defer { close(file); unlinkat(directory, Self.temporaryName, 0) }
        try checkFile(file)
        try bytes.withUnsafeBytes { buffer in
            var offset = 0
            while offset < buffer.count {
                let count = Darwin.write(file,
                    buffer.baseAddress!.advanced(by: offset), buffer.count - offset)
                if count < 0, errno == EINTR { continue }
                guard count > 0 else {
                    throw VPNUpdateBrokerTransactionStoreError.writeFailed
                }
                offset += count
            }
        }
        guard fsync(file) == 0 else {
            throw VPNUpdateBrokerTransactionStoreError.writeFailed
        }
        #if VPN_UPDATE_BROKER_TRANSACTION_STORE_TESTING
        try Self.checkpoint?("before-rename")
        #endif
        guard renameat(directory, Self.temporaryName,
                       directory, Self.fileName) == 0 else {
            throw VPNUpdateBrokerTransactionStoreError.writeFailed
        }
        #if VPN_UPDATE_BROKER_TRANSACTION_STORE_TESTING
        do { try Self.checkpoint?("after-rename") }
        catch { throw VPNUpdateBrokerTransactionStoreError.commitUncertain }
        #endif
        guard fsync(directory) == 0 else {
            throw VPNUpdateBrokerTransactionStoreError.commitUncertain
        }
    }

    private func encode(_ snapshot: VPNUpdateBrokerTransactionSnapshot) -> [UInt8] {
        let hasJournal = snapshot.journal != nil
        var bytes = number(Self.magic) + number(Self.format)
            + number(snapshot.phase.rawValue) + number(snapshot.recovery.rawValue)
            + number(snapshot.rotation.rawValue)
            + number(hasJournal ? Self.journalFlag : UInt32(0))
            + number(UInt32(0)) + Array(snapshot.identity)
            + number(snapshot.fromSequence) + number(snapshot.toSequence)
            + number(snapshot.revision)
        if let journal = snapshot.journal {
            bytes += uuidBytes(journal.transactionID)
            bytes += number(journal.revision) + number(journal.phase.rawValue)
        } else {
            bytes += [UInt8](repeating: 0, count: 16 + 8 + 2)
        }
        bytes += [UInt8](repeating: 0, count: 14)
        bytes += number(checksum(bytes))
        return bytes
    }

    private func decode(_ bytes: [UInt8]) throws
        -> VPNUpdateBrokerTransactionSnapshot {
        guard bytes.count == Self.byteCount,
              value64(bytes[0..<8]) == Self.magic,
              value16(bytes[8..<10]) == Self.format,
              let phase = VPNUpdateBrokerTransactionPhase(rawValue: value16(bytes[10..<12])),
              let recovery = VPNUpdateBrokerRecoveryState(rawValue: value16(bytes[12..<14])),
              let rotation = VPNUpdateBrokerRotationState(rawValue: value16(bytes[14..<16])),
              value32(bytes[20..<24]) == 0,
              bytes[106..<120].allSatisfy({ $0 == 0 }),
              value64(bytes[120..<128]) == checksum(Array(bytes[0..<120])) else {
            throw VPNUpdateBrokerTransactionStoreError.invalidState
        }
        let flags = value32(bytes[16..<20])
        guard flags == 0 || flags == Self.journalFlag else {
            throw VPNUpdateBrokerTransactionStoreError.invalidState
        }
        let identity = Data(bytes[24..<56])
        let from = value64(bytes[56..<64]), to = value64(bytes[64..<72])
        let revision = value64(bytes[72..<80])
        guard from > 0, to > from, revision > 0 else {
            throw VPNUpdateBrokerTransactionStoreError.invalidState
        }
        let journal: VPNUpdateBrokerJournalReference?
        if flags == Self.journalFlag {
            guard let journalPhase = VPNUpdateBrokerJournalPhase(
                    rawValue: value16(bytes[104..<106])) else {
                throw VPNUpdateBrokerTransactionStoreError.invalidState
            }
            journal = VPNUpdateBrokerJournalReference(
                transactionID: uuid(Array(bytes[80..<96])),
                revision: value64(bytes[96..<104]), phase: journalPhase)
        } else {
            guard bytes[80..<106].allSatisfy({ $0 == 0 }) else {
                throw VPNUpdateBrokerTransactionStoreError.invalidState
            }
            journal = nil
        }
        let snapshot = VPNUpdateBrokerTransactionSnapshot(
            identity: identity, fromSequence: from, toSequence: to,
            phase: phase, revision: revision, journal: journal,
            recovery: recovery, rotation: rotation)
        guard validLoaded(snapshot) else {
            throw VPNUpdateBrokerTransactionStoreError.invalidState
        }
        return snapshot
    }

    private func validLoaded(_ value: VPNUpdateBrokerTransactionSnapshot) -> Bool {
        if value.phase.rawValue >= VPNUpdateBrokerTransactionPhase.prepared.rawValue,
           value.phase != .failed, value.journal == nil { return false }
        if value.phase == .complete {
            return value.recovery == .complete && value.rotation == .complete
        }
        if value.phase == .failed { return value.recovery == .failed }
        return true
    }

    private func checkDirectory() throws {
        var attributes = stat(), filesystem = statfs()
        guard geteuid() == owner, fstat(directory, &attributes) == 0,
              attributes.st_mode & S_IFMT == S_IFDIR,
              attributes.st_nlink > 0, attributes.st_uid == owner,
              attributes.st_mode & 0o7777 == 0o700,
              fstatfs(directory, &filesystem) == 0,
              filesystem.f_flags & UInt32(MNT_LOCAL) != 0 else {
            throw VPNUpdateBrokerTransactionStoreError.unsafeStorage
        }
        try checkNoACL(directory)
    }

    private func checkFile(_ file: Int32) throws {
        var attributes = stat()
        guard fstat(file, &attributes) == 0,
              attributes.st_mode & S_IFMT == S_IFREG,
              attributes.st_nlink == 1, attributes.st_uid == owner,
              attributes.st_mode & 0o7777 == 0o600 else {
            throw VPNUpdateBrokerTransactionStoreError.unsafeStorage
        }
        try checkNoACL(file)
    }

    private func checkNoACL(_ descriptor: Int32) throws {
        var info = stat()
        guard let security = filesec_init() else {
            throw VPNUpdateBrokerTransactionStoreError.unsafeStorage
        }
        defer { filesec_free(security) }
        guard fstatx_np(descriptor, &info, security) == 0 else {
            throw VPNUpdateBrokerTransactionStoreError.unsafeStorage
        }
        var acl: acl_t?
        errno = 0
        let result = filesec_get_property(security, FILESEC_ACL, &acl)
        if result == -1, errno == ENOENT { return }
        guard result == 0, let acl else {
            throw VPNUpdateBrokerTransactionStoreError.unsafeStorage
        }
        defer { acl_free(UnsafeMutableRawPointer(acl)) }
        var entry: acl_entry_t?
        errno = 0
        guard acl_get_entry(acl, Int32(ACL_FIRST_ENTRY.rawValue), &entry) == -1,
              errno == EINVAL else {
            throw VPNUpdateBrokerTransactionStoreError.unsafeStorage
        }
    }

    private func checksum(_ bytes: [UInt8]) -> UInt64 {
        bytes.reduce(0xcbf2_9ce4_8422_2325) {
            ($0 ^ UInt64($1)) &* 0x0000_0100_0000_01b3
        }
    }

    private func uuidBytes(_ value: UUID) -> [UInt8] {
        withUnsafeBytes(of: value.uuid) { Array($0) }
    }

    private func uuid(_ bytes: [UInt8]) -> UUID {
        UUID(uuid: (bytes[0], bytes[1], bytes[2], bytes[3],
                    bytes[4], bytes[5], bytes[6], bytes[7],
                    bytes[8], bytes[9], bytes[10], bytes[11],
                    bytes[12], bytes[13], bytes[14], bytes[15]))
    }

    private func number(_ value: UInt16) -> [UInt8] {
        [UInt8(truncatingIfNeeded: value >> 8), UInt8(truncatingIfNeeded: value)]
    }
    private func number(_ value: UInt32) -> [UInt8] {
        (0..<4).reversed().map { UInt8(truncatingIfNeeded: value >> ($0 * 8)) }
    }
    private func number(_ value: UInt64) -> [UInt8] {
        (0..<8).reversed().map { UInt8(truncatingIfNeeded: value >> ($0 * 8)) }
    }
    private func value16(_ bytes: ArraySlice<UInt8>) -> UInt16 {
        bytes.reduce(0) { ($0 << 8) | UInt16($1) }
    }
    private func value32(_ bytes: ArraySlice<UInt8>) -> UInt32 {
        bytes.reduce(0) { ($0 << 8) | UInt32($1) }
    }
    private func value64(_ bytes: ArraySlice<UInt8>) -> UInt64 {
        bytes.reduce(0) { ($0 << 8) | UInt64($1) }
    }
}
