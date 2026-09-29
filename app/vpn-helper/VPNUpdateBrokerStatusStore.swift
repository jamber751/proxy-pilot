import Darwin
import Foundation

enum VPNUpdateBrokerStatusStoreError: Error, Equatable {
    case unsafeStorage
    case invalidState
    case staleRevision
    case busy
    case writeFailed
    case commitUncertain
}

/// `idle` is the state of a broker with no durable transaction. The remaining
/// values have a one-to-one mapping to the fixed public response vocabulary.
enum VPNUpdateBrokerDurableState: UInt16, Equatable {
    case idle = 0
    case accepted = 1
    case checking = 2
    case ready = 3
    case installing = 4
    case complete = 5
    case failed = 6
    case busy = 7
    case stale = 8

    init(responseState: VPNUpdateBrokerState) {
        self = Self(rawValue: responseState.rawValue + 1)!
    }

    var responseState: VPNUpdateBrokerState? {
        guard self != .idle else { return nil }
        return VPNUpdateBrokerState(rawValue: rawValue - 1)
    }
}

struct VPNUpdateBrokerStatusSnapshot: Equatable {
    let state: VPNUpdateBrokerDurableState
    let fromSequence: UInt64
    let toSequence: UInt64
    let revision: UInt64

    /// There is deliberately no invented public `idle` wire value. Callers may
    /// return `nil` as "no transaction"; every durable transaction maps exactly
    /// to the existing bounded numeric response.
    var response: VPNUpdateBrokerResponse? {
        guard let responseState = state.responseState else { return nil }
        return VPNUpdateBrokerResponse(state: responseState,
            fromSequence: fromSequence, toSequence: toSequence,
            revision: revision)
    }

    static let idle = Self(state: .idle, fromSequence: 0,
                           toSequence: 0, revision: 0)
}

/// Durable numeric-only status for the update broker. The directory is supplied
/// as already-open authority; this type never accepts or reconstructs a path and
/// cannot launch, install, select, or otherwise mutate VPN/application state.
final class VPNUpdateBrokerStatusStore {
    static let fileName = "update-broker-status.bin"
    private static let lockName = "update-broker-status.lock"
    private static let byteCount = 48
    private static let magic: UInt64 = 0x5050_4253_0000_0001
    private static let format: UInt16 = 1

    #if VPN_UPDATE_BROKER_STATUS_STORE_TESTING
    static var checkpoint: ((String) throws -> Void)?
    #endif

    private var directory: Int32
    private let owner: uid_t

    init(trustedDirectoryDescriptor: Int32) throws {
        owner = geteuid()
        directory = fcntl(trustedDirectoryDescriptor, F_DUPFD_CLOEXEC, 0)
        guard directory >= 0 else {
            throw VPNUpdateBrokerStatusStoreError.unsafeStorage
        }
        do { try checkDirectory() }
        catch { close(directory); directory = -1; throw error }
    }

    deinit { if directory >= 0 { close(directory) } }

    func load() throws -> VPNUpdateBrokerStatusSnapshot {
        try withLock { try readUnlocked() }
    }

    /// Publishes a new revision. Repeating the same value is idempotent, even
    /// when the first caller observed a crash/error immediately after rename.
    @discardableResult
    func publish(state: VPNUpdateBrokerState, fromSequence: UInt64,
                 toSequence: UInt64, expectedRevision: UInt64? = nil) throws
        -> VPNUpdateBrokerResponse {
        try withLock {
            let current = try readUnlocked()
            let desired = VPNUpdateBrokerDurableState(responseState: state)
            if current.state == desired,
               current.fromSequence == fromSequence,
               current.toSequence == toSequence,
               let response = current.response {
                return response
            }
            if let expectedRevision, current.revision != expectedRevision {
                throw VPNUpdateBrokerStatusStoreError.staleRevision
            }
            guard current.revision < UInt64.max else {
                throw VPNUpdateBrokerStatusStoreError.invalidState
            }
            let next = VPNUpdateBrokerStatusSnapshot(state: desired,
                fromSequence: fromSequence, toSequence: toSequence,
                revision: current.revision + 1)
            try replace(with: encode(next))
            return next.response!
        }
    }

    private func withLock<T>(_ body: () throws -> T) throws -> T {
        try checkDirectory()
        let lock = openat(directory, Self.lockName,
            O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK, 0o600)
        guard lock >= 0 else { throw VPNUpdateBrokerStatusStoreError.unsafeStorage }
        defer { close(lock) }
        try checkFile(lock)
        guard flock(lock, LOCK_EX | LOCK_NB) == 0 else {
            throw VPNUpdateBrokerStatusStoreError.busy
        }
        defer { _ = flock(lock, LOCK_UN) }
        return try body()
    }

    private func readUnlocked() throws -> VPNUpdateBrokerStatusSnapshot {
        try checkDirectory()
        let file = openat(directory, Self.fileName,
            O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard file >= 0 else {
            if errno == ENOENT { return .idle }
            throw VPNUpdateBrokerStatusStoreError.unsafeStorage
        }
        defer { close(file) }
        try checkFile(file)
        var attributes = stat()
        guard fstat(file, &attributes) == 0,
              attributes.st_size == Self.byteCount else {
            throw VPNUpdateBrokerStatusStoreError.invalidState
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
                throw VPNUpdateBrokerStatusStoreError.invalidState
            }
            offset += count
        }
        var extra: UInt8 = 0
        let trailing = Darwin.read(file, &extra, 1)
        guard trailing == 0 else {
            throw VPNUpdateBrokerStatusStoreError.invalidState
        }
        return try decode(bytes)
    }

    private func replace(with bytes: [UInt8]) throws {
        let temporary = ".update-broker-status-\(UUID().uuidString).tmp"
        let file = openat(directory, temporary,
            O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard file >= 0 else { throw VPNUpdateBrokerStatusStoreError.writeFailed }
        defer { close(file); unlinkat(directory, temporary, 0) }
        try checkFile(file)
        try bytes.withUnsafeBytes { buffer in
            var offset = 0
            while offset < buffer.count {
                let count = Darwin.write(file,
                    buffer.baseAddress!.advanced(by: offset), buffer.count - offset)
                if count < 0, errno == EINTR { continue }
                guard count > 0 else {
                    throw VPNUpdateBrokerStatusStoreError.writeFailed
                }
                offset += count
            }
        }
        guard fsync(file) == 0 else {
            throw VPNUpdateBrokerStatusStoreError.writeFailed
        }
        #if VPN_UPDATE_BROKER_STATUS_STORE_TESTING
        try Self.checkpoint?("before-rename")
        #endif
        guard renameat(directory, temporary, directory, Self.fileName) == 0 else {
            throw VPNUpdateBrokerStatusStoreError.writeFailed
        }
        #if VPN_UPDATE_BROKER_STATUS_STORE_TESTING
        do { try Self.checkpoint?("after-rename") }
        catch { throw VPNUpdateBrokerStatusStoreError.commitUncertain }
        #endif
        guard fsync(directory) == 0 else {
            throw VPNUpdateBrokerStatusStoreError.commitUncertain
        }
    }

    private func encode(_ snapshot: VPNUpdateBrokerStatusSnapshot) -> [UInt8] {
        var bytes = number(Self.magic) + number(Self.format)
            + number(snapshot.state.rawValue) + number(UInt32(0))
            + number(snapshot.fromSequence) + number(snapshot.toSequence)
            + number(snapshot.revision)
        bytes += number(checksum(bytes))
        return bytes
    }

    private func decode(_ bytes: [UInt8]) throws -> VPNUpdateBrokerStatusSnapshot {
        guard bytes.count == Self.byteCount,
              value64(bytes[0..<8]) == Self.magic,
              value16(bytes[8..<10]) == Self.format,
              value32(bytes[12..<16]) == 0,
              value64(bytes[40..<48]) == checksum(Array(bytes[0..<40])),
              let state = VPNUpdateBrokerDurableState(
                rawValue: value16(bytes[10..<12])), state != .idle else {
            throw VPNUpdateBrokerStatusStoreError.invalidState
        }
        let revision = value64(bytes[32..<40])
        guard revision > 0 else { throw VPNUpdateBrokerStatusStoreError.invalidState }
        return VPNUpdateBrokerStatusSnapshot(state: state,
            fromSequence: value64(bytes[16..<24]),
            toSequence: value64(bytes[24..<32]), revision: revision)
    }

    private func checkDirectory() throws {
        var attributes = stat(), filesystem = statfs()
        guard geteuid() == owner, fstat(directory, &attributes) == 0,
              attributes.st_mode & S_IFMT == S_IFDIR,
              attributes.st_nlink > 0, attributes.st_uid == owner,
              attributes.st_mode & 0o7777 == 0o700,
              fstatfs(directory, &filesystem) == 0,
              filesystem.f_flags & UInt32(MNT_LOCAL) != 0 else {
            throw VPNUpdateBrokerStatusStoreError.unsafeStorage
        }
        try checkNoACL(directory)
    }

    private func checkFile(_ file: Int32) throws {
        var attributes = stat()
        guard fstat(file, &attributes) == 0,
              attributes.st_mode & S_IFMT == S_IFREG,
              attributes.st_nlink == 1, attributes.st_uid == owner,
              attributes.st_mode & 0o7777 == 0o600 else {
            throw VPNUpdateBrokerStatusStoreError.unsafeStorage
        }
        try checkNoACL(file)
    }

    private func checkNoACL(_ descriptor: Int32) throws {
        var info = stat()
        guard let security = filesec_init() else {
            throw VPNUpdateBrokerStatusStoreError.unsafeStorage
        }
        defer { filesec_free(security) }
        guard fstatx_np(descriptor, &info, security) == 0 else {
            throw VPNUpdateBrokerStatusStoreError.unsafeStorage
        }
        var acl: acl_t?
        errno = 0
        let result = filesec_get_property(security, FILESEC_ACL, &acl)
        if result == -1, errno == ENOENT { return }
        guard result == 0, let acl else {
            throw VPNUpdateBrokerStatusStoreError.unsafeStorage
        }
        defer { acl_free(UnsafeMutableRawPointer(acl)) }
        var entry: acl_entry_t?
        errno = 0
        guard acl_get_entry(acl, Int32(ACL_FIRST_ENTRY.rawValue), &entry) == -1,
              errno == EINVAL else {
            throw VPNUpdateBrokerStatusStoreError.unsafeStorage
        }
    }

    private func checksum(_ bytes: [UInt8]) -> UInt64 {
        bytes.reduce(0xcbf2_9ce4_8422_2325) {
            ($0 ^ UInt64($1)) &* 0x0000_0100_0000_01b3
        }
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
