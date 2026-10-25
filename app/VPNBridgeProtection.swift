import Darwin
import Foundation

enum VPNBridgeProtectionError: Error, Equatable {
    case unsafeStorage, invalidState, capacity, busy, stale, writeFailed, expired
}

/// Monotonic ordinary-user boot protection, independent of VPN On/Off and TTL.
/// This is not a root route receipt or permission to release a DNS answer.
struct VPNBridgeProtectedSnapshot: Codable, Equatable {
    let schemaVersion: Int
    let revision: UInt64
    let matchers: [String]
    static let maximumMatchers = 5096 // 4096 retained IPs + 1000 static resources.
    static func canonical(_ value: String) throws -> String {
        let resource = try VPNResource(address:value)
        switch resource.kind {
        case .domain: throw VPNBridgeProtectionError.invalidState
        case .ipv4: return resource.address+"/32"
        case .ipv6: return resource.address+"/128"
        case .network4, .network6:
            // Maximum prefixes must obey the same remote-IP policy as hosts.
            let suffix = resource.kind == .network4 ? "/32" : "/128"
            if resource.address.hasSuffix(suffix) {
                let host = String(resource.address.dropLast(suffix.count))
                let checked = try VPNResource(address:host)
                guard checked.kind == .ipv4 || checked.kind == .ipv6 else { throw VPNBridgeProtectionError.invalidState }
            }
            return resource.address
        }
    }
    func validate() throws {
        guard schemaVersion == 1, revision > 0, matchers.count <= Self.maximumMatchers,
              matchers == matchers.sorted(), Set(matchers).count == matchers.count else { throw VPNBridgeProtectionError.invalidState }
        for value in matchers { guard try Self.canonical(value) == value else { throw VPNBridgeProtectionError.invalidState } }
    }
}

/// Caller supplies an already trusted, owner-private persistent directory FD.
/// One lifetime writer lock spans cache and bridge handoff; no path comes from
/// helper IPC. Corruption/missing-after-use is never interpreted as an empty set.
/// A fresh nil cache is NOT proof that root has no retained obligations: the
/// boot adapter must reconcile authenticated root custody before bridge listen.
final class VPNBridgeProtectionStore {
    static let filename = "protected-bridge-v1.json"
    private static let lockName = "protected-bridge.lock"
    private static let maximumBytes = 512 * 1024
    private var directory: Int32 = -1, ownerLock: Int32 = -1
    private let owner = geteuid(), lock = NSRecursiveLock()
    private var observed: VPNBridgeProtectedSnapshot?
    private var publication = false
    init(trustedDirectoryDescriptor: Int32) throws {
        guard getuid() == geteuid(), geteuid() != 0 else { throw VPNBridgeProtectionError.unsafeStorage }
        directory = fcntl(trustedDirectoryDescriptor,F_DUPFD_CLOEXEC,64)
        do {
            try checkDirectory()
            ownerLock = openat(directory,Self.lockName,O_RDWR|O_CREAT|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC,0o600)
            guard ownerLock >= 0 else { throw VPNBridgeProtectionError.unsafeStorage }
            try checkFile(ownerLock)
            guard flock(ownerLock,LOCK_EX|LOCK_NB) == 0 else { throw VPNBridgeProtectionError.busy }
            try checkOwner()
            guard fsync(ownerLock) == 0, fsync(directory) == 0 else { throw VPNBridgeProtectionError.writeFailed }
            observed = try read()
        } catch {
            if ownerLock >= 0 { close(ownerLock);ownerLock = -1 }
            if directory >= 0 { close(directory);directory = -1 }
            throw error
        }
    }
    deinit { if ownerLock >= 0 { close(ownerLock) };if directory >= 0 { close(directory) } }
    func exclusive<T>(_ body: () throws -> T) rethrows -> T { lock.lock();defer { lock.unlock() };return try body() }
    fileprivate func publishing<T>(_ body: () throws -> T) throws -> T {
        try exclusive {
            guard !publication else { throw VPNBridgeProtectionError.busy }
            publication = true;defer { publication = false };return try body()
        }
    }
    func snapshot() throws -> VPNBridgeProtectedSnapshot? {
        try exclusive {
            let value = try read()
            guard value == observed else { throw VPNBridgeProtectionError.stale }
            return value
        }
    }
    fileprivate func merge(_ addresses: [String], checkCurrent: () throws -> Void) throws -> VPNBridgeProtectedSnapshot {
        try exclusive {
            try checkOwner();try checkCurrent()
            guard addresses.count <= VPNBridgeProtectedSnapshot.maximumMatchers else { throw VPNBridgeProtectionError.capacity }
            let incoming = try addresses.map(VPNBridgeProtectedSnapshot.canonical)
            let previous = try snapshot(), union = Set((previous?.matchers ?? [])+incoming).sorted()
            guard union.count <= VPNBridgeProtectedSnapshot.maximumMatchers else { throw VPNBridgeProtectionError.capacity }
            if let previous, previous.matchers == union { try checkCurrent();return previous }
            let revision = previous?.revision ?? 0
            guard revision < UInt64.max else { throw VPNBridgeProtectionError.capacity }
            let next = VPNBridgeProtectedSnapshot(schemaVersion:1,revision:revision+1,matchers:union)
            try next.validate();try checkCurrent()
            let data = try Self.encode(next)
            guard data.count <= Self.maximumBytes else { throw VPNBridgeProtectionError.capacity }
            let name = ".protected-bridge-"+UUID().uuidString+".tmp"
            let fd = openat(directory,name,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0o600)
            guard fd >= 0 else { throw VPNBridgeProtectionError.writeFailed }
            defer { close(fd);unlinkat(directory,name,0) }
            try checkFile(fd)
            try data.withUnsafeBytes { bytes in
                var offset = 0
                while offset < bytes.count {
                    let n = Darwin.write(fd,bytes.baseAddress!.advanced(by:offset),bytes.count-offset)
                    if n < 0 && errno == EINTR { continue }
                    guard n > 0 else { throw VPNBridgeProtectionError.writeFailed };offset += n
                }
            }
            try checkCurrent();try checkOwner()
            guard try read() == previous else { throw VPNBridgeProtectionError.stale }
            guard fsync(fd) == 0 else { throw VPNBridgeProtectionError.writeFailed }
            let moved = previous == nil ? renameatx_np(directory,name,directory,Self.filename,UInt32(RENAME_EXCL))
                                        : renameat(directory,name,directory,Self.filename)
            guard moved == 0 else { throw VPNBridgeProtectionError.writeFailed }
            // A directory-sync failure is indeterminate. Keep the changed disk
            // state; this owner cannot silently continue from its old snapshot.
            guard fsync(directory) == 0 else { throw VPNBridgeProtectionError.writeFailed }
            observed = next
            try checkCurrent();try checkOwner();return next
        }
    }
    private static func encode(_ value: VPNBridgeProtectedSnapshot) throws -> Data {
        let encoder = JSONEncoder();encoder.outputFormatting = [.sortedKeys];return try encoder.encode(value)
    }
    private func read() throws -> VPNBridgeProtectedSnapshot? {
        try checkOwner()
        let fd = openat(directory,Self.filename,O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC)
        guard fd >= 0 else { if errno == ENOENT { return nil };throw VPNBridgeProtectionError.unsafeStorage }
        defer { close(fd) };try checkFile(fd)
        var info = stat();guard fstat(fd,&info) == 0, info.st_size >= 0, info.st_size <= Self.maximumBytes else { throw VPNBridgeProtectionError.capacity }
        var data = Data(), buffer = [UInt8](repeating:0,count:4096)
        while true {
            let n = Darwin.read(fd,&buffer,buffer.count)
            if n < 0 && errno == EINTR { continue }
            guard n >= 0, data.count+max(0,n) <= Self.maximumBytes else { throw VPNBridgeProtectionError.capacity }
            if n == 0 { break };data.append(contentsOf:buffer.prefix(n))
        }
        try checkFile(fd);try checkPath(Self.filename,fd:fd);try checkOwner()
        guard let value = try? JSONDecoder().decode(VPNBridgeProtectedSnapshot.self,from:data) else { throw VPNBridgeProtectionError.invalidState }
        try value.validate()
        guard try Self.encode(value) == data else { throw VPNBridgeProtectionError.invalidState };return value
    }
    private func checkDirectory() throws {
        var s = stat()
        guard directory >= 0, fstat(directory,&s) == 0, s.st_mode & S_IFMT == S_IFDIR,
              s.st_uid == owner, s.st_mode & 0o7777 == 0o700 else { throw VPNBridgeProtectionError.unsafeStorage }
    }
    private func checkFile(_ fd: Int32) throws {
        var s = stat()
        guard fd >= 0, fstat(fd,&s) == 0, s.st_mode & S_IFMT == S_IFREG, s.st_uid == owner,
              s.st_nlink == 1, s.st_mode & 0o7777 == 0o600 else { throw VPNBridgeProtectionError.unsafeStorage }
    }
    private func checkPath(_ name: String, fd: Int32) throws {
        var a = stat(),b = stat()
        guard fstat(fd,&a) == 0, fstatat(directory,name,&b,AT_SYMLINK_NOFOLLOW) == 0,
              a.st_dev == b.st_dev, a.st_ino == b.st_ino else { throw VPNBridgeProtectionError.unsafeStorage }
        try checkFile(fd)
    }
    private func checkOwner() throws { try checkDirectory();try checkFile(ownerLock);try checkPath(Self.lockName,fd:ownerLock) }
}

/// No default successful transport. A production implementation must bind the
/// exact pinned GOST epoch/private API and accept only the synchronous atomic
/// candidate's acknowledgement. Caller owns the authenticated resource lease.
protocol VPNBridgeProtectionTransport: AnyObject {
    func replace(_ snapshot: VPNBridgeProtectedSnapshot, epoch: UUID,
                 deadline: VPNDNSContinuousInstant, checkCurrent: () throws -> Void) throws
}

final class VPNBridgeProtectionPublisher {
    private let store: VPNBridgeProtectionStore, transport: VPNBridgeProtectionTransport
    private let epoch: UUID, clock: VPNDNSContinuousClock
    private let checkEpoch: (UUID) throws -> Void
    init(store: VPNBridgeProtectionStore, transport: VPNBridgeProtectionTransport, epoch: UUID,
         clock: VPNDNSContinuousClock = VPNDarwinDNSContinuousClock(), checkEpoch: @escaping (UUID) throws -> Void) {
        self.store=store;self.transport=transport;self.epoch=epoch;self.clock=clock;self.checkEpoch=checkEpoch
    }
    /// Disk union is durable BEFORE bridge activation; no rollback, TTL clearing
    /// or retries after an unknown API write. The callback stays under the same
    /// store/update lock. This callback alone is NOT a root DNS answer permit.
    func withPublished<T>(_ addresses: [String], deadline: VPNDNSContinuousInstant,
                          checkCurrent: () throws -> Void,
                          body: (VPNBridgeProtectedSnapshot) throws -> T) throws -> T {
        try store.publishing {
            var previous: VPNDNSContinuousInstant?
            func current() throws {
                let now = try clock.now()
                guard previous == nil || now >= previous! else { throw VPNDNSContinuousClockError.backwards }
                previous = now
                guard now < deadline else { throw VPNBridgeProtectionError.expired }
                try checkEpoch(epoch);try checkCurrent()
                let after = try clock.now()
                guard after >= now else { throw VPNDNSContinuousClockError.backwards }
                previous = after
                guard after < deadline else { throw VPNBridgeProtectionError.expired }
            }
            try current()
            let protected = try store.merge(addresses,checkCurrent:current)
            try current()
            try transport.replace(protected,epoch:epoch,deadline:deadline,checkCurrent:current)
            try current()
            guard try store.snapshot() == protected else { throw VPNBridgeProtectionError.stale }
            try current()
            return try body(protected)
        }
    }
}
