import Darwin
import Foundation

enum VPNExactFenceStoreError: VPNFlowDiagnosticError, Equatable {
    case unsafeStorage, invalidState, capacity, stale, recoveryRequired, writeFailed
    var vpnFlowFailureCode: VPNFlowFailureCode {
        switch self {
        case .unsafeStorage: return .unsafeStorage
        case .invalidState, .capacity: return .invalidState
        case .stale: return .stale
        case .recoveryRequired: return .recoveryRequired
        case .writeFailed: return .writeFailed
        }
    }
}

struct VPNExactFenceClaim: Codable, Equatable, Comparable {
    let resourceID: UUID
    let profileSHA256: String
    let generation: UInt64
    let revision: UInt64
    static func < (a: Self, b: Self) -> Bool { a.resourceID.uuidString < b.resourceID.uuidString }
    func validate() throws {
        guard generation > 0, revision > 0, profileSHA256.utf8.count == 64,
              profileSHA256.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }) else {
            throw VPNExactFenceStoreError.invalidState
        }
    }
}

enum VPNExactFencePhase: String, Codable { case adding, applied, releasing, retired }
enum VPNFencedHostPhase: String, Codable { case installing, applied, removing }
struct VPNFencedHostEntry: Codable, Equatable {
    let identity: VPNOwnedRouteIdentity
    let claim: VPNExactFenceClaim
    let phase: VPNFencedHostPhase
    func validate(address: VPNRoutePrefix) throws {
        try identity.validate(); try claim.validate()
        let route = VPNPlannedRoute(role:identity.role,destination:identity.destination,
            physicalGatewayBytes:identity.gatewayBytes,interfaceIndex:identity.interfaceIndex,
            interfaceName:identity.interfaceName,interfaceScope:identity.interfaceScope)
        try route.validate()
        guard identity.role == .resource, identity.destination == address,
              address.prefixLength == address.bytes.count * 8,
              identity.gatewayBytes == nil, identity.interfaceScope == nil,
              identity.flags == VPNManagedIPv6HostRoute.flags(for:route) else {
            throw VPNExactFenceStoreError.invalidState
        }
    }
}

/// Historical durable custody, not a current kernel/answer permit. No TTL field:
/// expiration, negative DNS answers and generation changes cannot erase claims.
struct VPNExactFenceEntry: Codable, Equatable {
    static let schema = 1
    static let activeSchema = 2
    let schemaVersion: Int
    let installationID: UUID
    let identity: VPNExactRouteFenceIdentity
    let phase: VPNExactFencePhase
    let claims: [VPNExactFenceClaim]
    let active: VPNFencedHostEntry?
    init(schemaVersion: Int, installationID: UUID, identity: VPNExactRouteFenceIdentity,
         phase: VPNExactFencePhase, claims: [VPNExactFenceClaim], active: VPNFencedHostEntry? = nil) {
        self.schemaVersion=schemaVersion;self.installationID=installationID;self.identity=identity
        self.phase=phase;self.claims=claims;self.active=active
    }
    func validate() throws {
        try identity.validate()
        guard (schemaVersion == Self.schema && active == nil) || schemaVersion == Self.activeSchema else {
            throw VPNExactFenceStoreError.invalidState
        }
        guard !claims.isEmpty, claims.count <= 1000,
              claims == claims.sorted(), Set(claims.map(\.resourceID)).count == claims.count else {
            throw VPNExactFenceStoreError.invalidState
        }
        for claim in claims { try claim.validate() }
        if let active {
            guard phase == .applied || phase == .adding, claims.contains(active.claim) else { throw VPNExactFenceStoreError.invalidState }
            try active.validate(address:identity.address)
        }
    }
    fileprivate func changing(phase: VPNExactFencePhase, claims: [VPNExactFenceClaim]? = nil,
                              installationID: UUID? = nil) -> Self {
        Self(schemaVersion: schemaVersion, installationID: installationID ?? self.installationID,
             identity: identity, phase: phase, claims: claims ?? self.claims, active:active)
    }
    fileprivate func changingActive(_ active: VPNFencedHostEntry?) -> Self {
        Self(schemaVersion:Self.activeSchema,installationID:installationID,identity:identity,
             phase:phase,claims:claims,active:active)
    }
}

/// One private persistent namespace, independent of tunnel generation folders.
/// The service owner supplies the trusted descriptor; no IPC path is accepted.
/// A lifetime file lock prevents two owners; the recursive lock spans journal +
/// native I/O so separate transactions using this store cannot interleave.
final class VPNExactFenceStore {
    static let maximumBytes = 256 * 1024
    static let maximumNamespaceBytes = 8 * 1024 * 1024
    static let maximumEntries = 4096
    private static let lockName = "owner.lock"
    private let owner = geteuid()
    private var directory: Int32 = -1, ownerLock: Int32 = -1
    private let mutex = NSRecursiveLock()

    init(trustedDirectoryDescriptor: Int32) throws {
        directory = fcntl(trustedDirectoryDescriptor, F_DUPFD_CLOEXEC, 64)
        do {
            try checkDirectory()
            ownerLock = openat(directory, Self.lockName, O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK, 0o600)
            guard ownerLock >= 0 else { throw VPNExactFenceStoreError.unsafeStorage }
            try checkFile(ownerLock)
            guard flock(ownerLock, LOCK_EX | LOCK_NB) == 0 else { throw VPNExactFenceStoreError.recoveryRequired }
            try checkOwner()
            guard fsync(ownerLock) == 0, fsync(directory) == 0 else { throw VPNExactFenceStoreError.writeFailed }
        } catch {
            if ownerLock >= 0 { close(ownerLock); ownerLock = -1 }
            if directory >= 0 { close(directory); directory = -1 }
            throw error
        }
    }
    deinit {
        if ownerLock >= 0 { close(ownerLock) }
        if directory >= 0 { close(directory) }
    }
    fileprivate func exclusive<T>(_ body: () throws -> T) rethrows -> T {
        mutex.lock(); defer { mutex.unlock() }; return try body()
    }
    /// Namespace/lock custody only; this is not live kernel route verification.
    func validateOwner() throws { try exclusive { try checkOwner() } }
    func load(_ address: VPNRoutePrefix) throws -> VPNExactFenceEntry? {
        try exclusive { try read(name: Self.name(address)) }
    }
    func entries() throws -> [VPNExactFenceEntry] {
        try exclusive {
            try names().map { name in
                guard let entry = try read(name: name) else { throw VPNExactFenceStoreError.stale }
                return entry
            }.sorted { $0.identity.address < $1.identity.address }
        }
    }
    static func name(_ address: VPNRoutePrefix) throws -> String {
        try address.validate()
        guard address.prefixLength == address.bytes.count * 8 else { throw VPNExactFenceStoreError.invalidState }
        return "fence-v1-\(address.family.rawValue)-" + address.bytes.map { String(format:"%02x",$0) }.joined() + ".json"
    }
    fileprivate func save(_ entry: VPNExactFenceEntry, replacing expected: VPNExactFenceEntry?) throws {
        try checkOwner(); try entry.validate()
        let name = try Self.name(entry.identity.address)
        guard try read(name: name) == expected else { throw VPNExactFenceStoreError.stale }
        let existingNames = try names()
        if expected == nil { guard existingNames.count < Self.maximumEntries else { throw VPNExactFenceStoreError.capacity } }
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
        let data = try encoder.encode(entry)
        guard data.count <= Self.maximumBytes else { throw VPNExactFenceStoreError.capacity }
        var total = data.count
        for existing in existingNames where existing != name {
            total += try size(existing)
            guard total <= Self.maximumNamespaceBytes else { throw VPNExactFenceStoreError.capacity }
        }
        let temporary = ".fence-\(UUID().uuidString).tmp"
        let fd = openat(directory, temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw VPNExactFenceStoreError.writeFailed }
        defer { close(fd); unlinkat(directory, temporary, 0) }
        try checkFile(fd)
        try data.withUnsafeBytes { bytes in
            var offset = 0
            while offset < bytes.count {
                let count = Darwin.write(fd, bytes.baseAddress!.advanced(by:offset),bytes.count-offset)
                if count < 0 && errno == EINTR { continue }
                guard count > 0 else { throw VPNExactFenceStoreError.writeFailed }
                offset += count
            }
        }
        try checkOwner()
        guard fsync(fd) == 0 else { throw VPNExactFenceStoreError.writeFailed }
        let moved = expected == nil
            ? renameatx_np(directory,temporary,directory,name,UInt32(RENAME_EXCL))
            : renameat(directory,temporary,directory,name)
        guard moved == 0, fsync(directory) == 0 else { throw VPNExactFenceStoreError.writeFailed }
    }
    private func read(name: String) throws -> VPNExactFenceEntry? {
        try checkOwner()
        let fd = openat(directory, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard fd >= 0 else {
            guard errno == ENOENT else { throw VPNExactFenceStoreError.unsafeStorage }
            return nil
        }
        defer { close(fd) }
        try checkFile(fd)
        var data = Data(), buffer = [UInt8](repeating:0,count:4096)
        while true {
            let count = Darwin.read(fd,&buffer,buffer.count)
            if count < 0 && errno == EINTR { continue }
            guard count >= 0, data.count + max(0,count) <= Self.maximumBytes else { throw VPNExactFenceStoreError.capacity }
            if count == 0 { break }
            data.append(contentsOf:buffer.prefix(count))
        }
        try checkFile(fd); try checkPath(name, fd: fd)
        guard let entry = try? JSONDecoder().decode(VPNExactFenceEntry.self,from:data) else { throw VPNExactFenceStoreError.invalidState }
        try entry.validate()
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
        guard try encoder.encode(entry) == data, try Self.name(entry.identity.address) == name else { throw VPNExactFenceStoreError.invalidState }
        return entry
    }
    private func names() throws -> [String] {
        try checkOwner()
        let fd = fcntl(directory,F_DUPFD_CLOEXEC,64)
        guard fd >= 0 else { throw VPNExactFenceStoreError.unsafeStorage }
        guard let stream = fdopendir(fd) else { close(fd); throw VPNExactFenceStoreError.unsafeStorage }
        defer { closedir(stream) }; rewinddir(stream)
        var result = [String]()
        while true {
            errno = 0
            guard let item = readdir(stream) else {
                guard errno == 0 else { throw VPNExactFenceStoreError.unsafeStorage }; break
            }
            let name = withUnsafePointer(to:&item.pointee.d_name) {
                $0.withMemoryRebound(to:CChar.self,capacity:Int(item.pointee.d_namlen)+1) { String(cString:$0) }
            }
            if name == "." || name == ".." || name == Self.lockName { continue }
            // A pre-rename temporary file cannot precede a native mutation.
            // Never adopt/delete stale temps as ownership evidence.
            if name.hasPrefix(".fence-") && name.hasSuffix(".tmp") { continue }
            guard name.hasPrefix("fence-v1-"), name.hasSuffix(".json"), name.utf8.count <= 49 else { throw VPNExactFenceStoreError.unsafeStorage }
            result.append(name)
            guard result.count <= Self.maximumEntries else { throw VPNExactFenceStoreError.capacity }
        }
        var total = 0
        for name in result {
            total += try size(name)
            guard total <= Self.maximumNamespaceBytes else { throw VPNExactFenceStoreError.capacity }
        }
        return result.sorted()
    }
    private func size(_ name: String) throws -> Int {
        var info = stat()
        guard fstatat(directory,name,&info,AT_SYMLINK_NOFOLLOW) == 0,
              info.st_mode & S_IFMT == S_IFREG, info.st_uid == owner, info.st_nlink == 1,
              info.st_mode & 0o7777 == 0o600 else { throw VPNExactFenceStoreError.unsafeStorage }
        guard info.st_size >= 0, info.st_size <= Self.maximumBytes else { throw VPNExactFenceStoreError.capacity }
        return Int(info.st_size)
    }
    private func checkDirectory() throws {
        var s = stat()
        guard directory >= 0, geteuid() == owner, fstat(directory,&s) == 0,
              s.st_mode & S_IFMT == S_IFDIR, s.st_uid == owner, s.st_nlink > 0,
              s.st_mode & 0o7777 == 0o700 else { throw VPNExactFenceStoreError.unsafeStorage }
    }
    private func checkFile(_ fd: Int32) throws {
        var s = stat()
        guard fstat(fd,&s) == 0, s.st_mode & S_IFMT == S_IFREG, s.st_uid == owner,
              s.st_nlink == 1, s.st_mode & 0o7777 == 0o600 else { throw VPNExactFenceStoreError.unsafeStorage }
    }
    private func checkPath(_ name: String, fd: Int32) throws {
        var a = stat(), b = stat()
        guard fstat(fd,&a) == 0, fstatat(directory,name,&b,AT_SYMLINK_NOFOLLOW) == 0,
              b.st_mode & S_IFMT == S_IFREG, a.st_dev == b.st_dev, a.st_ino == b.st_ino,
              b.st_nlink == 1, b.st_uid == owner, b.st_mode & 0o7777 == 0o600 else { throw VPNExactFenceStoreError.unsafeStorage }
    }
    fileprivate func checkOwner() throws {
        try checkDirectory(); try checkFile(ownerLock); try checkPath(Self.lockName,fd:ownerLock)
    }
}

protocol VPNExactFenceKernel: AnyObject {
    func lookupExactFence(_ identity: VPNExactRouteFenceIdentity, deadline: DispatchTime) throws -> VPNDarwinRouteSnapshot?
    func installExactFence(_ identity: VPNExactRouteFenceIdentity, deadline: DispatchTime) throws
    func deleteExactFence(_ identity: VPNExactRouteFenceIdentity, deadline: DispatchTime) throws
}
extension VPNDarwinRouteSocket: VPNExactFenceKernel {}
protocol VPNFencedHostKernel: VPNExactFenceKernel {
    func lookupFencedHost(_ identity: VPNOwnedRouteIdentity, fence: VPNExactRouteFenceIdentity,
                          deadline: DispatchTime) throws -> VPNDarwinRouteSnapshot?
    func installFencedHost(_ identity: VPNOwnedRouteIdentity, fence: VPNExactRouteFenceIdentity,
                           deadline: DispatchTime, checkCurrent: () throws -> Void) throws
    func deleteFencedHost(_ identity: VPNOwnedRouteIdentity, fence: VPNExactRouteFenceIdentity,
                          deadline: DispatchTime, checkCurrent: () throws -> Void) throws
}
extension VPNDarwinRouteSocket: VPNFencedHostKernel {}

/// Synchronous custody transaction, NOT a DNS answer authority. Caller must hold
/// its resource/generation/lifecycle lease through the final answer transaction.
/// Known-IP records survive TTL, revocation, service exit and new generations.
final class VPNExactFenceTransaction {
    private let store: VPNExactFenceStore
    private let kernel: VPNExactFenceKernel
    init(store: VPNExactFenceStore, kernel: VPNExactFenceKernel) { self.store = store; self.kernel = kernel }

    func ensure(_ identity: VPNExactRouteFenceIdentity, claim: VPNExactFenceClaim,
                deadline: DispatchTime, checkCurrent: () throws -> Void) throws -> VPNExactFenceEntry {
        try store.exclusive {
            try current(deadline,checkCurrent); try identity.validate(); try claim.validate()
            let old = try store.load(identity.address)
            if let old {
                guard old.identity == identity, old.phase != .releasing else { throw VPNExactFenceStoreError.recoveryRequired }
            }
            var claims = old?.phase == .retired ? [] : old?.claims ?? []
            if let index = claims.firstIndex(where: { $0.resourceID == claim.resourceID }) {
                let previous = claims[index]
                guard claim.generation > previous.generation || (claim.generation == previous.generation && claim.revision >= previous.revision) else { throw VPNExactFenceStoreError.stale }
                claims[index] = claim
            } else { claims.append(claim) }
            claims.sort()
            let observed = try kernel.lookupExactFence(identity,deadline:deadline)
            try current(deadline,checkCurrent)
            if let old, old.phase == .applied, let observed {
                guard identity.matches(observed) else { throw VPNDarwinRouteError.missingOrForeign }
                let next = old.changing(phase:.applied,claims:claims)
                if next != old { try store.save(next,replacing:old) }
                try current(deadline,checkCurrent); return next
            }
            // Equal-looking foreign or indeterminate ADD results are not adopted.
            guard observed == nil else { throw VPNExactFenceStoreError.recoveryRequired }
            let intent = VPNExactFenceEntry(schemaVersion:old?.schemaVersion ?? VPNExactFenceEntry.schema,
                installationID:UUID(),identity:identity,phase:.adding,claims:claims,active:old?.active)
            try current(deadline,checkCurrent); try store.save(intent,replacing:old)
            try current(deadline,checkCurrent)
            try kernel.installExactFence(identity,deadline:deadline)
            try current(deadline,checkCurrent)
            guard let installed = try kernel.lookupExactFence(identity,deadline:deadline), identity.matches(installed) else { throw VPNDarwinRouteError.verificationFailed }
            try current(deadline,checkCurrent)
            let applied = intent.changing(phase:.applied)
            try store.save(applied,replacing:intent)
            try current(deadline,checkCurrent); return applied
        }
    }

    /// Restore ALL retained denies before publishing any resolver/bridge listener.
    /// This restores protection only, never active routes or DNS answer permits.
    /// A blocked entry does not prevent protecting other known addresses, but
    /// any failure prevents a successful startup result. Unknown present ADDs
    /// are retained and blocked; they are never adopted as confirmed custody.
    func restoreRetained(deadline: DispatchTime, checkOwner: () throws -> Void) throws -> [VPNExactFenceEntry] {
        try store.exclusive {
            try current(deadline,checkOwner)
            let entries = try store.entries()
            var restored = [VPNExactFenceEntry](), failure: Error?
            for entry in entries where entry.phase != .retired {
                try current(deadline,checkOwner)
                do {
                    if entry.phase == .releasing {
                        _ = try retire(entry,deadline:deadline,checkCurrent:checkOwner)
                    } else {
                        let value = try ensure(entry.identity,claim:entry.claims[0],deadline:deadline,checkCurrent:checkOwner)
                        restored.append(try withdrawHost(value,deadline:deadline,checkCurrent:checkOwner))
                    }
                } catch { if failure == nil { failure = error } }
                // Owner/cancellation/deadline failure aborts immediately. A
                // route-specific failure may still leave other denies missing.
                try current(deadline,checkOwner)
            }
            if let failure { throw failure }
            // Earlier entries must still be live after the whole recovery pass.
            for entry in restored {
                try current(deadline,checkOwner)
                guard let observed = try kernel.lookupExactFence(entry.identity,deadline:deadline),
                      entry.identity.matches(observed) else { throw VPNDarwinRouteError.verificationFailed }
            }
            try current(deadline,checkOwner); return restored
        }
    }

    /// Active HOST custody is independent from the retained deny. The same
    /// private store lock orders journal and native operations; callbacks must
    /// not acquire a route socket before this store (no inverse lock ordering).
    func activateHost(_ expected: VPNExactFenceEntry, identity: VPNOwnedRouteIdentity,
                      claim: VPNExactFenceClaim, deadline: DispatchTime,
                      checkCurrent: () throws -> Void) throws -> VPNExactFenceEntry {
        try store.exclusive {
            try current(deadline,checkCurrent); try expected.validate()
            guard try store.load(expected.identity.address) == expected,
                  expected.phase == .applied, expected.claims.contains(claim),
                  let native = kernel as? VPNFencedHostKernel else { throw VPNExactFenceStoreError.stale }
            let proposed = VPNFencedHostEntry(identity:identity,claim:claim,phase:.applied)
            try proposed.validate(address:expected.identity.address)
            if let active = expected.active {
                guard active == proposed else { throw VPNExactFenceStoreError.recoveryRequired }
                try verifyHost(expected,deadline:deadline,checkCurrent:checkCurrent)
                return expected
            }
            guard try native.lookupFencedHost(identity,fence:expected.identity,deadline:deadline) == nil else {
                throw VPNDarwinRouteError.preexistingNonIdentical
            }
            try current(deadline,checkCurrent)
            let intent = expected.changingActive(VPNFencedHostEntry(identity:identity,claim:claim,phase:.installing))
            try store.save(intent,replacing:expected)
            try current(deadline,checkCurrent)
            try native.installFencedHost(identity,fence:expected.identity,deadline:deadline,
                checkCurrent:{ try self.current(deadline,checkCurrent) })
            try current(deadline,checkCurrent)
            guard let observed = try native.lookupFencedHost(identity,fence:expected.identity,deadline:deadline),
                  observed.matches(identity) else { throw VPNDarwinRouteError.verificationFailed }
            try current(deadline,checkCurrent)
            let applied = intent.changingActive(proposed)
            try store.save(applied,replacing:intent)
            try current(deadline,checkCurrent); return applied
        }
    }

    func verifyHost(_ expected: VPNExactFenceEntry, deadline: DispatchTime,
                    checkCurrent: () throws -> Void) throws {
        try store.exclusive {
            try current(deadline,checkCurrent); try expected.validate()
            guard try store.load(expected.identity.address) == expected,
                  expected.phase == .applied, let active = expected.active, active.phase == .applied,
                  let native = kernel as? VPNFencedHostKernel else { throw VPNExactFenceStoreError.stale }
            guard let observed = try native.lookupFencedHost(active.identity,fence:expected.identity,deadline:deadline),
                  observed.matches(active.identity) else { throw VPNDarwinRouteError.verificationFailed }
            try current(deadline,checkCurrent)
        }
    }

    /// Disconnect/recovery withdraws only confirmed active custody; it NEVER
    /// releases claims or the NET deny. Unknown writes can finish from proved
    /// absence only. A matching-looking unknown present route is not adopted.
    func withdrawHost(_ expected: VPNExactFenceEntry, deadline: DispatchTime,
                      checkCurrent: () throws -> Void) throws -> VPNExactFenceEntry {
        try store.exclusive {
            try current(deadline,checkCurrent); try expected.validate()
            guard try store.load(expected.identity.address) == expected, expected.phase == .applied else {
                throw VPNExactFenceStoreError.stale
            }
            guard let deny = try kernel.lookupExactFence(expected.identity,deadline:deadline),
                  expected.identity.matches(deny) else { throw VPNDarwinRouteError.missingOrForeign }
            try current(deadline,checkCurrent)
            guard let active = expected.active else { return expected }
            guard let native = kernel as? VPNFencedHostKernel else { throw VPNExactFenceStoreError.recoveryRequired }
            let observed = try native.lookupFencedHost(active.identity,fence:expected.identity,deadline:deadline)
            try current(deadline,checkCurrent)
            var intent = expected
            if let observed {
                guard observed.matches(active.identity) else { throw VPNDarwinRouteError.missingOrForeign }
                guard active.phase == .applied else { throw VPNExactFenceStoreError.recoveryRequired }
                intent = expected.changingActive(VPNFencedHostEntry(identity:active.identity,claim:active.claim,phase:.removing))
                try store.save(intent,replacing:expected)
                try current(deadline,checkCurrent)
                try native.deleteFencedHost(active.identity,fence:expected.identity,deadline:deadline,
                    checkCurrent:{ try self.current(deadline,checkCurrent) })
                try current(deadline,checkCurrent)
            }
            guard try native.lookupFencedHost(active.identity,fence:expected.identity,deadline:deadline) == nil else {
                throw VPNDarwinRouteError.verificationFailed
            }
            try current(deadline,checkCurrent)
            let cleared = intent.changingActive(nil)
            try store.save(cleared,replacing:intent)
            try current(deadline,checkCurrent); return cleared
        }
    }

    /// Remove only explicitly released references. Shared addresses stay fenced
    /// until their LAST exact claim is released under the caller's policy lease.
    func releaseClaims(_ expected: VPNExactFenceEntry, removing: [VPNExactFenceClaim],
                       deadline: DispatchTime, checkCurrent: () throws -> Void) throws -> VPNExactFenceEntry {
        try store.exclusive {
            try current(deadline,checkCurrent); try expected.validate()
            guard !removing.isEmpty, Set(removing.map(\.resourceID)).count == removing.count,
                  removing.allSatisfy(expected.claims.contains) else { throw VPNExactFenceStoreError.invalidState }
            guard try store.load(expected.identity.address) == expected,
                  expected.phase == .applied else { throw VPNExactFenceStoreError.stale }
            if let active = expected.active, removing.contains(active.claim) {
                throw VPNExactFenceStoreError.recoveryRequired
            }
            let remaining = expected.claims.filter { !removing.contains($0) }
            if remaining.isEmpty { return try retire(expected,deadline:deadline,checkCurrent:checkCurrent) }
            guard let observed = try kernel.lookupExactFence(expected.identity,deadline:deadline),
                  expected.identity.matches(observed) else { throw VPNDarwinRouteError.missingOrForeign }
            try current(deadline,checkCurrent)
            let next = expected.changing(phase:.applied,claims:remaining)
            try store.save(next,replacing:expected)
            try current(deadline,checkCurrent); return next
        }
    }

    /// Explicit policy release only. Caller must authorize ALL exact claims in
    /// expected; never invoke for TTL, negative replies, disconnect or revocation.
    /// A release that timed out may be completed only after confirmed absence.
    func retire(_ expected: VPNExactFenceEntry, deadline: DispatchTime,
                checkCurrent: () throws -> Void) throws -> VPNExactFenceEntry {
        try store.exclusive {
            try current(deadline,checkCurrent); try expected.validate()
            guard let old = try store.load(expected.identity.address), old == expected,
                  old.phase == .applied || old.phase == .releasing else { throw VPNExactFenceStoreError.stale }
            guard old.active == nil else { throw VPNExactFenceStoreError.recoveryRequired }
            let observed = try kernel.lookupExactFence(old.identity,deadline:deadline)
            try current(deadline,checkCurrent)
            if old.phase == .releasing {
                guard observed == nil else { throw VPNExactFenceStoreError.recoveryRequired }
            } else if let observed {
                guard old.identity.matches(observed) else { throw VPNDarwinRouteError.missingOrForeign }
            }
            let intent = old.changing(phase:.releasing)
            if intent != old { try store.save(intent,replacing:old) }
            try current(deadline,checkCurrent)
            if observed != nil { try kernel.deleteExactFence(old.identity,deadline:deadline) }
            try current(deadline,checkCurrent)
            guard try kernel.lookupExactFence(old.identity,deadline:deadline) == nil else { throw VPNDarwinRouteError.verificationFailed }
            try current(deadline,checkCurrent)
            let retired = intent.changing(phase:.retired)
            try store.save(retired,replacing:intent)
            try current(deadline,checkCurrent); return retired
        }
    }
    private func current(_ deadline: DispatchTime, _ check: () throws -> Void) throws {
        guard DispatchTime.now().uptimeNanoseconds < deadline.uptimeNanoseconds else { throw VPNDarwinRouteError.timeout }
        try store.checkOwner()
        try check()
        try store.checkOwner()
        guard DispatchTime.now().uptimeNanoseconds < deadline.uptimeNanoseconds else { throw VPNDarwinRouteError.timeout }
    }
}
