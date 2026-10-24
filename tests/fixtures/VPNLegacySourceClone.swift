import Darwin
import Foundation

enum VPNLegacySourceCloneError: Error {
    case requiresRoot, unsafeStorage, occupiedDestination, cloneUnavailable, incomplete
}

/// Experimental test fixture ONLY: does not publish an app, launch an executor, change
/// a journal/selector, or repair a pending update. No production role calls this.
/// A future caller must retain service→Update leases, authenticate the exact
/// pending transaction, and supply a fresh root-private destination under trusted
/// ancestors. Publication, durable migration authority and crash recovery are
/// intentionally absent; this primitive must not be wired to an installer alone.
enum VPNLegacySourceClone {
    private static let app = "ProxyPilot.app"

    @available(*, unavailable, message: "Durable migration authority and resume protocol are not implemented.")
    static func prepare(inApplicationsDirectory source: Int32,
                        protectedDestination destination: Int32,
                        release: VerifiedVPNRelease,
                        authorizedOwner: uid_t) throws {
        try perform(source: source, destination: destination, release: release,
                    owner: authorizedOwner, productionSource: true, checkpoint: { _ in })
    }

    #if VPN_LEGACY_SOURCE_CLONE_TESTING
    static func testPrepare(source: Int32, destination: Int32,
                            release: VerifiedVPNRelease, authorizedOwner: uid_t,
                            checkpoint: (String) throws -> Void = { _ in }) throws {
        try perform(source: source, destination: destination, release: release,
                    owner: authorizedOwner, productionSource: false, checkpoint: checkpoint)
    }
    #endif

    private static func perform(source: Int32, destination: Int32,
                                release: VerifiedVPNRelease, owner: uid_t,
                                productionSource: Bool,
                                checkpoint: (String) throws -> Void) throws {
        guard getuid() == 0, geteuid() == 0 else { throw VPNLegacySourceCloneError.requiresRoot }
        _ = try VPNStagedApplication.updateSourceOwner(observed: 0, authorizedUser: owner)
        try privateDirectory(destination)
        let original = try VPNStagedApplication.inspectInstalled(
            inApplicationsDirectory: source, ownerUserID: 0,
            productionParent: productionSource, release: release)
        try separateDestination(source: source, destination: destination)
        guard try names(destination).isEmpty else { throw VPNLegacySourceCloneError.occupiedDestination }
        try VPNStagedApplication.revalidate(original, inTrustedDirectory: source)
        // Fixed names and descriptor-relative clone, no shell or pathname walk.
        // Source inspection proved every owner is root. Preserve its groups;
        // only the private copy's UID is deliberately normalized below.
        let basic = UInt32(CLONE_NOFOLLOW)
        var result = clonefileat(source, app, destination, app, basic | 0x0010)
        if result != 0, errno == EINVAL {
            var value = stat()
            guard fstatat(destination, app, &value, AT_SYMLINK_NOFOLLOW) != 0,
                  errno == ENOENT else { throw VPNLegacySourceCloneError.unsafeStorage }
            result = clonefileat(source, app, destination, app, basic)
        }
        guard result == 0 else { throw VPNLegacySourceCloneError.cloneUnavailable }
        // Any failure leaves the private copy for the future transaction owner.
        // No implicit cleanup/resume may trust a partially normalized tree.
        try checkpoint("afterClone")
        try VPNStagedApplication.requireExclusiveBundle(inTrustedDirectory: destination)
        _ = try VPNStagedApplication.inspect(inTrustedDirectory: destination, release: release)
        var entries = 10_000
        try normalize(parent: destination, name: app, owner: owner, depth: 0,
                      remaining: &entries, checkpoint: checkpoint)
        try privateDirectory(destination)
        try VPNStagedApplication.requireExclusiveBundle(inTrustedDirectory: destination)
        let copied = try VPNStagedApplication.inspectProtected(
            inTrustedDirectory: destination, contentOwnerUserID: owner, release: release)
        try VPNStagedApplication.synchronize(copied, inTrustedDirectory: destination)
        try VPNStagedApplication.revalidate(original, inTrustedDirectory: source)
        try VPNStagedApplication.revalidate(copied, inTrustedDirectory: destination)
        guard fsync(destination) == 0 else { throw VPNLegacySourceCloneError.incomplete }
    }

    private static func normalize(parent: Int32, name: String, owner: uid_t, depth: Int,
                                  remaining: inout Int,
                                  checkpoint: (String) throws -> Void) throws {
        guard depth <= 48, remaining > 0 else { throw VPNLegacySourceCloneError.unsafeStorage }
        remaining -= 1
        var before = stat()
        guard fstatat(parent, name, &before, AT_SYMLINK_NOFOLLOW) == 0,
              before.st_uid == 0 else { throw VPNLegacySourceCloneError.unsafeStorage }
        let type = before.st_mode & S_IFMT
        if type == S_IFLNK {
            guard before.st_nlink == 1,
                  fchownat(parent, name, owner, gid_t.max, AT_SYMLINK_NOFOLLOW) == 0 else {
                throw VPNLegacySourceCloneError.unsafeStorage
            }
        } else {
            guard type == S_IFDIR || type == S_IFREG,
                  type != S_IFREG || before.st_nlink == 1 else {
                throw VPNLegacySourceCloneError.unsafeStorage
            }
            let fd = openat(parent, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC
                            | (type == S_IFDIR ? O_DIRECTORY : 0))
            guard fd >= 0 else { throw VPNLegacySourceCloneError.unsafeStorage }
            defer { close(fd) }
            var held = stat()
            guard fstat(fd, &held) == 0, same(before, held) else {
                throw VPNLegacySourceCloneError.unsafeStorage
            }
            if type == S_IFDIR {
                for child in try names(fd) {
                    try normalize(parent: fd, name: child, owner: owner, depth: depth + 1,
                                  remaining: &remaining, checkpoint: checkpoint)
                }
            }
            guard fchown(fd, owner, gid_t.max) == 0, fsync(fd) == 0 else {
                throw VPNLegacySourceCloneError.incomplete
            }
        }
        var after = stat()
        guard fstatat(parent, name, &after, AT_SYMLINK_NOFOLLOW) == 0,
              same(before, after), after.st_uid == owner,
              before.st_mode == after.st_mode, before.st_gid == after.st_gid else {
            throw VPNLegacySourceCloneError.unsafeStorage
        }
        try checkpoint("afterOwnershipChange")
    }

    private static func same(_ a: stat, _ b: stat) -> Bool {
        a.st_dev == b.st_dev && a.st_ino == b.st_ino && a.st_mode & S_IFMT == b.st_mode & S_IFMT
    }

    private static func separateDestination(source: Int32, destination: Int32) throws {
        var bundle = stat(), originalParent = stat(), current = stat()
        guard fstatat(source, app, &bundle, AT_SYMLINK_NOFOLLOW) == 0,
              fstat(source, &originalParent) == 0,
              fstat(destination, &current) == 0, current.st_dev == bundle.st_dev,
              !same(current, originalParent) else { throw VPNLegacySourceCloneError.unsafeStorage }
        var cursor = fcntl(destination, F_DUPFD_CLOEXEC, 0)
        guard cursor >= 0 else { throw VPNLegacySourceCloneError.unsafeStorage }
        defer { close(cursor) }
        // Explicitly reject a destination inside the source bundle: even an
        // empty unsealed directory must never turn this into a source mutation.
        for _ in 0..<128 {
            guard fstat(cursor, &current) == 0, !same(current, bundle) else {
                throw VPNLegacySourceCloneError.unsafeStorage
            }
            let parent = openat(cursor, "..", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard parent >= 0 else { throw VPNLegacySourceCloneError.unsafeStorage }
            var up = stat()
            guard fstat(parent, &up) == 0 else { close(parent); throw VPNLegacySourceCloneError.unsafeStorage }
            if same(current, up) { close(parent); return }
            close(cursor); cursor = parent
        }
        throw VPNLegacySourceCloneError.unsafeStorage
    }

    private static func privateDirectory(_ fd: Int32) throws {
        var value = stat(), fs = statfs()
        guard fstat(fd, &value) == 0, value.st_uid == 0,
              value.st_mode & S_IFMT == S_IFDIR, value.st_mode & 0o7777 == 0o700,
              value.st_nlink > 0, fstatfs(fd, &fs) == 0, fs.f_flags & UInt32(MNT_LOCAL) != 0,
              let security = filesec_init() else { throw VPNLegacySourceCloneError.unsafeStorage }
        defer { filesec_free(security) }
        guard fstatx_np(fd, &value, security) == 0 else { throw VPNLegacySourceCloneError.unsafeStorage }
        var retrieved: acl_t?
        errno = 0
        let result = filesec_get_property(security, FILESEC_ACL, &retrieved)
        if result == -1, errno == ENOENT { return }
        guard result == 0, let acl = retrieved else { throw VPNLegacySourceCloneError.unsafeStorage }
        defer { acl_free(UnsafeMutableRawPointer(acl)) }
        var entry: acl_entry_t?
        errno = 0
        guard acl_get_entry(acl, Int32(ACL_FIRST_ENTRY.rawValue), &entry) == -1,
              errno == EINVAL else { throw VPNLegacySourceCloneError.unsafeStorage }
    }

    private static func names(_ fd: Int32) throws -> [String] {
        let copy = openat(fd, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard copy >= 0 else { throw VPNLegacySourceCloneError.unsafeStorage }
        guard let stream = fdopendir(copy) else { close(copy); throw VPNLegacySourceCloneError.unsafeStorage }
        defer { closedir(stream) }
        var result: [String] = []
        let offset = MemoryLayout<dirent>.offset(of: \.d_name)!
        while true {
            errno = 0
            guard let row = readdir(stream) else {
                guard errno == 0 else { throw VPNLegacySourceCloneError.unsafeStorage }
                return result.sorted()
            }
            let length = Int(row.pointee.d_namlen)
            guard length > 0, length < 1024, offset + length < Int(row.pointee.d_reclen) else {
                throw VPNLegacySourceCloneError.unsafeStorage
            }
            let bytes = UnsafeRawPointer(row).advanced(by: offset).assumingMemoryBound(to: UInt8.self)
            guard bytes[length] == 0,
                  let name = String(bytes: UnsafeBufferPointer(start: bytes, count: length), encoding: .utf8),
                  !name.contains("/"), !name.utf8.contains(0) else { throw VPNLegacySourceCloneError.unsafeStorage }
            if name == "." || name == ".." { continue }
            guard result.count < 10_000 else { throw VPNLegacySourceCloneError.unsafeStorage }
            result.append(name)
        }
    }
}
