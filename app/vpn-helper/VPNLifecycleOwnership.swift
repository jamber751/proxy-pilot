import Darwin

enum VPNLifecycleOwnershipError: Error { case unsafeStorage, busy, lost }

/// Cross-process exclusive ownership of one helper lifecycle, held for the whole
/// lifetime of a supervisor. The coordinator's instance gate cannot stop a second
/// process from stopping or starting the same service; this can. It is NOT the
/// store's per-transaction disk lock, NOT an authorization to run a release and
/// NOT evidence that a helper is running or still owned at any later moment.
/// The kernel releases the lock when the owning process exits, including a crash.
final class VPNLifecycleLease {
    fileprivate static let name = "lifecycle.lock"
    private var directory: Int32
    private var lock: Int32

    fileprivate init(directory: Int32, lock: Int32) {
        self.directory = directory
        self.lock = lock
    }

    deinit { release() }

    /// Fail-closed recheck before every lifecycle action: our descriptor is still
    /// open and the protected directory still resolves this exact file. A replaced
    /// or unlinked lock means another supervisor may already own the service, so
    /// the caller must stop instead of recreating the lock and continuing.
    func check() throws {
        guard lock >= 0, directory >= 0 else { throw VPNLifecycleOwnershipError.lost }
        var held = stat(), named = stat()
        guard fstat(lock, &held) == 0,
              fstatat(directory, VPNLifecycleLease.name, &named, AT_SYMLINK_NOFOLLOW) == 0,
              held.st_dev == named.st_dev, held.st_ino == named.st_ino else {
            throw VPNLifecycleOwnershipError.lost
        }
        do { try VPNLifecycleOwnership.checkLockFile(lock) }
        catch { throw VPNLifecycleOwnershipError.lost }
    }

    func release() {
        if lock >= 0 { flock(lock, LOCK_UN); close(lock); lock = -1 }
        if directory >= 0 { close(directory); directory = -1 }
    }
}

/// Descriptor-relative, like the store: production must pass a securely opened
/// root-owned directory under fixed protected parents. Never accept this
/// descriptor from IPC and never fall back to a user-writable location.
enum VPNLifecycleOwnership {
    static func acquire(inTrustedDirectory trusted: Int32) throws -> VPNLifecycleLease {
        let directory = fcntl(trusted, F_DUPFD_CLOEXEC, 0)
        guard directory >= 0 else { throw VPNLifecycleOwnershipError.unsafeStorage }
        do {
            try checkDirectory(directory)
            let lock = openat(directory, VPNLifecycleLease.name,
                              O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK, 0o600)
            guard lock >= 0 else { throw VPNLifecycleOwnershipError.unsafeStorage }
            do {
                try checkLockFile(lock)
                guard flock(lock, LOCK_EX | LOCK_NB) == 0 else {
                    throw errno == EWOULDBLOCK ? VPNLifecycleOwnershipError.busy
                                               : VPNLifecycleOwnershipError.unsafeStorage
                }
                // Only after taking the lock: prove the directory still names this
                // exact file. A racing writer could have replaced it in between,
                // which would let a second supervisor lock the new file instead.
                let lease = VPNLifecycleLease(directory: directory, lock: lock)
                do { try lease.check() }
                catch { throw VPNLifecycleOwnershipError.busy }
                return lease
            } catch { close(lock); throw error }
        } catch { close(directory); throw error }
    }

    private static func checkDirectory(_ descriptor: Int32) throws {
        var attributes = stat(), filesystem = statfs()
        guard fstat(descriptor, &attributes) == 0, attributes.st_mode & S_IFMT == S_IFDIR,
              attributes.st_nlink > 0, attributes.st_uid == geteuid(),
              attributes.st_mode & 0o7777 == 0o700,
              fstatfs(descriptor, &filesystem) == 0, filesystem.f_flags & UInt32(MNT_LOCAL) != 0 else {
            throw VPNLifecycleOwnershipError.unsafeStorage
        }
        try checkNoACL(descriptor)
    }

    fileprivate static func checkLockFile(_ file: Int32) throws {
        var attributes = stat()
        guard fstat(file, &attributes) == 0, attributes.st_mode & S_IFMT == S_IFREG,
              attributes.st_nlink == 1, attributes.st_uid == geteuid(),
              attributes.st_mode & 0o7777 == 0o600 else {
            throw VPNLifecycleOwnershipError.unsafeStorage
        }
        try checkNoACL(file)
    }

    // Fail closed on any ACL entry; an absent ACL property is not an error.
    private static func checkNoACL(_ file: Int32) throws {
        guard let security = filesec_init() else { throw VPNLifecycleOwnershipError.unsafeStorage }
        defer { filesec_free(security) }
        var attributes = stat()
        guard fstatx_np(file, &attributes, security) == 0 else { throw VPNLifecycleOwnershipError.unsafeStorage }
        var retrieved: acl_t?
        errno = 0
        let result = filesec_get_property(security, FILESEC_ACL, &retrieved)
        if result == -1, errno == ENOENT { return }
        guard result == 0, let acl = retrieved else { throw VPNLifecycleOwnershipError.unsafeStorage }
        defer { acl_free(UnsafeMutableRawPointer(acl)) }
        var entry: acl_entry_t?
        errno = 0
        guard acl_get_entry(acl, Int32(ACL_FIRST_ENTRY.rawValue), &entry) == -1, errno == EINVAL else {
            throw VPNLifecycleOwnershipError.unsafeStorage
        }
    }
}
