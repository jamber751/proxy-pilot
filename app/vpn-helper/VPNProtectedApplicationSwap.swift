import Darwin
import Foundation

enum VPNApplicationSwapError: Error {
    case requiresRoot, invalidTransition, unsafeStorage, invalidLayout, unsafeExecutor
    case exchangeFailed, commitUncertain
}

/// Internal, protected-namespace exchange ONLY. This is not an Applications
/// installer or an installed/live-B proof. The caller must provision durable,
/// root-private staging under protected ancestors and authenticate its separate
/// executor. It must also retain real service ownership, check the journal and
/// drain at the authorization boundary. This namespace lease does not supply those guarantees.
/// No IPC, CLI, Sparkle, selector or service entry calls this primitive.
enum VPNProtectedApplicationSwap {
    enum Outcome { case exchanged, alreadyExchanged }
    private static let app = "ProxyPilot.app"

    static func exchange(inTrustedDirectory base: Int32, previous: VerifiedVPNRelease,
                         candidate: VerifiedVPNRelease, transition: VerifiedVPNUpdateTransition,
                         authorizeMutation: () throws -> Void) throws -> Outcome {
        guard getuid() == 0, geteuid() == 0 else { throw VPNApplicationSwapError.requiresRoot }
        return try perform(base: base, previous: previous, candidate: candidate, transition: transition,
                           requireProtectedExecutor: true, authorizeMutation: authorizeMutation, checkpoint: { _ in })
    }

    #if VPN_APPLICATION_SWAP_TESTING
    static func testExchange(inTrustedDirectory base: Int32, previous: VerifiedVPNRelease,
                             candidate: VerifiedVPNRelease, transition: VerifiedVPNUpdateTransition,
                             requireProtectedExecutor: Bool = false,
                             authorizeMutation: () throws -> Void = {},
                             checkpoint: (String) throws -> Void = { _ in }) throws -> Outcome {
        try perform(base: base, previous: previous, candidate: candidate, transition: transition,
                    requireProtectedExecutor: requireProtectedExecutor,
                    authorizeMutation: authorizeMutation, checkpoint: checkpoint)
    }
    #endif

    private struct Identity: Equatable {
        let device: dev_t
        let inode: ino_t
        init(_ value: stat) { device = value.st_dev; inode = value.st_ino }
    }

    private static func perform(base: Int32, previous: VerifiedVPNRelease, candidate: VerifiedVPNRelease,
                                transition: VerifiedVPNUpdateTransition,
                                requireProtectedExecutor: Bool,
                                authorizeMutation: () throws -> Void,
                                checkpoint: (String) throws -> Void) throws -> Outcome {
        guard transition.matchesSource(previous), transition.matchesDestination(candidate),
              !previous.isSameRelease(as: candidate) else { throw VPNApplicationSwapError.invalidTransition }
        // Identical app artifacts cannot encode swap direction, even if their
        // helper/release sequences differ. Such updates need a different path.
        guard previous.appHash(forArchitecture: "arm64") != candidate.appHash(forArchitecture: "arm64") ||
                previous.appHash(forArchitecture: "x86_64") != candidate.appHash(forArchitecture: "x86_64") else {
            throw VPNApplicationSwapError.invalidTransition
        }
        let lease = try VPNLifecycleOwnership.acquire(inTrustedDirectory: base)
        defer { lease.release() }
        let current = openat(base, "current", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard current >= 0 else { throw VPNApplicationSwapError.unsafeStorage }
        defer { close(current) }
        let staged = openat(base, "candidate", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard staged >= 0 else { throw VPNApplicationSwapError.unsafeStorage }
        defer { close(staged) }
        // Production always binds the running A to a separate protected slot.
        // The opt-out exists only for the primitive's inert test fixtures.
        try lease.check()
        try checkSlots(base: base, current: current, staged: staged)
        let executor = requireProtectedExecutor
            ? try VPNReplacementExecutor.inspect(inTrustedDirectory: base, release: previous) : nil

        func check() throws {
            try lease.check()
            try checkSlots(base: base, current: current, staged: staged)
            try excludeCurrentExecutor(current: current, staged: staged)
            try executor?.revalidate()
        }
        try check()
        let before = matches(current, previous) && matches(staged, candidate)
        let after = matches(current, candidate) && matches(staged, previous)
        guard before != after else { throw VPNApplicationSwapError.invalidLayout }
        if after {
            // A previous call may have died after rename. Never exchange back.
            do {
                try authorizeMutation()
                try check()
                guard matches(current, candidate), matches(staged, previous) else {
                    throw VPNApplicationSwapError.invalidLayout
                }
                try sync(current, staged)
            } catch { throw VPNApplicationSwapError.commitUncertain }
            return .alreadyExchanged
        }

        let oldCurrent = try childIdentity(current), oldStaged = try childIdentity(staged)
        let oldObservation = try VPNStagedApplication.inspect(inTrustedDirectory: current, release: previous)
        let newObservation = try VPNStagedApplication.inspect(inTrustedDirectory: staged, release: candidate)
        try checkpoint("beforeExchange")
        try check()
        try VPNStagedApplication.revalidate(oldObservation, inTrustedDirectory: current)
        try VPNStagedApplication.revalidate(newObservation, inTrustedDirectory: staged)
        try authorizeMutation()
        // Draining can take time. Recheck both namespace ownership and the
        // complete trees after authorization, not just before the callback.
        try check()
        try VPNStagedApplication.revalidate(oldObservation, inTrustedDirectory: current)
        try VPNStagedApplication.revalidate(newObservation, inTrustedDirectory: staged)
        // RENAME_SWAP is one same-filesystem namespace operation. Refuse any
        // failure, including EXDEV/unsupported; never fall back to two renames.
        guard renameatx_np(current, app, staged, app, UInt32(RENAME_SWAP)) == 0 else {
            throw VPNApplicationSwapError.exchangeFailed
        }
        do {
            try checkpoint("afterExchange")
            try sync(current, staged)
            try checkpoint("afterSync")
            try check()
            guard try childIdentity(current) == oldStaged, try childIdentity(staged) == oldCurrent,
                  matches(current, candidate), matches(staged, previous) else {
                throw VPNApplicationSwapError.invalidLayout
            }
        } catch {
            // The namespace has changed. No inverse exchange, deletion or
            // selector rollback is safe here; retry inspects the exact B/A pair.
            throw VPNApplicationSwapError.commitUncertain
        }
        return .exchanged
    }

    private static func matches(_ parent: Int32, _ release: VerifiedVPNRelease) -> Bool {
        (try? VPNStagedApplication.inspect(inTrustedDirectory: parent, release: release)) != nil
    }

    private static func sync(_ current: Int32, _ staged: Int32) throws {
        guard fsync(current) == 0, fsync(staged) == 0 else { throw VPNApplicationSwapError.commitUncertain }
    }

    private static func childIdentity(_ parent: Int32) throws -> Identity {
        var value = stat()
        guard fstatat(parent, app, &value, AT_SYMLINK_NOFOLLOW) == 0,
              value.st_mode & S_IFMT == S_IFDIR else { throw VPNApplicationSwapError.invalidLayout }
        return Identity(value)
    }

    private static func checkSlots(base: Int32, current: Int32, staged: Int32) throws {
        for fd in [base, current, staged] { try checkPrivateDirectory(fd) }
        var root = stat(), a = stat(), b = stat()
        guard fstat(base, &root) == 0, fstat(current, &a) == 0, fstat(staged, &b) == 0,
              a.st_dev == root.st_dev, b.st_dev == root.st_dev, Identity(a) != Identity(b) else {
            throw VPNApplicationSwapError.unsafeStorage
        }
        for (name, fd, attributes) in [("current", current, a), ("candidate", staged, b)] {
            var named = stat()
            guard attributes.st_mode & S_IFMT == S_IFDIR, attributes.st_uid == geteuid(),
                  attributes.st_mode & 0o7777 == 0o700, attributes.st_nlink > 0,
                  fstatat(base, name, &named, AT_SYMLINK_NOFOLLOW) == 0,
                  Identity(named) == Identity(attributes), named.st_mode & S_IFMT == S_IFDIR else {
                throw VPNApplicationSwapError.unsafeStorage
            }
            try checkSingleChild(fd)
        }
    }

    private static func checkPrivateDirectory(_ fd: Int32) throws {
        var value = stat(), fs = statfs()
        guard fstat(fd, &value) == 0, value.st_mode & S_IFMT == S_IFDIR,
              value.st_mode & 0o7777 == 0o700, value.st_uid == geteuid(), value.st_nlink > 0,
              fstatfs(fd, &fs) == 0, fs.f_flags & UInt32(MNT_LOCAL) != 0,
              let security = filesec_init() else { throw VPNApplicationSwapError.unsafeStorage }
        defer { filesec_free(security) }
        guard fstatx_np(fd, &value, security) == 0 else { throw VPNApplicationSwapError.unsafeStorage }
        var retrieved: acl_t?
        errno = 0
        let result = filesec_get_property(security, FILESEC_ACL, &retrieved)
        if result == -1, errno == ENOENT { return }
        guard result == 0, let acl = retrieved else { throw VPNApplicationSwapError.unsafeStorage }
        defer { acl_free(UnsafeMutableRawPointer(acl)) }
        var entry: acl_entry_t?
        errno = 0
        guard acl_get_entry(acl, Int32(ACL_FIRST_ENTRY.rawValue), &entry) == -1, errno == EINVAL else {
            throw VPNApplicationSwapError.unsafeStorage
        }
    }

    private static func checkSingleChild(_ directory: Int32) throws {
        let fd = openat(directory, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw VPNApplicationSwapError.unsafeStorage }
        guard let stream = fdopendir(fd) else { close(fd); throw VPNApplicationSwapError.unsafeStorage }
        defer { closedir(stream) }
        let offset = MemoryLayout<dirent>.offset(of: \.d_name)!
        var count = 0
        while true {
            errno = 0
            guard let entry = readdir(stream) else {
                guard errno == 0, count == 1 else { throw VPNApplicationSwapError.invalidLayout }
                return
            }
            let length = Int(entry.pointee.d_namlen)
            guard length > 0, length < Int(MAXPATHLEN), offset + length < Int(entry.pointee.d_reclen) else {
                throw VPNApplicationSwapError.invalidLayout
            }
            let start = UnsafeRawPointer(entry).advanced(by: offset).assumingMemoryBound(to: UInt8.self)
            let bytes = UnsafeBufferPointer(start: start, count: length)
            guard start[length] == 0, let name = String(bytes: bytes, encoding: .utf8) else {
                throw VPNApplicationSwapError.invalidLayout
            }
            if name == "." || name == ".." { continue }
            guard name == app, count == 0 else { throw VPNApplicationSwapError.invalidLayout }
            count += 1
        }
    }

    private static func excludeCurrentExecutor(current: Int32, staged: Int32) throws {
        // PROC_PIDPATHINFO_MAXSIZE is 4*MAXPATHLEN in the local SDK; the
        // expression macro is not imported by Swift.
        var bytes = [UInt8](repeating: 0, count: 4 * Int(MAXPATHLEN))
        let length = bytes.withUnsafeMutableBytes { proc_pidpath(getpid(), $0.baseAddress!, UInt32($0.count)) }
        guard length > 0, let end = bytes.firstIndex(of: 0), end > 0,
              let path = String(bytes: bytes[..<end], encoding: .utf8), path.hasPrefix("/") else {
            throw VPNApplicationSwapError.unsafeExecutor
        }
        let executable = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard executable >= 0 else { throw VPNApplicationSwapError.unsafeExecutor }
        defer { close(executable) }
        var executableInfo = stat()
        guard fstat(executable, &executableInfo) == 0, executableInfo.st_mode & S_IFMT == S_IFREG,
              executableInfo.st_nlink == 1 else { throw VPNApplicationSwapError.unsafeExecutor }
        // This exclusion is an anti-self-replacement check, not authentication
        // of the live process. Stable, independently authenticated execution
        // outside these slots remains a caller prerequisite.
        let parent = URL(fileURLWithPath: path).deletingLastPathComponent().path
        var directory = open(parent, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard directory >= 0 else { throw VPNApplicationSwapError.unsafeExecutor }
        defer { close(directory) }
        var a = stat(), b = stat()
        guard fstat(current, &a) == 0, fstat(staged, &b) == 0 else { throw VPNApplicationSwapError.unsafeExecutor }
        for _ in 0..<256 {
            var here = stat()
            guard fstat(directory, &here) == 0, Identity(here) != Identity(a), Identity(here) != Identity(b) else {
                throw VPNApplicationSwapError.unsafeExecutor
            }
            let next = openat(directory, "..", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard next >= 0 else { throw VPNApplicationSwapError.unsafeExecutor }
            var above = stat()
            guard fstat(next, &above) == 0 else { close(next); throw VPNApplicationSwapError.unsafeExecutor }
            if Identity(above) == Identity(here) { close(next); return }
            close(directory); directory = next
        }
        throw VPNApplicationSwapError.unsafeExecutor
    }
}
