import Darwin

enum VPNDirectoryError: Error { case requiresRoot, unsafeDirectory, unavailable, syncUncertain }

/// Installation-time primitive, not wired to an app/installer yet. Production
/// entry requires root BEFORE opening/creating anything. Tests use only the
/// descriptor-relative primitive below under a disposable directory.
enum VPNDirectoryProvisioner {
    /// The caller still needs the user's system installation authorization.
    /// Returned descriptor belongs to the caller; no service is registered.
    static func openSystemDirectory(create: Bool) throws -> Int32 {
        guard geteuid() == 0 else { throw VPNDirectoryError.requiresRoot }
        var parent = open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard parent >= 0 else { throw VPNDirectoryError.unavailable }
        defer { close(parent) }
        try check(parent, privateDirectory: false)
        for name in ["Library", "Application Support"] {
            let child = try openChild(parent: parent, name: name, create: false, privateDirectory: false)
            close(parent)
            parent = child
        }
        return try openBelowTrustedBase(parent, create: create)
    }

    /// Internal mechanism, NOT an IPC interface. The base fd must already be
    /// trusted; only the two hardcoded application directory names are created.
    /// In production openSystemDirectory is the only entry point to use.
    static func openBelowTrustedBase(_ base: Int32, create: Bool) throws -> Int32 {
        try check(base, privateDirectory: false)
        let app = try openChild(parent: base, name: "ProxyPilot", create: create, privateDirectory: true)
        defer { close(app) }
        return try openChild(parent: app, name: "VPN", create: create, privateDirectory: true)
    }

    /// Removes the two application directories, innermost first, and only when
    /// they are already empty and still pass the same checks. Never recursive and
    /// never forced: emptying the VPN directory is the caller's explicit step.
    static func removeBelowTrustedBase(_ base: Int32) throws {
        try check(base, privateDirectory: false)
        let app = try openChild(parent: base, name: "ProxyPilot", create: false, privateDirectory: true)
        defer { close(app) }
        let vpn = try openChild(parent: app, name: "VPN", create: false, privateDirectory: true)
        close(vpn)
        guard unlinkat(app, "VPN", AT_REMOVEDIR) == 0, fsync(app) == 0,
              unlinkat(base, "ProxyPilot", AT_REMOVEDIR) == 0, fsync(base) == 0 else {
            throw VPNDirectoryError.unavailable
        }
    }

    static func removeSystemDirectories() throws {
        guard geteuid() == 0 else { throw VPNDirectoryError.requiresRoot }
        var parent = open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard parent >= 0 else { throw VPNDirectoryError.unavailable }
        defer { close(parent) }
        try check(parent, privateDirectory: false)
        for name in ["Library", "Application Support"] {
            let child = try openChild(parent: parent, name: name, create: false, privateDirectory: false)
            close(parent)
            parent = child
        }
        try removeBelowTrustedBase(parent)
    }

    private static func openChild(parent: Int32, name: String, create: Bool, privateDirectory: Bool) throws -> Int32 {
        var child = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        if child < 0, errno == ENOENT, create {
            guard mkdirat(parent, name, 0o700) == 0 || errno == EEXIST else { throw VPNDirectoryError.unavailable }
            child = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        }
        guard child >= 0 else { throw VPNDirectoryError.unavailable }
        do {
            try check(child, privateDirectory: privateDirectory)
            if create, fsync(parent) != 0 { throw VPNDirectoryError.syncUncertain }
            return child
        } catch { close(child); throw error }
    }

    private static func check(_ descriptor: Int32, privateDirectory: Bool) throws {
        var attributes = stat(), filesystem = statfs()
        guard fstat(descriptor, &attributes) == 0, attributes.st_mode & S_IFMT == S_IFDIR,
              attributes.st_nlink > 0, attributes.st_uid == geteuid(),
              fstatfs(descriptor, &filesystem) == 0, filesystem.f_flags & UInt32(MNT_LOCAL) != 0 else {
            throw VPNDirectoryError.unsafeDirectory
        }
        if privateDirectory {
            guard attributes.st_mode & 0o7777 == 0o700 else { throw VPNDirectoryError.unsafeDirectory }
        } else {
            guard attributes.st_mode & 0o7022 == 0 else { throw VPNDirectoryError.unsafeDirectory }
        }
        // Fail closed on ACL entries, including inherited ones; never repair
        // an existing directory by clearing ACLs or changing its ownership.
        guard let security = filesec_init() else { throw VPNDirectoryError.unsafeDirectory }
        defer { filesec_free(security) }
        guard fstatx_np(descriptor, &attributes, security) == 0 else { throw VPNDirectoryError.unsafeDirectory }
        var acl: acl_t?
        errno = 0
        let result = filesec_get_property(security, FILESEC_ACL, &acl)
        if result == -1, errno == ENOENT { return }
        guard result == 0, let acl = acl else { throw VPNDirectoryError.unsafeDirectory }
        defer { acl_free(UnsafeMutableRawPointer(acl)) }
        var entry: acl_entry_t?
        errno = 0
        guard acl_get_entry(acl, Int32(ACL_FIRST_ENTRY.rawValue), &entry) == -1, errno == EINVAL else {
            throw VPNDirectoryError.unsafeDirectory
        }
    }
}
