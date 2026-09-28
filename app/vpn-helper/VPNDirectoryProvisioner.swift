import Darwin

enum VPNDirectoryError: Error { case requiresRoot, unsafeDirectory, unavailable, syncUncertain }

/// Installation-time primitive, not wired to an app/installer yet. Production
/// entry requires root BEFORE opening/creating anything. Tests use only the
/// descriptor-relative primitive below under a disposable directory.
enum VPNDirectoryProvisioner {
    /// The caller still needs the user's system installation authorization.
    /// Returned descriptor belongs to the caller; no service is registered.
    static func openSystemDirectory(create: Bool) throws -> Int32 {
        try openSystemComponent(name: "VPN", create: create)
    }

    /// Fixed application-replacement namespace. Keeping it beside, rather than
    /// inside, the service store lets recovery reopen the protected A/B slots
    /// after a process crash without accepting a path or conflating the two
    /// lifecycle locks.
    static func openSystemUpdateDirectory(create: Bool) throws -> Int32 {
        try openSystemComponent(name: "Update", create: create)
    }

    /// Binds an inherited descriptor to the one fixed production transaction
    /// directory. Root-private is necessary but not sufficient: a privileged
    /// caller must not redirect replacement into some other private tree.
    static func requireSystemUpdateDirectory(_ descriptor: Int32) throws {
        guard getuid() == 0, geteuid() == 0 else { throw VPNDirectoryError.requiresRoot }
        let expected = try openSystemUpdateDirectory(create: false)
        defer { close(expected) }
        try requireSameDirectory(descriptor, expected)
    }

    private static func openSystemComponent(name: String, create: Bool) throws -> Int32 {
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
        return try openComponentBelowTrustedBase(parent, name: name, create: create)
    }

    /// Internal mechanism, NOT an IPC interface. The base fd must already be
    /// trusted; only the two hardcoded application directory names are created.
    /// In production openSystemDirectory is the only entry point to use.
    static func openBelowTrustedBase(_ base: Int32, create: Bool) throws -> Int32 {
        try openComponentBelowTrustedBase(base, name: "VPN", create: create)
    }

    #if VPN_DIRECTORY_TESTING
    static func testOpenUpdateBelowTrustedBase(_ base: Int32, create: Bool) throws -> Int32 {
        try openComponentBelowTrustedBase(base, name: "Update", create: create)
    }

    static func testRequireUpdateDirectory(_ descriptor: Int32,
                                           belowTrustedBase base: Int32) throws {
        let expected = try testOpenUpdateBelowTrustedBase(base, create: false)
        defer { close(expected) }
        try requireSameDirectory(descriptor, expected)
    }
    #endif

    private static func requireSameDirectory(_ supplied: Int32, _ expected: Int32) throws {
        try check(supplied, privateDirectory: true)
        var actual = stat(), wanted = stat()
        guard fstat(supplied, &actual) == 0, fstat(expected, &wanted) == 0,
              actual.st_dev == wanted.st_dev, actual.st_ino == wanted.st_ino else {
            throw VPNDirectoryError.unsafeDirectory
        }
    }

    private static func openComponentBelowTrustedBase(_ base: Int32, name: String,
                                                       create: Bool) throws -> Int32 {
        guard name == "VPN" || name == "Update" else { throw VPNDirectoryError.unsafeDirectory }
        try check(base, privateDirectory: false)
        let app = try openChild(parent: base, name: "ProxyPilot", create: create, privateDirectory: true)
        defer { close(app) }
        return try openChild(parent: app, name: name, create: create, privateDirectory: true)
    }

    /// Removes the VPN directory after the caller has emptied it. The private
    /// application container is removed only when it is empty. A completed joint
    /// application update deliberately retains its separate `Update` sibling for
    /// a later authenticated cleanup transaction; that retained sibling must not
    /// turn an otherwise complete VPN-support removal into a failure.
    ///
    /// This remains non-recursive and never removes or even opens sibling
    /// contents. An unexpected child inside VPN still prevents the first rmdir;
    /// only ENOTEMPTY/EEXIST from the already-validated parent container is the
    /// accepted "another component is retained" result.
    static func removeBelowTrustedBase(_ base: Int32) throws {
        try check(base, privateDirectory: false)
        let app = try openChild(parent: base, name: "ProxyPilot", create: false, privateDirectory: true)
        defer { close(app) }
        let vpn = try openChild(parent: app, name: "VPN", create: false, privateDirectory: true)
        close(vpn)
        guard unlinkat(app, "VPN", AT_REMOVEDIR) == 0, fsync(app) == 0 else {
            throw VPNDirectoryError.unavailable
        }
        if unlinkat(base, "ProxyPilot", AT_REMOVEDIR) != 0 {
            guard errno == ENOTEMPTY || errno == EEXIST else {
                throw VPNDirectoryError.unavailable
            }
        }
        guard fsync(base) == 0 else { throw VPNDirectoryError.syncUncertain }
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
