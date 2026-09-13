import Darwin
import Foundation
import Security

enum VPNStagedApplicationError: Error {
    case unsafeStorage, invalidBundle, invalidSignature, changed, limitExceeded
}

/// A static observation of ONE protected staged object. Not installed-app
/// evidence, a live process, a retained lifecycle lease, or replacement authority.
/// Revalidation must repeat all checks; never serialize this as a receipt.
struct VPNStagedApplicationInspection {
    fileprivate let release: VerifiedVPNRelease
    fileprivate let snapshot: VPNStagedApplication.Snapshot
    fileprivate init(release: VerifiedVPNRelease, snapshot: VPNStagedApplication.Snapshot) {
        self.release = release; self.snapshot = snapshot
    }
    func matchesRelease(_ release: VerifiedVPNRelease) -> Bool {
        self.release.isSameRelease(as: release)
    }
}

/// Read-only staging verifier. Production must supply a root-private local
/// directory under protected parents and hold exclusive lifecycle/staging
/// ownership throughout. Never take this descriptor or an app path from IPC.
/// Tests use their own UID/private directories with the identical checks.
/// Security's path-based validation is NOT atomic against another trusted/root
/// writer; metadata checks supplement, never replace, that no-writer contract.
enum VPNStagedApplication {
    private static let bundleName = "ProxyPilot.app"
    private static let identifier = "kz.documentolog.proxypilot"
    private static let maximumEntries = 10000
    private static let maximumBytes: Int64 = 256 * 1024 * 1024
    private static let maximumDepth = 48

    fileprivate struct Entry: Equatable {
        let type: mode_t
        let facts: [UInt64]
        let target: String?
    }
    fileprivate struct Snapshot: Equatable {
        let parent: [UInt64]
        let entries: [String: Entry]
    }

    static func inspect(inTrustedDirectory parent: Int32, release: VerifiedVPNRelease) throws -> VPNStagedApplicationInspection {
        try checkParent(parent)
        let bundle = openat(parent, bundleName, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard bundle >= 0 else { throw VPNStagedApplicationError.unsafeStorage }
        defer { close(bundle) }
        let before = try capture(parent: parent, bundle: bundle)
        try checkLinks(before.entries)
        let contents = try openDirectory(bundle, "Contents")
        defer { close(contents) }
        let plist = try readFile(contents, "Info.plist", limit: 1024 * 1024)
        guard let info = try PropertyListSerialization.propertyList(from: plist, options: [], format: nil) as? [String: Any],
              info["CFBundleIdentifier"] as? String == identifier,
              info["CFBundleExecutable"] as? String == "ProxyPilot",
              info["CFBundlePackageType"] as? String == "APPL",
              info["CFBundleVersion"] as? String == release.version,
              info["CFBundleShortVersionString"] as? String == release.version else {
            throw VPNStagedApplicationError.invalidBundle
        }
        let macOS = try openDirectory(contents, "MacOS")
        defer { close(macOS) }
        let executable = try readFile(macOS, "ProxyPilot", limit: 64 * 1024 * 1024, executable: true)
        try checkUniversalExecutable(executable)
        let url = try boundBundleURL(parent: parent, bundle: bundle)
        try checkSignature(url: url, release: release)
        _ = try boundBundleURL(parent: parent, bundle: bundle)
        guard try capture(parent: parent, bundle: bundle) == before else {
            throw VPNStagedApplicationError.changed
        }
        return VPNStagedApplicationInspection(release: release, snapshot: before)
    }

    static func revalidate(_ inspection: VPNStagedApplicationInspection, inTrustedDirectory parent: Int32) throws {
        let current = try inspect(inTrustedDirectory: parent, release: inspection.release)
        guard current.snapshot == inspection.snapshot else { throw VPNStagedApplicationError.changed }
    }

    private static func checkSignature(url: URL, release: VerifiedVPNRelease) throws {
        // Fresh references for every inspection and architecture. This avoids
        // reusing our own stale object, not a promise to bypass all OS caches.
        let checks = SecCSFlags(rawValue: kSecCSStrictValidate | kSecCSCheckAllArchitectures
            | kSecCSCheckNestedCode | kSecCSRestrictSymlinks).union(.noNetworkAccess)
        var sealed: SecStaticCode?
        guard SecStaticCodeCreateWithPath(url as CFURL, [], &sealed) == errSecSuccess,
              let sealed = sealed, SecStaticCodeCheckValidity(sealed, checks, nil) == errSecSuccess else {
            throw VPNStagedApplicationError.invalidSignature
        }
        let required = SecCodeSignatureFlags.runtime.rawValue | SecCodeSignatureFlags.forceHard.rawValue
            | SecCodeSignatureFlags.forceKill.rawValue
        for architecture in ["arm64", "x86_64"] {
            var code: SecStaticCode?
            let attributes = [kSecCodeAttributeArchitecture as String: architecture] as CFDictionary
            guard SecStaticCodeCreateWithPathAndAttributes(url as CFURL, [], attributes, &code) == errSecSuccess,
                  let code = code, SecStaticCodeCheckValidity(code, checks, nil) == errSecSuccess else {
                throw VPNStagedApplicationError.invalidSignature
            }
            var raw: CFDictionary?
            guard SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &raw) == errSecSuccess,
                  let info = raw as? [String: Any],
                  info[kSecCodeInfoIdentifier as String] as? String == identifier,
                  let hash = info[kSecCodeInfoUnique as String] as? Data,
                  hash == release.appHash(forArchitecture: architecture),
                  let flags = info[kSecCodeInfoFlags as String] as? NSNumber,
                  flags.uint32Value & required == required else {
                throw VPNStagedApplicationError.invalidSignature
            }
            if let entitlements = info[kSecCodeInfoEntitlementsDict as String] {
                guard let values = entitlements as? [String: Any], values.isEmpty else {
                    throw VPNStagedApplicationError.invalidSignature
                }
            }
        }
    }

    private static func capture(parent: Int32, bundle: Int32) throws -> Snapshot {
        try checkParent(parent)
        _ = try boundBundleURL(parent: parent, bundle: bundle)
        var root = stat(), parentState = stat()
        guard fstat(bundle, &root) == 0, fstat(parent, &parentState) == 0 else { throw VPNStagedApplicationError.unsafeStorage }
        try checkNode(bundle, attributes: root, directory: true)
        var entries: [String: Entry] = ["": Entry(type: S_IFDIR, facts: facts(root), target: nil)]
        var bytes: Int64 = 0
        func visit(_ directory: Int32, prefix: String, depth: Int) throws {
            guard depth <= maximumDepth else { throw VPNStagedApplicationError.limitExceeded }
            let copy = openat(directory, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard copy >= 0 else { throw VPNStagedApplicationError.unsafeStorage }
            guard let stream = fdopendir(copy) else { close(copy); throw VPNStagedApplicationError.unsafeStorage }
            defer { closedir(stream) }
            while true {
                errno = 0
                guard let row = readdir(stream) else {
                    guard errno == 0 else { throw VPNStagedApplicationError.unsafeStorage }
                    break
                }
                // readdir returns variable-size records, NOT a full Swift
                // dirent value. Copying its 1024-byte d_name tuple can read
                // beyond libc's directory buffer, even for a short valid name.
                guard let offset = MemoryLayout<dirent>.offset(of: \.d_name) else {
                    throw VPNStagedApplicationError.invalidBundle
                }
                let length = Int(row.pointee.d_namlen)
                guard length > 0, length < Int(MAXPATHLEN),
                      offset + length < Int(row.pointee.d_reclen) else {
                    throw VPNStagedApplicationError.invalidBundle
                }
                let address = UnsafeRawPointer(row).advanced(by: offset).assumingMemoryBound(to: UInt8.self)
                let nameBytes = UnsafeBufferPointer(start: address, count: length)
                guard address[length] == 0, !nameBytes.contains(0), !nameBytes.contains(47),
                      let name = String(bytes: nameBytes, encoding: .utf8) else {
                    throw VPNStagedApplicationError.invalidBundle
                }
                if name == "." || name == ".." { continue }
                let relative = prefix.isEmpty ? name : prefix + "/" + name
                guard entries.count < maximumEntries, relative.utf8.count <= 4096 else {
                    throw VPNStagedApplicationError.limitExceeded
                }
                var named = stat()
                guard fstatat(directory, name, &named, AT_SYMLINK_NOFOLLOW) == 0,
                      named.st_dev == root.st_dev, named.st_uid == geteuid() else {
                    throw VPNStagedApplicationError.unsafeStorage
                }
                let kind = named.st_mode & S_IFMT
                var target: String?
                if kind == S_IFLNK {
                    guard named.st_nlink == 1 else { throw VPNStagedApplicationError.unsafeStorage }
                    var buffer = [UInt8](repeating: 0, count: 4097)
                    // readlinkat imports a void* destination: pass the array's
                    // element storage, not the address of its Swift value.
                    let length = buffer.withUnsafeMutableBytes {
                        readlinkat(directory, name, $0.baseAddress!, $0.count)
                    }
                    guard length > 0, length < buffer.count,
                          let value = String(bytes: buffer.prefix(length), encoding: .utf8),
                          !value.hasPrefix("/"), !value.utf8.contains(0) else {
                        throw VPNStagedApplicationError.invalidBundle
                    }
                    target = value
                    // Inspect the link object itself, never its target.
                    let link = openat(directory, name, O_RDONLY | O_SYMLINK | O_CLOEXEC)
                    guard link >= 0 else { throw VPNStagedApplicationError.unsafeStorage }
                    defer { close(link) }
                    var opened = stat()
                    guard fstat(link, &opened) == 0, facts(opened) == facts(named) else {
                        throw VPNStagedApplicationError.changed
                    }
                    try checkNoACL(link)
                } else if kind == S_IFDIR || kind == S_IFREG {
                    let flags = O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK | (kind == S_IFDIR ? O_DIRECTORY : 0)
                    let child = openat(directory, name, flags)
                    guard child >= 0 else { throw VPNStagedApplicationError.unsafeStorage }
                    defer { close(child) }
                    var opened = stat()
                    guard fstat(child, &opened) == 0, facts(opened) == facts(named) else {
                        throw VPNStagedApplicationError.changed
                    }
                    try checkNode(child, attributes: opened, directory: kind == S_IFDIR)
                    if kind == S_IFREG {
                        guard opened.st_size >= 0, opened.st_size <= maximumBytes - bytes else {
                            throw VPNStagedApplicationError.limitExceeded
                        }
                        bytes += opened.st_size
                    } else { try visit(child, prefix: relative, depth: depth + 1) }
                } else { throw VPNStagedApplicationError.unsafeStorage }
                // A recursive visit can fill the budget before its enclosing
                // directory is recorded; count that directory as well.
                guard entries.count < maximumEntries else { throw VPNStagedApplicationError.limitExceeded }
                entries[relative] = Entry(type: kind, facts: facts(named), target: target)
            }
        }
        try visit(bundle, prefix: "", depth: 0)
        return Snapshot(parent: facts(parentState), entries: entries)
    }

    private static func checkLinks(_ entries: [String: Entry]) throws {
        for (path, node) in entries where node.type == S_IFLNK {
            var resolved = Array(path.split(separator: "/").dropLast()).map(String.init)
            var remaining = node.target!.split(separator: "/", omittingEmptySubsequences: false).map(String.init)
            var seen: Set<String> = [path], hops = 0
            while !remaining.isEmpty {
                let component = remaining.removeFirst()
                if component.isEmpty || component == "." { continue }
                if component == ".." {
                    guard !resolved.isEmpty else { throw VPNStagedApplicationError.invalidBundle }
                    resolved.removeLast(); continue
                }
                let key = (resolved + [component]).joined(separator: "/")
                guard let next = entries[key] else { throw VPNStagedApplicationError.invalidBundle }
                if next.type == S_IFLNK {
                    hops += 1
                    guard hops <= 40, seen.insert(key).inserted else { throw VPNStagedApplicationError.invalidBundle }
                    remaining = next.target!.split(separator: "/", omittingEmptySubsequences: false).map(String.init) + remaining
                } else {
                    guard remaining.isEmpty || next.type == S_IFDIR else { throw VPNStagedApplicationError.invalidBundle }
                    resolved.append(component)
                }
            }
            let target = resolved.joined(separator: "/")
            guard !target.isEmpty, target != path,
                  !(entries[target]?.type == S_IFDIR && path.hasPrefix(target + "/")) else {
                throw VPNStagedApplicationError.invalidBundle
            }
        }
    }

    private static func boundBundleURL(parent: Int32, bundle: Int32) throws -> URL {
        var bytes = [CChar](repeating: 0, count: Int(MAXPATHLEN))
        guard fcntl(bundle, F_GETPATH, &bytes) == 0 else { throw VPNStagedApplicationError.unsafeStorage }
        let url = URL(fileURLWithPath: String(cString: bytes))
        var opened = stat(), child = stat(), path = stat()
        guard fstat(bundle, &opened) == 0,
              fstatat(parent, bundleName, &child, AT_SYMLINK_NOFOLLOW) == 0,
              lstat(url.path, &path) == 0, opened.st_mode & S_IFMT == S_IFDIR,
              facts(opened) == facts(child), facts(opened) == facts(path) else {
            throw VPNStagedApplicationError.changed
        }
        return url
    }

    private static func facts(_ s: stat) -> [UInt64] {
        [UInt64(truncatingIfNeeded: s.st_dev), UInt64(s.st_ino), UInt64(s.st_mode), UInt64(s.st_uid),
         UInt64(s.st_gid), UInt64(s.st_nlink), UInt64(truncatingIfNeeded: s.st_size),
         UInt64(truncatingIfNeeded: s.st_mtimespec.tv_sec), UInt64(s.st_mtimespec.tv_nsec),
         UInt64(truncatingIfNeeded: s.st_ctimespec.tv_sec), UInt64(s.st_ctimespec.tv_nsec)]
    }

    private static func checkParent(_ fd: Int32) throws {
        var s = stat(), fs = statfs()
        guard fstat(fd, &s) == 0, s.st_mode & 0o7777 == 0o700, s.st_nlink > 0,
              fstatfs(fd, &fs) == 0, fs.f_flags & UInt32(MNT_LOCAL) != 0 else {
            throw VPNStagedApplicationError.unsafeStorage
        }
        try checkNode(fd, attributes: s, directory: true)
    }

    private static func checkNode(_ fd: Int32, attributes s: stat, directory: Bool) throws {
        guard s.st_uid == geteuid(), s.st_mode & S_IFMT == (directory ? S_IFDIR : S_IFREG),
              s.st_mode & 0o7022 == 0, s.st_mode & 0o400 != 0,
              directory ? s.st_mode & 0o100 != 0 : s.st_nlink == 1 else {
            throw VPNStagedApplicationError.unsafeStorage
        }
        try checkNoACL(fd)
    }

    private static func checkNoACL(_ fd: Int32) throws {
        guard let security = filesec_init() else { throw VPNStagedApplicationError.unsafeStorage }
        defer { filesec_free(security) }
        var s = stat()
        guard fstatx_np(fd, &s, security) == 0 else { throw VPNStagedApplicationError.unsafeStorage }
        var retrieved: acl_t?
        errno = 0
        let result = filesec_get_property(security, FILESEC_ACL, &retrieved)
        if result == -1, errno == ENOENT { return }
        guard result == 0, let acl = retrieved else { throw VPNStagedApplicationError.unsafeStorage }
        defer { acl_free(UnsafeMutableRawPointer(acl)) }
        var entry: acl_entry_t?
        errno = 0
        guard acl_get_entry(acl, Int32(ACL_FIRST_ENTRY.rawValue), &entry) == -1, errno == EINVAL else {
            throw VPNStagedApplicationError.unsafeStorage
        }
    }

    private static func openDirectory(_ parent: Int32, _ name: String) throws -> Int32 {
        let fd = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw VPNStagedApplicationError.invalidBundle }
        return fd
    }

    private static func readFile(_ parent: Int32, _ name: String, limit: Int, executable: Bool = false) throws -> Data {
        let fd = openat(parent, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard fd >= 0 else { throw VPNStagedApplicationError.invalidBundle }
        defer { close(fd) }
        var s = stat()
        guard fstat(fd, &s) == 0 else { throw VPNStagedApplicationError.unsafeStorage }
        try checkNode(fd, attributes: s, directory: false)
        guard !executable || s.st_mode & 0o100 != 0 else { throw VPNStagedApplicationError.unsafeStorage }
        var result = Data(), bytes = [UInt8](repeating: 0, count: 8192)
        while true {
            let count = read(fd, &bytes, bytes.count)
            if count < 0, errno == EINTR { continue }
            guard count >= 0 else { throw VPNStagedApplicationError.invalidBundle }
            if count == 0 { return result }
            guard count <= limit - result.count else { throw VPNStagedApplicationError.limitExceeded }
            result.append(contentsOf: bytes.prefix(count))
        }
    }

    private static func checkUniversalExecutable(_ data: Data) throws {
        guard data.count >= 48 else { throw VPNStagedApplicationError.invalidBundle }
        func big(_ i: Int) -> UInt32 { data[i..<i+4].reduce(0) { ($0 << 8) | UInt32($1) } }
        guard big(0) == 0xcafebabe, big(4) == 2 else { throw VPNStagedApplicationError.invalidBundle }
        var cpus = Set<UInt32>(), ranges: [Range<Int>] = []
        for n in 0..<2 {
            let i = 8 + n * 20, cpu = big(i), subtype = big(i+4)
            let offset = Int(big(i+8)), size = Int(big(i+12)), alignment = big(i+16)
            guard (cpu == 0x0100000c && subtype == 0) || (cpu == 0x01000007 && subtype == 3),
                  cpus.insert(cpu).inserted, alignment <= 20, offset >= 48,
                  offset % (1 << alignment) == 0, size >= 32, offset <= data.count,
                  size <= data.count - offset else { throw VPNStagedApplicationError.invalidBundle }
            let range = offset..<offset+size
            guard !ranges.contains(where: { $0.overlaps(range) }) else { throw VPNStagedApplicationError.invalidBundle }
            ranges.append(range)
            func little(_ j: Int) -> UInt32 { data[j..<j+4].reversed().reduce(0) { ($0 << 8) | UInt32($1) } }
            guard little(offset) == 0xfeedfacf, little(offset+4) == cpu,
                  little(offset+8) == subtype, little(offset+12) == 2 else {
                throw VPNStagedApplicationError.invalidBundle
            }
        }
    }
}
