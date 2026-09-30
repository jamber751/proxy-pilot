import Darwin
import Dispatch
import Foundation

enum VPNEndpointError: Error { case requiresRoot, unsafeStorage, unavailable }

/// Public IPC lives separately from root-private profiles/policy. This directory
/// contains only the socket: 0755 root directory, 0666 root socket. Connection
/// permission is NOT command authority: both peer UID and signed build must pass
/// the listener gate before any input is read. No caller may supply a path.
enum VPNEndpointDirectory {
    static let directoryName = "kz.documentolog.proxypilot.vpn"

    static func openSystem(create: Bool) throws -> Int32 {
        if create, geteuid() != 0 { throw VPNEndpointError.requiresRoot }
        let parent = try systemParent()
        defer { close(parent) }
        return try openBelowTrustedBase(parent, owner: 0, create: create)
    }

    static func removeSystem() throws {
        guard geteuid() == 0 else { throw VPNEndpointError.requiresRoot }
        let parent = try systemParent()
        defer { close(parent) }
        let directory = try openBelowTrustedBase(parent, owner: 0, create: false)
        // The only regular file allowed in the public endpoint namespace is
        // the signed release receipt. Refuse unexpected type/owner/permissions.
        var receipt = stat()
        let receiptName = "release-receipt.json"
        if fstatat(directory, receiptName, &receipt,
                   AT_SYMLINK_NOFOLLOW) == 0 {
            guard receipt.st_mode & S_IFMT == S_IFREG, receipt.st_uid == 0,
                  receipt.st_nlink == 1, receipt.st_mode & 0o7777 == 0o644,
                  unlinkat(directory, receiptName, 0) == 0,
                  fsync(directory) == 0 else { close(directory); throw VPNEndpointError.unavailable }
        } else if errno != ENOENT {
            close(directory); throw VPNEndpointError.unavailable
        }
        close(directory)
        // Never recursive; an unexpected file keeps the directory in place.
        guard unlinkat(parent, directoryName, AT_REMOVEDIR) == 0, fsync(parent) == 0 else {
            throw VPNEndpointError.unavailable
        }
    }

    /// Application entry: read-only open under fixed protected ancestors.
    static func connectSystem(deadline: UInt64) throws -> Int32 {
        let directory = try openSystem(create: false)
        defer { close(directory) }
        return try connect(directory: directory, owner: 0, shared: true, deadline: deadline)
    }

    // Internal descriptor primitive used by disposable tests. Not an IPC API.
    static func openBelowTrustedBase(_ parent: Int32, owner: uid_t, create: Bool) throws -> Int32 {
        try checkDirectory(parent, owner: owner, permissions: nil)
        var created = false
        if create {
            if mkdirat(parent, directoryName, 0o755) == 0 { created = true }
            else if errno != EEXIST { throw VPNEndpointError.unavailable }
        }
        let directory = openat(parent, directoryName, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard directory >= 0 else { throw VPNEndpointError.unavailable }
        do {
            // Apply exact rights only to a directory just created by this call;
            // do not "repair" existing storage or erase pre-existing ACLs.
            if created {
                try checkDirectory(directory, owner: owner, permissions: nil)
                guard fchmod(directory, 0o755) == 0, fsync(parent) == 0 else { throw VPNEndpointError.unavailable }
            }
            try checkDirectory(directory, owner: owner, permissions: 0o755)
            return directory
        } catch { close(directory); throw error }
    }

    static func checkedPath(_ directory: Int32, owner: uid_t, shared: Bool) throws -> String {
        try checkDirectory(directory, owner: owner, permissions: shared ? 0o755 : 0o700)
        var path = [CChar](repeating: 0, count: Int(MAXPATHLEN)), opened = stat(), named = stat()
        guard fcntl(directory, F_GETPATH, &path) == 0 else { throw VPNEndpointError.unsafeStorage }
        let folder = String(cString: path)
        guard fstat(directory, &opened) == 0, lstat(folder, &named) == 0,
              opened.st_dev == named.st_dev, opened.st_ino == named.st_ino,
              named.st_mode & S_IFMT == S_IFDIR else { throw VPNEndpointError.unsafeStorage }
        return folder
    }

    static func connect(directory: Int32, owner: uid_t, shared: Bool, deadline: UInt64) throws -> Int32 {
        let folder = try checkedPath(directory, owner: owner, shared: shared)
        var endpoint = stat()
        guard fstatat(directory, VPNHelperProtocol.socketName, &endpoint, AT_SYMLINK_NOFOLLOW) == 0,
              endpoint.st_mode & S_IFMT == S_IFSOCK, endpoint.st_uid == owner,
              endpoint.st_nlink == 1, endpoint.st_mode & 0o7777 == (shared ? 0o666 : 0o600) else {
            throw VPNEndpointError.unavailable
        }
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        let bytes = Array((folder + "/" + VPNHelperProtocol.socketName).utf8) + [0]
        guard bytes.count <= MemoryLayout.size(ofValue: address.sun_path) else { throw VPNEndpointError.unsafeStorage }
        withUnsafeMutableBytes(of: &address.sun_path) { $0.copyBytes(from: bytes) }
        let descriptor = socket(AF_UNIX, SOCK_STREAM, 0)
        guard descriptor >= 0 else { throw VPNEndpointError.unavailable }
        do {
            guard fcntl(descriptor, F_SETFD, FD_CLOEXEC) == 0,
                  fcntl(descriptor, F_SETFL, O_NONBLOCK) == 0 else { throw VPNEndpointError.unavailable }
            let result = withUnsafePointer(to: &address) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    Darwin.connect(descriptor, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
                }
            }
            if result != 0 {
                guard [EINPROGRESS, EAGAIN, EWOULDBLOCK].contains(errno) else { throw VPNEndpointError.unavailable }
                try VPNHelperProtocol.wait(descriptor, events: Int16(POLLOUT), deadline: deadline)
                var error: Int32 = 0, size = socklen_t(MemoryLayout<Int32>.size)
                guard getsockopt(descriptor, SOL_SOCKET, SO_ERROR, &error, &size) == 0, error == 0 else {
                    throw VPNEndpointError.unavailable
                }
            }
            guard DispatchTime.now().uptimeNanoseconds < deadline else { throw VPNHelperTransportError.timeout }
            return descriptor
        } catch { close(descriptor); throw error }
    }

    private static func systemParent() throws -> Int32 {
        var parent = open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard parent >= 0 else { throw VPNEndpointError.unavailable }
        do {
            try checkDirectory(parent, owner: 0, permissions: nil)
            // /var/run is group-writable on some Macs. Use protected ancestors
            // rather than weakening the no-group-write requirement for it.
            for name in ["Library", "Application Support"] {
                let child = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
                guard child >= 0 else { throw VPNEndpointError.unavailable }
                close(parent); parent = child
                try checkDirectory(parent, owner: 0, permissions: nil)
            }
            return parent
        } catch { close(parent); throw error }
    }

    private static func checkDirectory(_ descriptor: Int32, owner: uid_t, permissions: mode_t?) throws {
        var attributes = stat(), filesystem = statfs()
        guard fstat(descriptor, &attributes) == 0, attributes.st_mode & S_IFMT == S_IFDIR,
              attributes.st_nlink > 0, attributes.st_uid == owner,
              attributes.st_mode & 0o7022 == 0,
              permissions == nil || attributes.st_mode & 0o7777 == permissions!,
              fstatfs(descriptor, &filesystem) == 0, filesystem.f_flags & UInt32(MNT_LOCAL) != 0 else {
            throw VPNEndpointError.unsafeStorage
        }
        guard let security = filesec_init() else { throw VPNEndpointError.unsafeStorage }
        defer { filesec_free(security) }
        guard fstatx_np(descriptor, &attributes, security) == 0 else { throw VPNEndpointError.unsafeStorage }
        var acl: acl_t?
        errno = 0
        let result = filesec_get_property(security, FILESEC_ACL, &acl)
        if result == -1, errno == ENOENT { return }
        guard result == 0, let acl = acl else { throw VPNEndpointError.unsafeStorage }
        defer { acl_free(UnsafeMutableRawPointer(acl)) }
        var entry: acl_entry_t?
        errno = 0
        guard acl_get_entry(acl, Int32(ACL_FIRST_ENTRY.rawValue), &entry) == -1, errno == EINVAL else {
            throw VPNEndpointError.unsafeStorage
        }
    }
}
