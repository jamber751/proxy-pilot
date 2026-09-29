import Darwin
import Foundation

enum VPNUpdateBrokerStateRemovalError: Error {
    case unsafeStorage, unexpectedContent, removalFailed, commitUncertain
}

/// Fail-closed, bounded cleanup of the fixed root-private Broker namespace.
final class VPNUpdateBrokerStateRemoval {
    private var directory: Int32
    private let owner: uid_t

    init(trustedDirectoryDescriptor: Int32) throws {
        owner = geteuid()
        directory = fcntl(trustedDirectoryDescriptor, F_DUPFD_CLOEXEC, 0)
        guard directory >= 0 else { throw VPNUpdateBrokerStateRemovalError.unsafeStorage }
        do { try checkDirectory() }
        catch { close(directory); directory = -1; throw error }
    }

    deinit { if directory >= 0 { close(directory) } }

    /// Read-only gate. Unknown, linked or oversized content aborts uninstall
    /// before launchd or service state is changed.
    func preflight() throws {
        try checkDirectory()
        let inbox = try VPNUpdateBrokerInbox(trustedParent: directory)
        try inbox.validateForUninstall()
        for name in try names() where !Self.isInbox(name) {
            guard Self.isOwnedFile(name) else {
                throw VPNUpdateBrokerStateRemovalError.unexpectedContent
            }
            try checkFile(name)
        }
    }

    /// Called only after the broker job and VPN service have been retired.
    /// The lifecycle lock is removed last while its lease is still held.
    func removeAll(lease: VPNLifecycleLease) throws {
        try preflight()
        try lease.check()
        let inbox = try VPNUpdateBrokerInbox(trustedParent: directory)
        try inbox.removeAllForUninstall()
        let ordinary = try names().filter {
            !Self.isInbox($0) && $0 != VPNLifecycleLease.lockName
        }
        for name in ordinary.sorted() { try unlink(name) }
        try lease.check()
        if try names().contains(VPNLifecycleLease.lockName) {
            try unlink(VPNLifecycleLease.lockName)
        }
        guard fsync(directory) == 0 else {
            throw VPNUpdateBrokerStateRemovalError.commitUncertain
        }
    }

    private func checkFile(_ name: String) throws {
        let file = openat(directory, name,
            O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard file >= 0 else { throw VPNUpdateBrokerStateRemovalError.unsafeStorage }
        defer { close(file) }
        var value = stat()
        guard fstat(file, &value) == 0,
              value.st_mode & S_IFMT == S_IFREG, value.st_nlink == 1,
              value.st_uid == owner, value.st_mode & 0o7777 == 0o600,
              value.st_size >= 0, Self.validSize(value.st_size, for: name) else {
            throw VPNUpdateBrokerStateRemovalError.unsafeStorage
        }
        try checkNoACL(file)
    }

    private func unlink(_ name: String) throws {
        guard Self.isOwnedFile(name) else {
            throw VPNUpdateBrokerStateRemovalError.unexpectedContent
        }
        try checkFile(name)
        guard unlinkat(directory, name, 0) == 0 || errno == ENOENT else {
            throw VPNUpdateBrokerStateRemovalError.removalFailed
        }
    }

    private func names() throws -> [String] {
        let copy = openat(directory, ".",
            O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard copy >= 0, let stream = fdopendir(copy) else {
            if copy >= 0 { close(copy) }
            throw VPNUpdateBrokerStateRemovalError.unsafeStorage
        }
        defer { closedir(stream) }
        var result: [String] = []
        while true {
            errno = 0
            guard let entry = readdir(stream) else {
                guard errno == 0 else { throw VPNUpdateBrokerStateRemovalError.unsafeStorage }
                break
            }
            let name = withUnsafePointer(to: &entry.pointee.d_name) {
                $0.withMemoryRebound(to: CChar.self, capacity: 1024) {
                    String(cString: $0)
                }
            }
            if name != "." && name != ".." { result.append(name) }
        }
        return result
    }

    private func checkDirectory() throws {
        var value = stat(), filesystem = statfs()
        guard fstat(directory, &value) == 0,
              value.st_mode & S_IFMT == S_IFDIR, value.st_nlink > 0,
              value.st_uid == owner, value.st_mode & 0o7777 == 0o700,
              fstatfs(directory, &filesystem) == 0,
              filesystem.f_flags & UInt32(MNT_LOCAL) != 0 else {
            throw VPNUpdateBrokerStateRemovalError.unsafeStorage
        }
        try checkNoACL(directory)
    }

    private func checkNoACL(_ descriptor: Int32) throws {
        var info = stat()
        guard let security = filesec_init() else {
            throw VPNUpdateBrokerStateRemovalError.unsafeStorage
        }
        defer { filesec_free(security) }
        guard fstatx_np(descriptor, &info, security) == 0 else {
            throw VPNUpdateBrokerStateRemovalError.unsafeStorage
        }
        var acl: acl_t?
        errno = 0
        let result = filesec_get_property(security, FILESEC_ACL, &acl)
        if result == -1, errno == ENOENT { return }
        guard result == 0, let acl else {
            throw VPNUpdateBrokerStateRemovalError.unsafeStorage
        }
        defer { acl_free(UnsafeMutableRawPointer(acl)) }
        var entry: acl_entry_t?
        errno = 0
        guard acl_get_entry(acl, Int32(ACL_FIRST_ENTRY.rawValue), &entry) == -1,
              errno == EINVAL else {
            throw VPNUpdateBrokerStateRemovalError.unsafeStorage
        }
    }

    private static func isOwnedFile(_ name: String) -> Bool {
        if [VPNLifecycleLease.lockName, VPNLifecycleLease.runtimeLockName,
            "update-broker-status.bin", "update-broker-status.lock",
            "update-broker-transaction.bin", "update-broker-transaction.lock",
            ".update-broker-transaction.tmp"].contains(name) { return true }
        guard name.hasPrefix(".update-broker-status-"), name.hasSuffix(".tmp") else {
            return false
        }
        let identity = name.dropFirst(22).dropLast(4)
        return UUID(uuidString: String(identity)) != nil
    }

    private static func validSize(_ size: off_t, for name: String) -> Bool {
        if name == "update-broker-status.bin" { return size == 48 }
        if name == "update-broker-transaction.bin" { return size == 128 }
        if name.hasPrefix(".update-broker-status-") { return size <= 48 }
        if name == ".update-broker-transaction.tmp" { return size <= 128 }
        return size <= 4096
    }

    private static func isInbox(_ name: String) -> Bool {
        if name.hasPrefix("inbox-"), name.count == 70 {
            return name.dropFirst(6).allSatisfy { $0.isHexDigit && !$0.isUppercase }
        }
        guard name.hasPrefix(".inbox-"), name.hasSuffix(".preparing") else {
            return false
        }
        let digest = name.dropFirst(7).dropLast(10)
        return digest.count == 64 && digest.allSatisfy {
            $0.isHexDigit && !$0.isUppercase
        }
    }
}
