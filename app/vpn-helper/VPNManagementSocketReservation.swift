import Darwin
import Foundation

enum VPNManagementSocketReservationError: Error { case unsafeDirectory, unsafeEndpoint }

/// Reserves one unpredictable socket name inside the helper's 0700 directory.
/// OpenVPN creates the socket while held; the coordinator then narrows its mode
/// to 0600 and binds cleanup to that exact inode.
final class VPNManagementSocketReservation {
    private var directory: Int32
    private let owner = geteuid()
    private let name: String
    private(set) var identity: (device: dev_t, inode: ino_t)?
    let configuration: VPNEngineManagementConfiguration

    init(trustedDirectoryDescriptor: Int32) throws {
        let copy = fcntl(trustedDirectoryDescriptor, F_DUPFD_CLOEXEC, 64)
        guard copy >= 0 else { throw VPNManagementSocketReservationError.unsafeDirectory }
        let generatedName = ".management-\(UUID().uuidString).sock"
        do {
            try Self.checkDirectory(copy, owner: owner)
            var path = [CChar](repeating: 0, count: Int(MAXPATHLEN))
            guard fcntl(copy, F_GETPATH, &path) == 0 else {
                throw VPNManagementSocketReservationError.unsafeDirectory
            }
            let folder = String(cString: path)
            var absent = stat()
            guard fstatat(copy, generatedName, &absent, AT_SYMLINK_NOFOLLOW) == -1, errno == ENOENT else {
                throw VPNManagementSocketReservationError.unsafeEndpoint
            }
            let prepared = try VPNEngineManagementConfiguration(
                unixSocketPath: folder + "/" + generatedName)
            directory = copy
            name = generatedName
            configuration = prepared
        } catch {
            close(copy)
            throw error
        }
    }

    deinit { cleanup(); if directory >= 0 { close(directory) } }

    /// Returns true only after the socket is owner-bound, mode 0600 and stable
    /// across the chmod/revalidation window.
    func secureIfPresent() throws -> Bool {
        try checkDirectory()
        var before = stat()
        guard fstatat(directory, name, &before, AT_SYMLINK_NOFOLLOW) == 0 else {
            if errno == ENOENT { return false }
            throw VPNManagementSocketReservationError.unsafeEndpoint
        }
        guard before.st_mode & S_IFMT == S_IFSOCK, before.st_uid == owner,
              before.st_nlink == 1 else { throw VPNManagementSocketReservationError.unsafeEndpoint }
        guard chmod(configuration.socketPath, 0o600) == 0 else {
            throw VPNManagementSocketReservationError.unsafeEndpoint
        }
        var after = stat()
        guard fstatat(directory, name, &after, AT_SYMLINK_NOFOLLOW) == 0,
              after.st_mode & S_IFMT == S_IFSOCK, after.st_uid == owner,
              after.st_nlink == 1, after.st_mode & 0o7777 == 0o600,
              before.st_dev == after.st_dev, before.st_ino == after.st_ino else {
            throw VPNManagementSocketReservationError.unsafeEndpoint
        }
        identity = (after.st_dev, after.st_ino)
        return true
    }

    func cleanup() {
        guard directory >= 0, let expected = identity else { return }
        var current = stat()
        guard fstatat(directory, name, &current, AT_SYMLINK_NOFOLLOW) == 0,
              current.st_mode & S_IFMT == S_IFSOCK, current.st_uid == owner,
              current.st_nlink == 1, current.st_dev == expected.device,
              current.st_ino == expected.inode else { return }
        _ = unlinkat(directory, name, 0)
        identity = nil
    }

    private func checkDirectory() throws {
        try Self.checkDirectory(directory, owner: owner)
    }

    private static func checkDirectory(_ directory: Int32, owner: uid_t) throws {
        var info = stat()
        guard directory >= 0, geteuid() == owner, fstat(directory, &info) == 0,
              info.st_mode & S_IFMT == S_IFDIR, info.st_uid == owner,
              info.st_nlink > 0, info.st_mode & 0o7777 == 0o700 else {
            throw VPNManagementSocketReservationError.unsafeDirectory
        }
    }
}
