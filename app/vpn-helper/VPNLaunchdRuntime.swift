import Darwin
import Dispatch
import Foundation

enum VPNLaunchdError: Error {
    case requiresRoot
    case invalidConfiguration
    case unsafeStorage
    case launchFailed
    case cleanupNotConfirmed
    case timeout
}

/// The production `VPNActivationRuntime`: launchd is the only thing that starts,
/// supervises and stops our fixed service. Nothing here comes from IPC — the
/// domain, label, plist location and socket name are fixed, and the executable
/// is the content-addressed file the store already verified for this deployment.
/// It starts an idle helper only: no profile, routes, DNS or VPN operation.
final class VPNLaunchdRuntime: VPNActivationRuntime {
    static let productionLabel = "kz.documentolog.proxypilot.vpn-helper"
    private static let socketName = "helper.sock"
    private static let launchctl = "/bin/launchctl"
    private let domain: String
    private let label: String
    private let plist: URL
    private let storage: URL
    private var directory: Int32

    /// Production entry point. Root is required before touching anything, and
    /// the daemon description lives in the fixed system LaunchDaemons directory.
    static func system(storageDirectory: Int32) throws -> VPNLaunchdRuntime {
        guard geteuid() == 0 else { throw VPNLaunchdError.requiresRoot }
        return try VPNLaunchdRuntime(domain: "system", label: productionLabel,
                                     plistDirectory: URL(fileURLWithPath: "/Library/LaunchDaemons", isDirectory: true),
                                     storageDirectory: storageDirectory)
    }

    #if VPN_LAUNCHD_TESTING
    /// Unprivileged per-user domain for disposable tests, absent from normal
    /// builds. It proves the launchd mechanics, never root service ownership.
    static func testUserDomain(label: String, plistDirectory: URL, storageDirectory: Int32) throws -> VPNLaunchdRuntime {
        try VPNLaunchdRuntime(domain: "gui/\(geteuid())", label: label,
                              plistDirectory: plistDirectory, storageDirectory: storageDirectory)
    }
    #endif

    private init(domain: String, label: String, plistDirectory: URL, storageDirectory: Int32) throws {
        guard !label.isEmpty, label.utf8.count <= 128,
              label.utf8.allSatisfy({
                  (48...57).contains($0) || (65...90).contains($0) ||
                  (97...122).contains($0) || $0 == 45 || $0 == 46
              }) else { throw VPNLaunchdError.invalidConfiguration }
        directory = fcntl(storageDirectory, F_DUPFD_CLOEXEC, 0)
        guard directory >= 0 else { throw VPNLaunchdError.unsafeStorage }
        self.domain = domain
        self.label = label
        self.plist = plistDirectory.appendingPathComponent("\(label).plist")
        // A path is needed for launchd and for connect(2), which have no
        // descriptor-relative form. Resolve it from the descriptor we were
        // given and confirm the name still points at that same directory.
        do {
            var path = [CChar](repeating: 0, count: Int(MAXPATHLEN))
            guard fcntl(directory, F_GETPATH, &path) == 0 else { throw VPNLaunchdError.unsafeStorage }
            storage = URL(fileURLWithPath: String(cString: path), isDirectory: true)
            var opened = stat(), named = stat()
            guard fstat(directory, &opened) == 0, lstat(storage.path, &named) == 0,
                  opened.st_dev == named.st_dev, opened.st_ino == named.st_ino,
                  named.st_mode & S_IFMT == S_IFDIR, opened.st_uid == geteuid(),
                  opened.st_mode & 0o7777 == 0o700,
                  storage.path.utf8.count + 1 + Self.socketName.utf8.count < 104 else {
                throw VPNLaunchdError.unsafeStorage
            }
        } catch { close(directory); directory = -1; throw error }
    }

    deinit { if directory >= 0 { close(directory) } }

    /// Unload the service, then positively confirm it: launchd no longer knows
    /// the label and nothing answers the socket. An unconfirmed stop is an
    /// error, never an assumption — the coordinator must not start a second one.
    func stopAndDrain(deadline: UInt64) throws {
        // "No such process" means it was not loaded, which is the wanted result.
        let status = try launchctl(["bootout", "\(domain)/\(label)"], deadline: deadline)
        guard status == 0 || status == ESRCH || status == EINPROGRESS else { throw VPNLaunchdError.launchFailed }
        while true {
            if try launchctl(["print", "\(domain)/\(label)"], deadline: deadline) != 0 { break }
            try pause(deadline: deadline)
        }
        while true {
            let socket = connectToHelper()
            guard socket >= 0 else { break }
            close(socket)
            try pause(deadline: deadline)
        }
        var endpoint = stat()
        if fstatat(directory, Self.socketName, &endpoint, AT_SYMLINK_NOFOLLOW) == 0 {
            // Only ever remove a socket: a replaced regular file or symlink here
            // means the protected directory is not in the state we require.
            guard endpoint.st_mode & S_IFMT == S_IFSOCK, endpoint.st_uid == geteuid(),
                  unlinkat(directory, Self.socketName, 0) == 0 else { throw VPNLaunchdError.unsafeStorage }
        }
    }

    /// Register and start the selected build, then hand the caller a connected,
    /// close-on-exec descriptor. Readiness authentication is the caller's job:
    /// a listening socket is not proof that our helper is the process behind it.
    func startIdleAndConnect(_ deployment: VPNAuthorizedDeployment, deadline: UInt64) throws -> Int32 {
        let executable = try checkedHelperPath(deployment)
        var endpoint = stat()
        guard fstatat(directory, Self.socketName, &endpoint, AT_SYMLINK_NOFOLLOW) != 0, errno == ENOENT else {
            throw VPNLaunchdError.cleanupNotConfirmed
        }
        try writeServiceDescription(executable: executable)
        guard try launchctl(["bootstrap", domain, plist.path], deadline: deadline) == 0 else {
            throw VPNLaunchdError.launchFailed
        }
        while true {
            let socket = connectToHelper()
            if socket >= 0 {
                guard fcntl(socket, F_SETFD, FD_CLOEXEC) == 0 else { close(socket); throw VPNLaunchdError.launchFailed }
                return socket
            }
            try pause(deadline: deadline)
        }
    }

    private func checkedHelperPath(_ deployment: VPNAuthorizedDeployment) throws -> String {
        // The store verified this file's signature, pinned hashes, permissions
        // and ACL for this deployment. Recheck that the name still resolves to a
        // private regular file before handing a path to launchd.
        let file = openat(directory, deployment.helperFileName, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard file >= 0 else { throw VPNLaunchdError.unsafeStorage }
        defer { close(file) }
        var attributes = stat()
        guard fstat(file, &attributes) == 0, attributes.st_mode & S_IFMT == S_IFREG,
              attributes.st_nlink == 1, attributes.st_uid == geteuid(),
              attributes.st_mode & 0o7777 == 0o700 else { throw VPNLaunchdError.unsafeStorage }
        return storage.appendingPathComponent(deployment.helperFileName).path
    }

    private func writeServiceDescription(executable: String) throws {
        let description: [String: Any] = [
            "Label": label,
            "ProgramArguments": [executable, "serve", storage.appendingPathComponent(Self.socketName).path],
            "RunAtLoad": true,
            "KeepAlive": false,
        ]
        guard let data = try? PropertyListSerialization.data(fromPropertyList: description, format: .xml, options: 0) else {
            throw VPNLaunchdError.invalidConfiguration
        }
        let folder = plist.deletingLastPathComponent()
        let parent = open(folder.path, O_RDONLY | O_DIRECTORY | O_CLOEXEC)
        guard parent >= 0 else { throw VPNLaunchdError.unsafeStorage }
        defer { close(parent) }
        var attributes = stat()
        guard fstat(parent, &attributes) == 0, attributes.st_uid == geteuid(),
              attributes.st_mode & 0o022 == 0 else { throw VPNLaunchdError.unsafeStorage }
        let temporary = ".\(label).\(UUID().uuidString).plist"
        let file = openat(parent, temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o644)
        guard file >= 0 else { throw VPNLaunchdError.unsafeStorage }
        defer { close(file); unlinkat(parent, temporary, 0) }
        try data.withUnsafeBytes { bytes in
            var offset = 0
            while offset < bytes.count {
                let count = write(file, bytes.baseAddress!.advanced(by: offset), bytes.count - offset)
                if count < 0, errno == EINTR { continue }
                guard count > 0 else { throw VPNLaunchdError.unsafeStorage }
                offset += count
            }
        }
        guard fsync(file) == 0,
              renameat(parent, temporary, parent, plist.lastPathComponent) == 0,
              fsync(parent) == 0 else { throw VPNLaunchdError.unsafeStorage }
    }

    private func connectToHelper() -> Int32 {
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        let bytes = Array(storage.appendingPathComponent(Self.socketName).path.utf8) + [0]
        guard bytes.count <= MemoryLayout.size(ofValue: address.sun_path) else { return -1 }
        withUnsafeMutableBytes(of: &address.sun_path) { $0.copyBytes(from: bytes) }
        let descriptor = socket(AF_UNIX, SOCK_STREAM, 0)
        guard descriptor >= 0 else { return -1 }
        let result = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(descriptor, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard result == 0 else { close(descriptor); return -1 }
        return descriptor
    }

    /// launchctl runs with no shell, no inherited environment payload and no
    /// caller-supplied arguments; a run that outlives the deadline is killed.
    private func launchctl(_ arguments: [String], deadline: UInt64) throws -> Int32 {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: Self.launchctl)
        process.arguments = arguments
        process.standardInput = FileHandle.nullDevice
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        process.environment = [:]
        guard (try? process.run()) != nil else { throw VPNLaunchdError.launchFailed }
        while process.isRunning {
            guard DispatchTime.now().uptimeNanoseconds < deadline else {
                kill(process.processIdentifier, SIGKILL)
                process.waitUntilExit()
                throw VPNLaunchdError.timeout
            }
            usleep(20_000)
        }
        process.waitUntilExit()
        guard process.terminationReason == .exit else { throw VPNLaunchdError.launchFailed }
        return process.terminationStatus
    }

    private func pause(deadline: UInt64) throws {
        guard DispatchTime.now().uptimeNanoseconds < deadline else { throw VPNLaunchdError.timeout }
        usleep(20_000)
    }
}
