import Darwin
import Dispatch
import Foundation

/// A separate boot-time recovery job for the narrow A→B selector window.
/// Its executable is never the mutable app in /Applications: launchd receives
/// only the already authenticated, content-addressed helper in protected
/// storage. The helper accepts no caller-controlled transaction or path.
final class VPNRecoveryLaunchdJob {
    static let productionLabel = "kz.documentolog.proxypilot.vpn-recovery"
    static let recoveryArgument = "recover-update"
    static let storagePath = "/Library/Application Support/ProxyPilot/VPN"
    private static let launchctlPath = "/bin/launchctl"

    private let domain: String
    private let label: String
    private let plist: URL
    private let storage: URL
    private var directory: Int32

    static func system(storageDirectory: Int32) throws -> VPNRecoveryLaunchdJob {
        guard getuid() == 0, geteuid() == 0 else { throw VPNLaunchdError.requiresRoot }
        return try VPNRecoveryLaunchdJob(
            domain: "system", label: productionLabel,
            plistDirectory: URL(fileURLWithPath: "/Library/LaunchDaemons", isDirectory: true),
            storageDirectory: storageDirectory, requireSystemStorage: true)
    }

    #if VPN_LAUNCHD_TESTING
    static func testUserDomain(label: String, plistDirectory: URL,
                               storageDirectory: Int32) throws -> VPNRecoveryLaunchdJob {
        try VPNRecoveryLaunchdJob(domain: "gui/\(geteuid())", label: label,
                                  plistDirectory: plistDirectory,
                                  storageDirectory: storageDirectory,
                                  requireSystemStorage: false)
    }
    #endif

    private init(domain: String, label: String, plistDirectory: URL,
                 storageDirectory: Int32, requireSystemStorage: Bool) throws {
        guard !label.isEmpty, label.utf8.count <= 128,
              label.utf8.allSatisfy({
                  (48...57).contains($0) || (65...90).contains($0) ||
                  (97...122).contains($0) || $0 == 45 || $0 == 46
              }) else { throw VPNLaunchdError.invalidConfiguration }
        directory = fcntl(storageDirectory, F_DUPFD_CLOEXEC, 0)
        guard directory >= 0 else { throw VPNLaunchdError.unsafeStorage }
        do {
            var path = [CChar](repeating: 0, count: Int(MAXPATHLEN))
            guard fcntl(directory, F_GETPATH, &path) == 0 else {
                throw VPNLaunchdError.unsafeStorage
            }
            storage = URL(fileURLWithPath: String(cString: path), isDirectory: true)
            var opened = stat(), named = stat()
            guard fstat(directory, &opened) == 0, lstat(storage.path, &named) == 0,
                  opened.st_dev == named.st_dev, opened.st_ino == named.st_ino,
                  named.st_mode & S_IFMT == S_IFDIR, opened.st_uid == geteuid(),
                  opened.st_mode & 0o7777 == 0o700 else {
                throw VPNLaunchdError.unsafeStorage
            }
            if requireSystemStorage {
                guard storage.path == Self.storagePath else {
                    throw VPNLaunchdError.unsafeStorage
                }
            }
        } catch {
            close(directory)
            directory = -1
            throw error
        }
        self.domain = domain
        self.label = label
        plist = plistDirectory.appendingPathComponent("\(label).plist")
    }

    deinit { if directory >= 0 { close(directory) } }

    /// Re-validates the protected candidate, replaces only our exact launchd
    /// description, and bootstraps it. RunAtLoad starts the bounded waiter before
    /// the selector is committed. The entry maps only transient failures to a
    /// nonzero exit, so SuccessfulExit=false retries only recoverable work.
    func installAndArm(_ deployment: VPNAuthorizedDeployment,
                       deadline: UInt64) throws {
        let executable = try checkedHelperPath(deployment)
        let old = try launchctl(["bootout", "\(domain)/\(label)"], deadline: deadline)
        guard old == 0 || old == ESRCH || old == EINPROGRESS else {
            throw VPNLaunchdError.launchFailed
        }
        try waitUntilUnloaded(deadline: deadline)
        try writeDescription(executable: executable)
        guard try launchctl(["bootstrap", domain, plist.path], deadline: deadline) == 0 else {
            throw VPNLaunchdError.launchFailed
        }
    }

    /// Unloads the exact job and removes only its own regular plist.
    func remove(deadline: UInt64) throws {
        let status = try launchctl(["bootout", "\(domain)/\(label)"], deadline: deadline)
        guard status == 0 || status == ESRCH || status == EINPROGRESS else {
            throw VPNLaunchdError.launchFailed
        }
        try waitUntilUnloaded(deadline: deadline)
        try removeDescription()
    }

    /// Disarms the recovery job from inside that job itself. The description is
    /// durably removed first because a successful `bootout` may terminate the
    /// caller before it can execute another instruction. A failed bootout leaves
    /// the already-loaded KeepAlive job able to retry, but it cannot return after
    /// reboot because its persistent description is gone.
    func removeCurrent(deadline: UInt64) throws {
        try removeDescription()
        let status = try launchctl(["bootout", "\(domain)/\(label)"], deadline: deadline)
        guard status == 0 || status == ESRCH || status == EINPROGRESS else {
            throw VPNLaunchdError.launchFailed
        }
    }

    private func removeDescription() throws {
        let parent = try openPlistDirectory()
        defer { close(parent) }
        var attributes = stat()
        guard fstatat(parent, plist.lastPathComponent, &attributes, AT_SYMLINK_NOFOLLOW) == 0 else {
            guard errno == ENOENT else { throw VPNLaunchdError.unsafeStorage }
            return
        }
        guard attributes.st_mode & S_IFMT == S_IFREG,
              attributes.st_uid == geteuid(),
              attributes.st_mode & 0o7777 == 0o644,
              unlinkat(parent, plist.lastPathComponent, 0) == 0,
              fsync(parent) == 0 else { throw VPNLaunchdError.unsafeStorage }
    }

    private func checkedHelperPath(_ deployment: VPNAuthorizedDeployment) throws -> String {
        let file = openat(directory, deployment.helperFileName,
                          O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard file >= 0 else { throw VPNLaunchdError.unsafeStorage }
        defer { close(file) }
        var attributes = stat()
        guard fstat(file, &attributes) == 0,
              attributes.st_mode & S_IFMT == S_IFREG,
              attributes.st_nlink == 1, attributes.st_uid == geteuid(),
              attributes.st_mode & 0o7777 == 0o700,
              attributes.st_size > 0,
              attributes.st_size <= VPNReleaseAuthority.maximumHelperBytes else {
            throw VPNLaunchdError.unsafeStorage
        }
        var bytes = Data(count: Int(attributes.st_size))
        try bytes.withUnsafeMutableBytes { buffer in
            var offset = 0
            while offset < buffer.count {
                let count = pread(file, buffer.baseAddress!.advanced(by: offset),
                                  buffer.count - offset, off_t(offset))
                if count < 0, errno == EINTR { continue }
                guard count > 0 else { throw VPNLaunchdError.unsafeStorage }
                offset += count
            }
        }
        try VPNHelperArtifact.validate(protectedFile: file, data: bytes,
                                       release: deployment.release)
        var path = [CChar](repeating: 0, count: Int(MAXPATHLEN))
        guard fcntl(file, F_GETPATH, &path) == 0 else {
            throw VPNLaunchdError.unsafeStorage
        }
        return String(cString: path)
    }

    private func writeDescription(executable: String) throws {
        let description: [String: Any] = [
            "Label": label,
            "ProgramArguments": [executable, Self.recoveryArgument, Self.storagePath],
            "RunAtLoad": true,
            "KeepAlive": ["SuccessfulExit": false],
            "ThrottleInterval": 10,
        ]
        guard let data = try? PropertyListSerialization.data(
            fromPropertyList: description, format: .xml, options: 0) else {
            throw VPNLaunchdError.invalidConfiguration
        }
        let parent = try openPlistDirectory()
        defer { close(parent) }
        var existing = stat()
        if fstatat(parent, plist.lastPathComponent, &existing, AT_SYMLINK_NOFOLLOW) == 0 {
            guard existing.st_mode & S_IFMT == S_IFREG,
                  existing.st_uid == geteuid(),
                  existing.st_mode & 0o7777 == 0o644 else {
                throw VPNLaunchdError.unsafeStorage
            }
        } else if errno != ENOENT {
            throw VPNLaunchdError.unsafeStorage
        }
        let temporary = ".\(label).\(UUID().uuidString).plist"
        let file = openat(parent, temporary,
                          O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o644)
        guard file >= 0 else { throw VPNLaunchdError.unsafeStorage }
        defer { close(file); unlinkat(parent, temporary, 0) }
        try data.withUnsafeBytes { buffer in
            var offset = 0
            while offset < buffer.count {
                let count = write(file, buffer.baseAddress!.advanced(by: offset),
                                  buffer.count - offset)
                if count < 0, errno == EINTR { continue }
                guard count > 0 else { throw VPNLaunchdError.unsafeStorage }
                offset += count
            }
        }
        guard fsync(file) == 0,
              renameat(parent, temporary, parent, plist.lastPathComponent) == 0,
              fsync(parent) == 0 else { throw VPNLaunchdError.unsafeStorage }
    }

    private func openPlistDirectory() throws -> Int32 {
        let parent = open(plist.deletingLastPathComponent().path,
                          O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard parent >= 0 else { throw VPNLaunchdError.unsafeStorage }
        var attributes = stat()
        guard fstat(parent, &attributes) == 0,
              attributes.st_mode & S_IFMT == S_IFDIR,
              attributes.st_uid == geteuid(),
              attributes.st_mode & 0o022 == 0 else {
            close(parent)
            throw VPNLaunchdError.unsafeStorage
        }
        return parent
    }

    private func launchctl(_ arguments: [String], deadline: UInt64) throws -> Int32 {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: Self.launchctlPath)
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

    private func waitUntilUnloaded(deadline: UInt64) throws {
        while try launchctl(["print", "\(domain)/\(label)"], deadline: deadline) == 0 {
            guard DispatchTime.now().uptimeNanoseconds < deadline else {
                throw VPNLaunchdError.timeout
            }
            usleep(20_000)
        }
    }
}
