import Darwin
import Dispatch
import Foundation

enum VPNUpdateBrokerLaunchdJobError: Error {
    case requiresRoot
    case invalidConfiguration
    case unsafeStorage
    case launchFailed
    case timeout
}

/// Persistent launchd ownership for the release-bound update broker.
///
/// Production has no configurable label, program, arguments, plist, domain, or
/// endpoint. The only executable ever published is the selected release's
/// content-addressed `helper-<sha256>` after its bytes and code identity have
/// been checked again against that exact signed release.
final class VPNUpdateBrokerLaunchdJob {
    static let productionLabel = "kz.documentolog.proxypilot.vpn-update-broker"
    static let brokerArgument = "serve-update-broker"
    static let storagePath = "/Library/Application Support/ProxyPilot/VPN"
    static let endpointPath = "/Library/Application Support/kz.documentolog.proxypilot.vpn/update-broker.sock"

    private static let launchctlPath = "/bin/launchctl"
    private static let socketKey = "Broker"

    private let domain: String
    private let label: String
    private let plist: URL
    private let endpoint: String
    private let storage: URL
    private let requirePublicEndpoint: Bool
    private var directory: Int32

    static func system(storageDirectory: Int32) throws -> VPNUpdateBrokerLaunchdJob {
        guard getuid() == 0, geteuid() == 0 else {
            throw VPNUpdateBrokerLaunchdJobError.requiresRoot
        }
        return try VPNUpdateBrokerLaunchdJob(
            domain: "system",
            label: productionLabel,
            plistDirectory: URL(fileURLWithPath: "/Library/LaunchDaemons", isDirectory: true),
            endpoint: endpointPath,
            storageDirectory: storageDirectory,
            requireSystemStorage: true)
    }

    #if VPN_UPDATE_BROKER_LAUNCHD_TESTING
    /// Disposable, unprivileged launchd seam. None of its configurable values
    /// is present in a production build or reachable from broker requests.
    static func testUserDomain(label: String, plistDirectory: URL, endpoint: URL,
                               storageDirectory: Int32) throws
        -> VPNUpdateBrokerLaunchdJob {
        try VPNUpdateBrokerLaunchdJob(
            domain: "gui/\(geteuid())", label: label,
            plistDirectory: plistDirectory, endpoint: endpoint.path,
            storageDirectory: storageDirectory, requireSystemStorage: false)
    }
    #endif

    private init(domain: String, label: String, plistDirectory: URL,
                 endpoint: String, storageDirectory: Int32,
                 requireSystemStorage: Bool) throws {
        guard Self.validLabel(label), endpoint.utf8.count > 1,
              endpoint.utf8.count < 104, endpoint.first == "/" else {
            throw VPNUpdateBrokerLaunchdJobError.invalidConfiguration
        }
        directory = fcntl(storageDirectory, F_DUPFD_CLOEXEC, 0)
        guard directory >= 0 else { throw VPNUpdateBrokerLaunchdJobError.unsafeStorage }
        do {
            var path = [CChar](repeating: 0, count: Int(MAXPATHLEN))
            guard fcntl(directory, F_GETPATH, &path) == 0 else {
                throw VPNUpdateBrokerLaunchdJobError.unsafeStorage
            }
            storage = URL(fileURLWithPath: String(cString: path), isDirectory: true)
            var opened = stat(), named = stat()
            guard fstat(directory, &opened) == 0,
                  lstat(storage.path, &named) == 0,
                  opened.st_dev == named.st_dev, opened.st_ino == named.st_ino,
                  named.st_mode & S_IFMT == S_IFDIR,
                  opened.st_uid == geteuid(), opened.st_mode & 0o7777 == 0o700 else {
                throw VPNUpdateBrokerLaunchdJobError.unsafeStorage
            }
            if requireSystemStorage {
                guard storage.path == Self.storagePath,
                      label == Self.productionLabel,
                      domain == "system", endpoint == Self.endpointPath,
                      plistDirectory.path == "/Library/LaunchDaemons" else {
                    throw VPNUpdateBrokerLaunchdJobError.unsafeStorage
                }
            }
        } catch {
            close(directory)
            directory = -1
            throw error
        }
        self.domain = domain
        self.label = label
        self.endpoint = endpoint
        requirePublicEndpoint = requireSystemStorage
        plist = plistDirectory.appendingPathComponent("\(label).plist")
    }

    deinit { if directory >= 0 { close(directory) } }

    /// Replaces exactly this label with a job bound to the selected helper.
    /// Bootout precedes the atomic plist replacement, so a changed release can
    /// never leave the old process supervised by a description naming the new.
    func installAndStart(_ deployment: VPNAuthorizedDeployment,
                         deadline: UInt64) throws {
        let executable = try checkedHelperPath(deployment)
        try bootout(deadline: deadline)
        try removeEndpoint()
        try writeDescription(executable: executable)
        guard try launchctl(["bootstrap", domain, plist.path], deadline: deadline) == 0 else {
            throw VPNUpdateBrokerLaunchdJobError.launchFailed
        }
    }

    /// Bootout and removal are independently idempotent. Only the exact label
    /// and exact plist basename owned by this object are affected.
    func remove(deadline: UInt64) throws {
        try bootout(deadline: deadline)
        try removeEndpoint()
        try removeDescription()
    }

    private func bootout(deadline: UInt64) throws {
        let status = try launchctl(["bootout", "\(domain)/\(label)"], deadline: deadline)
        guard status == 0 || status == ESRCH || status == EINPROGRESS else {
            throw VPNUpdateBrokerLaunchdJobError.launchFailed
        }
        while try launchctl(["print", "\(domain)/\(label)"], deadline: deadline) == 0 {
            try pause(deadline: deadline)
        }
    }

    private func checkedHelperPath(_ deployment: VPNAuthorizedDeployment) throws -> String {
        let file = openat(directory, deployment.helperFileName,
                          O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard file >= 0 else { throw VPNUpdateBrokerLaunchdJobError.unsafeStorage }
        defer { close(file) }
        var attributes = stat()
        guard fstat(file, &attributes) == 0,
              attributes.st_mode & S_IFMT == S_IFREG,
              attributes.st_nlink == 1, attributes.st_uid == geteuid(),
              attributes.st_mode & 0o7777 == 0o700,
              attributes.st_size > 0,
              attributes.st_size <= VPNReleaseAuthority.maximumHelperBytes else {
            throw VPNUpdateBrokerLaunchdJobError.unsafeStorage
        }
        var bytes = Data(count: Int(attributes.st_size))
        try bytes.withUnsafeMutableBytes { buffer in
            var offset = 0
            while offset < buffer.count {
                let count = pread(file, buffer.baseAddress!.advanced(by: offset),
                                  buffer.count - offset, off_t(offset))
                if count < 0, errno == EINTR { continue }
                guard count > 0 else { throw VPNUpdateBrokerLaunchdJobError.unsafeStorage }
                offset += count
            }
        }
        try VPNHelperArtifact.validate(protectedFile: file, data: bytes,
                                       release: deployment.release)
        var path = [CChar](repeating: 0, count: Int(MAXPATHLEN))
        guard fcntl(file, F_GETPATH, &path) == 0 else {
            throw VPNUpdateBrokerLaunchdJobError.unsafeStorage
        }
        let resolved = String(cString: path)
        guard resolved == storage.appendingPathComponent(deployment.helperFileName).path else {
            throw VPNUpdateBrokerLaunchdJobError.unsafeStorage
        }
        return resolved
    }

    private func writeDescription(executable: String) throws {
        let description: [String: Any] = [
            "Label": label,
            "ProgramArguments": [executable, Self.brokerArgument],
            "RunAtLoad": true,
            "KeepAlive": true,
            "ProcessType": "Background",
            "ThrottleInterval": 10,
            "Sockets": [
                Self.socketKey: [
                    "SockPathName": endpoint,
                    "SockPathMode": NSNumber(value: 0o666),
                ],
            ],
        ]
        guard let data = try? PropertyListSerialization.data(
            fromPropertyList: description, format: .xml, options: 0) else {
            throw VPNUpdateBrokerLaunchdJobError.invalidConfiguration
        }
        let parent = try openPlistDirectory()
        defer { close(parent) }
        var existing = stat()
        if fstatat(parent, plist.lastPathComponent, &existing, AT_SYMLINK_NOFOLLOW) == 0 {
            guard existing.st_mode & S_IFMT == S_IFREG,
                  existing.st_uid == geteuid(), existing.st_mode & 0o7777 == 0o644 else {
                throw VPNUpdateBrokerLaunchdJobError.unsafeStorage
            }
        } else if errno != ENOENT {
            throw VPNUpdateBrokerLaunchdJobError.unsafeStorage
        }
        let temporary = ".\(label).\(UUID().uuidString).plist"
        let file = openat(parent, temporary,
                          O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o644)
        guard file >= 0 else { throw VPNUpdateBrokerLaunchdJobError.unsafeStorage }
        defer { close(file); unlinkat(parent, temporary, 0) }
        try data.withUnsafeBytes { buffer in
            var offset = 0
            while offset < buffer.count {
                let count = write(file, buffer.baseAddress!.advanced(by: offset),
                                  buffer.count - offset)
                if count < 0, errno == EINTR { continue }
                guard count > 0 else { throw VPNUpdateBrokerLaunchdJobError.unsafeStorage }
                offset += count
            }
        }
        guard fsync(file) == 0,
              renameat(parent, temporary, parent, plist.lastPathComponent) == 0,
              fsync(parent) == 0 else { throw VPNUpdateBrokerLaunchdJobError.unsafeStorage }
    }

    private func removeDescription() throws {
        let parent = try openPlistDirectory()
        defer { close(parent) }
        var attributes = stat()
        guard fstatat(parent, plist.lastPathComponent, &attributes,
                      AT_SYMLINK_NOFOLLOW) == 0 else {
            guard errno == ENOENT else { throw VPNUpdateBrokerLaunchdJobError.unsafeStorage }
            return
        }
        guard attributes.st_mode & S_IFMT == S_IFREG,
              attributes.st_uid == geteuid(), attributes.st_mode & 0o7777 == 0o644,
              unlinkat(parent, plist.lastPathComponent, 0) == 0,
              fsync(parent) == 0 else { throw VPNUpdateBrokerLaunchdJobError.unsafeStorage }
    }

    /// launchd closes the activated descriptor at bootout but can leave the
    /// Unix-domain name behind. Remove only the exact socket after unload; a
    /// substituted file or symlink is an unsafe state, never cleanup fodder.
    private func removeEndpoint() throws {
        let url = URL(fileURLWithPath: endpoint)
        let parent = open(url.deletingLastPathComponent().path,
                          O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard parent >= 0 else { throw VPNUpdateBrokerLaunchdJobError.unsafeStorage }
        defer { close(parent) }
        var parentAttributes = stat()
        guard fstat(parent, &parentAttributes) == 0,
              parentAttributes.st_mode & S_IFMT == S_IFDIR,
              parentAttributes.st_uid == geteuid(),
              parentAttributes.st_mode & 0o022 == 0,
              !requirePublicEndpoint || parentAttributes.st_mode & 0o7777 == 0o755 else {
            throw VPNUpdateBrokerLaunchdJobError.unsafeStorage
        }
        var attributes = stat()
        guard fstatat(parent, url.lastPathComponent, &attributes,
                      AT_SYMLINK_NOFOLLOW) == 0 else {
            guard errno == ENOENT else {
                throw VPNUpdateBrokerLaunchdJobError.unsafeStorage
            }
            return
        }
        guard attributes.st_mode & S_IFMT == S_IFSOCK,
              attributes.st_uid == geteuid(),
              unlinkat(parent, url.lastPathComponent, 0) == 0,
              fsync(parent) == 0 else {
            throw VPNUpdateBrokerLaunchdJobError.unsafeStorage
        }
    }

    private func openPlistDirectory() throws -> Int32 {
        let parent = open(plist.deletingLastPathComponent().path,
                          O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard parent >= 0 else { throw VPNUpdateBrokerLaunchdJobError.unsafeStorage }
        var attributes = stat()
        guard fstat(parent, &attributes) == 0,
              attributes.st_mode & S_IFMT == S_IFDIR,
              attributes.st_uid == geteuid(), attributes.st_mode & 0o022 == 0 else {
            close(parent)
            throw VPNUpdateBrokerLaunchdJobError.unsafeStorage
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
        guard (try? process.run()) != nil else { throw VPNUpdateBrokerLaunchdJobError.launchFailed }
        while process.isRunning {
            guard DispatchTime.now().uptimeNanoseconds < deadline else {
                kill(process.processIdentifier, SIGKILL)
                process.waitUntilExit()
                throw VPNUpdateBrokerLaunchdJobError.timeout
            }
            usleep(20_000)
        }
        process.waitUntilExit()
        guard process.terminationReason == .exit else {
            throw VPNUpdateBrokerLaunchdJobError.launchFailed
        }
        return process.terminationStatus
    }

    private func pause(deadline: UInt64) throws {
        guard DispatchTime.now().uptimeNanoseconds < deadline else {
            throw VPNUpdateBrokerLaunchdJobError.timeout
        }
        usleep(20_000)
    }

    private static func validLabel(_ value: String) -> Bool {
        !value.isEmpty && value.utf8.count <= 128 && value.utf8.allSatisfy {
            (48...57).contains($0) || (65...90).contains($0)
                || (97...122).contains($0) || $0 == 45 || $0 == 46
        }
    }
}
