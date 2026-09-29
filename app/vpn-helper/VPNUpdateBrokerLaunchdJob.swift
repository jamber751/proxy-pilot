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
        // A successful bootstrap proves only that launchd accepted the plist.
        // Do not let a future transaction retire A on that evidence alone:
        // connect to the fixed endpoint and authenticate the live peer against
        // the exact selected helper B pins before reporting success.
        try proveRunning(deployment, executable: executable, deadline: deadline)
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

    private func proveRunning(_ deployment: VPNAuthorizedDeployment,
                              executable: String, deadline: UInt64) throws {
        #if VPN_UPDATE_BROKER_LAUNCHD_TESTING
        let policy = try deployment.release.testHelperPolicy()
        #else
        let policy = try deployment.release.helperPolicy()
        #endif
        while DispatchTime.now().uptimeNanoseconds < deadline {
            do {
                let connection = try connectEndpoint(deadline: deadline)
                defer { close(connection) }
                // On a socket-activated service the client-side peer token may
                // still identify launchd before accept(2). Use the connection
                // only as the readiness trigger, then bind the exact fixed job's
                // live PID to the already-verified B executable and code policy.
                let processID = try launchedProcessID(deadline: deadline)
                try requireProcess(processID, executes: executable)
                try VPNPeerAuthentication.validate(
                    processID: processID, policy: policy)
                try requireAcceptedConnection(connection, deadline: deadline)
                guard try launchedProcessID(deadline: deadline) == processID else {
                    throw VPNUpdateBrokerLaunchdJobError.launchFailed
                }
                try requireProcess(processID, executes: executable)
                return
            } catch VPNPeerAuthenticationError.denied {
                // The fixed socket reached a live process with the wrong code
                // identity. Retrying would turn an identity violation into a
                // race, so fail closed immediately.
                throw VPNUpdateBrokerLaunchdJobError.launchFailed
            } catch {
                try pause(deadline: deadline)
            }
        }
        throw VPNUpdateBrokerLaunchdJobError.timeout
    }

    /// Waits until the authenticated process has accepted the activation
    /// trigger. Production rejects this root maintenance connection without
    /// reading a frame; a test server may send a readiness byte. Either EOF or
    /// readable data proves the daemon, rather than launchd alone, handled it.
    private func requireAcceptedConnection(_ connection: Int32,
                                           deadline: UInt64) throws {
        while true {
            let now = DispatchTime.now().uptimeNanoseconds
            guard now < deadline else { throw VPNUpdateBrokerLaunchdJobError.timeout }
            var item = pollfd(fd: connection,
                events: Int16(POLLIN | POLLHUP), revents: 0)
            let remaining = max(1, min(100,
                Int((deadline - now + 999_999) / 1_000_000)))
            let result = poll(&item, 1, Int32(remaining))
            if result < 0, errno == EINTR { continue }
            guard result >= 0 else { throw VPNUpdateBrokerLaunchdJobError.launchFailed }
            if result == 0 { continue }
            guard item.revents & Int16(POLLNVAL | POLLERR) == 0 else {
                throw VPNUpdateBrokerLaunchdJobError.launchFailed
            }
            if item.revents & Int16(POLLIN) != 0 {
                var bytes = [UInt8](repeating: 0, count: 64)
                let count = Darwin.read(connection, &bytes, bytes.count)
                if count < 0, errno == EINTR { continue }
                guard count >= 0 else {
                    if errno == EAGAIN || errno == EWOULDBLOCK { continue }
                    throw VPNUpdateBrokerLaunchdJobError.launchFailed
                }
                return
            }
            if item.revents & Int16(POLLHUP) != 0 { return }
        }
    }

    private func launchedProcessID(deadline: UInt64) throws -> pid_t {
        let process = Process()
        let output = Pipe()
        process.executableURL = URL(fileURLWithPath: Self.launchctlPath)
        process.arguments = ["print", "\(domain)/\(label)"]
        process.standardInput = FileHandle.nullDevice
        process.standardOutput = output
        process.standardError = FileHandle.nullDevice
        process.environment = [:]
        guard (try? process.run()) != nil else {
            throw VPNUpdateBrokerLaunchdJobError.launchFailed
        }
        while process.isRunning {
            guard DispatchTime.now().uptimeNanoseconds < deadline else {
                kill(process.processIdentifier, SIGKILL)
                process.waitUntilExit()
                throw VPNUpdateBrokerLaunchdJobError.timeout
            }
            usleep(20_000)
        }
        process.waitUntilExit()
        guard process.terminationReason == .exit,
              process.terminationStatus == 0,
              let text = String(data: output.fileHandleForReading.readDataToEndOfFile(),
                                encoding: .utf8) else {
            throw VPNUpdateBrokerLaunchdJobError.launchFailed
        }
        let values = text.split(separator: "\n").compactMap { line -> pid_t? in
            let value = line.trimmingCharacters(in: .whitespaces)
            guard value.hasPrefix("pid = ") else { return nil }
            let digits = value.dropFirst("pid = ".count)
            guard !digits.isEmpty, digits.allSatisfy(\.isNumber),
                  let parsed = Int32(digits), parsed > 0 else { return nil }
            return parsed
        }
        guard values.count == 1 else {
            throw VPNUpdateBrokerLaunchdJobError.launchFailed
        }
        return values[0]
    }

    private func requireProcess(_ processID: pid_t,
                                executes expectedPath: String) throws {
        var bytes = [UInt8](repeating: 0, count: 4 * Int(MAXPATHLEN))
        let length = bytes.withUnsafeMutableBytes {
            proc_pidpath(processID, $0.baseAddress!, UInt32($0.count))
        }
        guard length > 0, let end = bytes.firstIndex(of: 0), end > 0,
              let path = String(bytes: bytes[..<end], encoding: .utf8),
              path == expectedPath else {
            throw VPNUpdateBrokerLaunchdJobError.launchFailed
        }
        let expected = open(expectedPath,
                            O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        let running = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard expected >= 0, running >= 0 else {
            if expected >= 0 { close(expected) }
            if running >= 0 { close(running) }
            throw VPNUpdateBrokerLaunchdJobError.launchFailed
        }
        defer { close(expected); close(running) }
        var expectedInfo = stat(), runningInfo = stat()
        guard fstat(expected, &expectedInfo) == 0,
              fstat(running, &runningInfo) == 0,
              expectedInfo.st_dev == runningInfo.st_dev,
              expectedInfo.st_ino == runningInfo.st_ino,
              runningInfo.st_mode & S_IFMT == S_IFREG,
              runningInfo.st_nlink == 1 else {
            throw VPNUpdateBrokerLaunchdJobError.launchFailed
        }
    }

    private func connectEndpoint(deadline: UInt64) throws -> Int32 {
        let url = URL(fileURLWithPath: endpoint)
        let parent = open(url.deletingLastPathComponent().path,
                          O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard parent >= 0 else { throw VPNUpdateBrokerLaunchdJobError.unsafeStorage }
        defer { close(parent) }
        var parentInfo = stat(), endpointInfo = stat()
        guard fstat(parent, &parentInfo) == 0,
              parentInfo.st_mode & S_IFMT == S_IFDIR,
              parentInfo.st_uid == geteuid(), parentInfo.st_mode & 0o022 == 0,
              !requirePublicEndpoint || parentInfo.st_mode & 0o7777 == 0o755,
              fstatat(parent, url.lastPathComponent, &endpointInfo,
                      AT_SYMLINK_NOFOLLOW) == 0,
              endpointInfo.st_mode & S_IFMT == S_IFSOCK,
              endpointInfo.st_uid == geteuid(), endpointInfo.st_nlink == 1,
              endpointInfo.st_mode & 0o7777 == 0o666 else {
            throw VPNUpdateBrokerLaunchdJobError.unsafeStorage
        }

        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        let bytes = Array(endpoint.utf8) + [0]
        guard bytes.count <= MemoryLayout.size(ofValue: address.sun_path) else {
            throw VPNUpdateBrokerLaunchdJobError.invalidConfiguration
        }
        withUnsafeMutableBytes(of: &address.sun_path) { buffer in
            buffer.copyBytes(from: bytes)
        }
        let connection = socket(AF_UNIX, SOCK_STREAM, 0)
        guard connection >= 0 else { throw VPNUpdateBrokerLaunchdJobError.launchFailed }
        do {
            guard fcntl(connection, F_SETFD, FD_CLOEXEC) == 0,
                  fcntl(connection, F_SETFL, O_NONBLOCK) == 0 else {
                throw VPNUpdateBrokerLaunchdJobError.launchFailed
            }
            let result = withUnsafePointer(to: &address) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    Darwin.connect(connection, $0,
                        socklen_t(MemoryLayout<sockaddr_un>.size))
                }
            }
            if result != 0 {
                guard errno == EINPROGRESS || errno == EAGAIN || errno == EWOULDBLOCK else {
                    throw VPNUpdateBrokerLaunchdJobError.launchFailed
                }
                while true {
                    let now = DispatchTime.now().uptimeNanoseconds
                    guard now < deadline else { throw VPNUpdateBrokerLaunchdJobError.timeout }
                    var item = pollfd(fd: connection, events: Int16(POLLOUT), revents: 0)
                    let remaining = max(1, min(100,
                        Int((deadline - now + 999_999) / 1_000_000)))
                    let polled = poll(&item, 1, Int32(remaining))
                    if polled < 0, errno == EINTR { continue }
                    guard polled > 0 else {
                        if polled == 0 { continue }
                        throw VPNUpdateBrokerLaunchdJobError.launchFailed
                    }
                    var socketError: Int32 = 0
                    var size = socklen_t(MemoryLayout<Int32>.size)
                    guard getsockopt(connection, SOL_SOCKET, SO_ERROR,
                                     &socketError, &size) == 0,
                          socketError == 0 else {
                        throw VPNUpdateBrokerLaunchdJobError.launchFailed
                    }
                    break
                }
            }
            guard DispatchTime.now().uptimeNanoseconds < deadline else {
                throw VPNUpdateBrokerLaunchdJobError.timeout
            }
            return connection
        } catch {
            close(connection)
            throw error
        }
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
