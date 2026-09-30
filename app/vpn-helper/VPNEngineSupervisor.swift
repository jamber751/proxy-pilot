import Darwin
import Foundation

/// OpenVPN may configure only its held tunnel interface. Profile/pushed routes,
/// DNS and scripts remain disabled; ProxyPilot owns those later transactions.
enum VPNEngineBootstrapPolicy {
    static func arguments(profileDescriptor: Int32,
                          management: VPNEngineManagementConfiguration?) -> [String] {
        var values = [
            "vpn-engine", "--config", "/dev/fd/\(profileDescriptor)",
            "--route-noexec", "--script-security", "1", "--auth-nocache", "--route-nopull"
        ]
        if let management {
            values += ["--management", management.socketPath, "unix",
                       "--management-hold", "--management-query-passwords"]
        }
        return values
    }
}

/// Private process role of the signed helper. The ordinary helper owns one end
/// of a socketpair; this process owns and reaps OpenVPN. EOF is an unforgeable
/// lifetime capability: if the ordinary helper disappears, OpenVPN is stopped.
enum VPNEngineSupervisorEntry {
    static let argument = "--proxypilot-private-engine-supervisor-v1"
    private static let processName = "vpn-engine-supervisor"
    private static let controlDescriptor: Int32 = 20
    private static let profileDescriptor: Int32 = 21
    private static let engineDescriptor: Int32 = 22
    private static let defaultGraceMilliseconds = 500

    static func runIfRequested(arguments: [String]) -> Int32? {
        guard arguments.contains(argument) || arguments.first == processName else { return nil }
        guard arguments == [processName, argument] else { return 64 }
        return run()
    }

    private static func run() -> Int32 {
        signal(SIGPIPE, SIG_IGN)
        signal(SIGTERM, SIG_IGN)
        signal(SIGINT, SIG_IGN)
        signal(SIGHUP, SIG_IGN)
        guard validCapability(controlDescriptor, socket: true),
              validCapability(profileDescriptor, socket: false),
              validEngine(engineDescriptor), privateProcessShape() else { return 65 }
        var child: pid_t?
        do {
            let management = try VPNEngineSupervisorWire.readStartup(from: controlDescriptor,
                                                                      timeoutMilliseconds: 5_000)
            let launched = try spawnEngine(management: management)
            child = launched
            try VPNEngineSupervisorWire.sendStarted(to: controlDescriptor)
            return supervise(launched)
        } catch {
            if let child { _ = terminateAndReap(child, graceMilliseconds: defaultGraceMilliseconds) }
            try? VPNEngineSupervisorWire.sendFailure(to: controlDescriptor)
            return 66
        }
    }

    private static func supervise(_ child: pid_t) -> Int32 {
        var command = [UInt8]()
        while true {
            if let terminal = reap(child, options: WNOHANG) {
                try? VPNEngineSupervisorWire.sendTerminal(terminal, to: controlDescriptor)
                return 0
            }
            var item = pollfd(fd: controlDescriptor,
                              events: Int16(POLLIN | POLLHUP | POLLERR), revents: 0)
            let result = poll(&item, 1, 20)
            if result < 0 && errno == EINTR { continue }
            if result < 0 {
                _ = terminateAndReap(child, graceMilliseconds: defaultGraceMilliseconds)
                return 67
            }
            if result == 0 { continue }
            if item.revents & Int16(POLLIN) != 0 {
                var bytes = [UInt8](repeating: 0, count: 32)
                let count = Darwin.read(controlDescriptor, &bytes, bytes.count)
                if count < 0 && errno == EINTR { continue }
                if count <= 0 {
                    _ = terminateAndReap(child, graceMilliseconds: defaultGraceMilliseconds)
                    return 0
                }
                command.append(contentsOf: bytes.prefix(count))
                guard command.count <= VPNEngineSupervisorWire.commandSize else {
                    _ = terminateAndReap(child, graceMilliseconds: defaultGraceMilliseconds)
                    return 68
                }
                if command.count == VPNEngineSupervisorWire.commandSize {
                    guard let grace = VPNEngineSupervisorWire.decodeStop(command) else {
                        _ = terminateAndReap(child, graceMilliseconds: defaultGraceMilliseconds)
                        return 68
                    }
                    let terminal = terminateAndReap(child, graceMilliseconds: grace)
                    try? VPNEngineSupervisorWire.sendTerminal(terminal, to: controlDescriptor)
                    return 0
                }
            }
            if item.revents & Int16(POLLHUP | POLLERR | POLLNVAL) != 0 {
                _ = terminateAndReap(child, graceMilliseconds: defaultGraceMilliseconds)
                return 0
            }
        }
    }

    private static func spawnEngine(management: VPNEngineManagementConfiguration?) throws -> pid_t {
        guard lseek(profileDescriptor, 0, SEEK_SET) == 0 else {
            throw VPNEngineProcessError.invalidProfile
        }
        var profile = stat(), selected = stat()
        guard fstat(profileDescriptor, &profile) == 0,
              profile.st_mode & S_IFMT == S_IFREG, profile.st_uid == geteuid(),
              profile.st_nlink == 1, profile.st_mode & 0o7777 == 0o600,
              profile.st_size > 0, profile.st_size <= VPNProfileVault.maximumBytes,
              fstat(engineDescriptor, &selected) == 0,
              selected.st_mode & S_IFMT == S_IFREG, selected.st_uid == geteuid(),
              selected.st_nlink == 1, selected.st_mode & 0o7022 == 0 else {
            throw VPNEngineProcessError.validationFailed
        }
        if let management {
            var endpoint = stat()
            guard lstat(management.socketPath, &endpoint) == -1, errno == ENOENT else {
                throw VPNEngineProcessError.invalidManagementEndpoint
            }
        }
        var enginePath = [CChar](repeating: 0, count: Int(MAXPATHLEN))
        guard fcntl(engineDescriptor, F_GETPATH, &enginePath) == 0 else {
            throw VPNEngineProcessError.validationFailed
        }
        var namedBeforeSpawn = stat()
        guard lstat(String(cString: enginePath), &namedBeforeSpawn) == 0,
              selected.st_dev == namedBeforeSpawn.st_dev,
              selected.st_ino == namedBeforeSpawn.st_ino else {
            throw VPNEngineProcessError.validationFailed
        }

        var actions: posix_spawn_file_actions_t? = nil
        var attributes: posix_spawnattr_t? = nil
        guard posix_spawn_file_actions_init(&actions) == 0,
              posix_spawnattr_init(&attributes) == 0 else {
            if actions != nil { posix_spawn_file_actions_destroy(&actions) }
            throw VPNEngineProcessError.spawnFailed(ENOMEM)
        }
        defer {
            posix_spawn_file_actions_destroy(&actions)
            posix_spawnattr_destroy(&attributes)
        }
        let stagedProfile = fcntl(profileDescriptor, F_DUPFD_CLOEXEC, 64)
        guard stagedProfile >= 0 else { throw VPNEngineProcessError.invalidProfile }
        defer { close(stagedProfile) }
        let null = "/dev/null"
        guard posix_spawn_file_actions_addopen(&actions, STDIN_FILENO, null, O_RDONLY, 0) == 0,
              posix_spawn_file_actions_addopen(&actions, STDOUT_FILENO, null, O_WRONLY, 0) == 0,
              posix_spawn_file_actions_addopen(&actions, STDERR_FILENO, null, O_WRONLY, 0) == 0,
              posix_spawn_file_actions_adddup2(&actions, stagedProfile, profileDescriptor) == 0 else {
            throw VPNEngineProcessError.spawnFailed(EINVAL)
        }
        let flags = Int16(POSIX_SPAWN_CLOEXEC_DEFAULT | POSIX_SPAWN_SETSIGDEF
                          | POSIX_SPAWN_SETSIGMASK)
        var emptyMask = sigset_t(), defaults = sigset_t()
        sigemptyset(&emptyMask); sigfillset(&defaults)
        guard posix_spawnattr_setflags(&attributes, flags) == 0,
              posix_spawnattr_setsigmask(&attributes, &emptyMask) == 0,
              posix_spawnattr_setsigdefault(&attributes, &defaults) == 0 else {
            throw VPNEngineProcessError.spawnFailed(EINVAL)
        }
        let argv = VPNEngineBootstrapPolicy.arguments(profileDescriptor: profileDescriptor,
                                                       management: management)
        var environment: [UnsafeMutablePointer<CChar>?] = [nil]
        var child: pid_t = 0
        guard let result = withCStrings(argv, { arguments in
            environment.withUnsafeMutableBufferPointer { environment in
                posix_spawn(&child, enginePath, &actions, &attributes,
                            arguments, environment.baseAddress!)
            }
        }) else { throw VPNEngineProcessError.spawnFailed(ENOMEM) }
        guard result == 0, child > 0 else { throw VPNEngineProcessError.spawnFailed(result) }
        var named = stat()
        guard lstat(String(cString: enginePath), &named) == 0,
              selected.st_dev == named.st_dev, selected.st_ino == named.st_ino else {
            _ = kill(child, SIGKILL); _ = reap(child, options: 0)
            throw VPNEngineProcessError.validationFailed
        }
        return child
    }

    private static func validCapability(_ descriptor: Int32, socket: Bool) -> Bool {
        var attributes = stat()
        guard fstat(descriptor, &attributes) == 0 else { return false }
        return socket ? attributes.st_mode & S_IFMT == S_IFSOCK
                      : attributes.st_mode & S_IFMT == S_IFREG
    }

    private static func validEngine(_ descriptor: Int32) -> Bool {
        var attributes = stat()
        return fstat(descriptor, &attributes) == 0
            && attributes.st_mode & S_IFMT == S_IFREG
            && attributes.st_uid == geteuid() && attributes.st_nlink == 1
            && attributes.st_mode & 0o7022 == 0
    }

    private static func privateProcessShape() -> Bool {
        let environment = ProcessInfo.processInfo.environment
        guard environment.keys.allSatisfy({ $0 == "__CF_USER_TEXT_ENCODING" }) else { return false }
        let allowed: Set<Int32> = [controlDescriptor, profileDescriptor, engineDescriptor]
        let limit = min(Int32(getdtablesize()), 65_536)
        for descriptor in Int32(3)..<limit where !allowed.contains(descriptor) {
            errno = 0
            if fcntl(descriptor, F_GETFD) != -1 || errno != EBADF { return false }
        }
        return true
    }

    private static func terminateAndReap(_ child: pid_t,
                                         graceMilliseconds: Int) -> VPNEngineProcessState {
        if let terminal = reap(child, options: WNOHANG) { return terminal }
        _ = kill(child, SIGTERM)
        let grace = max(0, min(graceMilliseconds, 10_000))
        let deadline = now() &+ UInt64(grace) * 1_000_000
        while now() < deadline {
            if let terminal = reap(child, options: WNOHANG) { return terminal }
            usleep(1_000)
        }
        _ = kill(child, SIGKILL)
        return reap(child, options: 0) ?? .signalled(SIGKILL)
    }

    private static func reap(_ child: pid_t, options: Int32) -> VPNEngineProcessState? {
        var status: Int32 = 0
        var result: pid_t
        repeat { result = waitpid(child, &status, options) } while result < 0 && errno == EINTR
        if result == 0 { return nil }
        guard result == child else { return .signalled(SIGKILL) }
        let signal = status & 0x7f
        return signal == 0 ? .exited((status >> 8) & 0xff) : .signalled(signal)
    }

    private static func now() -> UInt64 { clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW) }

    private static func withCStrings<T>(_ strings: [String],
        _ body: (UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>) -> T) -> T? {
        var storage: [UnsafeMutablePointer<CChar>] = []
        for string in strings {
            guard let pointer = strdup(string) else {
                storage.forEach { free(UnsafeMutableRawPointer($0)) }; return nil
            }
            storage.append(pointer)
        }
        defer { storage.forEach { free(UnsafeMutableRawPointer($0)) } }
        var pointers = storage.map(Optional.some) + [nil]
        return pointers.withUnsafeMutableBufferPointer { body($0.baseAddress!) }
    }
}

final class VPNEngineSupervisorClient {
    private var supervisorPID: pid_t
    private var control: Int32
    private var received = [UInt8]()
    private var terminal: VPNEngineProcessState?

    private init(supervisorPID: pid_t, control: Int32) {
        self.supervisorPID = supervisorPID; self.control = control
    }

    deinit { if control >= 0 { close(control) } }

    static func launch(engineDescriptor: Int32, profileDescriptor: Int32,
                       management: VPNEngineManagementConfiguration?) throws
        -> VPNEngineSupervisorClient {
        var pair: [Int32] = [-1, -1]
        guard socketpair(AF_UNIX, SOCK_STREAM, 0, &pair) == 0 else {
            throw VPNEngineProcessError.spawnFailed(errno)
        }
        defer { if pair[1] >= 0 { close(pair[1]) } }
        var noSignal: Int32 = 1
        guard fcntl(pair[0], F_SETFD, FD_CLOEXEC) == 0,
              fcntl(pair[1], F_SETFD, FD_CLOEXEC) == 0,
              setsockopt(pair[0], SOL_SOCKET, SO_NOSIGPIPE, &noSignal,
                         socklen_t(MemoryLayout.size(ofValue: noSignal))) == 0,
              setsockopt(pair[1], SOL_SOCKET, SO_NOSIGPIPE, &noSignal,
                         socklen_t(MemoryLayout.size(ofValue: noSignal))) == 0 else {
            let saved = errno; close(pair[0]); close(pair[1]); pair = [-1, -1]
            throw VPNEngineProcessError.spawnFailed(saved)
        }
        let executable = try currentExecutable()
        defer { close(executable.descriptor) }
        var actions: posix_spawn_file_actions_t? = nil
        var attributes: posix_spawnattr_t? = nil
        guard posix_spawn_file_actions_init(&actions) == 0,
              posix_spawnattr_init(&attributes) == 0 else {
            close(pair[0])
            if actions != nil { posix_spawn_file_actions_destroy(&actions) }
            throw VPNEngineProcessError.spawnFailed(ENOMEM)
        }
        defer {
            posix_spawn_file_actions_destroy(&actions)
            posix_spawnattr_destroy(&attributes)
        }
        let null = "/dev/null"
        guard posix_spawn_file_actions_addopen(&actions, STDIN_FILENO, null, O_RDONLY, 0) == 0,
              posix_spawn_file_actions_addopen(&actions, STDOUT_FILENO, null, O_WRONLY, 0) == 0,
              posix_spawn_file_actions_addopen(&actions, STDERR_FILENO, null, O_WRONLY, 0) == 0,
              posix_spawn_file_actions_adddup2(&actions, pair[1], 20) == 0,
              posix_spawn_file_actions_adddup2(&actions, profileDescriptor, 21) == 0,
              posix_spawn_file_actions_adddup2(&actions, engineDescriptor, 22) == 0 else {
            close(pair[0]); throw VPNEngineProcessError.spawnFailed(EINVAL)
        }
        let flags = Int16(POSIX_SPAWN_CLOEXEC_DEFAULT | POSIX_SPAWN_SETSIGDEF
                          | POSIX_SPAWN_SETSIGMASK)
        var emptyMask = sigset_t(), defaults = sigset_t()
        sigemptyset(&emptyMask); sigfillset(&defaults)
        guard posix_spawnattr_setflags(&attributes, flags) == 0,
              posix_spawnattr_setsigmask(&attributes, &emptyMask) == 0,
              posix_spawnattr_setsigdefault(&attributes, &defaults) == 0 else {
            close(pair[0]); throw VPNEngineProcessError.spawnFailed(EINVAL)
        }
        var argvStorage = [strdup("vpn-engine-supervisor"),
                           strdup(VPNEngineSupervisorEntry.argument), nil]
        guard argvStorage[0] != nil, argvStorage[1] != nil else {
            argvStorage.compactMap { $0 }.forEach { free(UnsafeMutableRawPointer($0)) }
            close(pair[0])
            throw VPNEngineProcessError.spawnFailed(ENOMEM)
        }
        defer {
            argvStorage.compactMap { $0 }.forEach { free(UnsafeMutableRawPointer($0)) }
        }
        var environment: [UnsafeMutablePointer<CChar>?] = [nil]
        var pid: pid_t = 0
        let result = argvStorage.withUnsafeMutableBufferPointer { argv in
            environment.withUnsafeMutableBufferPointer { environment in
                posix_spawn(&pid, executable.path, &actions, &attributes,
                            argv.baseAddress!, environment.baseAddress!)
            }
        }
        guard result == 0, pid > 0 else {
            close(pair[0]); throw VPNEngineProcessError.spawnFailed(result)
        }
        var named = stat()
        guard lstat(executable.path, &named) == 0,
              executable.identity.st_dev == named.st_dev,
              executable.identity.st_ino == named.st_ino else {
            close(pair[0]); _ = kill(pid, SIGKILL); _ = waitFor(pid)
            throw VPNEngineProcessError.validationFailed
        }
        close(pair[1]); pair[1] = -1
        let client = VPNEngineSupervisorClient(supervisorPID: pid, control: pair[0])
        do {
            try VPNEngineSupervisorWire.sendStartup(management, to: pair[0])
            try VPNEngineSupervisorWire.readStarted(from: pair[0], timeoutMilliseconds: 5_000)
            let current = fcntl(pair[0], F_GETFL)
            guard current >= 0, fcntl(pair[0], F_SETFL, current | O_NONBLOCK) == 0 else {
                throw VPNEngineProcessError.spawnFailed(errno)
            }
            return client
        } catch {
            close(pair[0]); client.control = -1
            if !waitFor(pid, timeoutMilliseconds: 2_000) {
                _ = kill(pid, SIGKILL); _ = waitFor(pid)
            }
            throw error
        }
    }

    func state() throws -> VPNEngineProcessState {
        if let terminal { return terminal }
        try readAvailable()
        if let decoded = VPNEngineSupervisorWire.decodeTerminal(received) {
            terminal = decoded; received.removeAll()
            try reapSupervisor(); closeControl(); return decoded
        }
        var status: Int32 = 0
        let result = waitpid(supervisorPID, &status, WNOHANG)
        if result == 0 { return .running }
        if result < 0 && errno == EINTR { return try state() }
        throw VPNEngineProcessError.waitFailed(result < 0 ? errno : EPIPE)
    }

    func wait(timeoutMilliseconds: Int) throws -> VPNEngineProcessState {
        guard timeoutMilliseconds >= 0 else { throw VPNEngineProcessError.waitFailed(EINVAL) }
        let deadline = Self.deadline(milliseconds: timeoutMilliseconds)
        while true {
            let value = try state()
            if value != .running || Self.now() >= deadline { return value }
            usleep(1_000)
        }
    }

    func stop(graceMilliseconds: Int) throws -> VPNEngineProcessState {
        guard graceMilliseconds >= 0 else { throw VPNEngineProcessError.waitFailed(EINVAL) }
        let current = try state()
        guard current == .running else { return current }
        try VPNEngineSupervisorWire.sendStop(graceMilliseconds: graceMilliseconds, to: control)
        let bounded = min(graceMilliseconds, 10_000) + 2_000
        let result = try wait(timeoutMilliseconds: bounded)
        guard result != .running else { throw VPNEngineProcessError.waitFailed(ETIMEDOUT) }
        return result
    }

    #if VPN_ENGINE_PROCESS_TESTING
    var testSupervisorPID: pid_t { supervisorPID }
    #endif

    private func readAvailable() throws {
        guard control >= 0 else { return }
        while true {
            var bytes = [UInt8](repeating: 0, count: 32)
            let count = Darwin.read(control, &bytes, bytes.count)
            if count > 0 {
                received.append(contentsOf: bytes.prefix(count))
                guard received.count <= VPNEngineSupervisorWire.terminalSize else {
                    throw VPNEngineProcessError.waitFailed(EPROTO)
                }
                continue
            }
            if count == 0 { return }
            if errno == EINTR { continue }
            if errno == EAGAIN || errno == EWOULDBLOCK { return }
            throw VPNEngineProcessError.waitFailed(errno)
        }
    }

    private func reapSupervisor() throws {
        guard supervisorPID > 0 else { return }
        guard VPNEngineSupervisorClient.waitFor(supervisorPID, timeoutMilliseconds: 2_000) else {
            _ = kill(supervisorPID, SIGKILL)
            guard VPNEngineSupervisorClient.waitFor(supervisorPID) else {
                throw VPNEngineProcessError.waitFailed(errno)
            }
            supervisorPID = -1; return
        }
        supervisorPID = -1
    }

    private func closeControl() { if control >= 0 { close(control); control = -1 } }

    private static func currentExecutable() throws -> (descriptor: Int32, path: String, identity: stat) {
        guard let raw = CommandLine.arguments.first, raw.hasPrefix("/") else {
            throw VPNEngineProcessError.validationFailed
        }
        var resolved = [CChar](repeating: 0, count: Int(PATH_MAX))
        guard realpath(raw, &resolved) != nil else { throw VPNEngineProcessError.validationFailed }
        let path = String(cString: resolved)
        let descriptor = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else { throw VPNEngineProcessError.validationFailed }
        var identity = stat()
        guard fstat(descriptor, &identity) == 0, identity.st_mode & S_IFMT == S_IFREG,
              identity.st_uid == geteuid(), identity.st_nlink == 1,
              identity.st_mode & 0o7022 == 0 else {
            close(descriptor); throw VPNEngineProcessError.validationFailed
        }
        return (descriptor, path, identity)
    }

    private static func waitFor(_ pid: pid_t, timeoutMilliseconds: Int? = nil) -> Bool {
        let deadline = timeoutMilliseconds.map { now() &+ UInt64(max(0, $0)) * 1_000_000 }
        while true {
            var status: Int32 = 0
            let result = waitpid(pid, &status, deadline == nil ? 0 : WNOHANG)
            if result == pid { return true }
            if result < 0 && errno == EINTR { continue }
            if result < 0 { return false }
            if let deadline, now() >= deadline { return false }
            usleep(1_000)
        }
    }

    private static func now() -> UInt64 { clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW) }

    private static func deadline(milliseconds: Int) -> UInt64 {
        let value = UInt64(milliseconds)
        let increment = value > UInt64.max / 1_000_000 ? UInt64.max : value * 1_000_000
        let current = now()
        return current > UInt64.max - increment ? UInt64.max : current + increment
    }
}

private enum VPNEngineSupervisorWire {
    static let commandSize = 5
    static let terminalSize = 6
    private static let startupMagic: [UInt8] = [0x50, 0x50, 0x56, 0x53]

    static func sendStartup(_ management: VPNEngineManagementConfiguration?, to descriptor: Int32) throws {
        let path = management.map { Array($0.socketPath.utf8) } ?? []
        guard path.count <= Int(UInt16.max) else { throw VPNEngineProcessError.invalidManagementEndpoint }
        var message = startupMagic + [1, UInt8(path.count >> 8), UInt8(path.count & 0xff)]
        message.append(contentsOf: path)
        try writeAll(message, to: descriptor)
    }

    static func readStartup(from descriptor: Int32,
                            timeoutMilliseconds: Int) throws -> VPNEngineManagementConfiguration? {
        let header = try readExact(7, from: descriptor, timeoutMilliseconds: timeoutMilliseconds)
        guard Array(header[0..<4]) == startupMagic, header[4] == 1 else {
            throw VPNEngineProcessError.spawnFailed(EPROTO)
        }
        let length = Int(header[5]) << 8 | Int(header[6])
        guard length <= 255 else { throw VPNEngineProcessError.invalidManagementEndpoint }
        let path = try readExact(length, from: descriptor, timeoutMilliseconds: timeoutMilliseconds)
        if path.isEmpty { return nil }
        guard let value = String(bytes: path, encoding: .utf8) else {
            throw VPNEngineProcessError.invalidManagementEndpoint
        }
        return try VPNEngineManagementConfiguration(unixSocketPath: value)
    }

    static func sendStarted(to descriptor: Int32) throws { try writeAll([0xa1, 0], to: descriptor) }
    static func sendFailure(to descriptor: Int32) throws { try writeAll([0xa1, 1], to: descriptor) }

    static func readStarted(from descriptor: Int32, timeoutMilliseconds: Int) throws {
        let value = try readExact(2, from: descriptor, timeoutMilliseconds: timeoutMilliseconds)
        guard value == [0xa1, 0] else { throw VPNEngineProcessError.spawnFailed(ECHILD) }
    }

    static func sendStop(graceMilliseconds: Int, to descriptor: Int32) throws {
        let grace = UInt32(max(0, min(graceMilliseconds, 10_000)))
        try writeAll([0xc1, UInt8(truncatingIfNeeded: grace >> 24),
                      UInt8(truncatingIfNeeded: grace >> 16),
                      UInt8(truncatingIfNeeded: grace >> 8),
                      UInt8(truncatingIfNeeded: grace)], to: descriptor)
    }

    static func decodeStop(_ bytes: [UInt8]) -> Int? {
        guard bytes.count == commandSize, bytes[0] == 0xc1 else { return nil }
        let value = UInt32(bytes[1]) << 24 | UInt32(bytes[2]) << 16
            | UInt32(bytes[3]) << 8 | UInt32(bytes[4])
        guard value <= 10_000 else { return nil }
        return Int(value)
    }

    static func sendTerminal(_ state: VPNEngineProcessState, to descriptor: Int32) throws {
        let kind: UInt8, value: Int32
        switch state {
        case .running: throw VPNEngineProcessError.waitFailed(EINVAL)
        case .exited(let code): kind = 0; value = code
        case .signalled(let signal): kind = 1; value = signal
        }
        let raw = UInt32(bitPattern: value)
        try writeAll([0xb1, kind, UInt8(truncatingIfNeeded: raw >> 24),
                      UInt8(truncatingIfNeeded: raw >> 16),
                      UInt8(truncatingIfNeeded: raw >> 8),
                      UInt8(truncatingIfNeeded: raw)], to: descriptor)
    }

    static func decodeTerminal(_ bytes: [UInt8]) -> VPNEngineProcessState? {
        guard bytes.count == terminalSize, bytes[0] == 0xb1, bytes[1] <= 1 else { return nil }
        let raw = UInt32(bytes[2]) << 24 | UInt32(bytes[3]) << 16
            | UInt32(bytes[4]) << 8 | UInt32(bytes[5])
        return bytes[1] == 0 ? .exited(Int32(bitPattern: raw)) : .signalled(Int32(bitPattern: raw))
    }

    private static func writeAll(_ bytes: [UInt8], to descriptor: Int32) throws {
        var offset = 0
        while offset < bytes.count {
            let count = bytes.withUnsafeBytes {
                Darwin.write(descriptor, $0.baseAddress!.advanced(by: offset), bytes.count - offset)
            }
            if count < 0 && errno == EINTR { continue }
            guard count > 0 else { throw VPNEngineProcessError.waitFailed(errno) }
            offset += count
        }
    }

    private static func readExact(_ count: Int, from descriptor: Int32,
                                  timeoutMilliseconds: Int) throws -> [UInt8] {
        if count == 0 { return [] }
        var result = [UInt8](); result.reserveCapacity(count)
        let deadline = clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW)
            &+ UInt64(max(0, timeoutMilliseconds)) * 1_000_000
        while result.count < count {
            let now = clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW)
            guard now < deadline else { throw VPNEngineProcessError.waitFailed(ETIMEDOUT) }
            let remaining = min(UInt64(Int32.max), (deadline - now + 999_999) / 1_000_000)
            var item = pollfd(fd: descriptor, events: Int16(POLLIN | POLLHUP | POLLERR), revents: 0)
            let ready = poll(&item, 1, Int32(remaining))
            if ready < 0 && errno == EINTR { continue }
            guard ready > 0, item.revents & Int16(POLLERR | POLLNVAL) == 0 else {
                throw VPNEngineProcessError.waitFailed(ready == 0 ? ETIMEDOUT : EPIPE)
            }
            var buffer = [UInt8](repeating: 0, count: count - result.count)
            let readCount = Darwin.read(descriptor, &buffer, buffer.count)
            if readCount < 0 && errno == EINTR { continue }
            guard readCount > 0 else { throw VPNEngineProcessError.waitFailed(EPIPE) }
            result.append(contentsOf: buffer.prefix(readCount))
        }
        return result
    }
}
