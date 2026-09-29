import Darwin
import Foundation

/// Coarse process lifecycle only. None of these values is evidence that a VPN
/// tunnel is authenticated, usable or connected.
enum VPNEngineProcessState: Equatable {
    case running
    case exited(Int32)
    case signalled(Int32)
}

/// Deliberately redacted: callers never receive an executable path, profile
/// contents, arguments or environment through an error value.
enum VPNEngineProcessError: Error, Equatable, CustomStringConvertible {
    case invalidSelection
    case validationFailed
    case invalidProfile
    case spawnFailed(Int32)
    case waitFailed(Int32)

    var description: String {
        switch self {
        case .invalidSelection: return "The selected VPN engine is unavailable."
        case .validationFailed: return "The selected VPN engine could not be verified."
        case .invalidProfile: return "The protected VPN profile is unavailable."
        case .spawnFailed(let code): return "The VPN engine could not be started (code \(code))."
        case .waitFailed(let code): return "The VPN engine state could not be read (code \(code))."
        }
    }
}

/// An engine selection is an operation that opens and revalidates the exact
/// content-addressed executable. Production also binds the descriptor back to
/// the named inode in a protected directory immediately before launch.
struct VPNEngineExecutableSelection {
    fileprivate let openValidatedDescriptor: () throws -> Int32

    #if VPN_ENGINE_PROCESS_TESTING
    static func test(_ operation: @escaping () throws -> Int32) -> Self {
        Self(openValidatedDescriptor: operation)
    }
    #else
    init(trustedDirectoryDescriptor: Int32, deployment: VPNAuthorizedDeployment) throws {
        guard let identity = deployment.release.engine,
              deployment.engineFileName == identity.artifactName else {
            throw VPNEngineProcessError.invalidSelection
        }
        let holder = try VPNEngineSelectionDirectory(trustedDirectoryDescriptor)
        openValidatedDescriptor = {
            do { return try holder.openValidated(name: identity.artifactName, release: deployment.release) }
            catch let error as VPNEngineProcessError { throw error }
            catch { throw VPNEngineProcessError.validationFailed }
        }
    }
    #endif
}

#if !VPN_ENGINE_PROCESS_TESTING
private final class VPNEngineSelectionDirectory {
    private var descriptor: Int32
    private let owner = geteuid()

    init(_ trustedDirectoryDescriptor: Int32) throws {
        descriptor = fcntl(trustedDirectoryDescriptor, F_DUPFD_CLOEXEC, 64)
        guard descriptor >= 0 else { throw VPNEngineProcessError.invalidSelection }
        do { try checkDirectory() }
        catch { close(descriptor); descriptor = -1; throw error }
    }

    deinit { if descriptor >= 0 { close(descriptor) } }

    func openValidated(name: String, release: VerifiedVPNRelease) throws -> Int32 {
        try checkDirectory()
        guard name == release.engine?.artifactName else { throw VPNEngineProcessError.invalidSelection }
        let file = openat(descriptor, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard file >= 0 else { throw VPNEngineProcessError.invalidSelection }
        do {
            var before = stat()
            guard fstat(file, &before) == 0, before.st_mode & S_IFMT == S_IFREG,
                  before.st_uid == owner, before.st_nlink == 1,
                  before.st_mode & 0o7022 == 0,
                  before.st_size > 0,
                  before.st_size <= VPNReleaseAuthority.maximumEngineBytes else {
                throw VPNEngineProcessError.invalidSelection
            }
            var bytes = Data(), buffer = [UInt8](repeating: 0, count: 16384)
            while true {
                let count = Darwin.read(file, &buffer, buffer.count)
                if count < 0, errno == EINTR { continue }
                guard count >= 0,
                      bytes.count + max(0, count) <= VPNReleaseAuthority.maximumEngineBytes else {
                    throw VPNEngineProcessError.validationFailed
                }
                if count == 0 { break }
                bytes.append(contentsOf: buffer.prefix(count))
            }
            try VPNEngineArtifact.validate(protectedFile: file, data: bytes, release: release)
            var after = stat(), named = stat()
            guard fstat(file, &after) == 0,
                  fstatat(descriptor, name, &named, AT_SYMLINK_NOFOLLOW) == 0,
                  before.st_dev == after.st_dev, before.st_ino == after.st_ino,
                  before.st_size == after.st_size,
                  before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec,
                  before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec,
                  before.st_ctimespec.tv_sec == after.st_ctimespec.tv_sec,
                  before.st_ctimespec.tv_nsec == after.st_ctimespec.tv_nsec,
                  before.st_dev == named.st_dev, before.st_ino == named.st_ino else {
                throw VPNEngineProcessError.validationFailed
            }
            _ = lseek(file, 0, SEEK_SET)
            return file
        } catch {
            close(file)
            if let typed = error as? VPNEngineProcessError { throw typed }
            throw VPNEngineProcessError.validationFailed
        }
    }

    private func checkDirectory() throws {
        var attributes = stat()
        guard descriptor >= 0, geteuid() == owner,
              fstat(descriptor, &attributes) == 0,
              attributes.st_mode & S_IFMT == S_IFDIR,
              attributes.st_uid == owner, attributes.st_nlink > 0,
              attributes.st_mode & 0o7777 == 0o700 else {
            throw VPNEngineProcessError.invalidSelection
        }
    }
}
#endif

/// Owns exactly one foreground OpenVPN child. It intentionally has no notion
/// of "connected" and cannot install routes or DNS settings. A later tunnel
/// coordinator must separately authenticate management state before doing so.
final class VPNEngineProcess {
    private static let profileDescriptor: Int32 = 21
    private var processID: pid_t
    private var terminalState: VPNEngineProcessState?

    private init(processID: pid_t) { self.processID = processID }

    deinit {
        if terminalState == nil { _ = try? stop(graceMilliseconds: 100) }
    }

    static func start(selection: VPNEngineExecutableSelection,
                      protectedProfileDescriptor profile: Int32) throws -> VPNEngineProcess {
        try validateProfile(profile)
        let stagedProfile = fcntl(profile, F_DUPFD_CLOEXEC, 64)
        guard stagedProfile >= 0, lseek(stagedProfile, 0, SEEK_SET) == 0 else {
            if stagedProfile >= 0 { close(stagedProfile) }
            throw VPNEngineProcessError.invalidProfile
        }
        defer { close(stagedProfile) }

        // Prepare every fallible non-security input before validation. Once the
        // exact engine descriptor is returned, the next operation is spawn.
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

        let null = "/dev/null"
        guard posix_spawn_file_actions_addopen(&actions, STDIN_FILENO, null, O_RDONLY, 0) == 0,
              posix_spawn_file_actions_addopen(&actions, STDOUT_FILENO, null, O_WRONLY, 0) == 0,
              posix_spawn_file_actions_addopen(&actions, STDERR_FILENO, null, O_WRONLY, 0) == 0,
              posix_spawn_file_actions_adddup2(&actions, stagedProfile, profileDescriptor) == 0 else {
            throw VPNEngineProcessError.spawnFailed(EINVAL)
        }
        let flags = Int16(POSIX_SPAWN_CLOEXEC_DEFAULT | POSIX_SPAWN_SETSIGDEF | POSIX_SPAWN_SETSIGMASK)
        var emptyMask = sigset_t(), defaults = sigset_t()
        sigemptyset(&emptyMask); sigfillset(&defaults)
        guard posix_spawnattr_setflags(&attributes, flags) == 0,
              posix_spawnattr_setsigmask(&attributes, &emptyMask) == 0,
              posix_spawnattr_setsigdefault(&attributes, &defaults) == 0 else {
            throw VPNEngineProcessError.spawnFailed(EINVAL)
        }

        let engine = try selection.openValidatedDescriptor()
        defer { close(engine) }
        var enginePath = [CChar](repeating: 0, count: Int(MAXPATHLEN))
        var selectedIdentity = stat()
        guard fcntl(engine, F_GETPATH, &enginePath) == 0,
              fstat(engine, &selectedIdentity) == 0 else {
            throw VPNEngineProcessError.validationFailed
        }
        var pid: pid_t = 0
        let argv = [
            "vpn-engine", "--config", "/dev/fd/\(profileDescriptor)",
            "--route-noexec", "--ifconfig-noexec", "--script-security", "1",
            "--auth-nocache", "--route-nopull"
        ]
        var environment: [UnsafeMutablePointer<CChar>?] = [nil]
        guard let result = withCStrings(argv, { arguments in
            environment.withUnsafeMutableBufferPointer { environment in
                // This is the canonical path obtained from the descriptor that
                // was revalidated immediately above. Production selections
                // additionally bind it to the named inode in a protected 0700
                // directory before this call.
                posix_spawn(&pid, enginePath, &actions, &attributes,
                            arguments, environment.baseAddress!)
            }
        }) else { throw VPNEngineProcessError.spawnFailed(ENOMEM) }
        guard result == 0, pid > 0 else { throw VPNEngineProcessError.spawnFailed(result) }
        var launchedIdentity = stat()
        guard lstat(String(cString: enginePath), &launchedIdentity) == 0,
              selectedIdentity.st_dev == launchedIdentity.st_dev,
              selectedIdentity.st_ino == launchedIdentity.st_ino else {
            _ = kill(pid, SIGKILL)
            var status: Int32 = 0
            while waitpid(pid, &status, 0) < 0 && errno == EINTR {}
            throw VPNEngineProcessError.validationFailed
        }
        return VPNEngineProcess(processID: pid)
    }

    func state() throws -> VPNEngineProcessState {
        if let terminalState = terminalState { return terminalState }
        var status: Int32 = 0
        var result: pid_t
        repeat { result = waitpid(processID, &status, WNOHANG) } while result < 0 && errno == EINTR
        if result == 0 { return .running }
        guard result == processID else { throw VPNEngineProcessError.waitFailed(errno) }
        let decoded = Self.decode(status)
        terminalState = decoded
        processID = -1
        return decoded
    }

    func wait(timeoutMilliseconds: Int) throws -> VPNEngineProcessState {
        guard timeoutMilliseconds >= 0 else { throw VPNEngineProcessError.waitFailed(EINVAL) }
        let deadline = Self.deadline(milliseconds: timeoutMilliseconds)
        while true {
            let current = try state()
            if current != .running || Self.now() >= deadline { return current }
            usleep(1_000)
        }
    }

    @discardableResult
    func stop(graceMilliseconds: Int = 1_000) throws -> VPNEngineProcessState {
        guard graceMilliseconds >= 0 else { throw VPNEngineProcessError.waitFailed(EINVAL) }
        let current = try state()
        guard current == .running else { return current }
        if kill(processID, SIGTERM) != 0, errno != ESRCH {
            throw VPNEngineProcessError.waitFailed(errno)
        }
        let graceful = try wait(timeoutMilliseconds: graceMilliseconds)
        if graceful != .running { return graceful }
        if kill(processID, SIGKILL) != 0, errno != ESRCH {
            throw VPNEngineProcessError.waitFailed(errno)
        }
        return try reapBlocking()
    }

    private func reapBlocking() throws -> VPNEngineProcessState {
        if let terminalState = terminalState { return terminalState }
        var status: Int32 = 0
        var result: pid_t = -1
        repeat { result = waitpid(processID, &status, 0) } while result < 0 && errno == EINTR
        guard result == processID else { throw VPNEngineProcessError.waitFailed(errno) }
        let decoded = Self.decode(status)
        terminalState = decoded; processID = -1
        return decoded
    }

    private static func validateProfile(_ descriptor: Int32) throws {
        var attributes = stat()
        guard descriptor >= 0, fstat(descriptor, &attributes) == 0,
              attributes.st_mode & S_IFMT == S_IFREG,
              attributes.st_uid == geteuid(), attributes.st_nlink == 1,
              attributes.st_mode & 0o7777 == 0o600,
              attributes.st_size > 0, attributes.st_size <= VPNProfileVault.maximumBytes else {
            throw VPNEngineProcessError.invalidProfile
        }
    }

    private static func decode(_ status: Int32) -> VPNEngineProcessState {
        let signal = status & 0x7f
        if signal == 0 { return .exited((status >> 8) & 0xff) }
        return .signalled(signal)
    }

    private static func now() -> UInt64 { clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW) }
    private static func deadline(milliseconds: Int) -> UInt64 {
        let value = UInt64(milliseconds)
        let increment = value > UInt64.max / 1_000_000 ? UInt64.max : value * 1_000_000
        let current = now()
        return current > UInt64.max - increment ? UInt64.max : current + increment
    }

    private static func withCStrings<T>(_ strings: [String], _ body: (UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>) -> T) -> T? {
        var storage: [UnsafeMutablePointer<CChar>] = []
        for string in strings {
            guard let pointer = strdup(string) else {
                storage.forEach { free($0) }
                return nil
            }
            storage.append(pointer)
        }
        defer { storage.forEach { free($0) } }
        var pointers = storage.map(Optional.some) + [nil]
        return pointers.withUnsafeMutableBufferPointer { body($0.baseAddress!) }
    }
}
