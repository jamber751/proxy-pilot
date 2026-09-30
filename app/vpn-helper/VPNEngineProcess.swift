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
    case invalidManagementEndpoint
    case spawnFailed(Int32)
    case waitFailed(Int32)

    var description: String {
        switch self {
        case .invalidSelection: return "The selected VPN engine is unavailable."
        case .validationFailed: return "The selected VPN engine could not be verified."
        case .invalidProfile: return "The protected VPN profile is unavailable."
        case .invalidManagementEndpoint: return "The VPN management endpoint is unavailable."
        case .spawnFailed(let code): return "The VPN engine could not be started (code \(code))."
        case .waitFailed(let code): return "The VPN engine state could not be read (code \(code))."
        }
    }
}

/// A local endpoint prepared inside the helper's private directory. OpenVPN
/// creates this socket and remains on management hold until a later stage is
/// explicitly allowed to release it.
struct VPNEngineManagementConfiguration: Equatable {
    let socketPath: String

    init(unixSocketPath: String) throws {
        let address = sockaddr_un()
        var existing = stat()
        let bytes = Array(unixSocketPath.utf8) + [0]
        guard unixSocketPath.hasPrefix("/"), !unixSocketPath.utf8.contains(0),
              bytes.count <= MemoryLayout.size(ofValue: address.sun_path),
              unixSocketPath.utf8.count <= Int(UInt8.max),
              lstat(unixSocketPath, &existing) == -1, errno == ENOENT else {
            throw VPNEngineProcessError.invalidManagementEndpoint
        }
        socketPath = unixSocketPath
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
    private let supervisor: VPNEngineSupervisorClient

    private init(supervisor: VPNEngineSupervisorClient) { self.supervisor = supervisor }

    deinit {
        if (try? state()) == .running { _ = try? stop(graceMilliseconds: 100) }
    }

    static func start(selection: VPNEngineExecutableSelection,
                      protectedProfileDescriptor profile: Int32,
                      management: VPNEngineManagementConfiguration? = nil) throws -> VPNEngineProcess {
        try validateProfile(profile)
        let stagedProfile = fcntl(profile, F_DUPFD_CLOEXEC, 64)
        guard stagedProfile >= 0, lseek(stagedProfile, 0, SEEK_SET) == 0 else {
            if stagedProfile >= 0 { close(stagedProfile) }
            throw VPNEngineProcessError.invalidProfile
        }
        defer { close(stagedProfile) }

        if let management = management {
            var endpoint = stat()
            guard lstat(management.socketPath, &endpoint) == -1, errno == ENOENT else {
                throw VPNEngineProcessError.invalidManagementEndpoint
            }
        }
        let engine = try selection.openValidatedDescriptor()
        defer { close(engine) }
        let client = try VPNEngineSupervisorClient.launch(engineDescriptor: engine,
            profileDescriptor: stagedProfile, management: management)
        return VPNEngineProcess(supervisor: client)
    }

    func state() throws -> VPNEngineProcessState { try supervisor.state() }

    func wait(timeoutMilliseconds: Int) throws -> VPNEngineProcessState {
        try supervisor.wait(timeoutMilliseconds: timeoutMilliseconds)
    }

    @discardableResult
    func stop(graceMilliseconds: Int = 1_000) throws -> VPNEngineProcessState {
        try supervisor.stop(graceMilliseconds: graceMilliseconds)
    }

    #if VPN_ENGINE_PROCESS_TESTING
    var testSupervisorPID: pid_t { supervisor.testSupervisorPID }
    #endif

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

}
