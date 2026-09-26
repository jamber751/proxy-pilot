import Darwin
import Foundation

enum VPNInstalledApplicationError: Error {
    case requiresRoot, unsafeStorage, wrongProcess
}

/// Descriptor-bound proof of the exact installed application executable. The
/// receipt is short-lived and must be revalidated at every launch/selection
/// boundary; `/Applications` remains a mutable namespace.
final class VPNInstalledApplication {
    private let destination: Int32
    private let bundle: Int32
    private let executable: Int32
    private let observation: VPNStagedApplicationInspection
    private let owner: uid_t

    private init(destination: Int32, bundle: Int32, executable: Int32,
                 observation: VPNStagedApplicationInspection,
                 owner: uid_t) {
        self.destination = destination; self.bundle = bundle; self.executable = executable
        self.observation = observation; self.owner = owner
    }

    deinit { close(executable); close(bundle); close(destination) }

    static func inspect(release: VerifiedVPNRelease) throws -> VPNInstalledApplication {
        guard getuid() == 0, geteuid() == 0 else { throw VPNInstalledApplicationError.requiresRoot }
        let directory = open("/Applications", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard directory >= 0 else { throw VPNInstalledApplicationError.unsafeStorage }
        do { return try make(destination: directory, release: release, owner: 0, production: true) }
        catch { close(directory); throw error }
    }

    #if VPN_APPLICATION_DESTINATION_TESTING
    static func testInspect(inApplicationsDirectory source: Int32,
                            release: VerifiedVPNRelease) throws -> VPNInstalledApplication {
        guard getuid() != 0, geteuid() == getuid() else { throw VPNPeerAuthenticationError.denied }
        let directory = fcntl(source, F_DUPFD_CLOEXEC, 0)
        guard directory >= 0 else { throw VPNInstalledApplicationError.unsafeStorage }
        do { return try make(destination: directory, release: release,
                             owner: geteuid(), production: false) }
        catch { close(directory); throw error }
    }
    #endif

    private static func make(destination: Int32, release: VerifiedVPNRelease,
                             owner: uid_t, production: Bool) throws -> VPNInstalledApplication {
        let observation = try VPNStagedApplication.inspectInstalled(
            inApplicationsDirectory: destination, ownerUserID: owner,
            productionParent: production, release: release)
        let bundle = openat(destination, "ProxyPilot.app",
                            O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard bundle >= 0 else { throw VPNInstalledApplicationError.unsafeStorage }
        var executable: Int32 = -1
        do {
            executable = try openExecutable(bundle, owner: owner)
            try VPNStagedApplication.revalidate(observation, inTrustedDirectory: destination)
            var held = stat(), named = stat()
            guard fstat(bundle, &held) == 0,
                  fstatat(destination, "ProxyPilot.app", &named, AT_SYMLINK_NOFOLLOW) == 0,
                  same(held, named) else { throw VPNInstalledApplicationError.unsafeStorage }
            return VPNInstalledApplication(destination: destination, bundle: bundle,
                executable: executable, observation: observation, owner: owner)
        } catch {
            if executable >= 0 { close(executable) }
            close(bundle)
            throw error
        }
    }

    func revalidate() throws {
        try checkBinding()
        try VPNStagedApplication.revalidate(observation, inTrustedDirectory: destination)
        let named = try Self.openExecutable(bundle, owner: owner)
        defer { close(named) }
        var held = stat(), current = stat()
        guard fstat(executable, &held) == 0, fstat(named, &current) == 0,
              Self.same(held, current), held.st_nlink == 1 else {
            throw VPNInstalledApplicationError.unsafeStorage
        }
        try checkBinding()
    }

    func path() throws -> String {
        try revalidate()
        var bytes = [CChar](repeating: 0, count: Int(MAXPATHLEN))
        guard fcntl(executable, F_GETPATH, &bytes) == 0 else {
            throw VPNInstalledApplicationError.unsafeStorage
        }
        let value = String(cString: bytes)
        let named = open(value, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard named >= 0 else { throw VPNInstalledApplicationError.unsafeStorage }
        defer { close(named) }
        var held = stat(), current = stat()
        guard fstat(executable, &held) == 0, fstat(named, &current) == 0,
              Self.same(held, current) else { throw VPNInstalledApplicationError.unsafeStorage }
        return value
    }

    func validateProcess(_ processID: pid_t) throws {
        try revalidate()
        var bytes = [UInt8](repeating: 0, count: 4 * Int(MAXPATHLEN))
        let length = bytes.withUnsafeMutableBytes {
            proc_pidpath(processID, $0.baseAddress!, UInt32($0.count))
        }
        guard length > 0, let end = bytes.firstIndex(of: 0), end > 0,
              let path = String(bytes: bytes[..<end], encoding: .utf8) else {
            throw VPNInstalledApplicationError.wrongProcess
        }
        let running = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard running >= 0 else { throw VPNInstalledApplicationError.wrongProcess }
        defer { close(running) }
        var held = stat(), actual = stat()
        guard fstat(executable, &held) == 0, fstat(running, &actual) == 0,
              Self.same(held, actual) else { throw VPNInstalledApplicationError.wrongProcess }
    }

    private func checkBinding() throws {
        var held = stat(), named = stat()
        guard fstat(bundle, &held) == 0,
              fstatat(destination, "ProxyPilot.app", &named, AT_SYMLINK_NOFOLLOW) == 0,
              held.st_mode & S_IFMT == S_IFDIR, held.st_uid == owner,
              Self.same(held, named) else { throw VPNInstalledApplicationError.unsafeStorage }
    }

    private static func openExecutable(_ bundle: Int32, owner: uid_t) throws -> Int32 {
        var directory = fcntl(bundle, F_DUPFD_CLOEXEC, 0)
        guard directory >= 0 else { throw VPNInstalledApplicationError.unsafeStorage }
        defer { close(directory) }
        for name in ["Contents", "MacOS"] {
            let next = openat(directory, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard next >= 0 else { throw VPNInstalledApplicationError.unsafeStorage }
            close(directory); directory = next
        }
        let result = openat(directory, "ProxyPilot", O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard result >= 0 else { throw VPNInstalledApplicationError.unsafeStorage }
        var value = stat()
        guard fstat(result, &value) == 0, value.st_mode & S_IFMT == S_IFREG,
              value.st_uid == owner, value.st_nlink == 1, value.st_mode & 0o100 != 0 else {
            close(result); throw VPNInstalledApplicationError.unsafeStorage
        }
        return result
    }

    private static func same(_ lhs: stat, _ rhs: stat) -> Bool {
        lhs.st_dev == rhs.st_dev && lhs.st_ino == rhs.st_ino
    }
}
