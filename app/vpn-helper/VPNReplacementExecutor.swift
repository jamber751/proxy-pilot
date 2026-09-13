import Darwin
import Foundation

/// In-memory binding to the running A app in the fixed protected executor slot.
/// The caller holds the application namespace lease and authenticates live A
/// separately. This class neither provisions nor launches the executor, and
/// does not prove installation in Applications. Trusted ancestors/no competing
/// privileged writers remain prerequisites of the supplied base descriptor.
final class VPNReplacementExecutor {
    private let base: Int32
    private let directory: Int32
    private let executable: Int32
    private let observation: VPNStagedApplicationInspection

    private init(base: Int32, directory: Int32, executable: Int32,
                 observation: VPNStagedApplicationInspection) {
        self.base = base; self.directory = directory; self.executable = executable
        self.observation = observation
    }

    deinit { close(executable); close(directory); close(base) }

    static func inspect(inTrustedDirectory source: Int32, release: VerifiedVPNRelease) throws -> VPNReplacementExecutor {
        let base = fcntl(source, F_DUPFD_CLOEXEC, 0)
        guard base >= 0 else { throw VPNApplicationSwapError.unsafeExecutor }
        var directory: Int32 = -1, executable: Int32 = -1
        do {
            directory = openat(base, "executor", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard directory >= 0 else { throw VPNApplicationSwapError.unsafeExecutor }
            try checkBinding(base: base, directory: directory)
            let observation = try VPNStagedApplication.inspect(inTrustedDirectory: directory, release: release)
            executable = try openExecutable(directory)
            // Complete all throwing checks before transferring fd ownership.
            try checkProcess(executable)
            try checkBinding(base: base, directory: directory)
            return VPNReplacementExecutor(base: base, directory: directory,
                executable: executable, observation: observation)
        } catch {
            if executable >= 0 { close(executable) }
            if directory >= 0 { close(directory) }
            close(base)
            throw error
        }
    }

    func revalidate() throws {
        try Self.checkBinding(base: base, directory: directory)
        try VPNStagedApplication.revalidate(observation, inTrustedDirectory: directory)
        let named = try Self.openExecutable(directory)
        defer { close(named) }
        var held = stat(), fresh = stat()
        guard fstat(executable, &held) == 0, fstat(named, &fresh) == 0,
              Self.same(held, fresh), held.st_nlink == 1 else { throw VPNApplicationSwapError.unsafeExecutor }
        try Self.checkProcess(executable)
        try Self.checkBinding(base: base, directory: directory)
    }

    private static func same(_ a: stat, _ b: stat) -> Bool {
        a.st_dev == b.st_dev && a.st_ino == b.st_ino
    }

    private static func checkBinding(base: Int32, directory: Int32) throws {
        var root = stat(), held = stat(), named = stat()
        guard fstat(base, &root) == 0, fstat(directory, &held) == 0,
              root.st_mode & S_IFMT == S_IFDIR, root.st_uid == geteuid(),
              root.st_mode & 0o7777 == 0o700, root.st_nlink > 0,
              held.st_mode & S_IFMT == S_IFDIR, held.st_uid == geteuid(),
              held.st_mode & 0o7777 == 0o700, held.st_nlink > 0,
              root.st_dev == held.st_dev, !same(root, held),
              fstatat(base, "executor", &named, AT_SYMLINK_NOFOLLOW) == 0,
              named.st_mode & S_IFMT == S_IFDIR, same(held, named) else {
            throw VPNApplicationSwapError.unsafeExecutor
        }
        for slot in ["current", "candidate"] {
            var other = stat()
            guard fstatat(base, slot, &other, AT_SYMLINK_NOFOLLOW) == 0,
                  other.st_mode & S_IFMT == S_IFDIR, !same(held, other) else {
                throw VPNApplicationSwapError.unsafeExecutor
            }
        }
        // The swap checks base ACL/locality under its lease; the full staged
        // inspector independently checks the executor directory and its tree.
    }

    private static func openExecutable(_ parent: Int32) throws -> Int32 {
        var directory = fcntl(parent, F_DUPFD_CLOEXEC, 0)
        guard directory >= 0 else { throw VPNApplicationSwapError.unsafeExecutor }
        defer { close(directory) }
        for name in ["ProxyPilot.app", "Contents", "MacOS"] {
            let next = openat(directory, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard next >= 0 else { throw VPNApplicationSwapError.unsafeExecutor }
            close(directory); directory = next
        }
        let file = openat(directory, "ProxyPilot", O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard file >= 0 else { throw VPNApplicationSwapError.unsafeExecutor }
        var info = stat()
        guard fstat(file, &info) == 0, info.st_mode & S_IFMT == S_IFREG,
              info.st_uid == geteuid(), info.st_nlink == 1, info.st_mode & 0o100 != 0 else {
            close(file); throw VPNApplicationSwapError.unsafeExecutor
        }
        return file
    }

    private static func checkProcess(_ expected: Int32) throws {
        var bytes = [UInt8](repeating: 0, count: 4 * Int(MAXPATHLEN))
        let length = bytes.withUnsafeMutableBytes { proc_pidpath(getpid(), $0.baseAddress!, UInt32($0.count)) }
        guard length > 0, let end = bytes.firstIndex(of: 0), end > 0,
              let path = String(bytes: bytes[..<end], encoding: .utf8), path.hasPrefix("/") else {
            throw VPNApplicationSwapError.unsafeExecutor
        }
        let processFile = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard processFile >= 0 else { throw VPNApplicationSwapError.unsafeExecutor }
        defer { close(processFile) }
        var actual = stat(), wanted = stat()
        guard fstat(processFile, &actual) == 0, fstat(expected, &wanted) == 0,
              actual.st_mode & S_IFMT == S_IFREG, actual.st_nlink == 1,
              same(actual, wanted) else { throw VPNApplicationSwapError.unsafeExecutor }
    }
}
