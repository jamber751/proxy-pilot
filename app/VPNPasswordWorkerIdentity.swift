import Darwin
import Foundation
import Security

/// One owner from acquisition through throwing initialization and deinit.
final class VPNPasswordWorkerDescriptor {
    let value: Int32
    init(taking value: Int32) { self.value = value }
    deinit {
        close(value)
        #if VPN_PASSWORD_WORKER_TESTING
        Self.testAfterClose?(value)
        #endif
    }
    #if VPN_PASSWORD_WORKER_TESTING
    static var testAfterClose: ((Int32) -> Void)?
    #endif
}

/// The currently running ordinary frontend, not a stable certificate identity.
/// Private inherited IPC is the capability; a socketpair's creator PID is NOT
/// used as proof that the spawned child became its peer.
final class VPNPasswordWorkerIdentity {
    struct ProcessStamp: Equatable {
        let pid: pid_t
        let parent: pid_t
        let seconds: UInt64
        let microseconds: UInt64
    }
    static let identifier = "kz.documentolog.proxypilot"
    let path: String
    private let executable: VPNPasswordWorkerDescriptor
    private let policy: VPNPeerPolicy
    private let attributes: stat

    init() throws {
        guard getuid() == geteuid(), getuid() >= 500 else { throw VPNPasswordWorkerError.denied }
        var code: SecCode?
        guard SecCodeCopySelf([], &code) == errSecSuccess, let code else { throw VPNPasswordWorkerError.denied }
        var raw: CFDictionary?
        guard SecCodeCopySigningInformation(unsafeBitCast(code, to: SecStaticCode.self),
                SecCSFlags(rawValue: kSecCSSigningInformation), &raw) == errSecSuccess,
              let info = raw as? [String: Any],
              info[kSecCodeInfoIdentifier as String] as? String == Self.identifier,
              let hash = info[kSecCodeInfoUnique as String] as? Data, hash.count == 20 else {
            throw VPNPasswordWorkerError.denied
        }
        policy = try VPNPeerPolicy(userID: getuid(), signingIdentifier: Self.identifier, codeDirectoryHashes: [hash])
        try VPNPeerAuthentication.validateCurrentProcess(policy: policy)
        path = try Self.processPath(getpid())
        let file = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard file >= 0 else { throw VPNPasswordWorkerError.denied }
        let owned = VPNPasswordWorkerDescriptor(taking: file)
        var before = stat()
        guard fstat(file, &before) == 0, before.st_mode & S_IFMT == S_IFREG,
              before.st_mode & 0o022 == 0, before.st_uid == getuid() || before.st_uid == 0 else {
            throw VPNPasswordWorkerError.denied
        }
        executable = owned; attributes = before
        #if VPN_PASSWORD_WORKER_TESTING
        if Self.testRejectInitialized { throw VPNPasswordWorkerError.denied }
        #endif
        var disk: SecStaticCode?
        guard SecStaticCodeCreateWithPath(URL(fileURLWithPath: path) as CFURL, [], &disk) == errSecSuccess,
              let disk,
              SecStaticCodeCheckValidity(disk, SecCSFlags(rawValue: kSecCSStrictValidate | kSecCSCheckAllArchitectures).union(.noNetworkAccess), nil) == errSecSuccess else {
            throw VPNPasswordWorkerError.denied
        }
        _ = try validateProcess(getpid())
    }

    #if VPN_PASSWORD_WORKER_TESTING
    static var testRejectInitialized = false
    #endif

    func validateProcess(_ pid: pid_t, expected: ProcessStamp? = nil,
                         parent: pid_t? = nil) throws -> ProcessStamp {
        let initial = try Self.stamp(pid)
        guard expected == nil || expected == initial,
              parent == nil || initial.parent == parent else { throw VPNPasswordWorkerError.denied }
        try validateImage(pid)
        try VPNPeerAuthentication.validate(processID: pid, policy: policy)
        try validateImage(pid)
        guard try Self.stamp(pid) == initial else { throw VPNPasswordWorkerError.denied }
        return initial
    }

    /// Full Security authentication already completed during READY, outside the
    /// Store lock. The child is then blocked on its private one-shot capability.
    func requireSameProcess(_ pid: pid_t, expected: ProcessStamp, parent: pid_t) throws {
        guard try Self.stamp(pid) == expected, expected.parent == parent else { throw VPNPasswordWorkerError.denied }
        try validateImage(pid)
    }

    private func validateImage(_ pid: pid_t) throws {
        let running = open(try Self.processPath(pid), O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard running >= 0 else { throw VPNPasswordWorkerError.denied }
        defer { close(running) }
        var held = stat(), actual = stat()
        guard fstat(executable.value, &held) == 0, fstat(running, &actual) == 0,
              Self.same(held, attributes), Self.same(held, actual) else { throw VPNPasswordWorkerError.denied }
    }

    private static func stamp(_ pid: pid_t) throws -> ProcessStamp {
        var info = proc_bsdinfo()
        let size = Int32(MemoryLayout.size(ofValue: info))
        guard pid > 0, proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, size) == size,
              info.pbi_uid == getuid(), info.pbi_ruid == getuid(), info.pbi_svuid == getuid() else {
            throw VPNPasswordWorkerError.denied
        }
        return ProcessStamp(pid: pid, parent: pid_t(info.pbi_ppid),
                            seconds: info.pbi_start_tvsec, microseconds: info.pbi_start_tvusec)
    }

    private static func processPath(_ pid: pid_t) throws -> String {
        var bytes = [UInt8](repeating: 0, count: 4 * Int(MAXPATHLEN))
        let length = bytes.withUnsafeMutableBytes { proc_pidpath(pid, $0.baseAddress!, UInt32($0.count)) }
        guard length > 0, let end = bytes.firstIndex(of: 0), end > 0,
              let path = String(bytes: bytes[..<end], encoding: .utf8), path.hasPrefix("/") else {
            throw VPNPasswordWorkerError.denied
        }
        return path
    }

    private static func same(_ a: stat, _ b: stat) -> Bool {
        a.st_dev == b.st_dev && a.st_ino == b.st_ino && a.st_size == b.st_size
            && a.st_mtimespec.tv_sec == b.st_mtimespec.tv_sec && a.st_mtimespec.tv_nsec == b.st_mtimespec.tv_nsec
            && a.st_ctimespec.tv_sec == b.st_ctimespec.tv_sec && a.st_ctimespec.tv_nsec == b.st_ctimespec.tv_nsec
    }
}

/// Only a validated inherited directory capability, never an argv path.
final class VPNPasswordWorkerDirectory {
    private let owned: VPNPasswordWorkerDescriptor
    var descriptor: Int32 { owned.value }
    let url: URL
    private let attributes: stat
    init(duplicating source: Int32) throws {
        let fd = fcntl(source, F_DUPFD_CLOEXEC, 64)
        guard fd >= 0 else { throw VPNPasswordWorkerError.denied }
        let owner = VPNPasswordWorkerDescriptor(taking: fd)
        var info = stat(), bytes = [CChar](repeating: 0, count: Int(MAXPATHLEN))
        guard fstat(fd, &info) == 0, info.st_mode & S_IFMT == S_IFDIR,
              info.st_uid == getuid(), info.st_mode & 0o7777 == 0o700,
              fcntl(fd, F_GETPATH, &bytes) == 0 else {
            throw VPNPasswordWorkerError.denied
        }
        owned = owner; attributes = info; url = URL(fileURLWithPath: String(cString: bytes), isDirectory: true)
        #if VPN_PASSWORD_WORKER_TESTING
        if Self.testRejectInitialized { throw VPNPasswordWorkerError.denied }
        #endif
        try revalidate()
    }
    #if VPN_PASSWORD_WORKER_TESTING
    static var testRejectInitialized = false
    #endif
    func revalidate() throws {
        try requireSameDirectory(as: url)
    }
    func requireSameDirectory(as candidate: URL) throws {
        let named = open(candidate.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard named >= 0 else { throw VPNPasswordWorkerError.denied }
        defer { close(named) }
        var held = stat(), actual = stat()
        guard fstat(descriptor, &held) == 0, fstat(named, &actual) == 0,
              held.st_dev == attributes.st_dev, held.st_ino == attributes.st_ino,
              held.st_dev == actual.st_dev, held.st_ino == actual.st_ino,
              held.st_uid == getuid(), held.st_mode & 0o7777 == 0o700 else { throw VPNPasswordWorkerError.denied }
    }
}
