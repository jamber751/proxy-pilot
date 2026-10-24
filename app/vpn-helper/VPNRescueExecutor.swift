import Darwin
import Foundation

enum VPNRescueExecutorError: Error {
    case requiresRoot, unsafeStorage, invalidArtifact, changed, wrongProcess
}

/// Live proof for the explicitly signed rescue role, not a substitute A policy.
/// A future caller must own the service/Update leases and trusted ancestors.
/// Production construction stays unavailable until the rescue boundary is wired.
final class VPNRescueExecutor {
    private let artifact: VPNRescueArtifactObservation
    var authorization: VerifiedVPNRescueAuthorization { artifact.authorization }

    private init(artifact: VPNRescueArtifactObservation) { self.artifact = artifact }

    @available(*, unavailable, message: "Explicit rescue lifecycle boundary is not implemented.")
    static func inspect(inTrustedDirectory directory: Int32,
                        authorization: VerifiedVPNRescueAuthorization) throws -> VPNRescueExecutor {
        try make(directory: directory, authorization: authorization)
    }

    #if VPN_RESCUE_EXECUTOR_TESTING
    static func testInspect(inTrustedDirectory directory: Int32,
                            authorization: VerifiedVPNRescueAuthorization) throws -> VPNRescueExecutor {
        try make(directory: directory, authorization: authorization)
    }
    #endif

    private static func make(directory: Int32,
                             authorization: VerifiedVPNRescueAuthorization) throws -> VPNRescueExecutor {
        let artifact = try VPNRescueArtifactObservation.inspect(directory: directory,
                                                               authorization: authorization)
        let result = VPNRescueExecutor(artifact: artifact)
        try result.revalidate()
        return result
    }

    func revalidate() throws {
        try artifact.revalidate()
        guard let arm = authorization.hash(forArchitecture: "arm64"),
              let intel = authorization.hash(forArchitecture: "x86_64") else {
            throw VPNRescueExecutorError.invalidArtifact
        }
        try VPNPeerAuthentication.validateCurrentProcess(
            policy: VPNPeerPolicy.rescue(codeDirectoryHashes: Set([arm, intel])))
        try artifact.requireCurrentProcess()
        try artifact.revalidate()
    }
}

/// Static-only observation. This type cannot be passed as a live rescue proof.
final class VPNRescueArtifactObservation {
    let authorization: VerifiedVPNRescueAuthorization
    private let directory: Int32
    private let executable: Int32
    private let parentIdentity: Facts
    private let executableIdentity: Facts
    private static let filename = "vpn-rescue"
    private static let maximumBytes = VPNRescueAuthorization.maximumArtifactBytes

    private init(directory: Int32, executable: Int32, authorization: VerifiedVPNRescueAuthorization,
                 parentIdentity: Facts, executableIdentity: Facts) {
        self.directory = directory; self.executable = executable
        self.authorization = authorization
        self.parentIdentity = parentIdentity; self.executableIdentity = executableIdentity
    }
    deinit { close(executable); close(directory) }

    fileprivate static func inspect(directory source: Int32,
                                    authorization: VerifiedVPNRescueAuthorization) throws -> VPNRescueArtifactObservation {
        guard getuid() == 0, geteuid() == 0 else { throw VPNRescueExecutorError.requiresRoot }
        guard authorization.artifactByteCount > 0,
              authorization.artifactByteCount <= maximumBytes else { throw VPNRescueExecutorError.invalidArtifact }
        let directory = fcntl(source, F_DUPFD_CLOEXEC, 0)
        guard directory >= 0 else { throw VPNRescueExecutorError.unsafeStorage }
        var executable: Int32 = -1
        var transferred = false
        defer {
            if !transferred {
                if executable >= 0 { close(executable) }
                close(directory)
            }
        }
        let parent = try checkDirectory(directory)
        executable = try openExecutable(directory)
        let file = try checkExecutable(executable)
        guard file.st_dev == parent.st_dev else { throw VPNRescueExecutorError.unsafeStorage }
        let result = VPNRescueArtifactObservation(directory: directory, executable: executable,
            authorization: authorization, parentIdentity: Facts(parent), executableIdentity: Facts(file))
        // Transfer descriptors before invoking a throwing revalidation.
        transferred = true
        try result.revalidate()
        return result
    }

    #if VPN_RESCUE_EXECUTOR_TESTING
    static func testInspect(inTrustedDirectory directory: Int32,
                            authorization: VerifiedVPNRescueAuthorization) throws -> VPNRescueArtifactObservation {
        try inspect(directory: directory, authorization: authorization)
    }
    #endif

    func revalidate() throws {
        guard getuid() == 0, geteuid() == 0 else { throw VPNRescueExecutorError.requiresRoot }
        guard Facts(try Self.checkDirectory(directory)) == parentIdentity,
              Facts(try Self.checkExecutable(executable)) == executableIdentity else {
            throw VPNRescueExecutorError.changed
        }
        let named = try Self.openExecutable(directory)
        defer { close(named) }
        guard Facts(try Self.checkExecutable(named)) == executableIdentity else {
            throw VPNRescueExecutorError.changed
        }
        let data = try readBounded()
        try authorization.validateArtifact(data)
        try VPNUniversalArtifact.validate(protectedFile: executable, data: data,
            identifier: "kz.documentolog.proxypilot.vpn-rescue", hash: authorization.hash,
            error: VPNRescueExecutorError.invalidArtifact)
        guard Facts(try Self.checkDirectory(directory)) == parentIdentity,
              Facts(try Self.checkExecutable(executable)) == executableIdentity,
              Facts(try Self.checkExecutable(named)) == executableIdentity else {
            throw VPNRescueExecutorError.changed
        }
    }

    fileprivate func requireCurrentProcess() throws {
        var bytes = [UInt8](repeating: 0, count: 4 * Int(MAXPATHLEN))
        let length = bytes.withUnsafeMutableBytes { proc_pidpath(getpid(), $0.baseAddress!, UInt32($0.count)) }
        guard length > 0, let end = bytes.firstIndex(of: 0), end > 0,
              let path = String(bytes: bytes[..<end], encoding: .utf8), path.hasPrefix("/") else {
            throw VPNRescueExecutorError.wrongProcess
        }
        let running = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard running >= 0 else { throw VPNRescueExecutorError.wrongProcess }
        defer { close(running) }
        guard Facts(try Self.checkExecutable(running)) == executableIdentity else {
            throw VPNRescueExecutorError.wrongProcess
        }
    }

    private func readBounded() throws -> Data {
        let count = authorization.artifactByteCount
        guard count > 0, count <= Self.maximumBytes,
              executableIdentity.size == Int64(count) else { throw VPNRescueExecutorError.invalidArtifact }
        var data = Data(count: count)
        let consumed = data.withUnsafeMutableBytes { buffer -> Int in
            var offset = 0
            while offset < count {
                let amount = pread(executable, buffer.baseAddress!.advanced(by: offset), count - offset, off_t(offset))
                if amount < 0, errno == EINTR { continue }
                guard amount > 0 else { return -1 }
                offset += amount
            }
            return offset
        }
        guard consumed == count else { throw VPNRescueExecutorError.invalidArtifact }
        return data
    }

    private struct Facts: Equatable {
        let device: dev_t, inode: ino_t, mode: mode_t, owner: uid_t, group: gid_t
        let links: nlink_t, size: Int64, flags: UInt32
        let modified: Int64, modifiedNS: Int64, changed: Int64, changedNS: Int64
        init(_ value: stat) {
            device = value.st_dev; inode = value.st_ino; mode = value.st_mode
            owner = value.st_uid; group = value.st_gid; links = value.st_nlink
            size = value.st_size; flags = value.st_flags
            modified = Int64(value.st_mtimespec.tv_sec); modifiedNS = Int64(value.st_mtimespec.tv_nsec)
            changed = Int64(value.st_ctimespec.tv_sec); changedNS = Int64(value.st_ctimespec.tv_nsec)
        }
    }

    private static func checkExecutable(_ fd: Int32) throws -> stat {
        var value = stat()
        guard fstat(fd, &value) == 0, value.st_mode & S_IFMT == S_IFREG,
              value.st_uid == 0, value.st_nlink == 1,
              value.st_mode & 0o7777 == 0o700, value.st_size > 0,
              value.st_size <= maximumBytes, value.st_flags == 0 else {
            throw VPNRescueExecutorError.unsafeStorage
        }
        try requireNoACL(fd)
        return value
    }

    private static func openExecutable(_ parent: Int32) throws -> Int32 {
        let file = openat(parent, filename, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard file >= 0 else { throw VPNRescueExecutorError.unsafeStorage }
        return file
    }

    private static func checkDirectory(_ fd: Int32) throws -> stat {
        var value = stat(), filesystem = statfs()
        guard fstat(fd, &value) == 0, value.st_mode & S_IFMT == S_IFDIR,
              value.st_uid == 0, value.st_mode & 0o7777 == 0o700, value.st_nlink > 0,
              value.st_flags == 0, fstatfs(fd, &filesystem) == 0,
              filesystem.f_flags & UInt32(MNT_LOCAL) != 0 else { throw VPNRescueExecutorError.unsafeStorage }
        try requireNoACL(fd)
        let scan = openat(fd, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard scan >= 0 else { throw VPNRescueExecutorError.unsafeStorage }
        guard let stream = fdopendir(scan) else { close(scan); throw VPNRescueExecutorError.unsafeStorage }
        defer { closedir(stream) }
        var found = false
        let offset = MemoryLayout<dirent>.offset(of: \.d_name)!
        while true {
            errno = 0
            guard let row = readdir(stream) else {
                guard errno == 0, found else { throw VPNRescueExecutorError.unsafeStorage }
                break
            }
            let length = Int(row.pointee.d_namlen)
            guard length > 0, length < 1024, offset + length < Int(row.pointee.d_reclen) else {
                throw VPNRescueExecutorError.unsafeStorage
            }
            let pointer = UnsafeRawPointer(row).advanced(by: offset).assumingMemoryBound(to: UInt8.self)
            guard pointer[length] == 0,
                  let name = String(bytes: UnsafeBufferPointer(start: pointer, count: length), encoding: .utf8) else {
                throw VPNRescueExecutorError.unsafeStorage
            }
            if name == "." || name == ".." { continue }
            guard name == filename, !found else { throw VPNRescueExecutorError.unsafeStorage }
            found = true
        }
        return value
    }

    private static func requireNoACL(_ fd: Int32) throws {
        var value = stat()
        guard let security = filesec_init() else { throw VPNRescueExecutorError.unsafeStorage }
        defer { filesec_free(security) }
        guard fstatx_np(fd, &value, security) == 0 else { throw VPNRescueExecutorError.unsafeStorage }
        var retrieved: acl_t?
        errno = 0
        let result = filesec_get_property(security, FILESEC_ACL, &retrieved)
        if result == -1, errno == ENOENT { return }
        guard result == 0, let acl = retrieved else { throw VPNRescueExecutorError.unsafeStorage }
        defer { acl_free(UnsafeMutableRawPointer(acl)) }
        var entry: acl_entry_t?
        errno = 0
        guard acl_get_entry(acl, Int32(ACL_FIRST_ENTRY.rawValue), &entry) == -1, errno == EINVAL else {
            throw VPNRescueExecutorError.unsafeStorage
        }
    }
}
