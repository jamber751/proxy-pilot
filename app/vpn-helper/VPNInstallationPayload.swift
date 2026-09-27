import Darwin
import Foundation

enum VPNInstallationPayloadError: Error { case unsafePackage, invalidSignatureEncoding, versionMismatch }

/// Fixed-name, independently signed sidecars BESIDE the sealed application.
/// Embedding a manifest containing the app's own CDHash inside its sealed
/// resources would change that hash. Never weaken resource sealing to avoid it.
struct VPNInstallationPayload {
    let manifest: Data
    let signature: Data
    let helper: Data
    let engine: Data?
    let release: VerifiedVPNRelease

    static func load(directory: URL, version: String, authority: VPNReleaseAuthority) throws -> VPNInstallationPayload {
        let parent = open(directory.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard parent >= 0 else { throw VPNInstallationPayloadError.unsafePackage }
        defer { close(parent) }
        try check(parent, directory: true)
        return try load(parent: parent, version: version, authority: authority)
    }

    fileprivate static func load(parent: Int32, version: String,
                                 authority: VPNReleaseAuthority) throws -> VPNInstallationPayload {
        let manifest = try read("vpn-release.manifest", in: parent, limit: VPNReleaseAuthority.maximumPayloadBytes)
        let signature = try readSignature("vpn-release.sig", in: parent)
        let release = try authority.verify(payload: manifest, signature: signature, previous: nil)
        guard release.version == version else { throw VPNInstallationPayloadError.versionMismatch }
        let helper = try read("vpn-helper", in: parent, limit: VPNReleaseAuthority.maximumHelperBytes) { file, bytes in
            try VPNHelperArtifact.validate(protectedFile: file, data: bytes, release: release)
        }
        var engine: Data?
        if release.engine != nil {
            engine = try read("vpn-engine", in: parent, limit: VPNReleaseAuthority.maximumEngineBytes) { file, bytes in
                try VPNEngineArtifact.validate(protectedFile: file, data: bytes, release: release)
            }
        } else {
            var unexpected = stat()
            guard fstatat(parent, "vpn-engine", &unexpected, AT_SYMLINK_NOFOLLOW) == -1, errno == ENOENT else {
                throw VPNInstallationPayloadError.unsafePackage
            }
        }
        try release.validateArtifacts(helper: helper, engine: engine)
        return VPNInstallationPayload(manifest: manifest, signature: signature, helper: helper, engine: engine, release: release)
    }

    fileprivate static func readSignature(_ name: String, in parent: Int32) throws -> Data {
        let encoded = try read(name, in: parent, limit: 89)
        guard let text = String(data: encoded, encoding: .utf8),
              text.count == 89, text.last == "\n",
              let signature = Data(base64Encoded: String(text.dropLast())),
              signature.count == 64,
              signature.base64EncodedString() + "\n" == text else {
            throw VPNInstallationPayloadError.invalidSignatureEncoding
        }
        return signature
    }

    fileprivate static func read(_ name: String, in parent: Int32, limit: Int,
                                 validate: ((Int32, Data) throws -> Void)? = nil) throws -> Data {
        let file = openat(parent, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard file >= 0 else { throw VPNInstallationPayloadError.unsafePackage }
        defer { close(file) }
        try check(file, directory: false)
        var before = stat()
        guard fstat(file, &before) == 0, before.st_size > 0, before.st_size <= limit else {
            throw VPNInstallationPayloadError.unsafePackage
        }
        var data = Data(), bytes = [UInt8](repeating: 0, count: 16384)
        while true {
            let count = Darwin.read(file, &bytes, bytes.count)
            if count < 0, errno == EINTR { continue }
            guard count >= 0, data.count + max(0, count) <= limit else {
                throw VPNInstallationPayloadError.unsafePackage
            }
            if count == 0 { break }
            data.append(contentsOf: bytes.prefix(count))
        }
        try validate?(file, data)
        var after = stat(), named = stat()
        guard fstat(file, &after) == 0, fstatat(parent, name, &named, AT_SYMLINK_NOFOLLOW) == 0,
              before.st_dev == named.st_dev, before.st_ino == named.st_ino,
              before.st_size == after.st_size, data.count == after.st_size,
              before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec,
              before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec,
              before.st_ctimespec.tv_sec == after.st_ctimespec.tv_sec,
              before.st_ctimespec.tv_nsec == after.st_ctimespec.tv_nsec else {
            throw VPNInstallationPayloadError.unsafePackage
        }
        try check(file, directory: false)
        return data
    }

    fileprivate static func check(_ fd: Int32, directory: Bool) throws {
        var info = stat(), filesystem = statfs()
        guard fstat(fd, &info) == 0, info.st_uid == geteuid(),
              info.st_mode & S_IFMT == (directory ? S_IFDIR : S_IFREG),
              info.st_mode & 0o7022 == 0, directory ? info.st_nlink > 0 : info.st_nlink == 1,
              fstatfs(fd, &filesystem) == 0, filesystem.f_flags & UInt32(MNT_LOCAL) != 0 else {
            throw VPNInstallationPayloadError.unsafePackage
        }
        guard let security = filesec_init() else { throw VPNInstallationPayloadError.unsafePackage }
        defer { filesec_free(security) }
        guard fstatx_np(fd, &info, security) == 0 else { throw VPNInstallationPayloadError.unsafePackage }
        var acl: acl_t?
        errno = 0
        let result = filesec_get_property(security, FILESEC_ACL, &acl)
        if result == -1, errno == ENOENT { return }
        guard result == 0, let acl = acl else { throw VPNInstallationPayloadError.unsafePackage }
        defer { acl_free(UnsafeMutableRawPointer(acl)) }
        var entry: acl_entry_t?
        errno = 0
        guard acl_get_entry(acl, Int32(ACL_FIRST_ENTRY.rawValue), &entry) == -1, errno == EINVAL else {
            throw VPNInstallationPayloadError.unsafePackage
        }
    }
}

/// Complete immutable input for a future joint app/helper replacement. The
/// package carries A only as signed metadata; production still has to match it
/// against protected installed state before any mutation. B and the exact edge
/// are verified together while one trusted package directory descriptor is held.
struct VPNJointUpdatePayload {
    let previousManifest: Data
    let previousSignature: Data
    let candidate: VPNInstallationPayload
    let previous: VerifiedVPNRelease
    let transition: VerifiedVPNUpdateTransition

    static func load(directory: URL, version: String,
                     authority: VPNReleaseAuthority) throws -> VPNJointUpdatePayload {
        let parent = open(directory.path,
                          O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard parent >= 0 else { throw VPNInstallationPayloadError.unsafePackage }
        defer { close(parent) }
        try VPNInstallationPayload.check(parent, directory: true)
        let candidate = try VPNInstallationPayload.load(
            parent: parent, version: version, authority: authority)
        let previousManifest = try VPNInstallationPayload.read(
            "vpn-previous-release.manifest", in: parent,
            limit: VPNReleaseAuthority.maximumPayloadBytes)
        let previousSignature = try VPNInstallationPayload.readSignature(
            "vpn-previous-release.sig", in: parent)
        let transitionPayload = try VPNInstallationPayload.read(
            "vpn-update-transition", in: parent,
            limit: VPNReleaseAuthority.maximumUpdateTransitionBytes)
        let transitionSignature = try VPNInstallationPayload.readSignature(
            "vpn-update-transition.sig", in: parent)
        let previous = try authority.verify(
            payload: previousManifest, signature: previousSignature, previous: nil)
        let transition = try authority.verifyUpdateTransition(
            payload: transitionPayload, signature: transitionSignature,
            previous: previous, candidatePayload: candidate.manifest,
            candidateSignature: candidate.signature)
        guard transition.matchesSource(previous),
              transition.matchesDestination(candidate.release) else {
            throw VPNReleaseAuthorizationError.invalidUpdateTransition
        }
        return VPNJointUpdatePayload(
            previousManifest: previousManifest,
            previousSignature: previousSignature,
            candidate: candidate, previous: previous, transition: transition)
    }
}
