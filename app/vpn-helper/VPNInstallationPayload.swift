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
    let release: VerifiedVPNRelease

    static func load(directory: URL, version: String, authority: VPNReleaseAuthority) throws -> VPNInstallationPayload {
        let parent = open(directory.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard parent >= 0 else { throw VPNInstallationPayloadError.unsafePackage }
        defer { close(parent) }
        try check(parent, directory: true)
        let manifest = try read("vpn-release.manifest", in: parent, limit: VPNReleaseAuthority.maximumPayloadBytes)
        let encoded = try read("vpn-release.sig", in: parent, limit: 89)
        guard let text = String(data: encoded, encoding: .utf8), text.count == 89, text.last == "\n",
              let signature = Data(base64Encoded: String(text.dropLast())), signature.count == 64,
              signature.base64EncodedString() + "\n" == text else {
            throw VPNInstallationPayloadError.invalidSignatureEncoding
        }
        let release = try authority.verify(payload: manifest, signature: signature, previous: nil)
        guard release.version == version else { throw VPNInstallationPayloadError.versionMismatch }
        let helper = try read("vpn-helper", in: parent, limit: VPNReleaseAuthority.maximumHelperBytes) { file, bytes in
            try VPNHelperArtifact.validate(protectedFile: file, data: bytes, release: release)
        }
        return VPNInstallationPayload(manifest: manifest, signature: signature, helper: helper, release: release)
    }

    private static func read(_ name: String, in parent: Int32, limit: Int,
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

    private static func check(_ fd: Int32, directory: Bool) throws {
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
