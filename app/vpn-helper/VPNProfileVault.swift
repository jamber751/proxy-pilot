import Darwin
import CryptoKit
import Foundation

enum VPNProfileVaultError: Error { case unsafeStorage, writeFailed, tooLarge }

/// The helper's own copy of the accepted VPN profile, inside the protected
/// directory. It stores bytes the helper itself re-validated — never bytes a
/// client called valid — and it does not run, parse or connect anything.
/// A failed write leaves the previous profile in place; there is no partial file.
final class VPNProfileVault {
    static let name = "profile.ovpn"
    /// Matches the importer's ceiling, kept here so the privileged side needs
    /// no part of the application to enforce its own storage limit.
    static let maximumBytes = 1_048_576
    private var directory: Int32
    private let owner = geteuid()

    init(trustedDirectoryDescriptor: Int32) throws {
        directory = fcntl(trustedDirectoryDescriptor, F_DUPFD_CLOEXEC, 0)
        guard directory >= 0 else { throw VPNProfileVaultError.unsafeStorage }
        do { try checkDirectory() }
        catch { close(directory); directory = -1; throw error }
    }

    deinit { if directory >= 0 { close(directory) } }

    @discardableResult
    func save(_ data: Data) throws -> String {
        guard !data.isEmpty, data.count <= Self.maximumBytes else {
            throw VPNProfileVaultError.tooLarge
        }
        try checkDirectory()
        let digest = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
        let addressed = Self.fileName(digest: digest)
        if let existing = try loadFile(addressed) {
            guard existing == data else { throw VPNProfileVaultError.unsafeStorage }
        } else {
            try replace(addressed, with: data)
        }
        // Keep the historical fixed name as the most recently accepted profile.
        // Active/pending transactions use the immutable digest-addressed copy.
        try replace(Self.name, with: data)
        return digest
    }

    func load(digest: String) throws -> Data? {
        guard Self.validDigest(digest) else { throw VPNProfileVaultError.unsafeStorage }
        return try loadFile(Self.fileName(digest: digest))
    }

    private func replace(_ name: String, with data: Data) throws {
        let temporary = ".profile-\(UUID().uuidString).tmp"
        let file = openat(directory, temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard file >= 0 else { throw VPNProfileVaultError.writeFailed }
        defer { close(file); unlinkat(directory, temporary, 0) }
        try check(file)
        try data.withUnsafeBytes { bytes in
            var offset = 0
            while offset < bytes.count {
                let count = write(file, bytes.baseAddress!.advanced(by: offset), bytes.count - offset)
                if count < 0, errno == EINTR { continue }
                guard count > 0 else { throw VPNProfileVaultError.writeFailed }
                offset += count
            }
        }
        // Rename only after the bytes are on disk: an interrupted save must not
        // replace a working profile with a truncated one.
        guard fsync(file) == 0, renameat(directory, temporary, directory, name) == 0,
              fsync(directory) == 0 else { throw VPNProfileVaultError.writeFailed }
    }

    func load() throws -> Data? {
        try checkDirectory()
        return try loadFile(Self.name)
    }

    private func loadFile(_ name: String) throws -> Data? {
        try checkDirectory()
        let file = openat(directory, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard file >= 0 else {
            guard errno == ENOENT else { throw VPNProfileVaultError.unsafeStorage }
            return nil
        }
        defer { close(file) }
        try check(file)
        var data = Data(), bytes = [UInt8](repeating: 0, count: 4096)
        while true {
            let count = read(file, &bytes, bytes.count)
            if count < 0, errno == EINTR { continue }
            guard count >= 0 else { throw VPNProfileVaultError.unsafeStorage }
            if count == 0 { return data }
            guard data.count + count <= Self.maximumBytes else { throw VPNProfileVaultError.tooLarge }
            data.append(contentsOf: bytes.prefix(count))
        }
    }

    static func fileName(digest: String) -> String { "profile-\(digest).ovpn" }

    static func validDigest(_ digest: String) -> Bool {
        digest.utf8.count == 64 && digest.allSatisfy {
            $0.isASCII && ($0.isNumber || ("a"..."f").contains(String($0)))
        }
    }

    private func checkDirectory() throws {
        var attributes = stat()
        guard geteuid() == owner, fstat(directory, &attributes) == 0,
              attributes.st_mode & S_IFMT == S_IFDIR, attributes.st_nlink > 0,
              attributes.st_uid == owner, attributes.st_mode & 0o7777 == 0o700 else {
            throw VPNProfileVaultError.unsafeStorage
        }
    }

    private func check(_ file: Int32) throws {
        var attributes = stat()
        guard fstat(file, &attributes) == 0, attributes.st_mode & S_IFMT == S_IFREG,
              attributes.st_nlink == 1, attributes.st_uid == owner,
              attributes.st_mode & 0o7777 == 0o600 else { throw VPNProfileVaultError.unsafeStorage }
    }
}
