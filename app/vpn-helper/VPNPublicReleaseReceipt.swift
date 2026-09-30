import Darwin
import Foundation

enum VPNPublicReleaseReceiptError: Error {
    case unsafeStorage, invalidReceipt, writeFailed
}

struct VPNPublicVerifiedReceipt {
    let ownerUserID: uid_t
    let payload: Data
    let signature: Data
    let release: VerifiedVPNRelease
}

/// Root publishes one non-secret, signed release description beside the public
/// socket. The desktop app verifies its signature first, then uses the exact
/// helper CDHashes from that release for the ordinary readiness handshake.
/// A stale receipt cannot authorize a new app/helper pair because both peers
/// are pinned by the signed payload.
enum VPNPublicReleaseReceipt {
    static let fileName = "release-receipt.json"
    private static let temporaryName = ".release-receipt.tmp"
    private static let maximumBytes = 16 * 1024

    private struct Envelope: Codable {
        let schema: Int
        let owner: uid_t
        let payload: Data
        let signature: Data
    }

    static func publish(ownerUserID: uid_t, payload: Data, signature: Data,
                        inTrustedDirectory directory: Int32) throws {
        guard ownerUserID >= 500, ownerUserID != uid_t.max else {
            throw VPNPublicReleaseReceiptError.invalidReceipt
        }
        let value = Envelope(schema: 1, owner: ownerUserID,
                             payload: payload, signature: signature)
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
        let data = try encoder.encode(value)
        guard data.count <= maximumBytes else { throw VPNPublicReleaseReceiptError.invalidReceipt }
        _ = unlinkat(directory, temporaryName, 0)
        let file = openat(directory, temporaryName,
            O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o644)
        guard file >= 0 else { throw VPNPublicReleaseReceiptError.writeFailed }
        var complete = false
        defer {
            close(file)
            if !complete { _ = unlinkat(directory, temporaryName, 0) }
        }
        var offset = 0
        while offset < data.count {
            let count = data.withUnsafeBytes {
                write(file, $0.baseAddress!.advanced(by: offset), data.count - offset)
            }
            if count < 0, errno == EINTR { continue }
            guard count > 0 else { throw VPNPublicReleaseReceiptError.writeFailed }
            offset += count
        }
        guard fchmod(file, 0o644) == 0, fsync(file) == 0,
              renameat(directory, temporaryName, directory, fileName) == 0,
              fsync(directory) == 0 else { throw VPNPublicReleaseReceiptError.writeFailed }
        complete = true
    }

    static func loadSystem(authority: VPNReleaseAuthority) throws
        -> VPNPublicVerifiedReceipt {
        let directory = try VPNEndpointDirectory.openSystem(create: false)
        defer { close(directory) }
        return try load(inTrustedDirectory: directory, expectedFileOwner: 0,
                        authority: authority)
    }

    static func load(inTrustedDirectory directory: Int32, expectedFileOwner: uid_t,
                     authority: VPNReleaseAuthority) throws
        -> VPNPublicVerifiedReceipt {
        let file = openat(directory, fileName,
            O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard file >= 0 else { throw VPNPublicReleaseReceiptError.unsafeStorage }
        defer { close(file) }
        var info = stat()
        guard fstat(file, &info) == 0, info.st_mode & S_IFMT == S_IFREG,
              info.st_uid == expectedFileOwner, info.st_nlink == 1,
              info.st_mode & 0o7777 == 0o644, info.st_size > 0,
              info.st_size <= maximumBytes else {
            throw VPNPublicReleaseReceiptError.unsafeStorage
        }
        var data = Data(), buffer = [UInt8](repeating: 0, count: 4096)
        while true {
            let count = read(file, &buffer, buffer.count)
            if count < 0, errno == EINTR { continue }
            guard count >= 0, data.count + max(0, count) <= maximumBytes else {
                throw VPNPublicReleaseReceiptError.unsafeStorage
            }
            if count == 0 { break }
            data.append(contentsOf: buffer.prefix(count))
        }
        let value = try JSONDecoder().decode(Envelope.self, from: data)
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
        guard value.schema == 1, value.owner >= 500, value.owner != uid_t.max,
              try encoder.encode(value) == data else {
            throw VPNPublicReleaseReceiptError.invalidReceipt
        }
        let release = try authority.verify(payload: value.payload,
                                           signature: value.signature, previous: nil)
        return VPNPublicVerifiedReceipt(ownerUserID: value.owner,
            payload: value.payload, signature: value.signature, release: release)
    }
}
