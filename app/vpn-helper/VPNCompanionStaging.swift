import Darwin
import Foundation

enum VPNCompanionStagingError: Error {
    case invalidRequest, unsafeStorage, oversized, incomplete, alreadyFinished
}

/// Owns the verified read-only artifact descriptor and its private temporary
/// storage. No path is exposed to updater or Broker IPC.
final class VPNDownloadedCompanion {
    private var descriptor: Int32
    private var directory: Int32
    private let directoryPath: String
    private static let fileName = "artifact.dmg"

    fileprivate init(descriptor: Int32, directory: Int32,
                     directoryPath: String) {
        self.descriptor = descriptor
        self.directory = directory
        self.directoryPath = directoryPath
    }

    func withFileDescriptor<T>(_ body: (Int32) throws -> T) rethrows -> T {
        try body(descriptor)
    }

    deinit {
        if descriptor >= 0 { close(descriptor); descriptor = -1 }
        if directory >= 0 {
            _ = unlinkat(directory, Self.fileName, 0)
            close(directory); directory = -1
        }
        _ = rmdir(directoryPath)
    }
}

/// Streaming, no-resume staging sink. It accepts bytes only up to the signed
/// exact length and returns an open descriptor only after SHA-256 validation.
final class VPNCompanionStaging {
    private static let fileName = "artifact.dmg"
    private var directory: Int32 = -1
    private var writer: Int32 = -1
    private var directoryPath = ""
    private let expectedBytes: UInt64
    private var received: UInt64 = 0
    private var finished = false

    init(expectedBytes: UInt64) throws {
        guard expectedBytes > 0,
              expectedBytes <= VPNCompanionMetadataAuthority.maximumArtifactBytes,
              getuid() == geteuid(), geteuid() != 0 else {
            throw VPNCompanionStagingError.invalidRequest
        }
        self.expectedBytes = expectedBytes
        var template = Array((NSTemporaryDirectory()
            + "ProxyPilot-Companion.XXXXXX").utf8CString)
        guard mkdtemp(&template) != nil else {
            throw VPNCompanionStagingError.unsafeStorage
        }
        directoryPath = String(cString: template)
        do {
            directory = open(directoryPath,
                O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard directory >= 0 else { throw VPNCompanionStagingError.unsafeStorage }
            var info = stat(), filesystem = statfs()
            guard fstat(directory, &info) == 0,
                  info.st_mode & S_IFMT == S_IFDIR,
                  info.st_uid == geteuid(), info.st_nlink > 0,
                  info.st_mode & 0o7777 == 0o700,
                  fstatfs(directory, &filesystem) == 0,
                  filesystem.f_flags & UInt32(MNT_LOCAL) != 0 else {
                throw VPNCompanionStagingError.unsafeStorage
            }
            writer = openat(directory, Self.fileName,
                O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
            guard writer >= 0 else { throw VPNCompanionStagingError.unsafeStorage }
            try checkFile(writer)
        } catch {
            cleanup()
            throw error
        }
    }

    func append(_ data: Data) throws {
        guard !finished, writer >= 0 else {
            throw VPNCompanionStagingError.alreadyFinished
        }
        guard !data.isEmpty else { return }
        guard UInt64(data.count) <= expectedBytes - received else {
            throw VPNCompanionStagingError.oversized
        }
        var offset = 0
        try data.withUnsafeBytes { bytes in
            while offset < bytes.count {
                let count = Darwin.write(
                    writer, bytes.baseAddress!.advanced(by: offset),
                    bytes.count - offset)
                if count < 0, errno == EINTR { continue }
                guard count > 0 else { throw VPNCompanionStagingError.unsafeStorage }
                offset += count
            }
        }
        received += UInt64(data.count)
    }

    func finish(metadata: VerifiedVPNCompanionMetadata) throws
        -> VPNDownloadedCompanion {
        guard !finished, writer >= 0 else {
            throw VPNCompanionStagingError.alreadyFinished
        }
        finished = true
        do {
            guard received == expectedBytes,
                  metadata.artifactBytes == expectedBytes else {
                throw VPNCompanionStagingError.incomplete
            }
            guard fsync(writer) == 0 else {
                throw VPNCompanionStagingError.unsafeStorage
            }
            try checkFile(writer)
            try metadata.validateArtifact(fileDescriptor: writer)
            var written = stat()
            guard fstat(writer, &written) == 0 else {
                throw VPNCompanionStagingError.unsafeStorage
            }
            close(writer); writer = -1
            let reader = openat(directory, Self.fileName,
                O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
            guard reader >= 0 else { throw VPNCompanionStagingError.unsafeStorage }
            do {
                var reopened = stat()
                try checkFile(reader)
                guard fstat(reader, &reopened) == 0,
                      reopened.st_dev == written.st_dev,
                      reopened.st_ino == written.st_ino,
                      reopened.st_size == written.st_size else {
                    throw VPNCompanionStagingError.unsafeStorage
                }
            } catch {
                close(reader)
                throw error
            }
            let result = VPNDownloadedCompanion(
                descriptor: reader, directory: directory,
                directoryPath: directoryPath)
            directory = -1
            directoryPath = ""
            return result
        } catch {
            cleanup()
            throw error
        }
    }

    private func checkFile(_ descriptor: Int32) throws {
        var info = stat(), filesystem = statfs()
        guard fstat(descriptor, &info) == 0,
              info.st_mode & S_IFMT == S_IFREG,
              info.st_uid == geteuid(), info.st_nlink == 1,
              info.st_mode & 0o7777 == 0o600,
              fstatfs(descriptor, &filesystem) == 0,
              filesystem.f_flags & UInt32(MNT_LOCAL) != 0 else {
            throw VPNCompanionStagingError.unsafeStorage
        }
    }

    private func cleanup() {
        if writer >= 0 { close(writer); writer = -1 }
        if directory >= 0 {
            _ = unlinkat(directory, Self.fileName, 0)
            close(directory); directory = -1
        }
        if !directoryPath.isEmpty { _ = rmdir(directoryPath); directoryPath = "" }
    }

    deinit { cleanup() }
}
