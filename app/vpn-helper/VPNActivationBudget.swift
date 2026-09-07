import Darwin
import Foundation

enum VPNActivationIntent { case automatic, explicit }

enum VPNActivationBudgetError: Error {
    case unsafeStorage
    case invalidState
    case turnedOff
    case exhausted
    case writeFailed
}

/// Durable answer to "may we try to start the helper again?", kept next to the
/// release policy in the protected directory. Two rules only: a user who turned
/// the VPN off outranks every automatic attempt, and repeated failures stop
/// automatic retries instead of looping. It authorizes nothing by itself — it
/// cannot start, stop or select anything, and it is not VPN state.
final class VPNActivationBudget {
    static let maximumConsecutiveFailures = 3
    private struct Record: Codable {
        let schema: Int
        let desired: Bool
        let failures: Int
    }
    private static let name = "activation.json"
    private static let maximumBytes = 512
    private var directory: Int32
    private let owner = geteuid()

    init(trustedDirectoryDescriptor: Int32) throws {
        directory = fcntl(trustedDirectoryDescriptor, F_DUPFD_CLOEXEC, 0)
        guard directory >= 0 else { throw VPNActivationBudgetError.unsafeStorage }
        do { try checkDirectory() }
        catch { close(directory); directory = -1; throw error }
    }

    deinit { if directory >= 0 { close(directory) } }

    /// Charges the attempt before it happens: a process that dies mid-attempt
    /// has still spent it, so a crash loop cannot restart the helper forever.
    /// An explicit user action is always allowed through — the budget exists to
    /// bound automation, not to lock the owner out of their own machine.
    func beginAttempt(intent: VPNActivationIntent) throws {
        let current = try read()
        if intent == .automatic {
            guard current.desired else { throw VPNActivationBudgetError.turnedOff }
            guard current.failures < Self.maximumConsecutiveFailures else { throw VPNActivationBudgetError.exhausted }
        }
        try write(Record(schema: 1, desired: current.desired, failures: current.failures + 1))
    }

    /// Only a confirmed activation clears the failures, and it also records that
    /// the VPN is meant to be on: nothing else may resurrect it after a manual off.
    func recordSuccess() throws {
        try write(Record(schema: 1, desired: true, failures: 0))
    }

    /// Manual off wins over automation until the owner explicitly turns it back
    /// on. It never clears the failure count, so a broken build stays bounded.
    func recordManualOff() throws {
        let current = try read()
        try write(Record(schema: 1, desired: false, failures: current.failures))
    }

    func snapshot() throws -> (desired: Bool, failures: Int) {
        let current = try read()
        return (current.desired, current.failures)
    }

    /// A missing record is a first run. A damaged one is never "repaired" into a
    /// fresh budget: that would be the easiest way to defeat both rules.
    private func read() throws -> Record {
        try checkDirectory()
        let file = openat(directory, Self.name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard file >= 0 else {
            guard errno == ENOENT else { throw VPNActivationBudgetError.unsafeStorage }
            return Record(schema: 1, desired: true, failures: 0)
        }
        defer { close(file) }
        try check(file)
        var data = Data(), bytes = [UInt8](repeating: 0, count: 256)
        while true {
            let count = Darwin.read(file, &bytes, bytes.count)
            if count < 0, errno == EINTR { continue }
            guard count >= 0 else { throw VPNActivationBudgetError.invalidState }
            if count == 0 { break }
            guard data.count + count <= Self.maximumBytes else { throw VPNActivationBudgetError.invalidState }
            data.append(contentsOf: bytes.prefix(count))
        }
        guard let record = try? JSONDecoder().decode(Record.self, from: data), record.schema == 1,
              record.failures >= 0, record.failures <= Self.maximumConsecutiveFailures,
              (try? encode(record)) == data else { throw VPNActivationBudgetError.invalidState }
        return record
    }

    private func write(_ record: Record) throws {
        let data = try encode(Record(schema: 1, desired: record.desired,
                                     failures: min(record.failures, Self.maximumConsecutiveFailures)))
        let temporary = ".activation-\(UUID().uuidString).tmp"
        let file = openat(directory, temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard file >= 0 else { throw VPNActivationBudgetError.writeFailed }
        defer { close(file); unlinkat(directory, temporary, 0) }
        try check(file)
        try data.withUnsafeBytes { bytes in
            var offset = 0
            while offset < bytes.count {
                let count = Darwin.write(file, bytes.baseAddress!.advanced(by: offset), bytes.count - offset)
                if count < 0, errno == EINTR { continue }
                guard count > 0 else { throw VPNActivationBudgetError.writeFailed }
                offset += count
            }
        }
        guard fsync(file) == 0, renameat(directory, temporary, directory, Self.name) == 0,
              fsync(directory) == 0 else { throw VPNActivationBudgetError.writeFailed }
    }

    private func encode(_ record: Record) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        guard let data = try? encoder.encode(record), data.count <= Self.maximumBytes else {
            throw VPNActivationBudgetError.invalidState
        }
        return data
    }

    private func checkDirectory() throws {
        var attributes = stat()
        guard geteuid() == owner, fstat(directory, &attributes) == 0,
              attributes.st_mode & S_IFMT == S_IFDIR, attributes.st_nlink > 0,
              attributes.st_uid == owner, attributes.st_mode & 0o7777 == 0o700 else {
            throw VPNActivationBudgetError.unsafeStorage
        }
    }

    private func check(_ file: Int32) throws {
        var attributes = stat()
        guard fstat(file, &attributes) == 0, attributes.st_mode & S_IFMT == S_IFREG,
              attributes.st_nlink == 1, attributes.st_uid == owner,
              attributes.st_mode & 0o7777 == 0o600 else { throw VPNActivationBudgetError.unsafeStorage }
    }
}
