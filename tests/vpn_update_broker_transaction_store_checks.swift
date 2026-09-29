import Darwin
import Foundation

private enum Injected: Error { case crash }

@main enum VPNUpdateBrokerTransactionStoreChecks {
    static let identity = Data((0..<32).map(UInt8.init))
    static let otherIdentity = Data(repeating: 0xa5, count: 32)
    static let transactionID = UUID(uuidString: "00112233-4455-6677-8899-aabbccddeeff")!

    static func require(_ value: @autoclosure () -> Bool) throws {
        guard value() else { throw NSError(domain: "broker-transaction", code: 1) }
    }

    static func rejects(_ expected: VPNUpdateBrokerTransactionStoreError,
                        _ body: () throws -> Void) throws {
        do {
            try body()
            throw NSError(domain: "broker-transaction", code: 2)
        } catch let error as VPNUpdateBrokerTransactionStoreError {
            try require(error == expected)
        }
    }

    static func directory(_ path: String) throws -> Int32 {
        try FileManager.default.createDirectory(atPath: path,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700])
        let fd = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw Injected.crash }
        return fd
    }

    static func journal(_ revision: UInt64,
                        _ phase: VPNUpdateBrokerJournalPhase = .prepared)
        -> VPNUpdateBrokerJournalReference {
        .init(transactionID: transactionID, revision: revision, phase: phase)
    }

    static func roundTrip(_ path: String) throws {
        let fd = try directory(path); defer { close(fd) }
        let store = try VPNUpdateBrokerTransactionStore(trustedDirectoryDescriptor: fd)
        let absent = try store.load()
        try require(absent == nil)
        // Simulate scratch bytes left by a process killed before rename.
        let stale = openat(fd, ".update-broker-transaction.tmp",
                           O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0o600)
        guard stale >= 0 else { throw Injected.crash }
        var staleByte: UInt8 = 7
        guard Darwin.write(stale, &staleByte, 1) == 1 else { throw Injected.crash }
        close(stale)
        let accepted = try store.begin(identity: identity, fromSequence: 41,
                                       toSequence: 42)
        try require(accepted.phase == .accepted && accepted.revision == 1)
        try require(accepted.recovery == .inboxRetained && accepted.journal == nil)
        let duplicate = try store.begin(identity: identity, fromSequence: 41,
                                        toSequence: 42)
        try require(duplicate == accepted)
        try rejects(.busy) {
            _ = try store.begin(identity: otherIdentity, fromSequence: 41,
                                toSequence: 43)
        }
        try rejects(.invalidState) {
            _ = try store.begin(identity: identity, fromSequence: 40,
                                toSequence: 42)
        }
        let authorized = try store.advance(identity: identity, expectedRevision: 1,
            phase: .authorized, journal: nil, recovery: .inboxRetained,
            rotation: .notStarted)
        let prepared = try store.advance(identity: identity, expectedRevision: 2,
            phase: .prepared, journal: journal(0), recovery: .journalRetained,
            rotation: .notStarted)
        try require(authorized.revision == 2 && prepared.revision == 3)
        let repeated = try store.advance(identity: identity, expectedRevision: 2,
            phase: .prepared, journal: journal(0), recovery: .journalRetained,
            rotation: .notStarted)
        try require(repeated == prepared)
        try rejects(.staleRevision) {
            _ = try store.advance(identity: identity, expectedRevision: 2,
                phase: .handoffStarted, journal: journal(1, .replacementPending),
                recovery: .journalRetained, rotation: .notStarted)
        }
        try rejects(.invalidState) {
            _ = try store.advance(identity: identity, expectedRevision: 3,
                phase: .handoffStarted, journal: nil,
                recovery: .journalRetained, rotation: .notStarted)
        }
        let started = try store.advance(identity: identity, expectedRevision: 3,
            phase: .handoffStarted, journal: journal(1, .replacementPending),
            recovery: .journalRetained, rotation: .notStarted)
        let handed = try store.advance(identity: identity, expectedRevision: 4,
            phase: .handoffComplete, journal: journal(2, .selected),
            recovery: .executorCommitted, rotation: .pending)
        let rotating = try store.advance(identity: identity, expectedRevision: 5,
            phase: .rotatingBroker, journal: journal(2, .selected),
            recovery: .executorCommitted, rotation: .pending)
        let complete = try store.advance(identity: identity, expectedRevision: 6,
            phase: .complete, journal: journal(3, .completed),
            recovery: .complete, rotation: .complete)
        try require(started.revision == 4 && handed.revision == 5)
        try require(rotating.revision == 6 && complete.revision == 7)
        let loaded = try store.load()
        try require(loaded == complete)
        try rejects(.invalidState) {
            _ = try store.advance(identity: identity, expectedRevision: 7,
                phase: .failed, journal: journal(3, .completed),
                recovery: .failed, rotation: .complete)
        }
    }

    static func crash(_ path: String, checkpoint: String) throws {
        let fd = try directory(path); defer { close(fd) }
        let store = try VPNUpdateBrokerTransactionStore(trustedDirectoryDescriptor: fd)
        VPNUpdateBrokerTransactionStore.checkpoint = { point in
            if point == checkpoint { throw Injected.crash }
        }
        if checkpoint == "before-rename" {
            do {
                _ = try store.begin(identity: identity, fromSequence: 8,
                                    toSequence: 9)
                throw NSError(domain: "broker-transaction", code: 3)
            } catch Injected.crash { }
            VPNUpdateBrokerTransactionStore.checkpoint = nil
            let absent = try store.load()
            try require(absent == nil)
        } else {
            try rejects(.commitUncertain) {
                _ = try store.begin(identity: identity, fromSequence: 8,
                                    toSequence: 9)
            }
            VPNUpdateBrokerTransactionStore.checkpoint = nil
        }
        let accepted = try store.begin(identity: identity, fromSequence: 8,
                                       toSequence: 9)
        try require(accepted.revision == 1)
        VPNUpdateBrokerTransactionStore.checkpoint = { point in
            if point == checkpoint { throw Injected.crash }
        }
        if checkpoint == "before-rename" {
            do {
                _ = try store.advance(identity: identity, expectedRevision: 1,
                    phase: .authorized, journal: nil, recovery: .inboxRetained,
                    rotation: .notStarted)
                throw NSError(domain: "broker-transaction", code: 4)
            } catch Injected.crash { }
        } else {
            try rejects(.commitUncertain) {
                _ = try store.advance(identity: identity, expectedRevision: 1,
                    phase: .authorized, journal: nil, recovery: .inboxRetained,
                    rotation: .notStarted)
            }
        }
        VPNUpdateBrokerTransactionStore.checkpoint = nil
        let recovered = try store.advance(identity: identity, expectedRevision: 1,
            phase: .authorized, journal: nil, recovery: .inboxRetained,
            rotation: .notStarted)
        try require(recovered.revision == 2)
    }

    static func hostile(_ path: String, kind: String) throws {
        let fd = try directory(path); defer { close(fd) }
        let store = try VPNUpdateBrokerTransactionStore(trustedDirectoryDescriptor: fd)
        _ = try store.begin(identity: identity, fromSequence: 1, toSequence: 2)
        let name = VPNUpdateBrokerTransactionStore.fileName
        switch kind {
        case "corrupt", "reserved":
            let file = openat(fd, name, O_RDWR | O_NOFOLLOW | O_CLOEXEC)
            guard file >= 0 else { throw Injected.crash }
            var byte: UInt8 = kind == "corrupt" ? 0xff : 1
            let offset: off_t = kind == "corrupt" ? 24 : 110
            guard pwrite(file, &byte, 1, offset) == 1 else { throw Injected.crash }
            close(file)
        case "extra":
            let file = openat(fd, name, O_WRONLY | O_APPEND | O_NOFOLLOW | O_CLOEXEC)
            guard file >= 0 else { throw Injected.crash }
            var byte: UInt8 = 0
            guard Darwin.write(file, &byte, 1) == 1 else { throw Injected.crash }
            close(file)
        case "writable":
            guard fchmodat(fd, name, 0o660, 0) == 0 else { throw Injected.crash }
        case "linked":
            guard linkat(fd, name, fd, "transaction-hardlink", 0) == 0 else {
                throw Injected.crash
            }
        case "symlink":
            guard unlinkat(fd, name, 0) == 0,
                  symlinkat("transaction-hardlink", fd, name) == 0 else {
                throw Injected.crash
            }
        default: throw Injected.crash
        }
        let expected: VPNUpdateBrokerTransactionStoreError =
            ["corrupt", "reserved", "extra"].contains(kind) ? .invalidState : .unsafeStorage
        try rejects(expected) { _ = try store.load() }
    }

    static func unsafeDirectory(_ path: String) throws {
        let fd = try directory(path); defer { close(fd) }
        guard fchmod(fd, 0o755) == 0 else { throw Injected.crash }
        try rejects(.unsafeStorage) {
            _ = try VPNUpdateBrokerTransactionStore(trustedDirectoryDescriptor: fd)
        }
    }

    static func main() throws {
        guard CommandLine.arguments.count == 3 else { exit(64) }
        let test = CommandLine.arguments[1], path = CommandLine.arguments[2]
        switch test {
        case "roundtrip": try roundTrip(path)
        case "before-rename", "after-rename": try crash(path, checkpoint: test)
        case "corrupt", "reserved", "extra", "writable", "linked", "symlink":
            try hostile(path, kind: test)
        case "unsafe-directory": try unsafeDirectory(path)
        default: exit(64)
        }
        print("\(test) checks passed")
    }
}
