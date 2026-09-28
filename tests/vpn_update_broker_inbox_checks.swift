import Darwin
import Foundation

enum InboxOutcome: Equatable {
    case published, alreadyPublished
}

enum InboxContractError: Error, Equatable {
    case invalidLayout, symlink, hardlink, special, unexpectedSibling, missingEntry
    case limitExceeded, sourceChanged, rejectedConflict, publishedChanged
}

struct InboxReceipt: Equatable {
    /// Opaque digest-like identity derived by the broker from signed candidate
    /// bytes. It is never a caller-supplied destination or filesystem path.
    let identity: Data
    let outcome: InboxOutcome
    let syncedNames: Set<String>
    let parentSynced: Bool
}

struct InboxPublishedMetadata: Equatable {
    let containerMode: mode_t
    let allNodesOwnedByEffectiveUser: Bool
    let anyGroupOrWorldWritableNode: Bool
}

/// Test adapter for a descriptor-relative production copier. No caller-selected
/// path or destination name exists on this surface.
protocol VPNUpdateBrokerInboxDriving {
    static var maximumEntries: Int { get }
    static var maximumBytes: Int64 { get }
    static var maximumDepth: Int { get }
    init(trustedParent: Int32) throws
    func ingest(sourceDirectory: Int32,
                checkpoint: (String) throws -> Void) throws -> InboxReceipt
    func publishedSnapshot(_ receipt: InboxReceipt) throws -> [String: Data]
    func publishedMetadata(_ receipt: InboxReceipt) throws -> InboxPublishedMetadata
    func publishedCount() throws -> Int
    func corruptPublished(_ receipt: InboxReceipt) throws
}

/// Resolved only in the inbox contract-test build.
typealias InboxDriver = VPNUpdateBrokerInboxContractHarness

@main enum VPNUpdateBrokerInboxChecks {
    enum InjectedCrash: Error { case stop }
    static let exactLayout: Set<String> = [
        "ProxyPilot.app", "vpn-helper", "vpn-engine",
        "vpn-release.manifest", "vpn-release.sig",
        "vpn-previous-release.manifest", "vpn-previous-release.sig",
        "vpn-update-transition", "vpn-update-transition.sig",
    ]

    static func require(_ value: @autoclosure () -> Bool) throws {
        guard value() else { throw NSError(domain: "inbox-contract", code: 1) }
    }

    static func write(_ data: Data, to directory: URL, name: String) throws {
        let target = directory.appendingPathComponent(name)
        guard FileManager.default.createFile(atPath: target.path,
                                              contents: data,
                                              attributes: [.posixPermissions: 0o600]) else {
            throw NSError(domain: "inbox-contract", code: 2)
        }
    }

    static func candidate(_ root: URL, marker: String = "B42") throws -> URL {
        let source = root.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(
            at: source, withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700])
        let app = source.appendingPathComponent("ProxyPilot.app")
        try FileManager.default.createDirectory(
            at: app, withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700])
        try write(Data("sealed-app-\(marker)".utf8), to: app, name: "fixture")
        for name in exactLayout.subtracting(["ProxyPilot.app"]) {
            try write(Data("\(name):\(marker)".utf8), to: source, name: name)
        }
        return source
    }

    static func openDirectory(_ url: URL) throws -> Int32 {
        let descriptor = open(url.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else { throw NSError(domain: "inbox-contract", code: 3) }
        return descriptor
    }

    static func withFixture(_ body: (URL, URL, Int32, Int32) throws -> Void) throws {
        let root = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent("pp-inbox-\(UUID().uuidString)")
        let trusted = root.appendingPathComponent("trusted")
        try FileManager.default.createDirectory(
            at: trusted, withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700])
        let source = try candidate(root)
        let trustedFD = try openDirectory(trusted)
        let sourceFD = try openDirectory(source)
        defer {
            close(sourceFD); close(trustedFD)
            try? FileManager.default.removeItem(at: root)
        }
        try body(source, trusted, sourceFD, trustedFD)
    }

    static func expectRejected(_ expected: InboxContractError,
                               source: URL, trustedFD: Int32) throws {
        let sourceFD = try openDirectory(source)
        defer { close(sourceFD) }
        let broker = try InboxDriver(trustedParent: trustedFD)
        let before = try broker.publishedCount()
        do {
            _ = try broker.ingest(sourceDirectory: sourceFD, checkpoint: { _ in })
            throw NSError(domain: "inbox-contract", code: 4)
        } catch let error as InboxContractError {
            try require(error == expected)
        }
        let after = try broker.publishedCount()
        try require(after == before)
    }

    static func layout() throws {
        try withFixture { source, _, sourceFD, trustedFD in
            let broker = try InboxDriver(trustedParent: trustedFD)
            let receipt = try broker.ingest(sourceDirectory: sourceFD, checkpoint: { _ in })
            try require(receipt.outcome == .published)
            let snapshot = try broker.publishedSnapshot(receipt)
            try require(Set(snapshot.keys) == exactLayout)
            let metadata = try broker.publishedMetadata(receipt)
            try require(metadata.containerMode & 0o7777 == 0o700)
            try require(metadata.allNodesOwnedByEffectiveUser)
            try require(!metadata.anyGroupOrWorldWritableNode)

            let root = source.deletingLastPathComponent()
            let extra = try candidate(root, marker: "extra")
            try write(Data("unexpected".utf8), to: extra, name: "unexpected")
            try expectRejected(.unexpectedSibling, source: extra, trustedFD: trustedFD)

            let missing = try candidate(root, marker: "missing")
            try FileManager.default.removeItem(at: missing.appendingPathComponent("vpn-engine"))
            try expectRejected(.missingEntry, source: missing, trustedFD: trustedFD)

            let linked = try candidate(root, marker: "symlink")
            try FileManager.default.removeItem(at: linked.appendingPathComponent("vpn-helper"))
            try FileManager.default.createSymbolicLink(
                at: linked.appendingPathComponent("vpn-helper"),
                withDestinationURL: linked.appendingPathComponent("vpn-release.sig"))
            try expectRejected(.symlink, source: linked, trustedFD: trustedFD)

            let hard = try candidate(root, marker: "hardlink")
            try FileManager.default.removeItem(at: hard.appendingPathComponent("vpn-helper"))
            guard link(hard.appendingPathComponent("vpn-release.sig").path,
                       hard.appendingPathComponent("vpn-helper").path) == 0 else {
                throw NSError(domain: "inbox-contract", code: 5)
            }
            try expectRejected(.hardlink, source: hard, trustedFD: trustedFD)

            let special = try candidate(root, marker: "special")
            try FileManager.default.removeItem(at: special.appendingPathComponent("vpn-helper"))
            guard mkfifo(special.appendingPathComponent("vpn-helper").path, 0o600) == 0 else {
                throw NSError(domain: "inbox-contract", code: 6)
            }
            try expectRejected(.special, source: special, trustedFD: trustedFD)
        }
    }

    static func bounds() throws {
        try withFixture { source, _, _, trustedFD in
            let root = source.deletingLastPathComponent()
            let tooLarge = try candidate(root, marker: "large")
            let file = open(tooLarge.appendingPathComponent("vpn-engine").path, O_WRONLY)
            guard file >= 0 else { throw NSError(domain: "inbox-contract", code: 7) }
            let resized = ftruncate(file, InboxDriver.maximumBytes + 1)
            close(file)
            guard resized == 0 else { throw NSError(domain: "inbox-contract", code: 8) }
            try expectRejected(.limitExceeded, source: tooLarge, trustedFD: trustedFD)

            let tooDeep = try candidate(root, marker: "deep")
            var cursor = tooDeep.appendingPathComponent("ProxyPilot.app")
            for index in 0...InboxDriver.maximumDepth {
                cursor.appendPathComponent("d\(index)")
                try FileManager.default.createDirectory(at: cursor,
                    withIntermediateDirectories: false,
                    attributes: [.posixPermissions: 0o700])
            }
            try expectRejected(.limitExceeded, source: tooDeep, trustedFD: trustedFD)

            try require(InboxDriver.maximumEntries >= exactLayout.count)
            try require(InboxDriver.maximumEntries <= 10_000)
            let tooMany = try candidate(root, marker: "entries")
            let app = tooMany.appendingPathComponent("ProxyPilot.app")
            for index in 0...InboxDriver.maximumEntries {
                try write(Data([UInt8(truncatingIfNeeded: index)]),
                          to: app, name: "entry-\(index)")
            }
            try expectRejected(.limitExceeded, source: tooMany, trustedFD: trustedFD)
        }
    }

    static func mutable() throws {
        try withFixture { source, _, sourceFD, trustedFD in
            let broker = try InboxDriver(trustedParent: trustedFD)
            do {
                _ = try broker.ingest(sourceDirectory: sourceFD) { point in
                    if point == "afterCopy:vpn-helper" {
                        try Data("changed-source".utf8).write(
                            to: source.appendingPathComponent("vpn-release.manifest"))
                    }
                }
                throw NSError(domain: "inbox-contract", code: 9)
            } catch let error as InboxContractError {
                try require(error == .sourceChanged)
            }
            let count = try broker.publishedCount()
            try require(count == 0)
        }

        try withFixture { source, _, sourceFD, trustedFD in
            let broker = try InboxDriver(trustedParent: trustedFD)
            let receipt = try broker.ingest(sourceDirectory: sourceFD, checkpoint: { _ in })
            let before = try broker.publishedSnapshot(receipt)
            try Data("mutateSource".utf8).write(
                to: source.appendingPathComponent("vpn-helper"))
            let after = try broker.publishedSnapshot(receipt)
            try require(after == before)
        }
    }

    static func durability() throws {
        for point in ["afterCopy:vpn-helper", "beforePublish", "afterPublish"] {
            try withFixture { _, _, sourceFD, trustedFD in
                var broker = try InboxDriver(trustedParent: trustedFD)
                do {
                    _ = try broker.ingest(sourceDirectory: sourceFD) { current in
                        if current == point { throw InjectedCrash.stop }
                    }
                    throw NSError(domain: "inbox-contract", code: 10)
                } catch InjectedCrash.stop { }
                // A fresh process view must resume safely or recognize the
                // already durable publication; it must never overwrite it.
                broker = try InboxDriver(trustedParent: trustedFD)
                let receipt = try broker.ingest(sourceDirectory: sourceFD, checkpoint: { _ in })
                try require([.published, .alreadyPublished].contains(receipt.outcome))
                try require(receipt.syncedNames == exactLayout)
                try require(receipt.parentSynced)
                let count = try broker.publishedCount()
                try require(count == 1)
            }
        }
    }

    static func retry() throws {
        try withFixture { source, _, sourceFD, trustedFD in
            let broker = try InboxDriver(trustedParent: trustedFD)
            let same = try broker.ingest(sourceDirectory: sourceFD, checkpoint: { _ in })
            let repeated = try broker.ingest(sourceDirectory: sourceFD, checkpoint: { _ in })
            try require(repeated.outcome == .alreadyPublished)
            try require(same.identity == repeated.identity)

            let conflicting = try candidate(source.deletingLastPathComponent(), marker: "B43")
            let conflictingFD = try openDirectory(conflicting)
            defer { close(conflictingFD) }
            do {
                _ = try broker.ingest(sourceDirectory: conflictingFD, checkpoint: { _ in })
                throw NSError(domain: "inbox-contract", code: 11)
            } catch let error as InboxContractError {
                try require(error == .rejectedConflict)
            }

            let before = try broker.publishedSnapshot(same)
            try broker.corruptPublished(same)
            do {
                _ = try broker.ingest(sourceDirectory: sourceFD, checkpoint: { _ in })
                throw NSError(domain: "inbox-contract", code: 12)
            } catch let error as InboxContractError {
                try require(error == .publishedChanged)
            }
            let after = try broker.publishedSnapshot(same)
            try require(after != before)
        }
    }

    static func main() throws {
        guard CommandLine.arguments.count == 2 else { exit(64) }
        let group = CommandLine.arguments[1]
        switch group {
        case "layout": try layout()
        case "bounds": try bounds()
        case "mutable": try mutable()
        case "durability": try durability()
        case "retry": try retry()
        default: exit(64)
        }
        print("\(group) checks passed")
    }
}
