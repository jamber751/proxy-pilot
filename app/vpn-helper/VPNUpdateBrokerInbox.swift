import CryptoKit
import Darwin
import Foundation

enum VPNUpdateBrokerInboxError: Error {
    case unsafeStorage, invalidLayout, symlink, hardlink, special
    case unexpectedSibling, missingEntry, limitExceeded, sourceChanged
    case rejectedConflict, publishedChanged, commitUncertain
}

enum VPNUpdateBrokerInboxOutcome { case published, alreadyPublished }

struct VPNUpdateBrokerInboxReceipt {
    let identity: Data
    let outcome: VPNUpdateBrokerInboxOutcome
    let syncedNames: Set<String>
    let parentSynced: Bool
}

/// Copies one exact broker candidate into a content-derived private inbox.
/// Both roots arrive as descriptors. Names below them are fixed or are derived
/// from a SHA-256 snapshot; no caller path or destination crosses this boundary.
final class VPNUpdateBrokerInbox {
    static let maximumEntries = 10_000
    static let maximumBytes: Int64 = 512 * 1024 * 1024
    static let maximumDepth = 48
    static let fixedLayout: Set<String> = [
        "ProxyPilot.app", "vpn-helper", "vpn-engine",
        "vpn-release.manifest", "vpn-release.sig",
        "vpn-previous-release.manifest", "vpn-previous-release.sig",
        "vpn-update-transition", "vpn-update-transition.sig",
    ]
    private static let cloneResolveBeneath: UInt32 = 0x0010
    private let parent: Int32

    private enum NodeKind: UInt8 { case directory = 0x44, file = 0x46, link = 0x4c }
    private struct Node: Equatable {
        let kind: NodeKind
        let mode: mode_t
        let size: Int64
        let digest: Data
        let target: String?
    }
    private struct Snapshot: Equatable {
        let nodes: [String: Node]
        let identity: Data
        let top: [String: Data]
    }

    init(trustedParent: Int32) throws {
        parent = fcntl(trustedParent, F_DUPFD_CLOEXEC, 0)
        guard parent >= 0 else { throw VPNUpdateBrokerInboxError.unsafeStorage }
        do { try Self.checkPrivateDirectory(parent) }
        catch { close(parent); throw error }
    }

    deinit { close(parent) }

    func ingest(sourceDirectory: Int32,
                checkpoint: (String) throws -> Void) throws
        -> VPNUpdateBrokerInboxReceipt {
        try Self.checkPrivateDirectory(parent)
        try Self.checkSourceDirectory(sourceDirectory)
        let source = try Self.snapshot(sourceDirectory, requireFixedLayout: true)
        let suffix = source.identity.map { String(format: "%02x", $0) }.joined()
        let publishedName = "inbox-\(suffix)"
        let pendingName = ".\(publishedName).preparing"

        let publishedCount = try countPublished()
        if let published = try Self.openDirectory(parent, publishedName) {
            defer { close(published) }
            let actual = try Self.snapshot(published, requireFixedLayout: true)
            guard actual == source else {
                throw VPNUpdateBrokerInboxError.publishedChanged
            }
            return VPNUpdateBrokerInboxReceipt(
                identity: source.identity, outcome: .alreadyPublished,
                syncedNames: Self.fixedLayout, parentSynced: true)
        }
        guard publishedCount == 0 else {
            throw VPNUpdateBrokerInboxError.rejectedConflict
        }
        let otherPending = try Self.topNames(parent).contains { name in
            name.hasPrefix(".inbox-") && name.hasSuffix(".preparing")
                && name != pendingName
        }
        guard !otherPending else { throw VPNUpdateBrokerInboxError.rejectedConflict }

        let pending: Int32
        if let existing = try Self.openDirectory(parent, pendingName) {
            pending = existing
        } else {
            guard mkdirat(parent, pendingName, 0o700) == 0,
                  fsync(parent) == 0,
                  let created = try Self.openDirectory(parent, pendingName) else {
                throw VPNUpdateBrokerInboxError.unsafeStorage
            }
            pending = created
        }
        defer { close(pending) }

        let existing = try Self.topNames(pending)
        guard existing.isSubset(of: Self.fixedLayout) else {
            throw VPNUpdateBrokerInboxError.invalidLayout
        }
        if !existing.isEmpty {
            let partial = try Self.snapshot(pending, requireFixedLayout: false)
            for name in existing {
                guard partial.top[name] == source.top[name] else {
                    throw VPNUpdateBrokerInboxError.invalidLayout
                }
            }
        }

        for name in Self.fixedLayout.sorted() where !existing.contains(name) {
            guard Self.cloneDirectChild(sourceDirectory, name, pending, name) == 0 else {
                throw VPNUpdateBrokerInboxError.unsafeStorage
            }
            try checkpoint("afterCopy:\(name)")
        }
        let after = try Self.snapshot(sourceDirectory, requireFixedLayout: true)
        guard after == source else { throw VPNUpdateBrokerInboxError.sourceChanged }
        let copied = try Self.snapshot(pending, requireFixedLayout: true)
        guard copied == source else { throw VPNUpdateBrokerInboxError.invalidLayout }
        try Self.synchronizeTree(pending)
        try checkpoint("beforePublish")
        guard renameat(parent, pendingName, parent, publishedName) == 0 else {
            throw VPNUpdateBrokerInboxError.commitUncertain
        }
        guard fsync(parent) == 0 else {
            throw VPNUpdateBrokerInboxError.commitUncertain
        }
        try checkpoint("afterPublish")
        guard let final = try Self.openDirectory(parent, publishedName) else {
            throw VPNUpdateBrokerInboxError.commitUncertain
        }
        defer { close(final) }
        guard try Self.snapshot(final, requireFixedLayout: true) == source else {
            throw VPNUpdateBrokerInboxError.commitUncertain
        }
        return VPNUpdateBrokerInboxReceipt(
            identity: source.identity, outcome: .published,
            syncedNames: Self.fixedLayout, parentSynced: true)
    }

    func publishedCount() throws -> Int { try countPublished() }

    func publishedSnapshot(identity: Data) throws -> [String: Data] {
        let directory = try published(identity)
        defer { close(directory) }
        return try Self.snapshot(directory, requireFixedLayout: true).top
    }

    func publishedMetadata(identity: Data) throws
        -> (mode: mode_t, owned: Bool, writable: Bool) {
        let directory = try published(identity)
        defer { close(directory) }
        var root = stat()
        guard fstat(directory, &root) == 0 else {
            throw VPNUpdateBrokerInboxError.publishedChanged
        }
        let facts = try Self.metadata(directory)
        return (root.st_mode, facts.owned, facts.writable)
    }

    /// Opens the exact immutable publication identified by a receipt returned
    /// from `ingest`. The caller owns the descriptor. No pathname from IPC is
    /// accepted or reconstructed outside this private directory.
    func openPublished(identity: Data) throws -> Int32 {
        guard identity.count == 32 else {
            throw VPNUpdateBrokerInboxError.publishedChanged
        }
        let directory = try published(identity)
        do {
            let actual = try Self.snapshot(directory, requireFixedLayout: true)
            guard actual.identity == identity else {
                throw VPNUpdateBrokerInboxError.publishedChanged
            }
            return directory
        } catch {
            close(directory)
            throw error
        }
    }

    /// Removes only the exact content-addressed tree after it has been fully
    /// re-snapshotted. The broker transaction lease must serialize this with
    /// ingest and recovery; every child is still rebound by inode before unlink.
    func retirePublished(identity: Data) throws {
        guard identity.count == 32 else {
            throw VPNUpdateBrokerInboxError.publishedChanged
        }
        let suffix = identity.map { String(format: "%02x", $0) }.joined()
        let name = "inbox-\(suffix)"
        guard let directory = try Self.openDirectory(parent, name) else { return }
        var root = stat()
        do {
            guard fstat(directory, &root) == 0,
                  try Self.snapshot(directory, requireFixedLayout: true).identity
                    == identity else {
                throw VPNUpdateBrokerInboxError.publishedChanged
            }
            var budget = Self.maximumEntries
            try Self.removeChildren(directory, depth: 0, budget: &budget)
            guard fsync(directory) == 0 else {
                throw VPNUpdateBrokerInboxError.commitUncertain
            }
        } catch {
            close(directory)
            throw error
        }
        close(directory)
        var named = stat()
        guard fstatat(parent, name, &named, AT_SYMLINK_NOFOLLOW) == 0,
              named.st_dev == root.st_dev, named.st_ino == root.st_ino,
              unlinkat(parent, name, AT_REMOVEDIR) == 0,
              fsync(parent) == 0 else {
            throw VPNUpdateBrokerInboxError.commitUncertain
        }
    }

    /// Read-only uninstall preflight for complete and crash-left partial inbox
    /// trees. It accepts no arbitrary top-level directory name and applies the
    /// same bounds, ownership, link and writable-node checks as ingestion.
    func validateForUninstall() throws {
        for name in try Self.topNames(parent) where Self.isInboxTreeName(name) {
            guard let directory = try Self.openDirectory(parent, name) else {
                throw VPNUpdateBrokerInboxError.publishedChanged
            }
            defer { close(directory) }
            let complete = name.hasPrefix("inbox-")
            let value = try Self.snapshot(
                directory, requireFixedLayout: complete)
            if !complete, !Set(value.top.keys).isSubset(of: Self.fixedLayout) {
                throw VPNUpdateBrokerInboxError.invalidLayout
            }
        }
    }

    /// Bounded removal used only after broker launchd ownership has been
    /// removed during an authorized uninstall. Unknown sibling names are not
    /// touched; the state remover rejects them during its earlier preflight.
    func removeAllForUninstall() throws {
        try validateForUninstall()
        for name in try Self.topNames(parent).filter(Self.isInboxTreeName) {
            try removeInboxTree(name)
        }
    }

    #if VPN_UPDATE_BROKER_INBOX_TESTING
    func corruptPublished(identity: Data) throws {
        let directory = try published(identity)
        defer { close(directory) }
        let file = openat(directory, "vpn-helper", O_WRONLY | O_TRUNC | O_NOFOLLOW | O_CLOEXEC)
        guard file >= 0 else { throw VPNUpdateBrokerInboxError.publishedChanged }
        defer { close(file) }
        let bytes = Array("corrupt".utf8)
        guard Darwin.write(file, bytes, bytes.count) == bytes.count,
              fsync(file) == 0 else {
            throw VPNUpdateBrokerInboxError.publishedChanged
        }
    }
    #endif

    private func published(_ identity: Data) throws -> Int32 {
        guard identity.count == 32 else {
            throw VPNUpdateBrokerInboxError.publishedChanged
        }
        let suffix = identity.map { String(format: "%02x", $0) }.joined()
        guard let directory = try Self.openDirectory(parent, "inbox-\(suffix)") else {
            throw VPNUpdateBrokerInboxError.publishedChanged
        }
        return directory
    }

    private func countPublished() throws -> Int {
        try Self.topNames(parent).filter { name in
            name.hasPrefix("inbox-") && name.count == 70
                && name.dropFirst(6).allSatisfy { $0.isHexDigit && !$0.isUppercase }
        }.count
    }

    private static func isInboxTreeName(_ name: String) -> Bool {
        if name.hasPrefix("inbox-"), name.count == 70 {
            return name.dropFirst(6).allSatisfy {
                $0.isHexDigit && !$0.isUppercase
            }
        }
        guard name.hasPrefix(".inbox-"), name.hasSuffix(".preparing") else {
            return false
        }
        let digest = name.dropFirst(7).dropLast(10)
        return digest.count == 64 && digest.allSatisfy {
            $0.isHexDigit && !$0.isUppercase
        }
    }

    private func removeInboxTree(_ name: String) throws {
        guard Self.isInboxTreeName(name),
              let directory = try Self.openDirectory(parent, name) else {
            throw VPNUpdateBrokerInboxError.publishedChanged
        }
        var root = stat()
        do {
            guard fstat(directory, &root) == 0 else {
                throw VPNUpdateBrokerInboxError.publishedChanged
            }
            var budget = Self.maximumEntries
            try Self.removeChildren(directory, depth: 0, budget: &budget)
            guard fsync(directory) == 0 else {
                throw VPNUpdateBrokerInboxError.commitUncertain
            }
        } catch {
            close(directory)
            throw error
        }
        close(directory)
        var rebound = stat()
        guard fstatat(parent, name, &rebound, AT_SYMLINK_NOFOLLOW) == 0,
              rebound.st_dev == root.st_dev, rebound.st_ino == root.st_ino,
              unlinkat(parent, name, AT_REMOVEDIR) == 0,
              fsync(parent) == 0 else {
            throw VPNUpdateBrokerInboxError.commitUncertain
        }
    }

    private static func snapshot(_ root: Int32, requireFixedLayout: Bool) throws -> Snapshot {
        var nodes: [String: Node] = [:], bytes: Int64 = 0
        try walk(root, prefix: "", depth: 0, nodes: &nodes, bytes: &bytes)
        try validateLinks(nodes)
        let topNames = Set(nodes.keys.compactMap { $0.split(separator: "/").first.map(String.init) })
        if requireFixedLayout {
            if !topNames.isSubset(of: Self.fixedLayout) {
                throw VPNUpdateBrokerInboxError.unexpectedSibling
            }
            if topNames != Self.fixedLayout {
                throw VPNUpdateBrokerInboxError.missingEntry
            }
        }
        let identity = digest(nodes.filter { !$0.key.isEmpty })
        var top: [String: Data] = [:]
        for name in topNames {
            top[name] = digest(nodes.filter {
                $0.key == name || $0.key.hasPrefix(name + "/")
            })
        }
        return Snapshot(nodes: nodes, identity: identity, top: top)
    }

    private static func walk(_ directory: Int32, prefix: String, depth: Int,
                             nodes: inout [String: Node], bytes: inout Int64) throws {
        guard depth <= maximumDepth else { throw VPNUpdateBrokerInboxError.limitExceeded }
        for name in try names(directory) {
            let path = prefix.isEmpty ? name : prefix + "/" + name
            var info = stat()
            guard fstatat(directory, name, &info, AT_SYMLINK_NOFOLLOW) == 0 else {
                throw VPNUpdateBrokerInboxError.sourceChanged
            }
            let type = info.st_mode & S_IFMT
            if type != S_IFDIR && type != S_IFREG && type != S_IFLNK {
                throw VPNUpdateBrokerInboxError.special
            }
            if type != S_IFDIR && info.st_nlink != 1 {
                throw VPNUpdateBrokerInboxError.hardlink
            }
            guard type == S_IFLNK || info.st_mode & 0o0022 == 0 else {
                throw VPNUpdateBrokerInboxError.invalidLayout
            }
            guard nodes.count < maximumEntries else {
                throw VPNUpdateBrokerInboxError.limitExceeded
            }
            if type == S_IFDIR {
                guard let child = try openDirectory(directory, name, privateMode: false) else {
                    throw VPNUpdateBrokerInboxError.sourceChanged
                }
                nodes[path] = Node(kind: .directory, mode: info.st_mode & 0o7777,
                                   size: 0, digest: Data(), target: nil)
                try walk(child, prefix: path, depth: depth + 1,
                         nodes: &nodes, bytes: &bytes)
                close(child)
            } else if type == S_IFREG {
                guard info.st_size >= 0, info.st_size <= maximumBytes - bytes else {
                    throw VPNUpdateBrokerInboxError.limitExceeded
                }
                let data = try readFile(directory, name, expected: info)
                bytes += Int64(data.count)
                nodes[path] = Node(kind: .file, mode: info.st_mode & 0o7777,
                    size: Int64(data.count), digest: Data(SHA256.hash(data: data)),
                    target: nil)
            } else {
                guard path.hasPrefix("ProxyPilot.app/") else {
                    throw VPNUpdateBrokerInboxError.symlink
                }
                let target = try readLink(directory, name)
                guard Int64(target.utf8.count) <= maximumBytes - bytes else {
                    throw VPNUpdateBrokerInboxError.limitExceeded
                }
                bytes += Int64(target.utf8.count)
                nodes[path] = Node(kind: .link, mode: 0,
                    size: Int64(target.utf8.count),
                    digest: Data(SHA256.hash(data: Data(target.utf8))),
                    target: target)
            }
        }
    }

    private static func readLink(_ directory: Int32, _ name: String) throws -> String {
        var bytes = [UInt8](repeating: 0, count: 4097)
        let count = bytes.withUnsafeMutableBytes {
            readlinkat(directory, name, $0.baseAddress!, $0.count)
        }
        guard count > 0, count < bytes.count,
              let target = String(bytes: bytes.prefix(count), encoding: .utf8),
              !target.hasPrefix("/"), !target.utf8.contains(0) else {
            throw VPNUpdateBrokerInboxError.symlink
        }
        return target
    }

    private static func validateLinks(_ nodes: [String: Node]) throws {
        for (path, node) in nodes where node.kind == .link {
            var resolved = path.split(separator: "/").dropLast().map(String.init)
            var remaining = node.target!.split(
                separator: "/", omittingEmptySubsequences: false).map(String.init)
            var seen: Set<String> = [path], hops = 0
            while !remaining.isEmpty {
                let component = remaining.removeFirst()
                if component.isEmpty || component == "." { continue }
                if component == ".." {
                    guard resolved.count > 1 else {
                        throw VPNUpdateBrokerInboxError.symlink
                    }
                    resolved.removeLast(); continue
                }
                let key = (resolved + [component]).joined(separator: "/")
                guard let next = nodes[key] else {
                    throw VPNUpdateBrokerInboxError.symlink
                }
                if next.kind == .link {
                    hops += 1
                    guard hops <= 40, seen.insert(key).inserted else {
                        throw VPNUpdateBrokerInboxError.symlink
                    }
                    remaining = next.target!.split(
                        separator: "/", omittingEmptySubsequences: false)
                        .map(String.init) + remaining
                } else {
                    guard remaining.isEmpty || next.kind == .directory else {
                        throw VPNUpdateBrokerInboxError.symlink
                    }
                    resolved.append(component)
                }
            }
            let target = resolved.joined(separator: "/")
            guard target.hasPrefix("ProxyPilot.app/"), target != path,
                  nodes[target] != nil else {
                throw VPNUpdateBrokerInboxError.symlink
            }
        }
    }

    private static func readFile(_ directory: Int32, _ name: String,
                                 expected: stat) throws -> Data {
        let file = openat(directory, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard file >= 0 else { throw VPNUpdateBrokerInboxError.sourceChanged }
        defer { close(file) }
        var result = Data(), buffer = [UInt8](repeating: 0, count: 64 * 1024)
        while true {
            let count = Darwin.read(file, &buffer, buffer.count)
            if count < 0, errno == EINTR { continue }
            guard count >= 0 else { throw VPNUpdateBrokerInboxError.sourceChanged }
            if count == 0 { break }
            guard Int64(result.count + count) <= maximumBytes else {
                throw VPNUpdateBrokerInboxError.limitExceeded
            }
            result.append(contentsOf: buffer.prefix(count))
        }
        var after = stat(), named = stat()
        guard fstat(file, &after) == 0,
              fstatat(directory, name, &named, AT_SYMLINK_NOFOLLOW) == 0,
              expected.st_dev == after.st_dev, expected.st_ino == after.st_ino,
              expected.st_dev == named.st_dev, expected.st_ino == named.st_ino,
              expected.st_size == after.st_size,
              expected.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec,
              expected.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec,
              expected.st_ctimespec.tv_sec == after.st_ctimespec.tv_sec,
              expected.st_ctimespec.tv_nsec == after.st_ctimespec.tv_nsec else {
            throw VPNUpdateBrokerInboxError.sourceChanged
        }
        return result
    }

    private static func digest(_ nodes: [String: Node]) -> Data {
        var hash = SHA256()
        for (path, node) in nodes.sorted(by: { $0.key < $1.key }) {
            hash.update(data: Data(path.utf8)); hash.update(data: Data([0]))
            hash.update(data: Data([node.kind.rawValue]))
            var mode = UInt32(node.mode).bigEndian
            withUnsafeBytes(of: &mode) { hash.update(data: Data($0)) }
            var size = UInt64(node.size).bigEndian
            withUnsafeBytes(of: &size) { hash.update(data: Data($0)) }
            hash.update(data: node.digest)
        }
        return Data(hash.finalize())
    }

    private static func synchronizeTree(_ directory: Int32) throws {
        for name in try names(directory) {
            var info = stat()
            guard fstatat(directory, name, &info, AT_SYMLINK_NOFOLLOW) == 0 else {
                throw VPNUpdateBrokerInboxError.commitUncertain
            }
            if info.st_mode & S_IFMT == S_IFLNK { continue }
            let flags = O_RDONLY | O_NOFOLLOW | O_CLOEXEC
                | (info.st_mode & S_IFMT == S_IFDIR ? O_DIRECTORY : O_NONBLOCK)
            let child = openat(directory, name, flags)
            guard child >= 0 else { throw VPNUpdateBrokerInboxError.commitUncertain }
            if info.st_mode & S_IFMT == S_IFDIR { try synchronizeTree(child) }
            guard fsync(child) == 0 else {
                close(child); throw VPNUpdateBrokerInboxError.commitUncertain
            }
            close(child)
        }
        guard fsync(directory) == 0 else { throw VPNUpdateBrokerInboxError.commitUncertain }
    }

    private static func removeChildren(_ directory: Int32, depth: Int,
                                       budget: inout Int) throws {
        guard depth <= maximumDepth else {
            throw VPNUpdateBrokerInboxError.limitExceeded
        }
        let children = try names(directory)
        guard children.count <= budget else {
            throw VPNUpdateBrokerInboxError.limitExceeded
        }
        budget -= children.count
        for name in children {
            var before = stat()
            guard fstatat(directory, name, &before, AT_SYMLINK_NOFOLLOW) == 0,
                  before.st_uid == geteuid(),
                  (before.st_mode & S_IFMT == S_IFLNK
                    || before.st_mode & 0o0022 == 0) else {
                throw VPNUpdateBrokerInboxError.publishedChanged
            }
            if before.st_mode & S_IFMT == S_IFDIR {
                guard let child = try openDirectory(directory, name, privateMode: false) else {
                    throw VPNUpdateBrokerInboxError.publishedChanged
                }
                do {
                    var held = stat()
                    guard fstat(child, &held) == 0,
                          held.st_dev == before.st_dev,
                          held.st_ino == before.st_ino else {
                        throw VPNUpdateBrokerInboxError.publishedChanged
                    }
                    try removeChildren(child, depth: depth + 1,
                                       budget: &budget)
                    guard fsync(child) == 0 else {
                        throw VPNUpdateBrokerInboxError.commitUncertain
                    }
                } catch {
                    close(child)
                    throw error
                }
                close(child)
                var rebound = stat()
                guard fstatat(directory, name, &rebound,
                              AT_SYMLINK_NOFOLLOW) == 0,
                      rebound.st_dev == before.st_dev,
                      rebound.st_ino == before.st_ino,
                      unlinkat(directory, name, AT_REMOVEDIR) == 0 else {
                    throw VPNUpdateBrokerInboxError.publishedChanged
                }
            } else if before.st_mode & S_IFMT == S_IFREG
                    || before.st_mode & S_IFMT == S_IFLNK {
                guard before.st_nlink == 1 else {
                    throw VPNUpdateBrokerInboxError.publishedChanged
                }
                let flags = before.st_mode & S_IFMT == S_IFLNK
                    ? O_RDONLY | O_SYMLINK | O_CLOEXEC
                    : O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK
                let file = openat(directory, name, flags)
                guard file >= 0 else {
                    throw VPNUpdateBrokerInboxError.publishedChanged
                }
                var held = stat()
                let exact = fstat(file, &held) == 0
                    && held.st_dev == before.st_dev && held.st_ino == before.st_ino
                close(file)
                guard exact, unlinkat(directory, name, 0) == 0 else {
                    throw VPNUpdateBrokerInboxError.publishedChanged
                }
            } else {
                throw VPNUpdateBrokerInboxError.publishedChanged
            }
        }
    }

    private static func metadata(_ directory: Int32) throws -> (owned: Bool, writable: Bool) {
        var owned = true, writable = false
        for name in try names(directory) {
            var info = stat()
            guard fstatat(directory, name, &info, AT_SYMLINK_NOFOLLOW) == 0 else {
                throw VPNUpdateBrokerInboxError.publishedChanged
            }
            owned = owned && info.st_uid == geteuid()
            if info.st_mode & S_IFMT != S_IFLNK {
                writable = writable || info.st_mode & 0o0022 != 0
            }
            if info.st_mode & S_IFMT == S_IFDIR {
                guard let child = try openDirectory(directory, name, privateMode: false) else {
                    throw VPNUpdateBrokerInboxError.publishedChanged
                }
                let nested = try metadata(child); close(child)
                owned = owned && nested.owned; writable = writable || nested.writable
            }
        }
        return (owned, writable)
    }

    private static func cloneDirectChild(_ source: Int32, _ sourceName: String,
                                         _ destination: Int32, _ destinationName: String) -> Int32 {
        let basic = UInt32(CLONE_NOFOLLOW | CLONE_NOOWNERCOPY)
        if clonefileat(source, sourceName, destination, destinationName,
                       basic | cloneResolveBeneath) == 0 { return 0 }
        guard errno == EINVAL else { return -1 }
        return clonefileat(source, sourceName, destination, destinationName, basic)
    }

    private static func checkPrivateDirectory(_ directory: Int32) throws {
        var info = stat(), filesystem = statfs()
        guard fstat(directory, &info) == 0,
              info.st_mode & S_IFMT == S_IFDIR, info.st_uid == geteuid(),
              info.st_mode & 0o7777 == 0o700, info.st_nlink > 0,
              fstatfs(directory, &filesystem) == 0,
              filesystem.f_flags & UInt32(MNT_LOCAL) != 0 else {
            throw VPNUpdateBrokerInboxError.unsafeStorage
        }
    }

    private static func checkSourceDirectory(_ directory: Int32) throws {
        var info = stat(), filesystem = statfs()
        guard fstat(directory, &info) == 0,
              info.st_mode & S_IFMT == S_IFDIR,
              info.st_mode & 0o0022 == 0, info.st_nlink > 0,
              fstatfs(directory, &filesystem) == 0,
              filesystem.f_flags & UInt32(MNT_LOCAL) != 0 else {
            throw VPNUpdateBrokerInboxError.unsafeStorage
        }
    }

    private static func openDirectory(_ parent: Int32, _ name: String,
                                      privateMode: Bool = true) throws -> Int32? {
        var info = stat()
        if fstatat(parent, name, &info, AT_SYMLINK_NOFOLLOW) != 0 {
            guard errno == ENOENT else { throw VPNUpdateBrokerInboxError.unsafeStorage }
            return nil
        }
        guard info.st_mode & S_IFMT == S_IFDIR, info.st_uid == geteuid(),
              info.st_nlink > 0,
              privateMode ? info.st_mode & 0o7777 == 0o700
                          : info.st_mode & 0o0022 == 0 else {
            throw VPNUpdateBrokerInboxError.unsafeStorage
        }
        let result = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard result >= 0 else { throw VPNUpdateBrokerInboxError.unsafeStorage }
        return result
    }

    private static func topNames(_ directory: Int32) throws -> Set<String> {
        Set(try names(directory))
    }

    private static func names(_ directory: Int32) throws -> [String] {
        let copy = openat(directory, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard copy >= 0, let stream = fdopendir(copy) else {
            if copy >= 0 { close(copy) }
            throw VPNUpdateBrokerInboxError.unsafeStorage
        }
        defer { closedir(stream) }
        var result: [String] = []
        let offset = MemoryLayout<dirent>.offset(of: \.d_name)!
        while true {
            errno = 0
            guard let entry = readdir(stream) else {
                guard errno == 0 else { throw VPNUpdateBrokerInboxError.unsafeStorage }
                return result
            }
            let length = Int(entry.pointee.d_namlen)
            guard length > 0, offset + length < Int(entry.pointee.d_reclen) else {
                throw VPNUpdateBrokerInboxError.invalidLayout
            }
            let bytes = UnsafeRawPointer(entry).advanced(by: offset)
                .assumingMemoryBound(to: UInt8.self)
            let view = UnsafeBufferPointer(start: bytes, count: length)
            guard bytes[length] == 0, !view.contains(0), !view.contains(47),
                  let name = String(bytes: view, encoding: .utf8) else {
                throw VPNUpdateBrokerInboxError.invalidLayout
            }
            if name != "." && name != ".." { result.append(name) }
        }
    }
}

#if VPN_UPDATE_BROKER_INBOX_TESTING
final class VPNUpdateBrokerInboxContractHarness: VPNUpdateBrokerInboxDriving {
    static let maximumEntries = VPNUpdateBrokerInbox.maximumEntries
    static let maximumBytes = VPNUpdateBrokerInbox.maximumBytes
    static let maximumDepth = VPNUpdateBrokerInbox.maximumDepth
    private let inbox: VPNUpdateBrokerInbox

    required init(trustedParent: Int32) throws {
        inbox = try VPNUpdateBrokerInbox(trustedParent: trustedParent)
    }

    func ingest(sourceDirectory: Int32,
                checkpoint: (String) throws -> Void) throws -> InboxReceipt {
        do {
            let receipt = try inbox.ingest(
                sourceDirectory: sourceDirectory, checkpoint: checkpoint)
            return InboxReceipt(
                identity: receipt.identity,
                outcome: receipt.outcome == .published ? .published : .alreadyPublished,
                syncedNames: receipt.syncedNames, parentSynced: receipt.parentSynced)
        } catch { throw map(error) }
    }

    func publishedSnapshot(_ receipt: InboxReceipt) throws -> [String: Data] {
        do { return try inbox.publishedSnapshot(identity: receipt.identity) }
        catch { throw map(error) }
    }

    func publishedMetadata(_ receipt: InboxReceipt) throws -> InboxPublishedMetadata {
        do {
            let value = try inbox.publishedMetadata(identity: receipt.identity)
            return InboxPublishedMetadata(
                containerMode: value.mode,
                allNodesOwnedByEffectiveUser: value.owned,
                anyGroupOrWorldWritableNode: value.writable)
        } catch { throw map(error) }
    }

    func publishedCount() throws -> Int { try inbox.publishedCount() }

    func retirePublished(_ receipt: InboxReceipt) throws {
        try inbox.retirePublished(identity: receipt.identity)
    }

    func corruptPublished(_ receipt: InboxReceipt) throws {
        try inbox.corruptPublished(identity: receipt.identity)
    }

    private func map(_ error: Error) -> Error {
        guard let error = error as? VPNUpdateBrokerInboxError else { return error }
        switch error {
        case .symlink: return InboxContractError.symlink
        case .hardlink: return InboxContractError.hardlink
        case .special: return InboxContractError.special
        case .unexpectedSibling: return InboxContractError.unexpectedSibling
        case .missingEntry: return InboxContractError.missingEntry
        case .limitExceeded: return InboxContractError.limitExceeded
        case .sourceChanged: return InboxContractError.sourceChanged
        case .rejectedConflict: return InboxContractError.rejectedConflict
        case .publishedChanged: return InboxContractError.publishedChanged
        default: return InboxContractError.invalidLayout
        }
    }
}
#endif
