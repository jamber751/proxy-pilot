import Darwin
import Foundation

/// Root-only disposable CI filesystem fixture. No service, key or system path.
@main enum VPNUpdateBrokerSourceOwnerChecks {
    enum Failure: Error { case assertion }
    static func check(_ condition: @autoclosure () throws -> Bool) throws {
        guard try condition() else { throw Failure.assertion }
    }
    static func rejects(_ operation: () throws -> Void) throws {
        do { try operation() } catch { return }; throw Failure.assertion
    }
    static func main() throws {
        let env = ProcessInfo.processInfo.environment
        guard getuid() == 0, geteuid() == 0,
              env["GITHUB_ACTIONS"] == "true", env["PROXYPILOT_VM_ROOT_TESTS"] == "1" else { exit(77) }
        let args = CommandLine.arguments
        guard args.count == 3 else { exit(64) }
        let root = URL(fileURLWithPath: args[2], isDirectory: true)
        var info = stat()
        guard args[2] == "/private/tmp/" + root.lastPathComponent,
              root.lastPathComponent.hasPrefix("pp-broker-owner-"),
              lstat(root.path, &info) == 0, info.st_mode & S_IFMT == S_IFDIR,
              info.st_uid == 0, info.st_mode & 0o7777 == 0o700 else { exit(77) }
        let source = root.appendingPathComponent("Source", isDirectory: true)
        let trusted = root.appendingPathComponent("Private", isDirectory: true)
        for directory in [source, trusted] {
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false,
                                                    attributes: [.posixPermissions: 0o700])
        }
        let nested = source.appendingPathComponent("ProxyPilot.app/Contents/Resources", isDirectory: true)
        try FileManager.default.createDirectory(at: nested, withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o755])
        try Data("synthetic-app".utf8).write(to: nested.appendingPathComponent("fixture"))
        for name in VPNUpdateBrokerInbox.fixedLayout.subtracting(["ProxyPilot.app"]) {
            let path = source.appendingPathComponent(name)
            try Data(("synthetic-" + name).utf8).write(to: path)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: path.path)
        }
        // Numeric synthetic ordinary owner; no account lookup or login/profile.
        let ordinary: uid_t = 501
        for path in [source] + FileManager.default.enumerator(at: source, includingPropertiesForKeys: nil)!.allObjects.compactMap({ $0 as? URL }) {
            guard lchown(path.path, ordinary, 20) == 0 else { throw Failure.assertion }
        }
        let sourceFD = open(source.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        let trustedFD = open(trusted.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard sourceFD >= 0, trustedFD >= 0 else { throw Failure.assertion }
        defer { close(sourceFD); close(trustedFD) }
        let inbox = try VPNUpdateBrokerInbox(trustedParent: trustedFD)
        if args[1] == "writable-source" {
            guard chmod(nested.path, 0o775) == 0 else { throw Failure.assertion }
            try rejects { _ = try inbox.ingest(sourceDirectory: sourceFD, checkpoint: { _ in }) }
            try check(inbox.publishedCount() == 0)
        } else if args[1] == "mutable-source" {
            try rejects {
                _ = try inbox.ingest(sourceDirectory: sourceFD) { point in
                    if point == "afterCopy:vpn-helper" {
                        try Data("changed-synthetic".utf8).write(to: source.appendingPathComponent("vpn-helper"))
                    }
                }
            }
            try check(inbox.publishedCount() == 0)
        } else {
            let receipt = try inbox.ingest(sourceDirectory: sourceFD, checkpoint: { _ in })
            let copied = try inbox.publishedMetadata(identity: receipt.identity)
            try check(copied.owned && !copied.writable && copied.mode & 0o7777 == 0o700)
            try check(inbox.publishedSnapshot(identity: receipt.identity).count == VPNUpdateBrokerInbox.fixedLayout.count)
            var original = stat()
            try check(lstat(nested.path, &original) == 0 && original.st_uid == ordinary)
            let publication = trusted.appendingPathComponent("inbox-" + receipt.identity.map { String(format: "%02x", $0) }.joined())
            if args[1] == "private-directory-owner" || args[1] == "private-file-owner" {
                let target = publication.appendingPathComponent(args[1] == "private-directory-owner"
                    ? "ProxyPilot.app/Contents/Resources" : "ProxyPilot.app/Contents/Resources/fixture")
                guard lchown(target.path, ordinary, 20) == 0 else { throw Failure.assertion }
                try rejects { _ = try inbox.publishedSnapshot(identity: receipt.identity) }
            } else { try check(args[1] == "ordinary-source") }
        }
        print("cross-UID inbox checks passed")
    }
}
