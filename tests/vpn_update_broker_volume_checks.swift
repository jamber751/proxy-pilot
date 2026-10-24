import Darwin
import Foundation

@main enum VPNUpdateBrokerVolumeChecks {
    enum Failure: Error { case assertion }
    static func main() throws {
        let env = ProcessInfo.processInfo.environment
        guard getuid() == 0, geteuid() == 0, env["GITHUB_ACTIONS"] == "true",
              env["PROXYPILOT_VM_ROOT_TESTS"] == "1", CommandLine.arguments.count == 2 else { exit(77) }
        let path = CommandLine.arguments[1]
        let root = URL(fileURLWithPath: path)
        guard path == "/private/tmp/" + root.lastPathComponent,
              root.lastPathComponent.hasPrefix("pp-broker-volume-") else { exit(77) }
        let base = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard base >= 0 else { throw Failure.assertion }
        defer { close(base) }
        var owner = stat()
        guard fstat(base, &owner) == 0, owner.st_uid == 0,
              owner.st_mode & 0o7777 == 0o700 else { exit(77) }
        let source = openat(base, "mount", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        let destination = openat(base, "private", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard source >= 0, destination >= 0 else { throw Failure.assertion }
        defer { close(source); close(destination) }
        var from = statfs(), to = statfs()
        guard fstatfs(source, &from) == 0, fstatfs(destination, &to) == 0,
              from.f_flags & UInt32(MNT_RDONLY) != 0,
              from.f_fsid.val.0 != to.f_fsid.val.0 || from.f_fsid.val.1 != to.f_fsid.val.1 else { throw Failure.assertion }
        guard clonefileat(source, "vpn-helper", destination, "clone-probe", UInt32(CLONE_NOFOLLOW | CLONE_NOOWNERCOPY)) == -1,
              errno == EXDEV || errno == ENOTSUP else { throw Failure.assertion }
        let inbox = try VPNUpdateBrokerInbox(trustedParent: destination)
        let result = try inbox.ingest(sourceDirectory: source, checkpoint: { _ in })
        guard try inbox.publishedSnapshot(identity: result.identity).count == VPNUpdateBrokerInbox.fixedLayout.count else { throw Failure.assertion }
        let facts = try inbox.publishedMetadata(identity: result.identity)
        guard facts.owned, !facts.writable else { throw Failure.assertion }
        print("readonly cross-volume inbox passed")
    }
}
