import Darwin
import Foundation

/// Ordinary disposable IPC-free filesystem proof; never accesses system paths.
@main enum VPNUpdateBrokerCopyChecks {
    enum Failure: Error { case check }
    static func main() throws {
        let args = CommandLine.arguments
        guard getuid() == geteuid(), getuid() != 0, args.count == 5 else { exit(77) }
        let source = open(args[1], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        let parent = open(args[2], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard source >= 0, parent >= 0 else { throw Failure.check }
        defer { close(source); close(parent) }
        #if VPN_UPDATE_BROKER_INBOX_COPY_TESTING
        VPNUpdateBrokerInbox.testCloneFailure = args[3] == "clone" ? nil : args[3] == "unsupported" ? ENOTSUP : (args[3] == "denied" ? EACCES : EXDEV)
        #endif
        let inbox = try VPNUpdateBrokerInbox(trustedParent: parent)
        var mutated = false
        let receipt = try inbox.ingest(sourceDirectory: source) { point in
            if args[3] == "mutate", point.hasPrefix("copyBytes:"), !mutated {
                mutated = true
                try Data("changed during copy".utf8).write(to: URL(fileURLWithPath: args[1]).appendingPathComponent("vpn-helper"))
            }
            if point == args[4] { _exit(43) }
        }
        guard try inbox.publishedSnapshot(identity: receipt.identity).count == VPNUpdateBrokerInbox.fixedLayout.count else { throw Failure.check }
        let facts = try inbox.publishedMetadata(identity: receipt.identity)
        guard facts.owned, !facts.writable, facts.mode & 0o7777 == 0o700 else { throw Failure.check }
        print("bounded copy passed")
    }
}
