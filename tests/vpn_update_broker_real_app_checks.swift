import Darwin
import Foundation

@main
enum RealAppChecks {
    static func main() throws {
        guard CommandLine.arguments.count == 2 else { exit(64) }
        let input = URL(fileURLWithPath: CommandLine.arguments[1])
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("pp-real-inbox-\(UUID().uuidString)")
        let trusted = root.appendingPathComponent("trusted")
        let source = root.appendingPathComponent("source")
        try FileManager.default.createDirectory(at: trusted,
            withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        try FileManager.default.createDirectory(at: source,
            withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.copyItem(at: input,
            to: source.appendingPathComponent("ProxyPilot.app"))
        for name in VPNUpdateBrokerInbox.fixedLayout where name != "ProxyPilot.app" {
            FileManager.default.createFile(
                atPath: source.appendingPathComponent(name).path,
                contents: Data(name.utf8), attributes: [.posixPermissions: 0o600])
        }
        let trustedFD = open(trusted.path,
            O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        let sourceFD = open(source.path,
            O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard trustedFD >= 0, sourceFD >= 0 else { exit(65) }
        defer { close(sourceFD); close(trustedFD) }
        let inbox = try VPNUpdateBrokerInbox(trustedParent: trustedFD)
        let receipt = try inbox.ingest(sourceDirectory: sourceFD, checkpoint: { _ in })
        let published = try inbox.openPublished(identity: receipt.identity)
        defer { close(published) }
        var path = [CChar](repeating: 0, count: Int(MAXPATHLEN))
        guard fcntl(published, F_GETPATH, &path) == 0 else { exit(66) }
        let copied = URL(fileURLWithPath: String(cString: path))
            .appendingPathComponent("ProxyPilot.app").path
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/codesign")
        process.arguments = ["--verify", "--deep", "--strict", copied]
        process.environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin"]
        try process.run(); process.waitUntilExit()
        guard process.terminationStatus == 0 else { exit(67) }
        try inbox.retirePublished(identity: receipt.identity)
        print("real app inbox check passed")
    }
}
