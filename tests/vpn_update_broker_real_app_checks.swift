import Darwin
import Foundation

// BEGIN PURE FRAMEWORK LINK CHECK
/// Fixed packaged locations only; these observations never execute an app.
/// Capture link targets themselves, not merely the files they resolve to.
enum SparkleFrameworkLinkProof {
    enum Failure: Error { case missingFramework, invalidFramework }
    static let locations = [
        "Contents/Frameworks/Sparkle.framework",
        "Contents/Helpers/ProxyPilot Updater.app/Contents/Frameworks/Sparkle.framework"
    ]
    static func capture(_ app: URL) throws -> [String: String] {
        var result = [String: String](), frameworks = 0
        for location in locations {
            let framework = app.appendingPathComponent(location)
            var info = stat()
            if lstat(framework.path, &info) != 0 {
                guard errno == ENOENT else { throw Failure.invalidFramework }
                continue
            }
            guard info.st_mode & S_IFMT == S_IFDIR else { throw Failure.invalidFramework }
            let versions = framework.appendingPathComponent("Versions")
            guard lstat(versions.path, &info) == 0, info.st_mode & S_IFMT == S_IFDIR else { throw Failure.invalidFramework }
            let current = versions.appendingPathComponent("Current")
            let binary = framework.appendingPathComponent("Sparkle")
            guard lstat(current.path, &info) == 0, info.st_mode & S_IFMT == S_IFLNK,
                  lstat(binary.path, &info) == 0, info.st_mode & S_IFMT == S_IFLNK else { throw Failure.invalidFramework }
            let version = try FileManager.default.destinationOfSymbolicLink(atPath: current.path)
            let target = try FileManager.default.destinationOfSymbolicLink(atPath: binary.path)
            // One bounded ASCII version component; no absolute/parent/control
            // target can become a framework version through normalization.
            guard !version.isEmpty, version.utf8.count <= 64, version != ".", version != "..",
                  version.utf8.allSatisfy({ (48...57).contains($0) || (65...90).contains($0) ||
                      (97...122).contains($0) || $0 == 45 || $0 == 46 || $0 == 95 }),
                  target == "Versions/Current/Sparkle" else { throw Failure.invalidFramework }
            let concrete = versions.appendingPathComponent(version)
            guard lstat(concrete.path, &info) == 0, info.st_mode & S_IFMT == S_IFDIR,
                  lstat(concrete.appendingPathComponent("Sparkle").path, &info) == 0,
                  info.st_mode & S_IFMT == S_IFREG else { throw Failure.invalidFramework }
            result[location + "/Versions/Current"] = version
            result[location + "/Sparkle"] = target
            frameworks += 1
        }
        guard frameworks > 0 else { throw Failure.missingFramework }
        return result
    }
}
// END PURE FRAMEWORK LINK CHECK

@main
enum RealAppChecks {
    static func verifySignature(_ app: URL) throws {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/codesign")
        process.arguments = ["--verify", "--deep", "--strict", app.path]
        process.environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin"]
        try process.run(); process.waitUntilExit()
        guard process.terminationStatus == 0 else { exit(67) }
    }
    static func main() throws {
        guard CommandLine.arguments.count == 2 else { exit(64) }
        let input = URL(fileURLWithPath: CommandLine.arguments[1])
        try verifySignature(input)
        let expectedLinks = try SparkleFrameworkLinkProof.capture(input)
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
        let stagedApp = source.appendingPathComponent("ProxyPilot.app")
        guard try SparkleFrameworkLinkProof.capture(stagedApp) == expectedLinks else { exit(68) }
        try verifySignature(stagedApp)
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
            .appendingPathComponent("ProxyPilot.app")
        guard try SparkleFrameworkLinkProof.capture(copied) == expectedLinks else { exit(68) }
        try verifySignature(copied)
        try inbox.retirePublished(identity: receipt.identity)
        print("real app inbox check passed")
    }
}
