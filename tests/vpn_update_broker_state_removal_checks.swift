import Darwin
import Foundation

@main
enum Checks {
    static func main() throws {
        let mode = CommandLine.arguments[1]
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("pp-broker-remove-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root,
            withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: root) }
        let directory = open(root.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard directory >= 0 else { throw NSError(domain: "open", code: 1) }
        defer { close(directory) }
        let lease = try VPNLifecycleOwnership.acquire(inTrustedDirectory: directory)
        defer { lease.release() }
        let removal = try VPNUpdateBrokerStateRemoval(trustedDirectoryDescriptor: directory)

        switch mode {
        case "unknown":
            try Data("x".utf8).write(to: root.appendingPathComponent("foreign"))
            try expectRefusal { try removal.preflight() }
        case "symlink":
            symlink("/dev/null", root.appendingPathComponent("update-broker-status.bin").path)
            try expectRefusal { try removal.preflight() }
        case "mode":
            let path = root.appendingPathComponent("update-broker-status.lock").path
            FileManager.default.createFile(atPath: path, contents: Data())
            chmod(path, 0o644)
            try expectRefusal { try removal.preflight() }
        case "partial":
            let pending = root.appendingPathComponent(".inbox-" + String(repeating: "a", count: 64) + ".preparing")
            try FileManager.default.createDirectory(at: pending,
                withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
            let helper = pending.appendingPathComponent("vpn-helper").path
            FileManager.default.createFile(atPath: helper, contents: Data("partial".utf8),
                attributes: [.posixPermissions: 0o600])
            try removal.preflight()
            try removal.removeAll(lease: lease)
            let names = try FileManager.default.contentsOfDirectory(atPath: root.path)
            guard names.isEmpty else { throw NSError(domain: "not-empty", code: 2) }
        default:
            throw NSError(domain: "argument", code: 3)
        }
        print("\(mode) check passed")
    }

    static func expectRefusal(_ body: () throws -> Void) throws {
        do {
            try body()
            throw NSError(domain: "accepted", code: 4)
        } catch is VPNUpdateBrokerStateRemovalError { return }
        catch is VPNUpdateBrokerInboxError { return }
    }
}
