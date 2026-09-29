import Darwin
import Dispatch
import Foundation

@main
enum MountChecks {
    static func main() throws {
        guard CommandLine.arguments.count == 2 else { exit(64) }
        let file = open(CommandLine.arguments[1],
            O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard file >= 0 else { exit(65) }
        defer { close(file) }
        var mount: VPNJointArtifactMount? = try VPNJointArtifactMount.open(
            artifactFile: file,
            deadline: DispatchTime.now().uptimeNanoseconds + 30_000_000_000)
        let copy = openat(mount!.directory, ".",
            O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard copy >= 0, let stream = fdopendir(copy) else { exit(66) }
        var names: Set<String> = []
        while let entry = readdir(stream) {
            let name = withUnsafePointer(to: &entry.pointee.d_name) {
                $0.withMemoryRebound(to: CChar.self, capacity: 1024) {
                    String(cString: $0)
                }
            }
            if name != "." && name != ".." { names.insert(name) }
        }
        closedir(stream)
        let expected: Set<String> = [
            "ProxyPilot.app", "vpn-helper", "vpn-engine",
            "vpn-release.manifest", "vpn-release.sig",
            "vpn-previous-release.manifest", "vpn-previous-release.sig",
            "vpn-update-transition", "vpn-update-transition.sig",
        ]
        guard names == expected else { exit(67) }
        mount = nil
        print("joint artifact mount check passed")
    }
}
