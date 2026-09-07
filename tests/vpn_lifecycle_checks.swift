import Darwin
import Foundation

// Unprivileged lifecycle-ownership fixture: no launchd, root, VPN or real files
// outside the disposable directory Python creates and owns. One process holds a
// lease and answers stdin commands; a second process tries to take the same one.
@main
enum VPNLifecycleChecks {
    static func say(_ text: String) { print(text); fflush(stdout) }

    static func open(_ path: String) -> Int32 {
        let descriptor = Darwin.open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        if descriptor < 0 { say("rejected:unopenable"); exit(77) }
        return descriptor
    }

    static func attempt(_ directory: Int32, label: String) -> VPNLifecycleLease? {
        do {
            let lease = try VPNLifecycleOwnership.acquire(inTrustedDirectory: directory)
            say("\(label):acquired")
            return lease
        } catch { say("\(label):\(error)"); return nil }
    }

    static func main() {
        guard geteuid() != 0 else { exit(77) }
        let args = CommandLine.arguments
        guard args.count == 3 else { exit(64) }
        let directory = open(args[2])
        defer { close(directory) }
        if args[1] == "try" {
            exit(attempt(directory, label: "try") == nil ? 77 : 0)
        }
        guard args[1] == "lease", let lease = attempt(directory, label: "held") else { exit(77) }
        var second: VPNLifecycleLease?
        while let command = readLine(strippingNewline: true) {
            switch command {
            case "check":
                do { try lease.check(); say("check:ok") } catch { say("check:\(error)") }
            case "again":
                second = attempt(directory, label: "again")
            case "drop-again":
                second?.release()
                second = nil
                say("drop-again:done")
            case "release":
                lease.release()
                say("released")
            case "crash":
                _exit(86)
            case "quit":
                exit(0)
            default:
                exit(64)
            }
        }
        exit(0)
    }
}
