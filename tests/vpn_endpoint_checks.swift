import Darwin
import Dispatch
import Foundation

@main
enum VPNEndpointChecks {
    static func main() {
        let args = CommandLine.arguments
        guard args.count == 3, geteuid() != 0 else { exit(64) }
        do {
            if args[1] == "root-guard" {
                let fd = try VPNEndpointDirectory.openSystem(create: true)
                close(fd); exit(70)
            }
            let base = open(args[2], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard base >= 0 else { exit(77) }
            defer { close(base) }
            let fd = try VPNEndpointDirectory.openBelowTrustedBase(base, owner: geteuid(), create: args[1] == "create")
            defer { close(fd) }
            if args[1] == "connect" || args[1] == "expired" {
                let deadline = args[1] == "expired" ? 0 : DispatchTime.now().uptimeNanoseconds + 250_000_000
                let socket = try VPNEndpointDirectory.connect(directory: fd, owner: geteuid(), shared: true, deadline: deadline)
                defer { close(socket) }
                guard fcntl(socket, F_GETFD) & FD_CLOEXEC != 0,
                      fcntl(socket, F_GETFL) & O_NONBLOCK != 0 else { exit(70) }
                print("connected nonblocking cloexec")
            } else {
                print("opened")
            }
        } catch { print("rejected:\(error)"); exit(77) }
    }
}
