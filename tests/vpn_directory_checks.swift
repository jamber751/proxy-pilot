import Darwin

@main
enum VPNDirectoryChecks {
    static func main() {
        do {
            guard CommandLine.arguments.count == 3 else { exit(64) }
            let operation = CommandLine.arguments[1]
            if operation == "root-guard" {
                // Never enter production provisioning from an elevated test.
                guard geteuid() != 0 else { exit(64) }
                _ = try VPNDirectoryProvisioner.openSystemDirectory(create: true)
                exit(70)
            }
            guard ["create", "read"].contains(operation) else { exit(64) }
            let base = open(CommandLine.arguments[2], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard base >= 0 else { exit(77) }
            defer { close(base) }
            let directory = try VPNDirectoryProvisioner.openBelowTrustedBase(base, create: operation == "create")
            defer { close(directory) }
            guard fcntl(directory, F_GETFD) & FD_CLOEXEC != 0 else { exit(70) }
            print("private-directory-ready")
        } catch {
            print("rejected:\(error)")
            exit(77)
        }
    }
}
