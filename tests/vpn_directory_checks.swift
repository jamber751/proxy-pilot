import Darwin

@main
enum VPNDirectoryChecks {
    static func main() {
        do {
            guard CommandLine.arguments.count == 3 else { exit(64) }
            let operation = CommandLine.arguments[1]
            if operation == "root-guard" || operation == "root-update-guard" {
                // Never enter production provisioning from an elevated test.
                guard geteuid() != 0 else { exit(64) }
                _ = try operation == "root-guard"
                    ? VPNDirectoryProvisioner.openSystemDirectory(create: true)
                    : VPNDirectoryProvisioner.openSystemUpdateDirectory(create: true)
                exit(70)
            }
            guard ["create", "read", "create-update", "read-update", "remove-vpn",
                   "validate-update", "validate-vpn-as-update"].contains(operation) else { exit(64) }
            let base = open(CommandLine.arguments[2], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard base >= 0 else { exit(77) }
            defer { close(base) }
            if operation.hasPrefix("validate-") {
                let supplied = try operation == "validate-update"
                    ? VPNDirectoryProvisioner.testOpenUpdateBelowTrustedBase(base, create: false)
                    : VPNDirectoryProvisioner.openBelowTrustedBase(base, create: false)
                defer { close(supplied) }
                try VPNDirectoryProvisioner.testRequireUpdateDirectory(
                    supplied, belowTrustedBase: base)
                print("private-directory-ready")
                return
            }
            if operation == "remove-vpn" {
                try VPNDirectoryProvisioner.removeBelowTrustedBase(base)
                print("private-directory-ready")
                return
            }
            let directory = try operation.hasSuffix("update")
                ? VPNDirectoryProvisioner.testOpenUpdateBelowTrustedBase(base, create: operation == "create-update")
                : VPNDirectoryProvisioner.openBelowTrustedBase(base, create: operation == "create")
            defer { close(directory) }
            guard fcntl(directory, F_GETFD) & FD_CLOEXEC != 0 else { exit(70) }
            print("private-directory-ready")
        } catch {
            print("rejected:\(error)")
            exit(77)
        }
    }
}
