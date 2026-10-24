import Darwin
import Dispatch
import Foundation

#if VPN_RESCUE_SYSTEM_ENTRY || VPN_INSTALLED_UPDATE_RESULT_TESTING
/// Final read-only observation through the exact installed selected frontend.
/// Its existing installer role can probe the helper; the rescue cannot.
enum VPNRescueInstalledResultVerifier {
    enum Outcome { case helperReady, remainedOff }

    #if VPN_RESCUE_SYSTEM_ENTRY
    static func verify(service: Int32, lease: VPNLifecycleLease,
                       selected: VPNAuthorizedDeployment, deadline: UInt64) throws -> Outcome {
        guard getuid() == 0, geteuid() == 0 else { throw VPNInstalledUpdateResultError.requiresRoot }
        try VPNDirectoryProvisioner.requireSystemDirectory(service)
        let store = try VPNReleaseStore(trustedDirectoryDescriptor: service,
                                        authority: VPNReleaseTrust.authority())
        let snapshot = try VPNInstalledUpdateResultSnapshot.capture(service: service, store: store)
        guard snapshot.selected.ownerUserID == selected.ownerUserID,
              snapshot.selected.release.isSameRelease(as: selected.release),
              try lease.checkedStorageIdentity() == store.storageIdentity() else {
            throw VPNInstalledUpdateResultError.changed
        }
        let installed = try VPNInstalledApplication.inspect(release: selected.release)
        func validate() throws {
            try lease.check()
            guard try lease.checkedStorageIdentity() == store.storageIdentity() else {
                throw VPNInstalledUpdateResultError.changed
            }
            try snapshot.validate(service: service, store: store)
            try installed.revalidate()
            guard DispatchTime.now().uptimeNanoseconds < deadline else {
                throw VPNInstalledUpdateResultError.deadlineExceeded
            }
        }
        try validate()
        return try observe(installed: installed, release: selected.release, desired: snapshot.desired,
            failures: snapshot.failures, expectedPath: "/Applications/ProxyPilot.app/Contents/MacOS/ProxyPilot",
            childPolicy: selected.release.installerPolicy(), deadline: deadline, validate: validate)
    }
    #endif

    #if VPN_INSTALLED_UPDATE_RESULT_TESTING
    static func testObserve(installed: VPNInstalledApplication, release: VerifiedVPNRelease,
                            desired: Bool, failures: Int, deadline: UInt64,
                            validate: () throws -> Void = {}) throws -> Outcome {
        guard getuid() != 0, getuid() == geteuid() else { throw VPNInstalledUpdateResultError.requiresRoot }
        return try observe(installed: installed, release: release, desired: desired, failures: failures,
            expectedPath: installed.path(), childPolicy: release.clientPolicy(forTrustedUserID: geteuid()),
            deadline: deadline, validate: validate)
    }
    #endif

    private static func observe(installed: VPNInstalledApplication, release: VerifiedVPNRelease,
                                desired: Bool, failures: Int, expectedPath: String,
                                childPolicy: VPNPeerPolicy, deadline: UInt64,
                                validate: () throws -> Void) throws -> Outcome {
        func check() throws {
            try validate()
            try installed.revalidate()
            guard DispatchTime.now().uptimeNanoseconds < deadline else {
                throw VPNInstalledUpdateResultError.deadlineExceeded
            }
        }
        try check()
        guard try installed.path() == expectedPath else { throw VPNInstalledUpdateResultError.invalidState }
        // /Applications is mutable. Suspend before any user code executes,
        // authenticate the actual child and held installed inode, then resume.
        // Pre/post path checks alone would miss a temporary launch-time swap.
        let processID = try spawnSuspended(path: expectedPath)
        var reaped = false
        defer {
            if !reaped {
                kill(processID, SIGKILL)
                while waitpid(processID, nil, 0) < 0 && errno == EINTR {}
            }
        }
        try installed.validateProcess(processID)
        try VPNPeerAuthentication.validate(processID: processID, policy: childPolicy)
        try check()
        guard kill(processID, SIGCONT) == 0 else { throw VPNInstalledUpdateResultError.childFailed }
        var status: Int32 = 0
        while true {
            let result = waitpid(processID, &status, WNOHANG)
            if result == processID { reaped = true; break }
            guard result == 0 || (result < 0 && errno == EINTR) else {
                throw VPNInstalledUpdateResultError.childFailed
            }
            guard DispatchTime.now().uptimeNanoseconds < deadline else {
                throw VPNInstalledUpdateResultError.deadlineExceeded
            }
            usleep(10_000)
        }
        guard status & 0x7f == 0 else { throw VPNInstalledUpdateResultError.childFailed }
        let code = (status >> 8) & 0xff
        let outcome: Outcome
        if desired, failures == 0,
           code == VPNInstalledUpdateResultEntry.helperReadyStatus {
            outcome = .helperReady
        } else if !desired, code == VPNInstalledUpdateResultEntry.remainedOffStatus {
            outcome = .remainedOff
        } else { throw VPNInstalledUpdateResultError.childFailed }
        try check()
        return outcome
    }

    private static func spawnSuspended(path: String) throws -> pid_t {
        var actions: posix_spawn_file_actions_t? = nil
        guard posix_spawn_file_actions_init(&actions) == 0 else {
            throw VPNInstalledUpdateResultError.spawnFailed
        }
        defer { posix_spawn_file_actions_destroy(&actions) }
        var attributes: posix_spawnattr_t? = nil
        guard posix_spawnattr_init(&attributes) == 0 else {
            throw VPNInstalledUpdateResultError.spawnFailed
        }
        defer { posix_spawnattr_destroy(&attributes) }
        guard posix_spawn_file_actions_addopen(&actions, STDIN_FILENO, "/dev/null", O_RDONLY, 0) == 0,
              posix_spawn_file_actions_addopen(&actions, STDOUT_FILENO, "/dev/null", O_WRONLY, 0) == 0,
              posix_spawn_file_actions_addopen(&actions, STDERR_FILENO, "/dev/null", O_WRONLY, 0) == 0,
              posix_spawnattr_setflags(&attributes,
                  Int16(POSIX_SPAWN_START_SUSPENDED | POSIX_SPAWN_CLOEXEC_DEFAULT)) == 0 else {
            throw VPNInstalledUpdateResultError.spawnFailed
        }
        let strings: [String] = [path, VPNInstalledUpdateResultEntry.argument]
        var arguments = strings.map { strdup($0) }
        arguments.append(nil)
        defer { for value in arguments where value != nil { free(value) } }
        var environment: [UnsafeMutablePointer<CChar>?] = [nil]
        var processID: pid_t = 0
        let result = path.withCString {
            posix_spawn(&processID, $0, &actions, &attributes, &arguments, &environment)
        }
        guard result == 0, processID > 0 else { throw VPNInstalledUpdateResultError.spawnFailed }
        return processID
    }
}
#endif
