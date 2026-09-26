import Darwin
import Dispatch
import Foundation

enum VPNInstalledCandidateHandoffError: Error {
    case requiresRoot, unsafeChannel, spawnFailed, authenticationFailed
    case contextChanged, childFailed
}

/// One-shot liveness proof for exact installed B. It holds B alive around one
/// caller-supplied selector commit, but cannot itself write the journal, start
/// VPN, or receive paths/commands. Journal authorization stays with the caller
/// and is rechecked on both sides of that commit.
enum VPNInstalledCandidateHandoff {
    static let childArgument = "--vpn-installed-candidate-ready"
    static let childSocket: Int32 = 22
    private static let ready: UInt8 = 0x52
    private static let go: UInt8 = 0x47
    private static let acknowledged: UInt8 = 0x41
    private static let finish: UInt8 = 0x46
    private static let deadlineOffset: UInt64 = 15_000_000_000

    static func prove(release: VerifiedVPNRelease,
                      validatePending: () throws -> Void,
                      commitSelection: () throws -> Void,
                      validateSelected: () throws -> Void) throws {
        guard getuid() == 0, geteuid() == 0 else {
            throw VPNInstalledCandidateHandoffError.requiresRoot
        }
        let installed = try VPNInstalledApplication.inspect(release: release)
        try perform(installed: installed, childPolicy: release.installerPolicy(),
                    validatePending: validatePending,
                    commitSelection: commitSelection,
                    validateSelected: validateSelected)
    }

    #if VPN_INSTALLED_CANDIDATE_HANDOFF_TESTING
    static func testProve(installed: VPNInstalledApplication,
                          release: VerifiedVPNRelease,
                          validatePending: () throws -> Void = {},
                          commitSelection: () throws -> Void = {},
                          validateSelected: () throws -> Void = {}) throws {
        try perform(installed: installed,
                    childPolicy: release.clientPolicy(forTrustedUserID: geteuid()),
                    validatePending: validatePending,
                    commitSelection: commitSelection,
                    validateSelected: validateSelected)
    }
    #endif

    static func runChildIfRequested(arguments: [String],
                                    selfPolicy: VPNPeerPolicy,
                                    parentPolicy: VPNPeerPolicy,
                                    validatePending: () throws -> Void,
                                    validateSelected: () throws -> Void) -> Int32? {
        guard arguments.count == 2, arguments[1] == childArgument else { return nil }
        let deadline = DispatchTime.now().uptimeNanoseconds + deadlineOffset
        do {
            try validateSocket(childSocket)
            try VPNPeerAuthentication.validateCurrentProcess(policy: selfPolicy)
            try VPNPeerAuthentication.validate(connectedSocket: childSocket, policy: parentPolicy)
            try validatePending()
            try VPNHelperProtocol.write([ready], socket: childSocket, deadline: deadline)
            guard try VPNHelperProtocol.read(count: 1, socket: childSocket, deadline: deadline) == [go] else {
                throw VPNInstalledCandidateHandoffError.unsafeChannel
            }
            try VPNPeerAuthentication.validate(connectedSocket: childSocket, policy: parentPolicy)
            try validatePending()
            try VPNHelperProtocol.write([acknowledged], socket: childSocket, deadline: deadline)
            guard try VPNHelperProtocol.read(count: 1, socket: childSocket, deadline: deadline) == [finish] else {
                throw VPNInstalledCandidateHandoffError.unsafeChannel
            }
            try VPNPeerAuthentication.validate(connectedSocket: childSocket, policy: parentPolicy)
            try validateSelected()
            return 0
        } catch {
            #if VPN_INSTALLED_CANDIDATE_HANDOFF_TESTING
            FileHandle.standardError.write(Data("candidate-child-rejected:\(error)\n".utf8))
            #endif
            return 77
        }
    }

    private static func perform(installed: VPNInstalledApplication,
                                childPolicy: VPNPeerPolicy,
                                validatePending: () throws -> Void,
                                commitSelection: () throws -> Void,
                                validateSelected: () throws -> Void) throws {
        try validatePending()
        try installed.revalidate()
        let path = try installed.path()
        var pair = [Int32](repeating: -1, count: 2)
        guard socketpair(AF_UNIX, SOCK_STREAM, 0, &pair) == 0 else {
            throw VPNInstalledCandidateHandoffError.unsafeChannel
        }
        var noSignal: Int32 = 1
        guard setCloseOnExec(pair[0]), setCloseOnExec(pair[1]),
              setsockopt(pair[0], SOL_SOCKET, SO_NOSIGPIPE, &noSignal,
                         socklen_t(MemoryLayout.size(ofValue: noSignal))) == 0,
              setsockopt(pair[1], SOL_SOCKET, SO_NOSIGPIPE, &noSignal,
                         socklen_t(MemoryLayout.size(ofValue: noSignal))) == 0 else {
            close(pair[0]); close(pair[1])
            throw VPNInstalledCandidateHandoffError.unsafeChannel
        }
        defer { close(pair[0]) }
        let processID: pid_t
        do { processID = try spawn(path: path, socket: pair[1]) }
        catch { close(pair[1]); throw error }
        close(pair[1])
        var reaped = false
        defer {
            if !reaped { kill(processID, SIGKILL); _ = waitpid(processID, nil, 0) }
        }
        let deadline = DispatchTime.now().uptimeNanoseconds + deadlineOffset
        guard try VPNHelperProtocol.read(count: 1, socket: pair[0], deadline: deadline) == [ready] else {
            throw VPNInstalledCandidateHandoffError.authenticationFailed
        }
        try VPNPeerAuthentication.validate(connectedSocket: pair[0], policy: childPolicy)
        try installed.validateProcess(processID)
        try validatePending()
        try VPNHelperProtocol.write([go], socket: pair[0], deadline: deadline)
        guard try VPNHelperProtocol.read(count: 1, socket: pair[0], deadline: deadline) == [acknowledged] else {
            throw VPNInstalledCandidateHandoffError.childFailed
        }
        try VPNPeerAuthentication.validate(connectedSocket: pair[0], policy: childPolicy)
        try installed.validateProcess(processID)
        try validatePending()
        try commitSelection()
        try validateSelected()
        try VPNPeerAuthentication.validate(connectedSocket: pair[0], policy: childPolicy)
        try installed.validateProcess(processID)
        try VPNHelperProtocol.write([finish], socket: pair[0], deadline: deadline)
        var status: Int32 = 0
        while DispatchTime.now().uptimeNanoseconds < deadline {
            let result = waitpid(processID, &status, WNOHANG)
            if result == processID { reaped = true; break }
            if result < 0, errno != EINTR { break }
            usleep(10_000)
        }
        guard reaped, status & 0x7f == 0, (status >> 8) & 0xff == 0 else {
            throw VPNInstalledCandidateHandoffError.childFailed
        }
        try validateSelected()
        try installed.revalidate()
    }

    private static func validateSocket(_ socket: Int32) throws {
        var kind: Int32 = 0
        var size = socklen_t(MemoryLayout.size(ofValue: kind))
        guard getsockopt(socket, SOL_SOCKET, SO_TYPE, &kind, &size) == 0,
              kind == SOCK_STREAM else { throw VPNInstalledCandidateHandoffError.unsafeChannel }
    }

    private static func setCloseOnExec(_ descriptor: Int32) -> Bool {
        let flags = fcntl(descriptor, F_GETFD)
        return flags >= 0 && fcntl(descriptor, F_SETFD, flags | FD_CLOEXEC) == 0
    }

    private static func spawn(path: String, socket: Int32) throws -> pid_t {
        var actions: posix_spawn_file_actions_t? = nil
        var attributes: posix_spawnattr_t? = nil
        guard posix_spawn_file_actions_init(&actions) == 0,
              posix_spawnattr_init(&attributes) == 0 else {
            throw VPNInstalledCandidateHandoffError.spawnFailed
        }
        defer { posix_spawn_file_actions_destroy(&actions); posix_spawnattr_destroy(&attributes) }
        guard posix_spawn_file_actions_adddup2(&actions, socket, childSocket) == 0,
              posix_spawn_file_actions_addclose(&actions, socket) == 0,
              posix_spawnattr_setflags(&attributes, Int16(POSIX_SPAWN_CLOEXEC_DEFAULT)) == 0 else {
            throw VPNInstalledCandidateHandoffError.spawnFailed
        }
        let strings = [path, childArgument]
        var argv = strings.map { strdup($0) }; argv.append(nil)
        defer { for value in argv where value != nil { free(value) } }
        var environment: [UnsafeMutablePointer<CChar>?] = [nil]
        var processID: pid_t = 0
        let result = path.withCString {
            posix_spawn(&processID, $0, &actions, &attributes, &argv, &environment)
        }
        guard result == 0, processID > 0 else { throw VPNInstalledCandidateHandoffError.spawnFailed }
        return processID
    }
}
