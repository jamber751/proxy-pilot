import Darwin
import Foundation

enum VPNExecutorHandoffError: Error {
    case requiresRoot
    case unsafeChannel
    case spawnFailed
    case authenticationFailed
    case invalidRequest
    case childFailed
    case commitUncertain
}

struct VPNExecutorHandoffRequest: Equatable {
    let transactionID: UUID
    let expectedRevision: UInt64
}

/// Starts only the fixed, protected A copy and gives it the minimum authority
/// needed to resume one already-journaled replacement. The child receives no
/// caller-controlled path, command or release metadata. Both peers authenticate
/// the live process before the parent releases its namespace lease and sends GO.
enum VPNReplacementExecutorHandoff {
    private enum ChildOperationStage: UInt8 {
        case applicationDestinationPreparation = 0x61
        case recoveryArm = 0x62
        case candidateProof = 0x63
        case candidateFinalization = 0x64
        case journalRetirement = 0x65
        case applicationDestinationRecheck = 0x66
        case applicationDestinationCommit = 0x67
        case applicationDestinationPostCommitSync = 0x68
        case applicationDestinationProtectedValidation = 0x69
        case applicationDestinationIdentityValidation = 0x6a
        case applicationDestinationCandidateInspection = 0x6b
        case applicationDestinationPreviousInspection = 0x6c
        case applicationDestinationCandidateRevalidation = 0x6d
        case applicationDestinationPreviousRevalidation = 0x6e

        var label: String {
            switch self {
            case .applicationDestinationPreparation: return "applicationDestinationPreparation"
            case .recoveryArm: return "recoveryArm"
            case .candidateProof: return "candidateProof"
            case .candidateFinalization: return "candidateFinalization"
            case .journalRetirement: return "journalRetirement"
            case .applicationDestinationRecheck: return "applicationDestinationRecheck"
            case .applicationDestinationCommit: return "applicationDestinationCommit"
            case .applicationDestinationPostCommitSync: return "applicationDestinationPostCommitSync"
            case .applicationDestinationProtectedValidation: return "applicationDestinationProtectedValidation"
            case .applicationDestinationIdentityValidation: return "applicationDestinationIdentityValidation"
            case .applicationDestinationCandidateInspection: return "applicationDestinationCandidateInspection"
            case .applicationDestinationPreviousInspection: return "applicationDestinationPreviousInspection"
            case .applicationDestinationCandidateRevalidation: return "applicationDestinationCandidateRevalidation"
            case .applicationDestinationPreviousRevalidation: return "applicationDestinationPreviousRevalidation"
            }
        }
    }

    private enum FailureStage: String {
        case preparation
        case channel
        case spawn
        case mutualAuthentication
        case request
        case childCompletion
        case childOperation
    }

    static let childArgument = "--vpn-protected-replacement-executor"
    static let childSocket: Int32 = 20
    static let childApplicationDirectory: Int32 = 21
    private static let ready: UInt8 = 0x52
    private static let exchanged: UInt8 = 0x31
    private static let alreadyExchanged: UInt8 = 0x32
    private static let failed: UInt8 = 0x30
    private static let magic = Data("PPVPNX01".utf8)
    private static let frameSize = 8 + 16 + 8
    private static let timeout: UInt64 = 45_000_000_000

    static func launchPrepared(inTrustedDirectory base: Int32,
                               release: VerifiedVPNRelease,
                               request: VPNExecutorHandoffRequest,
                               childPolicy: VPNPeerPolicy,
                               parentPolicy: VPNPeerPolicy) throws
        -> VPNProtectedApplicationSwap.Outcome {
        guard getuid() == 0, geteuid() == 0 else { throw VPNExecutorHandoffError.requiresRoot }
        try VPNDirectoryProvisioner.requireSystemUpdateDirectory(base)
        do {
            return try performLaunch(base: base, release: release, request: request,
                                     childPolicy: childPolicy, parentPolicy: parentPolicy,
                                     checkpoint: { _ in })
        } catch let error as VPNExecutorHandoffError {
            report(stage(for: error))
            throw error
        } catch {
            report(.preparation)
            throw error
        }
    }

    private static func stage(for error: VPNExecutorHandoffError) -> FailureStage {
        switch error {
        case .requiresRoot: return .preparation
        case .unsafeChannel: return .channel
        case .spawnFailed: return .spawn
        case .authenticationFailed: return .mutualAuthentication
        case .invalidRequest: return .request
        case .childFailed: return .childCompletion
        case .commitUncertain: return .childOperation
        }
    }

    private static func report(_ stage: FailureStage) {
        FileHandle.standardError.write(Data(
            "VPN executor handoff failed at \(stage.rawValue).\n".utf8))
    }

    #if VPN_EXECUTOR_HANDOFF_TESTING
    static func testLaunchPrepared(inTrustedDirectory base: Int32,
                                   release: VerifiedVPNRelease,
                                   request: VPNExecutorHandoffRequest,
                                   childPolicy: VPNPeerPolicy,
                                   parentPolicy: VPNPeerPolicy,
                                   checkpoint: (String) throws -> Void = { _ in }) throws
        -> VPNProtectedApplicationSwap.Outcome {
        guard getuid() != 0, geteuid() == getuid() else { throw VPNPeerAuthenticationError.denied }
        return try performLaunch(base: base, release: release, request: request,
                                 childPolicy: childPolicy, parentPolicy: parentPolicy,
                                 checkpoint: checkpoint)
    }

    #endif

    /// Returns nil for the ordinary app launch, or the executor's process exit
    /// status for the exact hidden role. The caller must exit immediately when
    /// this returns a value and must never initialize UI in that process.
    static func runChildIfRequested(arguments: [String], selfPolicy: VPNPeerPolicy,
                                    parentPolicy: VPNPeerPolicy,
                                    failureDiagnostic: (Error) -> UInt8? = { _ in nil },
                                    operation: (VPNExecutorHandoffRequest, Int32) throws
                                        -> VPNProtectedApplicationSwap.Outcome) -> Int32? {
        guard arguments.count == 2, arguments[1] == childArgument else { return nil }
        return runChild(selfPolicy: selfPolicy, parentPolicy: parentPolicy,
                        failureDiagnostic: failureDiagnostic, operation: operation)
    }

    private static func performLaunch(base: Int32, release: VerifiedVPNRelease,
                                      request: VPNExecutorHandoffRequest,
                                      childPolicy: VPNPeerPolicy,
                                      parentPolicy: VPNPeerPolicy,
                                      checkpoint: (String) throws -> Void) throws
        -> VPNProtectedApplicationSwap.Outcome {
        let lease = try VPNLifecycleOwnership.acquire(inTrustedDirectory: base)
        var leaseReleased = false
        defer { if !leaseReleased { lease.release() } }
        let prepared = try VPNReplacementExecutor.inspectPrepared(inTrustedDirectory: base, release: release)
        let executablePath = try prepared.path()

        var pair = [Int32](repeating: -1, count: 2)
        guard socketpair(AF_UNIX, SOCK_STREAM, 0, &pair) == 0 else {
            throw VPNExecutorHandoffError.unsafeChannel
        }
        let parentSocket = pair[0]
        var childSource = pair[1]
        defer { close(parentSocket) }
        var noSignal: Int32 = 1
        guard setCloseOnExec(parentSocket), setCloseOnExec(childSource),
              setsockopt(parentSocket, SOL_SOCKET, SO_NOSIGPIPE, &noSignal,
                         socklen_t(MemoryLayout.size(ofValue: noSignal))) == 0,
              setsockopt(childSource, SOL_SOCKET, SO_NOSIGPIPE, &noSignal,
                         socklen_t(MemoryLayout.size(ofValue: noSignal))) == 0 else {
            close(childSource); throw VPNExecutorHandoffError.unsafeChannel
        }
        let movedSocket = fcntl(childSource, F_DUPFD_CLOEXEC, 64)
        let movedBase = fcntl(base, F_DUPFD_CLOEXEC, 64)
        close(childSource); childSource = -1
        guard movedSocket >= 0, movedBase >= 0 else {
            if movedSocket >= 0 { close(movedSocket) }
            if movedBase >= 0 { close(movedBase) }
            throw VPNExecutorHandoffError.unsafeChannel
        }
        let processID: pid_t
        do {
            processID = try spawn(path: executablePath, socket: movedSocket, base: movedBase)
        } catch {
            close(movedSocket); close(movedBase)
            throw error
        }
        // Keeping either duplicate in the parent would keep the channel alive
        // after an early child denial and turn a precise failure into a timeout.
        close(movedSocket); close(movedBase)
        var sentGo = false
        var reaped = false
        defer {
            if !reaped {
                kill(processID, SIGKILL)
                let cleanupDeadline = DispatchTime.now().uptimeNanoseconds + 5_000_000_000
                while DispatchTime.now().uptimeNanoseconds < cleanupDeadline {
                    var status: Int32 = 0
                    let result = waitpid(processID, &status, WNOHANG)
                    if result == processID || (result < 0 && errno == ECHILD) { break }
                    if result < 0 && errno != EINTR { break }
                    usleep(10_000)
                }
            }
        }
        let deadline = DispatchTime.now().uptimeNanoseconds + timeout
        let readiness = try readExact(parentSocket, count: 1, deadline: deadline).first
        guard readiness == ready else {
            #if VPN_EXECUTOR_HANDOFF_TESTING
            FileHandle.standardError.write(Data("child-readiness:\(readiness ?? 0)\n".utf8))
            #endif
            throw VPNExecutorHandoffError.authenticationFailed
        }
        // Readiness carries no authority. Waiting for it first keeps Security
        // from resolving an audit token after an early-rejected child has died.
        // The child remains blocked on the request while both proofs run.
        do {
            try VPNPeerAuthentication.validate(connectedSocket: parentSocket,
                                                policy: childPolicy)
            try VPNPeerAuthentication.validateCurrentProcess(policy: parentPolicy)
            try prepared.validateProcess(processID)
        } catch {
            throw VPNExecutorHandoffError.authenticationFailed
        }
        try checkpoint("childReady")
        try lease.check()
        try prepared.validateProcess(processID)
        try checkpoint("beforeGo")
        try lease.check()
        try prepared.validateProcess(processID)

        // The child must acquire this same lease inside the journal-authorized
        // operation. Release it only after every parent-side proof is complete.
        lease.release(); leaseReleased = true
        do {
            try writeAll(parentSocket, data: encode(request), deadline: deadline)
            sentGo = true
            let result = try readExact(parentSocket, count: 1, deadline: deadline)
            let status = try waitForExit(processID, deadline: deadline)
            reaped = true
            if let byte = result.first, let stage = ChildOperationStage(rawValue: byte) {
                FileHandle.standardError.write(Data(
                    "VPN replacement executor failed at \(stage.label).\n".utf8))
                throw VPNExecutorHandoffError.commitUncertain
            }
            guard status & 0x7f == 0, (status >> 8) & 0xff == 0, let byte = result.first else {
                throw VPNExecutorHandoffError.childFailed
            }
            if byte == exchanged { return .exchanged }
            if byte == alreadyExchanged { return .alreadyExchanged }
            throw VPNExecutorHandoffError.childFailed
        } catch {
            if sentGo { throw VPNExecutorHandoffError.commitUncertain }
            throw error
        }
    }

    private static func runChild(selfPolicy: VPNPeerPolicy,
                                 parentPolicy: VPNPeerPolicy,
                                 failureDiagnostic: (Error) -> UInt8?,
                                 operation: (VPNExecutorHandoffRequest, Int32) throws
                                    -> VPNProtectedApplicationSwap.Outcome) -> Int32 {
        let deadline = DispatchTime.now().uptimeNanoseconds + timeout
        do {
            do { try validateInheritedDescriptors() }
            catch {
                try? writeAll(childSocket, data: Data([denialByte(0x41)]), deadline: deadline)
                throw error
            }
            do { try VPNPeerAuthentication.validateCurrentProcess(policy: selfPolicy) }
            catch {
                try? writeAll(childSocket, data: Data([denialByte(0x42)]), deadline: deadline)
                throw error
            }
            do { try VPNPeerAuthentication.validate(connectedSocket: childSocket,
                                                     policy: parentPolicy) }
            catch {
                try? writeAll(childSocket, data: Data([denialByte(0x43)]), deadline: deadline)
                throw error
            }
            try writeAll(childSocket, data: Data([ready]), deadline: deadline)
            let request = try decode(readExact(childSocket, count: frameSize, deadline: deadline))
            do {
                let outcome = try operation(request, childApplicationDirectory)
                let byte: UInt8 = outcome == .exchanged ? exchanged : alreadyExchanged
                try writeAll(childSocket, data: Data([byte]), deadline: deadline)
                return 0
            } catch {
                let diagnostic = failureDiagnostic(error)
                    .flatMap(ChildOperationStage.init(rawValue:))?.rawValue ?? failed
                try? writeAll(childSocket, data: Data([diagnostic]), deadline: deadline)
                return 77
            }
        } catch {
            #if VPN_EXECUTOR_HANDOFF_TESTING
            FileHandle.standardError.write(Data("child-handoff-rejected:\(error)\n".utf8))
            #endif
            return 77
        }
    }

    private static func validateInheritedDescriptors() throws {
        var socketKind: Int32 = 0
        var socketSize = socklen_t(MemoryLayout.size(ofValue: socketKind))
        var directory = stat()
        guard getsockopt(childSocket, SOL_SOCKET, SO_TYPE, &socketKind, &socketSize) == 0,
              socketKind == SOCK_STREAM,
              fstat(childApplicationDirectory, &directory) == 0,
              directory.st_mode & S_IFMT == S_IFDIR,
              directory.st_uid == geteuid(), directory.st_mode & 0o7777 == 0o700,
              directory.st_nlink > 0 else { throw VPNExecutorHandoffError.unsafeChannel }
    }

    private static func denialByte(_ diagnostic: UInt8) -> UInt8 {
        #if VPN_EXECUTOR_HANDOFF_TESTING
        return diagnostic
        #else
        return failed
        #endif
    }

    private static func spawn(path: String, socket: Int32, base: Int32) throws -> pid_t {
        var actions: posix_spawn_file_actions_t? = nil
        var attributes: posix_spawnattr_t? = nil
        guard posix_spawn_file_actions_init(&actions) == 0,
              posix_spawnattr_init(&attributes) == 0 else {
            if actions != nil { posix_spawn_file_actions_destroy(&actions) }
            throw VPNExecutorHandoffError.spawnFailed
        }
        defer {
            posix_spawn_file_actions_destroy(&actions)
            posix_spawnattr_destroy(&attributes)
        }
        guard posix_spawn_file_actions_adddup2(&actions, socket, childSocket) == 0,
              posix_spawn_file_actions_adddup2(&actions, base, childApplicationDirectory) == 0,
              posix_spawn_file_actions_addclose(&actions, socket) == 0,
              posix_spawn_file_actions_addclose(&actions, base) == 0,
              posix_spawnattr_setflags(&attributes, Int16(POSIX_SPAWN_CLOEXEC_DEFAULT)) == 0 else {
            throw VPNExecutorHandoffError.spawnFailed
        }
        let argumentStrings = [path, childArgument]
        var arguments = argumentStrings.map { strdup($0) }
        arguments.append(nil)
        defer { for argument in arguments where argument != nil { free(argument) } }
        var environment: [UnsafeMutablePointer<CChar>?] = [nil]
        var processID: pid_t = 0
        let result = path.withCString { executable in
            posix_spawn(&processID, executable, &actions, &attributes, &arguments, &environment)
        }
        guard result == 0, processID > 0 else { throw VPNExecutorHandoffError.spawnFailed }
        return processID
    }

    private static func encode(_ request: VPNExecutorHandoffRequest) -> Data {
        var result = magic
        var identifier = request.transactionID.uuid
        withUnsafeBytes(of: &identifier) { result.append(contentsOf: $0) }
        var revision = request.expectedRevision.bigEndian
        withUnsafeBytes(of: &revision) { result.append(contentsOf: $0) }
        return result
    }

    private static func decode(_ data: Data) throws -> VPNExecutorHandoffRequest {
        guard data.count == frameSize, data.prefix(8) == magic else {
            throw VPNExecutorHandoffError.invalidRequest
        }
        var identifier: uuid_t = (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
        _ = withUnsafeMutableBytes(of: &identifier) { destination in
            data.copyBytes(to: destination, from: 8..<24)
        }
        var revision: UInt64 = 0
        _ = withUnsafeMutableBytes(of: &revision) { destination in
            data.copyBytes(to: destination, from: 24..<32)
        }
        return VPNExecutorHandoffRequest(transactionID: UUID(uuid: identifier),
                                         expectedRevision: UInt64(bigEndian: revision))
    }

    private static func setCloseOnExec(_ descriptor: Int32) -> Bool {
        let flags = fcntl(descriptor, F_GETFD)
        return flags >= 0 && fcntl(descriptor, F_SETFD, flags | FD_CLOEXEC) == 0
    }

    private static func waitForExit(_ processID: pid_t, deadline: UInt64) throws -> Int32 {
        while DispatchTime.now().uptimeNanoseconds < deadline {
            var status: Int32 = 0
            let result = waitpid(processID, &status, WNOHANG)
            if result == processID { return status }
            if result < 0 && errno != EINTR { throw VPNExecutorHandoffError.childFailed }
            usleep(10_000)
        }
        throw VPNExecutorHandoffError.childFailed
    }

    private static func readExact(_ descriptor: Int32, count: Int,
                                  deadline: UInt64) throws -> Data {
        var result = Data(count: count)
        var offset = 0
        while offset < count {
            try wait(descriptor, events: Int16(POLLIN), deadline: deadline)
            let amount = result.withUnsafeMutableBytes { bytes in
                Darwin.read(descriptor, bytes.baseAddress!.advanced(by: offset), count - offset)
            }
            if amount < 0 && errno == EINTR { continue }
            guard amount > 0 else { throw VPNExecutorHandoffError.unsafeChannel }
            offset += amount
        }
        return result
    }

    private static func writeAll(_ descriptor: Int32, data: Data,
                                 deadline: UInt64) throws {
        var offset = 0
        while offset < data.count {
            try wait(descriptor, events: Int16(POLLOUT), deadline: deadline)
            let amount = data.withUnsafeBytes { bytes in
                Darwin.write(descriptor, bytes.baseAddress!.advanced(by: offset), data.count - offset)
            }
            if amount < 0 && errno == EINTR { continue }
            guard amount > 0 else { throw VPNExecutorHandoffError.unsafeChannel }
            offset += amount
        }
    }

    private static func wait(_ descriptor: Int32, events: Int16,
                             deadline: UInt64) throws {
        while true {
            let now = DispatchTime.now().uptimeNanoseconds
            guard now < deadline else { throw VPNExecutorHandoffError.unsafeChannel }
            let milliseconds = Int32(min((deadline - now + 999_999) / 1_000_000,
                                         UInt64(Int32.max)))
            var item = pollfd(fd: descriptor, events: events, revents: 0)
            let result = poll(&item, 1, milliseconds)
            if result < 0 && errno == EINTR { continue }
            guard result == 1, item.revents & events != 0,
                  item.revents & Int16(POLLERR | POLLNVAL) == 0 else {
                throw VPNExecutorHandoffError.unsafeChannel
            }
            return
        }
    }
}
