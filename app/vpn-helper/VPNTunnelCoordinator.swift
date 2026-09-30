import Darwin
import Foundation

enum VPNTunnelCoordinatorBlocker: Equatable {
    case noEnabledConfiguration
    case credentialRequired(OpenVPNCredentialKind)
    case alreadyRunning
}

/// Internal runtime evidence only. `managementReady` means the local protocol
/// handshake succeeded while OpenVPN is still held. It is never a claim that
/// routes, DNS or a usable VPN connection exist.
enum VPNTunnelCoordinatorReadiness: Equatable {
    case inactive
    case blocked(VPNTunnelCoordinatorBlocker)
    case processRunning(generation: UInt64)
    case managementReady(generation: UInt64, state: OpenVPNConnectionState)
    case stopped(generation: UInt64)
    case failed(generation: UInt64?)
}

enum VPNTunnelCoordinatorError: Error {
    case invalidState, engineExited, managementUnavailable, managementRejected
}

private enum VPNTunnelLaunchIntent {
    case ready(generation: UInt64, profileDigest: String)
    case blocked(VPNTunnelCoordinatorBlocker)
}

/// Owns at most one engine, one management connection and one socket inode.
/// Every public operation is serialized. Stage B deliberately never sends
/// `hold release`, so OpenVPN cannot advance into route or DNS application.
final class VPNTunnelCoordinator {
    private let lock = NSLock()
    private let intent: () throws -> VPNTunnelLaunchIntent
    private let openProfile: (String) throws -> Int32
    private let selection: VPNEngineExecutableSelection
    private let managementDirectory: Int32
    private var process: VPNEngineProcess?
    private var management: OpenVPNManagementClient?
    private var reservation: VPNManagementSocketReservation?
    private var current: VPNTunnelCoordinatorReadiness = .inactive

    #if !VPN_TUNNEL_COORDINATOR_TESTING
    init(trustedDirectoryDescriptor directory: Int32,
         deployment: VPNAuthorizedDeployment) throws {
        let state = try VPNTunnelStateStore(trustedDirectoryDescriptor: directory)
        let vault = try VPNProfileVault(trustedDirectoryDescriptor: directory)
        selection = try VPNEngineExecutableSelection(
            trustedDirectoryDescriptor: directory, deployment: deployment)
        managementDirectory = fcntl(directory, F_DUPFD_CLOEXEC, 64)
        guard managementDirectory >= 0 else { throw VPNTunnelCoordinatorError.invalidState }
        openProfile = { try vault.openValidated(digest: $0) }
        intent = {
            let snapshot = try state.load()
            guard snapshot.desiredEnabled else {
                return .blocked(.noEnabledConfiguration)
            }
            if let challenge = snapshot.challenge {
                let kind: OpenVPNCredentialKind = challenge.kind == .privateKeyPassword
                    ? .privateKeyPassphrase : .usernameAndPassword
                return .blocked(.credentialRequired(kind))
            }
            guard snapshot.phase == .connecting,
                  let application = snapshot.pending ?? snapshot.active else {
                throw VPNTunnelCoordinatorError.invalidState
            }
            if application.requiresPrivateKeyPassword {
                return .blocked(.credentialRequired(.privateKeyPassphrase))
            }
            if application.requiresVPNCredentials {
                let kind: OpenVPNCredentialKind = application.spec.authentication.mode == .oneTimePassword
                    ? .staticChallenge : .usernameAndPassword
                return .blocked(.credentialRequired(kind))
            }
            return .ready(generation: snapshot.generation,
                          profileDigest: application.spec.profileSHA256)
        }
    }
    #else
    init(testDirectory directory: Int32, selection: VPNEngineExecutableSelection,
         generation: UInt64 = 1, profileDigest: String,
         openProfile: @escaping (String) throws -> Int32,
         blocker: VPNTunnelCoordinatorBlocker? = nil) throws {
        self.selection = selection
        managementDirectory = fcntl(directory, F_DUPFD_CLOEXEC, 64)
        guard managementDirectory >= 0 else { throw VPNTunnelCoordinatorError.invalidState }
        self.openProfile = openProfile
        intent = {
            if let blocker = blocker { return .blocked(blocker) }
            return .ready(generation: generation, profileDigest: profileDigest)
        }
    }
    #endif

    deinit {
        lock.lock()
        stopLocked()
        lock.unlock()
        if managementDirectory >= 0 { close(managementDirectory) }
    }

    func readiness() -> VPNTunnelCoordinatorReadiness {
        lock.lock(); defer { lock.unlock() }
        return current
    }

    func start(timeoutMilliseconds: Int = 5_000) throws -> VPNTunnelCoordinatorReadiness {
        lock.lock(); defer { lock.unlock() }
        guard process == nil, management == nil, reservation == nil else {
            return .blocked(.alreadyRunning)
        }
        let launch = try intent()
        guard case .ready(let generation, let digest) = launch else {
            if case .blocked(let blocker) = launch { current = .blocked(blocker) }
            return current
        }
        guard (1...10_000).contains(timeoutMilliseconds) else {
            throw VPNTunnelCoordinatorError.invalidState
        }
        let now = clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW)
        let deadline = now + UInt64(timeoutMilliseconds) * 1_000_000

        var localProcess: VPNEngineProcess?
        var localClient: OpenVPNManagementClient?
        var localReservation: VPNManagementSocketReservation?
        do {
            let profile = try openProfile(digest)
            defer { close(profile) }
            let socket = try VPNManagementSocketReservation(
                trustedDirectoryDescriptor: managementDirectory)
            localReservation = socket
            let child = try VPNEngineProcess.start(selection: selection,
                protectedProfileDescriptor: profile, management: socket.configuration)
            localProcess = child
            current = .processRunning(generation: generation)
            let client = try connect(socket: socket, process: child, deadline: deadline)
            localClient = client
            let state = try initialize(client: client, deadline: deadline)
            process = child; management = client; reservation = socket
            current = .managementReady(generation: generation, state: state)
            return current
        } catch let blocker as CoordinatorCredentialBlock {
            localClient?.close()
            _ = try? localProcess?.stop(graceMilliseconds: 250)
            localReservation?.cleanup()
            current = .blocked(.credentialRequired(blocker.kind))
            return current
        } catch {
            localClient?.close()
            _ = try? localProcess?.stop(graceMilliseconds: 250)
            localReservation?.cleanup()
            current = .failed(generation: generation)
            throw error
        }
    }

    func observe(timeoutMilliseconds: Int = 2_000) throws -> VPNTunnelCoordinatorReadiness {
        lock.lock(); defer { lock.unlock() }
        guard let client = management, let child = process,
              case .managementReady(let generation, _) = current else {
            throw VPNTunnelCoordinatorError.invalidState
        }
        guard try child.state() == .running else {
            stopLocked(); current = .failed(generation: generation); return current
        }
        let event: OpenVPNManagementEvent
        do { event = try client.readEvent(timeoutMilliseconds: timeoutMilliseconds) }
        catch {
            stopLocked()
            current = .failed(generation: generation)
            throw error
        }
        switch event {
        case .state(let evidence):
            current = .managementReady(generation: generation, state: evidence.state)
        case .credentialRequired(let kind), .credentialRejected(let kind):
            stopLocked(); current = .blocked(.credentialRequired(kind))
        case .fatal, .commandFailed:
            stopLocked(); current = .failed(generation: generation)
        case .ready, .hold, .commandSucceeded, .commandCompleted: break
        }
        return current
    }

    @discardableResult
    func stop() -> VPNTunnelCoordinatorReadiness {
        lock.lock(); defer { lock.unlock() }
        let generation: UInt64
        switch current {
        case .processRunning(let value), .managementReady(let value, _), .stopped(let value):
            generation = value
        default: generation = 0
        }
        stopLocked()
        current = .stopped(generation: generation)
        return current
    }

    private func stopLocked() {
        if let client = management { try? client.send(.gracefulStop, timeoutMilliseconds: 250) }
        management?.close()
        _ = try? process?.stop(graceMilliseconds: 500)
        reservation?.cleanup()
        management = nil; process = nil; reservation = nil
    }

    private func connect(socket: VPNManagementSocketReservation, process: VPNEngineProcess,
                         deadline: UInt64) throws -> OpenVPNManagementClient {
        while Self.now() < deadline {
            guard try process.state() == .running else { throw VPNTunnelCoordinatorError.engineExited }
            if try socket.secureIfPresent() {
                let remaining = try Self.remaining(deadline)
                return try OpenVPNManagementClient.connect(
                    to: .unixSocket(socket.configuration.socketPath),
                    timeoutMilliseconds: min(remaining, 2_000))
            }
            usleep(5_000)
        }
        throw VPNTunnelCoordinatorError.managementUnavailable
    }

    private func initialize(client: OpenVPNManagementClient,
                            deadline: UInt64) throws -> OpenVPNConnectionState {
        try client.send(.enableStateNotifications, timeoutMilliseconds: Self.remaining(deadline))
        try awaitSuccess(client, deadline: deadline)
        try client.send(.requestCurrentState, timeoutMilliseconds: Self.remaining(deadline))
        var state: OpenVPNConnectionState?
        for _ in 0..<16 {
            switch try client.readEvent(timeoutMilliseconds: Self.remaining(deadline)) {
            case .state(let evidence): state = evidence.state
            case .commandCompleted:
                guard let state = state else { throw VPNTunnelCoordinatorError.managementRejected }
                return state
            case .credentialRequired(let kind), .credentialRejected(let kind):
                throw CoordinatorCredentialBlock(kind: kind)
            case .fatal, .commandFailed: throw VPNTunnelCoordinatorError.managementRejected
            case .ready, .hold, .commandSucceeded: break
            }
        }
        throw VPNTunnelCoordinatorError.managementRejected
    }

    private func awaitSuccess(_ client: OpenVPNManagementClient, deadline: UInt64) throws {
        for _ in 0..<16 {
            switch try client.readEvent(timeoutMilliseconds: Self.remaining(deadline)) {
            case .commandSucceeded: return
            case .credentialRequired(let kind), .credentialRejected(let kind):
                throw CoordinatorCredentialBlock(kind: kind)
            case .fatal, .commandFailed: throw VPNTunnelCoordinatorError.managementRejected
            case .ready, .hold, .state, .commandCompleted: break
            }
        }
        throw VPNTunnelCoordinatorError.managementRejected
    }

    private static func now() -> UInt64 { clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW) }

    private static func remaining(_ deadline: UInt64) throws -> Int {
        let current = now()
        guard current < deadline else { throw VPNTunnelCoordinatorError.managementUnavailable }
        return max(1, min(10_000, Int((deadline - current) / 1_000_000)))
    }
}

private struct CoordinatorCredentialBlock: Error { let kind: OpenVPNCredentialKind }
