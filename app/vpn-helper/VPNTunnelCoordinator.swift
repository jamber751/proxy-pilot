import Darwin
import Foundation
import os.log

/// Only allowlisted codes enter the system log, never Error descriptions or
/// management output (which can contain account names, endpoints or secrets).
enum VPNStartupDiagnostics {
    enum Stage: String {
        case intent, profile, endpoint, process, management, initialize
        case baseline, releaseHold, credentialPrompt, credentialBinding, bootstrap, routes, cleanup
        case credentialSubmission, credentialCommands, credentialNextPrompt
    }
    private static let log = OSLog(subsystem: "kz.documentolog.proxypilot.vpn", category: "startup")
    static func category(_ error: Error) -> String {
        switch error {
        case let value as VPNEngineProcessError:
            switch value {
            case .invalidSelection: return "engine-selection"
            case .validationFailed: return "engine-validation"
            case .invalidProfile: return "engine-profile"
            case .invalidManagementEndpoint: return "engine-endpoint"
            case .spawnFailed(let code): return "engine-spawn-\(code)"
            case .waitFailed(let code): return "engine-wait-\(code)"
            }
        case is VPNProfileVaultError: return "profile-vault"
        case is VPNManagementSocketReservationError: return "management-reservation"
        case OpenVPNManagementClientError.timeout: return "management-timeout"
        case OpenVPNManagementClientError.closed: return "management-closed"
        case is OpenVPNManagementClientError: return "management-transport"
        case let value as OpenVPNManagementParseError:
            switch value {
            case .malformed, .unsupportedEncoding: return "management-protocol"
            case .invalidStateHeader: return "management-state-header"
            case .invalidConnectedShape(let count): return "management-connected-fields-\(count)"
            case .invalidTunnelAddress: return "management-tunnel-address"
            case .invalidPeerEndpoint: return "management-peer-endpoint"
            case .invalidLocalEndpoint: return "management-local-endpoint"
            }
        case is VPNKernelInterfaceSnapshotError: return "interface-snapshot"
        case let value as VPNTunnelStateStoreError:
            switch value {
            case .unsafeStorage: return "attempt-storage"
            case .invalidState: return "attempt-state"
            case .stale: return "attempt-stale"
            case .writeFailed: return "attempt-write"
            }
        case OpenVPNHeldCredentialExchangeError.engineRejectedCredential: return "credential-rejected"
        case is OpenVPNHeldCredentialExchangeError: return "credential-binding"
        case let value as VPNTunnelCoordinatorError:
            switch value {
            case .invalidState: return "coordinator-state"
            case .engineExited: return "engine-exited"
            case .managementUnavailable: return "management-unavailable"
            case .managementRejected: return "management-rejected"
            case .unsafeBootstrapState: return "bootstrap-state"
            case .unsupportedCredentialPrompt: return "unsupported-prompt"
            }
        case let value as VPNFlowDiagnosticError: return "flow-" + value.vpnFlowFailureCode.rawValue
        default: return "unclassified"
        }
    }
    static func failed(_ stage: Stage, _ error: Error) {
        os_log("VPN startup failed: stage=%{public}@ category=%{public}@", log: log,
               type: .error, stage.rawValue as NSString, category(error) as NSString)
    }
    static func reached(_ stage: Stage) {
        os_log("VPN startup reached: stage=%{public}@", log: log,
               type: .default, stage.rawValue as NSString)
    }
}

enum VPNTunnelCoordinatorBlocker: Equatable {
    case noEnabledConfiguration
    case credentialRequired(OpenVPNCredentialKind)
    case alreadyRunning
    case splitDNSUnavailable
}

/// Proof that the engine completed only its controlled bootstrap. This is not
/// route, DNS, reachability or UI "Connected" authority.
struct VPNTunnelBootstrapProof: Equatable {
    let generation: UInt64
    let management: OpenVPNConnectedEvidence
    let tunnel: VPNTunnelInterfaceEvidence
}

/// Internal runtime evidence. `bootstrapReady` is emitted only after the
/// injected route transaction has committed; the proof value itself remains
/// engine/interface evidence and deliberately carries no DNS authority.
enum VPNTunnelCoordinatorReadiness: Equatable {
    case inactive
    case blocked(VPNTunnelCoordinatorBlocker)
    case processRunning(generation: UInt64)
    case bootstrapReady(VPNTunnelBootstrapProof)
    case stopped(generation: UInt64)
    case failed(generation: UInt64?)
}

enum VPNTunnelCoordinatorError: Error {
    case invalidState, engineExited, managementUnavailable, managementRejected,
         unsafeBootstrapState, unsupportedCredentialPrompt
}

/// Durable state-store boundary for management-driven credentials. The
/// coordinator owns no secret and cannot mint a challenge without the exact
/// attempt generation selected by the store.
struct VPNTunnelCredentialCallbacks {
    let issue: (UInt64, OpenVPNCredentialKind)
        throws -> (VPNCredentialChallenge, VPNValidatedApplication)
    let claim: (VPNCredentialChallenge) throws -> VPNConnectAttemptBinding
    let complete: (VPNConnectAttemptBinding) throws -> Bool
    let outstanding: (UInt64) throws -> Bool
    let fail: () -> Void
}

private enum VPNTunnelLaunchIntent {
    case ready(generation: UInt64, profileDigest: String,
               activateAndInstallRoutes: (VPNTunnelBootstrapProof) throws -> (() throws -> Void))
    case blocked(VPNTunnelCoordinatorBlocker)
}

/// Owns at most one engine, one management connection and one socket inode.
/// Every public operation is serialized. A certificate-only start releases the
/// initial hold once, solely to collect strict tunnel bootstrap evidence.
final class VPNTunnelCoordinator {
    private let lock = NSLock()
    private let intent: () throws -> VPNTunnelLaunchIntent
    private let openProfile: (String) throws -> Int32
    private let selection: VPNEngineExecutableSelection
    private let managementDirectory: Int32
    private let captureInterfaces: () throws -> VPNKernelInterfaceSnapshot
    private let prepareRoutesForProcessStop: () throws -> Void
    private let credentials: VPNTunnelCredentialCallbacks?
    private var process: VPNEngineProcess?
    private var management: OpenVPNManagementClient?
    private var reservation: VPNManagementSocketReservation?
    private var credentialExchange: OpenVPNHeldCredentialExchange?
    private var credentialChallenge: VPNCredentialChallenge?
    private var credentialKind: OpenVPNCredentialKind?
    private var pendingGeneration: UInt64?
    private var pendingRouteActivation:
        ((VPNTunnelBootstrapProof) throws -> (() throws -> Void))?
    private var verifyAppliedRoutes: (() throws -> Void)?
    private var initialHoldReleased = false
    private var attemptBaseline: VPNKernelInterfaceSnapshot?
    private var current: VPNTunnelCoordinatorReadiness = .inactive

    #if !VPN_TUNNEL_COORDINATOR_TESTING
    init(trustedDirectoryDescriptor directory: Int32,
         deployment: VPNAuthorizedDeployment,
         state: VPNTunnelStateStore,
         routeController: VPNTunnelRouteController) throws {
        let vault = try VPNProfileVault(trustedDirectoryDescriptor: directory)
        selection = try VPNEngineExecutableSelection(
            trustedDirectoryDescriptor: directory, deployment: deployment)
        managementDirectory = fcntl(directory, F_DUPFD_CLOEXEC, 64)
        guard managementDirectory >= 0 else { throw VPNTunnelCoordinatorError.invalidState }
        openProfile = { try vault.openValidated(digest: $0) }
        captureInterfaces = { try VPNKernelInterfaceSnapshot.capture() }
        credentials = VPNTunnelCredentialCallbacks(issue: { generation, prompt in
            let kind: VPNCredentialKind
            switch prompt {
            case .privateKeyPassphrase: kind = .privateKeyPassword
            case .usernameAndPassword: kind = .vpnPassword
            case .staticChallenge: throw VPNTunnelCoordinatorError.unsupportedCredentialPrompt
            }
            let snapshot = try state.load()
            guard let binding = snapshot.attempt, binding.generation == generation else {
                throw VPNTunnelCoordinatorError.invalidState
            }
            return (try state.issueChallenge(binding: binding, kind: kind), binding.application)
        }, claim: { try state.claimCredential($0) }, complete: { binding in
            let snapshot = try state.completeCredentialPrompt(binding: binding)
            let issued = Set(snapshot.issuedCredentialKinds.map(\.rawValue))
            let application = binding.application
            return (!application.requiresPrivateKeyPassword
                    || issued.contains(VPNCredentialKind.privateKeyPassword.rawValue))
                && (!application.requiresVPNCredentials
                    || issued.contains(VPNCredentialKind.vpnPassword.rawValue))
        }, outstanding: { generation in
            let snapshot = try state.load()
            guard let binding = snapshot.attempt, binding.generation == generation else {
                throw VPNTunnelCoordinatorError.invalidState
            }
            let issued = Set(snapshot.issuedCredentialKinds.map(\.rawValue))
            return (binding.application.requiresPrivateKeyPassword
                    && !issued.contains(VPNCredentialKind.privateKeyPassword.rawValue))
                || (binding.application.requiresVPNCredentials
                    && !issued.contains(VPNCredentialKind.vpnPassword.rawValue))
        }, fail: { _ = try? state.failCurrent() })
        intent = {
            let snapshot = try state.load()
            guard snapshot.desiredEnabled else {
                return .blocked(.noEnabledConfiguration)
            }
            guard snapshot.phase == .connecting,
                  let binding = snapshot.attempt,
                  binding.application == (snapshot.pending ?? snapshot.active) else {
                throw VPNTunnelCoordinatorError.invalidState
            }
            do { try binding.application.spec.validateCurrentRuntimeCapability() }
            catch VPNRuntimeCapabilityError.splitDNSUnavailable {
                return .blocked(.splitDNSUnavailable)
            }
            return .ready(generation: binding.generation,
                          profileDigest: binding.application.spec.profileSHA256,
                          activateAndInstallRoutes: { proof in
                              let exact = try state.activateForRouting(binding)
                              let routes = try routeController.install(
                                  bootstrap: proof, activeApplication: exact)
                              _ = try state.markConnected(binding)
                              return { try routeController.verifyApplied(routes) }
                          })
        }
        prepareRoutesForProcessStop = { try routeController.prepareForProcessStop() }
    }
    #else
    init(testDirectory directory: Int32, selection: VPNEngineExecutableSelection,
         generation: UInt64 = 1, profileDigest: String,
         openProfile: @escaping (String) throws -> Int32,
         captureInterfaces: @escaping () throws -> VPNKernelInterfaceSnapshot,
         blocker: VPNTunnelCoordinatorBlocker? = nil,
         activateAndInstallRoutes: @escaping (VPNTunnelBootstrapProof) throws -> Void = { _ in },
         prepareRoutesForProcessStop: @escaping () throws -> Void = {},
         credentials: VPNTunnelCredentialCallbacks? = nil) throws {
        self.selection = selection
        managementDirectory = fcntl(directory, F_DUPFD_CLOEXEC, 64)
        guard managementDirectory >= 0 else { throw VPNTunnelCoordinatorError.invalidState }
        self.openProfile = openProfile
        self.captureInterfaces = captureInterfaces
        self.prepareRoutesForProcessStop = prepareRoutesForProcessStop
        self.credentials = credentials
        intent = {
            if let blocker = blocker { return .blocked(blocker) }
            return .ready(generation: generation, profileDigest: profileDigest,
                          activateAndInstallRoutes: { proof in
                              try activateAndInstallRoutes(proof)
                              return {}
                          })
        }
    }
    #endif

    deinit {
        lock.lock()
        // Route cleanup is a hard barrier for every explicit stop. If teardown
        // itself follows an unprovable cleanup, keep the durable journal for
        // next-start recovery; VPNEngineProcess's own deinit remains the final
        // crash-equivalent child safety net.
        _ = try? stopLocked()
        lock.unlock()
        if managementDirectory >= 0 { close(managementDirectory) }
    }

    func readiness() -> VPNTunnelCoordinatorReadiness {
        lock.lock(); defer { lock.unlock() }
        return current
    }

    func ownsProcess() -> Bool {
        lock.lock(); defer { lock.unlock() }
        return process != nil
    }

    func start(timeoutMilliseconds: Int = 5_000) throws -> VPNTunnelCoordinatorReadiness {
        lock.lock(); defer { lock.unlock() }
        guard process == nil, management == nil, reservation == nil else {
            return .blocked(.alreadyRunning)
        }
        let launch: VPNTunnelLaunchIntent
        do { launch = try intent() }
        catch { VPNStartupDiagnostics.failed(.intent, error); throw error }
        guard case .ready(let generation, let digest, let activateRoutes) = launch else {
            if case .blocked(let blocker) = launch { current = .blocked(blocker) }
            return current
        }
        guard (1...10_000).contains(timeoutMilliseconds) else {
            throw VPNTunnelCoordinatorError.invalidState
        }
        let now = clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW)
        let deadline = now + UInt64(timeoutMilliseconds) * 1_000_000

        var stage = VPNStartupDiagnostics.Stage.profile
        do {
            VPNStartupDiagnostics.reached(stage)
            let profile = try openProfile(digest)
            defer { close(profile) }
            stage = .endpoint
            VPNStartupDiagnostics.reached(stage)
            let socket = try VPNManagementSocketReservation(
                trustedDirectoryDescriptor: managementDirectory)
            reservation = socket
            stage = .process
            VPNStartupDiagnostics.reached(stage)
            let child = try VPNEngineProcess.start(selection: selection,
                protectedProfileDescriptor: profile, management: socket.configuration)
            // Retain process ownership before any fallible management or route
            // step. If route cleanup later cannot be proven, unwinding start()
            // must not deinitialize and implicitly stop this child.
            process = child
            current = .processRunning(generation: generation)
            stage = .management
            VPNStartupDiagnostics.reached(stage)
            let client = try connect(socket: socket, process: child, deadline: deadline)
            management = client
            stage = .initialize
            VPNStartupDiagnostics.reached(stage)
            _ = try initialize(client: client, deadline: deadline)
            if try credentials?.outstanding(generation) == true {
                // Real OpenVPN asks for Auth only after its initial hold is
                // released. Capture interface evidence first and release once;
                // the credential prompt itself blocks further bootstrap.
                stage = .baseline
                VPNStartupDiagnostics.reached(stage)
                attemptBaseline = try captureInterfaces()
                stage = .releaseHold
                VPNStartupDiagnostics.reached(stage)
                try releaseInitialHold(client, deadline: deadline)
                _ = try awaitSuccess(client, deadline: deadline)
                stage = .credentialPrompt
                VPNStartupDiagnostics.reached(stage)
                let kind = try awaitNextCredentialPrompt(client, deadline: deadline)
                stage = .credentialBinding
                try parkCredentialPrompt(kind, generation: generation, client: client,
                                         activateRoutes: activateRoutes)
                current = .blocked(.credentialRequired(kind))
                VPNStartupDiagnostics.reached(stage)
                return current
            }
            stage = .baseline
            let baseline = try attemptBaseline ?? captureInterfaces()
            stage = .bootstrap
            VPNStartupDiagnostics.reached(stage)
            let proof = try bootstrap(client: client, generation: generation,
                                      baseline: baseline, deadline: deadline)
            stage = .routes
            VPNStartupDiagnostics.reached(stage)
            verifyAppliedRoutes = try activateRoutes(proof)
            current = .bootstrapReady(proof)
            return current
        } catch let blocker as CoordinatorCredentialBlock {
            guard credentials != nil, let client = management else {
                try stopLocked()
                current = .blocked(.credentialRequired(blocker.kind))
                return current
            }
            do {
                try parkCredentialPrompt(blocker.kind, generation: generation, client: client,
                                         activateRoutes: activateRoutes)
                current = .blocked(.credentialRequired(blocker.kind))
                return current
            } catch let promptError {
                VPNStartupDiagnostics.failed(.credentialBinding, promptError)
                current = .failed(generation: generation)
                credentials?.fail()
                do { try stopLocked() } catch { throw error }
                throw promptError
            }
        } catch let startError {
            VPNStartupDiagnostics.failed(stage, startError)
            current = .failed(generation: generation)
            credentials?.fail()
            do { try stopLocked() }
            catch let cleanupError {
                VPNStartupDiagnostics.failed(.cleanup, cleanupError)
                throw cleanupError
            }
            throw startError
        }
    }

    /// Claims durable one-shot authority before constructing or writing the
    /// transient command. On success either the next real prompt is parked or
    /// the initial hold is released exactly once and bootstrap continues.
    func submitCredential(_ response: inout VPNCredentialResponse,
                          timeoutMilliseconds: Int = 5_000) throws
        -> VPNTunnelCoordinatorReadiness {
        lock.lock(); defer { lock.unlock() }
        guard let callbacks = credentials, let client = management,
              let child = process, let exchange = credentialExchange,
              let challenge = credentialChallenge, let kind = credentialKind,
              let generation = pendingGeneration,
              let activateRoutes = pendingRouteActivation else {
            response.secret.resetBytes(in: 0..<response.secret.count)
            response.secret.removeAll(keepingCapacity: false)
            throw VPNTunnelCoordinatorError.invalidState
        }
        guard response.challenge == challenge,
              (1...10_000).contains(timeoutMilliseconds) else {
            response.secret.resetBytes(in: 0..<response.secret.count)
            response.secret.removeAll(keepingCapacity: false)
            callbacks.fail()
            current = .failed(generation: generation)
            do { try stopLocked() } catch { throw error }
            throw VPNTunnelCoordinatorError.invalidState
        }
        let deadline = Self.now() + UInt64(timeoutMilliseconds) * 1_000_000
        var stage = VPNStartupDiagnostics.Stage.credentialSubmission
        do {
            VPNStartupDiagnostics.reached(stage)
            guard try child.state() == .running else { throw VPNTunnelCoordinatorError.engineExited }
            // This durable transition burns UUID/generation/kind before any
            // secret object exists and therefore before a management write.
            let binding = try callbacks.claim(challenge)
            let transient = try OpenVPNTransientCredential(
                response: &response, application: binding.application)
            try exchange.submit(transient)
            credentialExchange = nil; credentialChallenge = nil; credentialKind = nil
            stage = .credentialCommands
            VPNStartupDiagnostics.reached(stage)
            try awaitCredentialCommandSuccesses(client, kind: kind, deadline: deadline)
            let complete = try callbacks.complete(binding)
            if !complete {
                stage = .credentialNextPrompt
                VPNStartupDiagnostics.reached(stage)
                let next = try awaitNextCredentialPrompt(client, deadline: deadline)
                try parkCredentialPrompt(next, generation: generation, client: client,
                                         activateRoutes: activateRoutes)
                current = .blocked(.credentialRequired(next))
                return current
            }
            stage = .baseline
            let baseline = try attemptBaseline ?? captureInterfaces()
            stage = .bootstrap
            VPNStartupDiagnostics.reached(stage)
            let proof = try bootstrap(client: client, generation: generation,
                                      baseline: baseline, deadline: deadline)
            stage = .routes
            VPNStartupDiagnostics.reached(stage)
            verifyAppliedRoutes = try activateRoutes(proof)
            pendingGeneration = nil; pendingRouteActivation = nil
            current = .bootstrapReady(proof)
            VPNStartupDiagnostics.reached(stage)
            return current
        } catch let submissionError {
            VPNStartupDiagnostics.failed(stage, submissionError)
            response.secret.resetBytes(in: 0..<response.secret.count)
            response.secret.removeAll(keepingCapacity: false)
            callbacks.fail()
            current = .failed(generation: generation)
            do { try stopLocked() } catch { throw error }
            throw submissionError
        }
    }

    func observe(timeoutMilliseconds: Int = 2_000) throws -> VPNTunnelCoordinatorReadiness {
        lock.lock(); defer { lock.unlock() }
        guard let client = management, let child = process,
              let verifyRoutes = verifyAppliedRoutes,
              case .bootstrapReady(let proof) = current else {
            throw VPNTunnelCoordinatorError.invalidState
        }
        let generation = proof.generation
        do { try verifyRoutes() }
        catch {
            current = .failed(generation: generation)
            credentials?.fail()
            do { try stopLocked() } catch { throw error }
            throw error
        }
        guard try child.state() == .running else {
            credentials?.fail()
            try stopLocked(); current = .failed(generation: generation); return current
        }
        let event: OpenVPNManagementEvent
        do { event = try client.readEvent(timeoutMilliseconds: timeoutMilliseconds) }
        catch {
            credentials?.fail()
            try stopLocked()
            current = .failed(generation: generation)
            throw error
        }
        switch event {
        case .state(let evidence) where evidence.state == .connected:
            guard evidence.connected == proof.management else {
                credentials?.fail()
                try stopLocked(); current = .failed(generation: generation); return current
            }
        case .state:
            credentials?.fail()
            try stopLocked(); current = .failed(generation: generation)
        case .credentialRequired(let kind), .credentialRejected(let kind):
            credentials?.fail()
            try stopLocked(); current = .blocked(.credentialRequired(kind))
        case .fatal, .commandFailed, .hold:
            credentials?.fail()
            try stopLocked(); current = .failed(generation: generation)
        case .ready, .commandSucceeded, .commandCompleted: break
        }
        return current
    }

    @discardableResult
    func stop() throws -> VPNTunnelCoordinatorReadiness {
        lock.lock(); defer { lock.unlock() }
        let generation: UInt64
        switch current {
        case .processRunning(let value), .stopped(let value):
            generation = value
        case .bootstrapReady(let proof): generation = proof.generation
        default: generation = 0
        }
        try stopLocked()
        current = .stopped(generation: generation)
        return current
    }

    private func stopLocked() throws {
        // This must succeed before any management signal, control-channel
        // close or supervisor stop. On failure all ownership remains intact.
        if process != nil { try prepareRoutesForProcessStop() }
        if let client = management { try? client.send(.gracefulStop, timeoutMilliseconds: 250) }
        management?.close()
        _ = try? process?.stop(graceMilliseconds: 500)
        reservation?.cleanup()
        credentialExchange = nil; credentialChallenge = nil; credentialKind = nil
        pendingGeneration = nil; pendingRouteActivation = nil
        verifyAppliedRoutes = nil
        initialHoldReleased = false; attemptBaseline = nil
        management = nil; process = nil; reservation = nil
    }

    private func parkCredentialPrompt(_ kind: OpenVPNCredentialKind,
                                      generation: UInt64,
                                      client: OpenVPNManagementClient,
                                      activateRoutes: @escaping
                                        (VPNTunnelBootstrapProof) throws
                                            -> (() throws -> Void)) throws {
        guard credentialExchange == nil, credentialChallenge == nil,
              let callbacks = credentials else {
            throw VPNTunnelCoordinatorError.invalidState
        }
        guard kind != .staticChallenge else {
            throw VPNTunnelCoordinatorError.unsupportedCredentialPrompt
        }
        let issued = try callbacks.issue(generation, kind)
        let exchange = try OpenVPNHeldCredentialExchange(
            challenge: issued.0, application: issued.1, transport: client)
        try exchange.observe(.credentialRequired(kind))
        credentialExchange = exchange
        credentialChallenge = issued.0
        credentialKind = kind
        pendingGeneration = generation
        pendingRouteActivation = activateRoutes
    }

    private func awaitCredentialCommandSuccesses(_ client: OpenVPNManagementClient,
                                                 kind: OpenVPNCredentialKind,
                                                 deadline: UInt64) throws {
        let expected = kind == .usernameAndPassword ? 2 : 1
        var accepted = 0
        for _ in 0..<16 {
            switch try client.readEvent(timeoutMilliseconds: Self.remaining(deadline)) {
            case .commandSucceeded:
                accepted += 1
                if accepted == expected { return }
            case .credentialRejected:
                throw OpenVPNHeldCredentialExchangeError.engineRejectedCredential
            case .credentialRequired, .fatal, .commandFailed, .commandCompleted:
                throw VPNTunnelCoordinatorError.managementRejected
            case .state(let evidence):
                guard evidence.state != .connected, evidence.state != .reconnecting,
                      evidence.state != .exiting else {
                    throw VPNTunnelCoordinatorError.unsafeBootstrapState
                }
            case .ready, .hold: break
            }
        }
        throw VPNTunnelCoordinatorError.managementRejected
    }

    private func awaitNextCredentialPrompt(_ client: OpenVPNManagementClient,
                                           deadline: UInt64) throws
        -> OpenVPNCredentialKind {
        for _ in 0..<32 {
            switch try client.readEvent(timeoutMilliseconds: Self.remaining(deadline)) {
            case .credentialRequired(let kind):
                guard kind != .staticChallenge else {
                    throw VPNTunnelCoordinatorError.unsupportedCredentialPrompt
                }
                return kind
            case .credentialRejected:
                throw OpenVPNHeldCredentialExchangeError.engineRejectedCredential
            case .fatal, .commandFailed:
                throw VPNTunnelCoordinatorError.managementRejected
            case .state(let evidence):
                guard evidence.state != .connected, evidence.state != .reconnecting,
                      evidence.state != .exiting else {
                    throw VPNTunnelCoordinatorError.unsafeBootstrapState
                }
            case .ready, .hold, .commandSucceeded, .commandCompleted: break
            }
        }
        throw VPNTunnelCoordinatorError.managementRejected
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
        var sawInitialHold = try awaitSuccess(client, deadline: deadline)
        try client.send(.requestCurrentState, timeoutMilliseconds: Self.remaining(deadline))
        var state: OpenVPNConnectionState?
        for _ in 0..<16 {
            switch try client.readEvent(timeoutMilliseconds: Self.remaining(deadline)) {
            case .state(let evidence):
                guard evidence.state != .connected, evidence.state != .reconnecting,
                      evidence.state != .exiting else {
                    throw VPNTunnelCoordinatorError.unsafeBootstrapState
                }
                state = evidence.state
            case .commandCompleted:
                guard sawInitialHold, let state = state else {
                    throw VPNTunnelCoordinatorError.managementRejected
                }
                return state
            case .credentialRequired(let kind), .credentialRejected(let kind):
                throw CoordinatorCredentialBlock(kind: kind)
            case .fatal, .commandFailed: throw VPNTunnelCoordinatorError.managementRejected
            case .hold: sawInitialHold = true
            case .ready, .commandSucceeded: break
            }
        }
        throw VPNTunnelCoordinatorError.managementRejected
    }

    private func awaitSuccess(_ client: OpenVPNManagementClient, deadline: UInt64) throws -> Bool {
        var sawHold = false
        for _ in 0..<16 {
            switch try client.readEvent(timeoutMilliseconds: Self.remaining(deadline)) {
            case .commandSucceeded: return sawHold
            case .credentialRequired(let kind), .credentialRejected(let kind):
                throw CoordinatorCredentialBlock(kind: kind)
            case .fatal, .commandFailed: throw VPNTunnelCoordinatorError.managementRejected
            case .state(let evidence):
                guard evidence.state != .connected, evidence.state != .reconnecting,
                      evidence.state != .exiting else {
                    throw VPNTunnelCoordinatorError.unsafeBootstrapState
                }
            case .hold: sawHold = true
            case .ready, .commandCompleted: break
            }
        }
        throw VPNTunnelCoordinatorError.managementRejected
    }

    /// Releases the initial management hold exactly once and returns only
    /// internal evidence. The caller must still install owned routes and DNS
    /// before any externally visible connected state can be published.
    private func bootstrap(client: OpenVPNManagementClient, generation: UInt64,
                           baseline: VPNKernelInterfaceSnapshot, deadline: UInt64) throws
        -> VPNTunnelBootstrapProof {
        var releaseAccepted = initialHoldReleased
        if !initialHoldReleased {
            try releaseInitialHold(client, deadline: deadline)
        }
        var connected: OpenVPNConnectedEvidence?
        for _ in 0..<64 {
            switch try client.readEvent(timeoutMilliseconds: Self.remaining(deadline)) {
            case .commandSucceeded:
                guard !releaseAccepted else { throw VPNTunnelCoordinatorError.managementRejected }
                releaseAccepted = true
            case .state(let evidence):
                switch evidence.state {
                case .connected:
                    guard connected == nil, let value = evidence.connected else {
                        throw VPNTunnelCoordinatorError.unsafeBootstrapState
                    }
                    connected = value
                case .reconnecting, .exiting:
                    throw VPNTunnelCoordinatorError.unsafeBootstrapState
                default: break
                }
            case .credentialRequired(let kind), .credentialRejected(let kind):
                throw CoordinatorCredentialBlock(kind: kind)
            case .hold:
                throw VPNTunnelCoordinatorError.unsafeBootstrapState
            case .fatal, .commandFailed, .commandCompleted:
                throw VPNTunnelCoordinatorError.managementRejected
            case .ready: break
            }
            if releaseAccepted, let management = connected {
                let tunnel = try resolveTunnel(baseline: baseline, management: management,
                                               deadline: deadline)
                return VPNTunnelBootstrapProof(generation: generation,
                                               management: management, tunnel: tunnel)
            }
        }
        throw VPNTunnelCoordinatorError.managementRejected
    }

    private func releaseInitialHold(_ client: OpenVPNManagementClient,
                                    deadline: UInt64) throws {
        guard !initialHoldReleased else { throw VPNTunnelCoordinatorError.invalidState }
        try client.send(.releaseHold, timeoutMilliseconds: Self.remaining(deadline))
        initialHoldReleased = true
    }

    private func resolveTunnel(baseline: VPNKernelInterfaceSnapshot,
                               management: OpenVPNConnectedEvidence,
                               deadline: UInt64) throws -> VPNTunnelInterfaceEvidence {
        while true {
            let after = try captureInterfaces()
            do {
                return try VPNTunnelInterfaceResolver.resolve(
                    baseline: baseline, after: after, management: management)
            } catch VPNTunnelInterfaceResolutionError.noCandidate {
                guard Self.now() < deadline else { throw VPNTunnelInterfaceResolutionError.noCandidate }
                usleep(5_000)
            }
        }
    }

    private static func now() -> UInt64 { clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW) }

    private static func remaining(_ deadline: UInt64) throws -> Int {
        let current = now()
        guard current < deadline else { throw VPNTunnelCoordinatorError.managementUnavailable }
        return max(1, min(10_000, Int((deadline - current) / 1_000_000)))
    }
}

private struct CoordinatorCredentialBlock: Error { let kind: OpenVPNCredentialKind }
