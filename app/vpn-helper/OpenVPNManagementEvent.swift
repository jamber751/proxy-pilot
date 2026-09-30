import Foundation
import os.log

/// Logging accepts only closed enums and numeric OS error codes. Never pass
/// Error descriptions, management lines, credentials or endpoint strings.
enum VPNFlowFailureCode: String {
    case unknown, invalidBootstrap, staleGeneration, inactiveApplication
    case applicationMismatch, peerRouteUsesTunnel, alreadyApplied, recoveryRequired
    case invalidPlan, preexistingRoute, cleanupBlocked, notApplied
    case invalidIdentity, malformedMessage, responseLimit, timeout, transport, closed
    case kernel, preexistingNonIdentical, missingOrForeign, verificationFailed
    case invalidPeer, unusableRoute
    case invalidGeneration, invalidRevision, unsupportedResource, duplicate, overlap
    case peerWouldBeCaptured, invalidPeerEvidence, invalidKernelEvidence, invalidTunnelEvidence
    case unsafeStorage, missing, alreadyExists, invalidState, stale, writeFailed, removeFailed
}
protocol VPNFlowDiagnosticError: Error {
    var vpnFlowFailureCode: VPNFlowFailureCode { get }
    var vpnFlowErrorNumber: Int32 { get }
}
extension VPNFlowDiagnosticError { var vpnFlowErrorNumber: Int32 { 0 } }

enum VPNFlowDiagnostics {
    enum Stage: String {
        case controllerInstall, controllerRecovery, controllerApplication
        case controllerIntent, controllerBootstrap, controllerPeer, controllerPlan
        case controllerTransaction, controllerVerify, controllerCleanup, controllerAuthority
        case transactionInstall, transactionPreflight, transactionJournal
        case transactionCheckpoint, transactionAdd, transactionVerify, transactionRecovery
        case kernelLookup, kernelAdd, kernelDelete, peerLookup
    }
    private static let log = OSLog(subsystem: "kz.documentolog.proxypilot.vpn", category: "flow")
    static func failureCode(_ error: Error) -> VPNFlowFailureCode {
        (error as? VPNFlowDiagnosticError)?.vpnFlowFailureCode ?? .unknown
    }
    static func run<T>(_ stage: Stage, _ body: () throws -> T) throws -> T {
        os_log("VPN flow begin: stage=%{public}@", log: log, type: .info, stage.rawValue as NSString)
        do {
            let result = try body()
            os_log("VPN flow complete: stage=%{public}@", log: log, type: .info, stage.rawValue as NSString)
            return result
        } catch {
            os_log("VPN flow failed: stage=%{public}@ code=%{public}@ osCode=%{public}d", log: log,
                type: .error, stage.rawValue as NSString, failureCode(error).rawValue as NSString,
                (error as? VPNFlowDiagnosticError)?.vpnFlowErrorNumber ?? 0)
            throw error
        }
    }
    static func managementCode(_ event: OpenVPNManagementEvent) -> String {
        let code: String
        switch event {
        case .ready: code = "ready"
        case .state(let evidence): code = "state-" + evidence.state.rawValue
        case .hold: code = "hold"
        case .credentialRequired(.usernameAndPassword): code = "auth-required"
        case .credentialRequired(.privateKeyPassphrase): code = "key-required"
        case .credentialRequired(.staticChallenge): code = "static-challenge-required"
        case .credentialRejected: code = "credential-rejected"
        case .commandSucceeded: code = "command-succeeded"
        case .commandFailed: code = "command-failed"
        case .commandCompleted: code = "command-completed"
        case .fatal: code = "fatal"
        }
        return code
    }
    static func management(_ event: OpenVPNManagementEvent) {
        os_log("VPN management event: %{public}@", log: log, type: .info, managementCode(event) as NSString)
    }
    static func route(_ stage: Stage, ordinal: Int, peer: Bool) {
        os_log("VPN route step: stage=%{public}@ ordinal=%{public}d role=%{public}@", log: log,
            type: .info, stage.rawValue as NSString, Int32(clamping: ordinal),
            (peer ? "peer-bypass" : "selected-resource") as NSString)
    }
    static func command(_ command: OpenVPNManagementCommand) {
        let code: String
        switch command {
        case .enableStateNotifications: code = "state-notifications"
        case .requestCurrentState: code = "state-request"
        case .enableHold: code = "hold-enable"
        case .releaseHold: code = "hold-release"
        case .gracefulStop: code = "graceful-stop"
        }
        os_log("VPN management command written: %{public}@", log: log, type: .info, code as NSString)
    }
    static func credentialWritten() {
        os_log("VPN credential command written (contents omitted)", log: log, type: .info)
    }
}

/// A deliberately small, redacted view of the OpenVPN management protocol.
/// Raw management lines, diagnostic text and credential values never cross
/// this boundary.
enum OpenVPNConnectionState: String, Equatable {
    case initial = "INITIAL"
    case connecting = "CONNECTING"
    case resolving = "RESOLVE"
    case tcpConnecting = "TCP_CONNECT"
    case waiting = "WAIT"
    case authenticating = "AUTH"
    case authenticationPending = "AUTH_PENDING"
    case fetchingConfiguration = "GET_CONFIG"
    case assigningAddress = "ASSIGN_IP"
    case addingRoutes = "ADD_ROUTES"
    case connected = "CONNECTED"
    case reconnecting = "RECONNECTING"
    case exiting = "EXITING"
}

enum OpenVPNCredentialKind: Equatable {
    case usernameAndPassword
    case privateKeyPassphrase
    case staticChallenge
}

enum OpenVPNManagementEvent: Equatable {
    case ready
    case state(OpenVPNStateEvidence)
    case hold
    case credentialRequired(OpenVPNCredentialKind)
    case credentialRejected(OpenVPNCredentialKind)
    case commandSucceeded
    case commandFailed
    case commandCompleted
    case fatal
}

enum OpenVPNManagementCommand: Equatable {
    case enableStateNotifications
    case requestCurrentState
    case enableHold
    case releaseHold
    case gracefulStop

    var bytes: [UInt8] {
        let command: String
        switch self {
        case .enableStateNotifications: command = "state on\n"
        case .requestCurrentState: command = "state\n"
        case .enableHold: command = "hold on\n"
        case .releaseHold: command = "hold release\n"
        case .gracefulStop: command = "signal SIGTERM\n"
        }
        return Array(command.utf8)
    }
}
