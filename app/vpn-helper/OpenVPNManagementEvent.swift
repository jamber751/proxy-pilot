import Foundation

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
    case state(OpenVPNConnectionState)
    case hold
    case credentialRequired(OpenVPNCredentialKind)
    case credentialRejected(OpenVPNCredentialKind)
    case commandSucceeded
    case commandFailed
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
