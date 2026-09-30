import Darwin
import Foundation

private let passwordProfile = """
client
dev tun
proto udp
remote vpn.company.example 1194
remote-cert-tls server
auth-user-pass
<ca>
-----BEGIN CERTIFICATE-----
QUJDRA==
-----END CERTIFICATE-----
</ca>
"""

private let certificateProfile = """
client
dev tun
proto udp
remote vpn.company.example 1194
remote-cert-tls server
<ca>
-----BEGIN CERTIFICATE-----
QUJDRA==
-----END CERTIFICATE-----
</ca>
<cert>
-----BEGIN CERTIFICATE-----
QUJDRA==
-----END CERTIFICATE-----
</cert>
<key>
-----BEGIN PRIVATE KEY-----
QUJDRA==
-----END PRIVATE KEY-----
</key>
"""

final class FakeLiveSession: VPNLiveSession {
    let requiresCredential: Bool
    let requiresSecondCredential: Bool
    var application: VPNApplicationSpec?
    var connected = false
    var cancelled = false
    var disconnected = false
    var closed = false
    var challenge = VPNCredentialChallenge(generation: 1, kind: .vpnPassword)
    var submissions = 0

    init(requiresCredential: Bool, requiresSecondCredential: Bool = false) {
        self.requiresCredential = requiresCredential
        self.requiresSecondCredential = requiresSecondCredential
    }
    func storeProfile(_ profile: Data) throws -> VPNHelperStatus { profile.isEmpty ? .invalidRequest : .ok }
    func apply(_ specification: VPNApplicationSpec) throws -> VPNHelperStatus {
        application = specification; return .ok
    }
    func connect() throws -> (VPNHelperStatus, VPNCredentialChallenge?) {
        if requiresCredential { return (.needsCredential, challenge) }
        connected = true; return (.ok, nil)
    }
    func disconnectTunnel() throws -> VPNHelperStatus { disconnected = true; connected = false; return .ok }
    func tunnelStatus() throws -> (VPNHelperStatus, VPNTunnelSnapshot?) {
        guard connected, let application else {
            return (.ok, VPNTunnelSnapshot(schemaVersion: 2, generation: 0,
                desiredEnabled: false, phase: .off, active: nil, pending: nil,
                challenge: nil))
        }
        let validated = VPNValidatedApplication(spec: application,
            requiresVPNCredentials: application.authentication.mode != .certificate,
            requiresPrivateKeyPassword: false)
        let binding = VPNConnectAttemptBinding(generation: 1, application: validated)
        return (.ok, VPNTunnelSnapshot(schemaVersion: 2, generation: 1,
            desiredEnabled: true, phase: .connected, active: validated,
            pending: nil, challenge: nil, attempt: binding,
            issuedCredentialKinds: requiresCredential ? [.vpnPassword] : []))
    }
    func submitCredentialExchange(_ response: inout VPNCredentialResponse) throws
        -> (VPNHelperStatus, VPNCredentialChallenge?) {
        guard response.challenge == challenge, !response.secret.isEmpty else { return (.invalidRequest, nil) }
        response.secret.resetBytes(in: 0..<response.secret.count)
        response.secret.removeAll(keepingCapacity: false)
        submissions += 1
        if requiresSecondCredential && submissions == 1 {
            challenge = VPNCredentialChallenge(generation: 1,
                                               kind: .privateKeyPassword)
            return (.needsCredential, challenge)
        }
        connected = true
        return (.ok, nil)
    }
    func cancelCredential(_ challenge: VPNCredentialChallenge) throws -> VPNHelperStatus {
        guard challenge == self.challenge else { return .invalidRequest }
        cancelled = true; return .ok
    }
    func close() { closed = true }
}

@main enum VPNLiveControllerChecks {
    static func require(_ value: @autoclosure () -> Bool, _ message: String) throws {
        guard value() else { throw NSError(domain: message, code: 1) }
    }

    static func configuredStore(_ path: String, password: Bool,
                                address: String = "10.20.0.0/16") throws -> VPNStore {
        let store = VPNStore(directory: URL(fileURLWithPath: path, isDirectory: true))
        let text = password ? passwordProfile : certificateProfile
        let imported = try VPNProfileImporter.inspect(data: Data(text.utf8), name: "company.ovpn")
        var configuration = VPNConfiguration()
        try configuration.setProfile(name: imported.name)
        try configuration.saveResource(VPNResource(name: "Работа", address: address))
        try configuration.setAuthentication(try VPNAuthentication(
            mode: password ? .oneTimePassword : .certificate,
            login: password ? "employee" : nil))
        _ = try store.save(configuration, importing: imported, expectedRevision: nil)
        return store
    }

    static func main() throws {
        let mode = CommandLine.arguments[1], path = CommandLine.arguments[2]
        switch mode {
        case "certificate":
            let store = try configuredStore(path, password: false)
            let live = FakeLiveSession(requiresCredential: false)
            let controller = VPNLiveController(store: store, openSession: { live })
            controller.connect()
            try require(controller.state == .connected && !controller.busy,
                        "certificate connect was not verified")
            let saved = try store.load()
            try require(saved?.applied?.configuration.desiredEnabled == true,
                        "connected revision was not acknowledged")
            print("certificate flow passed")
        case "credential":
            let store = try configuredStore(path, password: true)
            let live = FakeLiveSession(requiresCredential: true)
            let controller = VPNLiveController(store: store, openSession: { live })
            controller.connect()
            try require(controller.state == .needsCredential(.vpnPassword), "prompt missing")
            var secret = Data("123456".utf8)
            controller.submitCredential(&secret)
            try require(secret.isEmpty && controller.state == .connected,
                        "credential was retained or connection unverified")
            print("credential flow passed")
        case "cancel":
            let store = try configuredStore(path, password: true)
            let live = FakeLiveSession(requiresCredential: true)
            let controller = VPNLiveController(store: store, openSession: { live })
            controller.connect(); controller.cancelCredential()
            let saved = try store.load()
            try require(live.cancelled && controller.state == .off
                        && saved?.saved.configuration.desiredEnabled == false,
                        "cancel did not persist off")
            print("cancel flow passed")
        case "multi-credential":
            let store = try configuredStore(path, password: true)
            let live = FakeLiveSession(requiresCredential: true,
                                       requiresSecondCredential: true)
            let controller = VPNLiveController(store: store, openSession: { live })
            controller.connect()
            var first = Data("123456".utf8)
            controller.submitCredential(&first)
            try require(first.isEmpty
                        && controller.state == .needsCredential(.privateKeyPassword),
                        "second prompt was not propagated")
            var second = Data("key-password".utf8)
            controller.submitCredential(&second)
            try require(second.isEmpty && controller.state == .connected
                        && live.submissions == 2,
                        "multi-prompt flow was not completed")
            print("multi-credential flow passed")
        case "disconnect":
            let store = try configuredStore(path, password: false)
            let first = FakeLiveSession(requiresCredential: false)
            let second = FakeLiveSession(requiresCredential: false)
            let sessions = [first, second]; var index = 0
            let controller = VPNLiveController(store: store, openSession: {
                defer { index += 1 }; return sessions[index]
            })
            controller.connect(); controller.disconnect()
            let saved = try store.load()
            try require(second.disconnected && controller.state == .off
                        && saved?.applied == nil
                        && saved?.saved.configuration.desiredEnabled == false,
                        "disconnect did not prove cleanup and persist off")
            print("disconnect flow passed")
        case "unsupported":
            let store = try configuredStore(path, password: false,
                                            address: "intranet.company.example")
            var opened = false
            let controller = VPNLiveController(store: store, openSession: {
                opened = true; return FakeLiveSession(requiresCredential: false)
            })
            controller.connect()
            try require(!opened && controller.state.label.contains("IP-адреса"),
                        "unsupported domain intent reached helper")
            print("unsupported flow passed")
        default: exit(64)
        }
    }
}
