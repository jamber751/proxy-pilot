// Actual presentation adapter/controller; all helper responses and credentials
// are synthetic. No window, real profile, Keychain, socket or service is used.
import Foundation

// The normal adapter initializer is compiled but never used by this fixture.
// Its production transport default is deliberately unavailable in controller
// test builds; keep that branch incapable of opening a real helper session.
extension VPNLiveController {
    convenience init(store: VPNStore) {
        self.init(store: store, openSession: { throw VPNLiveControllerError.unverifiedState })
    }
}

private final class PromptSession: VPNLiveSession {
    var application: VPNApplicationSpec?
    var challenge = VPNCredentialChallenge(generation: 1, kind: .vpnPassword)
    var waiting = false
    var connected = false
    var cancelled = false
    var statusFailure = false
    var submissions = 0
    var generation: UInt64 = 0
    func storeProfile(_ profile: Data) throws -> VPNHelperStatus { .ok }
    func apply(_ specification: VPNApplicationSpec) throws -> VPNHelperStatus { application = specification; return .ok }
    func connect() throws -> (VPNHelperStatus, VPNCredentialChallenge?) {
        generation += 1
        challenge = VPNCredentialChallenge(generation: generation, kind: .vpnPassword)
        waiting = true; connected = false; cancelled = false
        return (.needsCredential, challenge)
    }
    func disconnectTunnel() throws -> VPNHelperStatus { waiting = false; connected = false; return .ok }
    func tunnelStatus() throws -> (VPNHelperStatus, VPNTunnelSnapshot?) {
        if statusFailure { throw NSError(domain: "synthetic status unavailable", code: 1) }
        guard (waiting || connected), let application else {
            return (.ok, VPNTunnelSnapshot(schemaVersion: 2, generation: generation, desiredEnabled: false,
                phase: .off, active: nil, pending: nil, challenge: nil))
        }
        let valid = VPNValidatedApplication(spec: application, requiresVPNCredentials: true, requiresPrivateKeyPassword: false)
        let result = VPNTunnelSnapshot(schemaVersion: 2, generation: generation, desiredEnabled: true,
            phase: waiting ? .needsCredential : .connected, active: connected ? valid : nil,
            pending: waiting ? valid : nil, challenge: waiting ? challenge : nil,
            attempt: VPNConnectAttemptBinding(generation: generation, application: valid),
            issuedCredentialKinds: [.vpnPassword])
        try result.validate()
        return (.ok, result)
    }
    func submitCredentialExchange(_ response: inout VPNCredentialResponse) throws -> (VPNHelperStatus, VPNCredentialChallenge?) {
        submissions += 1
        guard response.challenge == challenge, !response.secret.isEmpty else { return (.invalidRequest, nil) }
        response.secret.resetBytes(in: 0..<response.secret.count); response.secret.removeAll()
        waiting = false; connected = true; return (.ok, nil)
    }
    func cancelCredential(_ challenge: VPNCredentialChallenge) throws -> VPNHelperStatus {
        guard challenge == self.challenge else { return .invalidRequest }
        cancelled = true; waiting = false; return .ok
    }
    func close() {}
}

@main enum VPNPanelCredentialChecks {
    static func require(_ value: @autoclosure () -> Bool, _ message: String) throws {
        guard value() else { throw NSError(domain: message, code: 1) }
    }
    static func wait(_ panel: VPNPanelModel) throws {
        let deadline = Date().addingTimeInterval(3)
        while panel.working, Date() < deadline { RunLoop.main.run(until: Date().addingTimeInterval(0.005)) }
        try require(!panel.working, "adapter operation timed out")
    }
    static func main() throws {
        precondition(Thread.isMainThread)
        let a = CommandLine.arguments
        guard a.count == 3 else { exit(64) }
        let store = VPNStore(directory: URL(fileURLWithPath: a[2], isDirectory: true))
        let profile = try VPNProfileImporter.inspect(data: Data("""
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
        """.utf8), name: "synthetic.ovpn")
        var config = VPNConfiguration()
        try config.setProfile(name: profile.name)
        try config.saveResource(VPNResource(name: "Synthetic", address: "10.20.0.0/16"))
        try config.setAuthentication(VPNAuthentication(mode: a[1] == "password-consent" ? .password : .oneTimePassword,
            login: "employee", credentialPersistence: a[1] == "password-consent" ? .keychain : .none))
        _ = try store.save(config, importing: profile, expectedRevision: nil)
        let configuration = VPNModel(store: store); try configuration.load()
        let session = PromptSession()
        let controller = VPNLiveController(store: store, openSession: { session })
        let panel = VPNPanelModel(configuration: configuration, controller: controller)
        panel.toggle(); try wait(panel)
        try require(panel.needsCredential && controller.credentialPromptIdentifier == session.challenge.identifier, "prompt missing")
        let firstID = controller.credentialPromptIdentifier
        panel.secret = "synthetic draft"
        switch a[1] {
        case "cancel-new-attempt":
            panel.cancelCredential()
            try require(panel.secret.isEmpty, "cancel retained field before asynchronous work")
            try wait(panel)
            try require(session.cancelled && panel.liveState == .off, "cancel did not finish")
            panel.toggle(); try wait(panel)
            try require(panel.secret.isEmpty && panel.needsCredential && controller.credentialPromptIdentifier != firstID,
                        "new attempt inherited old input")
        case "same-prompt-refresh":
            panel.refresh(); try wait(panel)
            try require(panel.secret == "synthetic draft" && controller.credentialPromptIdentifier == firstID,
                        "background refresh erased the current prompt draft")
        case "same-kind-new-request":
            session.challenge = VPNCredentialChallenge(generation: session.generation, kind: .vpnPassword)
            panel.refresh(); try wait(panel)
            try require(panel.needsCredential && panel.secret.isEmpty && controller.credentialPromptIdentifier != firstID,
                        "new request of same kind inherited old input")
            // A refresh observes a new request, but does not transfer its held
            // transport ownership. This proves presentation clearing only;
            // submitting a newly entered secret may require reconnecting.
            panel.submitCredential()
            try require(session.submissions == 0, "old prompt draft was submitted to a new request")
        case "prompt-disappeared":
            session.waiting = false
            panel.refresh(); try wait(panel)
            try require(panel.liveState == .off && panel.secret.isEmpty, "disappeared prompt retained input")
        case "status-failed":
            session.statusFailure = true
            panel.refresh(); try wait(panel)
            try require(panel.liveState == .unavailable && panel.secret.isEmpty, "failed prompt retained input")
        case "network-new-attempt":
            panel.reconnectAfterNetworkChange()
            try require(panel.secret.isEmpty, "new attempt did not clear immediately")
            try wait(panel)
            try require(panel.needsCredential && controller.credentialPromptIdentifier != firstID && panel.secret.isEmpty,
                        "new attempt inherited input")
        case "hide-reopen", "password-consent":
            let auth = configuration.configuration.authentication
            panel.dismissCredentialPrompt()
            try require(panel.secret.isEmpty && panel.needsCredential, "hiding prompt cancelled VPN or kept input")
            panel.refresh(); try wait(panel)
            try require(panel.secret.isEmpty && panel.needsCredential && configuration.configuration.authentication == auth,
                        "hiding changed authentication policy")
            if a[1] == "password-consent" {
                let persisted = try store.load()?.saved.configuration.authentication
                try require(persisted?.mode == .password && persisted?.login == "employee" && persisted?.credentialPersistence == .keychain,
                            "transient clearing changed password persistence consent")
            }
        case "submit":
            panel.submitCredential()
            try require(panel.secret.isEmpty, "submit retained field")
            try wait(panel)
            try require(panel.connected && controller.credentialPromptIdentifier == nil, "completed prompt retained identity")
        default: exit(64)
        }
        print("credential presentation flow passed")
    }
}
