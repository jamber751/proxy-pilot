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
        guard waiting, response.challenge == challenge, !response.secret.isEmpty else { return (.invalidRequest, nil) }
        response.secret.resetBytes(in: 0..<response.secret.count); response.secret.removeAll()
        waiting = false; connected = true; return (.ok, nil)
    }
    func cancelCredential(_ challenge: VPNCredentialChallenge) throws -> VPNHelperStatus {
        guard challenge == self.challenge else { return .invalidRequest }
        cancelled = true; waiting = false; return .ok
    }
    func close() {}
}

private final class PanelPasswordSession: VPNPasswordPersistenceSession {
    var adds = 0
    func read(store: VPNStore, reference: VPNPasswordReference, revision: UInt64) throws -> Data? { nil }
    func addOnce(store: VPNStore, reference: VPNPasswordReference, revision: UInt64,
                 secret: inout Data) throws -> VPNPasswordAddOutcome {
        try store.addPasswordOnce(reference: reference, expectedRevision: revision) { reference in
            adds += 1
            return .added(VPNPasswordItemLocator(persistentReference: Data(reference.itemID.uuidString.utf8),
                origin: VPNPasswordBackendLocator(kind: .legacyKeychain, path: "/synthetic/panel.keychain",
                    device: 1, inode: 1, ownerUID: getuid(), birthSeconds: 1, birthNanoseconds: 0)))
        }
    }
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
        let editingAuthentication = a[1].hasPrefix("auth-")
        let testingConsent = a[1].hasPrefix("consent-")
        let testingFeedback = a[1].hasPrefix("feedback-")
        let staticPassword = editingAuthentication || testingConsent || testingFeedback || a[1] == "password-consent"
        let hasConsent = testingConsent ? a[1] == "consent-revoke" : staticPassword && !a[1].hasSuffix("default")
        try config.setAuthentication(VPNAuthentication(mode: staticPassword ? .password : .oneTimePassword,
            login: "employee", credentialPersistence: hasConsent ? .keychain : .none))
        _ = try store.save(config, importing: profile, expectedRevision: nil)
        let configuration = VPNModel(store: store); try configuration.load()
        let session = PromptSession()
        let passwordSession = PanelPasswordSession()
        var queuedSaves: [() -> Void] = []
        let prepareGate = DispatchSemaphore(value: 0)
        let cache = testingFeedback ? VPNPasswordPersistenceCoordinator(store: store,
            available: a[1] != "feedback-inert", prepare: { _ in
                if a[1] == "feedback-saving" {
                    guard prepareGate.wait(timeout: .now() + 2) == .success else {
                        throw NSError(domain: "synthetic prepare timed out", code: 1)
                    }
                }
                return a[1] == "feedback-unconfirmed" ? nil : passwordSession
            }, schedule: { queuedSaves.append($0) }) : testingConsent ? VPNPasswordPersistenceCoordinator(store: store,
            available: a[1] != "consent-unavailable") : nil
        let controller = VPNLiveController(store: store, passwordPersistence: cache, openSession: { session })
        let panel = VPNPanelModel(configuration: configuration, controller: controller)
        if testingFeedback {
            try require(panel.passwordPersistenceDetail == nil, "feedback invented before connection")
            panel.toggle(); try wait(panel)
            panel.secret = "synthetic static password"
            panel.submitCredential(expectedPromptIdentifier: panel.credentialPromptIdentifier); try wait(panel)
            try require(panel.connected && panel.secret.isEmpty && panel.message.isEmpty,
                        "feedback affected VPN state or retained input")
            if a[1] == "feedback-inert" {
                try require(queuedSaves.isEmpty && panel.passwordPersistenceDetail == nil, "inert driver displayed feedback")
            } else {
                try require(queuedSaves.count == 1, "verified save not queued")
                if a[1] == "feedback-saving" {
                    let work = queuedSaves.removeFirst()
                    let finished = DispatchSemaphore(value: 0)
                    DispatchQueue(label: "synthetic.password-save").async { work(); finished.signal() }
                    let deadline = Date().addingTimeInterval(1)
                    while panel.passwordPersistenceDetail != "Сохраняем пароль…", Date() < deadline {
                        RunLoop.main.run(until: Date().addingTimeInterval(0.005))
                    }
                    let showedSaving = panel.passwordPersistenceDetail == "Сохраняем пароль…" && panel.connected
                    prepareGate.signal()
                    try require(finished.wait(timeout: .now() + 2) == .success, "background save did not finish")
                    try require(showedSaving, "background saving phase was not presented")
                } else { queuedSaves.removeFirst()() }
                RunLoop.main.run(until: Date().addingTimeInterval(0.03))
                let expected = a[1] == "feedback-unconfirmed"
                    ? "Сохранение пароля не подтверждено." : "Пароль сохранён в Связке ключей."
                try require(panel.passwordPersistenceDetail == expected && panel.statusDetail.contains(expected),
                            "latest phase missing or earlier queued saving replaced terminal phase")
                if a[1] == "feedback-revoke" {
                    try configuration.setAuthentication(mode: .password, login: "employee", credentialPersistence: .none)
                    try require(panel.passwordPersistenceDetail == nil && !panel.statusDetail.contains("Связке"),
                                "revoked consent retained stale saved feedback")
                } else if a[1] == "feedback-disconnect" {
                    panel.toggle(); try wait(panel)
                    try require(panel.passwordPersistenceDetail == nil && panel.liveState == .off,
                                "disconnected intent retained stale feedback")
                }
                try require(panel.connected || a[1] == "feedback-disconnect", "save warning disconnected VPN")
                try require(passwordSession.adds == (a[1] == "feedback-unconfirmed" ? 0 : 1), "wrong cache side effects")
            }
            print("credential presentation flow passed"); return
        }
        if testingConsent {
            panel.settings = true; panel.beginAuthentication()
            try require(!panel.passwordPersistenceSelected || hasConsent, "save was enabled by default")
            panel.choosePasswordPersistence(a[1] != "consent-revoke")
            switch a[1] {
            case "consent-cancel": panel.cancelAuthentication()
            case "consent-login": panel.login = "another-employee"
            case "consent-case": panel.login = "Employee"
            case "consent-whitespace": panel.login = "  employee  "
            case "consent-otp": panel.selectAuthentication(.oneTimePassword)
            default: break
            }
            if a[1] == "consent-cancel" { panel.finishSettings() } else { panel.saveAuthentication() }
            try require(panel.message.isEmpty, "explicit save edit failed")
            let saved = try store.load()!
            let expectsConsent = a[1] == "consent-opt-in" || a[1] == "consent-whitespace"
            let expectedPersistence: VPNCredentialPersistence = expectsConsent ? .keychain : .none
            try require(saved.saved.configuration.authentication?.credentialPersistence == expectedPersistence,
                        "save consent crossed login/mode/cancel/capability boundary")
            try require(saved.passwordLedger.active == nil && saved.passwordLedger.pendingDeletion.isEmpty,
                        "settings edit created a password grant or credential write")
            print("credential presentation flow passed"); return
        }
        if editingAuthentication {
            let previous = configuration.configuration.authentication
            panel.settings = true
            panel.beginAuthentication()
            switch a[1].split(separator: "-").last {
            case "unchanged": panel.login = " \n employee \t" // same normalized, case-preserved login
            case "login": panel.login = "another-employee"
            case "case": panel.login = "Employee" // case change is a different credential binding
            case "mode": panel.selectAuthentication(.oneTimePassword)
            case "invalid": panel.login = "employ\nee"
            case "default": break
            default: exit(64)
            }
            if a[1].hasPrefix("auth-save-") { panel.saveAuthentication() }
            else if a[1].hasPrefix("auth-finish-") { panel.finishSettings() }
            else { exit(64) }
            let persisted = try store.load()?.saved.configuration
            if a[1].hasSuffix("invalid") {
                try require(!panel.message.isEmpty && persisted?.authentication == previous,
                            "invalid edit changed persisted authentication consent")
            } else {
                try require(panel.message.isEmpty, "authentication edit failed")
                let auth = persisted?.authentication
                let retains = a[1].hasSuffix("unchanged")
                let expectedPersistence: VPNCredentialPersistence = retains ? .keychain : .none
                try require(auth?.credentialPersistence == expectedPersistence,
                            "consent was erased for unchanged binding or inherited by a changed binding")
                let expectedMode: VPNAuthenticationMode = a[1].hasSuffix("mode") ? .oneTimePassword : .password
                let expectedLogin = a[1].hasSuffix("login") ? "another-employee"
                    : a[1].hasSuffix("case") ? "Employee" : "employee"
                try require(auth?.mode == expectedMode && auth?.login == expectedLogin,
                            "edit persisted incorrect mode or normalized login")
            }
            try require(persisted?.profileName == profile.name && persisted?.resources == config.resources
                        && persisted?.desiredEnabled == false && session.submissions == 0,
                        "settings edit changed profile/resources or submitted a secret")
            print("credential presentation flow passed")
            return
        }
        panel.toggle(); try wait(panel)
        try require(panel.needsCredential && controller.credentialPromptIdentifier == session.challenge.identifier, "prompt missing")
        let firstID = controller.credentialPromptIdentifier
        panel.secret = "synthetic draft"
        switch a[1] {
        case "stale-actions":
            panel.cancelCredential(expectedPromptIdentifier: firstID); try wait(panel)
            panel.toggle(); try wait(panel)
            let current = panel.credentialPromptIdentifier
            try require(current != nil && current != firstID, "replacement prompt missing")
            panel.secret = "new synthetic draft"
            panel.submitCredential(expectedPromptIdentifier: firstID)
            panel.cancelCredential(expectedPromptIdentifier: firstID)
            panel.submitCredential(expectedPromptIdentifier: nil)
            try require(!panel.working && panel.secret == "new synthetic draft" && session.submissions == 0 && !session.cancelled,
                        "stale UI action submitted/cancelled or erased the new prompt")
            panel.submitCredential(expectedPromptIdentifier: current); try wait(panel)
            try require(panel.connected && session.submissions == 1, "current prompt failed positive control")
        case "cancel-new-attempt":
            panel.cancelCredential(expectedPromptIdentifier: panel.credentialPromptIdentifier)
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
        case "busy-preserves-draft":
            panel.refresh()
            try require(panel.working, "refresh did not hold busy state")
            panel.submitCredential(expectedPromptIdentifier: panel.credentialPromptIdentifier); panel.cancelCredential(expectedPromptIdentifier: panel.credentialPromptIdentifier)
            try require(panel.secret == "synthetic draft" && !session.cancelled && session.submissions == 0,
                        "busy action discarded draft or invoked a credential operation")
            try wait(panel)
            try require(panel.secret == "synthetic draft", "same prompt refresh discarded draft")
        case "stale-view-does-not-wipe-new-prompt":
            panel.cancelCredential(expectedPromptIdentifier: firstID); try wait(panel)
            panel.toggle(); try wait(panel)
            try require(panel.credentialPromptIdentifier != firstID, "new attempt did not replace prompt")
            panel.secret = "new synthetic draft"
            panel.dismissCredentialPrompt(ifMatching: firstID)
            try require(panel.secret == "new synthetic draft", "old view erased a newer prompt draft")
            panel.dismissCredentialPrompt(ifMatching: panel.credentialPromptIdentifier)
            try require(panel.secret.isEmpty, "current disappearing prompt did not clear draft")
        case "same-kind-new-request":
            panel.cancelCredential(expectedPromptIdentifier: firstID); try wait(panel)
            panel.toggle(); try wait(panel)
            try require(panel.needsCredential && panel.secret.isEmpty && controller.credentialPromptIdentifier != firstID,
                        "new request of same kind inherited old input")
            try require(panel.credentialPromptIdentifier == controller.credentialPromptIdentifier,
                        "new prompt identity did not reach presentation")
            // The new authenticated request owns its transport. Empty old input
            // still cannot be submitted merely because the prompt kind matches.
            panel.submitCredential(expectedPromptIdentifier: panel.credentialPromptIdentifier)
            try require(session.submissions == 0, "old prompt draft was submitted to a new request")
        case "prompt-disappeared":
            session.waiting = false
            panel.submitCredential(expectedPromptIdentifier: firstID); try wait(panel)
            guard case .failed = panel.liveState else { throw NSError(domain: "expired prompt was accepted", code: 1) }
            try require(panel.secret.isEmpty && panel.credentialPromptIdentifier == nil, "expired prompt retained input")
        case "status-failed":
            panel.submitCredential(expectedPromptIdentifier: firstID); try wait(panel)
            try require(panel.connected, "terminal refresh positive control did not connect")
            panel.secret = "stale presentation draft"
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
            panel.submitCredential(expectedPromptIdentifier: panel.credentialPromptIdentifier)
            try require(panel.secret.isEmpty, "submit retained field")
            try wait(panel)
            try require(panel.connected && controller.credentialPromptIdentifier == nil, "completed prompt retained identity")
        default: exit(64)
        }
        print("credential presentation flow passed")
    }
}
