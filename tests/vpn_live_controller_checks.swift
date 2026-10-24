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
    var secondCredentialKind: VPNCredentialKind = .privateKeyPassword
    var badConnectedGeneration = false
    var unprovenConnected = false
    var rejectSubmission = false
    var changeAttemptOnSecondPrompt = false
    var requests = 0, statusRequests = 0
    var requestLimit: Int?
    var onSubmission: (() -> Void)?
    var onClose: (() -> Void)?

    init(requiresCredential: Bool, requiresSecondCredential: Bool = false) {
        self.requiresCredential = requiresCredential
        self.requiresSecondCredential = requiresSecondCredential
    }
    private func request() throws {
        requests += 1
        if let requestLimit, requests > requestLimit { throw NSError(domain: "helper-request-budget", code: 20) }
    }
    func storeProfile(_ profile: Data) throws -> VPNHelperStatus {
        try request(); return profile.isEmpty ? .invalidRequest : .ok
    }
    func apply(_ specification: VPNApplicationSpec) throws -> VPNHelperStatus {
        try request()
        application = specification; return .ok
    }
    func connect() throws -> (VPNHelperStatus, VPNCredentialChallenge?) {
        try request()
        if requiresCredential { return (.needsCredential, challenge) }
        connected = true; return (.ok, nil)
    }
    func disconnectTunnel() throws -> VPNHelperStatus {
        try request(); disconnected = true; connected = false; return .ok
    }
    func tunnelStatus() throws -> (VPNHelperStatus, VPNTunnelSnapshot?) {
        try request(); statusRequests += 1
        guard let application, connected || requiresCredential && !cancelled && !disconnected else {
            return (.ok, VPNTunnelSnapshot(schemaVersion: 2, generation: 0,
                desiredEnabled: false, phase: .off, active: nil, pending: nil,
                challenge: nil))
        }
        let validated = VPNValidatedApplication(spec: application,
            requiresVPNCredentials: application.authentication.mode != .certificate,
            requiresPrivateKeyPassword: false)
        let generation: UInt64 = connected && badConnectedGeneration ? 2 : challenge.generation
        let binding = VPNConnectAttemptBinding(generation: generation, application: validated)
        return (.ok, VPNTunnelSnapshot(schemaVersion: 2, generation: generation,
            desiredEnabled: true, phase: connected ? (unprovenConnected ? .connecting : .connected) : .needsCredential, active: validated,
            pending: nil, challenge: connected ? nil : challenge, attempt: binding,
            issuedCredentialKinds: requiresSecondCredential && submissions > 0
                ? [.vpnPassword, .privateKeyPassword] : requiresCredential ? [challenge.kind] : []))
    }
    func submitCredentialExchange(_ response: inout VPNCredentialResponse) throws
        -> (VPNHelperStatus, VPNCredentialChallenge?) {
        try request()
        guard response.challenge == challenge, !response.secret.isEmpty else { return (.invalidRequest, nil) }
        response.secret.resetBytes(in: 0..<response.secret.count)
        response.secret.removeAll(keepingCapacity: false)
        submissions += 1
        onSubmission?()
        if rejectSubmission { return (.invalidRequest, nil) }
        if requiresSecondCredential && submissions == 1 {
            challenge = VPNCredentialChallenge(generation: changeAttemptOnSecondPrompt ? 2 : 1,
                                               kind: secondCredentialKind)
            return (.needsCredential, challenge)
        }
        connected = true
        return (.ok, nil)
    }
    func cancelCredential(_ challenge: VPNCredentialChallenge) throws -> VPNHelperStatus {
        try request()
        guard challenge == self.challenge else { return .invalidRequest }
        cancelled = true; return .ok
    }
    func close() { closed = true; onClose?() }
}

final class FakePasswordSession: VPNPasswordPersistenceSession {
    var reads = 0, adds = 0
    var secrets: [UUID: Data] = [:]
    var addedReferences: [VPNPasswordReference] = []
    var addUnknown = false, readFails = false
    var addNoIO = false, failStoreAcknowledgment = false
    var afterRead: (() throws -> Void)?
    var beforeAdd: ((VPNPasswordReference) throws -> Void)?
    var afterAdd: ((VPNPasswordReference) throws -> Void)?
    func locator(_ reference: VPNPasswordReference) -> VPNPasswordItemLocator {
        VPNPasswordItemLocator(persistentReference: Data(reference.itemID.uuidString.utf8),
            origin: VPNPasswordBackendLocator(kind: .legacyKeychain, path: "/synthetic/fixture.keychain-db",
                device: 1, inode: 1, ownerUID: getuid(), birthSeconds: 1, birthNanoseconds: 0))
    }
    func read(store: VPNStore, reference: VPNPasswordReference, revision: UInt64) throws -> Data? {
        let result = try store.readPassword(reference: reference, expectedRevision: revision) { reference, _ -> Data? in
            reads += 1
            if readFails { return nil }
            return secrets[reference.itemID]
        }
        try afterRead?()
        return result
    }
    func addOnce(store: VPNStore, reference: VPNPasswordReference, revision: UInt64,
                 secret: inout Data) throws -> VPNPasswordAddOutcome {
        try beforeAdd?(reference)
        let outcome = try store.addPasswordOnce(reference: reference, expectedRevision: revision) { reference in
            adds += 1; addedReferences.append(reference)
            if addUnknown { return .indeterminate }
            if addNoIO { return .definitelyNoIO }
            #if VPN_PASSWORD_LEDGER_TESTING
            if failStoreAcknowledgment { store.testRejectNextWriteAfterRename = true }
            #endif
            secrets[reference.itemID] = secret.withUnsafeBytes { Data($0) }
            return .added(locator(reference))
        }
        try afterAdd?(reference)
        return outcome
    }
}

@main enum VPNLiveControllerChecks {
    static func require(_ value: @autoclosure () throws -> Bool, _ message: String) throws {
        guard try value() else { throw NSError(domain: message, code: 1) }
    }

    static func configuredStore(_ path: String, password: Bool,
                                address: String = "10.20.0.0/16", staticPassword: Bool = false,
                                savePassword: Bool = false) throws -> VPNStore {
        let store = VPNStore(directory: URL(fileURLWithPath: path, isDirectory: true))
        let text = password ? passwordProfile : certificateProfile
        let imported = try VPNProfileImporter.inspect(data: Data(text.utf8), name: "company.ovpn")
        var configuration = VPNConfiguration()
        try configuration.setProfile(name: imported.name)
        try configuration.saveResource(VPNResource(name: "Работа", address: address))
        try configuration.setAuthentication(try VPNAuthentication(
            mode: password ? (staticPassword ? .password : .oneTimePassword) : .certificate,
            login: password ? "employee" : nil, credentialPersistence: savePassword ? .keychain : .none))
        _ = try store.save(configuration, importing: imported, expectedRevision: nil)
        return store
    }

    static func cacheFlow(_ mode: String, path: String) throws {
        let isOTP = mode == "cache-otp"
        let store = try configuredStore(path, password: true, staticPassword: !isOTP, savePassword: !isOTP)
        let driver = FakePasswordSession()
        let deferred = mode.hasPrefix("cache-stale-") || mode.hasPrefix("cache-claim-") || mode == "cache-queued-replaced" || mode == "cache-queued-disconnect"
        let prepareReady = DispatchSemaphore(value: 0), prepareRelease = DispatchSemaphore(value: 0), saved = DispatchSemaphore(value: 0)
        var scheduled: [() -> Void] = []
        var prepares = 0
        let persistence = VPNPasswordPersistenceCoordinator(store: store, available: mode != "cache-inert",
            prepare: { store in
                // Reentrant reads would fail if READY preparation held Store.lock.
                _ = try store.load(); prepares += 1
                if mode == "cache-prepare-cancel" {
                    prepareReady.signal()
                    guard prepareRelease.wait(timeout: .now() + 3) == .success else { throw NSError(domain: "prepare-wait", code: 8) }
                }
                return driver
            }, schedule: { work in
                if mode == "cache-prepare-cancel" {
                    DispatchQueue.global().async(execute: DispatchWorkItem { work(); saved.signal() })
                } else if deferred { scheduled.append(work) } else { work() }
            })
        let twoPrompts = ["cache-private-sequence", "cache-new-vpn", "cache-cancel-candidate", "cache-reconnect",
                          "cache-private-attempt-changed", "cache-private-expired"].contains(mode)
        let live = FakeLiveSession(requiresCredential: true, requiresSecondCredential: twoPrompts)
        if mode == "cache-new-vpn" { live.secondCredentialKind = .vpnPassword }
        if mode == "cache-private-attempt-changed" { live.changeAttemptOnSecondPrompt = true }
        if mode == "cache-key-only" { live.challenge = VPNCredentialChallenge(generation: 1, kind: .privateKeyPassword) }
        if mode == "cache-bad-attempt" { live.badConnectedGeneration = true }
        if mode == "cache-unproven" { live.unprovenConnected = true }
        if mode == "cache-failed" || mode == "cache-auto-failed" { live.rejectSubmission = true }
        if mode == "cache-add-unknown" { driver.addUnknown = true }
        var original: VPNPasswordReference?
        if ["cache-auto", "cache-auto-reprompt", "cache-auto-failed", "cache-read-fallback", "cache-read-revoked"].contains(mode) {
            let state = try store.load()!
            let reference = try store.grantPasswordPersistence(expectedRevision: state.saved.configuration.revision)
            var bytes = Data("old-static".utf8)
            _ = try driver.addOnce(store: store, reference: reference, revision: state.saved.configuration.revision, secret: &bytes)
            original = reference; driver.adds = 0; driver.addedReferences = []
            if mode == "cache-auto-reprompt" { live.secondCredentialKind = .vpnPassword }
            if mode == "cache-read-fallback" { driver.readFails = true }
            if mode == "cache-read-revoked" {
                driver.afterRead = {
                    let state = try store.load()!; var config = state.saved.configuration
                    try config.setAuthentication(VPNAuthentication(mode: .password, login: "employee"))
                    _ = try store.save(config, expectedRevision: state.saved.configuration.revision)
                }
            }
        }
        // Auto rejection is one extra VPN-password challenge, not a new attempt.
        let actual: FakeLiveSession
        if mode == "cache-auto-reprompt" {
            actual = FakeLiveSession(requiresCredential: true, requiresSecondCredential: true)
            actual.secondCredentialKind = .vpnPassword
        } else { actual = live }
        let controller = VPNLiveController(store: store, passwordPersistence: persistence, openSession: { actual })
        var claimEvents: [VPNPasswordPersistenceEvent] = []
        if mode.hasPrefix("cache-claim-") {
            controller.setPasswordPersistenceEventHandler { claimEvents.append($0) }
        }
        var observedCandidate: VPNPasswordSaveCandidate?
        if mode == "cache-private-attempt-changed" {
            actual.onSubmission = { [weak controller] in observedCandidate = controller?.testPasswordCandidate }
        }
        controller.connect()
        if mode == "cache-auto" {
            try require(controller.state == .connected && driver.reads == 1 && driver.adds == 0,
                        "cached credential did not connect without re-add")
            try require(try store.load()!.passwordLedger.active?.reference == original, "cache rotated without manual input")
            return
        }
        if mode == "cache-auto-failed" {
            if case .failed = controller.state {} else { throw NSError(domain: "cached-rejection-not-observed", code: 3) }
            try require(driver.reads == 1 && actual.submissions == 1 && driver.adds == 0, "bad cache not rejected")
            actual.rejectSubmission = false
            actual.challenge = VPNCredentialChallenge(generation: 2, kind: .vpnPassword)
            controller.connect()
            try require(controller.state == .needsCredential(.vpnPassword) && driver.reads == 1 && actual.submissions == 1,
                        "failed cached item blocked manual recovery by repeating on reconnect")
        }
        if mode == "cache-auto-reprompt" {
            try require(driver.reads == 1 && actual.submissions == 1 && controller.state == .needsCredential(.vpnPassword),
                        "cache retried after a rejected prompt")
        }
        if mode == "cache-read-revoked" {
            try require(driver.reads == 1 && actual.submissions == 0 && controller.state == .needsCredential(.vpnPassword),
                        "revoked read result reached helper")
            return
        }
        if mode == "cache-stale-prompt" {
            // Not a delayed save case: reject an old UI token before helper use.
            var bytes = Data("manual-static".utf8)
            controller.submitCredential(&bytes, expectedPromptIdentifier: UUID())
            try require(bytes.isEmpty && actual.submissions == 0 && driver.adds == 0,
                        "stale presentation submitted a credential")
            return
        }
        let prompt = controller.credentialPromptIdentifier
        var manual = Data("manual-static".utf8)
        controller.submitCredential(&manual, expectedPromptIdentifier: prompt)
        try require(manual.isEmpty, "manual input retained")
        if mode == "cache-private-attempt-changed" {
            try require(observedCandidate != nil && observedCandidate?.isCleared == true && driver.adds == 0,
                        "candidate survived a different private-key attempt")
            return
        }
        if twoPrompts {
            let candidate = controller.testPasswordCandidate
            if mode == "cache-private-expired" {
                try require(candidate != nil && candidate?.isCleared == false, "candidate missing before expiry")
                actual.rejectSubmission = true
                var key = Data("private-key-secret".utf8)
                controller.submitCredential(&key, expectedPromptIdentifier: controller.credentialPromptIdentifier)
                try require(key.isEmpty && candidate?.isCleared == true && driver.adds == 0,
                            "actual expired helper exchange retained or saved a candidate")
                return
            }
            if mode == "cache-cancel-candidate" {
                try require(candidate != nil && candidate?.isCleared == false, "candidate missing before cancellation")
                controller.cancelCredential()
                try require(candidate?.isCleared == true && driver.adds == 0, "cancel retained candidate")
                return
            }
            if mode == "cache-reconnect" {
                controller.connect()
                try require(candidate?.isCleared == true && driver.adds == 0, "new session retained candidate")
                return
            }
            if mode == "cache-new-vpn" {
                try require(candidate == nil, "new VPN-password prompt retained previous password")
            } else {
                try require(candidate != nil && candidate?.isCleared == false && driver.adds == 0,
                            "same-attempt private-key prompt lost manual candidate or saved too early")
            }
            var key = Data((mode == "cache-new-vpn" ? "replacement-static" : "private-key-secret").utf8)
            controller.submitCredential(&key, expectedPromptIdentifier: controller.credentialPromptIdentifier)
            try require(key.isEmpty && candidate?.isCleared != false, "private-key completion retained input")
        }
        if mode == "cache-bad-attempt" || mode == "cache-unproven" || mode == "cache-failed" {
            try require(driver.adds == 0 && controller.testPasswordCandidate == nil, "unproven connection saved a password")
            return
        }
        if mode == "cache-claim-new-first" || mode == "cache-claim-old-first" {
            try require(scheduled.count == 1 && controller.state == .connected, "old verified save not queued")
            var oldClaim: VPNPasswordReference?
            func newerConfirmedSave() throws {
                // A silent lookup miss lets the newer user supply a manual
                // replacement even when the older item has already settled.
                driver.readFails = true
                actual.connected = false
                actual.challenge = VPNCredentialChallenge(generation: 2, kind: .vpnPassword)
                controller.connect()
                var newest = Data("newest-claimed-manual".utf8)
                controller.submitCredential(&newest, expectedPromptIdentifier: controller.credentialPromptIdentifier)
                try require(newest.isEmpty && controller.state == .connected && scheduled.count == 1,
                            "new manual attempt did not capture existing claim and verify")
                scheduled.removeFirst()()
            }
            if mode == "cache-claim-new-first" {
                driver.beforeAdd = { reference in
                    driver.beforeAdd = nil; oldClaim = reference
                    let state = try store.load()!
                    try require(state.passwordLedger.active?.reference == reference
                        && state.passwordLedger.active?.writeState == .notIssued,
                        "claim was mislabeled as dispatched Add")
                    try newerConfirmedSave()
                }
            } else {
                driver.afterAdd = { reference in
                    driver.afterAdd = nil; oldClaim = reference
                    let state = try store.load()!
                    try require(state.passwordLedger.active?.reference == reference
                        && state.passwordLedger.active?.writeState == .settled,
                        "completed old Add not settled before newer capture")
                    try newerConfirmedSave()
                }
            }
            scheduled.removeFirst()()
            let final = try store.load()!
            guard let oldClaim, let newest = final.passwordLedger.active else {
                throw NSError(domain: "claim-outcome-missing", code: 9)
            }
            try require(newest.reference != oldClaim && newest.writeState == .settled
                && driver.secrets[newest.reference.itemID] == Data("newest-claimed-manual".utf8),
                "old claim overwrote or blocked the newer confirmed password")
            guard let oldEvent = claimEvents.first, let finalEvent = claimEvents.last else {
                throw NSError(domain: "claim-feedback-missing", code: 10)
            }
            try require(finalEvent.phase == .saved && finalEvent.intentIdentifier != oldEvent.intentIdentifier
                && claimEvents.filter { $0.intentIdentifier == oldEvent.intentIdentifier }.map(\.phase) == [.saving]
                && !controller.isCurrentPasswordPersistenceEvent(oldEvent, configuration: final.saved.configuration)
                && controller.isCurrentPasswordPersistenceEvent(finalEvent, configuration: final.saved.configuration),
                "late claimed save overwrote newer feedback")
            if mode == "cache-claim-new-first" {
                try require(driver.adds == 1 && driver.secrets[oldClaim.itemID] == nil
                    && final.passwordLedger.pendingDeletion.isEmpty,
                    "stale old Add reached callback or created a false cleanup obligation")
            } else {
                try require(driver.adds == 2 && final.passwordLedger.pendingDeletion.count == 1
                    && final.passwordLedger.pendingDeletion[0].reference == oldClaim
                    && final.passwordLedger.pendingDeletion[0].writeState == .settled,
                    "known completed old item lost its exact cleanup obligation")
            }
            return
        }
        if mode == "cache-prepare-cancel" {
            try require(prepareReady.wait(timeout: .now() + 2) == .success, "worker READY not reached")
            let start = DispatchTime.now().uptimeNanoseconds
            controller.disconnect()
            let end = DispatchTime.now().uptimeNanoseconds
            prepareRelease.signal()
            try require(saved.wait(timeout: .now() + 2) == .success && driver.adds == 0 && controller.state == .off,
                        "cancelled prepared save issued Add")
            try require(end - start < 1_500_000_000, "worker preparation held cancellation lock")
            return
        }
        if mode == "cache-queued-replaced" || mode == "cache-queued-disconnect" {
            try require(scheduled.count == 1 && driver.adds == 0, "save not deferred")
            if mode == "cache-queued-disconnect" {
                controller.disconnect()
                scheduled.removeFirst()()
                try require(driver.adds == 0 && controller.state == .off, "disconnect did not invalidate queued save")
                return
            }
            actual.connected = false
            actual.challenge = VPNCredentialChallenge(generation: 2, kind: .vpnPassword)
            controller.connect()
            var newest = Data("newest-manual".utf8)
            controller.submitCredential(&newest, expectedPromptIdentifier: controller.credentialPromptIdentifier)
            try require(scheduled.count == 2 && controller.state == .connected, "second exact attempt not queued")
            while !scheduled.isEmpty { scheduled.removeFirst()() }
            try require(driver.adds == 1 && driver.secrets[driver.addedReferences[0].itemID] == Data("newest-manual".utf8),
                        "an older queued password displaced the newer confirmed password")
            return
        }
        if deferred {
            try require(controller.state == .connected && scheduled.count == 1 && driver.adds == 0,
                        "cache write ran before confirmed connection")
            let before = try store.load()!; var config = before.saved.configuration
            switch mode {
            case "cache-stale-revoke": try config.setAuthentication(VPNAuthentication(mode: .password, login: "employee"))
            case "cache-stale-login": try config.setAuthentication(VPNAuthentication(mode: .password, login: "other", credentialPersistence: .keychain))
            case "cache-stale-mode": try config.setAuthentication(VPNAuthentication(mode: .oneTimePassword, login: "employee"))
            case "cache-stale-profile":
                let changed = try VPNProfileImporter.inspect(data: Data(passwordProfile.replacingOccurrences(of: "vpn.company.example", with: "different.company.example").utf8), name: "company.ovpn")
                try config.setAuthentication(nil)
                _ = try store.save(config, importing: changed, expectedRevision: before.saved.configuration.revision)
            case "cache-stale-grant":
                _ = try store.createPasswordSaveGrant(expectedRevision: config.revision, expectedActive: before.passwordLedger.active?.reference)
            default: throw NSError(domain: "unknown-stale-case", code: 2)
            }
            if mode != "cache-stale-profile" && mode != "cache-stale-grant" {
                _ = try store.save(config, expectedRevision: before.saved.configuration.revision)
            }
            scheduled.removeFirst()()
            try require(driver.adds == 0 && controller.state == .connected, "stale binding saved or broke confirmed VPN")
            return
        }
        if isOTP || mode == "cache-key-only" || mode == "cache-inert" {
            try require(driver.adds == 0 && driver.reads == 0 && prepares == 0 && controller.state == .connected,
                        "noneligible credential touched persistence")
            return
        }
        try require(controller.state == .connected && driver.adds == 1, "manual static password was not saved once")
        if mode == "cache-add-unknown" {
            try require(try store.load()!.passwordLedger.active?.writeState == .pending, "unknown Add lost obligation")
        } else {
            let expected = Data((mode == "cache-new-vpn" ? "replacement-static" : "manual-static").utf8)
            try require(driver.secrets[driver.addedReferences[0].itemID] == expected,
                        "saved private-key input or helper-wiped response instead of manual password")
        }
        if let original {
            let state = try store.load()!
            try require(state.passwordLedger.active?.reference != original && state.passwordLedger.pendingDeletion.contains { $0.reference == original },
                        "manual confirmed save reused old item or retired obligation")
        }
    }

    static func feedbackFlow(_ mode: String, path: String) throws {
        let otp = mode == "feedback-otp"
        let store = try configuredStore(path, password: true, staticPassword: !otp, savePassword: !otp)
        let driver = FakePasswordSession()
        let deferred = mode.hasPrefix("feedback-stale-") && mode != "feedback-stale-delivery"
        var queued: [() -> Void] = []
        let persistence = VPNPasswordPersistenceCoordinator(store: store, available: mode != "feedback-inert",
            prepare: { store in
                _ = try store.load()
                if mode == "feedback-prepare-nil" { return nil }
                if mode == "feedback-prepare-throw" { throw NSError(domain: "synthetic-unavailable", code: 30) }
                if mode == "feedback-prepare-superseded" {
                    let state = try store.load()!
                    _ = try store.createPasswordSaveGrant(expectedRevision: state.saved.configuration.revision,
                                                         expectedActive: state.passwordLedger.active?.reference)
                }
                return driver
            }, schedule: { work in if deferred { queued.append(work) } else { work() } })
        let live = FakeLiveSession(requiresCredential: true, requiresSecondCredential: mode == "feedback-capture-private")
        if mode == "feedback-private-key" { live.challenge = VPNCredentialChallenge(generation: 1, kind: .privateKeyPassword) }
        if mode == "feedback-unknown" { driver.addUnknown = true }
        if mode == "feedback-no-io" { driver.addNoIO = true }
        if mode == "feedback-ack-failed" { driver.failStoreAcknowledgment = true }
        if mode.hasPrefix("feedback-read-") {
            let state = try store.load()!
            let reference = try store.grantPasswordPersistence(expectedRevision: state.saved.configuration.revision)
            var initial = Data("cached-static".utf8)
            _ = try driver.addOnce(store: store, reference: reference, revision: state.saved.configuration.revision, secret: &initial)
            driver.adds = 0; driver.addedReferences = []
            if mode != "feedback-read-success" { driver.readFails = true }
            if mode == "feedback-read-revoked" {
                driver.afterRead = {
                    let state = try store.load()!; var config = state.saved.configuration
                    try config.setAuthentication(VPNAuthentication(mode: .password, login: "employee"))
                    _ = try store.save(config, expectedRevision: state.saved.configuration.revision)
                }
            }
        }
        let controller = VPNLiveController(store: store, passwordPersistence: persistence, openSession: { live })
        var events: [VPNPasswordPersistenceEvent] = []
        var callbackWasOutsideLocks = true
        var saveFeedbackBeforeConnected = false
        controller.setPasswordPersistenceEventHandler { [weak controller] event in
            guard let controller else { return }
            events.append(event)
            // Both Store reads and cheap intent queries must be reentrant here.
            guard let state = try? store.load() else { callbackWasOutsideLocks = false; return }
            _ = controller.isCurrentPasswordPersistenceEvent(event, configuration: state.saved.configuration)
            _ = controller.passwordPersistenceEvent
            if !mode.hasPrefix("feedback-read-"), controller.state != .connected { saveFeedbackBeforeConnected = true }
        }
        controller.connect()
        if mode.hasPrefix("feedback-read-") {
            try require(driver.adds == 0 && callbackWasOutsideLocks, "cache read feedback wrote an item or held a lock")
            if mode == "feedback-read-success" {
                try require(controller.state == .connected && events.isEmpty, "cached success invented an Add/saved event")
            } else if mode == "feedback-read-revoked" {
                try require(events.isEmpty && live.submissions == 0, "revoked read produced stale feedback or submission")
            } else {
                try require(controller.state == .needsCredential(.vpnPassword) && events.map(\.phase) == [.needsConfirmation],
                            "failed cache read did not offer manual confirmation")
            }
            return
        }
        try require(events.isEmpty, "save feedback emitted before a manual attempt connected")
        var heldFD: Int32 = -1
        var emptyCapture: VPNPasswordSaveCandidate?
        if ["feedback-capture-failed", "feedback-capture-unproven", "feedback-capture-private", "feedback-capture-revoked"].contains(mode) {
            heldFD = open(store.directory.appendingPathComponent("state.lock").path, O_RDWR | O_NOFOLLOW | O_CLOEXEC)
            guard heldFD >= 0, flock(heldFD, LOCK_EX | LOCK_NB) == 0 else { throw NSError(domain: "capture-lock", code: 31) }
            live.onSubmission = {
                emptyCapture = controller.testPasswordCandidate
                if heldFD >= 0 { flock(heldFD, LOCK_UN); close(heldFD); heldFD = -1 }
            }
            if mode == "feedback-capture-revoked" {
                live.onClose = {
                    live.onClose = nil
                    guard let state = try? store.load() else { return }
                    var config = state.saved.configuration
                    try? config.setAuthentication(VPNAuthentication(mode: .password, login: "employee"))
                    _ = try? store.save(config, expectedRevision: state.saved.configuration.revision)
                }
            }
            if mode == "feedback-capture-unproven" { live.rejectSubmission = true }
        }
        if mode == "feedback-saved-busy" {
            driver.afterAdd = { _ in
                heldFD = open(store.directory.appendingPathComponent("state.lock").path, O_RDWR | O_NOFOLLOW | O_CLOEXEC)
                guard heldFD >= 0, flock(heldFD, LOCK_EX | LOCK_NB) == 0 else { throw NSError(domain: "saved-lock", code: 32) }
            }
            VPNPasswordPersistenceCoordinator.testAfterBusySavedObservation = {
                flock(heldFD, LOCK_UN); close(heldFD); heldFD = -1
            }
        }
        defer {
            VPNPasswordPersistenceCoordinator.testAfterBusySavedObservation = nil
            if heldFD >= 0 { flock(heldFD, LOCK_UN); close(heldFD) }
        }
        var manual = Data("manual-static".utf8)
        controller.submitCredential(&manual, expectedPromptIdentifier: controller.credentialPromptIdentifier)
        try require(manual.isEmpty, "manual input retained")
        if mode == "feedback-capture-private" {
            try require(events.isEmpty && controller.state == .needsCredential(.privateKeyPassword)
                && emptyCapture?.isCleared == true, "empty intent marker emitted before private-key continuation")
            var key = Data("private-key-secret".utf8)
            controller.submitCredential(&key, expectedPromptIdentifier: controller.credentialPromptIdentifier)
            try require(key.isEmpty, "private-key input retained")
        }
        if mode == "feedback-capture-unproven" {
            try require(events.isEmpty && driver.adds == 0 && emptyCapture?.isCleared == true,
                        "unproven capture failure leaked feedback or retained a secret")
            return
        }
        try require(controller.state == .connected && !saveFeedbackBeforeConnected && callbackWasOutsideLocks,
                    "cache feedback broke confirmed VPN or ran under a lock")
        if mode == "feedback-capture-revoked" {
            try require(events.isEmpty && driver.adds == 0 && emptyCapture?.isCleared == true
                && store.load()!.saved.configuration.authentication?.credentialPersistence == VPNCredentialPersistence.none,
                "failed capture warned after the user revoked consent")
            return
        }
        if mode == "feedback-prepare-superseded" {
            try require(events.map(\.phase) == [.saving] && driver.adds == 0 && controller.passwordPersistenceEvent == nil,
                        "superseded grant left an authoritative saving event")
            let config = try store.load()!.saved.configuration
            try require(!controller.isCurrentPasswordPersistenceEvent(events[0], configuration: config),
                        "queued old saving event survived a newer same-revision grant")
            return
        }
        if mode == "feedback-inert" || mode == "feedback-otp" || mode == "feedback-private-key" {
            try require(events.isEmpty && driver.adds == 0 && controller.passwordPersistenceEvent == nil,
                        "ineligible/unavailable input emitted persistence feedback")
            return
        }
        if mode == "feedback-stale-revoke" || mode == "feedback-stale-revision" {
            try require(queued.count == 1 && events.isEmpty, "save not deferred")
            let state = try store.load()!; var config = state.saved.configuration
            if mode == "feedback-stale-revoke" { try config.setAuthentication(VPNAuthentication(mode: .password, login: "employee")) }
            else { try config.saveResource(VPNResource(address: "10.30.0.0/16")) }
            _ = try store.save(config, expectedRevision: state.saved.configuration.revision)
            queued.removeFirst()()
            try require(events.isEmpty && driver.adds == 0 && controller.state == .connected,
                        "obsolete queued save warned for newer settings")
            return
        }
        if mode == "feedback-stale-input" {
            live.connected = false; live.challenge = VPNCredentialChallenge(generation: 2, kind: .vpnPassword)
            controller.connect()
            var newest = Data("newest-static".utf8)
            controller.submitCredential(&newest, expectedPromptIdentifier: controller.credentialPromptIdentifier)
            try require(queued.count == 2, "new confirmed intent not queued")
            while !queued.isEmpty { queued.removeFirst()() }
            try require(driver.adds == 1 && events.map(\.phase) == [.saving, .saved], "old queued intent emitted feedback")
        }
        if mode == "feedback-capture-failed" || mode == "feedback-capture-private" {
            try require(events.map(\.phase) == [.needsConfirmation] && driver.adds == 0
                && emptyCapture?.isCleared == true && store.load()!.passwordLedger.active == nil,
                "empty capture marker created a grant or skipped confirmation")
        } else if ["feedback-prepare-nil", "feedback-prepare-throw", "feedback-unknown", "feedback-no-io", "feedback-ack-failed"].contains(mode) {
            try require(events.map(\.phase) == [.saving, .needsConfirmation], "failed save falsely reported success")
            if mode == "feedback-ack-failed" {
                try require(try store.load()!.passwordLedger.active?.writeState == .settled,
                            "post-rename acknowledgment failure was not exercised")
            }
        } else {
            try require(events.map(\.phase) == [.saving, .saved], "positive Add/Store acknowledgment missing feedback")
        }
        guard let latest = events.last else { throw NSError(domain: "missing-feedback", code: 33) }
        let config = try store.load()!.saved.configuration
        try require(controller.isCurrentPasswordPersistenceEvent(latest, configuration: config), "latest scoped event rejected")
        if let first = events.first, first != latest {
            try require(!controller.isCurrentPasswordPersistenceEvent(first, configuration: config), "old phase could overwrite newer result")
        }
        if mode == "feedback-stale-delivery" {
            let old = latest
            live.connected = false; live.challenge = VPNCredentialChallenge(generation: 2, kind: .vpnPassword)
            driver.readFails = true; controller.connect()
            var newer = Data("newest-static".utf8)
            controller.submitCredential(&newer, expectedPromptIdentifier: controller.credentialPromptIdentifier)
            guard let fresh = events.last else { throw NSError(domain: "new-event-missing", code: 34) }
            try require(fresh.phase == .saved && fresh.intentIdentifier != old.intentIdentifier
                && fresh.configurationRevision == old.configurationRevision
                && !controller.isCurrentPasswordPersistenceEvent(old, configuration: config)
                && controller.isCurrentPasswordPersistenceEvent(fresh, configuration: config),
                "delayed old event survived a same-revision newer input")
            var object = try JSONSerialization.jsonObject(with: JSONEncoder().encode(config)) as! [String: Any]
            var auth = object["authentication"] as! [String: Any]; auth["credentialPersistence"] = "none"; object["authentication"] = auth
            let revoked = try JSONDecoder().decode(VPNConfiguration.self, from: JSONSerialization.data(withJSONObject: object))
            try require(!controller.isCurrentPasswordPersistenceEvent(fresh, configuration: revoked),
                        "cheap UI guard ignored revoked consent at same revision")
        }
        for event in events {
            let debug = String(reflecting: event)
            try require(debug == "VPNPasswordPersistenceEvent(redacted)" && !debug.contains(event.intentIdentifier.uuidString)
                && !debug.contains("employee") && !debug.contains("manual-static"), "feedback debug leaked private metadata")
        }
    }

    static func heldPromptRefresh(_ path: String) throws {
        let store = try configuredStore(path, password: true, staticPassword: true, savePassword: true)
        let driver = FakePasswordSession()
        let persistence = VPNPasswordPersistenceCoordinator(store: store, available: true,
            prepare: { _ in driver }, schedule: { $0() })
        let held = FakeLiveSession(requiresCredential: true, requiresSecondCredential: true)
        held.requestLimit = VPNHelperProtocol.maximumRequestsPerConnection
        let terminal = FakeLiveSession(requiresCredential: false)
        terminal.requestLimit = VPNHelperProtocol.maximumRequestsPerConnection
        var opened = 0
        let controller = VPNLiveController(store: store, passwordPersistence: persistence, openSession: {
            opened += 1
            guard opened <= 2 else { throw NSError(domain: "unexpected-conversation", code: 21) }
            return opened == 1 ? held : terminal
        })
        controller.connect()
        let vpnPrompt = controller.credentialPromptIdentifier
        try require(opened == 1 && held.requests == 4 && held.statusRequests == 1
            && controller.state == .needsCredential(.vpnPassword), "initial owned prompt not proven")
        for _ in 0..<5 { controller.refresh() }
        try require(opened == 1 && held.requests == 4 && held.statusRequests == 1
            && controller.credentialPromptIdentifier == vpnPrompt,
            "popover reopening opened or polled a second credential conversation")
        var password = Data("manual-static".utf8)
        controller.submitCredential(&password, expectedPromptIdentifier: vpnPrompt)
        let privatePrompt = controller.credentialPromptIdentifier
        let candidate = controller.testPasswordCandidate
        try require(password.isEmpty && held.requests == 6 && held.statusRequests == 2
            && controller.state == .needsCredential(.privateKeyPassword) && candidate?.isCleared == false,
            "private-key continuation missing")
        for _ in 0..<5 { controller.refresh() }
        try require(opened == 1 && held.requests == 6 && held.statusRequests == 2
            && controller.credentialPromptIdentifier == privatePrompt && candidate?.isCleared == false,
            "reopening spent the remaining helper budget or invalidated the held candidate")
        var key = Data("private-key-secret".utf8)
        controller.submitCredential(&key, expectedPromptIdentifier: privatePrompt)
        try require(key.isEmpty && opened == 1 && held.requests == 8 && held.statusRequests == 3
            && held.closed && controller.state == .connected && candidate?.isCleared == true
            && driver.adds == 1 && driver.secrets[driver.addedReferences[0].itemID] == Data("manual-static".utf8),
            "two-prompt flow exceeded eight requests or lost its verified static save")
        terminal.application = held.application; terminal.connected = true
        controller.refresh()
        try require(opened == 2 && terminal.requests == 1 && terminal.statusRequests == 1
            && terminal.closed && held.requests == 8 && controller.state == .connected,
            "terminal refresh did not use a fresh status conversation")
    }

    static func main() throws {
        let mode = CommandLine.arguments[1], path = CommandLine.arguments[2]
        if mode.hasPrefix("feedback-") {
            try feedbackFlow(mode, path: path); print("feedback flow passed"); return
        }
        if mode == "held-refresh" {
            try heldPromptRefresh(path); print("refresh flow passed"); return
        }
        if mode.hasPrefix("cache-") {
            try cacheFlow(mode, path: path); print("cache flow passed"); return
        }
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
            controller.submitCredential(&secret, expectedPromptIdentifier: controller.credentialPromptIdentifier)
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
            controller.submitCredential(&first, expectedPromptIdentifier: controller.credentialPromptIdentifier)
            try require(first.isEmpty
                        && controller.state == .needsCredential(.privateKeyPassword),
                        "second prompt was not propagated")
            var second = Data("key-password".utf8)
            controller.submitCredential(&second, expectedPromptIdentifier: controller.credentialPromptIdentifier)
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
