import CryptoKit
import Darwin
import Foundation

private func check(_ value: @autoclosure () throws -> Bool) throws {
    guard try value() else { throw NSError(domain: "runtime-check", code: 1) }
}
private let profileText = """
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
private func location(_ ref: VPNPasswordReference) -> VPNPasswordItemLocator {
    .init(persistentReference: Data(ref.itemID.uuidString.utf8), origin: .init(kind: .legacyKeychain,
        path: "/synthetic/runtime.keychain-db", device: 1, inode: 1, ownerUID: getuid(), birthSeconds: 1, birthNanoseconds: 0))
}
private final class Driver {
    var prepared = 0, adds = 0, deletes = 0
    var outcome = VPNPasswordDeleteOutcome.deleted
    var unknown = false
    var refs: [VPNPasswordReference] = []
    func session(_ store: VPNStore) throws -> Session {
        _ = try store.load(); prepared += 1; return Session(self)
    }
    final class Session: VPNPasswordPersistenceSession, VPNPasswordCleanupSession {
        let driver: Driver; var used = false
        init(_ driver: Driver) { self.driver = driver }
        func once() throws { try check(!used); used = true }
        func read(store: VPNStore, reference: VPNPasswordReference, revision: UInt64) throws -> Data? {
            try once(); return nil
        }
        func addOnce(store: VPNStore, reference: VPNPasswordReference, revision: UInt64, secret: inout Data) throws -> VPNPasswordAddOutcome {
            try once(); defer { secret.resetBytes(in: 0..<secret.count); secret.removeAll() }
            return try store.addPasswordOnce(reference: reference, expectedRevision: revision) { _ in
                self.driver.adds += 1
                return .added(location(reference))
            }
        }
        func deletePendingOutcome(store: VPNStore, reference: VPNPasswordReference) throws -> VPNPasswordDeleteOutcome {
            try once(); driver.deletes += 1; driver.refs.append(reference)
            if driver.unknown { return .indeterminate }
            var result: VPNPasswordDeleteOutcome?
            do {
                try store.deletePendingPassword(reference: reference) { _, _ in
                    result = self.driver.outcome; return self.driver.outcome
                }
            } catch { if let result, result != .deleted { return result }; throw error }
            return .deleted
        }
    }
}
private final class Fixture {
    let directory: URL, store: VPNStore
    let driver = Driver()
    var jobs: [() -> Void] = []
    lazy var runtime = VPNPasswordRuntime(store: store, available: true,
        persistencePrepare: { [unowned self] in try driver.session($0) }, cleanupPrepare: { [unowned self] in try driver.session($0) },
        schedule: { [unowned self] in jobs.append($0) })
    init() throws {
        directory = FileManager.default.temporaryDirectory.appendingPathComponent("pp-password-runtime-" + UUID().uuidString)
        store = VPNStore(directory: directory)
        let profile = try VPNProfileImporter.inspect(data: Data(profileText.utf8), name: "company.ovpn")
        var config = VPNConfiguration(); try config.setProfile(name: profile.name)
        try config.saveResource(VPNResource(address: "10.20.0.0/16"))
        try config.setAuthentication(VPNAuthentication(mode: .password, login: "employee", credentialPersistence: .keychain))
        try config.setEnabled(true)
        let state = try store.save(config, importing: profile, expectedRevision: nil)
        try store.acknowledgeApplied(revision: state.saved.configuration.revision)
    }
    deinit { try? FileManager.default.removeItem(at: directory) }
    func seed(_ pending: Bool = false) throws -> VPNPasswordReference {
        let state = try store.load()!
        let ref = try store.createPasswordSaveGrant(expectedRevision: state.saved.configuration.revision, expectedActive: state.passwordLedger.active?.reference)
        _ = try store.addPasswordOnce(reference: ref, expectedRevision: state.saved.configuration.revision) { _ in
            pending ? .indeterminate : .added(location(ref))
        }
        return ref
    }
    func flush() throws {
        var count = 0
        while !jobs.isEmpty { count += 1; try check(count < 10); jobs.removeFirst()() }
    }
    func binding() throws -> VPNPasswordPersistenceBinding {
        let state = try store.load()!
        let sha = SHA256.hash(data: state.saved.profileContents!).map { String(format: "%02x", $0) }.joined()
        let app = try VPNApplicationSpec(revision: state.saved.configuration.revision, profileSHA256: sha,
            resources: state.saved.configuration.resources, corporateDNS: [], authentication: state.saved.configuration.authentication!)
        let attempt = VPNConnectAttemptBinding(generation: 1, application: .init(spec: app, requiresVPNCredentials: true, requiresPrivateKeyPassword: true))
        return .init(sessionIdentifier: UUID(), attempt: attempt, challenge: VPNCredentialChallenge(generation: 1, kind: .vpnPassword))
    }
}
private final class AdoptionFailureStore: VPNModelStore {
    let actual: VPNStore
    init(_ actual: VPNStore) { self.actual = actual }
    func load() throws -> VPNStoredState? { try actual.load() }
    func save(_ configuration: VPNConfiguration, importing profile: VPNImportedProfile?, expectedRevision: UInt64?) throws -> VPNStoredState {
        let committed = try actual.save(configuration, importing: profile, expectedRevision: expectedRevision)
        return VPNStoredState(saved: VPNSnapshot(configuration: committed.saved.configuration,
            profileContents: Data("malformed".utf8), suggestedDNS: [], suggestedResources: [], hasIgnoredProfileRoutes: false),
            applied: committed.applied, passwordLedger: committed.passwordLedger)
    }
}
@main enum RuntimeChecks {
    static func main() throws {
        let mode = CommandLine.arguments[1]
        let f = try Fixture()
        if mode == "inert" {
            let empty = f.directory.appendingPathComponent("absent")
            let runtime = VPNPasswordRuntime(store: VPNStore(directory: empty), schedule: { _ in fatalError("inert scheduled") })
            runtime.start(); runtime.requestCleanup()
            try check(!runtime.available && !FileManager.default.fileExists(atPath: empty.path)); return done()
        }
        let old = try f.seed(mode == "unknown-add")
        let runtime = f.runtime
        try check(f.jobs.isEmpty && f.driver.prepared == 0)
        try runtime.configuration.load()
        if mode == "adopt-failed" {
            var committedCalls = 0
            let model = VPNModel(store: AdoptionFailureStore(f.store), didPersist: {
                committedCalls += 1
                precondition((try? f.store.load()) != nil, "hook held Store lock")
            })
            try model.load()
            var failed = false
            do { try model.setAuthentication(mode: .password, login: "other") } catch { failed = true }
            try check(failed && committedCalls == 1 && f.store.load()!.saved.configuration.authentication?.login == "other")
            return done()
        }
        if mode == "stale-save" {
            let state = try f.store.load()!
            var changed = state.saved.configuration
            try changed.setAuthentication(VPNAuthentication(mode: .password, login: "external"))
            _ = try f.store.save(changed, importing: nil, expectedRevision: state.saved.configuration.revision)
            do { try runtime.configuration.setAuthentication(mode: .password, login: "stale"); fatalError("stale accepted") }
            catch { try check(error as? VPNValidationError == .staleRevision && f.jobs.isEmpty && f.driver.prepared == 0) }
            return done()
        }
        if mode == "noop" {
            try runtime.configuration.setAuthentication(mode: .password, login: "employee", credentialPersistence: .keychain)
            try check(f.jobs.isEmpty); return done()
        }
        if mode == "capture-revoke" {
            let binding = try f.binding()
            let candidate = runtime.persistence.captureManual(Data("manual".utf8), binding: binding)!
            try check(!candidate.isCleared)
            try runtime.configuration.setAuthentication(mode: .password, login: "employee")
            try check(candidate.isCleared); try f.flush(); try check(f.driver.deletes == 1); return done()
        }
        if mode == "new-save" {
            let binding = try f.binding()
            let candidate = runtime.persistence.captureManual(Data("manual".utf8), binding: binding)!
            let snapshot = VPNTunnelSnapshot(schemaVersion: 2, generation: 1, desiredEnabled: true, phase: .connected,
                active: binding.attempt.application, pending: nil, challenge: nil, attempt: binding.attempt, issuedCredentialKinds: [.vpnPassword])
            runtime.persistence.saveVerified(candidate, snapshot: snapshot, sessionIdentifier: binding.sessionIdentifier)
            try check(f.jobs.count == 1 && f.driver.adds == 0)
            try f.flush()
            try check(f.driver.adds == 1 && f.driver.deletes == 1 && f.driver.refs == [old]
                && f.store.load()!.passwordLedger.active?.reference != old && runtime.cleanupDetail == nil)
            return done()
        }
        if mode == "startup" || mode == "unknown-delete" || mode == "partial" || mode == "unknown-add" {
            // Queue the old item before constructing presentation; no lifecycle callback.
            let before = try f.store.load()!
            var next = before.saved.configuration
            try next.setAuthentication(VPNAuthentication(mode: .password, login: "different", credentialPersistence: .keychain))
            _ = try f.store.save(next, importing: nil, expectedRevision: before.saved.configuration.revision)
            f.driver.unknown = mode == "unknown-delete"
            if mode == "partial" { f.driver.outcome = .notFound }
            runtime.start(); runtime.start(); try check(f.jobs.count == 1); try f.flush()
            if mode == "startup" { try check(f.driver.deletes == 1 && runtime.cleanupDetail == nil) }
            if mode == "unknown-add" { try check(f.driver.deletes == 0 && runtime.cleanupDetail != nil) }
            if mode == "partial" { try check(f.driver.deletes == 1 && runtime.cleanupDetail != nil) }
            if mode == "unknown-delete" {
                try check(f.driver.deletes == 1 && runtime.cleanupDetail != nil)
                runtime.requestCleanup(); try f.flush(); try check(f.driver.deletes == 1 && runtime.cleanupDetail != nil)
            }
            try check(f.jobs.isEmpty); return done()
        }
        switch mode {
        case "revoke": try runtime.configuration.setAuthentication(mode: .password, login: "employee")
        case "login": try runtime.configuration.setAuthentication(mode: .password, login: "other", credentialPersistence: .keychain)
        case "mode": try runtime.configuration.setAuthentication(mode: .oneTimePassword, login: "employee")
        case "import": try runtime.configuration.importProfile(data: Data(profileText.replacingOccurrences(of: "vpn.company", with: "changed.company").utf8), name: "company.ovpn")
        case "remove":
            try runtime.configuration.setEnabled(false)
            try f.store.acknowledgeStopped(revision: f.store.load()!.applied!.configuration.revision)
            try runtime.configuration.load()
            try runtime.configuration.removeProfile()
        default: fatalError("unknown test")
        }
        try check(!f.jobs.isEmpty); try f.flush()
        try check(f.driver.deletes == 1 && f.driver.prepared == 1 && f.store.load()!.passwordLedger.pendingDeletion.isEmpty && runtime.cleanupDetail == nil)
        done()
    }
    static func done() { print("runtime checks passed") }
}
