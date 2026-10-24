// Actual adapter and Store, synthetic imported bytes, no View/window/helper/API.
import Foundation
import Darwin

extension VPNLiveController {
    convenience init(store: VPNStore) {
        self.init(store: store, openSession: { throw VPNLiveControllerError.unverifiedState })
    }
}

@main enum CertificateRecoveryChecks {
    enum Failure: Error { case check }
    static let certificate = """
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
    static func check(_ condition: @autoclosure () throws -> Bool) throws {
        guard try condition() else { throw Failure.check }
    }
    static func addResource(_ model: VPNModel, address: String) throws {
        model.beginAddingResource()
        model.resourceDraft = VPNResourceDraft(name: "Synthetic", address: address)
        try model.saveResourceDraft()
    }
    static func imported(_ store: VPNStore, needsPassword: Bool = false, resources: Bool = true) throws {
        let initial = VPNModel(store: store)
        let bytes = certificate + (needsPassword ? "\nauth-user-pass\n" : "\n")
        try initial.importProfile(data: Data(bytes.utf8), name: "synthetic.ovpn")
        if resources { try addResource(initial, address: "10.20.0.0/16") }
        // Stop at the REAL durable import boundary, before the Panel's separate
        // certificate-auth metadata write. Do not copy an invented JSON state.
        try check(initial.configuration.authentication == nil)
    }
    static func run() throws {
        precondition(Thread.isMainThread)
        let args = CommandLine.arguments
        guard args.count == 3 else { throw Failure.check }
        let store = VPNStore(directory: URL(fileURLWithPath: args[2], isDirectory: true))
        let mode = args[1]
        if mode != "missing" { try imported(store, needsPassword: mode == "password", resources: mode != "resources") }
        let initial = try store.load()
        var writes = 0, helperOpens = 0
        // New model/adapter simulates reopening after interruption. Neither
        // construction nor saving metadata is allowed to initiate a helper.
        let reopened = VPNModel(store: store, didPersist: { writes += 1 })
        try reopened.load()
        let controller = VPNLiveController(store: store, openSession: {
            helperOpens += 1; throw VPNLiveControllerError.unverifiedState
        })
        let panel = VPNPanelModel(configuration: reopened, controller: controller)
        panel.settings = true
        switch mode {
        case "save", "continue", "resources":
            try check(reopened.profile?.requiresCredentials == false)
            if mode == "save" {
                panel.beginAuthentication()
                try check(panel.authenticationChoice == .certificate)
                panel.saveAuthentication()
                try check(!panel.editingAuthentication)
            } else { panel.finishSettings() }
            let saved = try store.load()!
            try check(saved.saved.configuration.authentication?.mode == .certificate &&
                saved.saved.configuration.authentication?.login == nil &&
                saved.saved.configuration.authentication?.credentialPersistence == VPNCredentialPersistence.none &&
                saved.saved.profileContents == initial!.saved.profileContents &&
                saved.saved.configuration.resources == initial!.saved.configuration.resources &&
                saved.passwordLedger == initial!.passwordLedger && !saved.saved.configuration.desiredEnabled && writes == 1)
            if mode == "resources" {
                try check(!panel.ready && panel.settings && panel.message == VPNConnectionAvailability.needsResources.label)
                try addResource(reopened, address: "10.21.0.0/16")
                panel.finishSettings()
            } else {
                try check(panel.ready && panel.message.isEmpty)
                panel.finishSettings()
            }
            let revision = try store.load()!.saved.configuration.revision
            panel.beginAuthentication(); panel.saveAuthentication(); panel.finishSettings()
            try check(panel.ready && !panel.settings && panel.message.isEmpty && store.load()!.saved.configuration.revision == revision)
        case "save-error", "continue-error":
            let stateFile = store.directory.appendingPathComponent("state.json")
            let before = try Data(contentsOf: stateFile)
            if mode == "save-error" { panel.beginAuthentication() }
            let lock = open(store.directory.appendingPathComponent("state.lock").path, O_RDWR | O_NOFOLLOW | O_CLOEXEC)
            try check(lock >= 0 && flock(lock, LOCK_EX | LOCK_NB) == 0)
            do {
                defer { flock(lock, LOCK_UN); close(lock) }
                if mode == "save-error" { panel.saveAuthentication() } else { panel.finishSettings() }
                try check(!panel.ready && panel.settings && !panel.message.isEmpty && writes == 0 &&
                    (mode != "save-error" || panel.editingAuthentication) && before == Data(contentsOf: stateFile))
            }
            try check(store.load() == initial)
            // Reopen after storage becomes available. The still-valid partial
            // import must be recoverable, not converted into a password prompt.
            let retryModel = VPNModel(store: store, didPersist: { writes += 1 }); try retryModel.load()
            let retry = VPNPanelModel(configuration: retryModel, controller: controller); retry.settings = true
            if mode == "save-error" { retry.beginAuthentication(); retry.saveAuthentication() }
            retry.finishSettings()
            try check(retry.ready && !retry.settings && retry.message.isEmpty && writes == 1 &&
                retryModel.configuration.authentication?.mode == .certificate &&
                store.load()!.saved.profileContents == initial!.saved.profileContents)
        case "password":
            panel.beginAuthentication()
            try check(panel.authenticationChoice == nil && reopened.profile?.requiresCredentials == true)
            panel.saveAuthentication(); panel.finishSettings()
            try check(!panel.ready && !panel.message.isEmpty && store.load() == initial && writes == 0)
            try reopened.setAuthentication(mode: .password, login: "Employee", credentialPersistence: .keychain)
            let revision = reopened.configuration.revision
            let reference = try store.grantPasswordPersistence(expectedRevision: revision)
            try reopened.load()
            let before = try store.load()
            panel.beginAuthentication(); panel.saveAuthentication(); panel.finishSettings()
            try check(panel.authenticationChoice == .password && panel.ready && store.load() == before &&
                store.load()!.passwordLedger.active?.reference == reference &&
                reopened.configuration.authentication?.credentialPersistence == .keychain)
            // An explicit OTP choice still works and never inherits consent.
            panel.beginAuthentication(); panel.selectAuthentication(.oneTimePassword); panel.saveAuthentication()
            try check(reopened.configuration.authentication?.mode == .oneTimePassword &&
                reopened.configuration.authentication?.credentialPersistence == VPNCredentialPersistence.none)
        case "missing":
            panel.beginAuthentication(); panel.saveAuthentication(); panel.finishSettings()
            try check(reopened.profile == nil && !panel.ready && panel.settings && store.load() == nil && writes == 0 &&
                reopened.configuration.authentication == nil)
        case "stale":
            panel.beginAuthentication()
            try check(panel.authenticationChoice == .certificate)
            let other = VPNModel(store: store); try other.load()
            try other.importProfile(data: Data((certificate + "\nauth-user-pass\n").utf8), name: "replacement.ovpn")
            let replaced = try store.load()
            panel.saveAuthentication()
            try check(!panel.message.isEmpty && store.load() == replaced && writes == 0 &&
                reopened.profile?.requiresCredentials == true && reopened.configuration.authentication == nil)
            panel.cancelAuthentication(); panel.beginAuthentication(); panel.saveAuthentication()
            try check(panel.authenticationChoice == nil && !panel.ready && store.load() == replaced)
        default: throw Failure.check
        }
        try check(helperOpens == 0 && !panel.working && controller.state == .off &&
            !reopened.configuration.desiredEnabled && !panel.needsCredential && panel.secret.isEmpty)
    }
    static func main() {
        do { try run(); print("certificate recovery check passed") }
        catch { fputs("certificate recovery check failed\n", stderr); exit(77) }
    }
}
