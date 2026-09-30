import Foundation

private let credentialProfile = """
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

private let inlineLoginProfile = """
client
dev tun
proto udp
remote vpn.company.example 1194
remote-cert-tls server
<auth-user-pass>
devzotarbayev
</auth-user-pass>
<ca>
-----BEGIN CERTIFICATE-----
QUJDRA==
-----END CERTIFICATE-----
</ca>
"""

@main struct VPNModelChecks {
    static var checks = 0

    static func check(_ condition: @autoclosure () throws -> Bool, _ message: String) throws {
        guard try condition() else {
            throw NSError(domain: "VPNModelChecks", code: 1,
                          userInfo: [NSLocalizedDescriptionKey: message])
        }
        checks += 1
    }

    static func rejects(_ expected: VPNValidationError, _ operation: () throws -> Void) throws {
        do { try operation() }
        catch let error as VPNValidationError where error == expected { checks += 1; return }
        throw NSError(domain: "VPNModelChecks", code: 2,
                      userInfo: [NSLocalizedDescriptionKey: "Expected \(expected)"])
    }

    static func rejectsImport(_ operation: () throws -> Void) throws {
        do { try operation() }
        catch is VPNImportError { checks += 1; return }
        throw NSError(domain: "VPNModelChecks", code: 4,
                      userInfo: [NSLocalizedDescriptionKey: "Expected VPN import rejection"])
    }

    static func main() throws {
        let base = URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true)
        try loadImportAndDrafts(base.appendingPathComponent("primary"))
        try staleRevision(base.appendingPathComponent("stale"))
        try pendingLabels(base.appendingPathComponent("pending"))
        try suggestedRoutes(base.appendingPathComponent("suggestions"))
        try previewIsolation(base.appendingPathComponent("must-not-exist"))
        try inlineLoginImport()
        print("vpn-model: \(checks) checks passed")
    }

    static func inlineLoginImport() throws {
        let imported = try VPNProfileImporter.inspect(data: Data(inlineLoginProfile.utf8),
                                                      name: "devzotarbayev.ovpn")
        try check(imported.requiresCredentials && imported.suggestedLogin == "devzotarbayev",
                  "username-only inline auth file is recognized without a secret")
        let roundTrip = try VPNProfileImporter.inspect(data: imported.protectedContents,
                                                       name: imported.name)
        try check(roundTrip.suggestedLogin == "devzotarbayev",
                  "suggested login survives protected profile persistence")
        let commented = inlineLoginProfile.replacingOccurrences(
            of: "devzotarbayev\n</auth-user-pass>",
            with: "# generated login\ndevzotarbayev\n\n</auth-user-pass>")
        let normalized = try VPNProfileImporter.inspect(data: Data(commented.utf8), name: "comments.ovpn")
        let normalizedText = String(decoding: normalized.protectedContents, as: UTF8.self)
        try check(!normalizedText.contains("generated login") && normalized.suggestedLogin == "devzotarbayev",
                  "inline auth comments are not passed to OpenVPN as credentials")
        let embeddedPassword = inlineLoginProfile.replacingOccurrences(
            of: "devzotarbayev\n</auth-user-pass>",
            with: "devzotarbayev\nsecret\n</auth-user-pass>")
        try rejectsImport {
            _ = try VPNProfileImporter.inspect(data: Data(embeddedPassword.utf8), name: "secret.ovpn")
        }
    }

    static func loadImportAndDrafts(_ directory: URL) throws {
        let store = VPNStore(directory: directory)
        let model = VPNModel(store: store)
        try model.load()
        try check(model.configuration == VPNConfiguration() && model.profile == nil,
                  "an absent store loads as an empty model")
        try check(model.connectionAvailability == .needsProfile,
                  "empty model asks for a profile")
        try check(model.persistence == .notConfigured && model.persistenceLabel == "Не настроен",
                  "empty persistence label")

        let input = directory.deletingLastPathComponent().appendingPathComponent("Корпоративный.ovpn")
        try Data(credentialProfile.utf8).write(to: input)
        try model.importProfile(files: [input])
        try check(model.profile?.name == "Корпоративный.ovpn" && model.profile?.requiresCredentials == true,
                  "file import exposes safe profile metadata")
        try check(model.configuration.authentication == nil,
                  "auth-user-pass remains undecided after import")
        try check(model.connectionAvailability == .needsResources,
                  "imported profile asks for resources before authentication")
        try check(model.persistence == .saved && !model.connected,
                  "an imported disabled profile is saved, never reported connected")

        model.beginAddingResource()
        model.resourceDraft?.name = "GitLab"
        model.resourceDraft?.address = "GITLAB.company.example."
        try model.saveResourceDraft()
        let resource = try model.configuration.resources.first.unwrap("missing added resource")
        try check(model.connectionAvailability == .needsAuthentication,
                  "resource list asks for an authentication choice")
        try check(resource.name == "GitLab" && resource.address == "gitlab.company.example",
                  "resource draft validates, normalizes and saves once")

        try model.beginEditingResource(id: resource.id)
        model.resourceDraft?.address = "discarded.company.example"
        model.cancelResourceDraft()
        try check(model.configuration.resources.first?.address == "gitlab.company.example",
                  "cancel leaves the saved resource untouched")

        try model.beginEditingResource(id: resource.id)
        model.resourceDraft?.name = "Source"
        model.resourceDraft?.address = "code.company.example"
        try model.saveResourceDraft()
        try check(model.configuration.resources.count == 1 &&
                  model.configuration.resources.first?.id == resource.id &&
                  model.configuration.resources.first?.name == "Source",
                  "editing preserves identity without a second list save")

        try model.setAuthentication(mode: .password, login: " employee ", credentialPersistence: .keychain)
        try check(model.connectionAvailability == .splitDNSUnavailable
                  && model.connectionAvailabilityLabel.contains("IP-адреса"),
                  "domain-only intent explains the current runtime limitation")
        try check(model.configuration.authentication ==
                  (try VPNAuthentication(mode: .password, login: "employee", credentialPersistence: .keychain)),
                  "password selection persists metadata only")
        let encoded = try JSONEncoder().encode(model.configuration)
        try check(!String(decoding: encoded, as: UTF8.self).contains("password\":"),
                  "configuration contains no password value")

        let replacement = credentialProfile + "\nremote backup.company.example 1194\n"
        try model.importProfile(data: Data(replacement.utf8), name: "replacement.ovpn")
        try check(model.configuration.profileName == "replacement.ovpn" &&
                  model.configuration.resources.count == 1 &&
                  model.configuration.resources.first?.id == resource.id,
                  "replacement keeps resource identities")
        try check(model.configuration.authentication == nil,
                  "replacement clears old authentication consent")
        let replacementState = model.configuration
        let replacementSummary = model.profile
        try rejectsImport {
            try model.importProfile(data: Data("not a profile".utf8), name: "broken.ovpn")
        }
        try check(model.configuration == replacementState && model.profile == replacementSummary &&
                  !model.error.isEmpty,
                  "rejected replacement publishes an error and preserves the active snapshot")
        try model.setAuthentication(mode: .oneTimePassword, login: "employee")
        try check(model.configuration.authentication?.mode == .oneTimePassword,
                  "OTP selection persists its mode")
        try check(model.configuration.authentication?.login == "employee" &&
                  model.configuration.authentication?.credentialPersistence == VPNCredentialPersistence.none,
                  "OTP metadata has a login and no persistence")
        let unchangedRevision = model.configuration.revision
        try model.setAuthentication(mode: .oneTimePassword, login: "employee")
        try check(model.configuration.revision == unchangedRevision,
                  "saving unchanged authentication is an idempotent no-op")
        let reloaded = VPNModel(store: store)
        try reloaded.load()
        try check(reloaded.configuration == model.configuration && reloaded.profile == model.profile,
                  "a fresh model loads the complete saved projection")

        try reloaded.removeProfile()
        try check(reloaded.profile == nil && reloaded.configuration.profileName == nil &&
                  reloaded.configuration.resources.isEmpty && reloaded.configuration.authentication == nil,
                  "removing VPN clears the protected profile projection and settings")
        try check(try store.load()?.saved.profileContents == nil,
                  "removing VPN drops protected profile bytes from the atomic store")

        try rejects(.invalidConfiguration) {
            try model.setAuthentication(mode: .certificate)
        }
        try check(model.configuration.authentication?.mode == .oneTimePassword,
                  "incompatible auth metadata does not replace the saved selection")

        let certificate = VPNModel(store: VPNStore(directory: directory.appendingPathComponent("certificate")))
        try certificate.importProfile(data: Data(certificateProfile.utf8), name: "certificate.ovpn")
        try certificate.setAuthentication(mode: .certificate)
        try check(certificate.configuration.authentication?.mode == .certificate,
                  "certificate profiles accept certificate metadata")
        try rejects(.invalidConfiguration) {
            try certificate.setAuthentication(mode: .password, login: "employee")
        }
    }

    static func staleRevision(_ directory: URL) throws {
        let store = VPNStore(directory: directory)
        let first = VPNModel(store: store)
        try first.importProfile(data: Data(credentialProfile.utf8), name: "company.ovpn")
        first.beginAddingResource()
        first.resourceDraft?.address = "one.company.example"
        try first.saveResourceDraft()

        let stale = VPNModel(store: store)
        try stale.load()
        first.beginAddingResource()
        first.resourceDraft?.address = "two.company.example"
        try first.saveResourceDraft()

        try rejects(.staleRevision) {
            try stale.setAuthentication(mode: .password, login: "employee")
        }
        try check(stale.configuration == first.configuration && stale.profile == first.profile,
                  "a stale write reloads the winning snapshot")
        try check(stale.error == VPNValidationError.staleRevision.localizedDescription,
                  "stale revision remains visible to the UI")
    }

    static func pendingLabels(_ directory: URL) throws {
        let store = VPNStore(directory: directory)
        let model = VPNModel(store: store)
        try model.importProfile(data: Data(credentialProfile.utf8), name: "company.ovpn")
        model.beginAddingResource()
        model.resourceDraft?.address = "git.company.example"
        try model.saveResourceDraft()
        try model.setAuthentication(mode: .password, login: "employee")
        try model.setEnabled(true)
        try check(model.persistence == .pendingApplication &&
                  model.persistenceLabel == "Ожидает подключения" && !model.connected,
                  "enabled intent is pending, not a live connection")

        try store.acknowledgeApplied(revision: model.configuration.revision)
        try model.load()
        try check(model.persistence == .applied && model.persistenceLabel == "Применено",
                  "verified applied revision has a distinct label")
        try check(!model.connected, "even an applied snapshot is not guessed live")

        model.beginAddingResource()
        model.resourceDraft?.address = "wiki.company.example"
        try model.saveResourceDraft()
        try check(model.persistence == .pendingApplication,
                  "editing an applied snapshot returns to pending")
    }

    static func suggestedRoutes(_ directory: URL) throws {
        let model = VPNModel(store: VPNStore(directory: directory))
        let profile = credentialProfile + "\nroute 10.44.0.0 255.255.0.0\nroute 10.55.4.8\n"
        try model.importProfile(data: Data(profile.utf8), name: "routes.ovpn")
        try check(model.configuration.resources.isEmpty && model.suggestedResources.count == 2,
                  "profile routes remain explicit suggestions")
        try model.acceptSupportedSuggestions()
        try check(Set(model.configuration.resources.map(\.address)) == Set(["10.44.0.0/16", "10.55.4.8"]),
                  "accepted IP suggestions are committed together")
        let revision = model.configuration.revision
        try model.acceptSupportedSuggestions()
        try check(model.configuration.revision == revision,
                  "accepting the same suggestions is an idempotent no-op")
    }

    static func previewIsolation(_ forbidden: URL) throws {
        try check(!FileManager.default.fileExists(atPath: forbidden.path), "preview sentinel starts absent")
        let preview = VPNModel()
        try preview.load()
        try preview.importProfile(data: Data(credentialProfile.utf8), name: "preview.ovpn")
        preview.beginAddingResource()
        preview.resourceDraft?.address = "preview.company.example"
        try preview.saveResourceDraft()
        try preview.setAuthentication(mode: .oneTimePassword, login: "preview")
        try check(preview.preview && preview.storedState == nil &&
                  preview.configuration.resources.count == 1,
                  "preview editing is memory-only")
        try check(!FileManager.default.fileExists(atPath: forbidden.path),
                  "preview never creates the production-like sentinel path")
        try check(!preview.connected, "preview cannot claim a live tunnel")
    }
}

private extension Optional {
    func unwrap(_ message: String) throws -> Wrapped {
        guard let value = self else {
            throw NSError(domain: "VPNModelChecks", code: 3,
                          userInfo: [NSLocalizedDescriptionKey: message])
        }
        return value
    }
}
