import Combine
import Foundation

/// Narrow persistence boundary used by the menu-bar model. Production uses the
/// private on-disk store; previews inject no store and therefore cannot touch a
/// user's profile or settings.
protocol VPNModelStore: AnyObject {
    func load() throws -> VPNStoredState?
    func save(_ configuration: VPNConfiguration, importing profile: VPNImportedProfile?,
              expectedRevision: UInt64?) throws -> VPNStoredState
}

extension VPNStore: VPNModelStore {}

enum VPNModelPersistence: Equatable {
    case notConfigured
    case saved
    case pendingApplication
    case applied

    var label: String {
        switch self {
        case .notConfigured: return "Не настроен"
        case .saved: return "Сохранено"
        case .pendingApplication: return "Ожидает подключения"
        case .applied: return "Применено"
        }
    }
}

enum VPNConnectionAvailability: Equatable {
    case needsProfile
    case needsResources
    case needsAuthentication
    case splitDNSUnavailable
    case ready

    var label: String {
        switch self {
        case .needsProfile: return "Добавьте файл VPN"
        case .needsResources: return "Добавьте рабочие ресурсы"
        case .needsAuthentication: return "Выберите способ входа"
        case .splitDNSUnavailable:
            return "В этой версии через VPN можно открыть IP-адреса и сети. Доменные имена пока недоступны."
        case .ready: return "Готово к подключению"
        }
    }
}

struct VPNProfileSummary: Equatable {
    let name: String
    let requiresCredentials: Bool
    let requiresKeyPassword: Bool
    let suggestedDNS: [String]
    let suggestedResources: [VPNResource]
    let hasIgnoredRoutes: Bool

    init(_ profile: VPNImportedProfile) {
        name = profile.name
        requiresCredentials = profile.requiresCredentials
        requiresKeyPassword = profile.requiresKeyPassword
        suggestedDNS = profile.suggestedDNS
        suggestedResources = profile.suggestedResources
        hasIgnoredRoutes = profile.hasIgnoredRoutes
    }

    func supports(_ authentication: VPNAuthentication?) -> Bool {
        guard let authentication else { return true }
        return requiresCredentials ? authentication.mode != .certificate : authentication.mode == .certificate
    }
}

struct VPNResourceDraft: Equatable {
    let id: UUID?
    var name: String
    var address: String

    init(id: UUID? = nil, name: String = "", address: String = "") {
        self.id = id
        self.name = name
        self.address = address
    }
}

/// Saved configuration state for the future VPN views. This layer deliberately
/// has no runtime/controller dependency: an applied snapshot is not proof that
/// a tunnel is connected now, so `connected` never guesses from persisted data.
final class VPNModel: ObservableObject {
    @Published private(set) var configuration: VPNConfiguration
    @Published private(set) var profile: VPNProfileSummary?
    @Published private(set) var storedState: VPNStoredState?
    @Published var resourceDraft: VPNResourceDraft?
    @Published private(set) var error: String = ""

    let preview: Bool
    private let store: VPNModelStore?

    init(store: VPNModelStore) {
        self.store = store
        preview = false
        configuration = VPNConfiguration()
    }

    /// Preview state is intentionally memory-only. It may exercise validation
    /// and editing, but it cannot resolve or create a production storage path.
    init(previewConfiguration: VPNConfiguration = VPNConfiguration()) {
        store = nil
        preview = true
        configuration = previewConfiguration
    }

    var persistence: VPNModelPersistence {
        guard configuration.profileName != nil else { return .notConfigured }
        guard let storedState else { return .saved }
        if storedState.applied == nil {
            return configuration.desiredEnabled ? .pendingApplication : .saved
        }
        if storedState.hasPendingChanges { return .pendingApplication }
        return .applied
    }

    var persistenceLabel: String { persistence.label }

    /// A user-facing projection of the capabilities in the installed
    /// route-only helper. It does not infer live state or mutate configuration.
    var connectionAvailability: VPNConnectionAvailability {
        guard profile != nil else { return .needsProfile }
        guard !configuration.resources.isEmpty else { return .needsResources }
        guard configuration.authentication != nil else { return .needsAuthentication }
        guard configuration.corporateDNS.isEmpty,
              !configuration.resources.contains(where: { $0.kind == .domain }) else {
            return .splitDNSUnavailable
        }
        return .ready
    }

    var connectionAvailabilityLabel: String { connectionAvailability.label }

    /// Live status belongs to the future controller, never to VPNStore.
    var connected: Bool { false }

    func load() throws {
        guard let store else { return }
        do {
            try adopt(store.load())
            error = ""
        } catch {
            self.error = error.localizedDescription
            throw error
        }
    }

    func importProfile(files: [URL]) throws {
        do {
            let imported = try VPNProfileImporter.inspect(files: files)
            try importProfile(imported)
        } catch {
            self.error = error.localizedDescription
            throw error
        }
    }

    func importProfile(data: Data, name: String) throws {
        do {
            let imported = try VPNProfileImporter.inspect(data: data, name: name)
            try importProfile(imported)
        } catch {
            self.error = error.localizedDescription
            throw error
        }
    }

    func beginAddingResource() {
        resourceDraft = VPNResourceDraft()
        error = ""
    }

    func beginEditingResource(id: UUID) throws {
        guard let resource = configuration.resources.first(where: { $0.id == id }) else {
            throw VPNValidationError.missingResource
        }
        resourceDraft = VPNResourceDraft(id: resource.id, name: resource.name, address: resource.address)
        error = ""
    }

    func cancelResourceDraft() {
        resourceDraft = nil
        error = ""
    }

    func saveResourceDraft() throws {
        guard let draft = resourceDraft else { throw VPNValidationError.missingResource }
        let resource = try VPNResource(id: draft.id ?? UUID(), name: draft.name, address: draft.address)
        var next = configuration
        try next.saveResource(resource, replacing: draft.id)
        try persist(next)
        resourceDraft = nil
    }

    func removeResource(id: UUID, confirmingVPNOff: Bool = false) throws {
        var next = configuration
        try next.removeResource(id: id, confirmingVPNOff: confirmingVPNOff)
        try persist(next)
        if resourceDraft?.id == id { resourceDraft = nil }
    }

    func setAuthentication(mode: VPNAuthenticationMode, login: String? = nil,
                           credentialPersistence: VPNCredentialPersistence = .none) throws {
        let authentication = try VPNAuthentication(mode: mode, login: login,
                                                   credentialPersistence: credentialPersistence)
        guard profile?.supports(authentication) != false else {
            throw VPNValidationError.invalidConfiguration
        }
        var next = configuration
        try next.setAuthentication(authentication)
        try persist(next)
    }

    func clearAuthentication() throws {
        var next = configuration
        try next.setAuthentication(nil)
        try persist(next)
    }

    /// Persists owner intent only. A future controller is responsible for the
    /// actual connection and for acknowledging the applied revision.
    func setEnabled(_ enabled: Bool) throws {
        var next = configuration
        try next.setEnabled(enabled)
        try persist(next)
    }

    private func importProfile(_ imported: VPNImportedProfile) throws {
        var next = configuration
        try next.setProfile(name: imported.name)
        do {
            if let store {
                let saved = try store.save(next, importing: imported,
                                           expectedRevision: storedState?.saved.configuration.revision)
                try adopt(saved)
            } else {
                configuration = next
                profile = VPNProfileSummary(imported)
            }
            resourceDraft = nil
            error = ""
        } catch {
            try recoverFromStale(error)
            self.error = error.localizedDescription
            throw error
        }
    }

    private func persist(_ next: VPNConfiguration) throws {
        do {
            if let store {
                let saved = try store.save(next, importing: nil,
                                           expectedRevision: storedState?.saved.configuration.revision)
                try adopt(saved)
            } else {
                configuration = next
            }
            error = ""
        } catch {
            try recoverFromStale(error)
            self.error = error.localizedDescription
            throw error
        }
    }

    private func recoverFromStale(_ caught: Error) throws {
        guard caught as? VPNValidationError == .staleRevision, let store else { return }
        try adopt(store.load())
    }

    private func adopt(_ state: VPNStoredState?) throws {
        storedState = state
        configuration = state?.saved.configuration ?? VPNConfiguration()
        profile = try state?.saved.inspectProfile().map(VPNProfileSummary.init)
        resourceDraft = nil
    }
}
