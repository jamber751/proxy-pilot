import Combine
import CryptoKit
import Foundation

enum VPNLiveState: Equatable {
    case unavailable
    case off
    case connecting
    case needsCredential(VPNCredentialKind)
    case connected
    case failed(String)

    var label: String {
        switch self {
        case .unavailable: return "VPN не установлен"
        case .off: return "VPN выключен"
        case .connecting: return "Подключаемся…"
        case .needsCredential(.privateKeyPassword): return "Введите пароль ключа"
        case .needsCredential(.vpnPassword): return "Введите пароль или код"
        case .connected: return "VPN включён"
        case .failed(let message): return message
        }
    }
}

protocol VPNLiveSession: AnyObject {
    func storeProfile(_ profile: Data) throws -> VPNHelperStatus
    func apply(_ specification: VPNApplicationSpec) throws -> VPNHelperStatus
    func connect() throws -> (VPNHelperStatus, VPNCredentialChallenge?)
    func disconnectTunnel() throws -> VPNHelperStatus
    func tunnelStatus() throws -> (VPNHelperStatus, VPNTunnelSnapshot?)
    func submitCredentialExchange(_ response: inout VPNCredentialResponse) throws
        -> (VPNHelperStatus, VPNCredentialChallenge?)
    func cancelCredential(_ challenge: VPNCredentialChallenge) throws -> VPNHelperStatus
    func close()
}

#if !VPN_LIVE_CONTROLLER_TESTING
extension VPNHelperSession: VPNLiveSession {}
#endif

enum VPNLiveControllerError: Error, LocalizedError {
    case notConfigured, unsupportedResources, helperRejected, unverifiedState
    case profileRejected, configurationRejected, engineStartFailed

    var errorDescription: String? {
        switch self {
        case .notConfigured: return "Сначала завершите настройку VPN."
        case .unsupportedResources:
            return "В этой версии через VPN можно открыть IP-адреса и сети. Доменные имена пока недоступны."
        case .helperRejected: return "Не удалось применить настройки VPN. Попробуйте ещё раз."
        case .profileRejected: return "Компонент VPN не принял файл конфигурации. Проверьте профиль и повторите попытку."
        case .configurationRejected: return "Компонент VPN не принял настройки подключения. Проверьте ресурсы и способ входа."
        case .engineStartFailed: return "Не удалось запустить подключение VPN. Попробуйте ещё раз."
        case .unverifiedState: return "Подключение не подтверждено. Попробуйте ещё раз."
        }
    }
}

/// One-button owner for the ordinary app. Persisted intent is never treated as
/// live state; `connected` is published only after reading the helper's exact
/// route-proven snapshot back over the authenticated session.
final class VPNLiveController: ObservableObject {
    @Published private(set) var state: VPNLiveState = .off
    @Published private(set) var busy = false

    private let store: VPNStore
    private let openSession: () throws -> VPNLiveSession
    private var session: VPNLiveSession?
    private var challenge: VPNCredentialChallenge?
    private var expectedApplication: VPNApplicationSpec?

    #if VPN_LIVE_CONTROLLER_TESTING
    init(store: VPNStore, openSession: @escaping () throws -> VPNLiveSession) {
        self.store = store
        self.openSession = openSession
    }
    #else
    init(store: VPNStore,
         openSession: @escaping () throws -> VPNLiveSession = {
             try VPNFrontendHelperSession.open()
         }) {
        self.store = store
        self.openSession = openSession
    }
    #endif

    deinit { session?.close() }

    func refresh() {
        guard !busy else { return }
        do {
            let live = try openSession()
            defer { live.close() }
            let (status, snapshot) = try live.tunnelStatus()
            guard status == .ok, let snapshot else { throw VPNLiveControllerError.unverifiedState }
            state = Self.project(snapshot)
        } catch {
            state = .unavailable
        }
    }

    func connect() {
        guard !busy else { return }
        busy = true; state = .connecting
        do {
            closeHeldSession()
            let input = try enabledInput()
            let live = try openSession()
            session = live
            guard try live.storeProfile(input.profile) == .ok else {
                throw VPNLiveControllerError.profileRejected
            }
            guard try live.apply(input.application) == .ok else {
                throw VPNLiveControllerError.configurationRejected
            }
            expectedApplication = input.application
            let result = try live.connect()
            guard result.0 == .ok || result.0 == .needsCredential else {
                throw VPNLiveControllerError.engineStartFailed
            }
            try accept(result, revision: input.application.revision)
        } catch {
            fail(error)
        }
        busy = false
    }

    func submitCredential(_ secret: inout Data) {
        guard !busy, let live = session, let challenge else {
            secret.resetBytes(in: 0..<secret.count)
            secret.removeAll(keepingCapacity: false)
            return
        }
        busy = true; state = .connecting
        var response = VPNCredentialResponse(challenge: challenge, secret: secret)
        secret.resetBytes(in: 0..<secret.count)
        secret.removeAll(keepingCapacity: false)
        defer {
            response.secret.resetBytes(in: 0..<response.secret.count)
            response.secret.removeAll(keepingCapacity: false)
            busy = false
        }
        do {
            let result = try live.submitCredentialExchange(&response)
            let revision = try expectedApplication.unwrap().revision
            try accept(result, revision: revision)
        } catch {
            fail(error)
        }
    }

    func cancelCredential() {
        guard !busy, let live = session, let challenge else { return }
        busy = true
        defer { busy = false }
        do {
            guard try live.cancelCredential(challenge) == .ok else {
                throw VPNLiveControllerError.helperRejected
            }
            closeHeldSession()
            try persistDisabledAfterStop()
            state = .off
        } catch { fail(error) }
    }

    func disconnect() {
        guard !busy else { return }
        busy = true
        defer { busy = false }
        do {
            let live: VPNLiveSession
            if let held = session { live = held }
            else { live = try openSession() }
            guard try live.disconnectTunnel() == .ok else {
                throw VPNLiveControllerError.helperRejected
            }
            live.close(); session = nil; challenge = nil; expectedApplication = nil
            try persistDisabledAfterStop()
            state = .off
        } catch { fail(error) }
    }

    private func enabledInput() throws -> (profile: Data, application: VPNApplicationSpec) {
        guard var stored = try store.load(),
              let name = stored.saved.configuration.profileName,
              let bytes = stored.saved.profileContents,
              let authentication = stored.saved.configuration.authentication else {
            throw VPNLiveControllerError.notConfigured
        }
        var configuration = stored.saved.configuration
        guard configuration.corporateDNS.isEmpty,
              !configuration.resources.contains(where: { $0.kind == .domain }) else {
            throw VPNLiveControllerError.unsupportedResources
        }
        if !configuration.desiredEnabled {
            try configuration.setEnabled(true)
            stored = try store.save(configuration,
                expectedRevision: stored.saved.configuration.revision)
        }
        let profile = try VPNProfileImporter.inspect(data: bytes, name: name)
        guard profile.supports(authentication: authentication) else {
            throw VPNLiveControllerError.notConfigured
        }
        let digest = SHA256.hash(data: profile.protectedContents)
            .map { String(format: "%02x", $0) }.joined()
        let application = try VPNApplicationSpec(
            revision: stored.saved.configuration.revision,
            profileSHA256: digest, resources: stored.saved.configuration.resources,
            corporateDNS: stored.saved.configuration.corporateDNS,
            authentication: authentication)
        try application.validateCurrentRuntimeCapability()
        return (profile.protectedContents, application)
    }

    private func accept(_ result: (VPNHelperStatus, VPNCredentialChallenge?),
                        revision: UInt64) throws {
        switch result.0 {
        case .needsCredential:
            guard let next = result.1 else { throw VPNLiveControllerError.unverifiedState }
            challenge = next
            state = .needsCredential(next.kind)
        case .ok:
            guard let live = session, let expectedApplication else {
                throw VPNLiveControllerError.unverifiedState
            }
            let (status, snapshot) = try live.tunnelStatus()
            guard status == .ok, let snapshot, snapshot.phase == .connected,
                  snapshot.active?.spec == expectedApplication else {
                throw VPNLiveControllerError.unverifiedState
            }
            try store.acknowledgeApplied(revision: revision)
            closeHeldSession(); state = .connected
        default:
            throw VPNLiveControllerError.helperRejected
        }
    }

    private func fail(_ error: Error) {
        closeHeldSession()
        if let localized = error as? LocalizedError,
           let description = localized.errorDescription {
            state = .failed(description)
        } else {
            state = .failed("Не удалось подключить VPN. Попробуйте ещё раз.")
        }
    }

    private func persistDisabledAfterStop() throws {
        guard let before = try store.load() else {
            throw VPNLiveControllerError.notConfigured
        }
        let appliedRevision = before.applied?.configuration.revision
            ?? before.saved.configuration.revision
        var disabled = before.saved.configuration
        try disabled.setEnabled(false)
        if disabled.revision != before.saved.configuration.revision {
            _ = try store.save(disabled,
                expectedRevision: before.saved.configuration.revision)
        }
        try store.acknowledgeStopped(revision: appliedRevision)
    }

    private func closeHeldSession() {
        session?.close(); session = nil; challenge = nil; expectedApplication = nil
    }

    private static func project(_ snapshot: VPNTunnelSnapshot) -> VPNLiveState {
        switch snapshot.phase {
        case .off, .pending: return .off
        case .connecting, .authenticating: return .connecting
        case .needsCredential:
            return snapshot.challenge.map { .needsCredential($0.kind) }
                ?? .failed("Подключение не подтверждено. Попробуйте ещё раз.")
        case .connected: return .connected
        case .failed: return .failed("Не удалось подключить VPN. Попробуйте ещё раз.")
        }
    }
}

private extension Optional {
    func unwrap() throws -> Wrapped {
        guard let self else { throw VPNLiveControllerError.unverifiedState }
        return self
    }
}
