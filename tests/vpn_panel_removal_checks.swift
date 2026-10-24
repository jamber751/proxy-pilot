// Real VPN adapter/controller/ProductView, synthetic persistence and helper only.
import AppKit
import SwiftUI

struct RemovalProxyState: Equatable {
    let configured: Bool
    let enabled: Bool
    let running: String
    let systemProxy: Bool
    let ownsSystemProxy: Bool
    let selected: String
    let socksEndpoint: String
    let httpEndpoint: String
}
final class ProxyModel: ObservableObject {
    @Published var state: RemovalProxyState
    @Published var editing = false
    @Published var addingProxy = true
    @Published var choosingRoute = true
    @Published var manual = true
    @Published var address = "unsaved proxy URL"
    @Published var proxyHost = "unsaved.proxy.example"
    @Published var proxyPort = "9999"
    @Published var proxyScheme = "http"
    @Published var error = "synthetic proxy error"
    init(configured: Bool) {
        state = RemovalProxyState(configured: configured, enabled: configured,
            running: configured ? "socks" : "none", systemProxy: configured,
            ownsSystemProxy: configured, selected: "socks",
            socksEndpoint: configured ? "socks5://proxy.example:1080" : "",
            httpEndpoint: configured ? "http://proxy.example:3128" : "")
    }
    var drafts: [String] { [address, proxyHost, proxyPort, proxyScheme, error] }
}
final class UpdateModel: ObservableObject {}
struct RemovalDestination: Equatable {
    let screen: String
    let vpnStatus: String?
    var cleanupDetail: String? = nil
}
struct RemovalDestinationKey: PreferenceKey {
    static var defaultValue = RemovalDestination(screen: "none", vpnStatus: nil)
    static func reduce(value: inout RemovalDestination, nextValue: () -> RemovalDestination) {
        let next = nextValue(); if next.screen != "none" { value = next }
    }
}
struct RemovalRowBoundsKey: PreferenceKey {
    static var defaultValue: CGRect = .zero
    static func reduce(value: inout CGRect, nextValue: () -> CGRect) { value = nextValue() }
}
struct PilotView: View {
    @ObservedObject var model: ProxyModel
    @ObservedObject var updates: UpdateModel
    let openVPN: (() -> Void)?
    let vpnStatus: String?
    let vpnSettingsDetail: String?
    private var accent: Color { PilotTheme.accent }
    private var ink: Color { .primary }
    var body: some View {
        VStack {
            Text(model.editing ? "Application settings" : "Proxy home")
            // ACTUAL_VPN_SETTINGS_ROW
        }
            .preference(key: RemovalDestinationKey.self,
                value: RemovalDestination(screen: model.editing ? "settings" : "home", vpnStatus: vpnStatus, cleanupDetail: vpnSettingsDetail))
    }
}
struct PowerStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        PilotButtonStyle(highlightsSurface: false).makeBody(configuration: configuration)
    }
}
extension VPNLiveController {
    convenience init(store: VPNStore) {
        self.init(store: store, openSession: { throw VPNLiveControllerError.unverifiedState })
    }
}
private final class RemovalSession: VPNLiveSession {
    let rejectStop: Bool
    var stopConfirmed = false
    init(rejectStop: Bool) { self.rejectStop = rejectStop }
    func storeProfile(_ profile: Data) throws -> VPNHelperStatus { fatalError("unexpected profile transport") }
    func apply(_ specification: VPNApplicationSpec) throws -> VPNHelperStatus { fatalError("unexpected apply") }
    func connect() throws -> (VPNHelperStatus, VPNCredentialChallenge?) { fatalError("unexpected connect") }
    func disconnectTunnel() throws -> VPNHelperStatus {
        if rejectStop { return .invalidRequest }
        stopConfirmed = true; return .ok
    }
    func tunnelStatus() throws -> (VPNHelperStatus, VPNTunnelSnapshot?) {
        (.ok, VPNTunnelSnapshot(schemaVersion: 2, generation: 0, desiredEnabled: false,
            phase: .off, active: nil, pending: nil, challenge: nil))
    }
    func submitCredentialExchange(_ response: inout VPNCredentialResponse) throws -> (VPNHelperStatus, VPNCredentialChallenge?) { fatalError("unexpected credential") }
    func cancelCredential(_ challenge: VPNCredentialChallenge) throws -> VPNHelperStatus { fatalError("unexpected cancellation") }
    func close() {}
}
private final class RemovalStore: VPNModelStore {
    let actual: VPNStore
    let rejectDeletion: Bool
    init(actual: VPNStore, rejectDeletion: Bool) { self.actual = actual; self.rejectDeletion = rejectDeletion }
    func load() throws -> VPNStoredState? { try actual.load() }
    func save(_ configuration: VPNConfiguration, importing profile: VPNImportedProfile?, expectedRevision: UInt64?) throws -> VPNStoredState {
        if rejectDeletion && configuration.profileName == nil { throw VPNValidationError.storageUnavailable }
        return try actual.save(configuration, importing: profile, expectedRevision: expectedRevision)
    }
}
private final class RemovalMetrics { var destination = RemovalDestinationKey.defaultValue; var rowBounds: CGRect = .zero }
@main enum VPNPanelRemovalChecks {
    static func require(_ value: @autoclosure () -> Bool, _ message: String) throws {
        guard value() else { throw NSError(domain: message, code: 1) }
    }
    static func settle(_ view: NSView? = nil, cycles: Int = 12) {
        for _ in 0..<cycles {
            view?.layoutSubtreeIfNeeded()
            RunLoop.main.run(until: Date().addingTimeInterval(0.01))
        }
    }
    static func wait(_ panel: VPNPanelModel) throws {
        let deadline = Date().addingTimeInterval(3)
        while panel.working, Date() < deadline { settle(cycles: 1) }
        try require(!panel.working, "removal timed out")
    }
    static func main() throws {
        precondition(Thread.isMainThread)
        let a = CommandLine.arguments
        guard a.count == 3 else { exit(64) }
        let mode = a[1]
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
        try config.setAuthentication(VPNAuthentication(mode: mode == "cleanup-warning" ? .password : .oneTimePassword, login: "employee",
            credentialPersistence: mode == "cleanup-warning" ? .keychain : .none))
        try config.setEnabled(true)
        _ = try store.save(config, importing: profile, expectedRevision: nil)
        let persistence = RemovalStore(actual: store, rejectDeletion: mode == "failed-delete")
        let configuration = VPNModel(store: persistence); try configuration.load()
        let originalSaved = try store.load()!
        let session = RemovalSession(rejectStop: mode == "failed-stop")
        let controller = VPNLiveController(store: store, openSession: { session })
        let panel: VPNPanelModel
        var retainedRuntime: VPNPasswordRuntime?
        var cleanupJobs: [() -> Void] = []
        if mode == "cleanup-warning" {
            let state = try store.load()!
            let reference = try store.createPasswordSaveGrant(expectedRevision: state.saved.configuration.revision, expectedActive: nil)
            _ = try store.addPasswordOnce(reference: reference, expectedRevision: state.saved.configuration.revision) { ref in
                .added(.init(persistentReference: Data(ref.itemID.uuidString.utf8), origin: .init(kind: .legacyKeychain,
                    path: "/synthetic/removal.keychain-db", device: 1, inode: 1, ownerUID: getuid(), birthSeconds: 1, birthNanoseconds: 0)))
            }
            let runtime = VPNPasswordRuntime(store: store, available: true,
                cleanupPrepare: { _ in RemovalCleanupSession() }, schedule: { cleanupJobs.append($0) }, openSession: { session })
            retainedRuntime = runtime
            panel = VPNPanelModel(runtime: runtime)
        } else { panel = VPNPanelModel(configuration: configuration, controller: controller) }
        defer { withExtendedLifetime(retainedRuntime) {} }
        panel.settings = true
        var requests: [VPNPanelNavigationRequest] = []
        var emittedAfterCommit = true
        let observation = panel.$navigationRequest.compactMap { $0 }.sink { request in
            requests.append(request)
            let saved = try? store.load()
            if !session.stopConfirmed || saved == nil || saved?.saved.configuration.profileName != nil { emittedAfterCommit = false }
        }
        defer { observation.cancel() }
        if mode == "consume" {
            panel.confirmRemoveVPN(); try wait(panel)
            guard let request = panel.navigationRequest else { fatalError("successful deletion emitted no request") }
            try require(!panel.consumeNavigationRequest(.applicationSettingsAfterVPNRemoval(UUID())), "stale request consumed current event")
            try require(panel.navigationRequest == request, "stale request erased current event")
            try require(panel.consumeNavigationRequest(request), "current event not consumed")
            try require(!panel.consumeNavigationRequest(request) && panel.navigationRequest == nil, "event consumed twice")
            try require(requests.count == 1 && emittedAfterCommit, "event emitted before stop/commit")
            print("removal consume flow passed"); return
        }
        let app = NSApplication.shared; app.setActivationPolicy(.prohibited)
        let proxy = ProxyModel(configured: mode != "vpn-only")
        let originalState = proxy.state, originalDrafts = proxy.drafts
        let metrics = RemovalMetrics()
        if mode == "pending-on-mount" { panel.confirmRemoveVPN(); try wait(panel) }
        let root = VPNProductView(proxy: proxy, updates: UpdateModel(), vpn: panel)
            .onPreferenceChange(RemovalDestinationKey.self) { metrics.destination = $0 }
            .onPreferenceChange(RemovalRowBoundsKey.self) { metrics.rowBounds = $0 }
        let host = NSHostingView(rootView: root)
        host.frame = NSRect(x: 0, y: 0, width: 344, height: 432)
        let window = NSWindow(contentRect: host.frame, styleMask: [.borderless], backing: .buffered, defer: false)
        window.contentView = host; window.setFrameOrigin(NSPoint(x: -10000, y: -10000)); window.orderBack(nil)
        defer { window.orderOut(nil); window.contentView = nil }
        settle(host)
        if mode != "pending-on-mount" {
            panel.requestsPresentation = true; settle(host); try wait(panel)
            try require(metrics.destination.screen == "vpn", "VPN destination not shown")
            if mode == "cancel" {
                panel.requestVPNRemoval(); panel.confirmVPNRemoval = false
            } else { panel.confirmRemoveVPN(); try wait(panel) }
            settle(host)
        }
        if mode == "cleanup-warning" {
            while !cleanupJobs.isEmpty { cleanupJobs.removeFirst()() }
            let deadline = Date().addingTimeInterval(2)
            while panel.passwordCleanupDetail == nil && Date() < deadline { settle(host, cycles: 1) }
            settle(host)
            try require(metrics.destination.screen == "settings" && panel.configuration.profile == nil,
                "removal warning prevented completed product navigation")
            try require(metrics.destination.cleanupDetail == "Удаление прежних паролей пока не подтверждено. VPN можно использовать.",
                "unknown cleanup warning lost after navigation")
            try require(host.fittingSize.height <= 432 && metrics.rowBounds.height >= 48 && metrics.rowBounds.maxX <= 345
                && metrics.rowBounds.minX >= -1 && metrics.rowBounds.maxY <= 432 && !host.subviewsRecursive.contains(where: { $0 is NSScrollView }),
                "warning introduced scrolling or excessive height")
        }
        try require(proxy.state == originalState && proxy.drafts == originalDrafts, "proxy runtime or draft state changed")
        if mode == "failed-stop" || mode == "failed-delete" || mode == "cancel" {
            try require(panel.navigationRequest == nil && requests.isEmpty, "failed/cancelled deletion emitted navigation")
            try require(metrics.destination.screen == "vpn" && configuration.profile?.name == "synthetic.ovpn",
                        "failed/cancelled deletion left VPN")
            try require(!proxy.editing && proxy.addingProxy && proxy.choosingRoute && proxy.manual,
                        "failed/cancelled deletion changed proxy navigation")
            if mode != "cancel" { try require(!panel.message.isEmpty, "failure not shown inline") }
            else { try require(!session.stopConfirmed, "cancelled dialog stopped VPN") }
            let saved = try store.load()!
            if mode == "failed-delete" {
                try require(saved.saved.profileContents == originalSaved.saved.profileContents &&
                            saved.saved.configuration.resources == originalSaved.saved.configuration.resources &&
                            saved.saved.configuration.authentication == originalSaved.saved.configuration.authentication &&
                            !saved.saved.configuration.desiredEnabled,
                            "failed deletion lost profile or reversed confirmed stop")
            } else {
                try require(saved == originalSaved, "failed stop/cancel changed persisted VPN state")
            }
        } else {
            try require(session.stopConfirmed && panel.configuration.profile == nil && panel.mainStatus == nil,
                        "successful removal kept VPN state")
            try require(metrics.destination.screen == "settings" && metrics.destination.vpnStatus == nil,
                        "successful removal did not show application settings without VPN status")
            try require(proxy.editing && !proxy.addingProxy && !proxy.choosingRoute && !proxy.manual,
                        "proxy settings navigation not reset")
            try require(!panel.requestsPresentation && panel.navigationRequest == nil && requests.count == 1 && emittedAfterCommit,
                        "navigation mismatch count=\(requests.count) committed=\(emittedAfterCommit) presenting=\(panel.requestsPresentation) pending=\(panel.navigationRequest != nil)")
        }
        print("removal product flow passed")
    }
}

private struct RemovalCleanupSession: VPNPasswordCleanupSession {
    func deletePendingOutcome(store: VPNStore, reference: VPNPasswordReference) throws -> VPNPasswordDeleteOutcome {
        do { try store.deletePendingPassword(reference: reference) { _, _ in .indeterminate } }
        catch { return .indeterminate }
        throw VPNValidationError.storageUnavailable
    }
}
private extension NSView {
    var subviewsRecursive: [NSView] { subviews + subviews.flatMap { $0.subviewsRecursive } }
}
