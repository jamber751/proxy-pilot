import Darwin
import Foundation

private func check(_ value: @autoclosure () throws -> Bool) throws {
    guard try value() else { throw NSError(domain: "capacity-flow", code: 1) }
}
private let profile = """
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
private let locator = VPNPasswordItemLocator(persistentReference: Data("synthetic".utf8), origin: .init(kind: .legacyKeychain,
    path: "/synthetic/capacity.keychain-db", device: 1, inode: 1, ownerUID: getuid(), birthSeconds: 1, birthNanoseconds: 0))
private final class Cache: VPNPasswordPersistenceSession {
    var adds = 0, reads = 0
    func read(store: VPNStore, reference: VPNPasswordReference, revision: UInt64) throws -> Data? {
        reads += 1; return nil // New-image silent denial, never a Keychain call.
    }
    func addOnce(store: VPNStore, reference: VPNPasswordReference, revision: UInt64, secret: inout Data) throws -> VPNPasswordAddOutcome {
        adds += 1; secret.resetBytes(in: 0..<secret.count); secret.removeAll()
        return .indeterminate
    }
}
@main private enum CapacityFlow {
    static func main() throws {
        let store = VPNStore(directory: URL(fileURLWithPath: CommandLine.arguments[2]))
        let imported = try VPNProfileImporter.inspect(data: Data(profile.utf8), name: "company.ovpn")
        var config = VPNConfiguration(); try config.setProfile(name: imported.name)
        try config.saveResource(VPNResource(address: "10.20.0.0/16"))
        try config.setAuthentication(VPNAuthentication(mode: .password, login: "employee", credentialPersistence: .keychain))
        let initial = try store.save(config, importing: imported, expectedRevision: nil)
        let ref = try store.createPasswordSaveGrant(expectedRevision: config.revision, expectedActive: nil)
        _ = try store.addPasswordOnce(reference: ref, expectedRevision: config.revision) { _ in .added(locator) }
        let active = try store.load()!.passwordLedger.active!
        let queue = (0..<64).map { _ in VPNPasswordSlot(reference: VPNPasswordReference(itemID: UUID(),
            profileSHA256: ref.profileSHA256, login: "employee"), writeState: .pending) }
        // A genuine legacy-valid shape:64 unknown obligations+1 issued active.
        var raw = try JSONSerialization.jsonObject(with: JSONEncoder().encode(VPNStoredState(saved: initial.saved, applied: nil,
            passwordLedger: VPNPasswordLedger(active: active, pendingDeletion: queue)))) as! [String: Any]
        raw["schemaVersion"] = 4
        let file = store.directory.appendingPathComponent("state.json")
        try JSONSerialization.data(withJSONObject: raw).write(to: file, options: .atomic)
        guard chmod(file.path, 0o600) == 0 else { throw VPNValidationError.storageUnavailable }
        let model = VPNModel(store: store); try model.load()
        if CommandLine.arguments[1] == "retired65" {
            try model.setAuthentication(mode: .password, login: "employee")
            try model.setAuthentication(mode: .password, login: "employee", credentialPersistence: .keychain)
            try check(store.load()!.passwordLedger.pendingDeletion.count == 65 && store.load()!.passwordLedger.active == nil)
        }
        let cache = Cache(), helper = FakeLiveSession(requiresCredential: true)
        let persistence = VPNPasswordPersistenceCoordinator(store: store, available: true,
            prepare: { _ in cache }, schedule: { $0() })
        let controller = VPNLiveController(store: store, passwordPersistence: persistence, openSession: { helper })
        controller.connect()
        try check(controller.credentialPromptIdentifier != nil)
        var secret = Data("manual-synthetic".utf8)
        controller.submitCredential(&secret, expectedPromptIdentifier: controller.credentialPromptIdentifier)
        try check(secret.isEmpty && controller.state == .connected && helper.submissions == 1 && cache.adds == 0
            && persistence.currentEvent?.phase == .needsConfirmation)
        // Cache admission failure must not prevent a verified disconnect or
        // later revoke/change/import/removal through the real model/store.
        controller.disconnect(); try check(controller.state == .off)
        try model.load()
        try model.setAuthentication(mode: .password, login: "employee")
        let retired = try store.load()!.passwordLedger.pendingDeletion
        try check(retired.count == 65 && retired.map(\.reference) == (queue + [active]).map(\.reference))
        try model.setAuthentication(mode: .oneTimePassword, login: "changed")
        try model.importProfile(data: Data(profile.replacingOccurrences(of: "vpn.company", with: "new.company").utf8), name: "company.ovpn")
        try model.removeProfile()
        try check(model.profile == nil && store.load()!.passwordLedger.pendingDeletion == retired
            && store.load()!.passwordLedger.active == nil && cache.adds == 0)
        print("capacity flow passed")
    }
}
