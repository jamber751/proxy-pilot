// Actual item-provider delivery and transactional importer over synthetic files.
// No Finder, OpenPanel, helper session, Keychain or system settings are used.
import AppKit
import Foundation

extension VPNLiveController {
    convenience init(store: VPNStore) {
        self.init(store: store, openSession: { throw VPNLiveControllerError.unverifiedState })
    }
}

@main enum VPNPanelImportChecks {
    static func require(_ value: @autoclosure () -> Bool, _ message: String) throws {
        guard value() else { throw NSError(domain: message, code: 1) }
    }
    static func wait(_ condition: () -> Bool) throws {
        let deadline = Date().addingTimeInterval(5)
        while !condition(), Date() < deadline { RunLoop.main.run(until: Date().addingTimeInterval(0.005)) }
        try require(condition(), "item-provider delivery timed out")
    }
    static func profile(_ server: String) -> Data {
        Data("""
        client
        dev tun
        proto udp
        remote \(server) 1194
        remote-cert-tls server
        auth-user-pass
        <ca>
        -----BEGIN CERTIFICATE-----
        QUJDRA==
        -----END CERTIFICATE-----
        </ca>
        """.utf8)
    }
    static func provider(_ url: URL) -> NSItemProvider {
        NSItemProvider(item: url.dataRepresentation as NSData, typeIdentifier: "public.file-url")
    }
    static func main() throws {
        precondition(Thread.isMainThread)
        let a = CommandLine.arguments
        guard a.count == 3 else { exit(64) }
        let root = URL(fileURLWithPath: a[2], isDirectory: true)
        let storeDirectory = root.appendingPathComponent("store", isDirectory: true)
        try FileManager.default.createDirectory(at: storeDirectory, withIntermediateDirectories: false,
                                                attributes: [.posixPermissions: 0o700])
        let store = VPNStore(directory: storeDirectory)
        let oldProfile = try VPNProfileImporter.inspect(data: profile("old-vpn.company.example"), name: "old.ovpn")
        var config = VPNConfiguration()
        try config.setProfile(name: oldProfile.name)
        try config.saveResource(VPNResource(name: "First", address: "10.20.0.0/16"))
        try config.saveResource(VPNResource(name: "Second", address: "10.30.1.2"))
        try config.setAuthentication(VPNAuthentication(mode: .oneTimePassword, login: "employee"))
        _ = try store.save(config, importing: oldProfile, expectedRevision: nil)
        let configuration = VPNModel(store: store); try configuration.load()
        let blockedSession = DispatchSemaphore(value: 0)
        defer { blockedSession.signal() }
        let controller = VPNLiveController(store: store, openSession: {
            if a[1] == "delayed-delivery" { _ = blockedSession.wait(timeout: .now() + 5) }
            throw VPNLiveControllerError.unverifiedState
        })
        let panel = VPNPanelModel(configuration: configuration, controller: controller)
        let stateFile = storeDirectory.appendingPathComponent("state.json")
        let before = try Data(contentsOf: stateFile)
        let oldResources = configuration.configuration.resources
        var replacement = root.appendingPathComponent("new.ovpn")
        let newContents = profile("new-vpn.company.example")
        try newContents.write(to: replacement)
        let accepted: Bool
        switch a[1] {
        case "replacement": accepted = panel.acceptDrop([provider(replacement)])
        case "wrong-extension":
            replacement = root.appendingPathComponent("new.txt"); try newContents.write(to: replacement)
            accepted = panel.acceptDrop([provider(replacement)])
        case "empty":
            try Data().write(to: replacement)
            accepted = panel.acceptDrop([provider(replacement)])
        case "malformed":
            try Data("not an OpenVPN profile".utf8).write(to: replacement)
            accepted = panel.acceptDrop([provider(replacement)])
        case "symlink":
            let link = root.appendingPathComponent("link.ovpn")
            try FileManager.default.createSymbolicLink(at: link, withDestinationURL: replacement)
            accepted = panel.acceptDrop([provider(link)])
        case "multiple": accepted = panel.acceptDrop([provider(replacement), provider(replacement)])
        case "not-a-file":
            accepted = panel.acceptDrop([NSItemProvider(item: "plain text" as NSString, typeIdentifier: "public.text")])
        case "delayed-delivery":
            var delivery: ((Data?, Error?) -> Void)?
            let delayed = NSItemProvider()
            delayed.registerDataRepresentation(forTypeIdentifier: "public.file-url", visibility: .all) { completion in
                DispatchQueue.main.async { delivery = completion }
                return nil
            }
            accepted = panel.acceptDrop([delayed])
            try wait { delivery != nil }
            panel.refresh() // Keep the controller queue occupied while delivery arrives.
            try require(panel.working, "refresh was not started")
            delivery?(replacement.dataRepresentation, nil)
            try wait { !panel.message.isEmpty }
            blockedSession.signal()
            try wait { !panel.working }
        default: exit(64)
        }
        if a[1] == "replacement" {
            try require(accepted, "valid provider was refused")
            try wait { configuration.profile?.name == "new.ovpn" }
            let saved = try store.load()!
            let expected = try VPNProfileImporter.inspect(files: [replacement])
            try require(saved.saved.profileContents == expected.protectedContents, "replacement contents not committed")
            try require(saved.saved.configuration.resources == oldResources, "resource IDs or addresses changed")
            try require(saved.saved.configuration.authentication == nil, "old authentication carried to replacement")
            try require(panel.settings && panel.message.isEmpty, "replacement result not shown inline")
        } else {
            if a[1] == "multiple" || a[1] == "not-a-file" {
                try require(!accepted, "invalid provider list accepted")
            } else {
                try require(accepted, "file provider should reach bounded importer")
                try wait { !panel.message.isEmpty }
            }
            try require(configuration.profile?.name == "old.ovpn", "failed drop changed displayed filename")
            try require(configuration.configuration.resources == oldResources, "failed drop changed resources")
            let after = try Data(contentsOf: stateFile)
            try require(after == before, "failed drop changed persisted profile")
        }
        print("profile drop flow passed")
    }
}
