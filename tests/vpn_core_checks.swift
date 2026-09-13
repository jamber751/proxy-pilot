import Foundation
import Darwin

// Deliberately synthetic PEM payload: these tests exercise structure, not TLS
// trust or a real corporate identity. Nothing in this executable connects.
private let fixture = """
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

@main struct VPNCoreChecks {
    static var count = 0
    static func check(_ condition: @autoclosure () throws -> Bool, _ message: String) throws {
        guard try condition() else { throw NSError(domain: "VPNCoreChecks", code: 1, userInfo: [NSLocalizedDescriptionKey: message]) }
        count += 1
    }
    static func rejects(_ message: String, _ operation: () throws -> Void) throws {
        do { try operation() } catch { count += 1; return }
        throw NSError(domain: "VPNCoreChecks", code: 2, userInfo: [NSLocalizedDescriptionKey: "Expected rejection: " + message])
    }
    static func profile(_ text: String = fixture, name: String = "company.ovpn") throws -> VPNImportedProfile {
        try VPNProfileImporter.inspect(data: Data(text.utf8), name: name)
    }
    static func main() throws {
        let group = CommandLine.arguments[1]
        let directory = URL(fileURLWithPath: CommandLine.arguments[2], isDirectory: true)
        switch group {
        case "resources": try resources()
        case "configuration": try configuration()
        case "authentication": try authentication(directory)
        case "import": try importing()
        case "unsafe": try unsafeProfiles()
        case "files": try files(directory)
        case "store": try store(directory)
        case "store-security": try storeSecurity(directory)
        case "migration": try migration()
        default: fatalError("Unknown test group")
        }
        print("\(group): \(count) checks passed")
    }
    static func authentication(_ directory: URL) throws {
        let certificate = try VPNAuthentication(mode: .certificate)
        let password = try VPNAuthentication(mode: .password, login: " employee ", credentialPersistence: .keychain)
        let otp = try VPNAuthentication(mode: .oneTimePassword, login: "employee")
        try check(certificate.login == nil && certificate.credentialPersistence == .none, "certificate mode has no login or persistence")
        try check(password.login == "employee" && password.credentialPersistence == .keychain, "static-password metadata can opt into future Keychain storage")
        try check(otp.credentialPersistence == .none, "OTP metadata is never persistent")
        for invalid in [
            { try VPNAuthentication(mode: .certificate, login: "employee") },
            { try VPNAuthentication(mode: .password, login: "") },
            { try VPNAuthentication(mode: .oneTimePassword, login: "employee", credentialPersistence: .keychain) },
            { try VPNAuthentication(mode: .password, login: "bad\nlogin") }
        ] { try rejects("invalid authentication metadata") { _ = try invalid() } }

        var config = VPNConfiguration()
        try config.setProfile(name: "company.ovpn")
        try config.saveResource(VPNResource(address: "gitlab.company.example"))
        try config.setAuthentication(password)
        let data = try JSONEncoder().encode(config)
        let object = try JSONSerialization.jsonObject(with: data) as! [String: Any]
        let authenticationObject = object["authentication"] as! [String: Any]
        try check(Set(authenticationObject.keys) == ["mode", "login", "credentialPersistence"],
                  "Codable authentication contains metadata fields only")
        let decoded = try JSONDecoder().decode(VPNConfiguration.self, from: data)
        try decoded.validate()
        try check(decoded.authentication == password, "login, mode and persistence round trip")

        var legacyObject = try JSONSerialization.jsonObject(with: data) as! [String: Any]
        legacyObject.removeValue(forKey: "authentication")
        let legacy = try JSONDecoder().decode(VPNConfiguration.self, from: JSONSerialization.data(withJSONObject: legacyObject))
        try legacy.validate()
        try check(legacy.authentication == nil && legacy.resources == config.resources && legacy.profileName == config.profileName,
                  "auth-less saved configurations retain profile and resources without guessing a mode")

        for mutation in [
            { (row: inout [String: Any]) in row["login"] = "bad\nlogin" },
            { (row: inout [String: Any]) in row["mode"] = "oneTimePassword"; row["credentialPersistence"] = "keychain" }
        ] {
            var forged = object
            var row = forged["authentication"] as! [String: Any]
            mutation(&row); forged["authentication"] = row
            let decoded = try JSONDecoder().decode(VPNConfiguration.self, from: JSONSerialization.data(withJSONObject: forged))
            try rejects("forged decoded authentication metadata") { try decoded.validate() }
        }
        var unknown = object
        var unknownAuth = unknown["authentication"] as! [String: Any]
        unknownAuth["mode"] = "challenge"; unknown["authentication"] = unknownAuth
        try rejects("unknown decoded authentication mode") {
            _ = try JSONDecoder().decode(VPNConfiguration.self, from: JSONSerialization.data(withJSONObject: unknown))
        }

        let beforeReplacement = config
        try config.setProfile(name: "company.ovpn")
        try check(config.authentication == nil && config.resources == beforeReplacement.resources,
                  "even same-name profile replacement clears login and persistence consent")
        try config.setAuthentication(password)

        let credentials = try profile()
        let certificateOnly = try profile(fixture.replacingOccurrences(of: "auth-user-pass\n", with: "") + "\n<cert>\n-----BEGIN CERTIFICATE-----\nQUJDRA==\n-----END CERTIFICATE-----\n</cert>\n<key>\n-----BEGIN PRIVATE KEY-----\nQUJDRA==\n-----END PRIVATE KEY-----\n</key>")
        try check(credentials.supports(authentication: nil) && credentials.supports(authentication: password) && credentials.supports(authentication: otp),
                  "credential profile stays undecided until password or OTP is explicitly selected")
        try check(!credentials.supports(authentication: certificate), "credential profile rejects certificate-only selection")
        try check(certificateOnly.supports(authentication: certificate) && !certificateOnly.supports(authentication: password) && !certificateOnly.supports(authentication: otp),
                  "certificate-only profile rejects credential modes")

        let store = VPNStore(directory: directory.appendingPathComponent("Authentication"))
        try store.save(config, importing: credentials, expectedRevision: nil)
        let saved = try store.load()!
        try check(saved.saved.configuration.authentication == password && saved.saved.inspectProfile()?.requiresCredentials == true,
                  "store preserves explicit auth metadata alongside protected profile bytes")
        var incompatible = config
        try incompatible.setAuthentication(certificate)
        try rejects("store rejects auth mode incompatible with imported profile") {
            try store.save(incompatible, expectedRevision: config.revision)
        }
        try check(try store.load() == saved, "rejected auth change leaves saved profile and resources intact")

        var reimport = config
        try reimport.setDNS(["192.0.2.53"])
        let identical = try store.save(reimport, importing: credentials, expectedRevision: config.revision)
        try check(identical.saved.configuration.authentication == password,
                  "byte-identical reimport may retain explicit authentication")
        let changedProfile = try profile(fixture + "\nremote backup.company.example 1194\n")
        var replacement = reimport
        try replacement.setDNS([])
        try rejects("direct changed-content import cannot carry authentication under the same filename") {
            try store.save(replacement, importing: changedProfile, expectedRevision: reimport.revision)
        }
        try check(try store.load() == identical, "rejected replacement preserves the entire old snapshot")
        try replacement.setAuthentication(nil)
        let cleared = try store.save(replacement, importing: changedProfile, expectedRevision: reimport.revision)
        let inspectedReplacement = try cleared.saved.inspectProfile()
        try check(cleared.saved.configuration.authentication == nil && inspectedReplacement?.protectedContents == changedProfile.protectedContents,
                  "changed profile imports after clearing the old selection")
        let clearedRevision = replacement.revision
        try replacement.setAuthentication(otp)
        let selected = try store.save(replacement, expectedRevision: clearedRevision)
        try check(selected.saved.configuration.authentication == otp, "replacement can get a fresh explicit choice")

        var noProfile = VPNConfiguration()
        try rejects("authentication selection requires a profile") { try noProfile.setAuthentication(password) }
        var noProfileObject = try JSONSerialization.jsonObject(with: JSONEncoder().encode(noProfile)) as! [String: Any]
        noProfileObject["authentication"] = authenticationObject
        noProfile = try JSONDecoder().decode(VPNConfiguration.self, from: JSONSerialization.data(withJSONObject: noProfileObject))
        try rejects("authentication cannot exist without a profile") { try noProfile.validate() }
    }
    static func migration() throws {
        func migrated(_ text: String) -> [String] {
            VPNLegacyMigration.resources(inLegacyConfiguration: text).migrated.map { $0.address }
        }
        try check(migrated("VPN_ROUTES=\"10.0.0.0/8 192.168.1.0/24\"\n") == ["10.0.0.0/8", "192.168.1.0/24"],
                  "plain networks migrate in order")
        try check(migrated("OFFICE_IP=1.2.3.4\nexport VPN_ROUTES='10.1.0.0/16,10.2.0.0/16'\n")
                  == ["10.1.0.0/16", "10.2.0.0/16"], "quoting, export and commas")
        try check(migrated("VPN_ROUTES=10.3.0.0/16 # office\n") == ["10.3.0.0/16"], "unquoted value ends at a comment")
        try check(migrated("VPN_ROUTES=\"10.4.0.0/16\"\nVPN_ROUTES=\"10.5.0.0/16\"\n") == ["10.5.0.0/16"],
                  "the last assignment wins")
        try check(migrated("#VPN_ROUTES=\"10.6.0.0/16\"\n").isEmpty, "commented assignments are ignored")
        try check(migrated("VPN_ROUTES=\"\"\n").isEmpty && migrated("OFFICE_IP=1.2.3.4\n").isEmpty,
                  "absent or empty routes migrate nothing")

        let mixed = "VPN_ROUTES=\"10.7.0.0/16 0.0.0.0/0 10.0.0.0/4 gitlab.example 2001:db8::/48 not-an-address 10.7.0.0/16 $(rm -rf /)\""
        let result = VPNLegacyMigration.resources(inLegacyConfiguration: mixed)
        try check(result.migrated.map { $0.address } == ["10.7.0.0/16"], "only IPv4 hosts and networks migrate")
        // The command substitution is only three unparsable words here: nothing
        // in this path expands, quotes or executes anything from the old file.
        try check(result.skipped == 9, "everything else is counted as skipped")

        var config = VPNConfiguration()
        let applied = try VPNLegacyMigration.migrate(into: &config, legacyConfiguration: "VPN_ROUTES=\"10.8.0.0/16 10.9.0.0/16\"")
        try check(applied.migrated.count == 2 && config.resources.count == 2, "migration fills an empty list")
        try check(config.profileName == nil && !config.desiredEnabled, "migration never enables the VPN or invents a profile")
        try check(config.resources.allSatisfy { $0.name.isEmpty }, "migrated resources carry no invented names")
        do {
            _ = try VPNLegacyMigration.migrate(into: &config, legacyConfiguration: "VPN_ROUTES=\"10.10.0.0/16\"")
            throw NSError(domain: "VPNCoreChecks", code: 3, userInfo: [NSLocalizedDescriptionKey: "second migration accepted"])
        } catch let error as VPNMigrationError {
            try check(error == .alreadyConfigured, "a configured list is never overwritten")
        }
        try config.validate()
    }

    static func resources() throws {
        let examples: [(String, String, VPNResource.Kind)] = [
            (" GitLab.Company.Example. ", "gitlab.company.example", .domain),
            ("https://gitlab.company.example/project?q=1#issue", "gitlab.company.example", .domain),
            ("10.20.30.40", "10.20.30.40", .ipv4), ("10.20.30.40/16", "10.20.0.0/16", .network4),
            ("10.20.30.40/32", "10.20.30.40/32", .network4),
            ("2001:0DB8:0000:0000:0000:0000:0000:0001", "2001:db8::1", .ipv6),
            ("2001:db8:1234:5678::1/48", "2001:db8:1234::/48", .network6),
            ("https://[2001:db8::1]/page", "2001:db8::1", .ipv6)
        ]
        for (input, expected, kind) in examples {
            let resource = try VPNResource(address: input)
            try check(resource.address == expected && resource.kind == kind, "normalized resource")
            try resource.validate()
        }
        for invalid in ["", "localhost", "https://user:password@example.com", "https://example.com:443", "10.01.2.3", "256.1.1.1", "127.0.0.1", "0.0.0.0", "224.0.0.1", "169.254.1.1", "::", "::1", "::ffff:127.0.0.1", "ff02::1", "fe80::1", "fe80::1%en0", "10.2.3.4/0", "::/0", "10.1.1.1/-1", "10.1.1.1/33", "2001:db8::1/129", "10.1.1.1/1/2", "x..example", "-x.example", "x-.example", "a_b.example", "*.example", "example.com/path", "example.com:80", "example.com\nplugin"] {
            try rejects("invalid resource: " + invalid) { _ = try VPNResource(address: invalid) }
        }
        try rejects("long label") { _ = try VPNResource(address: String(repeating: "a", count: 64) + ".example") }
        try rejects("name control character") { _ = try VPNResource(name: "Name\n", address: "a.example\nplugin") }
        try rejects("long name") { _ = try VPNResource(name: String(repeating: "a", count: 61), address: "a.example") }
    }
    static func configuration() throws {
        var config = VPNConfiguration()
        try rejects("enable without profile") { try config.setEnabled(true) }
        try config.setProfile(name: "Конфигурация.OVPN")
        try rejects("enable without resources") { try config.setEnabled(true) }
        let resource = try VPNResource(name: "GitLab", address: "gitlab.company.example")
        try config.saveResource(resource)
        let before = config
        try rejects("duplicate normalized domain") { try config.saveResource(VPNResource(address: "GITLAB.company.example.")) }
        try check(config == before, "failed mutation is atomic")
        try config.setEnabled(true)
        try config.saveResource(VPNResource(id: resource.id, name: "Source", address: "code.company.example"), replacing: resource.id)
        try check(config.resources.first?.id == resource.id && config.resources.count == 1, "stable edit identity")
        try rejects("last deletion needs confirmation") { try config.removeResource(id: resource.id) }
        try config.setDNS(["10.20.0.53", "2001:db8::53"])
        let configured = config
        try rejects("DNS hostname") { try config.setDNS(["dns.company.example"]) }
        try rejects("duplicate DNS") { try config.setDNS(["10.20.0.53", "10.20.0.53"]) }
        try check(config == configured, "invalid DNS keeps settings")
        try config.setProfile(name: "replacement.ovpn")
        try check(config.resources == configured.resources && config.desiredEnabled, "replace profile keeps resources and intent")
        try config.removeResource(id: resource.id, confirmingVPNOff: true)
        try check(!config.desiredEnabled && config.resources.isEmpty && config.profileName != nil, "last removal disables, keeps file")
        for index in 0..<100 { try config.saveResource(VPNResource(address: "service\(index).company.example")) }
        try check(config.resources.count == 100 && Set(config.resources.map { $0.id }).count == 100, "long list identity")
        let decoded = try JSONDecoder().decode(VPNConfiguration.self, from: JSONEncoder().encode(config))
        try decoded.validate(); try check(decoded == config, "configuration round trip")
        let encoded = try JSONEncoder().encode(config)
        for field in ["schemaVersion", "resources"] {
            var object = try JSONSerialization.jsonObject(with: encoded) as! [String: Any]
            if field == "schemaVersion" { object[field] = 2 }
            else { var rows = object[field] as! [[String: Any]]; rows.append(rows[0]); object[field] = rows }
            let invalid = try JSONDecoder().decode(VPNConfiguration.self, from: JSONSerialization.data(withJSONObject: object))
            try rejects("decoded data needs validation") { try invalid.validate() }
        }
        try config.removeProfile()
        try check(config.resources.isEmpty && config.corporateDNS.isEmpty && config.profileName == nil && !config.desiredEnabled, "remove configuration")
        for name in ["../secret.ovpn", "a/b.ovpn", "a\\b.ovpn", "bad.txt", "bad\n.ovpn"] {
            try rejects("invalid profile name") { try config.setProfile(name: name) }
        }
    }
    static func importing() throws {
        let imported = try profile()
        try check(imported.requiresCredentials && !imported.requiresKeyPassword, "auth classification")
        try check(!String(reflecting: imported).contains("QUJD") && !String(describing: imported).contains("company"), "redacted descriptions")
        let repeatImport = try VPNProfileImporter.inspect(data: imported.protectedContents, name: imported.name)
        try check(repeatImport.protectedContents == imported.protectedContents, "canonical import idempotent")
        let routing = try profile(fixture + "\nroute 10.0.0.0 255.0.0.0\nredirect-gateway def1\nroute-ipv6 ::/0\ndhcp-option DNS 10.20.0.53\nsetenv opt block-outside-dns\n")
        let text = String(decoding: routing.protectedContents, as: UTF8.self)
        try check(routing.hasIgnoredRoutes && routing.suggestedDNS == ["10.20.0.53"], "routes ignored, DNS suggested")
        try check(routing.suggestedResources.map { $0.address } == ["10.0.0.0/8"], "safe profile route becomes a suggestion, default route does not")
        try check(!text.contains("redirect-gateway") && !text.contains("dhcp-option") && !text.contains("route-ipv6"), "no profile-controlled network configuration")
        try check(text.contains("route-nopull") && text.contains("script-security 1") && text.contains("auth-nocache"), "conservative generated controls")
        _ = try profile(fixture.replacingOccurrences(of: "remote vpn.company.example 1194", with: "--remote 'vpn.company.example' 443 tcp-client # comment"))
        count += 1
        _ = try profile("\u{feff}" + fixture.replacingOccurrences(of: "\n", with: "\r\n"), name: "Клиент.OVPN"); count += 1
        let key = "\n<cert>\n-----BEGIN CERTIFICATE-----\nQUJDRA==\n-----END CERTIFICATE-----\n</cert>\n<key>\n-----BEGIN ENCRYPTED PRIVATE KEY-----\nQUJDRA==\n-----END ENCRYPTED PRIVATE KEY-----\n</key>"
        let certificateProfile = try profile(fixture.replacingOccurrences(of: "auth-user-pass\n", with: "") + key)
        try check(!certificateProfile.requiresCredentials && certificateProfile.requiresKeyPassword, "certificate login classification")
        let tls = "\n<tls-auth>\n-----BEGIN OpenVPN Static key V1-----\n" + String(repeating: "a", count: 512) + "\n-----END OpenVPN Static key V1-----\n</tls-auth>\nkey-direction 1"
        _ = try profile(fixture + tls); count += 1
        let commonOptions = "\nignore-unknown-option block-outside-dns\nsetenv opt block-outside-dns\ntls-cipher TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256\nexplicit-exit-notify"
        let compatible = try profile(fixture + commonOptions)
        let compatibleText = String(decoding: compatible.protectedContents, as: UTF8.self)
        try check(!compatibleText.contains("ignore-unknown-option") && !compatibleText.contains("block-outside-dns"), "Windows exception does not escape importer")
        try check(compatibleText.contains("TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256") && compatibleText.contains("explicit-exit-notify"), "preserve supported TLS suite and default exit notification")
        try check(VPNProfileImporter.inspect(data: compatible.protectedContents, name: compatible.name).protectedContents == compatible.protectedContents, "compatible profile survives protected-store reload")
        _ = try profile(fixture + "\ntls-cipher ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384\nexplicit-exit-notify 2"); count += 1
        let suggestions = try profile(fixture + "\nroute 10.20.1.7 255.255.255.0\nroute 10.20.1.0 255.255.255.0\nroute 10.30.0.1 255.255.255.255\nroute 10.30.0.1\nroute 0.0.0.0 0.0.0.0\nroute 10.40.0.0 255.0.255.0\nroute 10.50.0.0 255.255.0.0 net_gateway\nroute evil.example 255.255.255.0\nroute-ipv6 2001:db8:1::/48")
        try check(suggestions.suggestedResources.map { $0.address } == ["10.20.1.0/24", "10.30.0.1", "2001:db8:1::/48"], "deduplicate routes, skip noncontiguous masks and custom gateways")
    }
    static func unsafeProfiles() throws {
        let unsafe = ["up /tmp/script", "down /tmp/script", "plugin /tmp/plugin.so", "--config /tmp/extra", "config extra.ovpn", "management /tmp/socket unix", "management-external-key", "log /tmp/log", "log-append /tmp/log", "status /tmp/status", "writepid /tmp/pid", "cd /tmp", "chroot /tmp", "daemon", "user root", "group wheel", "script-security 2", "script-security 3", "tls-verify /tmp/verify", "iproute /tmp/route", "setenv opt up /tmp/script", "setenv IV_SSO openurl", "ignore-unknown-option up", "auth-user-pass credentials.txt", "askpass password.txt", "ca ca.crt", "pkcs12 identity.p12", "http-proxy proxy.example 3128", "socks-proxy proxy.example 1080", "compress lz4", "comp-lzo", "auth none", "cipher none", "tls-version-min 1.0", "dev tap", "static-challenge Token 1", "pkcs11-providers /tmp/token", "<connection>\nremote x.example 443\n</connection>"]
        for line in unsafe { try rejects("unsupported profile option") { _ = try profile(fixture + "\n" + line) } }
        for line in ["ignore-unknown-option plugin", "ignore-unknown-option block-outside-dns up", "ignore-unknown-option block-outside-dns\nplugin /tmp/plugin", "tls-cipher ALL", "tls-cipher DEFAULT:@SECLEVEL=0", "tls-cipher TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256:", "tls-cipher ECDHE-ECDSA-AES128-GCM-SHA256:RC4-SHA", "explicit-exit-notify -1", "explicit-exit-notify 6", "explicit-exit-notify 1 2"] {
            try rejects("compatibility must not loosen safety") { _ = try profile(fixture + "\n" + line) }
        }
        for changed in [fixture.replacingOccurrences(of: "remote-cert-tls server", with: ""), fixture.replacingOccurrences(of: "remote vpn.company.example 1194", with: ""), fixture.replacingOccurrences(of: "1194", with: "65536"), fixture.replacingOccurrences(of: "1194", with: "-1"), fixture.replacingOccurrences(of: "auth-user-pass", with: ""), fixture.replacingOccurrences(of: "</ca>", with: ""), fixture.replacingOccurrences(of: "QUJDRA==", with: "up /tmp/script"), fixture.replacingOccurrences(of: "QUJDRA==", with: "</ca>\nplugin /tmp/plugin\n<ca>"), fixture + "\nremote 'unfinished", fixture + "\nunknown-option x", fixture + "\n\u{0}", fixture + "\nclient"] {
            try rejects("malformed or incomplete profile") { _ = try profile(changed) }
        }
        try rejects("oversized profile") { _ = try profile(String(repeating: "x", count: VPNProfileImporter.maximumBytes + 1)) }
        try rejects("empty profile") { _ = try profile("") }
        try rejects("binary profile") { _ = try VPNProfileImporter.inspect(data: Data([0xff, 0xfe]), name: "test.ovpn") }
        do { _ = try profile(fixture + "\nplugin /private/SECRET/PASSWORD") }
        catch { try check(!error.localizedDescription.contains("SECRET") && !error.localizedDescription.contains("PASSWORD"), "error does not expose option values") }
    }
    static func files(_ directory: URL) throws {
        let original = directory.appendingPathComponent("Корпоративный.OVPN")
        let bytes = Data(fixture.utf8)
        try bytes.write(to: original)
        let imported = try VPNProfileImporter.inspect(files: [original])
        try check(imported.name == original.lastPathComponent && Data(contentsOf: original) == bytes, "real filename, original untouched")
        _ = try VPNProfileImporter.inspect(files: [original]); count += 1
        try rejects("multiple dropped files") { _ = try VPNProfileImporter.inspect(files: [original, original]) }
        try rejects("no files") { _ = try VPNProfileImporter.inspect(files: []) }
        let folder = directory.appendingPathComponent("folder.ovpn")
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: false)
        try rejects("dropped directory") { _ = try VPNProfileImporter.inspect(files: [folder]) }
        let link = directory.appendingPathComponent("link.ovpn")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: original)
        try rejects("symlink") { _ = try VPNProfileImporter.inspect(files: [link]) }
        let pipe = directory.appendingPathComponent("pipe.ovpn")
        try check(mkfifo(pipe.path, 0o600) == 0, "create test pipe")
        try rejects("FIFO does not block") { _ = try VPNProfileImporter.inspect(files: [pipe]) }
        try rejects("remote URL") { _ = try VPNProfileImporter.inspect(files: [URL(string: "https://example.com/file.ovpn")!]) }
    }
    static func seededStore(_ directory: URL) throws -> (VPNStore, VPNConfiguration) {
        let store = VPNStore(directory: directory.appendingPathComponent("VPN"))
        var config = VPNConfiguration()
        try config.setProfile(name: "company.ovpn")
        try config.saveResource(VPNResource(address: "gitlab.company.example"))
        try store.save(config, importing: profile(fixture + "\ndhcp-option DNS 10.20.0.53\nroute 10.0.0.0 255.0.0.0"), expectedRevision: nil)
        return (store, config)
    }
    static func store(_ directory: URL) throws {
        let absent = VPNStore(directory: directory.appendingPathComponent("Absent"))
        try check(absent.load() == nil && !FileManager.default.fileExists(atPath: absent.directory.path), "empty read does not create storage")
        let (store, initial) = try seededStore(directory)
        var config = initial
        var loaded = try store.load()!
        try check(loaded.saved.configuration == config && loaded.applied == nil, "save is not connect")
        try check(loaded.saved.configuration.authentication == nil, "legacy/unselected authentication is not guessed from auth-user-pass")
        let legacyEnvelope = try JSONSerialization.jsonObject(with: Data(contentsOf: store.directory.appendingPathComponent("state.json"))) as! [String: Any]
        let legacySaved = legacyEnvelope["saved"] as! [String: Any]
        let legacyConfiguration = legacySaved["configuration"] as! [String: Any]
        try check(legacyConfiguration["authentication"] == nil && loaded.saved.configuration.resources == config.resources && loaded.saved.inspectProfile()?.name == "company.ovpn",
                  "auth-less store envelope retains resources and protected profile")
        try check(loaded.saved.inspectProfile()?.name == "company.ovpn", "profile round trip")
        try check(loaded.saved.suggestedDNS == ["10.20.0.53"] && loaded.saved.hasIgnoredProfileRoutes, "import notices survive reload")
        try check(loaded.saved.suggestedResources.map { $0.address } == ["10.0.0.0/8"], "route suggestions survive reload without replacing configured resources")
        try config.setEnabled(true)
        try store.save(config, expectedRevision: initial.revision)
        try store.acknowledgeApplied(revision: config.revision)
        loaded = try store.load()!
        try check(!loaded.hasPendingChanges && loaded.applied?.configuration == config, "explicit verified revision")
        let applied = config
        try config.saveResource(VPNResource(address: "10.20.0.0/16"))
        loaded = try store.save(config, expectedRevision: applied.revision)
        try check(loaded.hasPendingChanges && loaded.applied?.configuration == applied, "offline/pending save keeps working snapshot")
        try rejects("stale editor") { try store.save(config, expectedRevision: applied.revision) }
        try rejects("late connection acknowledgement") { try store.acknowledgeApplied(revision: applied.revision) }
        try rejects("stop of a different session") { try store.acknowledgeStopped(revision: applied.revision - 1) }
        try check(store.load() == loaded, "stale operation does not overwrite")
        let beforeReplace = config
        try config.setProfile(name: "replacement.ovpn")
        try rejects("replacement without file") { try store.save(config, expectedRevision: beforeReplace.revision) }
        try check(store.load() == loaded, "failed import keeps all data")
        loaded = try store.save(config, importing: profile(name: "replacement.ovpn"), expectedRevision: beforeReplace.revision)
        try check(loaded.saved.configuration.resources == applied.resources + [VPNResource(id: config.resources[1].id, address: "10.20.0.0/16")], "replacement preserves resources")
        try check(loaded.applied?.inspectProfile()?.name == "company.ovpn", "old profile retained for failed apply rollback")
        let beforeDelete = config
        try config.removeProfile()
        try rejects("cannot forget cleanup data before stop") { try store.save(config, expectedRevision: beforeDelete.revision) }
        try store.acknowledgeStopped(revision: applied.revision)
        loaded = try store.save(config, expectedRevision: beforeDelete.revision)
        try check(loaded.applied == nil && loaded.saved.inspectProfile() == nil, "delete after cleanup")
        let file = store.directory.appendingPathComponent("state.json")
        let attrs = try FileManager.default.attributesOfItem(atPath: file.path)
        try check((attrs[.posixPermissions] as? NSNumber)?.intValue == 0o600, "private state file")
        try check(try FileManager.default.contentsOfDirectory(atPath: store.directory.path).sorted() == ["state.json", "state.lock"], "no temporary files left behind")
        try rejects("cannot apply a deleted/disabled profile") { try store.acknowledgeApplied(revision: config.revision) }
    }
    static func storeSecurity(_ directory: URL) throws {
        let (store, config) = try seededStore(directory)
        let file = store.directory.appendingPathComponent("state.json")
        let original = try Data(contentsOf: file)
        let lock = open(store.directory.appendingPathComponent("state.lock").path, O_RDWR)
        try check(lock >= 0 && flock(lock, LOCK_EX | LOCK_NB) == 0, "hold competing store lock")
        try rejects("competing operation does not wait or overwrite") { try store.save(config, expectedRevision: config.revision) }
        flock(lock, LOCK_UN); close(lock)
        try check(store.load()?.saved.configuration == config, "concurrent writer keeps settings")
        try Data("broken".utf8).write(to: file)
        try rejects("corruption never resets to empty") { _ = try store.load() }
        try check(Data(contentsOf: file) == Data("broken".utf8), "corrupt file preserved for recovery")
        try rejects("save refuses corrupt predecessor") { try store.save(config, expectedRevision: nil) }
        try original.write(to: file)
        try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: file.path)
        try rejects("public-readable state") { _ = try store.load() }
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)
        let linked = directory.appendingPathComponent("linked-state")
        try FileManager.default.linkItem(at: file, to: linked)
        try rejects("hard-linked state") { _ = try store.load() }
        try FileManager.default.removeItem(at: linked)
        try FileManager.default.removeItem(at: file)
        let unrelated = directory.appendingPathComponent("unrelated.txt")
        try Data("untouched".utf8).write(to: unrelated)
        try FileManager.default.createSymbolicLink(at: file, withDestinationURL: unrelated)
        try rejects("state symlink read") { _ = try store.load() }
        try rejects("state symlink save") { try store.save(config, expectedRevision: nil) }
        try check(Data(contentsOf: unrelated) == Data("untouched".utf8), "unrelated target unchanged")
        let directoryLink = directory.appendingPathComponent("VPN-link")
        try FileManager.default.createSymbolicLink(at: directoryLink, withDestinationURL: store.directory)
        try rejects("directory symlink") { _ = try VPNStore(directory: directoryLink).load() }
    }
}
