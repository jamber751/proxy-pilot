import Darwin
import Foundation

// Synthetic profile and in-memory callback observations only, no Keychain,
// helper session, root state, personal profile or network access.
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

@main enum VPNPasswordLedgerChecks {
    enum Failure: Error { case expected, assertion }
    static func check(_ value: @autoclosure () throws -> Bool) throws {
        guard try value() else { throw Failure.assertion }
    }
    static func rejects(_ operation: () throws -> Void) throws {
        do { try operation() } catch { return }; throw Failure.assertion
    }
    static func seeded(_ store: VPNStore) throws -> VPNStoredState {
        let profile = try VPNProfileImporter.inspect(data: Data(profileText.utf8), name: "synthetic.ovpn")
        var config = VPNConfiguration(); try config.setProfile(name: profile.name)
        try config.saveResource(VPNResource(address: "10.20.0.0/16"))
        try config.setAuthentication(VPNAuthentication(mode: .password, login: "employee", credentialPersistence: .keychain))
        return try store.save(config, importing: profile, expectedRevision: nil)
    }
    static func auth(_ store: VPNStore, _ mode: VPNAuthenticationMode = .password,
                     login: String = "employee", consent: VPNCredentialPersistence = .none) throws -> VPNStoredState {
        let current = try store.load()!; var config = current.saved.configuration
        try config.setAuthentication(VPNAuthentication(mode: mode, login: login, credentialPersistence: consent))
        return try store.save(config, expectedRevision: current.saved.configuration.revision)
    }
    static func grant(_ store: VPNStore) throws -> VPNPasswordReference {
        try store.grantPasswordPersistence(expectedRevision: store.load()!.saved.configuration.revision)
    }
    static func main() throws {
        let args = CommandLine.arguments; guard args.count == 3 else { exit(64) }
        let folder = URL(fileURLWithPath: args[2], isDirectory: true)
        let store = VPNStore(directory: folder)
        let file = folder.appendingPathComponent("state.json")
        if args[1] == "lock-child" {
            do { _ = try auth(store); exit(1) }
            catch VPNValidationError.storageUnavailable { exit(0) }
            catch { exit(1) }
        }
        if args[1] == "delete-crash" {
            let old = try store.load()!.passwordLedger.pendingDeletion[0].reference
            try store.deletePendingPassword(reference: old) { _ in
                try FileManager.default.removeItem(at: folder.appendingPathComponent("fake-item"))
                _exit(42) // real process crash boundary, before durable ack
            }
            throw Failure.assertion
        }
        if args[1] == "add-crash" {
            let state = try store.load()!
            try store.addPasswordOnce(reference: state.passwordLedger.active!.reference,
                                      expectedRevision: state.saved.configuration.revision) { _ in _exit(43) }
            throw Failure.assertion
        }
        if args[1] == "resume-add-crash" {
            let state = try store.load()!; let old = state.passwordLedger.active!.reference
            try check(state.passwordLedger.active?.writeState == .pending)
            var called = false
            try rejects { _ = try store.readPassword(reference: old, expectedRevision: state.saved.configuration.revision) { _ in called = true } }
            try rejects { _ = try store.addPasswordOnce(reference: old, expectedRevision: state.saved.configuration.revision) { _ in called = true; return .definiteSuccess } }
            _ = try auth(store)
            try rejects { try store.deletePendingPassword(reference: old) { _ in called = true } }
            try check(!called && store.load()!.passwordLedger.pendingDeletion[0].writeState == .pending)
            print("ledger checks passed"); return
        }
        if args[1] == "resume-crash" {
            let state = try store.load()!
            try check(state.passwordLedger.active == nil && state.passwordLedger.pendingDeletion.count == 1)
            try check(!FileManager.default.fileExists(atPath: folder.appendingPathComponent("fake-item").path))
            try store.deletePendingPassword(reference: state.passwordLedger.pendingDeletion[0].reference) { _ in /* not-found success */ }
            try check(store.load()!.passwordLedger.pendingDeletion.isEmpty)
            print("ledger checks passed"); return
        }
        let initial = try seeded(store)
        let reference = try grant(store)
        let revision = initial.saved.configuration.revision
        if !["grant", "errors", "lock", "schema", "once", "unknown", "late-active", "unissued", "pending-sync", "prepare-add-crash"].contains(args[1]) {
            try store.addPasswordOnce(reference: reference, expectedRevision: revision) { _ in .definiteSuccess }
        }
        switch args[1] {
        case "grant":
            try check(initial.passwordLedger.active == nil && initial.schemaVersion == 3)
            try check(grant(store) == reference)
            var reads = 0, writes = 0
            try rejects { _ = try store.readPassword(reference: reference, expectedRevision: revision) { _ in reads += 1 } }
            try store.addPasswordOnce(reference: reference, expectedRevision: revision) { _ in writes += 1; return .definiteSuccess }
            let result = try store.readPassword(reference: reference, expectedRevision: revision) { observed in
                try check(observed == reference); reads += 1; return 17
            }
            try rejects { _ = try store.addPasswordOnce(reference: reference, expectedRevision: revision) { _ in writes += 1; return .definiteSuccess } }
            try check(result == 17 && reads == 1 && writes == 1)
            var next = initial.saved.configuration; try next.saveResource(VPNResource(address: "10.30.0.0/16"))
            let updated = try store.save(next, expectedRevision: revision)
            try check(updated.passwordLedger.active?.reference == reference)
            try rejects { _ = try store.readPassword(reference: reference, expectedRevision: revision) { _ in throw Failure.assertion } }
            _ = try store.readPassword(reference: reference, expectedRevision: next.revision) { _ in 0 }
            try check(!String(decoding: Data(contentsOf: file), as: UTF8.self).contains("synthetic-password-value"))
        case "revoke", "prepare-crash":
            let revoked = try auth(store)
            try check(revoked.passwordLedger.active == nil && revoked.passwordLedger.pendingDeletion.map(\.reference) == [reference])
            let restarted = VPNStore(directory: folder)
            var calls = 0
            try rejects { _ = try restarted.readPassword(reference: reference, expectedRevision: revoked.saved.configuration.revision) { _ in calls += 1 } }
            try check(calls == 0)
            try rejects { try restarted.deletePendingPassword(reference: reference) { _ in throw Failure.expected } }
            try check(restarted.load()!.passwordLedger == revoked.passwordLedger)
            if args[1] == "prepare-crash" { try Data("synthetic-password-value".utf8).write(to: folder.appendingPathComponent("fake-item")) }
            else {
                try restarted.deletePendingPassword(reference: reference) { _ in calls += 1 }
                try check(calls == 1 && restarted.load()!.passwordLedger.pendingDeletion.isEmpty)
            }
        case "regrant":
            _ = try auth(store); _ = try auth(store, consent: .keychain)
            let new = try grant(store); try check(new.itemID != reference.itemID && new.login == reference.login && new.profileSHA256 == reference.profileSHA256)
            var deleted: VPNPasswordReference?
            try store.deletePendingPassword(reference: reference) { deleted = $0 }
            try check(deleted == reference && store.load()!.passwordLedger.active?.reference == new)
            try rejects { try store.deletePendingPassword(reference: new) { _ in throw Failure.assertion } }
        case "stale":
            let before = try Data(contentsOf: file)
            var outdated = initial.saved.configuration; try outdated.setAuthentication(VPNAuthentication(mode: .password, login: "other"))
            var next = initial.saved.configuration; try next.setDNS(["10.20.0.53"])
            let current = try store.save(next, expectedRevision: revision)
            try rejects { _ = try store.save(outdated, expectedRevision: revision) }
            try check(store.load() == current && before != Data(contentsOf: file))
            _ = try auth(store)
            var called = false
            try rejects { try store.addPasswordOnce(reference: reference, expectedRevision: revision) { _ in called = true; return .definiteSuccess } }
            let revokedRevision = try store.load()!.saved.configuration.revision
            try rejects { try store.addPasswordOnce(reference: reference, expectedRevision: revokedRevision) { _ in called = true; return .definiteSuccess } }
            let fake = VPNPasswordReference(itemID: reference.itemID, profileSHA256: reference.profileSHA256, login: "forged")
            try rejects { try store.deletePendingPassword(reference: fake) { _ in called = true } }
            try check(!called && store.load()!.passwordLedger.pendingDeletion.map(\.reference) == [reference])
        case "identity":
            _ = try auth(store, login: "Employee", consent: .keychain)
            try check(store.load()!.passwordLedger.active == nil && store.load()!.passwordLedger.pendingDeletion.map(\.reference) == [reference])
            let second = try grant(store)
            _ = try auth(store, .oneTimePassword, login: "Employee")
            try check(store.load()!.passwordLedger.pendingDeletion.map(\.reference) == [reference, second])
            try rejects { _ = try grant(store) }
        case "profile":
            var next = initial.saved.configuration; try next.setProfile(name: "synthetic.ovpn")
            let changed = try VPNProfileImporter.inspect(data: Data(profileText.replacingOccurrences(of: "1194", with: "1195").utf8), name: "synthetic.ovpn")
            let replaced = try store.save(next, importing: changed, expectedRevision: revision)
            try check(replaced.passwordLedger.active == nil && replaced.passwordLedger.pendingDeletion.map(\.reference) == [reference])
            _ = try auth(store, consent: .keychain); let second = try grant(store)
            let before = try store.load()!; next = before.saved.configuration; try next.removeProfile()
            let removed = try store.save(next, expectedRevision: before.saved.configuration.revision)
            try check(removed.saved.profileContents == nil && removed.passwordLedger.pendingDeletion.map(\.reference) == [reference, second])
        case "ack":
            var config = initial.saved.configuration; try config.setEnabled(true)
            _ = try store.save(config, expectedRevision: revision)
            try store.acknowledgeApplied(revision: config.revision)
            try check(store.load()!.passwordLedger.active?.reference == reference)
            let revoked = try auth(store)
            try check(revoked.applied?.configuration.authentication?.credentialPersistence == VPNCredentialPersistence.keychain)
            try check(revoked.passwordLedger.active == nil)
            try store.acknowledgeStopped(revision: config.revision)
            try check(store.load()!.passwordLedger == revoked.passwordLedger)
            try store.acknowledgeApplied(revision: revoked.saved.configuration.revision)
            try check(store.load()!.passwordLedger == revoked.passwordLedger)
        case "lock":
            var denied = false
            try store.addPasswordOnce(reference: reference, expectedRevision: revision) { _ in
                let child = Process()
                child.executableURL = URL(fileURLWithPath: args[0])
                child.arguments = ["lock-child", folder.path]
                try child.run(); child.waitUntilExit()
                denied = child.terminationStatus == 0
                return .definiteSuccess
            }
            try check(denied && store.load()!.passwordLedger.active?.reference == reference)
        case "schema":
            let current = try Data(contentsOf: file)
            var envelope = try JSONSerialization.jsonObject(with: current) as! [String: Any]
            envelope["schemaVersion"] = 1; envelope.removeValue(forKey: "passwordLedger")
            try JSONSerialization.data(withJSONObject: envelope).write(to: file)
            let migrated = try store.load()!
            try check(migrated.schemaVersion == 3 && migrated.passwordLedger.active == nil && migrated.saved == initial.saved)
            let renewed = try grant(store)
            try check(renewed != reference)
            let valid = try Data(contentsOf: file)
            let parsed = try JSONSerialization.jsonObject(with: valid) as! [String: Any]
            var ledger = parsed["passwordLedger"] as! [String: Any]
            let active = ledger["active"] as! [String: Any]
            // Schema2 has refs without write status: migrate conservatively,
            // never permit a second add or cache read for an unknown old item.
            var legacy = parsed; legacy["schemaVersion"] = 2
            legacy["passwordLedger"] = ["active": active["reference"]!, "pendingDeletion": []]
            try JSONSerialization.data(withJSONObject: legacy).write(to: file)
            let oldSchema = try store.load()!
            try check(oldSchema.schemaVersion == 3 && oldSchema.passwordLedger.active?.writeState == .pending)
            try rejects { _ = try grant(store) }
            try rejects { _ = try store.addPasswordOnce(reference: renewed, expectedRevision: revision) { _ in .definiteSuccess } }
            legacy["passwordLedger"] = ["pendingDeletion": [active["reference"]!]]
            try JSONSerialization.data(withJSONObject: legacy).write(to: file)
            try check(store.load()!.passwordLedger.pendingDeletion[0].writeState == .pending)
            var deletionCalled = false
            try rejects { try store.deletePendingPassword(reference: renewed) { _ in deletionCalled = true } }
            try check(!deletionCalled)
            try valid.write(to: file)
            let malformed: [[String: Any]] = [[:], ["pendingDeletion": [active, active]],
                ["active": active, "pendingDeletion": [active]],
                ["active": ["reference": active["reference"]!, "writeState": "unknown"], "pendingDeletion": []],
                ["active": ["reference": active["reference"]!], "pendingDeletion": []],
                ["active": ["reference": ["itemID": UUID().uuidString, "profileSHA256": "bad", "login": "employee"], "writeState": "settled"], "pendingDeletion": []]]
            for bad in malformed {
                var corrupt = parsed; corrupt["passwordLedger"] = bad
                try JSONSerialization.data(withJSONObject: corrupt).write(to: file)
                try rejects { _ = try store.load() }
            }
            var corrupt = parsed; corrupt["schemaVersion"] = 1
            try JSONSerialization.data(withJSONObject: corrupt).write(to: file)
            try rejects { _ = try store.load() }
            try valid.write(to: file)
            ledger["active"] = ["reference": ["itemID": UUID().uuidString, "profileSHA256": String(repeating: "f", count: 64), "login": "employee"], "writeState": "settled"]
            corrupt = parsed; corrupt["passwordLedger"] = ledger
            try JSONSerialization.data(withJSONObject: corrupt).write(to: file)
            try rejects { _ = try store.load() }
        case "capacity":
            for index in 0..<VPNPasswordLedger.maximumPendingDeletions {
                _ = try auth(store)
                if index + 1 < VPNPasswordLedger.maximumPendingDeletions { _ = try auth(store, consent: .keychain); _ = try grant(store) }
            }
            _ = try auth(store, consent: .keychain); let active = try grant(store)
            let before = try Data(contentsOf: file)
            try rejects { _ = try auth(store) }
            try check(before == Data(contentsOf: file) && store.load()!.passwordLedger.active?.reference == active)
        case "errors":
            let before = try Data(contentsOf: file)
            try rejects { try store.addPasswordOnce(reference: reference, expectedRevision: revision) { _ in throw Failure.expected } }
            try rejects { _ = try store.readPassword(reference: reference, expectedRevision: revision) { _ in throw Failure.expected } }
            try check(before != Data(contentsOf: file) && store.load()!.passwordLedger.active?.writeState == .pending)
            _ = try auth(store)
            try store.completePasswordAdd(reference: reference)
            let revoked = try Data(contentsOf: file)
            try rejects { try store.deletePendingPassword(reference: reference) { _ in throw Failure.expected } }
            try check(revoked == Data(contentsOf: file))
        case "prepare-add-crash": break
        case "pending-sync":
            store.testRejectNextPendingDirectorySync = true
            var calls = 0
            try rejects { _ = try store.addPasswordOnce(reference: reference, expectedRevision: revision) { _ in calls += 1; return .definiteSuccess } }
            let restart = VPNStore(directory: folder)
            try check(calls == 0 && restart.load()!.passwordLedger.active?.writeState == .pending)
            try rejects { _ = try restart.addPasswordOnce(reference: reference, expectedRevision: revision) { _ in calls += 1; return .definiteSuccess } }
            try check(calls == 0 && restart.load()!.saved.configuration == initial.saved.configuration)
        case "once":
            var calls = 0
            let result = try store.addPasswordOnce(reference: reference, expectedRevision: revision) { _ in
                let raw = try JSONSerialization.jsonObject(with: Data(contentsOf: file)) as! [String: Any]
                let slot = (raw["passwordLedger"] as! [String: Any])["active"] as! [String: Any]
                try check(slot["writeState"] as? String == "pending")
                calls += 1; return .definiteFailure
            }
            try check(result == .definiteFailure && store.load()!.passwordLedger.active?.writeState == .settled)
            try rejects { _ = try grant(store) }
            try rejects { _ = try store.addPasswordOnce(reference: reference, expectedRevision: revision) { _ in calls += 1; return .definiteSuccess } }
            let new = try store.createPasswordSaveGrant(expectedRevision: revision, expectedActive: reference)
            try check(new.itemID != reference.itemID && store.load()!.passwordLedger.pendingDeletion[0].writeState == .settled)
            let before = try Data(contentsOf: file)
            try rejects { _ = try store.createPasswordSaveGrant(expectedRevision: revision, expectedActive: reference) }
            try rejects { try store.completePasswordAdd(reference: reference) }
            try check(calls == 1 && before == Data(contentsOf: file))
        case "unknown":
            var calls = 0, deletes = 0
            var fakeItems: [UUID: String] = [:]
            try store.addPasswordOnce(reference: reference, expectedRevision: revision) { _ in calls += 1; return .indeterminate }
            try check(store.load()!.passwordLedger.active?.writeState == .pending)
            _ = try auth(store); _ = try auth(store, consent: .keychain)
            let currentRevision = try store.load()!.saved.configuration.revision
            let new = try store.createPasswordSaveGrant(expectedRevision: currentRevision, expectedActive: nil)
            try store.addPasswordOnce(reference: new, expectedRevision: currentRevision) { _ in
                calls += 1; fakeItems[new.itemID] = "new-password"; return .definiteSuccess
            }
            // Delayed fake kernel commit of the ONE old add. Presence does not
            // settle uncertainty; neither does absence or elapsed time.
            fakeItems[reference.itemID] = "old-password"
            try rejects { try store.deletePendingPassword(reference: reference) { _ in deletes += 1 } }
            try rejects { _ = try store.addPasswordOnce(reference: reference, expectedRevision: currentRevision) { _ in calls += 1; return .definiteSuccess } }
            try check(store.load()!.passwordLedger.pendingDeletion[0].writeState == .pending && deletes == 0)
            let forged = VPNPasswordReference(itemID: reference.itemID, profileSHA256: reference.profileSHA256, login: "forged")
            try rejects { try store.completePasswordAdd(reference: forged) }
            // A trusted late definite receipt addresses only the old UUID.
            try store.completePasswordAdd(reference: reference)
            try store.deletePendingPassword(reference: reference) { old in deletes += 1; fakeItems.removeValue(forKey: old.itemID) }
            try check(calls == 2 && deletes == 1 && fakeItems[new.itemID] == "new-password" && fakeItems[reference.itemID] == nil)
            try check(store.load()!.passwordLedger.active?.reference == new && store.load()!.passwordLedger.active?.writeState == .settled)
        case "late-active":
            try store.addPasswordOnce(reference: reference, expectedRevision: revision) { _ in .indeterminate }
            let restart = VPNStore(directory: folder)
            let state = try restart.load()!; var changed = state.saved.configuration
            try changed.setDNS(["10.20.0.53"])
            _ = try restart.save(changed, expectedRevision: revision)
            try check(restart.load()!.passwordLedger.active?.writeState == .pending)
            // Only this trusted definite completion may settle, independent of
            // resource revision; no read/not-found observation can do so.
            try restart.completePasswordAdd(reference: reference)
            var reads = 0, writes = 0
            _ = try restart.readPassword(reference: reference, expectedRevision: changed.revision) { _ in reads += 1 }
            try rejects { _ = try restart.addPasswordOnce(reference: reference, expectedRevision: changed.revision) { _ in writes += 1; return .definiteSuccess } }
            try check(reads == 1 && writes == 0 && restart.load()!.passwordLedger.active?.writeState == .settled)
        case "unissued":
            let new = try store.createPasswordSaveGrant(expectedRevision: revision, expectedActive: reference)
            try check(new != reference && store.load()!.passwordLedger.pendingDeletion.isEmpty)
            _ = try auth(store)
            try store.deletePendingPassword(reference: new) { _ in throw Failure.assertion }
            try check(store.load()!.passwordLedger.pendingDeletion.isEmpty)
        default: exit(64)
        }
        print("ledger checks passed")
    }
}
