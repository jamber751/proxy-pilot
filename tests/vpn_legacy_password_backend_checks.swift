import Darwin
import Foundation
import Security

private final class SyntheticLegacyAPI: VPNLegacyPasswordAPI {
    let a = VPNPasswordBackendLocator(kind: .legacyKeychain, path: "/synthetic/A.keychain-db", device: 1, inode: 1,
        ownerUID: getuid(), birthSeconds: 1, birthNanoseconds: 0)
    let b = VPNPasswordBackendLocator(kind: .legacyKeychain, path: "/synthetic/B.keychain-db", device: 1, inode: 2,
        ownerUID: getuid(), birthSeconds: 2, birthNanoseconds: 0)
    var disabled = 0, targets = 0, additions = 0, findings = 0, deletions = 0
    var chooseB = false, failTarget = false, missingOriginal = false
    var addError: OSStatus?, deleteError: OSStatus?
    var transform: ((VPNLegacyPasswordItem) -> VPNLegacyPasswordItem)?
    var records: [Data: VPNLegacyPasswordItem] = [:]
    func disableInteraction() throws { disabled += 1 }
    func addTarget() throws -> VPNLegacyPasswordTarget {
        targets += 1
        if failTarget { throw VPNLegacyPasswordError.unavailable }
        return .init(keychain: nil, origin: chooseB ? b : a)
    }
    func openOriginal(_ origin: VPNPasswordBackendLocator) throws -> VPNLegacyPasswordTarget {
        if missingOriginal || (origin != a && origin != b) { throw VPNLegacyPasswordError.unavailable }
        return .init(keychain: nil, origin: origin)
    }
    func add(target: VPNLegacyPasswordTarget, service: String, account: String, envelope: Data) throws -> VPNLegacyPasswordItem {
        additions += 1
        if let addError { throw VPNLegacyPasswordError.status(addError) }
        let persistent = Data(UUID().uuidString.utf8)
        var item = VPNLegacyPasswordItem(reference: nil, persistentReference: persistent,
            origin: target.origin, service: service, account: account, envelope: envelope)
        if let transform { item = transform(item) }
        records[persistent] = item
        return item
    }
    func find(target: VPNLegacyPasswordTarget, persistentReference: Data) throws -> VPNLegacyPasswordItem {
        findings += 1
        guard let item = records[persistentReference] else { throw VPNLegacyPasswordError.status(errSecItemNotFound) }
        guard item.origin == target.origin else { throw VPNLegacyPasswordError.unavailable }
        return item
    }
    func delete(_ item: VPNLegacyPasswordItem) -> OSStatus {
        deletions += 1
        if let deleteError { return deleteError }
        return records.removeValue(forKey: item.persistentReference) == nil ? errSecItemNotFound : errSecSuccess
    }
}

@main enum VPNLegacyPasswordBackendChecks {
    enum Failure: Error { case check }
    static func check(_ condition: @autoclosure () throws -> Bool) throws {
        guard try condition() else { throw Failure.check }
    }
    static func rejects(_ action: () throws -> Void) throws {
        do { try action() } catch { return }; throw Failure.check
    }
    static func main() throws {
        // NO Security function is invoked: all operations use this injected API.
        guard CommandLine.arguments.count == 2 else { exit(64) }
        let api = SyntheticLegacyAPI(), reference = VPNPasswordReference(itemID: UUID(),
            profileSHA256: String(repeating: "a", count: 64), login: "synthetic")
        let backend = try VPNLegacyPasswordBackend.testInjected(api)
        func operation(_ operation: VPNPasswordWorkerOperation, locator: VPNPasswordItemLocator? = nil,
                       secret: String = "synthetic-password") throws -> VPNPasswordWorkerWire.Response {
            var request = VPNPasswordWorkerWire.Request(metadata: .init(operation: operation,
                reference: reference, revision: 1, locator: locator), secret: operation == .add ? Data(secret.utf8) : Data())
            defer { VPNPasswordWorkerWire.clear(&request.secret) }
            return try backend.execute(&request)
        }
        switch CommandLine.arguments[1] {
        case "roundtrip":
            let added = try operation(.add); guard let locator = added.locator else { throw Failure.check }
            try check(added.status == .success && locator.origin == api.a && api.disabled == 1)
            api.chooseB = true
            let decoy = try api.add(target: .init(keychain: nil, origin: api.b), service: VPNLegacyPasswordBackend.service,
                account: reference.itemID.uuidString, envelope: VPNLegacyPasswordEnvelope.encode(reference: reference, secret: Data("decoy".utf8)))
            var read = try operation(.read, locator: locator)
            try check(read.status == .success && read.secret == Data("synthetic-password".utf8))
            VPNPasswordWorkerWire.clear(&read.secret)
            try check(operation(.delete, locator: locator).status == .success)
            try check(api.targets == 1 && api.findings == 2 && api.deletions == 1 && api.records[decoy.persistentReference] != nil)
        case "before-api":
            api.failTarget = true
            try check(operation(.add).status == .definitelyNoIO && api.additions == 0)
        case "uncertain-errors":
            for status in [errSecAuthFailed, errSecInteractionNotAllowed, errSecDuplicateItem, errSecParam] {
                api.addError = status
                try check(operation(.add).status == .indeterminate)
            }
            try check(api.additions == 4)
        case "capture-failure":
            api.transform = { item in .init(reference: nil, persistentReference: Data(), origin: item.origin,
                service: item.service, account: item.account, envelope: item.envelope) }
            try check(operation(.add).status == .indeterminate && api.additions == 1)
        case "wrong-owner":
            api.transform = { item in .init(reference: nil, persistentReference: item.persistentReference, origin: api.b,
                service: item.service, account: item.account, envelope: item.envelope) }
            try check(operation(.add).status == .indeterminate)
        case "original-unavailable":
            let added = try operation(.add); guard let locator = added.locator else { throw Failure.check }
            api.missingOriginal = true; api.chooseB = true
            try check(operation(.read, locator: locator).status == .unavailable)
            try check(operation(.delete, locator: locator).status == .unavailable)
            try check(api.targets == 1 && api.findings == 0 && api.deletions == 0)
        case "not-found":
            let added = try operation(.add); guard let locator = added.locator else { throw Failure.check }
            api.records.removeAll()
            try check(operation(.read, locator: locator).status == .notFound)
            try check(operation(.delete, locator: locator).status == .notFound && api.deletions == 0)
        case "delete-no-ack":
            let added = try operation(.add); guard let locator = added.locator else { throw Failure.check }
            for status in [errSecItemNotFound, errSecAuthFailed, errSecInteractionNotAllowed, errSecParam, errSecNotAvailable] {
                api.deleteError = status
                let expected: VPNPasswordWorkerStatus = status == errSecItemNotFound ? .notFound : .indeterminate
                try check(operation(.delete, locator: locator).status == expected)
                try check(api.records[locator.persistentReference] != nil)
            }
        case "malformed-envelope":
            let added = try operation(.add); guard let locator = added.locator, var item = api.records[locator.persistentReference] else { throw Failure.check }
            item.envelope.append(0); api.records[locator.persistentReference] = item
            try check(operation(.read, locator: locator).status == .unavailable)
            try check(operation(.delete, locator: locator).status == .unavailable && api.deletions == 0)
        case "wrong-account":
            let added = try operation(.add); guard let locator = added.locator, let item = api.records[locator.persistentReference] else { throw Failure.check }
            api.records[locator.persistentReference] = .init(reference: nil, persistentReference: item.persistentReference,
                origin: item.origin, service: item.service, account: "wrong", envelope: item.envelope)
            try check(operation(.read, locator: locator).status == .unavailable)
            try check(operation(.delete, locator: locator).status == .unavailable && api.deletions == 0)
        case "envelope":
            for count in [1, VPNPasswordWorkerWire.maximumSecretBytes] {
                var secret = Data(repeating: 65, count: count)
                var bytes = try VPNLegacyPasswordEnvelope.encode(reference: reference, secret: secret)
                var decoded = try VPNLegacyPasswordEnvelope.decode(bytes, reference: reference)
                try check(decoded == secret)
                for foreign in [VPNPasswordReference(itemID: UUID(), profileSHA256: reference.profileSHA256, login: reference.login),
                    VPNPasswordReference(itemID: reference.itemID, profileSHA256: String(repeating: "b", count: 64), login: reference.login),
                    VPNPasswordReference(itemID: reference.itemID, profileSHA256: reference.profileSHA256, login: "different")] {
                    try rejects { _ = try VPNLegacyPasswordEnvelope.decode(bytes, reference: foreign) }
                }
                bytes.append(0); try rejects { _ = try VPNLegacyPasswordEnvelope.decode(bytes, reference: reference) }
                VPNPasswordWorkerWire.clear(&secret); VPNPasswordWorkerWire.clear(&bytes); VPNPasswordWorkerWire.clear(&decoded)
            }
        default: exit(64)
        }
        print("legacy injected checks passed")
    }
}
