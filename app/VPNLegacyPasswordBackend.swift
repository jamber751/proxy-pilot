import Darwin
import Foundation
import Security

/// Legacy-only adapter, deliberately NOT selected by VPNPasswordWorker's factory.
/// Its noninteractive flag belongs in the authenticated disposable child only.
struct VPNLegacyPasswordTarget {
    let keychain: SecKeychain?
    let origin: VPNPasswordBackendLocator
}
struct VPNLegacyPasswordItem {
    let reference: SecKeychainItem?
    let persistentReference: Data
    let origin: VPNPasswordBackendLocator
    let service: String
    let account: String
    var envelope: Data
}
protocol VPNLegacyPasswordAPI {
    func disableInteraction() throws
    func addTarget() throws -> VPNLegacyPasswordTarget
    func openOriginal(_ origin: VPNPasswordBackendLocator) throws -> VPNLegacyPasswordTarget
    func add(target: VPNLegacyPasswordTarget, service: String, account: String, envelope: Data) throws -> VPNLegacyPasswordItem
    func find(target: VPNLegacyPasswordTarget, persistentReference: Data) throws -> VPNLegacyPasswordItem
    func delete(_ item: VPNLegacyPasswordItem) -> OSStatus
}
enum VPNLegacyPasswordError: Error { case unavailable, status(OSStatus) }

/// Binary transient envelope; credential bytes are never Codable or diagnostics.
/// Owned Data buffers are cleared best effort; CFData/COW copies are not
/// claimed to be universally zeroed by this adapter.
enum VPNLegacyPasswordEnvelope {
    static let maximumBytes = 8 + 16 + 64 + 2 + 255 + 2 + VPNPasswordWorkerWire.maximumSecretBytes
    static func encode(reference: VPNPasswordReference, secret: Data) throws -> Data {
        guard VPNPasswordWorkerWire.validSecret(secret), reference.profileSHA256.utf8.count == 64,
              reference.profileSHA256.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }),
              try VPNAuthentication(mode: .password, login: reference.login).login == reference.login else {
            throw VPNLegacyPasswordError.unavailable
        }
        var uuid = reference.itemID.uuid
        var result = Data("PPKCPW01".utf8)
        withUnsafeBytes(of: &uuid) { result.append(contentsOf: $0) }
        result.append(contentsOf: reference.profileSHA256.utf8)
        let login = Data(reference.login.utf8)
        result.append(contentsOf: [UInt8(login.count >> 8), UInt8(login.count & 255)])
        result.append(login)
        result.append(contentsOf: [UInt8(secret.count >> 8), UInt8(secret.count & 255)])
        result.append(secret)
        return result
    }
    static func decode(_ bytes: Data, reference: VPNPasswordReference) throws -> Data {
        guard bytes.count <= maximumBytes, bytes.count >= 92, bytes.prefix(8) == Data("PPKCPW01".utf8) else {
            throw VPNLegacyPasswordError.unavailable
        }
        let loginCount = Int(bytes[88]) << 8 | Int(bytes[89])
        guard loginCount > 0, loginCount <= 255, bytes.count >= 92 + loginCount else { throw VPNLegacyPasswordError.unavailable }
        let secretOffset = 92 + loginCount
        let count = Int(bytes[90 + loginCount]) << 8 | Int(bytes[91 + loginCount])
        guard count > 0, count <= VPNPasswordWorkerWire.maximumSecretBytes, bytes.count == secretOffset + count else {
            throw VPNLegacyPasswordError.unavailable
        }
        var secret = bytes.subdata(in: secretOffset..<bytes.count)
        do {
            var canonical = try encode(reference: reference, secret: secret)
            defer { VPNPasswordWorkerWire.clear(&canonical) }
            guard canonical == bytes else { throw VPNLegacyPasswordError.unavailable }
            return secret
        } catch { VPNPasswordWorkerWire.clear(&secret); throw error }
    }
}

final class VPNLegacyPasswordBackend: VPNPasswordWorkerBackend {
    static let service = "kz.documentolog.proxypilot.vpn.static-password.v1"
    private let api: VPNLegacyPasswordAPI
    let available = true
    private init(api: VPNLegacyPasswordAPI) throws {
        self.api = api
        try api.disableInteraction()
    }
    private static func requireWorker() throws {
        guard CommandLine.arguments.count == 2, CommandLine.arguments[1] == VPNPasswordWorker.argument,
              getuid() == geteuid(), getuid() >= 500 else { throw VPNLegacyPasswordError.unavailable }
    }
    /// Not wired: GUI callers cannot instantiate a real backend by default.
    static func makeForCurrentWorker() throws -> VPNLegacyPasswordBackend {
        try requireWorker()
        return try VPNLegacyPasswordBackend(api: VPNLegacyPasswordSecurityAPI(privateAddPath: nil))
    }
    #if VPN_LEGACY_PASSWORD_BACKEND_TESTING
    static func testInjected(_ api: VPNLegacyPasswordAPI) throws -> VPNLegacyPasswordBackend {
        try VPNLegacyPasswordBackend(api: api)
    }
    /// Test-only real API entry. The GHA parent must create this private marker
    /// after its explicit opt-in/fresh-directory guard, before spawning a child.
    static func testPrivateWorker(directory: Int32) throws -> VPNLegacyPasswordBackend {
        try requireWorker()
        var info = stat()
        guard fstat(directory, &info) == 0, info.st_mode & S_IFMT == S_IFDIR,
              info.st_uid == getuid(), info.st_mode & 0o777 == 0o700 else { throw VPNLegacyPasswordError.unavailable }
        let marker = openat(directory, "private-keychain-opt-in", O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard marker >= 0 else { throw VPNLegacyPasswordError.unavailable }; defer { close(marker) }
        guard fstat(marker, &info) == 0, info.st_mode & S_IFMT == S_IFREG, info.st_uid == getuid(),
              info.st_nlink == 1, info.st_mode & 0o777 == 0o600 else { throw VPNLegacyPasswordError.unavailable }
        var bytes = [UInt8](repeating: 0, count: 64)
        let count = read(marker, &bytes, bytes.count)
        guard count == 31, Data(bytes.prefix(count)) == Data("GHA-PRIVATE-KEYCHAIN-BACKEND-01".utf8) else { throw VPNLegacyPasswordError.unavailable }
        var path = [CChar](repeating: 0, count: Int(MAXPATHLEN))
        guard fcntl(directory, F_GETPATH, &path) == 0 else { throw VPNLegacyPasswordError.unavailable }
        let selection = openat(directory, "private-add-target", O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard selection >= 0 else { throw VPNLegacyPasswordError.unavailable }; defer { close(selection) }
        guard fstat(selection, &info) == 0, info.st_mode & S_IFMT == S_IFREG, info.st_uid == getuid(),
              info.st_nlink == 1, info.st_mode & 0o777 == 0o600 else { throw VPNLegacyPasswordError.unavailable }
        var selected: UInt8 = 0
        guard read(selection, &selected, 1) == 1, info.st_size == 1, selected == 65 || selected == 66 else { throw VPNLegacyPasswordError.unavailable }
        let record = selected == 65 ? "private-keychain-name-A" : "private-keychain-name-B"
        let format = openat(directory, record, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard format >= 0 else { throw VPNLegacyPasswordError.unavailable }; defer { close(format) }
        guard fstat(format, &info) == 0, info.st_mode & S_IFMT == S_IFREG, info.st_uid == getuid(),
              info.st_nlink == 1, info.st_mode & 0o777 == 0o600, info.st_size > 0, info.st_size < 64 else { throw VPNLegacyPasswordError.unavailable }
        var nameBytes = [UInt8](repeating: 0, count: 64)
        let nameCount = read(format, &nameBytes, nameBytes.count)
        guard Int64(nameCount) == info.st_size else { throw VPNLegacyPasswordError.unavailable }
        let name = String(decoding: nameBytes.prefix(nameCount), as: UTF8.self)
        let allowed = selected == 65 ? ["first.keychain", "first.keychain-db"] : ["second.keychain", "second.keychain-db"]
        guard allowed.contains(name) else { throw VPNLegacyPasswordError.unavailable }
        return try VPNLegacyPasswordBackend(api: VPNLegacyPasswordSecurityAPI(
            privateAddPath: String(cString: path) + "/" + name, testDirectory: directory))
    }
    #endif

    func execute(_ request: inout VPNPasswordWorkerWire.Request) throws -> VPNPasswordWorkerWire.Response {
        // Validate the closed wire shape even for injected callers.
        _ = try request.metadata.encoded()
        let captured = request.metadata
        switch captured.operation {
        case .add:
            var envelope = Data()
            defer { VPNPasswordWorkerWire.clear(&envelope) }
            let target: VPNLegacyPasswordTarget
            do {
                envelope = try VPNLegacyPasswordEnvelope.encode(reference: captured.reference, secret: request.secret)
                target = try api.addTarget()
                try target.origin.validate()
            } catch { return .init(status: .definitelyNoIO, secret: Data()) }
            // From this point even a thrown capture/API error is uncertain.
            do {
                var item = try api.add(target: target, service: Self.service,
                    account: captured.reference.itemID.uuidString, envelope: envelope)
                defer { VPNPasswordWorkerWire.clear(&item.envelope) }
                guard item.origin.path == target.origin.path else { throw VPNLegacyPasswordError.unavailable }
                let locator = try verified(item, reference: captured.reference, expected: nil)
                var observed = try VPNLegacyPasswordEnvelope.decode(item.envelope, reference: captured.reference)
                defer { VPNPasswordWorkerWire.clear(&observed) }
                guard observed == request.secret else { throw VPNLegacyPasswordError.unavailable }
                return .init(status: .success, secret: Data(), locator: locator)
            } catch { return .init(status: .indeterminate, secret: Data()) }
        case .read, .delete:
            guard let locator = captured.locator else { throw VPNLegacyPasswordError.unavailable }
            do {
                let target = try api.openOriginal(locator.origin)
                guard target.origin == locator.origin else { throw VPNLegacyPasswordError.unavailable }
                var item = try api.find(target: target, persistentReference: locator.persistentReference)
                defer { VPNPasswordWorkerWire.clear(&item.envelope) }
                _ = try verified(item, reference: captured.reference, expected: locator)
                var secret = try VPNLegacyPasswordEnvelope.decode(item.envelope, reference: captured.reference)
                defer { VPNPasswordWorkerWire.clear(&secret) }
                if captured.operation == .read { return .init(status: .success, secret: secret) }
                let status = api.delete(item)
                if status == errSecSuccess { return .init(status: .success, secret: Data()) }
                // A generic mutation API error cannot prove the delete was not
                // committed. Preserve both the obligation and unknown outcome.
                return .init(status: status == errSecItemNotFound ? .notFound : .indeterminate, secret: Data())
            } catch VPNLegacyPasswordError.status(errSecItemNotFound) {
                return .init(status: .notFound, secret: Data())
            } catch { return .init(status: .unavailable, secret: Data()) }
        }
    }
    private func verified(_ item: VPNLegacyPasswordItem, reference: VPNPasswordReference,
                          expected: VPNPasswordItemLocator?) throws -> VPNPasswordItemLocator {
        guard item.service == Self.service, item.account == reference.itemID.uuidString else { throw VPNLegacyPasswordError.unavailable }
        let locator = VPNPasswordItemLocator(persistentReference: item.persistentReference, origin: item.origin)
        try locator.validate()
        if let expected, locator != expected { throw VPNLegacyPasswordError.unavailable }
        return locator
    }
}

/// Every real API call is reached only after the factory's worker-role guard.
/// This adapter never creates/unlocks keychains or changes preferences/ACLs.
private struct VPNLegacyPasswordSecurityAPI: VPNLegacyPasswordAPI {
    let privateAddPath: String?
    #if VPN_LEGACY_PASSWORD_BACKEND_TESTING
    var testDirectory: Int32 = -1
    /// Diagnostics are never a mutation receipt. The ordinary parent still
    /// relies solely on the authenticated worker response and Store gate.
    private func recordDelete(_ stage: UInt8, status: OSStatus) {
        guard testDirectory >= 0 else { return }
        let fd = openat(testDirectory, "private-delete-diagnostic.bin",
            O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC, 0o600)
        guard fd >= 0 else { return }; defer { close(fd) }
        var info = stat()
        guard fstat(fd, &info) == 0, info.st_mode & S_IFMT == S_IFREG,
              info.st_uid == getuid(), info.st_nlink == 1, info.st_mode & 0o777 == 0o600,
              info.st_size == 0 else { return }
        var bytes = Data("PPDEL001".utf8)
        bytes.append(stage)
        var code = UInt32(bitPattern: status).bigEndian
        withUnsafeBytes(of: &code) { bytes.append(contentsOf: $0) }
        _ = bytes.withUnsafeBytes { Darwin.write(fd, $0.baseAddress, $0.count) }
    }
    #endif
    func disableInteraction() throws {
        guard SecKeychainSetUserInteractionAllowed(false) == errSecSuccess else { throw VPNLegacyPasswordError.unavailable }
        var allowed: DarwinBoolean = true
        guard SecKeychainGetUserInteractionAllowed(&allowed) == errSecSuccess, !allowed.boolValue else { throw VPNLegacyPasswordError.unavailable }
    }
    func addTarget() throws -> VPNLegacyPasswordTarget {
        var value: SecKeychain?
        if let path = privateAddPath {
            _ = try identity(path)
            guard SecKeychainOpen(path, &value) == errSecSuccess, let value else { throw VPNLegacyPasswordError.unavailable }
            let observed = try origin(value)
            guard observed.path == path, observed == (try identity(path)) else { throw VPNLegacyPasswordError.unavailable }
            return .init(keychain: value, origin: observed)
        }
        guard SecKeychainCopyDefault(&value) == errSecSuccess, let value else { throw VPNLegacyPasswordError.unavailable }
        return .init(keychain: value, origin: try origin(value))
    }
    func openOriginal(_ expected: VPNPasswordBackendLocator) throws -> VPNLegacyPasswordTarget {
        guard try identity(expected.path) == expected else { throw VPNLegacyPasswordError.unavailable }
        var value: SecKeychain?
        guard SecKeychainOpen(expected.path, &value) == errSecSuccess, let value,
              try origin(value) == expected, try identity(expected.path) == expected else { throw VPNLegacyPasswordError.unavailable }
        return .init(keychain: value, origin: expected)
    }
    func add(target: VPNLegacyPasswordTarget, service: String, account: String, envelope: Data) throws -> VPNLegacyPasswordItem {
        guard let keychain = target.keychain, try origin(keychain) == target.origin else { throw VPNLegacyPasswordError.unavailable }
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service, kSecAttrAccount as String: account,
            kSecUseKeychain as String: keychain, kSecValueData as String: envelope,
            kSecReturnRef as String: true, kSecReturnPersistentRef as String: true,
            kSecReturnAttributes as String: true, kSecReturnData as String: true]
        var value: CFTypeRef?
        let status = SecItemAdd(query as CFDictionary, &value)
        guard status == errSecSuccess else { throw VPNLegacyPasswordError.status(status) }
        return try capture(value)
    }
    func find(target: VPNLegacyPasswordTarget, persistentReference: Data) throws -> VPNLegacyPasswordItem {
        guard let keychain = target.keychain, try origin(keychain) == target.origin else { throw VPNLegacyPasswordError.unavailable }
        // Apple's macOS API uses [CFData] in kSecMatchItemList to resolve pRefs.
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
            kSecMatchItemList as String: [persistentReference], kSecMatchSearchList as String: [keychain],
            kSecMatchLimit as String: kSecMatchLimitOne, kSecReturnRef as String: true,
            kSecReturnPersistentRef as String: true, kSecReturnAttributes as String: true, kSecReturnData as String: true]
        var value: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &value)
        guard status == errSecSuccess else { throw VPNLegacyPasswordError.status(status) }
        return try capture(value)
    }
    func delete(_ item: VPNLegacyPasswordItem) -> OSStatus {
        guard let reference = item.reference, let observed = try? owner(reference), observed == item.origin,
              (try? identity(item.origin.path)) == item.origin else {
            #if VPN_LEGACY_PASSWORD_BACKEND_TESTING
            recordDelete(0, status: errSecNotAvailable)
            #endif
            return errSecNotAvailable
        }
        let status = SecItemDelete([kSecMatchItemList as String: [reference]] as CFDictionary)
        #if VPN_LEGACY_PASSWORD_BACKEND_TESTING
        recordDelete(1, status: status)
        #endif
        return status
    }
    private func capture(_ value: CFTypeRef?) throws -> VPNLegacyPasswordItem {
        guard let dictionary = value as? [String: Any],
              let raw = dictionary[kSecValueRef as String], CFGetTypeID(raw as CFTypeRef) == SecKeychainItemGetTypeID(),
              let persistent = dictionary[kSecValuePersistentRef as String] as? Data,
              let service = dictionary[kSecAttrService as String] as? String,
              let account = dictionary[kSecAttrAccount as String] as? String,
              let envelope = dictionary[kSecValueData as String] as? Data,
              envelope.count <= VPNLegacyPasswordEnvelope.maximumBytes else { throw VPNLegacyPasswordError.unavailable }
        let reference = unsafeBitCast(raw as CFTypeRef, to: SecKeychainItem.self)
        return .init(reference: reference, persistentReference: persistent, origin: try owner(reference),
            service: service, account: account, envelope: envelope)
    }
    private func owner(_ item: SecKeychainItem) throws -> VPNPasswordBackendLocator {
        var keychain: SecKeychain?
        guard SecKeychainItemCopyKeychain(item, &keychain) == errSecSuccess, let keychain else { throw VPNLegacyPasswordError.unavailable }
        return try origin(keychain)
    }
    private func origin(_ keychain: SecKeychain) throws -> VPNPasswordBackendLocator {
        var count = UInt32(MAXPATHLEN), bytes = [CChar](repeating: 0, count: Int(MAXPATHLEN))
        guard SecKeychainGetPath(keychain, &count, &bytes) == errSecSuccess else { throw VPNLegacyPasswordError.unavailable }
        return try identity(String(cString: bytes))
    }
    private func identity(_ path: String) throws -> VPNPasswordBackendLocator {
        let fd = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard fd >= 0 else { throw VPNLegacyPasswordError.unavailable }; defer { close(fd) }
        var held = stat(), named = stat()
        guard fstat(fd, &held) == 0, lstat(path, &named) == 0,
              held.st_mode & S_IFMT == S_IFREG, held.st_uid == getuid(), held.st_nlink == 1,
              held.st_mode & 0o022 == 0, held.st_dev == named.st_dev, held.st_ino == named.st_ino,
              named.st_mode & S_IFMT == S_IFREG else { throw VPNLegacyPasswordError.unavailable }
        let result = VPNPasswordBackendLocator(kind: .legacyKeychain, path: path,
            device: UInt64(UInt32(bitPattern: held.st_dev)), inode: UInt64(held.st_ino), ownerUID: held.st_uid,
            birthSeconds: Int64(held.st_birthtimespec.tv_sec), birthNanoseconds: UInt32(held.st_birthtimespec.tv_nsec))
        try result.validate(); return result
    }
}
