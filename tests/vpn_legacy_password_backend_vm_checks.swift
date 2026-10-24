import CryptoKit
import Darwin
import Foundation
import Security

// BEGIN NO-KEYCHAIN FILE IDENTITY
// Pure filesystem proof, also exercised without importing or invoking Security APIs.
struct VPNPrivateKeychainPathProof {
    enum Target: String { case first, second
        var base: Leaf { self == .first ? .firstBase : .secondBase }
        var db: Leaf { self == .first ? .firstDB : .secondDB }
    }
    enum Leaf: String {
        case firstBase = "first.keychain", firstDB = "first.keychain-db"
        case secondBase = "second.keychain", secondDB = "second.keychain-db"
    }
    var actualExists = false, intendedExists = false, actualRegularOwned = false, regularOwned = false
    var baseExists = false, dbExists = false, baseMissingPositive = false, dbMissingPositive = false
    var uniqueKnownLeaf = false, expectedLeafMatches = false
    var sameFile = false, sameParent = false, canonicalEqual = false, namesStable = false
    var canonicalActual: String?
    var attributes: stat?
    var leaf: Leaf?
    var accepted: Bool {
        actualExists && intendedExists && actualRegularOwned && regularOwned && uniqueKnownLeaf && expectedLeafMatches &&
        sameFile && sameParent && canonicalEqual && namesStable
    }
    private static func same(_ a: stat, _ b: stat) -> Bool {
        a.st_dev == b.st_dev && a.st_ino == b.st_ino && a.st_uid == b.st_uid &&
        a.st_birthtimespec.tv_sec == b.st_birthtimespec.tv_sec && a.st_birthtimespec.tv_nsec == b.st_birthtimespec.tv_nsec
    }
    private static func regular(_ a: stat) -> Bool {
        a.st_mode & S_IFMT == S_IFREG && a.st_uid == getuid() && a.st_nlink == 1 && a.st_mode & 0o022 == 0
    }
    private static func fullPath(_ fd: Int32) -> String? {
        var bytes = [CChar](repeating: 0, count: Int(MAXPATHLEN))
        guard fcntl(fd, F_GETPATH, &bytes) == 0 else { return nil }
        let result = String(cString: bytes)
        return result.hasPrefix("/") ? result : nil
    }
    static func inspect(actual: String, directory: Int32, target: Target, requiredLeaf: Leaf? = nil) -> Self {
        var proof = Self(), heldDirectory = stat()
        guard actual.hasPrefix("/"), fstat(directory, &heldDirectory) == 0, heldDirectory.st_mode & S_IFMT == S_IFDIR,
              heldDirectory.st_uid == getuid(), heldDirectory.st_mode & 0o777 == 0o700 else { return proof }
        let actualFD = open(actual, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        defer { if actualFD >= 0 { close(actualFD) } }
        proof.actualExists = actualFD >= 0
        var actualInfo = stat()
        // Observe actual-file and parent facts independently of candidate lookup.
        if actualFD >= 0, fstat(actualFD, &actualInfo) == 0 {
            proof.actualRegularOwned = regular(actualInfo); proof.attributes = actualInfo
            if let actualPath = fullPath(actualFD), let separator = actualPath.lastIndex(of: "/") {
                proof.canonicalActual = actualPath
                let parentFD = open(String(actualPath[..<separator]), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
                if parentFD >= 0 {
                    var parent = stat()
                    proof.sameParent = fstat(parentFD, &parent) == 0 && same(parent, heldDirectory)
                    close(parentFD)
                }
            }
        }
        let baseFD = openat(directory, target.base.rawValue, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        proof.baseExists = baseFD >= 0; proof.baseMissingPositive = baseFD < 0 && errno == ENOENT
        let dbFD = openat(directory, target.db.rawValue, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        proof.dbExists = dbFD >= 0; proof.dbMissingPositive = dbFD < 0 && errno == ENOENT
        defer { if baseFD >= 0 { close(baseFD) }; if dbFD >= 0 { close(dbFD) } }
        let intendedFD: Int32, selected: Leaf, absent: Leaf
        if baseFD >= 0, proof.dbMissingPositive { intendedFD = baseFD; selected = target.base; absent = target.db }
        else if dbFD >= 0, proof.baseMissingPositive { intendedFD = dbFD; selected = target.db; absent = target.base }
        else { return proof } // both/neither/permission/symlink ambiguity is refused
        proof.uniqueKnownLeaf = true; proof.leaf = selected; proof.intendedExists = true
        proof.expectedLeafMatches = requiredLeaf == nil || requiredLeaf == selected
        guard actualFD >= 0, let actualPath = proof.canonicalActual else { return proof }
        var intendedInfo = stat()
        guard fstat(intendedFD, &intendedInfo) == 0 else { return proof }
        proof.regularOwned = proof.actualRegularOwned && regular(intendedInfo)
        proof.sameFile = same(actualInfo, intendedInfo)
        proof.canonicalEqual = fullPath(intendedFD) == actualPath
        var directoryAfter = stat(), actualNamed = stat(), intendedNamed = stat(), canonicalNamed = stat(), alternateNamed = stat()
        let alternateAbsent = fstatat(directory, absent.rawValue, &alternateNamed, AT_SYMLINK_NOFOLLOW) != 0 && errno == ENOENT
        proof.namesStable = lstat(actual, &actualNamed) == 0 && regular(actualNamed) && same(actualInfo, actualNamed) &&
            fstatat(directory, selected.rawValue, &intendedNamed, AT_SYMLINK_NOFOLLOW) == 0 && regular(intendedNamed) && same(intendedInfo, intendedNamed) &&
            lstat(actualPath, &canonicalNamed) == 0 && regular(canonicalNamed) && same(actualInfo, canonicalNamed) && alternateAbsent &&
            fstat(directory, &directoryAfter) == 0 && same(heldDirectory, directoryAfter) && directoryAfter.st_mode & 0o777 == 0o700
        return proof
    }
}
// END NO-KEYCHAIN FILE IDENTITY

/// REAL APIs ONLY in a fresh opt-in disposable GHA job. Never run on a host.
@main enum VPNLegacyPasswordBackendVMChecks {
    enum Failure: Error { case guardFailed, check, api }
    private enum Evidence: String {
        case searchList, searchListDecoded, defaultKeychain, getPath
        case initialInteraction, finalInteraction, interactionUnchanged
        case createKeychain, createHandle, createdPathIsDB, createdPathIsBase
        case createdPrivateMode, fixtureAdd, fixtureAddResult, itemDictionary
        case itemOwner, ownerIsPrivate, ownerFileOpen, ownerFileIdentity
        case privateLock, cleanupKeychain, preferencesUnchanged
        case workerAddAdded, workerAddNoIO, workerAcknowledgmentBegin, workerAcknowledgmentBusy
        case actualFileExists, intendedFileExists, pathRegularOwned, pathSameFile
        case pathSameParent, pathCanonicalEqual, pathNamesStable, actualRegularOwned
        case baseFileExists, dbFileExists, baseMissingPositive, dbMissingPositive, uniqueKnownLeaf, expectedLeafMatches
    }
    private static func evidence(_ phase: Evidence, status: OSStatus? = nil, value: Bool? = nil) {
        // Closed identifiers, decimal status and boolean ONLY. No exceptions,
        // keychain/default names, paths, dictionaries, refs or credential data.
        let statusText = status.map { String($0) } ?? "none"
        let valueText = value.map { $0 ? "true" : "false" } ?? "none"
        FileHandle.standardError.write(Data("private-backend:\(phase.rawValue):status=\(statusText):ok=\(valueText)\n".utf8))
    }
    private enum Boundary: String { case prepare, initialAdd }
    private enum BoundaryError: String {
        case invalid, denied, unavailable, transport, timeout
        case storageUnavailable, staleRevision, invalidConfiguration, receiptBusy, other
    }
    private static func boundaryError(_ error: Error) -> BoundaryError {
        if let error = error as? VPNPasswordWorkerError {
            switch error {
            case .invalid: return .invalid
            case .denied: return .denied
            case .unavailable: return .unavailable
            case .transport: return .transport
            case .timeout: return .timeout
            }
        }
        if let error = error as? VPNValidationError {
            switch error {
            case .storageUnavailable: return .storageUnavailable
            case .staleRevision: return .staleRevision
            case .invalidConfiguration: return .invalidConfiguration
            default: return .other
            }
        }
        if let error = error as? VPNPasswordReceiptAcknowledgmentError {
            switch error { case .lockBusy: return .receiptBusy }
        }
        return .other
    }
    private static func trace<T>(_ boundary: Boundary, _ operation: () throws -> T) throws -> T {
        let prefix = "private-backend-boundary:stage=" + boundary.rawValue
        FileHandle.standardError.write(Data((prefix + ":event=begin\n").utf8))
        do {
            let result = try operation()
            FileHandle.standardError.write(Data((prefix + ":event=ok\n").utf8))
            return result
        } catch {
            FileHandle.standardError.write(Data((prefix + ":event=fail:category=" + boundaryError(error).rawValue + "\n").utf8))
            throw error
        }
    }
    /// Diagnostic callbacks on the EXISTING test-only seams. They observe only
    /// receipt acknowledgment, never request another GO or alter the clock.
    private static func observingInitialAcknowledgment<T>(_ body: () throws -> T) rethrows -> T {
        let previousBegin = VPNPasswordWorker.Prepared.testBeforeAcknowledgment
        let previousBusy = VPNPasswordWorker.Prepared.testAfterBusyAcknowledgment
        var began = false, busyCount = 0
        VPNPasswordWorker.Prepared.testBeforeAcknowledgment = {
            guard !began else { return }; began = true
            evidence(.workerAcknowledgmentBegin, value: true)
        }
        VPNPasswordWorker.Prepared.testAfterBusyAcknowledgment = {
            guard busyCount < 3 else { return }; busyCount += 1
            evidence(.workerAcknowledgmentBusy, value: true)
        }
        defer {
            VPNPasswordWorker.Prepared.testBeforeAcknowledgment = previousBegin
            VPNPasswordWorker.Prepared.testAfterBusyAcknowledgment = previousBusy
        }
        return try body()
    }
    static func check(_ condition: @autoclosure () throws -> Bool) throws {
        guard try condition() else { throw Failure.check }
    }
    static func waitChildren() throws {
        let deadline = DispatchTime.now().uptimeNanoseconds + 7_000_000_000
        repeat {
            var status: Int32 = 0
            let result = waitpid(-1, &status, WNOHANG)
            if result < 0, errno == ECHILD { return }
            guard result >= 0 else { throw Failure.check }
            usleep(20_000)
        } while DispatchTime.now().uptimeNanoseconds < deadline
        throw Failure.check
    }
    static func path(_ keychain: SecKeychain) throws -> String {
        var size = UInt32(MAXPATHLEN), bytes = [CChar](repeating: 0, count: Int(MAXPATHLEN))
        let status = SecKeychainGetPath(keychain, &size, &bytes)
        evidence(.getPath, status: status)
        guard status == errSecSuccess else { throw Failure.api }
        return String(cString: bytes)
    }
    static func preferences() throws -> Data {
        var list: CFArray?, defaultKeychain: SecKeychain?
        let searchStatus = SecKeychainCopySearchList(&list)
        evidence(.searchList, status: searchStatus)
        let decoded = list as? [SecKeychain]
        evidence(.searchListDecoded, value: decoded != nil)
        guard searchStatus == errSecSuccess, let list = decoded else { throw Failure.api }
        let status = SecKeychainCopyDefault(&defaultKeychain)
        evidence(.defaultKeychain, status: status, value: defaultKeychain != nil)
        guard status == errSecSuccess || status == errSecNoDefaultKeychain else { throw Failure.api }
        return try JSONSerialization.data(withJSONObject: ["search": list.map { try path($0) },
            "default": try defaultKeychain.map { try path($0) } ?? "", "status": status], options: .sortedKeys)
    }
    static func unchangedPreferences(_ baseline: Data) throws -> Bool {
        let unchanged = try preferences() == baseline
        evidence(.preferencesUnchanged, value: unchanged)
        return unchanged
    }
    static func seed(_ folder: URL) throws -> (VPNStore, VPNPasswordReference, UInt64) {
        let store = VPNStore(directory: folder)
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
        var config = VPNConfiguration(); try config.setProfile(name: profile.name)
        try config.saveResource(VPNResource(address: "10.20.0.0/16"))
        try config.setAuthentication(VPNAuthentication(mode: .password, login: "synthetic", credentialPersistence: .keychain))
        _ = try store.save(config, importing: profile, expectedRevision: nil)
        return (store, try store.grantPasswordPersistence(expectedRevision: config.revision), config.revision)
    }
    static func revoke(_ store: VPNStore) throws {
        let state = try store.load()!; var config = state.saved.configuration
        try config.setAuthentication(VPNAuthentication(mode: .password, login: "synthetic"))
        _ = try store.save(config, expectedRevision: state.saved.configuration.revision)
    }
    static func privateWrite(_ bytes: Data, _ path: URL) throws {
        try bytes.write(to: path, options: .atomic)
        guard chmod(path.path, 0o600) == 0 else { throw Failure.guardFailed }
    }
    static func privateProof(_ actual: String, directory: Int32, target: VPNPrivateKeychainPathProof.Target,
                             requiredLeaf: VPNPrivateKeychainPathProof.Leaf? = nil) throws -> VPNPrivateKeychainPathProof {
        let proof = VPNPrivateKeychainPathProof.inspect(actual: actual, directory: directory, target: target, requiredLeaf: requiredLeaf)
        evidence(.actualFileExists, value: proof.actualExists)
        evidence(.intendedFileExists, value: proof.intendedExists)
        evidence(.actualRegularOwned, value: proof.actualRegularOwned)
        evidence(.baseFileExists, value: proof.baseExists); evidence(.dbFileExists, value: proof.dbExists)
        evidence(.baseMissingPositive, value: proof.baseMissingPositive); evidence(.dbMissingPositive, value: proof.dbMissingPositive)
        evidence(.uniqueKnownLeaf, value: proof.uniqueKnownLeaf); evidence(.expectedLeafMatches, value: proof.expectedLeafMatches)
        evidence(.pathRegularOwned, value: proof.regularOwned)
        evidence(.pathSameFile, value: proof.sameFile)
        evidence(.pathSameParent, value: proof.sameParent)
        evidence(.pathCanonicalEqual, value: proof.canonicalEqual)
        evidence(.pathNamesStable, value: proof.namesStable)
        guard proof.accepted else { throw Failure.guardFailed }
        return proof
    }
    struct CreatedKeychain {
        let keychain: SecKeychain
        let target: VPNPrivateKeychainPathProof.Target
        let leaf: VPNPrivateKeychainPathProof.Leaf
    }
    static func create(_ folder: URL, directory: Int32, target: VPNPrivateKeychainPathProof.Target) throws -> CreatedKeychain {
        let base = folder.appendingPathComponent(target.base.rawValue).path
        var info = stat()
        guard lstat(base, &info) != 0, errno == ENOENT,
              lstat(base + "-db", &info) != 0, errno == ENOENT else { throw Failure.guardFailed }
        let password = Data("synthetic-disposable-keychain-password".utf8)
        var result: SecKeychain?
        let status = password.withUnsafeBytes { SecKeychainCreate(base, UInt32($0.count), $0.baseAddress, false, nil, &result) }
        evidence(.createKeychain, status: status)
        evidence(.createHandle, value: result != nil)
        guard status == errSecSuccess, let result else { throw Failure.api }
        let observed = try path(result)
        evidence(.createdPathIsDB, value: observed == base + "-db")
        evidence(.createdPathIsBase, value: observed == base)
        // Different POSIX spellings are accepted only with independent held
        // descriptor proof of this exact known fresh DB and private parent.
        let proof = try privateProof(observed, directory: directory, target: target)
        guard let leaf = proof.leaf else { throw Failure.guardFailed }
        let file = openat(directory, leaf.rawValue, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard file >= 0 else { throw Failure.guardFailed }; defer { close(file) }
        var held = stat()
        guard let expected = proof.attributes, fstat(file, &held) == 0,
              held.st_dev == expected.st_dev, held.st_ino == expected.st_ino, held.st_uid == expected.st_uid,
              held.st_birthtimespec.tv_sec == expected.st_birthtimespec.tv_sec,
              held.st_birthtimespec.tv_nsec == expected.st_birthtimespec.tv_nsec else { throw Failure.guardFailed }
        let privateMode = fchmod(file, 0o600) == 0
        evidence(.createdPrivateMode, value: privateMode)
        guard privateMode else { throw Failure.guardFailed }
        return CreatedKeychain(keychain: result, target: target, leaf: leaf)
    }
    static func observedLocator(_ raw: CFTypeRef?, directory: Int32, intended: CreatedKeychain) throws -> VPNPasswordItemLocator {
        evidence(.itemDictionary, value: raw as? [String: Any] != nil)
        guard let result = raw as? [String: Any], let persistent = result[kSecValuePersistentRef as String] as? Data,
              let rawItem = result[kSecValueRef as String], CFGetTypeID(rawItem as CFTypeRef) == SecKeychainItemGetTypeID() else { throw Failure.api }
        let item = unsafeBitCast(rawItem as CFTypeRef, to: SecKeychainItem.self)
        var keychain: SecKeychain?
        let status = SecKeychainItemCopyKeychain(item, &keychain)
        evidence(.itemOwner, status: status, value: keychain != nil)
        guard status == errSecSuccess, let keychain else { throw Failure.api }
        let actual = try path(keychain)
        let proof = try privateProof(actual, directory: directory, target: intended.target, requiredLeaf: intended.leaf)
        guard let canonical = proof.canonicalActual, let info = proof.attributes else { throw Failure.guardFailed }
        let locator = VPNPasswordItemLocator(persistentReference: persistent, origin: .init(kind: .legacyKeychain,
            path: canonical, device: UInt64(UInt32(bitPattern: info.st_dev)), inode: UInt64(info.st_ino), ownerUID: info.st_uid,
            birthSeconds: Int64(info.st_birthtimespec.tv_sec), birthNanoseconds: UInt32(info.st_birthtimespec.tv_nsec)))
        try locator.validate(); return locator
    }
    static func fixtureAdd(_ intended: CreatedKeychain, directory: Int32, reference: VPNPasswordReference,
                           envelope: Data) throws -> VPNPasswordItemLocator {
        // Explicit owned target verified before API: never an absent target that
        // could accidentally select the CI account's default keychain.
        let keychain = intended.keychain
        let actual = try path(keychain)
        let before = try privateProof(actual, directory: directory, target: intended.target, requiredLeaf: intended.leaf)
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: VPNLegacyPasswordBackend.service, kSecAttrAccount as String: reference.itemID.uuidString,
            kSecUseKeychain as String: keychain, kSecValueData as String: envelope,
            kSecReturnRef as String: true, kSecReturnPersistentRef as String: true]
        var result: CFTypeRef?
        let status = SecItemAdd(query as CFDictionary, &result)
        evidence(.fixtureAdd, status: status)
        evidence(.fixtureAddResult, value: result != nil)
        guard status == errSecSuccess else { throw Failure.api }
        let locator = try observedLocator(result, directory: directory, intended: intended)
        guard locator.origin.path == before.canonicalActual else { throw Failure.guardFailed }
        return locator
    }
    static func main() throws {
        if let status = VPNPasswordWorker.testRunIfRequested(arguments: CommandLine.arguments,
            backend: { try VPNLegacyPasswordBackend.testPrivateWorker(directory: $0) }) { exit(status) }
        // BEFORE any parent Security/flag/preference API, create/open or lookup.
        guard ProcessInfo.processInfo.environment["GITHUB_ACTIONS"] == "true",
              ProcessInfo.processInfo.environment["PROXYPILOT_VM_PASSWORD_BACKEND_TESTS"] == "1",
              getuid() == geteuid(), getuid() >= 500, CommandLine.arguments.count >= 3 else { exit(77) }
        let action = CommandLine.arguments[1]
        guard ["roundtrip", "locked", "missing", "replaced", "malformed", "denied-version", "deny-existing", "marker"].contains(action) else { exit(64) }
        let root = URL(fileURLWithPath: CommandLine.arguments[2], isDirectory: true).standardizedFileURL.resolvingSymlinksInPath()
        var info = stat()
        guard root.path != NSHomeDirectory(), root.path != "/", lstat(root.path, &info) == 0,
              info.st_mode & S_IFMT == S_IFDIR, info.st_uid == getuid(), info.st_mode & 0o777 == 0o700 else { throw Failure.guardFailed }
        #if DIFFERENT_BACKEND_BUILD
        if action == "marker" { print("different-backend-code"); return }
        #else
        if action == "marker" { print("original-backend-code"); return }
        #endif
        if action == "deny-existing" {
            let store = VPNStore(directory: root)
            guard let state = try store.load(), let reference = state.passwordLedger.active?.reference else { throw Failure.guardFailed }
            let marker = root.appendingPathComponent("private-unknown-api")
            try privateWrite(Data("read".utf8), marker)
            let read = try VPNPasswordWorker.prepare(store: store).read(store: store, reference: reference,
                revision: state.saved.configuration.revision)
            if read.status != .indeterminate { try FileManager.default.removeItem(at: marker) }
            try check(read.status != .success && read.status != .indeterminate && read.secret.isEmpty)
            try waitChildren(); print("private backend denial passed"); return
        }
        let folder = root.appendingPathComponent("Store", isDirectory: true)
        guard lstat(folder.path, &info) != 0, errno == ENOENT else { throw Failure.guardFailed }
        let baseline = try preferences()
        var allowed: DarwinBoolean = false
        let initialFlagStatus = SecKeychainGetUserInteractionAllowed(&allowed)
        evidence(.initialInteraction, status: initialFlagStatus, value: allowed.boolValue)
        guard initialFlagStatus == errSecSuccess else { throw Failure.api }
        let beforeFlag = allowed.boolValue
        let (store, reference, revision) = try seed(folder)
        // Hold the original private parent across Create/Add and all proofs.
        let directory = open(folder.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard directory >= 0 else { throw Failure.guardFailed }; defer { close(directory) }
        let unknownAPI = folder.appendingPathComponent("private-unknown-api")
        func begin(_ operation: String) throws { try privateWrite(Data(operation.utf8), unknownAPI) }
        func definite() throws { try FileManager.default.removeItem(at: unknownAPI) }
        func safeToClean() -> Bool {
            guard (try? waitChildren()) != nil else { return false }
            if !FileManager.default.fileExists(atPath: unknownAPI.path) { return true }
            // A late exact typed receipt proves only the INITIAL Add finished.
            // It cannot authorize cleanup of an unknown decoy Add or Delete RPC.
            guard (try? String(contentsOf: unknownAPI, encoding: .utf8)) == "initial-add",
                  let state = try? store.load(), let slot = state.passwordLedger.active,
                  slot.reference == reference,
                  (slot.writeState == .noItem || (slot.writeState == .settled && slot.locator != nil)) else { return false }
            do { try definite(); return true } catch { return false }
        }
        func cleanup(_ created: CreatedKeychain) -> Bool {
            guard safeToClean() else { return false }
            do {
                _ = try privateProof(path(created.keychain), directory: directory,
                    target: created.target, requiredLeaf: created.leaf)
                try begin("keychain-delete")
                let status = SecKeychainDelete(created.keychain)
                evidence(.cleanupKeychain, status: status)
                guard status == errSecSuccess else { return false }
                try definite(); return true
            } catch { return false }
        }
        try privateWrite(Data("GHA-PRIVATE-KEYCHAIN-BACKEND-01".utf8), folder.appendingPathComponent("private-keychain-opt-in"))
        try privateWrite(Data("A".utf8), folder.appendingPathComponent("private-add-target"))
        try begin("keychain-create")
        let first = try create(folder, directory: directory, target: .first)
        try definite()
        try privateWrite(Data(first.leaf.rawValue.utf8), folder.appendingPathComponent("private-keychain-name-A"))
        var firstExists = true
        defer {
            // Unknown Add may outlive its soft reply. Never remove its target
            // while a child might still be inside the credential API.
            if firstExists { _ = cleanup(first) }
        }
        try begin("keychain-create")
        let second = try create(folder, directory: directory, target: .second)
        try definite()
        try privateWrite(Data(second.leaf.rawValue.utf8), folder.appendingPathComponent("private-keychain-name-B"))
        var secondExists = true
        defer { if secondExists { _ = cleanup(second) } }
        try check(unchangedPreferences(baseline))
        var secret = Data("synthetic-static-password".utf8)
        defer { VPNPasswordWorkerWire.clear(&secret) }
        let locator: VPNPasswordItemLocator
        if action == "malformed" {
            let result = try store.addPasswordOnce(reference: reference, expectedRevision: revision) { _ in
                try begin("initial-add")
                let captured = try fixtureAdd(first, directory: directory, reference: reference, envelope: Data("not-an-envelope".utf8))
                try definite()
                return .added(captured)
            }
            guard case .added(let captured) = result else { throw Failure.check }; locator = captured
        } else {
            let worker = try trace(.prepare) { try VPNPasswordWorker.prepare(store: store) }
            try begin("initial-add")
            let result = try trace(.initialAdd) {
                try observingInitialAcknowledgment {
                    try worker.addOnce(store: store, reference: reference, revision: revision, secret: &secret)
                }
            }
            if case .added = result { evidence(.workerAddAdded, value: true); try definite() }
            else {
                evidence(.workerAddAdded, value: false)
                evidence(.workerAddNoIO, value: result == .definitelyNoIO)
                if result == .definitelyNoIO { try definite() }
            }
            guard case .added(let captured) = result else { throw Failure.check }; locator = captured
            try waitChildren()
        }
        try check(unchangedPreferences(baseline))
        _ = try privateProof(locator.origin.path, directory: directory, target: first.target, requiredLeaf: first.leaf)
        var fileInfo = stat()
        guard lstat(locator.origin.path, &fileInfo) == 0 else { throw Failure.check }
        try check(locator.origin.device == UInt64(UInt32(bitPattern: fileInfo.st_dev)) && locator.origin.inode == UInt64(fileInfo.st_ino))
        if action == "roundtrip" {
            // A different PRIVATE Add target and an explicit B decoy model a
            // default-context change without ever changing CI preferences.
            try begin("decoy-add")
            _ = try fixtureAdd(second, directory: directory, reference: reference,
                envelope: VPNLegacyPasswordEnvelope.encode(reference: reference, secret: Data("decoy".utf8)))
            try definite()
            try privateWrite(Data("B".utf8), folder.appendingPathComponent("private-add-target"))
            try begin("read")
            var read = try VPNPasswordWorker.prepare(store: store).read(store: store, reference: reference, revision: revision)
            if read.status != .indeterminate { try definite() }
            try check(read.status == .success && read.secret == Data("synthetic-static-password".utf8))
            VPNPasswordWorkerWire.clear(&read.secret); try waitChildren(); try revoke(store)
            try begin("delete")
            try VPNPasswordWorker.prepare(store: store).deletePending(store: store, reference: reference)
            try definite()
            try waitChildren(); try check(store.load()!.passwordLedger.pendingDeletion.isEmpty)
            var value: CFTypeRef?
            let decoy: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: VPNLegacyPasswordBackend.service, kSecAttrAccount as String: reference.itemID.uuidString,
                kSecMatchSearchList as String: [second.keychain], kSecReturnRef as String: true]
            try check(SecItemCopyMatching(decoy as CFDictionary, &value) == errSecSuccess)
        } else if action == "denied-version" {
            guard CommandLine.arguments.count == 4 else { throw Failure.guardFailed }
            try begin("read")
            var positive = try VPNPasswordWorker.prepare(store: store).read(store: store, reference: reference, revision: revision)
            if positive.status != .indeterminate { try definite() }
            try check(positive.status == .success && positive.secret == Data("synthetic-static-password".utf8))
            VPNPasswordWorkerWire.clear(&positive.secret); try waitChildren()
            let process = Process(); process.executableURL = URL(fileURLWithPath: CommandLine.arguments[3])
            process.arguments = ["deny-existing", folder.path]
            process.standardOutput = FileHandle.nullDevice; process.standardError = FileHandle.nullDevice
            try process.run(); process.waitUntilExit(); try check(process.terminationStatus == 0)
            try check(store.load()!.passwordLedger.active?.locator == locator)
        } else {
            let original = folder.appendingPathComponent(first.leaf.rawValue)
            let held = folder.appendingPathComponent("held-" + first.leaf.rawValue)
            if action == "locked" {
                try begin("keychain-lock")
                let status = SecKeychainLock(first.keychain)
                evidence(.privateLock, status: status)
                try check(status == errSecSuccess)
                try definite()
            }
            if action == "missing" || action == "replaced" {
                try FileManager.default.moveItem(at: original, to: held)
                if action == "replaced" { try FileManager.default.copyItem(at: folder.appendingPathComponent(second.leaf.rawValue), to: original) }
            }
            defer {
                if (action == "missing" || action == "replaced"), safeToClean() {
                    if action == "replaced" { try? FileManager.default.removeItem(at: original) }
                    try? FileManager.default.moveItem(at: held, to: original)
                }
            }
            try begin("read")
            let read = try VPNPasswordWorker.prepare(store: store).read(store: store, reference: reference, revision: revision)
            if read.status != .indeterminate { try definite() }
            try check(read.status != .success && read.status != .indeterminate && read.secret.isEmpty)
            try waitChildren(); try revoke(store)
            let worker = try VPNPasswordWorker.prepare(store: store)
            try begin("delete")
            var observed: VPNPasswordWorkerStatus?
            do {
                try store.deletePendingPassword(reference: reference) { _, captured in
                    var empty = Data()
                    let result = try worker.testPerform(operation: .delete, reference: reference, revision: revision,
                        secret: &empty, timeout: 5_000_000_000, locator: captured)
                    observed = result.status
                    if result.status != .indeterminate { try definite() }
                    switch result.status {
                    case .success: return .deleted
                    case .notFound: return .notFound
                    case .unavailable: return .unavailable
                    default: return .indeterminate
                    }
                }
                throw Failure.check
            } catch VPNValidationError.storageUnavailable { }
            try check(observed != nil && observed != .indeterminate)
            try waitChildren(); try check(store.load()!.passwordLedger.pendingDeletion.count == 1)
        }
        try check(safeToClean())
        try check(unchangedPreferences(baseline))
        try check(cleanup(second)); secondExists = false
        try check(cleanup(first)); firstExists = false
        var afterFlag = DarwinBoolean(!beforeFlag)
        let finalFlagStatus = SecKeychainGetUserInteractionAllowed(&afterFlag)
        evidence(.finalInteraction, status: finalFlagStatus, value: afterFlag.boolValue)
        guard finalFlagStatus == errSecSuccess else { throw Failure.api }
        evidence(.interactionUnchanged, value: afterFlag.boolValue == beforeFlag)
        try check(afterFlag.boolValue == beforeFlag && unchangedPreferences(baseline))
        print("private backend checks passed")
    }
}
