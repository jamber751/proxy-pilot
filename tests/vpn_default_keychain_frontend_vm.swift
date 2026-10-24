// Compiled ONLY into a private acceptance-source snapshot, never a release.
// The genuine worker entry and its production backend factory are unchanged.
import Darwin
import Dispatch
import Foundation
import Security

enum VPNDefaultKeychainVMEntry {
    static let argument = "--vpn-default-keychain-vm"
    static let optIn = "PROXYPILOT-DISPOSABLE-DEFAULT-KEYCHAIN-01"
    enum Failure: Error { case guardFailed, checkFailed, apiFailed, ambiguous }
    enum Step: String {
        case baseline, path, createA, createB, setA, setB, addA, addB, readA, readB
        case otherRead, otherDelete, deleteA, deleteB, restore, removeA, removeB
    }
    // Closed VM-only diagnostics around existing calls. No extra Security API
    // preflight and no changes to the genuine worker/backend source or factory.
    enum TraceStage: String {
        case targetAnchor, expectedDefault, setAPI, resultDefault, requireDefault
        case prepare, begin, dispatch, locatorProof, children, ledger, definite
    }
    enum ErrorCategory: String {
        case invalid, denied, unavailable, transport, timeout
        case storageUnavailable, staleRevision, invalidConfiguration, receiptBusy
        case guardFailed, checkFailed, apiFailed, ambiguous, other
    }
    enum AnchorRole: String { case standalone, target, expected, actual }
    enum AnchorFailure: String { case heldStat, heldIdentity, heldLink, namedStat, namedIdentity, namedRegular }
    static func category(_ error: Error) -> ErrorCategory {
        if let error = error as? VPNPasswordWorkerError {
            switch error {
            case .invalid: return .invalid
            case .denied: return .denied
            case .unavailable: return .unavailable
            case .transport: return .transport
            case .timeout: return .timeout
            }
        }
        if let error = error as? VPNPeerAuthenticationError {
            switch error { case .invalidPolicy: return .invalid; case .denied: return .denied }
        }
        if let error = error as? VPNValidationError {
            switch error {
            case .storageUnavailable: return .storageUnavailable
            case .staleRevision: return .staleRevision
            case .invalidConfiguration: return .invalidConfiguration
            default: return .invalid
            }
        }
        if let error = error as? VPNPasswordReceiptAcknowledgmentError {
            switch error { case .lockBusy: return .receiptBusy }
        }
        if let error = error as? Failure {
            switch error {
            case .guardFailed: return .guardFailed
            case .checkFailed: return .checkFailed
            case .apiFailed: return .apiFailed
            case .ambiguous: return .ambiguous
            }
        }
        return .other
    }
    static func trace<T>(_ step: Step, _ stage: TraceStage, _ operation: () throws -> T) throws -> T {
        let prefix = "default-keychain-vm:boundary=" + step.rawValue + ":stage=" + stage.rawValue
        print(prefix + ":event=begin"); fflush(stdout)
        do {
            let result = try operation()
            print(prefix + ":event=ok"); fflush(stdout)
            return result
        } catch {
            print(prefix + ":event=fail:category=" + category(error).rawValue); fflush(stdout)
            throw error
        }
    }
    static func anchorCheck(_ value: Bool, role: AnchorRole, failure: AnchorFailure) throws {
        guard value else {
            print("default-keychain-vm:anchor=" + role.rawValue + ":failure=" + failure.rawValue); fflush(stdout)
            throw Failure.guardFailed
        }
    }
    enum OtherRead: String { case allowed, fallback }
    enum OtherDelete: String { case deleted, unavailable, notFound, indeterminate }
    static let secretA = Data("genuine-static-password-A".utf8)
    static let secretB = Data("genuine-decoy-password-B".utf8)

    static func runIfRequested(arguments: [String]) -> Int32? {
        guard arguments.dropFirst().contains(argument) else { return nil }
        guard arguments.count == 5, arguments[1] == argument,
              ["roundtrip", "crossrelease", "other-read", "other-delete"].contains(arguments[2]) else { return 64 }
        // BEFORE every preference, interaction flag or Keychain API.
        guard ProcessInfo.processInfo.environment["GITHUB_ACTIONS"] == "true",
              ProcessInfo.processInfo.environment["PROXYPILOT_VM_DEFAULT_KEYCHAIN_TESTS"] == "1",
              getuid() == geteuid(), getuid() >= 500 else { return 77 }
        do {
            let root = try Root.open(arguments[3], fresh: arguments[2] == "roundtrip" || arguments[2] == "crossrelease")
            if arguments[2] == "other-read" { try otherRead(root); return 0 }
            if arguments[2] == "other-delete" { return try otherDelete(root) }
            return try runFresh(root, action: arguments[2], otherImage: arguments[4])
        } catch {
            // No error descriptions, item references, paths, accounts or data.
            print("default-keychain-vm:outcome=failed")
            return 77
        }
    }
    static func check(_ value: @autoclosure () throws -> Bool) throws {
        guard try value() else { throw Failure.checkFailed }
    }
    static func evidence(_ step: Step, _ status: OSStatus) {
        print("default-keychain-vm:phase=" + step.rawValue + ":status=" + String(status))
        fflush(stdout)
    }
    static func status(_ step: Step, _ operation: () -> OSStatus) throws {
        let result = operation(); evidence(step, result)
        guard result == errSecSuccess else { throw Failure.apiFailed }
    }
    static func path(_ keychain: SecKeychain) throws -> String {
        var bytes = [CChar](repeating: 0, count: Int(MAXPATHLEN)); var count = UInt32(bytes.count)
        try status(.path) { SecKeychainGetPath(keychain, &count, &bytes) }
        let value = String(cString: bytes)
        guard value.hasPrefix("/"), value.utf8.count < Int(MAXPATHLEN) else { throw Failure.guardFailed }
        return value
    }
    static func same(_ a: stat, _ b: stat) -> Bool {
        a.st_dev == b.st_dev && a.st_ino == b.st_ino && a.st_uid == b.st_uid &&
        a.st_birthtimespec.tv_sec == b.st_birthtimespec.tv_sec && a.st_birthtimespec.tv_nsec == b.st_birthtimespec.tv_nsec
    }
    final class DefaultAnchor {
        let keychain: SecKeychain
        let descriptor: Int32
        let attributes: stat
        let canonical: String
        init(_ keychain: SecKeychain) throws {
            let named = try path(keychain)
            let fd = open(named, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
            guard fd >= 0 else { throw Failure.guardFailed }
            var transferred = false; defer { if !transferred { close(fd) } }
            var info = stat(), again = stat(), filesystem = statfs()
            guard fstat(fd, &info) == 0, info.st_mode & S_IFMT == S_IFREG,
                  info.st_uid == getuid(), info.st_nlink == 1, info.st_mode & 0o022 == 0,
                  fstatfs(fd, &filesystem) == 0, filesystem.f_flags & UInt32(MNT_LOCAL) != 0,
                  lstat(named, &again) == 0, same(info, again) else { throw Failure.guardFailed }
            var full = [CChar](repeating: 0, count: Int(MAXPATHLEN))
            guard fcntl(fd, F_GETPATH, &full) == 0 else { throw Failure.guardFailed }
            self.keychain = keychain; self.descriptor = fd; self.attributes = info
            self.canonical = String(cString: full); transferred = true
        }
        deinit { close(descriptor) }
        func validate(role: AnchorRole = .standalone) throws {
            var held = stat(), named = stat()
            let name = try path(keychain)
            // Same strict checks and short-circuit syscall order as before.
            // Categories reveal neither paths nor inode/UID values.
            try anchorCheck(fstat(descriptor, &held) == 0, role: role, failure: .heldStat)
            try anchorCheck(same(held, attributes), role: role, failure: .heldIdentity)
            try anchorCheck(held.st_nlink == 1, role: role, failure: .heldLink)
            try anchorCheck(lstat(name, &named) == 0, role: role, failure: .namedStat)
            try anchorCheck(same(held, named), role: role, failure: .namedIdentity)
            try anchorCheck(named.st_mode & S_IFMT == S_IFREG, role: role, failure: .namedRegular)
        }
        func matches(_ other: DefaultAnchor) throws -> Bool {
            try validate(role: .expected); try other.validate(role: .actual)
            return canonical == other.canonical && same(attributes, other.attributes)
        }
    }
    static func copyDefault() throws -> DefaultAnchor {
        var reference: SecKeychain?
        try status(.baseline) { SecKeychainCopyDefault(&reference) }
        guard let reference else { throw Failure.guardFailed }
        return try DefaultAnchor(reference)
    }
    static func requireDefault(_ expected: DefaultAnchor) throws {
        let actual = try copyDefault()
        try check(expected.matches(actual))
    }
    final class Root {
        let url: URL
        let descriptor: Int32
        let a: Int32
        let b: Int32
        private init(url: URL, descriptor: Int32, a: Int32, b: Int32) {
            self.url = url; self.descriptor = descriptor; self.a = a; self.b = b
        }
        deinit { close(a); close(b); close(descriptor) }
        static func open(_ text: String, fresh: Bool) throws -> Root {
            guard text.hasPrefix("/private/tmp/pp-default-keychain-vm-"),
                  !text.contains("/../"), !text.contains("/./") else { throw Failure.guardFailed }
            let url = URL(fileURLWithPath: text, isDirectory: true)
            let fd = Darwin.open(text, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard fd >= 0 else { throw Failure.guardFailed }
            var a: Int32 = -1, b: Int32 = -1, transferred = false
            defer { if !transferred { if a >= 0 { close(a) }; if b >= 0 { close(b) }; close(fd) } }
            try privateDirectory(fd)
            var full = [CChar](repeating: 0, count: Int(MAXPATHLEN))
            guard fcntl(fd, F_GETPATH, &full) == 0, String(cString: full) == text else { throw Failure.guardFailed }
            a = openat(fd, "A", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            b = openat(fd, "B", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard a >= 0, b >= 0 else { throw Failure.guardFailed }
            try privateDirectory(a); try privateDirectory(b)
            let root = Root(url: url, descriptor: fd, a: a, b: b); transferred = true
            try check(root.read("opt-in") == optIn)
            if fresh {
                try check(Set(FileManager.default.contentsOfDirectory(atPath: text)) == ["opt-in", "A", "B"])
                try check(FileManager.default.contentsOfDirectory(atPath: url.appendingPathComponent("A").path).isEmpty)
                try check(FileManager.default.contentsOfDirectory(atPath: url.appendingPathComponent("B").path).isEmpty)
            } else {
                try check(root.read("parent-ready") == "OWNED-CREATED-PRIVATE-TARGETS")
                try check(root.read("default-not-restored") == "OWNED-DEFAULT-LEASE")
            }
            return root
        }
        static func privateDirectory(_ fd: Int32) throws {
            var info = stat(), filesystem = statfs()
            guard fstat(fd, &info) == 0, info.st_mode & S_IFMT == S_IFDIR,
                  info.st_uid == getuid(), info.st_mode & 0o7777 == 0o700, info.st_nlink > 0,
                  fstatfs(fd, &filesystem) == 0, filesystem.f_flags & UInt32(MNT_LOCAL) != 0 else { throw Failure.guardFailed }
        }
        func absent(_ name: String) -> Bool {
            var info = stat(); return fstatat(descriptor, name, &info, AT_SYMLINK_NOFOLLOW) != 0 && errno == ENOENT
        }
        func writeNew(_ value: String, _ name: String) throws {
            let bytes = Data(value.utf8)
            guard bytes.count <= 128 else { throw Failure.guardFailed }
            let fd = openat(descriptor, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
            guard fd >= 0 else { throw Failure.guardFailed }; defer { close(fd) }
            try bytes.withUnsafeBytes { raw in
                guard Darwin.write(fd, raw.baseAddress, raw.count) == raw.count, fsync(fd) == 0,
                      fsync(descriptor) == 0 else { throw Failure.guardFailed }
            }
        }
        func read(_ name: String) throws -> String {
            let fd = openat(descriptor, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
            guard fd >= 0 else { throw Failure.guardFailed }; defer { close(fd) }
            var info = stat(); guard fstat(fd, &info) == 0, info.st_mode & S_IFMT == S_IFREG,
                info.st_uid == getuid(), info.st_nlink == 1, info.st_mode & 0o7777 == 0o600,
                info.st_size > 0, info.st_size <= 128 else { throw Failure.guardFailed }
            var bytes = [UInt8](repeating: 0, count: 129)
            let count = Darwin.read(fd, &bytes, bytes.count)
            guard count == info.st_size, let text = String(bytes: bytes.prefix(count), encoding: .utf8) else { throw Failure.guardFailed }
            return text
        }
        func remove(_ name: String) throws {
            _ = try read(name)
            guard unlinkat(descriptor, name, 0) == 0, fsync(descriptor) == 0 else { throw Failure.guardFailed }
        }
        func begin(_ step: Step) throws { try writeNew(step.rawValue, "unknown-rpc") }
        func definite(_ step: Step) throws {
            try check(read("unknown-rpc") == step.rawValue)
            try remove("unknown-rpc")
        }
    }
    struct Created {
        let anchor: DefaultAnchor
        let folder: URL
        let directory: Int32
        let target: VPNPrivateKeychainPathProof.Target
        let leaf: VPNPrivateKeychainPathProof.Leaf
    }
    static func create(_ root: Root, first: Bool) throws -> Created {
        let target: VPNPrivateKeychainPathProof.Target = first ? .first : .second
        let folder = root.url.appendingPathComponent(first ? "A" : "B")
        let directory = first ? root.a : root.b
        var info = stat()
        guard fstatat(directory, target.base.rawValue, &info, AT_SYMLINK_NOFOLLOW) != 0, errno == ENOENT,
              fstatat(directory, target.db.rawValue, &info, AT_SYMLINK_NOFOLLOW) != 0, errno == ENOENT else { throw Failure.guardFailed }
        let step: Step = first ? .createA : .createB
        try root.begin(step)
        var reference: SecKeychain?
        let password = Data("fresh-disposable-only-password".utf8)
        let code = password.withUnsafeBytes {
            SecKeychainCreate(folder.appendingPathComponent(target.base.rawValue).path, UInt32($0.count), $0.baseAddress, false, nil, &reference)
        }
        evidence(step, code)
        guard code == errSecSuccess, let reference else { throw Failure.apiFailed }
        let proof = VPNPrivateKeychainPathProof.inspect(actual: try path(reference), directory: directory, target: target)
        guard proof.accepted, let leaf = proof.leaf, let expected = proof.attributes else { throw Failure.guardFailed }
        let fd = openat(directory, leaf.rawValue, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard fd >= 0 else { throw Failure.guardFailed }; defer { close(fd) }
        guard fstat(fd, &info) == 0, same(info, expected), fchmod(fd, 0o600) == 0 else { throw Failure.guardFailed }
        let anchor = try DefaultAnchor(reference)
        try root.definite(step)
        return Created(anchor: anchor, folder: folder, directory: directory, target: target, leaf: leaf)
    }
    static func prove(_ locator: VPNPasswordItemLocator, _ created: Created) throws {
        try locator.validate()
        let proof = VPNPrivateKeychainPathProof.inspect(actual: locator.origin.path, directory: created.directory,
            target: created.target, requiredLeaf: created.leaf)
        guard proof.accepted, let info = proof.attributes else { throw Failure.guardFailed }
        try check(locator.origin.device == UInt64(UInt32(bitPattern: info.st_dev)) && locator.origin.inode == UInt64(info.st_ino)
            && locator.origin.ownerUID == info.st_uid && locator.origin.birthSeconds == Int64(info.st_birthtimespec.tv_sec)
            && locator.origin.birthNanoseconds == UInt32(info.st_birthtimespec.tv_nsec))
    }
    static func setDefault(_ root: Root, target: DefaultAnchor, expected: DefaultAnchor, step: Step) throws {
        try trace(step, .targetAnchor) { try target.validate(role: .target) }
        try trace(step, .expectedDefault) { try requireDefault(expected) }
        try trace(step, .begin) { try root.begin(step) }
        try trace(step, .setAPI) { try status(step) { SecKeychainSetDefault(target.keychain) } }
        try trace(step, .resultDefault) { try requireDefault(target) }
        try trace(step, .definite) { try root.definite(step) }
    }
    static func joinChildren() throws {
        let deadline = DispatchTime.now().uptimeNanoseconds + 7_000_000_000
        repeat {
            var status: Int32 = 0
            let result = waitpid(-1, &status, WNOHANG)
            if result < 0, errno == ECHILD { return }
            guard result >= 0 else { throw Failure.checkFailed }
            usleep(10_000)
        } while DispatchTime.now().uptimeNanoseconds < deadline
        throw Failure.ambiguous
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
        var configuration = VPNConfiguration(); try configuration.setProfile(name: profile.name)
        try configuration.saveResource(VPNResource(address: "10.20.0.0/16"))
        try configuration.setAuthentication(VPNAuthentication(mode: .password, login: "synthetic", credentialPersistence: .keychain))
        _ = try store.save(configuration, importing: profile, expectedRevision: nil)
        let reference = try store.grantPasswordPersistence(expectedRevision: configuration.revision)
        return (store, reference, configuration.revision)
    }
    static func revoke(_ store: VPNStore) throws {
        guard let state = try store.load() else { throw Failure.checkFailed }
        var configuration = state.saved.configuration
        try configuration.setAuthentication(VPNAuthentication(mode: .password, login: "synthetic"))
        _ = try store.save(configuration, expectedRevision: state.saved.configuration.revision)
    }
    static func read(_ store: VPNStore, reference: VPNPasswordReference, revision: UInt64, expected: Data) throws {
        var result = try VPNPasswordWorkerSession.prepare(store: store).read(store: store, reference: reference, revision: revision)
        defer { if result != nil { VPNPasswordWorkerWire.clear(&result!) } }
        try check(result == expected)
        try joinChildren()
    }
    static func add(_ root: Root, _ store: VPNStore, reference: VPNPasswordReference, revision: UInt64,
                    secret: Data, target: Created, step: Step) throws -> VPNPasswordItemLocator {
        try trace(step, .requireDefault) { try requireDefault(target.anchor) }
        let session = try trace(step, .prepare) { try VPNPasswordWorkerSession.prepare(store: store) }
        try trace(step, .begin) { try root.begin(step) }
        var bytes = secret
        defer { VPNPasswordWorkerWire.clear(&bytes) }
        let result = try trace(step, .dispatch) {
            try session.addOnce(store: store, reference: reference, revision: revision, secret: &bytes)
        }
        let locator = try trace(step, .locatorProof) { () throws -> VPNPasswordItemLocator in
            guard case .added(let locator) = result else { throw Failure.ambiguous }
            try prove(locator, target); return locator
        }
        try trace(step, .children) { try joinChildren() }
        try trace(step, .ledger) { try check(store.load()?.passwordLedger.active?.locator == locator) }
        try trace(step, .definite) { try root.definite(step) }
        return locator
    }
    static func delete(_ root: Root, _ store: VPNStore, reference: VPNPasswordReference, step: Step) throws {
        let session = try VPNPasswordWorkerSession.prepare(store: store)
        try root.begin(step)
        guard try session.deletePendingOutcome(store: store, reference: reference) == .deleted else { throw Failure.ambiguous }
        try joinChildren()
        try check(store.load()?.passwordLedger.pendingDeletion.contains(where: { $0.reference == reference }) == false)
        try root.definite(step)
    }
    static func remove(_ root: Root, _ target: Created, step: Step) throws {
        try check(root.absent("unknown-rpc") && root.absent("default-not-restored"))
        try joinChildren(); try target.anchor.validate()
        try root.begin(step)
        try status(step) { SecKeychainDelete(target.anchor.keychain) }
        var info = stat()
        guard fstatat(target.directory, target.target.base.rawValue, &info, AT_SYMLINK_NOFOLLOW) != 0, errno == ENOENT,
              fstatat(target.directory, target.target.db.rawValue, &info, AT_SYMLINK_NOFOLLOW) != 0, errno == ENOENT else { throw Failure.guardFailed }
        try root.definite(step)
    }
    static func existing(_ root: Root) throws -> (VPNStore, VPNPasswordReference, UInt64) {
        let store = VPNStore(directory: root.url.appendingPathComponent("StoreA"))
        guard let state = try store.load() else { throw Failure.guardFailed }
        let reference = state.passwordLedger.active?.reference ?? state.passwordLedger.pendingDeletion.first?.reference
        guard let reference, reference.login == "synthetic" else { throw Failure.guardFailed }
        return (store, reference, state.saved.configuration.revision)
    }
    static func otherRead(_ root: Root) throws {
        let (store, reference, revision) = try existing(root)
        guard let slot = try store.load()?.passwordLedger.active, slot.reference == reference, slot.locator != nil else { throw Failure.guardFailed }
        var response = try VPNPasswordWorker.prepare(store: store).read(store: store, reference: reference, revision: revision)
        defer { VPNPasswordWorkerWire.clear(&response.secret) }
        try response.validate(operation: .read)
        try check(response.status != .indeterminate)
        let allowed = response.status == .success
        if allowed { try check(response.secret == secretA) }
        try joinChildren()
        var adapted = try VPNPasswordWorkerSession.prepare(store: store).read(store: store, reference: reference, revision: revision)
        defer { if adapted != nil { VPNPasswordWorkerWire.clear(&adapted!) } }
        if allowed { try check(adapted == secretA) } else { try check(adapted == nil) }
        try joinChildren()
        try root.writeNew(allowed ? OtherRead.allowed.rawValue : OtherRead.fallback.rawValue, "other-read-outcome")
    }
    static func otherDelete(_ root: Root) throws -> Int32 {
        let (store, reference, _) = try existing(root)
        guard let slot = try store.load()?.passwordLedger.pendingDeletion.first(where: { $0.reference == reference }), slot.locator != nil else { throw Failure.guardFailed }
        let session = try VPNPasswordWorkerSession.prepare(store: store)
        try root.begin(.otherDelete)
        let result = try session.deletePendingOutcome(store: store, reference: reference)
        try joinChildren()
        switch result {
        case .deleted:
            try check(store.load()?.passwordLedger.pendingDeletion.contains(where: { $0.reference == reference }) == false)
            try root.definite(.otherDelete); try root.writeNew(OtherDelete.deleted.rawValue, "other-delete-outcome"); return 0
        case .unavailable:
            // The genuine backend emits unavailable only before its Delete API.
            // Generic post-API statuses map to indeterminate, never unavailable.
            try check(store.load()?.passwordLedger.pendingDeletion.contains(where: { $0 == slot }) == true)
            try root.definite(.otherDelete); try root.writeNew(OtherDelete.unavailable.rawValue, "other-delete-outcome"); return 0
        case .notFound, .indeterminate:
            try check(store.load()?.passwordLedger.pendingDeletion.contains(where: { $0 == slot }) == true)
            try root.writeNew(result == .notFound ? OtherDelete.notFound.rawValue : OtherDelete.indeterminate.rawValue, "other-delete-outcome")
            return 75
        }
    }
    static func runOther(_ root: Root, image: String, action: String, accepted: Set<Int32>) throws -> Int32 {
        guard image.hasPrefix("/"), image.hasSuffix("/Contents/MacOS/ProxyPilot") else { throw Failure.guardFailed }
        let process = Process(); process.executableURL = URL(fileURLWithPath: image)
        process.arguments = [argument, action, root.url.path, "unused"]
        process.environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "GITHUB_ACTIONS": "true", "PROXYPILOT_VM_DEFAULT_KEYCHAIN_TESTS": "1"]
        process.standardInput = FileHandle.nullDevice; process.standardOutput = FileHandle.nullDevice; process.standardError = FileHandle.nullDevice
        try process.run(); process.waitUntilExit()
        try check(process.terminationReason == .exit && accepted.contains(process.terminationStatus))
        try joinChildren()
        return process.terminationStatus
    }
    static func runFresh(_ root: Root, action: String, otherImage: String) throws -> Int32 {
        // Hold this exact prior default; absence/invalid identity refuses before
        // Create/SetDefault. No search-list or unrelated item query is made.
        let original = try copyDefault()
        let first = try create(root, first: true)
        let second = try create(root, first: false)
        let (storeA, reference, revision) = try seed(root.url.appendingPathComponent("StoreA"))
        // Clone the NOT-ISSUED grant before either Add. Separate private stores
        // intentionally authorize identical accounts in separate keychains.
        try FileManager.default.copyItem(at: storeA.directory, to: root.url.appendingPathComponent("StoreB"))
        let storeB = VPNStore(directory: root.url.appendingPathComponent("StoreB"))
        try check(storeB.load()?.passwordLedger.active?.reference == reference)
        try root.writeNew("OWNED-DEFAULT-LEASE", "default-not-restored")
        try setDefault(root, target: first.anchor, expected: original, step: .setA)
        let locatorA = try add(root, storeA, reference: reference, revision: revision, secret: secretA, target: first, step: .addA)
        try setDefault(root, target: second.anchor, expected: first.anchor, step: .setB)
        let locatorB = try add(root, storeB, reference: reference, revision: revision, secret: secretB, target: second, step: .addB)
        try check(locatorA.origin != locatorB.origin)
        try read(storeA, reference: reference, revision: revision, expected: secretA)
        if action == "crossrelease" {
            try root.writeNew("OWNED-CREATED-PRIVATE-TARGETS", "parent-ready")
            _ = try runOther(root, image: otherImage, action: "other-read", accepted: [0])
            let outcome = try root.read("other-read-outcome")
            try check(OtherRead(rawValue: outcome) != nil)
            print("default-keychain-vm:cross-read=" + outcome)
            // Positive C read BEFORE D deletion distinguishes ACL denial from
            // a missing/replaced item. Never silently Add a replacement.
            try read(storeA, reference: reference, revision: revision, expected: secretA)
            try revoke(storeA)
            let exit = try runOther(root, image: otherImage, action: "other-delete", accepted: [0, 75])
            let deletion = try root.read("other-delete-outcome")
            if exit == 75 {
                try check(deletion == OtherDelete.notFound.rawValue || deletion == OtherDelete.indeterminate.rawValue)
                try check(root.read("unknown-rpc") == Step.otherDelete.rawValue)
                try root.writeNew("EXPECTED-UNKNOWN-PRESERVED", "preserved-unknown")
                print("default-keychain-vm:outcome=preserved-unknown")
                return 0 // NO restore, Delete, file removal or positive-clean claim.
            }
            if deletion == OtherDelete.unavailable.rawValue {
                try check(storeA.load()?.passwordLedger.pendingDeletion.count == 1)
                try delete(root, storeA, reference: reference, step: .deleteA)
                print("default-keychain-vm:cross-delete=unavailable-retained")
            } else { try check(deletion == OtherDelete.deleted.rawValue); print("default-keychain-vm:cross-delete=positive") }
        } else {
            try revoke(storeA)
            try delete(root, storeA, reference: reference, step: .deleteA)
        }
        try read(storeB, reference: reference, revision: revision, expected: secretB)
        try revoke(storeB); try delete(root, storeB, reference: reference, step: .deleteB)
        try joinChildren()
        try setDefault(root, target: original, expected: second.anchor, step: .restore)
        try root.remove("default-not-restored")
        try requireDefault(original)
        try remove(root, second, step: .removeB); try remove(root, first, step: .removeA)
        try check(root.absent("unknown-rpc") && root.absent("default-not-restored"))
        try root.writeNew("POSITIVE-RESTORED-AND-DELETED", "complete")
        print("default-keychain-vm:outcome=restored-and-clean")
        return 0
    }
}
