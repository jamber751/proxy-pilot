import Darwin
import Dispatch
import Foundation

/// Compile-time synthetic backend only. Never calls a Keychain/UI-setting API.
private struct FakePasswordBackend: VPNPasswordWorkerBackend {
    let directory: Int32
    var available: Bool { behavior() != "unavailable" }
    private func behavior() -> String {
        let fd = openat(directory, "behavior", O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { return "normal" }; defer { close(fd) }
        var bytes = [UInt8](repeating: 0, count: 64)
        let count = read(fd, &bytes, bytes.count)
        return count > 0 ? String(decoding: bytes.prefix(count), as: UTF8.self) : "normal"
    }
    fileprivate func locator(_ reference: VPNPasswordReference, descriptor: Int32) throws -> VPNPasswordItemLocator {
        var info = stat()
        guard fstat(descriptor, &info) == 0, info.st_mode & S_IFMT == S_IFREG,
              info.st_uid == geteuid(), info.st_nlink == 1, info.st_mode & 0o777 == 0o600 else {
            throw VPNPasswordWorkerError.unavailable
        }
        var path = [CChar](repeating: 0, count: Int(MAXPATHLEN))
        guard fcntl(directory, F_GETPATH, &path) == 0 else { throw VPNPasswordWorkerError.unavailable }
        let result = VPNPasswordItemLocator(persistentReference: Data(reference.itemID.uuidString.utf8),
            origin: .init(kind: .legacyKeychain,
                path: String(cString: path) + "/item-" + reference.itemID.uuidString,
                device: UInt64(UInt32(bitPattern: info.st_dev)), inode: UInt64(info.st_ino),
                ownerUID: info.st_uid, birthSeconds: Int64(info.st_birthtimespec.tv_sec),
                birthNanoseconds: UInt32(info.st_birthtimespec.tv_nsec)))
        try result.validate(); return result
    }
    func execute(_ request: inout VPNPasswordWorkerWire.Request) throws -> VPNPasswordWorkerWire.Response {
        if behavior() == "noio", request.metadata.operation == .add {
            return .init(status: .definitelyNoIO, secret: Data())
        }
        let event = openat(directory, "events", O_WRONLY | O_APPEND | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard event >= 0 else { throw VPNPasswordWorkerError.unavailable }
        let label = Data((request.metadata.operation.rawValue + "\n").utf8)
        _ = label.withUnsafeBytes { write(event, $0.baseAddress, $0.count) }; close(event)
        if behavior() == "delay" || behavior() == "mutate-request" { usleep(400_000) }
        if behavior() == "wait-release" || behavior() == "delete-wait-release" {
            let deadline = DispatchTime.now().uptimeNanoseconds
                + (behavior() == "delete-wait-release" ? 7_000_000_000 : 3_000_000_000)
            var info = stat()
            while fstatat(directory, "release", &info, AT_SYMLINK_NOFOLLOW) != 0, DispatchTime.now().uptimeNanoseconds < deadline { usleep(1000) }
            guard fstatat(directory, "release", &info, AT_SYMLINK_NOFOLLOW) == 0 else {
                return .init(status: .failed, secret: Data())
            }
        }
        if behavior() == "crash" { _exit(71) }
        if behavior() == "denied" { return .init(status: .denied, secret: Data()) }
        if behavior() == "delete-unavailable", request.metadata.operation == .delete {
            return .init(status: .unavailable, secret: Data())
        }
        let name = "item-" + request.metadata.reference.itemID.uuidString
        switch request.metadata.operation {
        case .add:
            let fd = openat(directory, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
            guard fd >= 0 else { return .init(status: .failed, secret: Data()) }; defer { close(fd) }
            let n = request.secret.withUnsafeBytes { write(fd, $0.baseAddress, $0.count) }
            if behavior() == "commit-crash" { _exit(72) }
            guard n == request.secret.count else { return .init(status: .failed, secret: Data()) }
            if behavior() == "missing-locator" { return .init(status: .success, secret: Data()) }
            var captured = try locator(request.metadata.reference, descriptor: fd)
            if behavior() == "invalid-locator" {
                captured = .init(persistentReference: Data(), origin: captured.origin)
            }
            if behavior() == "mutate-request" {
                let original = request.metadata
                VPNPasswordWorkerWire.clear(&request.secret)
                request = .init(metadata: .init(operation: .add,
                    reference: .init(itemID: UUID(), profileSHA256: original.reference.profileSHA256,
                                     login: original.reference.login), revision: original.revision), secret: Data())
            }
            return .init(status: .success, secret: Data(), locator: captured)
        case .read:
            let fd = openat(directory, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
            guard fd >= 0 else { return .init(status: .notFound, secret: Data()) }; defer { close(fd) }
            guard request.metadata.locator == (try locator(request.metadata.reference, descriptor: fd)) else {
                return .init(status: .denied, secret: Data())
            }
            var bytes = [UInt8](repeating: 0, count: VPNPasswordWorkerWire.maximumSecretBytes)
            let n = read(fd, &bytes, bytes.count)
            defer { bytes.withUnsafeMutableBytes { _ = memset_s($0.baseAddress, $0.count, 0, $0.count) } }
            guard n > 0 else { return .init(status: .failed, secret: Data()) }
            return .init(status: .success, secret: Data(bytes.prefix(n)))
        case .delete:
            let fd = openat(directory, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
            guard fd >= 0 else { return .init(status: errno == ENOENT ? .notFound : .failed, secret: Data()) }
            defer { close(fd) }
            guard request.metadata.locator == (try locator(request.metadata.reference, descriptor: fd)) else {
                return .init(status: .denied, secret: Data())
            }
            let result = unlinkat(directory, name, 0)
            return .init(status: result == 0 ? .success : (errno == ENOENT ? .notFound : .failed), secret: Data())
        }
    }
}

@main enum VPNPasswordWorkerChecks {
    enum Failure: Error { case check }
    static func check(_ condition: @autoclosure () throws -> Bool) throws {
        guard try condition() else { throw Failure.check }
    }
    static func rejects(_ action: () throws -> Void) throws {
        do { try action() } catch { return }; throw Failure.check
    }
    static func wait(_ predicate: () throws -> Bool) throws {
        let deadline = DispatchTime.now().uptimeNanoseconds + 7_000_000_000
        repeat {
            do { if try predicate() { return } }
            catch VPNValidationError.storageUnavailable { /* Observer raced a legitimate Store writer. */ }
            // No producer retry, deadline renewal, or swallowing other errors.
            usleep(20_000)
        } while DispatchTime.now().uptimeNanoseconds < deadline
        throw Failure.check
    }
    static func joinOwnChildren() throws {
        try wait {
            var status: Int32 = 0
            let result = waitpid(-1, &status, WNOHANG)
            if result > 0 { return false }
            if result < 0, errno == ECHILD { return true }
            guard result == 0 else { throw Failure.check }
            return false
        }
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
    static func events(_ folder: URL) -> [String] {
        let data = (try? String(contentsOf: folder.appendingPathComponent("events"), encoding: .utf8)) ?? ""
        return data.split(separator: "\n").map(String.init)
    }
    static func revoke(_ store: VPNStore) throws {
        let state = try store.load()!; var config = state.saved.configuration
        try config.setAuthentication(VPNAuthentication(mode: .password, login: "synthetic"))
        _ = try store.save(config, expectedRevision: state.saved.configuration.revision)
    }
    static func fakeLocator(_ folder: URL, reference: VPNPasswordReference) throws -> VPNPasswordItemLocator {
        let directory = open(folder.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard directory >= 0 else { throw Failure.check }; defer { close(directory) }
        let item = openat(directory, "item-" + reference.itemID.uuidString, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard item >= 0 else { throw Failure.check }; defer { close(item) }
        return try FakePasswordBackend(directory: directory).locator(reference, descriptor: item)
    }
    static func main() throws {
        if let status = VPNPasswordWorker.testRunIfRequested(arguments: CommandLine.arguments,
                backend: { FakePasswordBackend(directory: $0) }) { exit(status) }
        guard getuid() == geteuid(), getuid() >= 500 else { exit(77) }
        let args = CommandLine.arguments; guard args.count >= 3 else { exit(64) }
        #if DIFFERENT_WORKER_BUILD
        if args[1] == "marker" { print("different-code"); return }
        #else
        if args[1] == "marker" { print("original-code"); return }
        #endif
        let folder = URL(fileURLWithPath: args[2], isDirectory: true)
        let (store, reference, revision) = try seed(folder)
        switch args[1] {
        case "wire-invalid":
            let locator = VPNPasswordItemLocator(persistentReference: Data([1]), origin: .init(kind: .legacyKeychain,
                path: "/synthetic/item", device: 1, inode: 1, ownerUID: getuid(), birthSeconds: 0, birthNanoseconds: 0))
            let nonce = Data(repeating: 0, count: VPNPasswordWorkerWire.nonceBytes)
            let invalid = VPNPasswordItemLocator(persistentReference: Data(), origin: locator.origin)
            for operation in [VPNPasswordWorkerOperation.read, .delete] {
                try rejects { _ = try VPNPasswordWorkerWire.Metadata(operation: operation, reference: reference, revision: revision).encoded() }
                try rejects { _ = try VPNPasswordWorkerWire.Metadata(operation: operation, reference: reference, revision: revision, locator: invalid).encoded() }
                try rejects { _ = try VPNPasswordWorkerWire.response(.init(status: .definitelyNoIO, secret: Data()), nonce: nonce, operation: operation) }
            }
            try rejects { _ = try VPNPasswordWorkerWire.Metadata(operation: .add, reference: reference, revision: revision, locator: locator).encoded() }
            for captured in [nil, invalid] as [VPNPasswordItemLocator?] {
                let response = VPNPasswordWorkerWire.Response(status: .success, secret: Data(), locator: captured)
                try check(response.addOutcome == .indeterminate)
                try rejects { _ = try VPNPasswordWorkerWire.response(response, nonce: nonce, operation: .add) }
            }
            for status in [VPNPasswordWorkerStatus.failed, .denied, .unavailable, .notFound, .indeterminate] {
                let response = VPNPasswordWorkerWire.Response(status: status, secret: Data())
                try check(response.addOutcome == .indeterminate)
                try rejects { _ = try VPNPasswordWorkerWire.response(.init(status: status, secret: Data(), locator: locator), nonce: nonce, operation: .add) }
            }
            try rejects { _ = try VPNPasswordWorkerWire.response(.init(status: .success, secret: Data("secret".utf8)), nonce: nonce, operation: .add) }
            try rejects { _ = try VPNPasswordWorkerWire.response(.init(status: .success, secret: Data("secret".utf8), locator: locator), nonce: nonce, operation: .read) }
            var old = try VPNPasswordWorkerWire.request(.init(metadata: .init(operation: .add,
                reference: reference, revision: revision), secret: Data("secret".utf8)), nonce: nonce)
            old.replaceSubrange(0..<8, with: Data("PPPWGO01".utf8))
            try rejects { _ = try VPNPasswordWorkerWire.decodeRequest(old, nonce: nonce) }
            var response = try VPNPasswordWorkerWire.response(.init(status: .success, secret: Data(), locator: locator), nonce: nonce, operation: .add)
            response.replaceSubrange(0..<8, with: Data("PPPWRS01".utf8))
            try rejects { _ = try VPNPasswordWorkerWire.decodeResponse(response, nonce: nonce, operation: .add) }
        case "missing-locator", "invalid-locator", "generic-denied", "noio":
            let behavior = args[1] == "generic-denied" ? "denied" : args[1]
            try Data(behavior.utf8).write(to: folder.appendingPathComponent("behavior"))
            var secret = Data("synthetic-password".utf8)
            let outcome = try VPNPasswordWorker.prepare(store: store).addOnce(store: store,
                reference: reference, revision: revision, secret: &secret)
            try joinOwnChildren()
            try check(secret.isEmpty)
            let slot = try store.load()!.passwordLedger.active!
            if args[1] == "noio" {
                try check(outcome == .definitelyNoIO && slot.writeState == .noItem && slot.locator == nil && events(folder).isEmpty)
            } else {
                try check(outcome == .indeterminate && slot.writeState == .pending && slot.locator == nil && events(folder) == ["add"])
            }
            var again = Data("synthetic-password".utf8)
            try rejects { _ = try VPNPasswordWorker.prepare(store: store).addOnce(store: store,
                reference: reference, revision: revision, secret: &again) }
            try check(again.isEmpty && events(folder).filter { $0 == "add" }.count == (args[1] == "noio" ? 0 : 1))
        case "stale-read":
            var secret = Data("synthetic-password".utf8)
            _ = try VPNPasswordWorker.prepare(store: store).addOnce(store: store, reference: reference, revision: revision, secret: &secret)
            try joinOwnChildren()
            let captured = try store.load()!.passwordLedger.active!.locator!
            let path = folder.appendingPathComponent("item-" + reference.itemID.uuidString)
            try FileManager.default.removeItem(at: path)
            try Data("other-item".utf8).write(to: path)
            guard chmod(path.path, 0o600) == 0 else { throw Failure.check }
            let actual = try fakeLocator(folder, reference: reference)
            try check(actual != captured)
            let read = try VPNPasswordWorker.prepare(store: store).read(store: store, reference: reference, revision: revision)
            try joinOwnChildren()
            try check(read.status == .denied && read.secret.isEmpty && store.load()!.passwordLedger.active?.locator == captured)
            try check(events(folder) == ["add", "read"])
        case "late-delete", "changed-delete-locator":
            var secret = Data("synthetic-password".utf8)
            _ = try VPNPasswordWorker.prepare(store: store).addOnce(store: store, reference: reference, revision: revision, secret: &secret)
            try joinOwnChildren(); try revoke(store)
            try Data("wait-release".utf8).write(to: folder.appendingPathComponent("behavior"))
            let worker = try VPNPasswordWorker.prepare(store: store)
            try rejects {
                try store.deletePendingPassword(reference: reference) { _, locator in
                    var empty = Data()
                    let response = try worker.testPerform(operation: .delete, reference: reference, revision: revision,
                        secret: &empty, timeout: 30_000_000, locator: locator)
                    try check(response.status == .indeterminate)
                    return .indeterminate
                }
            }
            var changed: VPNPasswordItemLocator?
            if args[1] == "changed-delete-locator" {
                let other = VPNPasswordReference(itemID: UUID(), profileSHA256: reference.profileSHA256, login: reference.login)
                let file = folder.appendingPathComponent("item-" + other.itemID.uuidString)
                try Data("other-item".utf8).write(to: file)
                guard chmod(file.path, 0o600) == 0 else { throw Failure.check }
                changed = try fakeLocator(folder, reference: other)
                let state = try store.load()!; var ledger = state.passwordLedger
                ledger.pendingDeletion[0].locator = changed
                let replacement = VPNStoredState(saved: state.saved, applied: state.applied, passwordLedger: ledger)
                let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
                try encoder.encode(replacement).write(to: folder.appendingPathComponent("state.json"), options: .atomic)
                guard chmod(folder.appendingPathComponent("state.json").path, 0o600) == 0 else { throw Failure.check }
            }
            try Data().write(to: folder.appendingPathComponent("release"))
            try joinOwnChildren()
            let state = try store.load()!
            if let changed {
                try check(state.passwordLedger.pendingDeletion.count == 1 && state.passwordLedger.pendingDeletion[0].locator == changed)
            } else { try check(state.passwordLedger.pendingDeletion.isEmpty) }
            try check(!FileManager.default.fileExists(atPath: folder.appendingPathComponent("item-" + reference.itemID.uuidString).path))
            try check(events(folder) == ["add", "delete"])
        case "wire-bounds":
            let origin = VPNPasswordBackendLocator(kind: .legacyKeychain,
                path: "/" + String(repeating: "\\\"", count: 511),
                device: UInt64(UInt32.max), inode: UInt64.max, ownerUID: UInt32.max - 1,
                birthSeconds: Int64.max, birthNanoseconds: 999_999_999)
            let locator = VPNPasswordItemLocator(persistentReference: Data(repeating: 255, count: 4096), origin: origin)
            try locator.validate()
            let longReference = VPNPasswordReference(itemID: UUID(), profileSHA256: String(repeating: "f", count: 64),
                login: String(repeating: "\"", count: 255))
            let metadata = VPNPasswordWorkerWire.Metadata(operation: .read, reference: longReference,
                revision: UInt64.max, locator: locator)
            let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
            let measured = try encoder.encode(metadata).count
            print("wire-bound-metadata=\(measured)")
            try check(measured > 8192 && measured <= VPNPasswordWorkerWire.maximumMetadataBytes)
            let nonce = Data(repeating: 0, count: VPNPasswordWorkerWire.nonceBytes)
            let request = try VPNPasswordWorkerWire.request(.init(metadata: metadata, secret: Data()), nonce: nonce)
            try check(request.count < VPNPasswordWorkerWire.maximumFrameBytes)
            try check(VPNPasswordWorkerWire.decodeRequest(request, nonce: nonce).metadata == metadata)
            let response = try VPNPasswordWorkerWire.response(.init(status: .success, secret: Data(), locator: locator),
                nonce: nonce, operation: .add)
            try check(VPNPasswordWorkerWire.decodeResponse(response, nonce: nonce, operation: .add).locator == locator)
        case "observer":
            var attempts = 0
            try wait {
                attempts += 1
                if attempts < 3 { throw VPNValidationError.storageUnavailable }
                return true
            }
            try check(attempts == 3)
            attempts = 0
            do {
                try wait { attempts += 1; throw VPNValidationError.invalidConfiguration }
                throw Failure.check
            } catch VPNValidationError.invalidConfiguration { }
            try check(attempts == 1)
        case "roundtrip":
            let worker = try VPNPasswordWorker.prepare(store: store)
            var secret = Data("synthetic-static-password".utf8)
            let outcome = try worker.addOnce(store: store, reference: reference, revision: revision, secret: &secret)
            guard case .added(let captured) = outcome else { throw Failure.check }
            try captured.validate()
            // A successful response is sent before the child's final Store
            // observation. Join it before starting the next independent op.
            try joinOwnChildren()
            try check(secret.isEmpty && store.load()!.passwordLedger.active?.writeState == .settled &&
                store.load()!.passwordLedger.active?.locator == captured)
            var again = Data("synthetic-static-password".utf8)
            try rejects { _ = try worker.addOnce(store: store, reference: reference, revision: revision, secret: &again) }
            var read = try VPNPasswordWorker.prepare(store: store).read(store: store, reference: reference, revision: revision)
            try check(read.status == .success && read.secret == Data("synthetic-static-password".utf8))
            VPNPasswordWorkerWire.clear(&read.secret)
            try joinOwnChildren()
            try revoke(store)
            try VPNPasswordWorker.prepare(store: store).deletePending(store: store, reference: reference)
            try joinOwnChildren()
            try check(store.load()!.passwordLedger.pendingDeletion.isEmpty && events(folder) == ["add", "read", "delete"])
        case "before-go":
            var worker: VPNPasswordWorker.Prepared? = try VPNPasswordWorker.prepare(store: store)
            try check(worker != nil); worker = nil
            usleep(80_000)
            try check(events(folder).isEmpty && store.load()!.passwordLedger.active?.writeState == .notIssued)
        case "truncated":
            let worker = try VPNPasswordWorker.prepare(store: store)
            try worker.testTruncatedGO(); usleep(100_000)
            try check(events(folder).isEmpty)
        case "wrong-nonce":
            let worker = try VPNPasswordWorker.prepare(store: store)
            try worker.testWrongNonceGO(reference: reference, revision: revision)
            usleep(100_000)
            try check(events(folder).isEmpty)
        case "replay":
            try Data("delay".utf8).write(to: folder.appendingPathComponent("behavior"))
            let worker = try VPNPasswordWorker.prepare(store: store)
            var secret = Data("synthetic-password".utf8)
            let result = try store.addPasswordOnce(reference: reference, expectedRevision: revision) { _ in
                let response = try worker.testReplayGO(reference: reference, revision: revision, secret: &secret)
                return response.addOutcome
            }
            guard case .added = result else { throw Failure.check }
            try check(secret.isEmpty && events(folder) == ["add"])
        case "unavailable":
            try Data("unavailable".utf8).write(to: folder.appendingPathComponent("behavior"))
            do { _ = try VPNPasswordWorker.prepare(store: store); throw Failure.check }
            catch VPNPasswordWorkerError.unavailable { }
            try check(events(folder).isEmpty && store.load()!.passwordLedger.active?.writeState == .notIssued)
        case "wrong-peer":
            guard args.count == 4 else { exit(64) }
            try rejects { _ = try VPNPasswordWorker.testPrepare(store: store, executableOverride: args[3]) }
            try check(events(folder).isEmpty)
        case "foreign-store":
            let other = folder.appendingPathComponent("Other", isDirectory: true)
            let (otherStore, otherRef, otherRevision) = try seed(other)
            let worker = try VPNPasswordWorker.prepare(store: store)
            var secret = Data("synthetic-password".utf8)
            try rejects { _ = try worker.addOnce(store: otherStore, reference: otherRef, revision: otherRevision, secret: &secret) }
            try check(secret.isEmpty && otherStore.load()!.passwordLedger.active?.writeState == .notIssued && events(folder).isEmpty)
        case "not-found-delete":
            var secret = Data("synthetic-password".utf8)
            _ = try VPNPasswordWorker.prepare(store: store).addOnce(store: store, reference: reference, revision: revision, secret: &secret)
            try joinOwnChildren()
            try FileManager.default.removeItem(at: folder.appendingPathComponent("item-" + reference.itemID.uuidString))
            try revoke(store)
            try rejects { try VPNPasswordWorker.prepare(store: store).deletePending(store: store, reference: reference) }
            usleep(100_000)
            try check(store.load()!.passwordLedger.pendingDeletion.count == 1)
        case "typed-delete-pending", "typed-delete-unissued":
            if args[1] == "typed-delete-pending" {
                _ = try store.addPasswordOnce(reference: reference, expectedRevision: revision) { _ in .indeterminate }
            }
            try revoke(store)
            var worker: VPNPasswordWorker.Prepared? = try VPNPasswordWorker.prepare(store: store)
            if args[1] == "typed-delete-pending" {
                try rejects { _ = try worker!.deletePendingOutcome(store: store, reference: reference) }
                try check(store.load()!.passwordLedger.pendingDeletion.count == 1)
            } else {
                // Current Store retires an unissued grant directly on revoke;
                // a stale request must not issue GO or invent an item to delete.
                try rejects { _ = try worker!.deletePendingOutcome(store: store, reference: reference) }
                try check(store.load()!.passwordLedger.pendingDeletion.isEmpty)
            }
            worker = nil
            try joinOwnChildren()
            try check(events(folder).isEmpty)
        case "typed-delete", "typed-delete-not-found", "typed-delete-unavailable", "typed-delete-unknown",
             "typed-delete-write-error", "typed-delete-late":
            var secret = Data("synthetic-password".utf8)
            _ = try VPNPasswordWorker.prepare(store: store).addOnce(store: store, reference: reference, revision: revision, secret: &secret)
            try joinOwnChildren(); try revoke(store)
            let item = folder.appendingPathComponent("item-" + reference.itemID.uuidString)
            switch args[1] {
            case "typed-delete-not-found": try FileManager.default.removeItem(at: item)
            case "typed-delete-unavailable": try Data("delete-unavailable".utf8).write(to: folder.appendingPathComponent("behavior"))
            case "typed-delete-unknown": try Data("crash".utf8).write(to: folder.appendingPathComponent("behavior"))
            case "typed-delete-late": try Data("delete-wait-release".utf8).write(to: folder.appendingPathComponent("behavior"))
            default: break
            }
            let before = try Data(contentsOf: folder.appendingPathComponent("state.json"))
            let worker = try VPNPasswordWorker.prepare(store: store)
            if args[1] == "typed-delete-write-error" {
                store.testRejectNextWriteAfterRename = true
                try rejects { _ = try worker.deletePendingOutcome(store: store, reference: reference) }
                try joinOwnChildren()
                // Positive API result is not returned as .deleted when Store
                // reports uncertainty. Atomic rename may still have committed.
                try check(!FileManager.default.fileExists(atPath: item.path))
                try check(store.load()!.passwordLedger.pendingDeletion.isEmpty)
            } else {
                let outcome = try worker.deletePendingOutcome(store: store, reference: reference)
                if args[1] == "typed-delete" {
                    try check(outcome == .deleted && store.load()!.passwordLedger.pendingDeletion.isEmpty)
                } else {
                    let expected: VPNPasswordDeleteOutcome = args[1] == "typed-delete-not-found" ? .notFound
                        : args[1] == "typed-delete-unavailable" ? .unavailable : .indeterminate
                    try check(outcome == expected && before == Data(contentsOf: folder.appendingPathComponent("state.json")))
                }
                if args[1] == "typed-delete-late" {
                    let state = try store.load()!; var config = state.saved.configuration
                    try config.setAuthentication(VPNAuthentication(mode: .password, login: "synthetic", credentialPersistence: .keychain))
                    let enabled = try store.save(config, expectedRevision: state.saved.configuration.revision)
                    let newer = try store.grantPasswordPersistence(expectedRevision: enabled.saved.configuration.revision)
                    try Data().write(to: folder.appendingPathComponent("release"))
                    try wait { try store.load()!.passwordLedger.pendingDeletion.isEmpty }
                    try check(store.load()!.passwordLedger.active?.reference == newer)
                }
                try joinOwnChildren()
                if args[1] == "typed-delete-not-found" {
                    do {
                        try VPNPasswordWorker.prepare(store: store).deletePending(store: store, reference: reference)
                        throw Failure.check
                    } catch VPNValidationError.storageUnavailable {}
                    try joinOwnChildren()
                    try check(store.load()!.passwordLedger.pendingDeletion.count == 1)
                }
            }
            try check(events(folder) == (args[1] == "typed-delete-not-found" ? ["add", "delete", "delete"] : ["add", "delete"]))
        case "late", "parent-death", "commit-crash", "busy", "mutated-late-add":
            let behavior = args[1] == "commit-crash" ? "commit-crash" :
                (args[1] == "busy" ? "wait-release" : (args[1] == "mutated-late-add" ? "mutate-request" : "delay"))
            try Data(behavior.utf8).write(to: folder.appendingPathComponent("behavior"))
            let worker = try VPNPasswordWorker.prepare(store: store)
            var secret = Data("synthetic-password".utf8)
            let result = try store.addPasswordOnce(reference: reference, expectedRevision: revision) { _ in
                let response = try worker.testPerform(operation: .add, reference: reference, revision: revision,
                    secret: &secret, timeout: 30_000_000)
                return response.addOutcome
            }
            try check(result == .indeterminate && secret.isEmpty)
            if args[1] == "parent-death" { _exit(0) }
            if args[1] == "busy" {
                let lock = open(folder.appendingPathComponent("state.lock").path, O_RDWR | O_NOFOLLOW | O_CLOEXEC)
                guard lock >= 0, flock(lock, LOCK_EX | LOCK_NB) == 0 else { throw Failure.check }
                do {
                    defer { flock(lock, LOCK_UN); close(lock) }
                    try Data().write(to: folder.appendingPathComponent("release"))
                    try wait { FileManager.default.fileExists(atPath: folder.appendingPathComponent("item-" + reference.itemID.uuidString).path) }
                    usleep(50_000)
                    let raw = try JSONSerialization.jsonObject(with: Data(contentsOf: folder.appendingPathComponent("state.json"))) as! [String: Any]
                    let active = (raw["passwordLedger"] as! [String: Any])["active"] as! [String: Any]
                    try check(active["writeState"] as? String == "pending")
                }
                try wait { try store.load()!.passwordLedger.active?.writeState == .settled }
                try check(events(folder) == ["add"])
            } else if args[1] == "commit-crash" {
                usleep(100_000)
                try check(store.load()!.passwordLedger.active?.writeState == .pending && events(folder) == ["add"])
            } else {
                try revoke(store)
                let state = try store.load()!; var config = state.saved.configuration
                try config.setAuthentication(VPNAuthentication(mode: .password, login: "synthetic", credentialPersistence: .keychain))
                _ = try store.save(config, expectedRevision: state.saved.configuration.revision)
                let new = try store.createPasswordSaveGrant(expectedRevision: config.revision, expectedActive: nil)
                try wait { try store.load()!.passwordLedger.pendingDeletion[0].writeState == .settled }
                try joinOwnChildren()
                try check(store.load()!.passwordLedger.pendingDeletion[0].locator == fakeLocator(folder, reference: reference))
                try check(store.load()!.passwordLedger.active?.reference == new && store.load()!.passwordLedger.active?.writeState == .notIssued)
                try check(events(folder) == ["add"])
            }
        case "fd-ownership":
            let source = open(folder.path, O_RDONLY | O_DIRECTORY | O_CLOEXEC)
            let replacement = open("/dev/null", O_RDWR | O_CLOEXEC)
            guard source >= 0, replacement >= 0 else { throw Failure.check }
            defer { close(source); close(replacement) }
            for identity in [false, true] {
                var closes = 0, reused: Int32 = -1
                VPNPasswordWorkerDescriptor.testAfterClose = { fd in
                    closes += 1; reused = dup2(replacement, fd)
                }
                VPNPasswordWorkerIdentity.testRejectInitialized = identity
                VPNPasswordWorkerDirectory.testRejectInitialized = !identity
                do {
                    defer {
                        VPNPasswordWorkerDescriptor.testAfterClose = nil
                        VPNPasswordWorkerIdentity.testRejectInitialized = false
                        VPNPasswordWorkerDirectory.testRejectInitialized = false
                    }
                    try rejects {
                        if identity { _ = try VPNPasswordWorkerIdentity() }
                        else { _ = try VPNPasswordWorkerDirectory(duplicating: source) }
                    }
                }
                try check(closes == 1 && reused >= 0 && fcntl(reused, F_GETFD) >= 0)
                close(reused)
            }
        case "expired-deadline":
            var pair: [Int32] = [-1, -1]; guard socketpair(AF_UNIX, SOCK_STREAM, 0, &pair) == 0 else { throw Failure.check }
            defer { close(pair[0]); close(pair[1]) }
            for _ in 0..<1000 {
                try rejects { _ = try VPNPasswordWorkerWire.receive(socket: pair[0], deadline: DispatchTime.now().uptimeNanoseconds + 1) }
            }
        default: exit(64)
        }
        print("worker checks passed")
    }
}
