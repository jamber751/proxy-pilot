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
    func execute(_ request: inout VPNPasswordWorkerWire.Request) throws -> VPNPasswordWorkerWire.Response {
        let event = openat(directory, "events", O_WRONLY | O_APPEND | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard event >= 0 else { throw VPNPasswordWorkerError.unavailable }
        let label = Data((request.metadata.operation.rawValue + "\n").utf8)
        _ = label.withUnsafeBytes { write(event, $0.baseAddress, $0.count) }; close(event)
        if behavior() == "delay" { usleep(400_000) }
        if behavior() == "wait-release" {
            let deadline = Date().addingTimeInterval(3)
            var info = stat()
            while fstatat(directory, "release", &info, AT_SYMLINK_NOFOLLOW) != 0, Date() < deadline { usleep(1000) }
            guard fstatat(directory, "release", &info, AT_SYMLINK_NOFOLLOW) == 0 else {
                return .init(status: .failed, secret: Data())
            }
        }
        if behavior() == "crash" { _exit(71) }
        if behavior() == "denied" { return .init(status: .denied, secret: Data()) }
        let name = "item-" + request.metadata.reference.itemID.uuidString
        switch request.metadata.operation {
        case .add:
            let fd = openat(directory, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
            guard fd >= 0 else { return .init(status: .failed, secret: Data()) }; defer { close(fd) }
            let n = request.secret.withUnsafeBytes { write(fd, $0.baseAddress, $0.count) }
            if behavior() == "commit-crash" { _exit(72) }
            return .init(status: n == request.secret.count ? .success : .failed, secret: Data())
        case .read:
            let fd = openat(directory, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
            guard fd >= 0 else { return .init(status: .notFound, secret: Data()) }; defer { close(fd) }
            var bytes = [UInt8](repeating: 0, count: VPNPasswordWorkerWire.maximumSecretBytes)
            let n = read(fd, &bytes, bytes.count)
            defer { bytes.withUnsafeMutableBytes { _ = memset_s($0.baseAddress, $0.count, 0, $0.count) } }
            guard n > 0 else { return .init(status: .failed, secret: Data()) }
            return .init(status: .success, secret: Data(bytes.prefix(n)))
        case .delete:
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
        let deadline = Date().addingTimeInterval(7)
        repeat { if try predicate() { return }; usleep(20_000) } while Date() < deadline
        throw Failure.check
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
        case "roundtrip":
            let worker = try VPNPasswordWorker.prepare(store: store)
            var secret = Data("synthetic-static-password".utf8)
            try check(worker.addOnce(store: store, reference: reference, revision: revision, secret: &secret) == .definiteSuccess)
            try check(secret.isEmpty && store.load()!.passwordLedger.active?.writeState == .settled)
            var again = Data("synthetic-static-password".utf8)
            try rejects { _ = try worker.addOnce(store: store, reference: reference, revision: revision, secret: &again) }
            var read = try VPNPasswordWorker.prepare(store: store).read(store: store, reference: reference, revision: revision)
            try check(read.status == .success && read.secret == Data("synthetic-static-password".utf8))
            VPNPasswordWorkerWire.clear(&read.secret)
            try revoke(store)
            try VPNPasswordWorker.prepare(store: store).deletePending(store: store, reference: reference)
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
                return response.status == .success ? .definiteSuccess : .definiteFailure
            }
            try check(result == .definiteSuccess && secret.isEmpty && events(folder) == ["add"])
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
            try FileManager.default.removeItem(at: folder.appendingPathComponent("item-" + reference.itemID.uuidString))
            try revoke(store)
            try rejects { try VPNPasswordWorker.prepare(store: store).deletePending(store: store, reference: reference) }
            usleep(100_000)
            try check(store.load()!.passwordLedger.pendingDeletion.count == 1)
        case "late", "parent-death", "commit-crash", "busy":
            let behavior = args[1] == "commit-crash" ? "commit-crash" : (args[1] == "busy" ? "wait-release" : "delay")
            try Data(behavior.utf8).write(to: folder.appendingPathComponent("behavior"))
            let worker = try VPNPasswordWorker.prepare(store: store)
            var secret = Data("synthetic-password".utf8)
            let result = try store.addPasswordOnce(reference: reference, expectedRevision: revision) { _ in
                let response = try worker.testPerform(operation: .add, reference: reference, revision: revision,
                    secret: &secret, timeout: 30_000_000)
                return response.status == .indeterminate ? .indeterminate : .definiteSuccess
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
