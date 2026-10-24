import CryptoKit
import Darwin
import Foundation

private enum CheckFailure: Error { case check, unknown }
private func check(_ value: @autoclosure () throws -> Bool) throws {
    guard try value() else { throw CheckFailure.check }
}
private func locator(_ reference: VPNPasswordReference, variant: UInt64 = 1) -> VPNPasswordItemLocator {
    .init(persistentReference: Data(reference.itemID.uuidString.utf8), origin: .init(kind: .legacyKeychain,
        path: "/synthetic/cleanup.keychain-db", device: 1, inode: variant, ownerUID: getuid(),
        birthSeconds: 1, birthNanoseconds: 0))
}
private final class Fixture {
    let store: VPNStore
    let root: URL
    init() throws {
        root = FileManager.default.temporaryDirectory.appendingPathComponent("pp-cleanup-" + UUID().uuidString)
        store = VPNStore(directory: root)
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
        var config = VPNConfiguration()
        try config.setProfile(name: profile.name)
        try config.saveResource(VPNResource(address: "10.20.0.0/16"))
        try config.setAuthentication(VPNAuthentication(mode: .password, login: "employee", credentialPersistence: .keychain))
        _ = try store.save(config, importing: profile, expectedRevision: nil)
    }
    deinit { try? FileManager.default.removeItem(at: root) }
    func slot(_ state: VPNPasswordWriteState = .settled) throws -> VPNPasswordSlot {
        let current = try store.load()!
        let sha = SHA256.hash(data: current.saved.profileContents!).map { String(format: "%02x", $0) }.joined()
        let reference = VPNPasswordReference(itemID: UUID(), profileSHA256: sha, login: "employee")
        return VPNPasswordSlot(reference: reference, writeState: state,
                               locator: state == .settled ? locator(reference) : nil)
    }
    /// Synthetic, validated metadata only; no password enters this file.
    func queue(_ slots: [VPNPasswordSlot], active: VPNPasswordSlot? = nil) throws {
        let current = try store.load()!
        let state = VPNStoredState(saved: current.saved, applied: current.applied,
            passwordLedger: VPNPasswordLedger(active: active, pendingDeletion: slots))
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
        try encoder.encode(state).write(to: root.appendingPathComponent("state.json"), options: .atomic)
        guard chmod(root.appendingPathComponent("state.json").path, 0o600) == 0 else { throw CheckFailure.check }
    }
}
private final class Driver {
    enum Policy { case outcome(VPNPasswordDeleteOutcome), unknownThrow, falsePositive, deleteThenThrow }
    var policies: [UUID: Policy] = [:]
    var calls: [VPNPasswordReference] = []
    var backendCalls: [VPNPasswordReference] = []
    var prepared = 0
    var before: ((VPNPasswordReference) throws -> Void)?
    var after: ((VPNPasswordReference) throws -> Void)?
    func prepare(_ store: VPNStore) throws -> VPNPasswordCleanupSession? {
        _ = try store.load() // Must succeed: no Store lock during READY/auth.
        prepared += 1
        return Session(self)
    }
    private final class Session: VPNPasswordCleanupSession {
        let driver: Driver
        var used = false
        init(_ driver: Driver) { self.driver = driver }
        func deletePendingOutcome(store: VPNStore, reference: VPNPasswordReference) throws -> VPNPasswordDeleteOutcome {
            guard !used else { throw CheckFailure.check }; used = true
            driver.calls.append(reference)
            try driver.before?(reference)
            let policy = driver.policies[reference.itemID] ?? .outcome(.deleted)
            if case .unknownThrow = policy { throw CheckFailure.unknown }
            if case .falsePositive = policy { return .deleted }
            var observed: VPNPasswordDeleteOutcome?
            do {
                try store.deletePendingPassword(reference: reference) { ref, captured in
                    try check(ref == reference && captured == locator(reference))
                    driver.backendCalls.append(ref)
                    let result: VPNPasswordDeleteOutcome
                    if case .outcome(let outcome) = policy { result = outcome } else { result = .deleted }
                    observed = result; return result
                }
            } catch {
                if let observed, observed != .deleted { return observed }
                throw error
            }
            try driver.after?(reference)
            if case .deleteThenThrow = policy { throw CheckFailure.unknown }
            return .deleted
        }
    }
}

@main enum VPNPasswordCleanupChecks {
    static func main() throws {
        guard getuid() == geteuid(), getuid() != 0, CommandLine.arguments.count == 2 else { exit(77) }
        let fixture = try Fixture(), driver = Driver()
        var reports: [VPNPasswordCleanupReport] = []
        let mode = CommandLine.arguments[1]
        if mode == "coalesced-new" { try concurrent(fixture, driver); print("cleanup checks passed"); return }
        var scheduled: [() -> Void] = []
        let coordinator = VPNPasswordCleanupCoordinator(store: fixture.store, available: mode != "unavailable",
            prepare: { store in
                if mode == "prepare-throw" { throw CheckFailure.unknown }
                if mode == "prepare-nil" { return nil }
                let session = try driver.prepare(store)
                if mode == "changed-locator" {
                    let state = try store.load()!
                    var slots = state.passwordLedger.pendingDeletion
                    slots[0].locator = locator(slots[0].reference, variant: 2)
                    try fixture.queue(slots)
                }
                return session
            }, schedule: { scheduled.append($0) }, onPass: { reports.append($0) })
        func run() { coordinator.request(); while !scheduled.isEmpty { scheduled.removeFirst()() } }
        switch mode {
        case "positive", "not-found", "known-unavailable", "indeterminate", "throw", "false-positive", "post-delete-throw":
            let slot = try fixture.slot(); try fixture.queue([slot])
            switch mode {
            case "not-found": driver.policies[slot.reference.itemID] = .outcome(.notFound)
            case "known-unavailable": driver.policies[slot.reference.itemID] = .outcome(.unavailable)
            case "indeterminate": driver.policies[slot.reference.itemID] = .outcome(.indeterminate)
            case "throw": driver.policies[slot.reference.itemID] = .unknownThrow
            case "false-positive": driver.policies[slot.reference.itemID] = .falsePositive
            case "post-delete-throw": driver.policies[slot.reference.itemID] = .deleteThenThrow
            default: break
            }
            run()
            try check(reports.count == 1 && reports[0].visited == 1)
            if mode == "positive" {
                try check(reports[0].deleted == 1 && fixture.store.load()!.passwordLedger.pendingDeletion.isEmpty)
            } else {
                try check(reports[0].deleted == 0)
                if mode == "post-delete-throw" {
                    // Simulate an old queue restored later: absence did not
                    // settle the unknown receipt or discard quarantine history.
                    try check(fixture.store.load()!.passwordLedger.pendingDeletion.isEmpty)
                    try fixture.queue([slot])
                }
                run()
                let known = mode == "not-found" || mode == "known-unavailable"
                try check(driver.calls.count == (known ? 2 : 1))
                try check(reports.last!.quarantinedSkipped == (known ? 0 : 1))
                try check(fixture.store.load()!.passwordLedger.pendingDeletion.count == 1)
            }
        #if VPN_PASSWORD_CLEANUP_TESTING
        case "positive-busy", "positive-busy-held", "positive-malformed":
            let slot = try fixture.slot(); try fixture.queue([slot])
            var held: Int32 = -1, busyReads = 0
            driver.after = { _ in
                if mode == "positive-malformed" {
                    try Data("invalid-store".utf8).write(to: fixture.root.appendingPathComponent("state.json"))
                } else {
                    held = open(fixture.root.appendingPathComponent("state.lock").path, O_RDWR | O_NOFOLLOW | O_CLOEXEC)
                    guard held >= 0, flock(held, LOCK_EX | LOCK_NB) == 0 else { throw CheckFailure.check }
                }
            }
            VPNPasswordCleanupCoordinator.testAfterBusyObservation = {
                busyReads += 1
                if mode == "positive-busy", held >= 0 {
                    flock(held, LOCK_UN); close(held); held = -1
                }
            }
            defer {
                VPNPasswordCleanupCoordinator.testAfterBusyObservation = nil
                if held >= 0 { flock(held, LOCK_UN); close(held) }
            }
            run()
            try check(driver.calls.count == 1 && driver.prepared == 1 && scheduled.isEmpty && reports.count == 1)
            if mode == "positive-busy" {
                try check(busyReads == 1 && reports[0].deleted == 1 && !reports[0].stoppedOnUnknown)
            } else if mode == "positive-busy-held" {
                try check((1...3).contains(busyReads) && reports[0].deleted == 0 && reports[0].stoppedOnUnknown)
            } else {
                try check(busyReads == 0 && reports[0].deleted == 0 && reports[0].stoppedOnUnknown)
            }
        #endif
        case "stop-unknown", "stop-throw", "stop-ack":
            let first = try fixture.slot(), other = try fixture.slot()
            try fixture.queue([first, other])
            if mode == "stop-unknown" { driver.policies[first.reference.itemID] = .outcome(.indeterminate) }
            if mode == "stop-throw" { driver.policies[first.reference.itemID] = .unknownThrow }
            if mode == "stop-ack" { driver.policies[first.reference.itemID] = .falsePositive }
            run()
            try check(driver.calls == [first.reference] && reports[0].stoppedOnUnknown
                && reports[0].visited == 1 && reports[0].deleted == 0)
            run()
            try check(driver.calls == [first.reference, other.reference] && reports.last!.deleted == 1
                && reports.last!.quarantinedSkipped == 1
                && fixture.store.load()!.passwordLedger.pendingDeletion == [first])
        case "store-busy":
            let slot = try fixture.slot(); try fixture.queue([slot])
            let file = fixture.root.appendingPathComponent("state.json")
            let before = try Data(contentsOf: file)
            let fd = open(fixture.root.appendingPathComponent("state.lock").path, O_RDWR | O_NOFOLLOW | O_CLOEXEC)
            guard fd >= 0, flock(fd, LOCK_EX | LOCK_NB) == 0 else { throw CheckFailure.check }
            defer { flock(fd, LOCK_UN); close(fd) }
            run()
            try check(reports[0].storageUnavailable && driver.calls.isEmpty
                && scheduled.isEmpty && Data(contentsOf: file) == before)
            guard flock(fd, LOCK_UN) == 0 else { throw CheckFailure.check }
            run()
            try check(driver.calls.count == 1 && reports.last!.deleted == 1)
        case "recreated":
            let slot = try fixture.slot(); try fixture.queue([slot])
            driver.policies[slot.reference.itemID] = .outcome(.indeterminate)
            run()
            let other = Driver()
            var otherReport: VPNPasswordCleanupReport?
            let recreated = VPNPasswordCleanupCoordinator(store: fixture.store, available: true,
                prepare: other.prepare, schedule: { $0() }, onPass: { otherReport = $0 })
            recreated.request()
            try check(driver.calls.count == 1 && other.prepared == 0 && other.calls.isEmpty
                && otherReport?.quarantinedSkipped == 1)
        case "profile-removed":
            let slot = try fixture.slot(); try fixture.queue([slot])
            let before = try fixture.store.load()!; var config = before.saved.configuration
            try config.removeProfile()
            _ = try fixture.store.save(config, expectedRevision: before.saved.configuration.revision)
            run()
            let after = try fixture.store.load()!
            try check(reports[0].deleted == 1 && after.saved.configuration.profileName == nil
                && after.saved.profileContents == nil && after.passwordLedger.pendingDeletion.isEmpty)
        case "mixed":
            let settled = try fixture.slot(), pending = try fixture.slot(.pending)
            let never = try fixture.slot(.notIssued), noItem = try fixture.slot(.noItem)
            let active = try fixture.slot(.notIssued)
            try fixture.queue([settled, pending, never, noItem], active: active)
            run()
            let state = try fixture.store.load()!
            try check(driver.prepared == 1 && driver.backendCalls == [settled.reference])
            try check(reports[0].visited == 4 && reports[0].deleted == 1
                && reports[0].retiredWithoutIO == 2 && reports[0].pendingSkipped == 1)
            try check(state.passwordLedger.active == active && state.passwordLedger.pendingDeletion == [pending])
        case "pending", "no-io":
            let slots = try mode == "pending" ? [fixture.slot(.pending)] : [fixture.slot(.notIssued), fixture.slot(.noItem)]
            try fixture.queue(slots); run()
            try check(driver.prepared == 0 && driver.calls.isEmpty)
            try check(reports[0].pendingSkipped == (mode == "pending" ? 1 : 0))
            try check(reports[0].retiredWithoutIO == (mode == "no-io" ? 2 : 0))
        case "prepare-throw", "prepare-nil", "changed-locator":
            let slot = try fixture.slot(); try fixture.queue([slot]); run()
            try check(driver.calls.isEmpty && reports[0].deleted == 0)
            try check(fixture.store.load()!.passwordLedger.pendingDeletion.count == 1)
        case "coalesced-same":
            let slot = try fixture.slot(); driver.policies[slot.reference.itemID] = .outcome(.notFound)
            try fixture.queue([slot])
            for _ in 0..<20 { coordinator.request() }
            try check(scheduled.count == 1 && driver.calls.isEmpty)
            scheduled.removeFirst()()
            try check(scheduled.isEmpty && reports.count == 1 && driver.calls.count == 1)
        case "bounds":
            let slots = try (0..<64).map { _ in try fixture.slot() }
            for slot in slots { driver.policies[slot.reference.itemID] = .outcome(.indeterminate) }
            try fixture.queue(slots)
            for count in 1...64 {
                run()
                try check(driver.calls.count == count && reports.last!.visited <= 64
                    && reports.last!.stoppedOnUnknown)
            }
            for slot in slots {
                // A synthetic trusted late positive completion removes old refs.
                try fixture.store.deletePendingPassword(reference: slot.reference) { _, _ in .deleted }
            }
            try fixture.queue([fixture.slot()]); run()
            try check(driver.calls.count == 64 && reports.last!.capacitySkipped == 1)
        case "malformed-bounds":
            let slots = try (0..<65).map { _ in try fixture.slot() }
            try fixture.queue(slots); run()
            try check(reports[0].storageUnavailable && reports[0].visited == 0 && driver.calls.isEmpty)
        case "unavailable":
            try Data("not-a-store".utf8).write(to: fixture.root.appendingPathComponent("state.json"))
            coordinator.request()
            try check(scheduled.isEmpty && reports.isEmpty && driver.prepared == 0)
        default: throw CheckFailure.check
        }
        for report in reports {
            let rendered = String(reflecting: report)
            try check(!rendered.contains(fixture.root.path) && !rendered.contains("employee") && !rendered.contains("keychain"))
        }
        print("cleanup checks passed")
    }

    private static func concurrent(_ fixture: Fixture, _ driver: Driver) throws {
        let old = try fixture.slot(), newest = try fixture.slot()
        try fixture.queue([old]); driver.policies[old.reference.itemID] = .outcome(.notFound)
        let entered = DispatchSemaphore(value: 0), release = DispatchSemaphore(value: 0), done = DispatchSemaphore(value: 0)
        driver.before = { reference in
            if reference == old.reference {
                entered.signal()
                guard release.wait(timeout: .now() + 3) == .success else { throw CheckFailure.check }
            }
        }
        var schedules = 0
        var reports: [VPNPasswordCleanupReport] = []
        let coordinator = VPNPasswordCleanupCoordinator(store: fixture.store, available: true,
            prepare: driver.prepare, schedule: { work in
                schedules += 1
                DispatchQueue.global().async(execute: DispatchWorkItem { work(); done.signal() })
            }, onPass: { reports.append($0) })
        coordinator.request()
        try check(entered.wait(timeout: .now() + 2) == .success)
        try fixture.queue([old, newest])
        for _ in 0..<20 { coordinator.request() }
        release.signal()
        try check(done.wait(timeout: .now() + 3) == .success)
        try check(schedules == 1 && reports.count == 2 && reports.allSatisfy { $0.visited == 1 })
        try check(driver.calls == [old.reference, newest.reference] && driver.prepared == 2)
        try check(fixture.store.load()!.passwordLedger.pendingDeletion == [old])
    }
}
