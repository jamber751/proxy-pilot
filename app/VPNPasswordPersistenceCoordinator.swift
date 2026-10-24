import CryptoKit
import Foundation

/// A prepared, authenticated ordinary worker. Preparation happens outside Store
/// locks; these operations must use the Store's bounded read/add-once gates.
/// The concrete Security worker bridge is deliberately supplied separately.
protocol VPNPasswordPersistenceSession {
    func read(store: VPNStore, reference: VPNPasswordReference, revision: UInt64) throws -> Data?
    func addOnce(store: VPNStore, reference: VPNPasswordReference, revision: UInt64,
                 secret: inout Data) throws -> VPNPasswordAddOutcome
}

struct VPNPasswordPersistenceBinding: Equatable {
    let sessionIdentifier: UUID
    let attempt: VPNConnectAttemptBinding
    let challenge: VPNCredentialChallenge

    var application: VPNApplicationSpec { attempt.application.spec }
    var eligible: Bool {
        (try? attempt.validate()) != nil
            && challenge.kind == .vpnPassword && challenge.generation == attempt.generation
            && application.authentication.mode == .password
            && application.authentication.credentialPersistence == .keychain
    }
}

/// UI payload only. Public scope contains no credential or item identity.
struct VPNPasswordPersistenceEvent: Equatable, CustomStringConvertible, CustomDebugStringConvertible {
    enum Phase: String { case saving, saved, needsConfirmation }
    let intentIdentifier: UUID
    let configurationRevision: UInt64
    let phase: Phase
    var description: String { "VPNPasswordPersistenceEvent(redacted)" }
    var debugDescription: String { description }
}

struct VPNPasswordCachedCredential {
    let reference: VPNPasswordReference
    var secret: Data
}

/// One manual input, owned only until its exact attempt is proven connected or
/// invalidated. No secret participates in Codable, descriptions or diagnostics.
final class VPNPasswordSaveCandidate {
    let binding: VPNPasswordPersistenceBinding
    let expectedActive: VPNPasswordReference?
    fileprivate let intentIdentifier: UUID
    fileprivate let captureFailed: Bool
    private let lock = NSLock()
    private var bytes: Data
    fileprivate init(binding: VPNPasswordPersistenceBinding, expectedActive: VPNPasswordReference?,
                     intentIdentifier: UUID, secret: Data, captureFailed: Bool = false) {
        self.binding = binding; self.expectedActive = expectedActive
        self.intentIdentifier = intentIdentifier; self.captureFailed = captureFailed
        bytes = secret.withUnsafeBytes { Data($0) }
    }
    var isCleared: Bool { lock.lock(); defer { lock.unlock() }; return bytes.isEmpty }
    func clear() {
        lock.lock(); defer { lock.unlock() }
        bytes.resetBytes(in: 0..<bytes.count)
        bytes.removeAll(keepingCapacity: false)
    }
    fileprivate func take() -> Data {
        lock.lock(); defer { lock.unlock() }
        let result = bytes
        bytes = Data()
        return result
    }
    deinit { clear() }
}

/// An inert default keeps the UI honest until a real worker driver is enabled.
/// Cache failures are intentionally independent of the verified VPN state.
final class VPNPasswordPersistenceCoordinator {
    typealias Prepare = (VPNStore) throws -> VPNPasswordPersistenceSession?
    typealias Schedule = (@escaping () -> Void) -> Void
    private static let queue = DispatchQueue(label: "ProxyPilot.password-persistence")
    private let store: VPNStore
    private let prepare: Prepare
    private let schedule: Schedule
    let available: Bool
    private let intentLock = NSLock()
    private var intentIdentifier = UUID()
    private weak var queuedCandidate: VPNPasswordSaveCandidate?
    private var latestEvent: VPNPasswordPersistenceEvent?
    private var eventHandler: (VPNPasswordPersistenceEvent) -> Void = { _ in }

    var currentEvent: VPNPasswordPersistenceEvent? {
        intentLock.lock(); defer { intentLock.unlock() }; return latestEvent
    }
    func setEventHandler(_ handler: @escaping (VPNPasswordPersistenceEvent) -> Void) {
        intentLock.lock(); eventHandler = handler; let event = latestEvent; intentLock.unlock()
        if let event { handler(event) }
    }
    /// Call again on the UI delivery queue, using its current saved settings.
    /// No disk access or credential data is needed to reject an obsolete event.
    func isCurrentEvent(_ event: VPNPasswordPersistenceEvent, configuration: VPNConfiguration) -> Bool {
        guard available, configuration.revision == event.configurationRevision,
              configuration.authentication?.mode == .password,
              configuration.authentication?.credentialPersistence == .keychain else { return false }
        intentLock.lock(); defer { intentLock.unlock() }
        return event.intentIdentifier == intentIdentifier && latestEvent == event
    }

    init(store: VPNStore, available: Bool = false,
         prepare: @escaping Prepare = { _ in nil }, schedule: Schedule? = nil) {
        self.store = store; self.available = available; self.prepare = prepare
        self.schedule = schedule ?? { work in Self.queue.async(execute: DispatchWorkItem(block: work)) }
    }

    func captureManual(_ secret: Data, binding: VPNPasswordPersistenceBinding) -> VPNPasswordSaveCandidate? {
        guard available, binding.eligible else { return nil }
        intentLock.lock(); defer { intentLock.unlock() }
        invalidateLocked()
        let current = try? current(binding.application)
        let captured = current != nil && Self.valid(secret)
        // An empty marker remembers only the eligible intent. It can report a
        // failed capture after connection proof but can never create a grant.
        return VPNPasswordSaveCandidate(binding: binding,
            expectedActive: current?.passwordLedger.active?.reference,
            intentIdentifier: intentIdentifier, secret: captured ? secret : Data(), captureFailed: !captured)
    }

    /// Cancel only queued, pre-claim work. A persisted fresh grant is an
    /// irrevocable save claim, not proof that Add was dispatched: its slot stays
    /// notIssued until Store.addPasswordOnce durably marks pending. Claimed work
    /// may still reach that exact Store gate after invalidation; a newer grant
    /// makes the stale reference fail before its backend callback.
    func invalidatePendingSave() {
        guard available else { return }
        intentLock.lock(); defer { intentLock.unlock() }
        invalidateLocked()
    }
    private func invalidateLocked() {
        intentIdentifier = UUID(); latestEvent = nil
        queuedCandidate?.clear(); queuedCandidate = nil
    }
    private func invalidateIfCurrent(_ identifier: UUID) {
        intentLock.lock(); defer { intentLock.unlock() }
        if identifier == intentIdentifier { invalidateLocked() }
    }
    private func isCurrentIntent(_ identifier: UUID) -> Bool {
        intentLock.lock(); defer { intentLock.unlock() }
        return identifier == intentIdentifier
    }

    /// Call at most once for an exact held-session attempt. Never put returned
    /// bytes into the panel's String field, and never turn cached input into Add.
    func read(binding: VPNPasswordPersistenceBinding,
              excluding rejected: VPNPasswordReference? = nil) -> VPNPasswordCachedCredential? {
        guard available, binding.eligible else { return nil }
        intentLock.lock(); let identifier = intentIdentifier; intentLock.unlock()
        var result = Data()
        var expected: VPNPasswordReference?
        var hadSlot = false
        do {
            let before = try current(binding.application)
            guard let slot = before.passwordLedger.active else { return nil }
            hadSlot = true; expected = slot.reference
            guard slot.writeState == .settled, slot.reference != rejected, slot.locator != nil,
                  let worker = try prepare(store) else {
                needsConfirmation(binding.application, intent: identifier, expectedActive: expected, matchActive: true)
                return nil
            }
            result = try worker.read(store: store, reference: slot.reference,
                                     revision: binding.application.revision) ?? Data()
            let after = try current(binding.application)
            guard after.passwordLedger.active == slot else {
                Self.clear(&result); invalidateIfCurrent(identifier); return nil
            }
            guard Self.valid(result) else {
                Self.clear(&result)
                needsConfirmation(binding.application, intent: identifier, expectedActive: expected, matchActive: true)
                return nil
            }
            return VPNPasswordCachedCredential(reference: slot.reference, secret: result)
        } catch {
            Self.clear(&result)
            needsConfirmation(binding.application, intent: identifier, expectedActive: expected, matchActive: hadSlot)
            return nil
        }
    }

    /// Only the controller's authenticated connected snapshot may reach here.
    /// It has already acknowledged exactly this saved revision before closing
    /// the helper session. The candidate is consumed even if a caller repeats.
    func saveVerified(_ candidate: VPNPasswordSaveCandidate, snapshot: VPNTunnelSnapshot,
                      sessionIdentifier: UUID) {
        guard available, candidate.binding.eligible, isCurrentIntent(candidate.intentIdentifier),
              candidate.binding.sessionIdentifier == sessionIdentifier,
              snapshot.phase == .connected, snapshot.desiredEnabled,
              snapshot.attempt == candidate.binding.attempt,
              snapshot.active == candidate.binding.attempt.application,
              snapshot.generation == candidate.binding.attempt.generation,
              (try? snapshot.validate()) != nil else { candidate.clear(); return }
        if candidate.captureFailed {
            candidate.clear()
            needsConfirmation(candidate.binding.application, intent: candidate.intentIdentifier)
            return
        }
        var transferred = candidate.take()
        guard Self.valid(transferred) else { Self.clear(&transferred); return }
        let binding = candidate.binding, expectedActive = candidate.expectedActive
        let identifier = candidate.intentIdentifier
        let owned = VPNPasswordSaveCandidate(binding: binding, expectedActive: expectedActive,
                                             intentIdentifier: identifier, secret: transferred)
        Self.clear(&transferred)
        intentLock.lock()
        guard identifier == intentIdentifier else { intentLock.unlock(); owned.clear(); return }
        queuedCandidate = owned
        intentLock.unlock()
        schedule { [self, owned] in
            var secret = owned.take()
            defer { Self.clear(&secret) }
            var expectedForFailure = expectedActive
            do {
                guard Self.valid(secret), isCurrentIntent(identifier) else { return }
                let before = try current(binding.application)
                guard before.applied == before.saved,
                      before.passwordLedger.active?.reference == expectedActive else {
                    invalidateIfCurrent(identifier); return
                }
                publish(.saving, application: binding.application, intent: identifier)
                guard let worker = try prepare(store) else {
                    needsConfirmation(binding.application, intent: identifier, expectedActive: expectedActive, matchActive: true)
                    return
                }
                // READY/authentication is outside both locks. Only short
                // metadata/grant work is serialized with fresh manual capture.
                guard let fresh = try grantIfCurrent(binding.application,
                    expectedActive: expectedActive, intent: identifier) else { return }
                expectedForFailure = fresh
                let result = try worker.addOnce(store: store, reference: fresh,
                                               revision: binding.application.revision, secret: &secret)
                if case .added(let locator) = result {
                    switch try observeAdded(fresh, locator: locator, application: binding.application) {
                    case .acknowledged: publish(.saved, application: binding.application, intent: identifier)
                    case .stale: invalidateIfCurrent(identifier)
                    case .unconfirmed:
                        needsConfirmation(binding.application, intent: identifier, expectedActive: fresh, matchActive: true)
                    }
                } else {
                    needsConfirmation(binding.application, intent: identifier, expectedActive: fresh, matchActive: true)
                }
            } catch {
                needsConfirmation(binding.application, intent: identifier,
                                  expectedActive: expectedForFailure, matchActive: true)
            }
        }
        // Dropped/cancelled work also clears its owned candidate on deinit.
        // Data/COW and Security copies are not universally zeroed here.
    }

    private func publish(_ phase: VPNPasswordPersistenceEvent.Phase,
                         application: VPNApplicationSpec, intent: UUID) {
        guard available else { return }
        let event = VPNPasswordPersistenceEvent(intentIdentifier: intent,
            configurationRevision: application.revision, phase: phase)
        intentLock.lock()
        guard intent == intentIdentifier, latestEvent != event else { intentLock.unlock(); return }
        latestEvent = event; let handler = eventHandler
        intentLock.unlock()
        handler(event) // Never under intentLock, Store.lock, or worker IPC.
    }
    private func needsConfirmation(_ application: VPNApplicationSpec, intent: UUID,
                                   expectedActive: VPNPasswordReference? = nil, matchActive: Bool = false) {
        guard available, isCurrentIntent(intent) else { return }
        do {
            let state = try current(application)
            if matchActive, state.passwordLedger.active?.reference != expectedActive {
                invalidateIfCurrent(intent); return
            }
        } catch VPNValidationError.staleRevision { invalidateIfCurrent(intent); return }
        catch { /* Unknown cache storage needs confirmation, not VPN failure. */ }
        publish(.needsConfirmation, application: application, intent: intent)
    }
    private enum AddedObservation { case acknowledged, stale, unconfirmed }
    private func observeAdded(_ reference: VPNPasswordReference, locator: VPNPasswordItemLocator,
                              application: VPNApplicationSpec) throws -> AddedObservation {
        let deadline = DispatchTime.now().uptimeNanoseconds + 50_000_000
        for attempt in 0..<3 {
            if attempt > 0, DispatchTime.now().uptimeNanoseconds >= deadline { throw VPNValidationError.storageUnavailable }
            do {
                let state = try current(application)
                guard let slot = state.passwordLedger.active, slot.reference == reference else { return .stale }
                return slot.writeState == .settled && slot.locator == locator ? .acknowledged : .unconfirmed
            } catch VPNValidationError.staleRevision { return .stale }
            catch VPNValidationError.storageUnavailable {
                #if VPN_LIVE_CONTROLLER_TESTING
                Self.testAfterBusySavedObservation?()
                #endif
                let now = DispatchTime.now().uptimeNanoseconds
                guard attempt < 2, now < deadline, deadline - now >= 10_000_000 else { throw VPNValidationError.storageUnavailable }
                Thread.sleep(forTimeInterval: 0.01)
            }
        }
        throw VPNValidationError.storageUnavailable
    }
    #if VPN_LIVE_CONTROLLER_TESTING
    static var testAfterBusySavedObservation: (() -> Void)?
    #endif

    private func grantIfCurrent(_ application: VPNApplicationSpec,
                                expectedActive: VPNPasswordReference?, intent: UUID) throws -> VPNPasswordReference? {
        intentLock.lock(); defer { intentLock.unlock() }
        guard intent == intentIdentifier else { return nil }
        let ready = try current(application)
        guard ready.applied == ready.saved,
              ready.passwordLedger.active?.reference == expectedActive else {
            invalidateLocked(); return nil
        }
        let claimed = try store.createPasswordSaveGrant(expectedRevision: application.revision, expectedActive: expectedActive)
        // Linearize the claim with manual capture. From here this UUID belongs
        // to Store, while a later manual capture observes it as expectedActive.
        // No intent lock is held across worker IPC or credential APIs.
        queuedCandidate = nil
        return claimed
    }

    private func current(_ application: VPNApplicationSpec) throws -> VPNStoredState {
        guard let state = try store.load(), let bytes = state.saved.profileContents,
              let auth = state.saved.configuration.authentication,
              auth.mode == .password, auth.credentialPersistence == .keychain,
              state.saved.configuration.desiredEnabled,
              state.saved.configuration.revision == application.revision else {
            throw VPNValidationError.staleRevision
        }
        let observed = try VPNApplicationSpec(revision: state.saved.configuration.revision,
            profileSHA256: SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined(),
            resources: state.saved.configuration.resources,
            corporateDNS: state.saved.configuration.corporateDNS, authentication: auth)
        guard observed == application else { throw VPNValidationError.staleRevision }
        return state
    }
    private static func valid(_ bytes: Data) -> Bool {
        !bytes.isEmpty && bytes.count <= 1024 && bytes.allSatisfy { $0 >= 32 && $0 != 127 }
    }
    private static func clear(_ bytes: inout Data) {
        bytes.resetBytes(in: 0..<bytes.count); bytes.removeAll(keepingCapacity: false)
    }
}
