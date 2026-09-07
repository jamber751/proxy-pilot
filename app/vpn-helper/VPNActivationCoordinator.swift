import Darwin
import Dispatch
import Foundation

/// Trusted local adapter, NOT IPC and not implemented for launchd yet. It must
/// manage only our fixed service, honor deadlines, serialize process ownership,
/// and positively confirm resource cleanup/process exit before returning.
/// startIdleAndConnect must not apply profiles, routes or DNS: it starts only
/// an idle service and returns an exclusively owned close-on-exec connection.
protocol VPNActivationRuntime {
    func stopAndDrain(deadline: UInt64) throws
    func startIdleAndConnect(_ deployment: VPNAuthorizedDeployment, deadline: UInt64) throws -> Int32
}

enum VPNActivationPhase { case stop, commit, start, readiness, selection }
struct VPNActivationFailure: Error {
    let phase: VPNActivationPhase
    let cleanupConfirmed: Bool
}
enum VPNActivationCoordinatorError: Error { case busy, deadlineExceeded, selectionChanged }

/// Single-owner, synchronous coordinator; not yet connected to an installer,
/// updater or launchd. One call is one attempt, with no retry loop or downgrade.
/// Production needs an exclusive lifetime/supervisor lock around this owner;
/// this local gate alone is NOT cross-process lifecycle serialization.
final class VPNActivationCoordinator {
    private let store: VPNReleaseStore
    private let runtime: VPNActivationRuntime
    private let gate = NSLock()

    init(store: VPNReleaseStore, runtime: VPNActivationRuntime) {
        self.store = store
        self.runtime = runtime
    }

    func update(payload: Data, signature: Data, helper: Data, expectedSequence: UInt64) throws -> VPNHelperReady {
        try exclusively {
            // Invalid or obsolete candidates do not stop the working service.
            let prepared = try store.prepareDeployment(payload: payload, signature: signature,
                                                        helper: helper, expectedSequence: expectedSequence)
            try stop()
            let selected: VPNAuthorizedDeployment
            do { selected = try store.commitPreparedDeployment(prepared) }
            catch {
                // Includes uncertain disk commits. Never guess which release
                // won or restart the previous binary. Explicit recovery reloads.
                throw VPNActivationFailure(phase: .commit, cleanupConfirmed: true)
            }
            return try startAndCheck(selected)
        }
    }

    /// Explicit recovery/retry: stop any instance owned by our supervisor,
    /// re-read the authenticated disk selection, then make exactly one attempt.
    /// After a committed update, only the new security floor may be restarted.
    func recoverSelected() throws -> VPNHelperReady {
        try exclusively {
            try stop()
            let selected: VPNAuthorizedDeployment
            do { selected = try store.loadDeployment() }
            catch { throw VPNActivationFailure(phase: .selection, cleanupConfirmed: true) }
            return try startAndCheck(selected)
        }
    }

    private func exclusively<T>(_ body: () throws -> T) throws -> T {
        guard gate.try() else { throw VPNActivationCoordinatorError.busy }
        defer { gate.unlock() }
        return try body()
    }

    private func stop() throws {
        let deadline = Self.deadline()
        do {
            try runtime.stopAndDrain(deadline: deadline)
            try Self.check(deadline)
        } catch { throw VPNActivationFailure(phase: .stop, cleanupConfirmed: false) }
    }

    private func startAndCheck(_ selected: VPNAuthorizedDeployment) throws -> VPNHelperReady {
        var phase = VPNActivationPhase.selection
        do {
            try requireSelected(selected)
            phase = .start
            let deadline = Self.deadline()
            let socket = try runtime.startIdleAndConnect(selected, deadline: deadline)
            // Ownership transfers to the probe, including invalid/late fds.
            let now = DispatchTime.now().uptimeNanoseconds
            guard now < deadline else {
                if socket >= 0 { close(socket) }
                throw VPNActivationCoordinatorError.deadlineExceeded
            }
            phase = .readiness
            let remaining = max(1, min(2000, Int((deadline - now) / 1_000_000)))
            let ready: VPNHelperReady
            #if VPN_HELPER_READINESS_TESTING
            ready = try VPNHelperReadiness.testProbe(takingSocket: socket, release: selected.release, timeoutMilliseconds: remaining)
            #else
            ready = try VPNHelperReadiness.probe(takingSocket: socket, release: selected.release, timeoutMilliseconds: remaining)
            #endif
            phase = .selection
            try requireSelected(selected)
            return ready
        } catch {
            // The adapter may have started a process even when launch threw.
            // Cleanup failure is explicit; never return a stale "ready" receipt.
            var cleaned = false
            let deadline = Self.deadline()
            do { try runtime.stopAndDrain(deadline: deadline); try Self.check(deadline); cleaned = true }
            catch { }
            throw VPNActivationFailure(phase: phase, cleanupConfirmed: cleaned)
        }
    }

    private func requireSelected(_ expected: VPNAuthorizedDeployment) throws {
        let actual = try store.loadDeployment()
        guard actual.ownerUserID == expected.ownerUserID,
              actual.release.isSameRelease(as: expected.release) else { throw VPNActivationCoordinatorError.selectionChanged }
    }

    private static func deadline() -> UInt64 { DispatchTime.now().uptimeNanoseconds + 5_000_000_000 }
    private static func check(_ deadline: UInt64) throws {
        guard DispatchTime.now().uptimeNanoseconds < deadline else { throw VPNActivationCoordinatorError.deadlineExceeded }
    }
}
