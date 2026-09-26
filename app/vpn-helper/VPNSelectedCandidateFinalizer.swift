import Darwin
import Dispatch
import Foundation

enum VPNSelectedCandidateFinalizerError: Error {
    case invalidJournal, deadlineExceeded, commitUncertain
}

/// Finishes an already selected A→B transaction. Desired-off completes without
/// resurrecting the helper. Desired-on starts only exact selected B in idle mode
/// and requires authenticated readiness before recording completion.
enum VPNSelectedCandidateFinalizer {
    enum Outcome { case helperReady, remainedOff }

    static func finish(store: VPNReleaseStore, runtime: VPNActivationRuntime,
                       lease: VPNLifecycleLease, budget: VPNActivationBudget,
                       transactionID: UUID, expectedRevision: UInt64,
                       candidate: VPNAuthorizedDeployment,
                       testPolicy: Bool = false) throws -> Outcome {
        guard expectedRevision < UInt64.max else {
            throw VPNSelectedCandidateFinalizerError.invalidJournal
        }
        func selected() throws {
            try lease.check()
            let deployment = try store.loadDeployment()
            guard let journal = try store.loadUpdateJournal(),
                  journal.transactionID == transactionID,
                  journal.revision == expectedRevision,
                  journal.phase == .selected,
                  journal.recovery == .recoverCandidate,
                  journal.candidate.ownerUserID == candidate.ownerUserID,
                  journal.candidate.release.isSameRelease(as: candidate.release),
                  deployment.ownerUserID == candidate.ownerUserID,
                  deployment.release.isSameRelease(as: candidate.release) else {
                throw VPNSelectedCandidateFinalizerError.invalidJournal
            }
            try lease.check()
        }
        func completed() throws {
            try lease.check()
            guard let journal = try store.loadUpdateJournal(),
                  journal.transactionID == transactionID,
                  journal.revision == expectedRevision + 1,
                  journal.phase == .completed,
                  journal.recovery == .completed,
                  journal.candidate.ownerUserID == candidate.ownerUserID,
                  journal.candidate.release.isSameRelease(as: candidate.release) else {
                throw VPNSelectedCandidateFinalizerError.invalidJournal
            }
            try lease.check()
        }

        try selected()
        let desired = try budget.snapshot().desired
        var mayHaveStarted = false
        var journalMayHaveCompleted = false
        do {
            if desired {
                try budget.beginAttempt(intent: .automatic)
                try selected()
                let deadline = DispatchTime.now().uptimeNanoseconds + 5_000_000_000
                mayHaveStarted = true
                let socket = try runtime.startIdleAndConnect(candidate, deadline: deadline)
                let now = DispatchTime.now().uptimeNanoseconds
                guard now < deadline else {
                    if socket >= 0 { close(socket) }
                    throw VPNSelectedCandidateFinalizerError.deadlineExceeded
                }
                let remaining = max(1, min(2000, Int((deadline - now) / 1_000_000)))
                #if VPN_HELPER_READINESS_TESTING
                if testPolicy {
                    _ = try VPNHelperReadiness.testProbe(
                        takingSocket: socket, release: candidate.release,
                        timeoutMilliseconds: remaining)
                } else {
                    _ = try VPNHelperReadiness.probe(
                        takingSocket: socket, release: candidate.release,
                        timeoutMilliseconds: remaining)
                }
                #else
                _ = testPolicy
                _ = try VPNHelperReadiness.probe(
                    takingSocket: socket, release: candidate.release,
                    timeoutMilliseconds: remaining)
                #endif
                try selected()
                try budget.recordSuccess()
                try selected()
            }
            journalMayHaveCompleted = true
            _ = try store.completeUpdateJournal(
                transactionID: transactionID, expectedRevision: expectedRevision)
            try completed()
            return desired ? .helperReady : .remainedOff
        } catch {
            if journalMayHaveCompleted { throw VPNSelectedCandidateFinalizerError.commitUncertain }
            if mayHaveStarted {
                let deadline = DispatchTime.now().uptimeNanoseconds + 5_000_000_000
                do { try runtime.stopAndDrain(deadline: deadline) } catch { }
            }
            throw error
        }
    }
}
