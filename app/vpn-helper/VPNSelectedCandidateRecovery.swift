import Darwin
import Foundation

enum VPNSelectedCandidateRecoveryError: Error {
    case invalidJournal, retirementUncertain
}

/// Forward-only recovery for a disk-installed exact B. It never accepts paths,
/// releases or desired state from IPC and never rolls selector B back to A.
enum VPNSelectedCandidateRecovery {
    static func recover(store: VPNReleaseStore, runtime: VPNActivationRuntime,
                        lease: VPNLifecycleLease, budget: VPNActivationBudget,
                        journal initial: VPNUpdateJournalSnapshot,
                        testPolicy: Bool = false) throws
        -> VPNSelectedCandidateFinalizer.Outcome {
        var current = initial
        if initial.phase == .replacementPending && initial.recovery == .recoverCandidate {
            try lease.check()
            current = try store.selectUpdateCandidate(
                transactionID: initial.transactionID,
                expectedRevision: initial.revision)
            try lease.check()
        }
        let recoverable = current.phase == .selected && current.recovery == .recoverCandidate
            || current.phase == .completed && current.recovery == .completed
        guard recoverable else {
            throw VPNSelectedCandidateRecoveryError.invalidJournal
        }
        let outcome: VPNSelectedCandidateFinalizer.Outcome
        if current.phase == .selected {
            outcome = try VPNSelectedCandidateFinalizer.finish(
                store: store, runtime: runtime, lease: lease, budget: budget,
                transactionID: current.transactionID,
                expectedRevision: current.revision,
                candidate: current.candidate, testPolicy: testPolicy)
        } else {
            outcome = try VPNSelectedCandidateFinalizer.reconcileCompleted(
                store: store, runtime: runtime, lease: lease, budget: budget,
                transactionID: current.transactionID,
                expectedRevision: current.revision,
                candidate: current.candidate, testPolicy: testPolicy)
        }
        try retireCompleted(store: store, lease: lease,
                            transactionID: current.transactionID,
                            expectedRevision: 3, candidate: current.candidate)
        return outcome
    }

    /// Retires only an exact completed transaction whose selected deployment is
    /// still candidate B. The caller must already hold a fresh readiness or
    /// explicit desired-off receipt under this same lifecycle lease.
    static func retireCompleted(store: VPNReleaseStore, lease: VPNLifecycleLease,
                                transactionID: UUID, expectedRevision: UInt64,
                                candidate: VPNAuthorizedDeployment) throws {
        try lease.check()
        guard let completed = try store.loadUpdateJournal(),
              completed.transactionID == transactionID,
              completed.revision == expectedRevision,
              completed.phase == .completed,
              completed.recovery == .completed,
              completed.candidate.ownerUserID == candidate.ownerUserID,
              completed.candidate.release.isSameRelease(as: candidate.release) else {
            throw VPNSelectedCandidateRecoveryError.invalidJournal
        }
        do {
            try store.retireUpdateJournal(transactionID: completed.transactionID,
                                          expectedRevision: completed.revision)
            try lease.check()
            let selected = try store.loadDeployment()
            guard try store.loadUpdateJournal() == nil,
                  selected.ownerUserID == candidate.ownerUserID,
                  selected.release.isSameRelease(as: candidate.release) else {
                throw VPNSelectedCandidateRecoveryError.retirementUncertain
            }
        } catch {
            throw VPNSelectedCandidateRecoveryError.retirementUncertain
        }
    }
}
