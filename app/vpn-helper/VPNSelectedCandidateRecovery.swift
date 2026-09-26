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
        let recoverable = initial.phase == .selected && initial.recovery == .recoverCandidate
            || initial.phase == .completed && initial.recovery == .completed
        guard recoverable else {
            throw VPNSelectedCandidateRecoveryError.invalidJournal
        }
        let outcome: VPNSelectedCandidateFinalizer.Outcome
        if initial.phase == .selected {
            outcome = try VPNSelectedCandidateFinalizer.finish(
                store: store, runtime: runtime, lease: lease, budget: budget,
                transactionID: initial.transactionID,
                expectedRevision: initial.revision,
                candidate: initial.candidate, testPolicy: testPolicy)
        } else {
            outcome = try VPNSelectedCandidateFinalizer.reconcileCompleted(
                store: store, runtime: runtime, lease: lease, budget: budget,
                transactionID: initial.transactionID,
                expectedRevision: initial.revision,
                candidate: initial.candidate, testPolicy: testPolicy)
        }
        try lease.check()
        guard let completed = try store.loadUpdateJournal(),
              completed.transactionID == initial.transactionID,
              completed.revision == 3,
              completed.phase == .completed,
              completed.recovery == .completed,
              completed.candidate.ownerUserID == initial.candidate.ownerUserID,
              completed.candidate.release.isSameRelease(as: initial.candidate.release) else {
            throw VPNSelectedCandidateRecoveryError.invalidJournal
        }
        do {
            try store.retireUpdateJournal(transactionID: completed.transactionID,
                                          expectedRevision: completed.revision)
            try lease.check()
            let selected = try store.loadDeployment()
            guard try store.loadUpdateJournal() == nil,
                  selected.ownerUserID == initial.candidate.ownerUserID,
                  selected.release.isSameRelease(as: initial.candidate.release) else {
                throw VPNSelectedCandidateRecoveryError.retirementUncertain
            }
        } catch {
            throw VPNSelectedCandidateRecoveryError.retirementUncertain
        }
        return outcome
    }
}
