import Darwin
import Dispatch
import Foundation

/// Fixed recovery role for the protected, content-addressed candidate helper.
/// A future launchd recovery job may execute this binary safely: unlike an app
/// path in /Applications, the helper is already rooted in the protected store.
/// The role accepts no transaction, release, owner, path or desired state.
enum VPNSelectedCandidateRecoveryDaemonEntry {
    static func runIfRequested(arguments: [String]) -> Int32? {
        guard arguments.count == 3,
              arguments[1] == VPNRecoveryLaunchdJob.recoveryArgument,
              arguments[2] == VPNRecoveryLaunchdJob.storagePath else { return nil }
        guard getuid() == 0, geteuid() == 0 else { return 77 }
        do {
            let authority = try VPNReleaseTrust.authority()
            let directory = try VPNDirectoryProvisioner.openSystemDirectory(create: false)
            defer { close(directory) }
            let store = try VPNReleaseStore(trustedDirectoryDescriptor: directory,
                                            authority: authority)
            guard var journal = try store.loadUpdateJournal() else {
                // Retirement is durable before self-removal. If bootout failed,
                // KeepAlive invokes us again with no journal; only the exact
                // selected helper may finish this stale-job maintenance.
                let selected = try store.loadDeployment()
                try VPNPeerAuthentication.validateCurrentProcess(
                    policy: selected.release.helperPolicy())
                let lease = try VPNLifecycleOwnership.acquire(inTrustedDirectory: directory)
                defer { lease.release() }
                try VPNJointUpdateCleanup.completeSystem(
                    service: directory, lease: lease, authority: authority)
                try VPNSelectedCandidateRecovery.cleanRetiredRecoveryJob(
                    store: store, lease: lease, selected: selected) {
                        let recovery = try VPNRecoveryLaunchdJob.system(
                            storageDirectory: directory)
                        try recovery.removeCurrent(
                            deadline: DispatchTime.now().uptimeNanoseconds + 2_000_000_000)
                    }
                return 0
            }
            let armed = journal.phase == .replacementPending && journal.recovery == .inspectApplication
            let recoverable = journal.phase == .replacementPending && journal.recovery == .recoverCandidate
                || journal.phase == .selected && journal.recovery == .recoverCandidate
                || journal.phase == .completed && journal.recovery == .completed
            guard armed || recoverable else { return 0 }
            try VPNPeerAuthentication.validateCurrentProcess(
                policy: journal.candidate.release.helperPolicy())
            let installed = try VPNInstalledApplication.inspect(
                release: journal.candidate.release)
            // The recovery job is bootstrapped immediately before B proves
            // itself and commits the selector. Its first RunAtLoad invocation
            // therefore waits briefly for that exact journal to advance. This
            // closes the post-selector crash window without WatchPaths, whose
            // events are explicitly lossy/racy. A timeout while A still owns
            // the transaction is a successful no-op; source-A recovery owns it.
            if armed {
                let transactionID = journal.transactionID
                let candidate = journal.candidate.release
                let deadline = DispatchTime.now().uptimeNanoseconds + 30_000_000_000
                while journal.phase == .replacementPending && journal.recovery == .inspectApplication {
                    // Stay retryable until A either advances or cancels the
                    // durable transaction. A successful exit here would leave
                    // launchd dormant and reopen the post-selector crash gap.
                    guard DispatchTime.now().uptimeNanoseconds < deadline else { return 75 }
                    usleep(100_000)
                    guard let fresh = try store.loadUpdateJournal() else { return 0 }
                    guard fresh.transactionID == transactionID,
                          fresh.candidate.release.isSameRelease(as: candidate) else { return 0 }
                    journal = fresh
                }
                let advanced = journal.phase == .replacementPending && journal.recovery == .recoverCandidate
                    || journal.phase == .selected && journal.recovery == .recoverCandidate
                    || journal.phase == .completed && journal.recovery == .completed
                guard advanced else { return 0 }
            }
            let lease = try VPNLifecycleOwnership.acquire(inTrustedDirectory: directory)
            defer { lease.release() }
            try installed.revalidate()
            let runtime = try VPNLaunchdRuntime.system(storageDirectory: directory)
            let budget = try VPNActivationBudget(trustedDirectoryDescriptor: directory)
            _ = try VPNSelectedCandidateRecovery.recover(
                store: store, runtime: runtime, lease: lease, budget: budget,
                journal: journal,
                retiredCleanup: { outcome in
                    guard outcome == .remainedOff else { return }
                    try VPNJointUpdateCleanup.completeSystem(
                        service: directory, lease: lease, authority: authority)
                    try VPNSelectedCandidateRecovery.cleanRetiredRecoveryJob(
                        store: store, lease: lease, selected: journal.candidate) {
                            let recovery = try VPNRecoveryLaunchdJob.system(
                                storageDirectory: directory)
                            try recovery.removeCurrent(
                                deadline: DispatchTime.now().uptimeNanoseconds + 2_000_000_000)
                        }
                })
            return 0
        } catch VPNLifecycleOwnershipError.busy {
            // A still-live coordinator owns this attempt. The launchd recovery
            // job may retry without treating contention as corruption.
            return 75
        } catch VPNActivationBudgetError.turnedOff,
                VPNActivationBudgetError.exhausted {
            return 0
        } catch let error as VPNSelectedCandidateFinalizerError {
            switch error {
            case .invalidJournal: return 0
            case .deadlineExceeded, .commitUncertain: return 75
            }
        } catch let error as VPNSelectedCandidateRecoveryError {
            switch error {
            case .invalidJournal: return 0
            case .retirementUncertain: return 75
            }
        } catch is VPNLaunchdError, is VPNHelperReadinessError {
            return 75
        } catch {
            // Invalid policy, damaged storage, missing installed B and corrupt
            // records require a new external event or explicit repair. A
            // launchd keepalive must not spin forever on permanent state.
            return 0
        }
    }
}
