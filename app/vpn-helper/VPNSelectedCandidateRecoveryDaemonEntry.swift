import Darwin
import Foundation

/// Fixed recovery role for the protected, content-addressed candidate helper.
/// A future launchd recovery job may execute this binary safely: unlike an app
/// path in /Applications, the helper is already rooted in the protected store.
/// The role accepts no transaction, release, owner, path or desired state.
enum VPNSelectedCandidateRecoveryDaemonEntry {
    static let argument = "recover-update"

    static func runIfRequested(arguments: [String]) -> Int32? {
        guard arguments.count == 3, arguments[1] == argument,
              arguments[2] == VPNHelperDaemon.storagePath else { return nil }
        guard getuid() == 0, geteuid() == 0 else { return 77 }
        do {
            let authority = try VPNReleaseTrust.authority()
            let directory = try VPNDirectoryProvisioner.openSystemDirectory(create: false)
            defer { close(directory) }
            let store = try VPNReleaseStore(trustedDirectoryDescriptor: directory,
                                            authority: authority)
            guard let journal = try store.loadUpdateJournal() else { return 0 }
            let recoverable = journal.phase == .replacementPending && journal.recovery == .recoverCandidate
                || journal.phase == .selected && journal.recovery == .recoverCandidate
                || journal.phase == .completed && journal.recovery == .completed
            // Watch-based launch may observe prepared/pending journal writes.
            // Those states belong to source A and are a successful no-op here.
            guard recoverable else { return 0 }
            try VPNPeerAuthentication.validateCurrentProcess(
                policy: journal.candidate.release.helperPolicy())
            let installed = try VPNInstalledApplication.inspect(
                release: journal.candidate.release)
            let lease = try VPNLifecycleOwnership.acquire(inTrustedDirectory: directory)
            defer { lease.release() }
            try installed.revalidate()
            let runtime = try VPNLaunchdRuntime.system(storageDirectory: directory)
            let budget = try VPNActivationBudget(trustedDirectoryDescriptor: directory)
            _ = try VPNSelectedCandidateRecovery.recover(
                store: store, runtime: runtime, lease: lease, budget: budget,
                journal: journal)
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
