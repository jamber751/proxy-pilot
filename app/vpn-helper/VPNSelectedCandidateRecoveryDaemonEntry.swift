import Darwin
import Dispatch
import Foundation

/// Fixed recovery role for the protected, content-addressed candidate helper.
/// A future launchd recovery job may execute this binary safely: unlike an app
/// path in /Applications, the helper is already rooted in the protected store.
/// The role accepts no transaction, release, owner, path or desired state.
enum VPNSelectedCandidateRecoveryDaemonEntry {
    static func runIfRequested(arguments: [String]) -> Int32? {
        guard requested(arguments) else { return nil }
        guard getuid() == 0, geteuid() == 0 else { return 77 }
        do {
            let authority = try VPNReleaseTrust.authority()
            let directory = try VPNDirectoryProvisioner.openSystemDirectory(create: false)
            defer { close(directory) }
            return try run(
                directory: directory, authority: authority,
                currentPolicy: { try $0.helperPolicy() },
                installedApplication: { try VPNInstalledApplication.inspect(release: $0) },
                runtime: { try VPNLaunchdRuntime.system(storageDirectory: $0) },
                completeCleanup: { service, lease in
                    try VPNJointUpdateCleanup.completeSystem(
                        service: service, lease: lease, authority: authority)
                },
                removeRecoveryJob: { service, deadline in
                    let recovery = try VPNRecoveryLaunchdJob.system(storageDirectory: service)
                    try recovery.removeCurrent(deadline: deadline)
                }, testPolicy: false)
        } catch { return status(error) }
    }

    #if VPN_RECOVERY_DAEMON_TESTING
    /// Unprivileged launchd integration seam. All mutable locations arrive as
    /// already-open disposable descriptors and this code is absent in release builds.
    static func testRunIfRequested(
        arguments: [String], directory: Int32,
        authority: VPNReleaseAuthority, applicationsDirectory: Int32,
        runtime: @escaping (Int32) throws -> VPNActivationRuntime,
        completeCleanup: @escaping (Int32, VPNLifecycleLease) throws -> Void = { _, _ in },
        removeRecoveryJob: @escaping (Int32, UInt64) throws -> Void
    ) -> Int32? {
        guard requested(arguments) else { return nil }
        guard getuid() != 0, getuid() == geteuid() else { return 77 }
        do {
            return try run(
                directory: directory, authority: authority,
                currentPolicy: { try $0.testHelperPolicy() },
                installedApplication: {
                    try VPNInstalledApplication.testInspect(
                        inApplicationsDirectory: applicationsDirectory, release: $0)
                }, runtime: runtime, completeCleanup: completeCleanup,
                removeRecoveryJob: removeRecoveryJob, testPolicy: true)
        } catch { return status(error) }
    }
    #endif

    private static func requested(_ arguments: [String]) -> Bool {
        arguments.count == 3
            && arguments[1] == VPNRecoveryLaunchdJob.recoveryArgument
            && arguments[2] == VPNRecoveryLaunchdJob.storagePath
    }

    private static func run(
        directory: Int32, authority: VPNReleaseAuthority,
        currentPolicy: (VerifiedVPNRelease) throws -> VPNPeerPolicy,
        installedApplication: (VerifiedVPNRelease) throws -> VPNInstalledApplication,
        runtime: (Int32) throws -> VPNActivationRuntime,
        completeCleanup: (Int32, VPNLifecycleLease) throws -> Void,
        removeRecoveryJob: (Int32, UInt64) throws -> Void,
        testPolicy: Bool
    ) throws -> Int32 {
        let store = try VPNReleaseStore(trustedDirectoryDescriptor: directory,
                                        authority: authority)
        guard var journal = try store.loadUpdateJournal() else {
            let selected = try store.loadDeployment()
            try VPNPeerAuthentication.validateCurrentProcess(
                policy: currentPolicy(selected.release))
            let lease = try VPNLifecycleOwnership.acquire(inTrustedDirectory: directory)
            defer { lease.release() }
            try completeCleanup(directory, lease)
            try VPNSelectedCandidateRecovery.cleanRetiredRecoveryJob(
                store: store, lease: lease, selected: selected) {
                    try removeRecoveryJob(
                        directory,
                        DispatchTime.now().uptimeNanoseconds + 2_000_000_000)
                }
            return 0
        }
        let armed = journal.phase == .replacementPending && journal.recovery == .inspectApplication
        let recoverable = journal.phase == .replacementPending && journal.recovery == .recoverCandidate
            || journal.phase == .selected && journal.recovery == .recoverCandidate
            || journal.phase == .completed && journal.recovery == .completed
        guard armed || recoverable else { return 0 }
        try VPNPeerAuthentication.validateCurrentProcess(
            policy: currentPolicy(journal.candidate.release))
        let installed = try installedApplication(journal.candidate.release)
        if armed {
            let transactionID = journal.transactionID
            let candidate = journal.candidate.release
            let deadline = DispatchTime.now().uptimeNanoseconds + 30_000_000_000
            while journal.phase == .replacementPending && journal.recovery == .inspectApplication {
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
        let activationRuntime = try runtime(directory)
        let budget = try VPNActivationBudget(trustedDirectoryDescriptor: directory)
        _ = try VPNSelectedCandidateRecovery.recover(
            store: store, runtime: activationRuntime, lease: lease, budget: budget,
            journal: journal, testPolicy: testPolicy,
            retiredCleanup: { outcome in
                guard outcome == .remainedOff else { return }
                try completeCleanup(directory, lease)
                try VPNSelectedCandidateRecovery.cleanRetiredRecoveryJob(
                    store: store, lease: lease, selected: journal.candidate) {
                        try removeRecoveryJob(
                            directory,
                            DispatchTime.now().uptimeNanoseconds + 2_000_000_000)
                    }
            })
        return 0
    }

    private static func status(_ error: Error) -> Int32 {
        switch error {
        case VPNLifecycleOwnershipError.busy:
            return 75
        case VPNActivationBudgetError.turnedOff,
             VPNActivationBudgetError.exhausted:
            return 0
        case let error as VPNSelectedCandidateFinalizerError:
            switch error {
            case .invalidJournal: return 0
            case .deadlineExceeded, .commitUncertain: return 75
            }
        case let error as VPNSelectedCandidateRecoveryError:
            switch error {
            case .invalidJournal: return 0
            case .retirementUncertain: return 75
            }
        case is VPNLaunchdError, is VPNHelperReadinessError:
            return 75
        default:
            return 0
        }
    }
}
