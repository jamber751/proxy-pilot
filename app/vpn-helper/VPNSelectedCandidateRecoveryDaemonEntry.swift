import Darwin
import Dispatch
import Foundation

/// Fixed recovery role for the protected, content-addressed candidate helper.
/// A future launchd recovery job may execute this binary safely: unlike an app
/// path in /Applications, the helper is already rooted in the protected store.
/// The role accepts no transaction, release, owner, path or desired state.
enum VPNSelectedCandidateRecoveryDaemonEntry {
    private enum EntryError: Error { case transientRetiredMaintenance }
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
            try retiredMaintenance {
                try completeCleanup(directory, lease)
                try VPNSelectedCandidateRecovery.cleanRetiredRecoveryJob(
                    store: store, lease: lease, selected: selected) {
                        try removeRecoveryJob(
                            directory,
                            DispatchTime.now().uptimeNanoseconds + 2_000_000_000)
                    }
            }
            return 0
        }
        let sourceRecoverable = journal.phase == .prepared && journal.recovery == .canCancelOrReplace
            || journal.phase == .replacementPending && journal.recovery == .inspectApplication
        let cancelled = journal.phase == .cancelled && journal.recovery == .cancelled
        let recoverable = journal.phase == .replacementPending && journal.recovery == .recoverCandidate
            || journal.phase == .selected && journal.recovery == .recoverCandidate
            || journal.phase == .completed && journal.recovery == .completed
        guard sourceRecoverable || cancelled || recoverable else { return 0 }
        try VPNPeerAuthentication.validateCurrentProcess(
            policy: currentPolicy(journal.candidate.release))
        let lease = try VPNLifecycleOwnership.acquire(inTrustedDirectory: directory)
        defer { lease.release() }
        guard let fresh = try store.loadUpdateJournal(),
              fresh.transactionID == journal.transactionID,
              fresh.revision == journal.revision,
              fresh.phase == journal.phase,
              fresh.recovery == journal.recovery,
              fresh.previous.ownerUserID == journal.previous.ownerUserID,
              fresh.candidate.ownerUserID == journal.candidate.ownerUserID,
              fresh.previous.release.isSameRelease(as: journal.previous.release),
              fresh.candidate.release.isSameRelease(as: journal.candidate.release) else {
            return 0
        }
        journal = fresh
        if cancelled {
            try removeRecoveryJob(
                directory, DispatchTime.now().uptimeNanoseconds + 2_000_000_000)
            return 0
        }

        var installed: VPNInstalledApplication
        if sourceRecoverable {
            if let candidate = try? installedApplication(journal.candidate.release) {
                // Exact B with a still-source selector means the app exchange
                // committed but the updater died before selector commit. Only
                // replacementPending is forward recoverable; prepared+B is an
                // impossible/hostile state and remains untouched.
                guard journal.phase == .replacementPending else { return 0 }
                try candidate.revalidate()
                journal = try store.selectUpdateCandidate(
                    transactionID: journal.transactionID,
                    expectedRevision: journal.revision)
                installed = candidate
            } else {
                let previous = try installedApplication(journal.previous.release)
                try reconcilePrevious(
                    store: store, runtime: try runtime(directory), lease: lease,
                    budget: VPNActivationBudget(trustedDirectoryDescriptor: directory),
                    journal: journal, installed: previous)
                try removeRecoveryJob(
                    directory, DispatchTime.now().uptimeNanoseconds + 2_000_000_000)
                return 0
            }
        } else {
            installed = try installedApplication(journal.candidate.release)
        }
        try installed.revalidate()
        let activationRuntime = try runtime(directory)
        let budget = try VPNActivationBudget(trustedDirectoryDescriptor: directory)
        #if VPN_RECOVERY_DAEMON_TESTING
        _ = try VPNSelectedCandidateRecovery.recover(
            store: store, runtime: activationRuntime, lease: lease, budget: budget,
            journal: journal, testPolicy: testPolicy,
            retiredCleanup: { outcome in
                guard outcome == .remainedOff else { return }
                try retiredMaintenance {
                    try completeCleanup(directory, lease)
                    try VPNSelectedCandidateRecovery.cleanRetiredRecoveryJob(
                        store: store, lease: lease, selected: journal.candidate) {
                            try removeRecoveryJob(
                                directory,
                                DispatchTime.now().uptimeNanoseconds + 2_000_000_000)
                        }
                }
            })
        #else
        var brokerCompletion: VPNUpdateBrokerRotation.Completion?
        _ = try VPNSelectedCandidateRecovery.recover(
            store: store, runtime: activationRuntime, lease: lease, budget: budget,
            journal: journal, testPolicy: testPolicy,
            beforeJournalRetirement: { completed in
                brokerCompletion = try VPNUpdateBrokerRotation.rotateIfRequired(
                    serviceDirectory: directory, store: store, lease: lease,
                    journal: completed, authority: authority)
            }, afterJournalRetirement: { _, lease in
                if let brokerCompletion {
                    try VPNUpdateBrokerRotation.finish(
                        brokerCompletion, serviceDirectory: directory,
                        lease: lease, authority: authority)
                }
            }, retiredCleanup: { outcome in
                guard outcome == .remainedOff else { return }
                try retiredMaintenance {
                    try completeCleanup(directory, lease)
                    try VPNSelectedCandidateRecovery.cleanRetiredRecoveryJob(
                        store: store, lease: lease, selected: journal.candidate) {
                            try removeRecoveryJob(
                                directory,
                                DispatchTime.now().uptimeNanoseconds + 2_000_000_000)
                        }
                }
            })
        #endif
        return 0
    }

    /// Restores exact A after a crash before B became authoritative. The signed
    /// journal remains prepared/pending and resumable; this method changes
    /// neither selector nor journal. Manual-off remains off, and automatic
    /// restart is charged before launch so a broken A cannot loop forever.
    private static func reconcilePrevious(
        store: VPNReleaseStore, runtime: VPNActivationRuntime,
        lease: VPNLifecycleLease, budget: VPNActivationBudget,
        journal: VPNUpdateJournalSnapshot, installed: VPNInstalledApplication
    ) throws {
        try lease.check()
        let selected = try store.loadDeployment()
        guard selected.ownerUserID == journal.previous.ownerUserID,
              selected.release.isSameRelease(as: journal.previous.release) else {
            throw VPNSelectedCandidateRecoveryError.invalidJournal
        }
        try installed.revalidate()
        let deadline = DispatchTime.now().uptimeNanoseconds + 5_000_000_000
        try runtime.stopAndDrain(deadline: deadline)
        let state = try budget.snapshot()
        if state.desired {
            try budget.beginAttempt(intent: .automatic)
            var socket: Int32 = -1
            do {
                socket = try runtime.startIdleAndConnect(journal.previous, deadline: deadline)
                let now = DispatchTime.now().uptimeNanoseconds
                guard now < deadline else { throw VPNLaunchdError.timeout }
                let remaining = max(1, min(2000, Int((deadline - now) / 1_000_000)))
                // The readiness probe owns and closes the descriptor on every
                // result. Clear our fallback owner before handing it over so a
                // failed probe cannot close a subsequently reused descriptor.
                let probeSocket = socket
                socket = -1
                #if VPN_HELPER_READINESS_TESTING
                _ = try VPNHelperReadiness.testProbe(
                    takingSocket: probeSocket, release: journal.previous.release,
                    timeoutMilliseconds: remaining)
                #else
                _ = try VPNHelperReadiness.probe(
                    takingSocket: probeSocket, release: journal.previous.release,
                    timeoutMilliseconds: remaining)
                #endif
                try lease.check()
                try installed.revalidate()
                let currentSelection = try store.loadDeployment()
                guard let current = try store.loadUpdateJournal(),
                      current.transactionID == journal.transactionID,
                      current.revision == journal.revision,
                      current.phase == journal.phase,
                      current.recovery == journal.recovery,
                      currentSelection.ownerUserID == journal.previous.ownerUserID,
                      currentSelection.release.isSameRelease(as: journal.previous.release) else {
                    throw VPNSelectedCandidateRecoveryError.invalidJournal
                }
                try budget.recordSuccess()
            } catch {
                if socket >= 0 { close(socket) }
                try? runtime.stopAndDrain(
                    deadline: DispatchTime.now().uptimeNanoseconds + 2_000_000_000)
                throw error
            }
        }
        try lease.check()
    }

    /// Once the transaction is durably retired, an uncertain maintenance
    /// failure must keep the recovery job retryable. Authenticated evidence
    /// mismatches remain permanent refusals and must not create a retry loop.
    private static func retiredMaintenance(_ work: () throws -> Void) throws {
        do { try work() }
        catch let error as VPNSelectedCandidateRecoveryError {
            throw error
        } catch let error as VPNReleaseStoreError {
            switch error {
            case .invalidState, .deploymentRequired, .invalidUpdateJournal,
                 .invalidCleanupReceipt, .invalidUpdatePreparation,
                 .alreadyInitialized, .staleRevision:
                throw error
            default:
                throw EntryError.transientRetiredMaintenance
            }
        } catch let error as VPNDirectoryError {
            switch error {
            case .requiresRoot, .unsafeDirectory: throw error
            case .unavailable, .syncUncertain: throw EntryError.transientRetiredMaintenance
            }
        } catch let error as VPNJointUpdateCleanupError {
            switch error {
            case .requiresRoot, .unsafeStorage, .invalidLayout: throw error
            case .commitUncertain: throw EntryError.transientRetiredMaintenance
            }
        } catch is VPNLaunchdError {
            throw EntryError.transientRetiredMaintenance
        } catch let error as VPNReleaseAuthorizationError {
            throw error
        } catch let error as VPNStagedApplicationError {
            throw error
        } catch {
            throw EntryError.transientRetiredMaintenance
        }
    }

    private static func status(_ error: Error) -> Int32 {
        switch error {
        case EntryError.transientRetiredMaintenance:
            return 75
        case VPNLifecycleOwnershipError.busy:
            return 75
        case VPNActivationBudgetError.turnedOff,
             VPNActivationBudgetError.exhausted:
            return 0
        case VPNActivationBudgetError.writeFailed:
            return 75
        case VPNReleaseStoreError.busy,
             VPNReleaseStoreError.writeFailed,
             VPNReleaseStoreError.commitUncertain:
            return 75
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
