import Darwin
import Dispatch
import Foundation

enum VPNJointApplicationReplacementFailure: UInt8, Error {
    case applicationDestinationPreparation = 0x61
    case recoveryArm = 0x62
    case candidateProof = 0x63
    case candidateFinalization = 0x64
    case journalRetirement = 0x65
    case applicationDestinationRecheck = 0x66
    case applicationDestinationCommit = 0x67
    case applicationDestinationPostCommitSync = 0x68
    case applicationDestinationProtectedValidation = 0x69
    case applicationDestinationIdentityValidation = 0x6a
    case applicationDestinationCandidateInspection = 0x6b
    case applicationDestinationPreviousInspection = 0x6c
    case applicationDestinationCandidateRevalidation = 0x6d
    case applicationDestinationPreviousRevalidation = 0x6e

    var diagnosticByte: UInt8 {
        rawValue
    }

    var label: String {
        switch self {
        case .applicationDestinationPreparation: return "applicationDestinationPreparation"
        case .recoveryArm: return "recoveryArm"
        case .candidateProof: return "candidateProof"
        case .candidateFinalization: return "candidateFinalization"
        case .journalRetirement: return "journalRetirement"
        case .applicationDestinationRecheck: return "applicationDestinationRecheck"
        case .applicationDestinationCommit: return "applicationDestinationCommit"
        case .applicationDestinationPostCommitSync: return "applicationDestinationPostCommitSync"
        case .applicationDestinationProtectedValidation: return "applicationDestinationProtectedValidation"
        case .applicationDestinationIdentityValidation: return "applicationDestinationIdentityValidation"
        case .applicationDestinationCandidateInspection: return "applicationDestinationCandidateInspection"
        case .applicationDestinationPreviousInspection: return "applicationDestinationPreviousInspection"
        case .applicationDestinationCandidateRevalidation: return "applicationDestinationCandidateRevalidation"
        case .applicationDestinationPreviousRevalidation: return "applicationDestinationPreviousRevalidation"
        }
    }
}

/// Journal-authorized replacement boundary. The legacy entry exchanges only
/// protected copies; the production executor entry also installs exact B into
/// Applications. The executor must be exact A in its separate fixed slot, with
/// protected ancestry supplied by a trusted caller. The full production entry
/// proves live app B, selects B, restores idle-helper availability according to
/// the durable activation intent, and records completion. It never applies a
/// VPN profile, routes, DNS, or changes the user's desired-on/off state.
enum VPNJointApplicationReplacement {
    static func exchangePreparedCopies(applicationDirectory: Int32, transactionID: UUID,
                                       expectedRevision: UInt64, authority: VPNReleaseAuthority) throws
        -> VPNProtectedApplicationSwap.Outcome {
        guard getuid() == 0, geteuid() == 0 else { throw VPNInstallerError.requiresRoot }
        try VPNDirectoryProvisioner.requireSystemUpdateDirectory(applicationDirectory)
        let directory = try VPNDirectoryProvisioner.openSystemDirectory(create: false)
        defer { close(directory) }
        return try perform(applicationDirectory: applicationDirectory, transactionID: transactionID,
                           expectedRevision: expectedRevision, authority: authority, directory: directory,
                           testPolicy: false, destination: nil,
                           runtime: { try VPNLaunchdRuntime.system(storageDirectory: directory) })
    }

    /// Completes replacement and readiness while the journal and stopped-service
    /// authority remain held. It never applies profile/routes/DNS.
    static func installPreparedApplication(applicationDirectory: Int32, transactionID: UUID,
                                           expectedRevision: UInt64,
                                           authority: VPNReleaseAuthority) throws
        -> VPNProtectedApplicationSwap.Outcome {
        guard getuid() == 0, geteuid() == 0 else { throw VPNInstallerError.requiresRoot }
        try VPNDirectoryProvisioner.requireSystemUpdateDirectory(applicationDirectory)
        let directory = try VPNDirectoryProvisioner.openSystemDirectory(create: false)
        defer { close(directory) }
        return try perform(applicationDirectory: applicationDirectory, transactionID: transactionID,
                           expectedRevision: expectedRevision, authority: authority, directory: directory,
                           testPolicy: false, destination: nil, installDestination: true,
                           runtime: { try VPNLaunchdRuntime.system(storageDirectory: directory) })
    }

    /// Candidate B may hand a still-prepared transaction to exact executor A.
    /// A validates both protected copies first; the same service lease then
    /// covers drain, prepared→replacementPending and every replacement step.
    static func installPreparedOrPendingApplication(
        applicationDirectory: Int32, transactionID: UUID,
        expectedRevision: UInt64, authority: VPNReleaseAuthority) throws
        -> VPNProtectedApplicationSwap.Outcome {
        guard getuid() == 0, geteuid() == 0 else {
            throw VPNInstallerError.requiresRoot
        }
        try VPNDirectoryProvisioner.requireSystemUpdateDirectory(applicationDirectory)
        let directory = try VPNDirectoryProvisioner.openSystemDirectory(create: false)
        defer { close(directory) }
        return try perform(
            applicationDirectory: applicationDirectory,
            transactionID: transactionID, expectedRevision: expectedRevision,
            authority: authority, directory: directory, testPolicy: false,
            destination: nil, installDestination: true, beginPrepared: true,
            runtime: { try VPNLaunchdRuntime.system(storageDirectory: directory) })
    }

    #if VPN_INSTALLER_TESTING && VPN_APPLICATION_SWAP_TESTING
    static func testExchangePreparedCopies(applicationDirectory: Int32, transactionID: UUID,
                                           expectedRevision: UInt64, authority: VPNReleaseAuthority,
                                           base: Int32, runtime: (Int32) throws -> VPNActivationRuntime) throws
        -> VPNProtectedApplicationSwap.Outcome {
        guard getuid() != 0, geteuid() == getuid() else { throw VPNPeerAuthenticationError.denied }
        let directory = try VPNDirectoryProvisioner.openBelowTrustedBase(base, create: false)
        defer { close(directory) }
        return try perform(applicationDirectory: applicationDirectory, transactionID: transactionID,
                           expectedRevision: expectedRevision, authority: authority, directory: directory,
                           testPolicy: true, destination: nil,
                           runtime: { try runtime(directory) })
    }

    #if VPN_APPLICATION_DESTINATION_TESTING
    static func testInstallPreparedApplication(applicationDirectory: Int32,
                                               destination: Int32,
                                               transactionID: UUID,
                                               expectedRevision: UInt64,
                                               authority: VPNReleaseAuthority,
                                               base: Int32,
                                               runtime: (Int32) throws -> VPNActivationRuntime) throws
        -> VPNProtectedApplicationSwap.Outcome {
        guard getuid() != 0, geteuid() == getuid() else { throw VPNPeerAuthenticationError.denied }
        let directory = try VPNDirectoryProvisioner.openBelowTrustedBase(base, create: false)
        defer { close(directory) }
        return try perform(applicationDirectory: applicationDirectory, transactionID: transactionID,
                           expectedRevision: expectedRevision, authority: authority, directory: directory,
                           testPolicy: true, destination: destination, installDestination: true,
                           runtime: { try runtime(directory) })
    }

    static func testInstallPreparedOrPendingApplication(
        applicationDirectory: Int32, destination: Int32,
        transactionID: UUID, expectedRevision: UInt64,
        authority: VPNReleaseAuthority, base: Int32,
        runtime: (Int32) throws -> VPNActivationRuntime) throws
        -> VPNProtectedApplicationSwap.Outcome {
        guard getuid() != 0, geteuid() == getuid() else {
            throw VPNPeerAuthenticationError.denied
        }
        let directory = try VPNDirectoryProvisioner.openBelowTrustedBase(base, create: false)
        defer { close(directory) }
        return try perform(
            applicationDirectory: applicationDirectory,
            transactionID: transactionID, expectedRevision: expectedRevision,
            authority: authority, directory: directory, testPolicy: true,
            destination: destination, installDestination: true,
            beginPrepared: true, runtime: { try runtime(directory) })
    }
    #endif
    #endif

    private static func perform(applicationDirectory: Int32, transactionID: UUID,
                                expectedRevision: UInt64, authority: VPNReleaseAuthority,
                                directory: Int32, testPolicy: Bool,
                                destination: Int32?, installDestination: Bool = false,
                                beginPrepared: Bool = false,
                                runtime: () throws -> VPNActivationRuntime) throws -> VPNProtectedApplicationSwap.Outcome {
        // Two distinct locks, always service first, then app namespace.
        var serviceInfo = stat(), applicationInfo = stat()
        guard fstat(directory, &serviceInfo) == 0, fstat(applicationDirectory, &applicationInfo) == 0,
              serviceInfo.st_dev != applicationInfo.st_dev || serviceInfo.st_ino != applicationInfo.st_ino else {
            throw VPNApplicationSwapError.unsafeStorage
        }
        let lease = try VPNLifecycleOwnership.acquire(inTrustedDirectory: directory)
        defer { lease.release() }
        let store = try VPNReleaseStore(trustedDirectoryDescriptor: directory, authority: authority)

        func authenticated(_ revision: UInt64) throws -> VPNUpdateJournalSnapshot {
            try lease.check()
            guard let journal = try store.loadUpdateJournal() else { throw VPNReleaseStoreError.invalidUpdateJournal }
            guard journal.transactionID == transactionID, journal.revision == revision else {
                throw VPNReleaseStoreError.staleRevision
            }
            #if VPN_INSTALLER_TESTING && VPN_APPLICATION_SWAP_TESTING
            if testPolicy {
                try VPNPeerAuthentication.validateCurrentProcess(
                    policy: journal.previous.release.clientPolicy(forTrustedUserID: journal.previous.ownerUserID))
            } else {
                try VPNPeerAuthentication.validateCurrentProcess(policy: journal.previous.release.installerPolicy())
            }
            #else
            _ = testPolicy
            try VPNPeerAuthentication.validateCurrentProcess(policy: journal.previous.release.installerPolicy())
            #endif
            try lease.check()
            return journal
        }

        let initial = try authenticated(expectedRevision)
        let beginsPrepared = initial.phase == .prepared
            && initial.recovery == .canCancelOrReplace && beginPrepared
        guard beginsPrepared || (initial.phase == .replacementPending
                && initial.recovery == .inspectApplication) else {
            throw VPNReleaseStoreError.invalidUpdateJournal
        }
        var replacementPending = !beginsPrepared
        var activeRevision = initial.revision
        func recheck() throws {
            let fresh = try authenticated(activeRevision)
            let phaseMatches = replacementPending
                ? fresh.phase == .replacementPending && fresh.recovery == .inspectApplication
                : fresh.phase == .prepared && fresh.recovery == .canCancelOrReplace
            guard phaseMatches else { throw VPNReleaseStoreError.invalidUpdateJournal }
            guard fresh.previous.ownerUserID == initial.previous.ownerUserID,
                  fresh.previous.release.isSameRelease(as: initial.previous.release),
                  fresh.candidate.release.isSameRelease(as: initial.candidate.release) else {
                throw VPNReleaseStoreError.invalidUpdateJournal
            }
        }
        func selectedContext() throws {
            try lease.check()
            guard let fresh = try store.loadUpdateJournal(),
                  fresh.transactionID == initial.transactionID,
                  fresh.revision == activeRevision + 1,
                  fresh.phase == .selected,
                  fresh.recovery == .recoverCandidate,
                  fresh.previous.ownerUserID == initial.previous.ownerUserID,
                  fresh.previous.release.isSameRelease(as: initial.previous.release),
                  fresh.candidate.release.isSameRelease(as: initial.candidate.release) else {
                throw VPNReleaseStoreError.invalidUpdateJournal
            }
            try lease.check()
        }
        func selectCandidate() throws {
            try recheck()
            _ = try store.selectUpdateCandidate(
                transactionID: initial.transactionID,
                expectedRevision: activeRevision)
            try selectedContext()
        }
        func completedContext() throws {
            try lease.check()
            guard let fresh = try store.loadUpdateJournal(),
                  fresh.transactionID == initial.transactionID,
                  fresh.revision == activeRevision + 2,
                  fresh.phase == .completed,
                  fresh.recovery == .completed,
                  fresh.candidate.release.isSameRelease(as: initial.candidate.release) else {
                throw VPNReleaseStoreError.invalidUpdateJournal
            }
            try lease.check()
        }
        var adapter: VPNActivationRuntime?
        var drained = false
        func authorizeMutation() throws {
            try recheck()
            if !drained {
                // Invalid staged copies must never interrupt the service. Construct
                // the adapter lazily, only after the swap validated both trees.
                let created = try runtime()
                adapter = created
                try recheck()
                let deadline = DispatchTime.now().uptimeNanoseconds + 20_000_000_000
                try created.stopAndDrain(deadline: deadline)
                guard DispatchTime.now().uptimeNanoseconds < deadline else { throw VPNLaunchdError.timeout }
                drained = true
                if !replacementPending {
                    let advanced = try store.markUpdateReplacementPending(
                        transactionID: initial.transactionID,
                        expectedRevision: activeRevision)
                    guard advanced.phase == .replacementPending,
                          advanced.recovery == .inspectApplication,
                          advanced.revision == activeRevision + 1 else {
                        throw VPNReleaseStoreError.invalidUpdateJournal
                    }
                    activeRevision = advanced.revision
                    replacementPending = true
                }
            }
            _ = adapter
            try recheck()
        }
        let outcome: VPNProtectedApplicationSwap.Outcome
        #if VPN_INSTALLER_TESTING && VPN_APPLICATION_SWAP_TESTING
        if testPolicy {
            outcome = try VPNProtectedApplicationSwap.testExchange(inTrustedDirectory: applicationDirectory,
                previous: initial.previous.release, candidate: initial.candidate.release,
                transition: initial.transition, requireProtectedExecutor: true, authorizeMutation: authorizeMutation)
        } else {
            outcome = try VPNProtectedApplicationSwap.exchange(inTrustedDirectory: applicationDirectory,
                previous: initial.previous.release, candidate: initial.candidate.release,
                transition: initial.transition, authorizeMutation: authorizeMutation)
        }
        #else
        outcome = try VPNProtectedApplicationSwap.exchange(inTrustedDirectory: applicationDirectory,
            previous: initial.previous.release, candidate: initial.candidate.release,
            transition: initial.transition, authorizeMutation: authorizeMutation)
        #endif
        // The rename may already have committed. Never reverse it on failure.
        do { try recheck() } catch { throw VPNApplicationSwapError.commitUncertain }
        guard installDestination else { return outcome }

        var failureStage = VPNJointApplicationReplacementFailure.applicationDestinationPreparation
        do {
            let destinationCheckpoint: (String) -> Void = { checkpoint in
                switch checkpoint {
                case "beforeExchange": failureStage = .applicationDestinationCommit
                case "afterExchange": failureStage = .applicationDestinationPostCommitSync
                case "afterSync": failureStage = .applicationDestinationProtectedValidation
                case "afterProtectedValidation": failureStage = .applicationDestinationIdentityValidation
                case "afterIdentityValidation": failureStage = .applicationDestinationCandidateInspection
                case "afterCandidateInspection": failureStage = .applicationDestinationPreviousInspection
                case "afterPreviousInspection": failureStage = .applicationDestinationCandidateRevalidation
                case "afterCandidateRevalidation": failureStage = .applicationDestinationPreviousRevalidation
                default: break
                }
            }
            let destinationOutcome: VPNApplicationDestinationExchange.Outcome
            #if VPN_APPLICATION_DESTINATION_TESTING
            if testPolicy {
                guard let destination else { throw VPNApplicationDestinationExchangeError.unsafeStorage }
                do {
                    destinationOutcome = try VPNApplicationDestinationExchange.testExchange(
                        inTrustedDirectory: applicationDirectory, destination: destination,
                        previous: initial.previous.release,
                        previousOwnerUserID: initial.previous.ownerUserID,
                        candidate: initial.candidate.release, transition: initial.transition,
                        requireExecutor: true, authorizeMutation: authorizeMutation)
                } catch VPNApplicationDestinationExchangeError.unsafeStorage {
                    _ = try VPNApplicationDestinationStage.testPrepare(
                        inTrustedDirectory: applicationDirectory, destination: destination,
                        release: initial.candidate.release)
                    destinationOutcome = try VPNApplicationDestinationExchange.testExchange(
                        inTrustedDirectory: applicationDirectory, destination: destination,
                        previous: initial.previous.release,
                        previousOwnerUserID: initial.previous.ownerUserID,
                        candidate: initial.candidate.release, transition: initial.transition,
                        requireExecutor: true, authorizeMutation: authorizeMutation)
                }
            } else {
                destinationOutcome = try installProductionDestination(
                    applicationDirectory: applicationDirectory, journal: initial,
                    authorizeMutation: authorizeMutation, checkpoint: destinationCheckpoint)
            }
            #else
            _ = destination
            destinationOutcome = try installProductionDestination(
                applicationDirectory: applicationDirectory, journal: initial,
                authorizeMutation: authorizeMutation, checkpoint: destinationCheckpoint)
            #endif
            failureStage = .applicationDestinationRecheck
            try recheck()
            if !testPolicy {
                // Arm the protected candidate helper before B is allowed to
                // commit the selector. If this process dies after selection,
                // launchd finishes readiness/reconciliation from the durable
                // journal without executing the mutable app path.
                failureStage = .recoveryArm
                let recovery = try VPNRecoveryLaunchdJob.system(storageDirectory: directory)
                try recovery.installAndArm(
                    initial.candidate,
                    deadline: DispatchTime.now().uptimeNanoseconds + 20_000_000_000)
                try recheck()
            }
            #if VPN_APPLICATION_DESTINATION_TESTING && VPN_INSTALLED_CANDIDATE_HANDOFF_TESTING
            if testPolicy {
                // The standalone handoff suite owns the disposable child role.
                // Joint tests use different synthetic A/B bundle seals and have
                // no production fixed store from which B can load A's policy.
                try recheck()
            } else {
                failureStage = .candidateProof
                try VPNInstalledCandidateHandoff.prove(
                    release: initial.candidate.release,
                    validatePending: recheck,
                    commitSelection: selectCandidate,
                    validateSelected: selectedContext)
            }
            #else
            failureStage = .candidateProof
            try VPNInstalledCandidateHandoff.prove(
                release: initial.candidate.release,
                validatePending: recheck,
                commitSelection: selectCandidate,
                validateSelected: selectedContext)
            #endif
            if testPolicy {
                try recheck()
            } else {
                try selectedContext()
                guard let adapter else { throw VPNLaunchdError.invalidConfiguration }
                let budget = try VPNActivationBudget(trustedDirectoryDescriptor: directory)
                failureStage = .candidateFinalization
                _ = try VPNSelectedCandidateFinalizer.finish(
                    store: store, runtime: adapter, lease: lease, budget: budget,
                    transactionID: initial.transactionID,
                    expectedRevision: activeRevision + 1,
                    candidate: initial.candidate)
                try completedContext()
                failureStage = .journalRetirement
                try VPNSelectedCandidateRecovery.retireCompleted(
                    store: store, lease: lease,
                    transactionID: initial.transactionID,
                    expectedRevision: activeRevision + 2,
                    candidate: initial.candidate)
            }
            return outcome == .exchanged || destinationOutcome == .exchanged
                ? .exchanged : .alreadyExchanged
        } catch {
            if !testPolicy {
                // The protected executor inherits only its authenticated socket
                // and directory descriptor. Report this allowlisted stage over
                // that socket; touching closed stdio would terminate Foundation
                // before the parent could receive the diagnostic.
                throw failureStage
            }
            #if VPN_INSTALLED_CANDIDATE_HANDOFF_TESTING
            FileHandle.standardError.write(Data("joint-install-rejected:\(error)\n".utf8))
            #endif
            throw VPNApplicationSwapError.commitUncertain
        }
    }

    private static func installProductionDestination(
        applicationDirectory: Int32, journal: VPNUpdateJournalSnapshot,
        authorizeMutation: () throws -> Void,
        checkpoint: (String) throws -> Void) throws
        -> VPNApplicationDestinationExchange.Outcome {
        do {
            return try VPNApplicationDestinationExchange.exchange(
                inTrustedDirectory: applicationDirectory,
                previous: journal.previous.release,
                previousOwnerUserID: journal.previous.ownerUserID,
                candidate: journal.candidate.release, transition: journal.transition,
                authorizeMutation: authorizeMutation, checkpoint: checkpoint)
        } catch VPNApplicationDestinationExchangeError.unsafeStorage {
            _ = try VPNApplicationDestinationStage.prepare(
                inTrustedDirectory: applicationDirectory,
                release: journal.candidate.release)
            return try VPNApplicationDestinationExchange.exchange(
                inTrustedDirectory: applicationDirectory,
                previous: journal.previous.release,
                previousOwnerUserID: journal.previous.ownerUserID,
                candidate: journal.candidate.release, transition: journal.transition,
                authorizeMutation: authorizeMutation, checkpoint: checkpoint)
        }
    }
}
