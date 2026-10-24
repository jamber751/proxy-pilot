import Darwin
import Dispatch
import Foundation

#if VPN_RESCUE_SYSTEM_ENTRY && VPN_EXPLICIT_RESCUE && VPN_RESCUE_PREPARATION
/// Fixed, separately signed repair role. All decisions come from the protected
/// store under its lifecycle lease; the package supplies only exact signed input.
/// Recovery waits occur after releasing the lease. The existing recovery job is
/// retained on every failure, including timeout and interrupted replacement.
enum VPNRescueSystemEntry {
    private enum Failure: Error { case invalidState, timeout }
    private enum Step { case advance, waitForRecovery, reconcileBroker, finished }
    private enum Leg { case first, second }
    private enum Phase: String {
        case verifyInputs, firstReplace, cleanup, secondPrepare, secondReplace
        case waitRecovery, reconcileBroker, verifyFinal, retireRecovery, success
    }
    private static let totalBudget: UInt64 = 300_000_000_000

    /// Type-only diagnostics: never interpolate Error descriptions, associated
    /// values, file names, release material, process arguments or user state.
    private enum ErrorCategory: String {
        case liveIdentity, preparationIdentity, directory, store, broker
        case destinationStage, destinationExchange, destinationLayout, destinationStorage, destinationUncertain
        case protectedSwap, cleanup
        case installedResult, launchd, authorization, ownership, package, state, timeout, other
    }
    private static func category(for error: Error) -> ErrorCategory {
        switch error {
        case is VPNRescueExecutorError, is VPNPeerAuthenticationError: return .liveIdentity
        case is VPNRescuePreparationContextError, is VPNRescuePreparationAuthorizationError: return .preparationIdentity
        case is VPNDirectoryError, is VPNEndpointError: return .directory
        case is VPNReleaseStoreError, is VPNActivationBudgetError: return .store
        case is VPNRescueBrokerCoordinator.Failure, is VPNUpdateBrokerError,
             is VPNUpdateBrokerTransactionStoreError, is VPNUpdateBrokerInboxError,
             is VPNUpdateBrokerLaunchdJobError, is VPNUpdateBrokerRotationError,
             is VPNUpdateBrokerStateRemovalError, is VPNUpdateBrokerStatusStoreError: return .broker
        case is VPNApplicationDestinationStageError, is VPNStagedApplicationError: return .destinationStage
        case let error as VPNApplicationDestinationExchangeError:
            switch error {
            case .invalidLayout: return .destinationLayout
            case .unsafeStorage: return .destinationStorage
            case .commitUncertain: return .destinationUncertain
            default: return .destinationExchange
            }
        case is VPNApplicationSwapError: return .protectedSwap
        case is VPNJointUpdateCleanupError, is VPNRescueCleanupContextError: return .cleanup
        case is VPNInstalledUpdateResultError, is VPNInstalledApplicationError: return .installedResult
        case is VPNLaunchdError: return .launchd
        case is VPNReleaseAuthorizationError, is VPNRescueAuthorizationError: return .authorization
        case is VPNLifecycleOwnershipError: return .ownership
        case is VPNRescueInstallationPayloadError: return .package
        case is VPNRescueJournalContextError, is Failure: return .state
        default: return .other
        }
    }
    private static func reportFailure(_ category: ErrorCategory) {
        FileHandle.standardError.write(Data("ProxyPilot VPN repair failure category: \(category.rawValue)\n".utf8))
    }

    static func run(arguments: [String]) -> Int32 {
        if arguments.count == 3, arguments[1] == "verify-package" {
            do {
                let package = try loadPackage(at: arguments[2])
                try package.revalidate()
                return 0
            } catch { return 77 }
        }
        if arguments.count == 3, arguments[1] == "preflight-install" {
            guard getuid() == 0, geteuid() == 0 else { return 77 }
            do { try preflight(at: arguments[2]); return 0 }
            catch { return 77 }
        }
        guard arguments.count == 2, arguments[1] == "repair" else { return 64 }
        guard getuid() == 0, geteuid() == 0 else { return 77 }
        do {
            try perform(deadline: DispatchTime.now().uptimeNanoseconds + totalBudget)
            return 0
        } catch Failure.timeout { reportFailure(.timeout); return 75 }
        catch {
            reportFailure(category(for: error))
            // Error descriptions can include paths or state. Installer output
            // carries only a fixed message and status, never package contents.
            FileHandle.standardError.write(Data("ProxyPilot VPN repair could not be completed.\n".utf8))
            return 77
        }
    }

    private static func loadPackage(at path: String) throws -> VPNRescueInstallationPayload {
        let parent = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard parent >= 0 else { throw VPNRescueInstallationPayloadError.unsafePackage }
        defer { close(parent) }
        return try VPNRescueInstallationPayload.load(inTrustedDirectory: parent,
                                                     authority: VPNReleaseTrust.authority())
    }

    private static func preflight(at path: String) throws {
        let incoming = try loadPackage(at: path)
        let executable = try incoming.duplicateExecutableDirectory()
        defer { close(executable) }
        let first = try VPNRescueExecutor.inspect(inTrustedDirectory: executable,
                                                  authorization: incoming.finishFirst)
        let second = try VPNRescueExecutor.inspect(inTrustedDirectory: executable,
                                                   authorization: incoming.finishSecond)
        let start = try VPNRescuePreparationExecutor.inspect(executor: second,
            authorization: incoming.prepareSecond, previous: incoming.intermediate,
            candidate: incoming.second.candidate.release, transition: incoming.second.transition)
        let service = try VPNDirectoryProvisioner.openSystemDirectory(create: false)
        defer { close(service) }
        if let existingDirectory = try openExistingRescue(service: service) {
            defer { close(existingDirectory) }
            let existing = try VPNRescueInstallationPayload.load(inTrustedDirectory: existingDirectory,
                                                                 authority: VPNReleaseTrust.authority())
            try existing.revalidate()
            guard existing.hasSameVerifiedMaterial(as: incoming) else { throw Failure.invalidState }
        }
        try incoming.revalidate(); try first.revalidate(); try second.revalidate(); try start.revalidate()
        try VPNDirectoryProvisioner.requireSystemDirectory(service)
    }

    /// Only ENOENT for the final fixed child means absence. Ancestors are
    /// reached through the already verified fixed service; no file is created.
    private static func openExistingRescue(service: Int32) throws -> Int32? {
        let parent = openat(service, "..", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard parent >= 0 else { throw Failure.invalidState }
        defer { close(parent) }
        try VPNInstallationPayload.check(parent, directory: true)
        var base = stat(), held = stat(), named = stat()
        guard fstat(parent, &base) == 0, base.st_mode & 0o7777 == 0o700, base.st_flags == 0,
              fstat(service, &held) == 0, fstatat(parent, "VPN", &named, AT_SYMLINK_NOFOLLOW) == 0,
              named.st_dev == held.st_dev, named.st_ino == held.st_ino else { throw Failure.invalidState }
        let child = openat(parent, "Rescue", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard child >= 0 else {
            guard errno == ENOENT else { throw Failure.invalidState }
            return nil
        }
        do {
            try VPNInstallationPayload.check(child, directory: true)
            var observed = stat(), current = stat()
            guard fstat(child, &observed) == 0, observed.st_mode & 0o7777 == 0o700, observed.st_flags == 0,
                  fstatat(parent, "Rescue", &current, AT_SYMLINK_NOFOLLOW) == 0,
                  current.st_dev == observed.st_dev, current.st_ino == observed.st_ino else { throw Failure.invalidState }
            return child
        } catch { close(child); throw error }
    }

    private static func perform(deadline: UInt64) throws {
        var lastPhase: Phase?
        func report(_ phase: Phase) {
            guard phase != lastPhase else { return }
            lastPhase = phase
            FileHandle.standardError.write(Data("ProxyPilot VPN repair phase: \(phase.rawValue)\n".utf8))
        }
        report(.verifyInputs)
        let authority = try VPNReleaseTrust.authority()
        let rescue = try VPNDirectoryProvisioner.openSystemRescueDirectory(create: false)
        defer { close(rescue) }
        let payload = try VPNRescueInstallationPayload.load(inTrustedDirectory: rescue, authority: authority)
        let executable = try payload.duplicateExecutableDirectory()
        defer { close(executable) }
        let firstExecutor = try VPNRescueExecutor.inspect(inTrustedDirectory: executable,
                                                          authorization: payload.finishFirst)
        let secondExecutor = try VPNRescueExecutor.inspect(inTrustedDirectory: executable,
                                                           authorization: payload.finishSecond)
        let preparationExecutor = try VPNRescuePreparationExecutor.inspect(executor: secondExecutor,
            authorization: payload.prepareSecond, previous: payload.intermediate,
            candidate: payload.second.candidate.release, transition: payload.second.transition)
        let service = try VPNDirectoryProvisioner.openSystemDirectory(create: false)
        defer { close(service) }
        let store = try VPNReleaseStore(trustedDirectoryDescriptor: service, authority: authority)
        let broker = try VPNRescueBrokerCoordinator.system(service: service, payload: payload,
                                                           executor: secondExecutor, authority: authority)
        // This is progress only. Final success independently proves the actual
        // C broker again under both leases; the Boolean grants no authority.
        var brokerReconciled = false
        // Reboot/crash retry safely rearms once. Repeated bootout/bootstrap on
        // every poll would starve the recovery job waiting for this same lease.
        var armedRecovery: UUID?
        // Completion in this invocation may select read-only waiting only.
        // Fresh journal/lease/executor/installed-app proofs are still required;
        // this set grants no mutation or final-success authority.
        var completedExchanges: Set<UUID> = []

        func check() throws {
            try requireTime(deadline)
            try VPNDirectoryProvisioner.requireSystemDirectory(service)
            let named = try VPNDirectoryProvisioner.openSystemRescueDirectory(create: false)
            defer { close(named) }
            var original = stat(), current = stat()
            guard fstat(rescue, &original) == 0, fstat(named, &current) == 0,
                  original.st_dev == current.st_dev, original.st_ino == current.st_ino else { throw Failure.invalidState }
            try payload.revalidate()
            try firstExecutor.revalidate(); try secondExecutor.revalidate(); try preparationExecutor.revalidate()
        }
        func leg(for journal: VPNUpdateJournalSnapshot) throws -> Leg {
            if payload.finishFirst.matchesSource(journal.previous.release),
               payload.finishFirst.matchesDestination(journal.candidate.release),
               payload.finishFirst.matchesTransition(journal.transition) { return .first }
            if payload.finishSecond.matchesSource(journal.previous.release),
               payload.finishSecond.matchesDestination(journal.candidate.release),
               payload.finishSecond.matchesTransition(journal.transition) { return .second }
            throw Failure.invalidState
        }
        func executor(for leg: Leg) -> VPNRescueExecutor { leg == .first ? firstExecutor : secondExecutor }
        func arm(_ deployment: VPNAuthorizedDeployment, transactionID: UUID,
                 lease: VPNLifecycleLease) throws {
            try check(); try lease.check()
            guard let before = try store.loadUpdateJournal(), before.transactionID == transactionID,
                  before.candidate.ownerUserID == deployment.ownerUserID,
                  before.candidate.release.isSameRelease(as: deployment.release) else { throw Failure.invalidState }
            _ = try leg(for: before)
            if armedRecovery != transactionID {
                let job = try VPNRecoveryLaunchdJob.system(storageDirectory: service)
                try job.installAndArm(deployment, deadline: actionDeadline(deadline))
                armedRecovery = transactionID
            }
            try check(); try lease.check()
            guard let after = try store.loadUpdateJournal(), after.transactionID == before.transactionID,
                  after.revision == before.revision, after.phase == before.phase,
                  after.recovery == before.recovery,
                  after.previous.ownerUserID == before.previous.ownerUserID,
                  after.candidate.ownerUserID == before.candidate.ownerUserID,
                  after.previous.release.isSameRelease(as: before.previous.release),
                  after.candidate.release.isSameRelease(as: before.candidate.release) else { throw Failure.invalidState }
        }
        func drain() throws {
            try check()
            let runtime = try VPNLaunchdRuntime.system(storageDirectory: service)
            try runtime.stopAndDrain(deadline: actionDeadline(deadline))
            try check()
        }

        func dispatch(lease: VPNLifecycleLease) throws -> Step {
            try check(); try lease.check()
            guard try lease.checkedStorageIdentity() == store.storageIdentity() else { throw Failure.invalidState }
            let selected = try store.loadDeployment()
            guard selected.ownerUserID >= 500, selected.ownerUserID != uid_t.max else { throw Failure.invalidState }
            let receipt = try store.loadUpdateCleanupReceipt()
            let preparation = try store.loadUpdatePreparation()
            let journal = try store.loadUpdateJournal()

            if let receipt {
                report(.cleanup)
                guard preparation == nil, journal == nil else { throw Failure.invalidState }
                let proof: VPNRescueExecutor
                if payload.finishFirst.matchesSource(receipt.previous.release),
                   payload.finishFirst.matchesDestination(receipt.candidate.release),
                   payload.finishFirst.matchesTransition(receipt.transition) { proof = firstExecutor }
                else if payload.finishSecond.matchesSource(receipt.previous.release),
                        payload.finishSecond.matchesDestination(receipt.candidate.release),
                        payload.finishSecond.matchesTransition(receipt.transition) { proof = secondExecutor }
                else { throw Failure.invalidState }
                let context = try VPNRescueCleanupContext.capture(authorization: proof.authorization,
                                                                  store: store, lease: lease)
                _ = try VPNJointUpdateCleanup.completeRescueSystem(service: service, lease: lease,
                    authority: authority, context: context, executor: proof)
                try check(); try lease.check()
                return .advance
            }

            if let journal {
                let edge = try leg(for: journal)
                guard journal.previous.ownerUserID == selected.ownerUserID,
                      journal.candidate.ownerUserID == selected.ownerUserID else { throw Failure.invalidState }
                let candidateSelected = selected.release.isSameRelease(as: journal.candidate.release)
                let recoverable = journal.phase == .replacementPending && journal.revision == 1 && journal.recovery == .recoverCandidate
                    || journal.phase == .selected && journal.revision == 2 && journal.recovery == .recoverCandidate
                    || journal.phase == .completed && journal.revision == 3 && journal.recovery == .completed
                if candidateSelected && recoverable {
                    guard preparation == nil else { throw Failure.invalidState }
                    _ = try VPNInstalledApplication.inspect(release: journal.candidate.release)
                    try arm(journal.candidate, transactionID: journal.transactionID, lease: lease)
                    return .waitForRecovery
                }
                guard selected.release.isSameRelease(as: journal.previous.release) else { throw Failure.invalidState }
                if completedExchanges.contains(journal.transactionID) {
                    guard preparation == nil, journal.phase == .replacementPending,
                          journal.revision == 1, journal.recovery == .inspectApplication,
                          armedRecovery == journal.transactionID else { throw Failure.invalidState }
                    let proof = executor(for: edge)
                    let context = try VPNRescueJournalContext.capture(authorization: proof.authorization,
                                                                      store: store, lease: lease)
                    guard context.transactionID == journal.transactionID else { throw Failure.invalidState }
                    // Replaying the already acknowledged exchange also replays
                    // its arm/drain callback and holds the lease recovery needs.
                    // Observe exact installed B/C instead, then release to it.
                    try VPNRescuePendingCoordinator.observeSystem(service: service, lease: lease,
                        context: context, executor: proof)
                    return .waitForRecovery
                }
                if edge == .first {
                    report(.firstReplace)
                    guard preparation == nil, journal.phase == .replacementPending,
                          journal.revision == 1, journal.recovery == .inspectApplication else { throw Failure.invalidState }
                    let context = try VPNRescueJournalContext.capture(authorization: firstExecutor.authorization,
                                                                      store: store, lease: lease)
                    let update = try VPNDirectoryProvisioner.openSystemUpdateDirectory(create: false)
                    defer { close(update) }
                    _ = try VPNRescuePendingCoordinator.runSystem(service: service, update: update, lease: lease,
                        context: context, executor: firstExecutor,
                        armCandidateRecovery: { try arm(journal.candidate, transactionID: journal.transactionID, lease: lease) },
                        drainPreviousService: drain)
                    completedExchanges.insert(journal.transactionID)
                    return .waitForRecovery
                }
                if journal.phase == .replacementPending {
                    report(.secondReplace)
                    guard preparation == nil, journal.revision == 1,
                          journal.recovery == .inspectApplication else { throw Failure.invalidState }
                    let update = try VPNDirectoryProvisioner.openSystemUpdateDirectory(create: false)
                    defer { close(update) }
                    _ = try VPNRescueReplacementCoordinator.runSystem(service: service, update: update,
                        authority: authority, lease: lease, preparationExecutor: preparationExecutor,
                        executor: secondExecutor,
                        armCandidateRecovery: { try arm($0, transactionID: journal.transactionID, lease: lease) },
                        drainPreviousService: drain)
                    completedExchanges.insert(journal.transactionID)
                    return .waitForRecovery
                }
                guard journal.phase == .prepared, journal.revision == 0,
                      journal.recovery == .canCancelOrReplace else { throw Failure.invalidState }
                // Exact matching conversion/prepared retry is verified again by
                // the preparation coordinator before touching either namespace.
            }

            if selected.release.isSameRelease(as: payload.intermediate) {
                report(.secondPrepare)
                let candidate = try payload.duplicateCandidateDirectory()
                defer { close(candidate) }
                let prepared = try VPNRescuePreparationCoordinator.prepareSystem(service: service,
                    lease: lease, candidateDirectory: candidate, payload: payload.second,
                    authority: authority, executor: preparationExecutor)
                let update = try VPNDirectoryProvisioner.openSystemUpdateDirectory(create: false)
                defer { close(update) }
                report(.secondReplace)
                _ = try VPNRescueReplacementCoordinator.runSystem(service: service, update: update,
                    authority: authority, lease: lease, preparationExecutor: preparationExecutor,
                    executor: secondExecutor,
                    armCandidateRecovery: { try arm($0, transactionID: prepared.journal.transactionID, lease: lease) },
                    drainPreviousService: drain)
                completedExchanges.insert(prepared.journal.transactionID)
                return .waitForRecovery
            }
            guard selected.release.isSameRelease(as: payload.second.candidate.release),
                  preparation == nil, journal == nil else { throw Failure.invalidState }
            _ = try VPNInstalledApplication.inspect(release: selected.release)
            guard brokerReconciled else { return .reconcileBroker }
            report(.verifyFinal)
            try verifyFinalResult(service: service, lease: lease, selected: selected, deadline: deadline)
            try broker.requireFinalReady(serviceLease: lease, deadline: actionDeadline(deadline))
            try check(); try lease.check()
            let final = try store.loadDeployment()
            guard final.ownerUserID == selected.ownerUserID,
                  final.release.isSameRelease(as: selected.release),
                  try store.loadUpdatePreparation() == nil, try store.loadUpdateJournal() == nil,
                  try store.loadUpdateCleanupReceipt() == nil else { throw Failure.invalidState }
            // Recovery may have exited or been booted out while its persistent
            // description remains. Retire both only after exact C readiness and
            // all journals are gone, holding broker + service ownership so the
            // next updater cannot arm a different transaction concurrently.
            report(.retireRecovery)
            try VPNSelectedCandidateRecovery.cleanRetiredRecoveryJob(
                store: store, lease: lease, selected: final) {
                    try VPNRecoveryLaunchdJob.system(storageDirectory: service)
                        .remove(deadline: actionDeadline(deadline))
                }
            try check(); try lease.check()
            return .finished
        }

        while true {
            try requireTime(deadline)
            do { try broker.acquire() }
            catch VPNLifecycleOwnershipError.busy { try pause(deadline); continue }
            let lease: VPNLifecycleLease
            do { lease = try VPNLifecycleOwnership.acquire(inTrustedDirectory: service) }
            catch VPNLifecycleOwnershipError.busy { try pause(deadline); continue }
            let step: Step
            do {
                do {
                    try broker.validateForRepair(serviceLease: lease)
                    step = try dispatch(lease: lease)
                    try broker.validateForRepair(serviceLease: lease)
                } catch {
                    let original = error
                    // If replacement marked exact pending1 before failing, its
                    // prepared broker receipt must durably cross handoff before
                    // releasing service ownership to the armed old recovery.
                    // Foreign/changed evidence fails this check without a write.
                    try broker.validateForRepair(serviceLease: lease)
                    throw original
                }
            }
            catch VPNLifecycleOwnershipError.busy { lease.release(); try pause(deadline); continue }
            catch VPNReleaseStoreError.busy { lease.release(); try pause(deadline); continue }
            catch VPNUpdateBrokerTransactionStoreError.busy { lease.release(); try pause(deadline); continue }
            catch VPNUpdateBrokerStatusStoreError.busy { lease.release(); try pause(deadline); continue }
            catch { lease.release(); throw error }
            lease.release()
            switch step {
            case .finished: report(.success); return
            case .advance: continue
            case .waitForRecovery: report(.waitRecovery); try pause(deadline)
            case .reconcileBroker:
                report(.reconcileBroker)
                do {
                    _ = try broker.reconcileFinal(deadline: actionDeadline(deadline))
                    brokerReconciled = true
                } catch VPNLifecycleOwnershipError.busy { try pause(deadline) }
                catch VPNReleaseStoreError.busy { try pause(deadline) }
                catch VPNUpdateBrokerTransactionStoreError.busy { try pause(deadline) }
                catch VPNUpdateBrokerStatusStoreError.busy { try pause(deadline) }
            }
        }
    }

    private static func verifyFinalResult(service: Int32, lease: VPNLifecycleLease,
                                          selected: VPNAuthorizedDeployment, deadline: UInt64) throws {
        // Only signed installed C is already an accepted helper peer. This
        // read-only child proves readiness/off without widening rescue policy.
        _ = try VPNRescueInstalledResultVerifier.verify(service: service, lease: lease,
            selected: selected, deadline: deadline)
    }
    private static func requireTime(_ deadline: UInt64) throws {
        guard DispatchTime.now().uptimeNanoseconds < deadline else { throw Failure.timeout }
    }
    private static func actionDeadline(_ deadline: UInt64) -> UInt64 {
        min(deadline, DispatchTime.now().uptimeNanoseconds + 20_000_000_000)
    }
    private static func pause(_ deadline: UInt64) throws {
        let now = DispatchTime.now().uptimeNanoseconds
        guard now < deadline else { throw Failure.timeout }
        let remaining = deadline - now
        usleep(useconds_t(min(1_000_000, remaining / 1000)))
        try requireTime(deadline)
    }
}
#endif
