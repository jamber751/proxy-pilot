import Darwin
import Foundation

/// Journal-authorized replacement boundary. The legacy entry exchanges only
/// protected copies; the production executor entry also installs exact B into
/// Applications. The executor must be exact A in its separate fixed slot, with
/// protected ancestry supplied by a trusted caller. Success still does not
/// prove live B and never advances the selector, journal, activation budget or
/// the user's desired-on/off state.
enum VPNJointApplicationReplacement {
    static func exchangePreparedCopies(applicationDirectory: Int32, transactionID: UUID,
                                       expectedRevision: UInt64, authority: VPNReleaseAuthority) throws
        -> VPNProtectedApplicationSwap.Outcome {
        guard getuid() == 0, geteuid() == 0 else { throw VPNInstallerError.requiresRoot }
        let directory = try VPNDirectoryProvisioner.openSystemDirectory(create: false)
        defer { close(directory) }
        return try perform(applicationDirectory: applicationDirectory, transactionID: transactionID,
                           expectedRevision: expectedRevision, authority: authority, directory: directory,
                           testPolicy: false, destination: nil,
                           runtime: { try VPNLaunchdRuntime.system(storageDirectory: directory) })
    }

    /// Completes the disk replacement while the journal and stopped-service
    /// authority remain held. It still does not launch B or advance selector B.
    static func installPreparedApplication(applicationDirectory: Int32, transactionID: UUID,
                                           expectedRevision: UInt64,
                                           authority: VPNReleaseAuthority) throws
        -> VPNProtectedApplicationSwap.Outcome {
        guard getuid() == 0, geteuid() == 0 else { throw VPNInstallerError.requiresRoot }
        let directory = try VPNDirectoryProvisioner.openSystemDirectory(create: false)
        defer { close(directory) }
        return try perform(applicationDirectory: applicationDirectory, transactionID: transactionID,
                           expectedRevision: expectedRevision, authority: authority, directory: directory,
                           testPolicy: false, destination: nil, installDestination: true,
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
    #endif
    #endif

    private static func perform(applicationDirectory: Int32, transactionID: UUID,
                                expectedRevision: UInt64, authority: VPNReleaseAuthority,
                                directory: Int32, testPolicy: Bool,
                                destination: Int32?, installDestination: Bool = false,
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

        func context() throws -> VPNUpdateJournalSnapshot {
            try lease.check()
            guard let journal = try store.loadUpdateJournal() else { throw VPNReleaseStoreError.invalidUpdateJournal }
            guard journal.transactionID == transactionID, journal.revision == expectedRevision else {
                throw VPNReleaseStoreError.staleRevision
            }
            guard journal.phase == .replacementPending, journal.recovery == .inspectApplication else {
                throw VPNReleaseStoreError.invalidUpdateJournal
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

        let initial = try context()
        func recheck() throws {
            let fresh = try context()
            guard fresh.previous.ownerUserID == initial.previous.ownerUserID,
                  fresh.previous.release.isSameRelease(as: initial.previous.release),
                  fresh.candidate.release.isSameRelease(as: initial.candidate.release) else {
                throw VPNReleaseStoreError.invalidUpdateJournal
            }
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

        do {
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
                    authorizeMutation: authorizeMutation)
            }
            #else
            _ = destination
            destinationOutcome = try installProductionDestination(
                applicationDirectory: applicationDirectory, journal: initial,
                authorizeMutation: authorizeMutation)
            #endif
            try recheck()
            return outcome == .exchanged || destinationOutcome == .exchanged
                ? .exchanged : .alreadyExchanged
        } catch {
            throw VPNApplicationSwapError.commitUncertain
        }
    }

    private static func installProductionDestination(
        applicationDirectory: Int32, journal: VPNUpdateJournalSnapshot,
        authorizeMutation: () throws -> Void) throws
        -> VPNApplicationDestinationExchange.Outcome {
        do {
            return try VPNApplicationDestinationExchange.exchange(
                inTrustedDirectory: applicationDirectory,
                previous: journal.previous.release,
                previousOwnerUserID: journal.previous.ownerUserID,
                candidate: journal.candidate.release, transition: journal.transition,
                authorizeMutation: authorizeMutation)
        } catch VPNApplicationDestinationExchangeError.unsafeStorage {
            _ = try VPNApplicationDestinationStage.prepare(
                inTrustedDirectory: applicationDirectory,
                release: journal.candidate.release)
            return try VPNApplicationDestinationExchange.exchange(
                inTrustedDirectory: applicationDirectory,
                previous: journal.previous.release,
                previousOwnerUserID: journal.previous.ownerUserID,
                candidate: journal.candidate.release, transition: journal.transition,
                authorizeMutation: authorizeMutation)
        }
    }
}
