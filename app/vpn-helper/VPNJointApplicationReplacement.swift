import Darwin
import Foundation

/// Journal-authorized exchange of protected COPIES, not an Applications
/// installer. No CLI/IPC calls this boundary. The executor must be exact A,
/// outside both slots, with protected ancestry supplied by a trusted caller.
/// Success does not prove installed/live B and never advances the selector,
/// journal, activation budget or the user's desired-on/off state.
enum VPNJointApplicationReplacement {
    static func exchangePreparedCopies(applicationDirectory: Int32, transactionID: UUID,
                                       expectedRevision: UInt64, authority: VPNReleaseAuthority) throws
        -> VPNProtectedApplicationSwap.Outcome {
        guard getuid() == 0, geteuid() == 0 else { throw VPNInstallerError.requiresRoot }
        let directory = try VPNDirectoryProvisioner.openSystemDirectory(create: false)
        defer { close(directory) }
        return try perform(applicationDirectory: applicationDirectory, transactionID: transactionID,
                           expectedRevision: expectedRevision, authority: authority, directory: directory,
                           testPolicy: false, runtime: { try VPNLaunchdRuntime.system(storageDirectory: directory) })
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
                           testPolicy: true, runtime: { try runtime(directory) })
    }
    #endif

    private static func perform(applicationDirectory: Int32, transactionID: UUID,
                                expectedRevision: UInt64, authority: VPNReleaseAuthority,
                                directory: Int32, testPolicy: Bool,
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
        func authorizeMutation() throws {
            try recheck()
            // Invalid staged copies must never interrupt the service. Construct
            // the adapter lazily, only after the swap validated both trees.
            let adapter = try runtime()
            try recheck()
            let deadline = DispatchTime.now().uptimeNanoseconds + 20_000_000_000
            try adapter.stopAndDrain(deadline: deadline)
            guard DispatchTime.now().uptimeNanoseconds < deadline else { throw VPNLaunchdError.timeout }
            try recheck()
        }
        let outcome: VPNProtectedApplicationSwap.Outcome
        #if VPN_INSTALLER_TESTING && VPN_APPLICATION_SWAP_TESTING
        if testPolicy {
            outcome = try VPNProtectedApplicationSwap.testExchange(inTrustedDirectory: applicationDirectory,
                previous: initial.previous.release, candidate: initial.candidate.release,
                transition: initial.transition, authorizeMutation: authorizeMutation)
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
        return outcome
    }
}
