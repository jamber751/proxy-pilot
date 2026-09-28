import Darwin
import Foundation

enum VPNJointUpdateCleanupError: Error {
    case requiresRoot, unsafeStorage, invalidLayout, commitUncertain
}

/// Retires the four authenticated working copies left by a completed joint
/// update. Exact verified directories are atomically renamed into
/// transaction-specific archives. Only after their identities are durably
/// recorded does a bounded descriptor-relative walk remove those archives.
/// The signed cleanup receipt is advanced only after each namespace is durable.
enum VPNJointUpdateCleanup {
    private static let applicationStage = ".ProxyPilot.vpn-update"
    #if VPN_JOINT_UPDATE_CLEANUP_TESTING
    static var checkpoint: ((String) -> Void)?
    #endif

    static func completeSystem(authority: VPNReleaseAuthority) throws {
        guard getuid() == 0, geteuid() == 0 else {
            throw VPNJointUpdateCleanupError.requiresRoot
        }
        let service = try VPNDirectoryProvisioner.openSystemDirectory(create: false)
        defer { close(service) }
        let lease = try VPNLifecycleOwnership.acquire(inTrustedDirectory: service)
        defer { lease.release() }
        try completeSystem(service: service, lease: lease, authority: authority)
    }

    /// Uninstall's single-lease cleanup gate. Prepared work is explicitly
    /// cancelled here; any later phase remains fail-closed.
    static func completeAllSystem(service: Int32, lease: VPNLifecycleLease,
                                  authority: VPNReleaseAuthority) throws {
        try completeSystem(service: service, lease: lease, authority: authority)
        let store = try VPNReleaseStore(trustedDirectoryDescriptor: service,
                                        authority: authority)
        _ = try store.finishUpdatePreparationConversion()
        if try store.loadUpdatePreparation() != nil {
            try completePreparationSystem(service: service, lease: lease,
                                          authority: authority)
        }
        if let journal = try store.loadUpdateJournal() {
            let cancelled: VPNUpdateJournalSnapshot
            if journal.phase == .prepared, journal.recovery == .canCancelOrReplace {
                cancelled = try store.cancelUpdateJournal(
                    transactionID: journal.transactionID,
                    expectedRevision: journal.revision)
            } else if journal.recovery == .cancelled {
                cancelled = journal
            } else {
                throw VPNReleaseStoreError.updateInProgress
            }
            try completeCancelledSystem(service: service, lease: lease,
                                        authority: authority,
                                        transactionID: cancelled.transactionID)
        }
        try store.requireNoPendingUpdate()
        guard try store.loadUpdateCleanupReceipt() == nil else {
            throw VPNReleaseStoreError.cleanupPending
        }
    }

    /// Recovery already owns the service lifecycle. Reuse that lease so cleanup
    /// cannot deadlock or invert the service→Update lock order.
    static func completeSystem(service: Int32, lease: VPNLifecycleLease,
                               authority: VPNReleaseAuthority) throws {
        try lease.check()
        let store = try VPNReleaseStore(trustedDirectoryDescriptor: service, authority: authority)
        // update.json is committed first. If a crash left both canonical
        // records, equality and artifact validation are sufficient to finish
        // the conversion before any later mutation is considered.
        _ = try store.finishUpdatePreparationConversion()
        guard try store.loadUpdateCleanupReceipt() != nil else { return }
        let update = try VPNDirectoryProvisioner.openSystemUpdateDirectory(create: false)
        defer { close(update) }
        let retired = try VPNDirectoryProvisioner.openSystemRetirementDirectory(create: true)
        defer { close(retired) }
        let applications = open("/Applications", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard applications >= 0 else { throw VPNJointUpdateCleanupError.unsafeStorage }
        defer { close(applications) }
        try perform(service: service, update: update, retirement: retired,
                    applications: applications, authority: authority,
                    productionApplications: true, existingServiceLease: lease)
    }

    /// Cancellation keeps the signed journal as authority until every staged
    /// application copy has been quarantined, garbage-collected and fsynced.
    /// The caller already owns the service lifecycle lease.
    static func completeCancelledSystem(service: Int32, lease: VPNLifecycleLease,
                                        authority: VPNReleaseAuthority,
                                        transactionID: UUID) throws {
        guard getuid() == 0, geteuid() == 0 else {
            throw VPNJointUpdateCleanupError.requiresRoot
        }
        try lease.check()
        let update = try VPNDirectoryProvisioner.openSystemUpdateDirectory(create: false)
        defer { close(update) }
        let retired = try VPNDirectoryProvisioner.openSystemRetirementDirectory(create: true)
        defer { close(retired) }
        let applications = open("/Applications", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard applications >= 0 else { throw VPNJointUpdateCleanupError.unsafeStorage }
        defer { close(applications) }
        try performCancelled(service: service, update: update, retirement: retired,
                             applications: applications, authority: authority,
                             transactionID: transactionID,
                             productionApplications: true, lease: lease)
    }

    /// Retires a preparation which never acquired journal authority. Creating
    /// an absent Update namespace is intentional: it gives the cleanup a fixed,
    /// root-owned lock and an empty exact layout instead of treating every open
    /// failure as absence. The preparation remains authoritative through GC.
    static func completePreparationSystem(service: Int32, lease: VPNLifecycleLease,
                                          authority: VPNReleaseAuthority) throws {
        guard getuid() == 0, geteuid() == 0 else {
            throw VPNJointUpdateCleanupError.requiresRoot
        }
        try lease.check()
        let store = try VPNReleaseStore(trustedDirectoryDescriptor: service,
                                        authority: authority)
        guard try store.loadUpdatePreparation() != nil else { return }
        let update = try VPNDirectoryProvisioner.openSystemUpdateDirectory(create: true)
        defer { close(update) }
        let retired = try VPNDirectoryProvisioner.openSystemRetirementDirectory(create: true)
        defer { close(retired) }
        try performPreparation(service: service, update: update,
                               retirement: retired, authority: authority,
                               lease: lease)
    }

    #if VPN_JOINT_UPDATE_CLEANUP_TESTING
    static func testComplete(service: Int32, update: Int32, retirement: Int32,
                             applications: Int32,
                             authority: VPNReleaseAuthority) throws {
        guard getuid() != 0, geteuid() == getuid() else {
            throw VPNPeerAuthenticationError.denied
        }
        try perform(service: service, update: update, retirement: retirement,
                    applications: applications, authority: authority,
                    productionApplications: false, existingServiceLease: nil)
    }

    static func testCompleteCancelled(service: Int32, update: Int32,
                                      retirement: Int32, applications: Int32,
                                      authority: VPNReleaseAuthority,
                                      transactionID: UUID,
                                      lease: VPNLifecycleLease) throws {
        guard getuid() != 0, geteuid() == getuid() else {
            throw VPNPeerAuthenticationError.denied
        }
        try performCancelled(service: service, update: update, retirement: retirement,
                             applications: applications, authority: authority,
                             transactionID: transactionID,
                             productionApplications: false, lease: lease)
    }

    static func testCompletePreparation(service: Int32, update: Int32,
                                        retirement: Int32,
                                        authority: VPNReleaseAuthority,
                                        lease: VPNLifecycleLease) throws {
        guard getuid() != 0, geteuid() == getuid() else {
            throw VPNPeerAuthenticationError.denied
        }
        try performPreparation(service: service, update: update,
                               retirement: retirement, authority: authority,
                               lease: lease)
    }

    static func testCompleteAll(service: Int32, update: Int32, retirement: Int32,
                                applications: Int32,
                                authority: VPNReleaseAuthority,
                                lease: VPNLifecycleLease) throws {
        try perform(service: service, update: update, retirement: retirement,
                    applications: applications, authority: authority,
                    productionApplications: false, existingServiceLease: lease)
        let store = try VPNReleaseStore(trustedDirectoryDescriptor: service,
                                        authority: authority)
        _ = try store.finishUpdatePreparationConversion()
        if try store.loadUpdatePreparation() != nil {
            try performPreparation(service: service, update: update,
                                   retirement: retirement, authority: authority,
                                   lease: lease)
        }
        if let journal = try store.loadUpdateJournal() {
            let cancelled: VPNUpdateJournalSnapshot
            if journal.phase == .prepared, journal.recovery == .canCancelOrReplace {
                cancelled = try store.cancelUpdateJournal(
                    transactionID: journal.transactionID,
                    expectedRevision: journal.revision)
            } else if journal.recovery == .cancelled { cancelled = journal }
            else { throw VPNReleaseStoreError.updateInProgress }
            try performCancelled(service: service, update: update,
                                 retirement: retirement, applications: applications,
                                 authority: authority,
                                 transactionID: cancelled.transactionID,
                                 productionApplications: false, lease: lease)
        }
        try store.requireNoPendingUpdate()
        guard try store.loadUpdateCleanupReceipt() == nil else {
            throw VPNReleaseStoreError.cleanupPending
        }
    }
    #endif

    private static func performPreparation(service: Int32, update: Int32,
                                           retirement: Int32,
                                           authority: VPNReleaseAuthority,
                                           lease: VPNLifecycleLease) throws {
        try requirePrivateDirectory(service); try requirePrivateDirectory(update)
        try requirePrivateDirectory(retirement)
        try requireDistinct([service, update, retirement])
        try lease.check()
        let updateLease = try VPNLifecycleOwnership.acquire(inTrustedDirectory: update)
        defer { updateLease.release() }
        let store = try VPNReleaseStore(trustedDirectoryDescriptor: service,
                                        authority: authority)
        guard var preparation = try store.loadUpdatePreparation() else { return }
        guard try store.loadUpdateJournal() == nil else {
            // Both records are a conversion checkpoint, not abandoned staging.
            throw VPNReleaseStoreError.invalidUpdatePreparation
        }
        let archiveName = preparation.transactionID.uuidString.lowercased() + "-preparation"
        let archive = try openArchive(parent: retirement, name: archiveName)
        defer { close(archive) }
        let slots: [(String, String, VerifiedVPNRelease, Bool)] = [
            ("current", "current", preparation.previous.release, true),
            ("candidate", "candidate", preparation.candidate.release, true),
            (".current.preparing", "pending-current", preparation.previous.release, false),
            (".candidate.preparing", "pending-candidate", preparation.candidate.release, false)
        ]
        if preparation.phase == .staging {
            try validatePreparationLayout(update: update, archive: archive,
                                          slots: slots, allowSources: true)
            for (source, destination, _, _) in slots {
                try retireOptionalExact(from: update, source: source, to: archive,
                                        destination: destination)
                testCheckpoint("preparation:after-\(destination)")
            }
            try validatePreparationLayout(update: update, archive: archive,
                                          slots: slots, allowSources: false)
            var roots: [VPNUpdateCleanupRootIdentity] = []
            for (_, destination, _, _) in slots where try directoryExists(archive, destination) {
                roots.append(try rootIdentity(logical: destination,
                                              parent: archive, name: destination))
            }
            roots.sort { $0.name < $1.name }
            preparation = try store.authorizeUpdatePreparationCleanup(
                transactionID: preparation.transactionID, roots: roots)
            testCheckpoint("preparation:gc-authorized")
        }
        guard preparation.phase == .gcAuthorized,
              let roots = preparation.cleanupRoots else {
            throw VPNReleaseStoreError.invalidUpdatePreparation
        }
        let identities = Dictionary(uniqueKeysWithValues: roots.map { ($0.name, $0) })
        var remainingEntries = 200_000
        for (_, destination, _, _) in slots {
            if let identity = identities[destination] {
                try removeTree(parent: archive, name: destination,
                               identity: identity, owner: preparation.ownerUserID,
                               remainingEntries: &remainingEntries)
            }
        }
        guard (try names(archive)).isEmpty else {
            throw VPNJointUpdateCleanupError.invalidLayout
        }
        if unlinkat(retirement, archiveName, AT_REMOVEDIR) != 0, errno != ENOENT {
            throw VPNJointUpdateCleanupError.invalidLayout
        }
        guard fsync(retirement) == 0 else {
            throw VPNJointUpdateCleanupError.commitUncertain
        }
        try lease.check(); try updateLease.check()
        try store.retireUpdatePreparation(transactionID: preparation.transactionID)
    }

    private static func directoryExists(_ parent: Int32, _ name: String) throws -> Bool {
        guard let child = try directory(parent, name) else { return false }
        close(child); return true
    }

    private static func validatePreparationLayout(
        update: Int32, archive: Int32,
        slots: [(String, String, VerifiedVPNRelease, Bool)], allowSources: Bool) throws {
        for (source, destination, release, requiresExactBundle) in slots {
            let sourceFD = try directory(update, source)
            let archiveFD = try directory(archive, destination)
            defer { if let sourceFD { close(sourceFD) }; if let archiveFD { close(archiveFD) } }
            guard sourceFD == nil || archiveFD == nil,
                  allowSources || sourceFD == nil else {
                throw VPNJointUpdateCleanupError.invalidLayout
            }
            if let selected = sourceFD ?? archiveFD, requiresExactBundle {
                let contents = try names(selected)
                guard contents == ["ProxyPilot.app"] else {
                    throw VPNJointUpdateCleanupError.invalidLayout
                }
                try VPNStagedApplication.requireExclusiveBundle(inTrustedDirectory: selected)
                _ = try VPNStagedApplication.inspect(
                    inTrustedDirectory: selected, release: release)
            }
        }
        let permitted = Set([VPNLifecycleLease.lockName] + (allowSources ? slots.map(\.0) : []))
        guard Set(try names(update)).isSubset(of: permitted),
              Set(try names(update)).contains(VPNLifecycleLease.lockName),
              Set(try names(archive)).isSubset(of: Set(slots.map(\.1))) else {
            throw VPNJointUpdateCleanupError.invalidLayout
        }
    }

    private static func performCancelled(service: Int32, update: Int32,
                                         retirement: Int32, applications: Int32,
                                         authority: VPNReleaseAuthority,
                                         transactionID: UUID,
                                         productionApplications: Bool,
                                         lease: VPNLifecycleLease) throws {
        try requirePrivateDirectory(service); try requirePrivateDirectory(update)
        try requirePrivateDirectory(retirement)
        try requireApplications(applications, production: productionApplications)
        try requireDistinct([service, update, retirement, applications])
        try lease.check()
        let updateLease = try VPNLifecycleOwnership.acquire(inTrustedDirectory: update)
        defer { updateLease.release() }
        let store = try VPNReleaseStore(trustedDirectoryDescriptor: service, authority: authority)
        guard var journal = try store.loadUpdateJournal(),
              journal.transactionID == transactionID,
              journal.recovery == .cancelled else {
            throw VPNReleaseStoreError.invalidUpdateJournal
        }
        let archiveName = transactionID.uuidString.lowercased() + "-cancelled"
        let archive = try openArchive(parent: retirement, name: archiveName)
        defer { close(archive) }
        let applicationArchive = applicationStage + ".cancelled-" + transactionID.uuidString.lowercased()

        if journal.phase == .cancelled {
            try validateOptionalApplication(parent: applications,
                                            source: applicationStage,
                                            archiveName: applicationArchive,
                                            release: journal.candidate.release,
                                            sourceMayExist: true)
            try validateCancelledUpdateLayout(update: update, archive: archive,
                                              journal: journal, allowSources: true)
            try retireOptionalExact(from: applications, source: applicationStage,
                                    to: applications, destination: applicationArchive)
            testCheckpoint("cancel:application-retired")
            journal = try store.advanceCancelledUpdateCleanup(
                transactionID: transactionID, expectedRevision: journal.revision,
                expectedPhase: .cancelled, to: .cancellationApplicationRetired)
        }
        if journal.phase == .cancellationApplicationRetired {
            try validateOptionalApplication(parent: applications,
                                            source: applicationStage,
                                            archiveName: applicationArchive,
                                            release: journal.candidate.release,
                                            sourceMayExist: false)
            try validateCancelledUpdateLayout(update: update, archive: archive,
                                              journal: journal, allowSources: true)
            let updateSlots = [("current", "current"), ("candidate", "candidate"),
                               ("executor", "executor"),
                               (".executor.preparing", "pending-executor")]
            for (source, destination) in updateSlots {
                try retireOptionalExact(from: update, source: source, to: archive,
                                        destination: destination)
                testCheckpoint("cancel:update-after-\(destination)")
            }
            try validateCancelledUpdateLayout(update: update, archive: archive,
                                              journal: journal, allowSources: false)
            journal = try store.advanceCancelledUpdateCleanup(
                transactionID: transactionID, expectedRevision: journal.revision,
                expectedPhase: .cancellationApplicationRetired,
                to: .cancellationUpdateRetired)
        }
        if journal.phase == .cancellationUpdateRetired {
            try validateOptionalApplication(parent: applications,
                                            source: applicationStage,
                                            archiveName: applicationArchive,
                                            release: journal.candidate.release,
                                            sourceMayExist: false)
            try validateCancelledUpdateLayout(update: update, archive: archive,
                                              journal: journal, allowSources: false)
            var roots: [VPNUpdateCleanupRootIdentity] = []
            if let fd = try directory(applications, applicationArchive) {
                close(fd)
                roots.append(try rootIdentity(logical: "application", parent: applications,
                                              name: applicationArchive))
            }
            for name in ["candidate", "current", "executor", "pending-executor"] {
                if let fd = try directory(archive, name) {
                    close(fd)
                    roots.append(try rootIdentity(logical: name, parent: archive, name: name))
                }
            }
            roots.sort { $0.name < $1.name }
            journal = try store.authorizeCancelledUpdateCleanupGC(
                transactionID: transactionID, expectedRevision: journal.revision,
                roots: roots)
            testCheckpoint("cancel:gc-authorized")
        }
        guard journal.phase == .cancellationGCAuthorized,
              let roots = journal.cancellationGCRoots else {
            throw VPNReleaseStoreError.invalidUpdateJournal
        }
        let identities = Dictionary(uniqueKeysWithValues: roots.map { ($0.name, $0) })
        var remainingEntries = 200_000
        if let identity = identities["application"] {
            try removeTree(parent: applications, name: applicationArchive,
                           identity: identity, owner: journal.previous.ownerUserID,
                           remainingEntries: &remainingEntries)
        }
        for name in ["current", "candidate", "executor", "pending-executor"] {
            if let identity = identities[name] {
                try removeTree(parent: archive, name: name, identity: identity,
                               owner: journal.previous.ownerUserID,
                               remainingEntries: &remainingEntries)
            }
        }
        guard (try names(archive)).isEmpty else {
            throw VPNJointUpdateCleanupError.invalidLayout
        }
        if unlinkat(retirement, archiveName, AT_REMOVEDIR) != 0, errno != ENOENT {
            throw VPNJointUpdateCleanupError.invalidLayout
        }
        guard fsync(retirement) == 0 else { throw VPNJointUpdateCleanupError.commitUncertain }
        try lease.check(); try updateLease.check()
        try store.retireUpdateJournal(transactionID: transactionID,
                                      expectedRevision: journal.revision)
    }

    private static func validateOptionalApplication(parent: Int32, source: String,
                                                    archiveName: String,
                                                    release: VerifiedVPNRelease,
                                                    sourceMayExist: Bool) throws {
        let sourceFD = try directory(parent, source)
        let archiveFD = try directory(parent, archiveName)
        defer { if let sourceFD { close(sourceFD) }; if let archiveFD { close(archiveFD) } }
        guard sourceFD == nil || archiveFD == nil, sourceMayExist || sourceFD == nil else {
            throw VPNJointUpdateCleanupError.invalidLayout
        }
        if let selected = sourceFD ?? archiveFD {
            try VPNStagedApplication.requireExclusiveBundle(inTrustedDirectory: selected)
            _ = try VPNStagedApplication.inspect(inTrustedDirectory: selected, release: release)
        }
    }

    private static func validateCancelledUpdateLayout(update: Int32, archive: Int32,
                                                      journal: VPNUpdateJournalSnapshot,
                                                      allowSources: Bool) throws {
        try validateOneOf(parent: update, source: "current", archiveParent: archive,
                          archiveName: "current", release: journal.previous.release,
                          sourceMayExist: allowSources)
        try validateOneOf(parent: update, source: "candidate", archiveParent: archive,
                          archiveName: "candidate", release: journal.candidate.release,
                          sourceMayExist: allowSources)
        let sourceExecutor = try directory(update, "executor")
        let archivedExecutor = try directory(archive, "executor")
        let sourcePending = try directory(update, ".executor.preparing")
        let archivedPending = try directory(archive, "pending-executor")
        defer {
            if let sourceExecutor { close(sourceExecutor) }
            if let archivedExecutor { close(archivedExecutor) }
            if let sourcePending { close(sourcePending) }
            if let archivedPending { close(archivedPending) }
        }
        let executorCopies = [sourceExecutor, archivedExecutor, sourcePending, archivedPending]
            .compactMap { $0 }
        guard executorCopies.count <= 1,
              allowSources || (sourceExecutor == nil && sourcePending == nil) else {
            throw VPNJointUpdateCleanupError.invalidLayout
        }
        if let executor = executorCopies.first {
            try VPNStagedApplication.requireExclusiveBundle(inTrustedDirectory: executor)
            _ = try VPNStagedApplication.inspect(inTrustedDirectory: executor,
                                                 release: journal.previous.release)
        }
        let allowedUpdate = Set([VPNLifecycleLease.lockName, "current", "candidate",
                                 "executor", ".executor.preparing"])
        let actualUpdate = Set(try names(update))
        guard actualUpdate.isSubset(of: allowedUpdate),
              actualUpdate.contains(VPNLifecycleLease.lockName) else {
            throw VPNJointUpdateCleanupError.invalidLayout
        }
        guard Set(try names(archive)).isSubset(of: ["current", "candidate", "executor",
                                                   "pending-executor"]) else {
            throw VPNJointUpdateCleanupError.invalidLayout
        }
    }

    private static func retireOptionalExact(from sourceParent: Int32, source: String,
                                            to destinationParent: Int32,
                                            destination: String) throws {
        let sourceFD = try directory(sourceParent, source)
        let destinationFD = try directory(destinationParent, destination)
        defer { if let sourceFD { close(sourceFD) }; if let destinationFD { close(destinationFD) } }
        if sourceFD == nil, destinationFD == nil { return }
        if sourceFD == nil, destinationFD != nil { return }
        guard sourceFD != nil, destinationFD == nil else {
            throw VPNJointUpdateCleanupError.invalidLayout
        }
        guard renameatx_np(sourceParent, source, destinationParent, destination,
                           UInt32(RENAME_EXCL)) == 0,
              fsync(sourceParent) == 0,
              sourceParent == destinationParent || fsync(destinationParent) == 0 else {
            throw VPNJointUpdateCleanupError.commitUncertain
        }
    }

    private static func rootIdentity(logical: String, parent: Int32,
                                     name: String) throws -> VPNUpdateCleanupRootIdentity {
        guard let fd = try directory(parent, name) else {
            throw VPNJointUpdateCleanupError.invalidLayout
        }
        defer { close(fd) }
        var value = stat()
        guard fstat(fd, &value) == 0 else { throw VPNJointUpdateCleanupError.unsafeStorage }
        return VPNUpdateCleanupRootIdentity(name: logical,
            device: UInt64(truncatingIfNeeded: value.st_dev), inode: UInt64(value.st_ino))
    }

    private static func perform(service: Int32, update: Int32, retirement: Int32,
                                applications: Int32, authority: VPNReleaseAuthority,
                                productionApplications: Bool,
                                existingServiceLease: VPNLifecycleLease?) throws {
        try requirePrivateDirectory(service)
        try requirePrivateDirectory(update)
        try requirePrivateDirectory(retirement)
        try requireApplications(applications, production: productionApplications)
        try requireDistinct([service, update, retirement, applications])

        // Global lock order is service lifecycle, then Update namespace.
        let acquiredServiceLease = try existingServiceLease == nil
            ? VPNLifecycleOwnership.acquire(inTrustedDirectory: service) : nil
        defer { acquiredServiceLease?.release() }
        let serviceLease = existingServiceLease ?? acquiredServiceLease!
        let updateLease = try VPNLifecycleOwnership.acquire(inTrustedDirectory: update)
        defer { updateLease.release() }
        try serviceLease.check(); try updateLease.check()

        let store = try VPNReleaseStore(trustedDirectoryDescriptor: service, authority: authority)
        guard var receipt = try store.loadUpdateCleanupReceipt() else { return }
        // The selected floor says B, but cleanup must also observe the exact
        // live installed B before retiring anything and again before deleting
        // the final durable authority.
        _ = try VPNStagedApplication.inspectInstalled(
            inApplicationsDirectory: applications,
            ownerUserID: productionApplications ? 0 : geteuid(),
            productionParent: productionApplications,
            release: receipt.candidate.release)
        let transactionName = receipt.transactionID.uuidString.lowercased()
        let archive = try openArchive(parent: retirement, name: transactionName)
        defer { close(archive) }
        testCheckpoint("begin:opened")

        if receipt.cleanupPhase == .pending {
            try validateApplicationPair(parent: applications, archiveName: applicationArchiveName(receipt),
                                        owner: receipt.ownerUserID,
                                        release: receipt.previous.release)
            testCheckpoint("begin:application-validated")
            try validateUpdateLayout(update: update, archive: archive, receipt: receipt,
                                     allowSources: true)
            testCheckpoint("begin:update-validated")
            try retireExact(from: applications, source: applicationStage,
                            to: applications, destination: applicationArchiveName(receipt))
            testCheckpoint("application:after-rename")
            try validateApplicationRetired(parent: applications,
                                           archiveName: applicationArchiveName(receipt),
                                           owner: receipt.ownerUserID,
                                           release: receipt.previous.release)
            receipt = try store.advanceUpdateCleanupReceipt(
                transactionID: receipt.transactionID, expectedPhase: .pending,
                to: .applicationRetired)
        }

        if receipt.cleanupPhase == .applicationRetired {
            try validateApplicationRetired(parent: applications,
                                           archiveName: applicationArchiveName(receipt),
                                           owner: receipt.ownerUserID,
                                           release: receipt.previous.release)
            try validateUpdateLayout(update: update, archive: archive, receipt: receipt,
                                     allowSources: true)
            for name in ["current", "candidate", "executor"] {
                try retireExact(from: update, source: name, to: archive, destination: name)
                testCheckpoint("update:after-\(name)")
            }
            try validateUpdateLayout(update: update, archive: archive, receipt: receipt,
                                     allowSources: false)
            receipt = try store.advanceUpdateCleanupReceipt(
                transactionID: receipt.transactionID,
                expectedPhase: .applicationRetired, to: .updateRetired)
        }

        if receipt.cleanupPhase == .updateRetired {
            try validateApplicationRetired(parent: applications,
                                           archiveName: applicationArchiveName(receipt),
                                           owner: receipt.ownerUserID,
                                           release: receipt.previous.release)
            try validateUpdateLayout(update: update, archive: archive, receipt: receipt,
                                     allowSources: false)
            let roots = try cleanupRoots(applications: applications, archive: archive,
                                         receipt: receipt)
            receipt = try store.authorizeUpdateCleanupGC(
                transactionID: receipt.transactionID, roots: roots)
            testCheckpoint("gc:after-authorize")
        }
        guard receipt.cleanupPhase == .gcAuthorized, let roots = receipt.gcRoots else {
            throw VPNJointUpdateCleanupError.invalidLayout
        }
        let identities = Dictionary(uniqueKeysWithValues: roots.map { ($0.name, $0) })
        var remainingEntries = 200_000
        try removeTree(parent: applications, name: applicationArchiveName(receipt),
                       identity: identities["application"]!, owner: receipt.ownerUserID,
                       remainingEntries: &remainingEntries)
        for name in ["current", "candidate", "executor"] {
            try removeTree(parent: archive, name: name, identity: identities[name]!,
                           owner: receipt.ownerUserID,
                           remainingEntries: &remainingEntries)
        }
        guard (try names(archive)).isEmpty else {
            throw VPNJointUpdateCleanupError.invalidLayout
        }
        guard unlinkat(retirement, transactionName, AT_REMOVEDIR) == 0 || errno == ENOENT,
              fsync(retirement) == 0 else {
            throw VPNJointUpdateCleanupError.commitUncertain
        }
        try serviceLease.check(); try updateLease.check()
        _ = try VPNStagedApplication.inspectInstalled(
            inApplicationsDirectory: applications,
            ownerUserID: productionApplications ? 0 : geteuid(),
            productionParent: productionApplications,
            release: receipt.candidate.release)
        try store.retireUpdateCleanupReceipt(transactionID: receipt.transactionID)
    }

    private static func testCheckpoint(_ name: String) {
        #if VPN_JOINT_UPDATE_CLEANUP_TESTING
        checkpoint?(name)
        #else
        _ = name
        #endif
    }

    private static func applicationArchiveName(_ receipt: VPNUpdateCleanupReceiptSnapshot) -> String {
        "\(applicationStage).retired-\(receipt.transactionID.uuidString.lowercased())"
    }

    private static func validateApplicationPair(parent: Int32, archiveName: String,
                                                owner: uid_t,
                                                release: VerifiedVPNRelease) throws {
        try validateApplicationOneOf(parent: parent, source: applicationStage,
                                     archiveName: archiveName, owner: owner,
                                     release: release, sourceMayExist: true)
    }

    private static func validateApplicationRetired(parent: Int32, archiveName: String,
                                                   owner: uid_t,
                                                   release: VerifiedVPNRelease) throws {
        try validateApplicationOneOf(parent: parent, source: applicationStage,
                                     archiveName: archiveName, owner: owner,
                                     release: release, sourceMayExist: false)
    }

    private static func validateApplicationOneOf(parent: Int32, source: String,
                                                 archiveName: String, owner: uid_t,
                                                 release: VerifiedVPNRelease,
                                                 sourceMayExist: Bool) throws {
        let sourceFD = try directory(parent, source)
        let archiveFD = try directory(parent, archiveName)
        guard (sourceFD == nil) != (archiveFD == nil), sourceMayExist || sourceFD == nil else {
            if let sourceFD { close(sourceFD) }; if let archiveFD { close(archiveFD) }
            throw VPNJointUpdateCleanupError.invalidLayout
        }
        let selected = sourceFD ?? archiveFD!
        defer { if let sourceFD { close(sourceFD) }; if let archiveFD { close(archiveFD) } }
        try VPNStagedApplication.requireExclusiveBundle(inTrustedDirectory: selected)
        _ = try VPNStagedApplication.inspectProtected(
            inTrustedDirectory: selected, contentOwnerUserID: owner, release: release)
    }

    private static func validateUpdateLayout(update: Int32, archive: Int32,
                                             receipt: VPNUpdateCleanupReceiptSnapshot,
                                             allowSources: Bool) throws {
        let expected: [(String, VerifiedVPNRelease)] = [
            ("current", receipt.candidate.release),
            ("candidate", receipt.previous.release),
            ("executor", receipt.previous.release)
        ]
        for (name, release) in expected {
            try validateOneOf(parent: update, source: name,
                              archiveParent: archive, archiveName: name,
                              release: release, sourceMayExist: allowSources)
        }
        let updateNames = try names(update)
        let permitted = Set([VPNLifecycleLease.lockName] + (allowSources ? expected.map(\.0) : []))
        guard Set(updateNames).isSubset(of: permitted),
              Set(updateNames).contains(VPNLifecycleLease.lockName) else {
            throw VPNJointUpdateCleanupError.invalidLayout
        }
        let archiveNames = Set(try names(archive))
        let expectedNames = Set(expected.map(\.0))
        guard archiveNames.isSubset(of: expectedNames),
              allowSources || archiveNames == expectedNames else {
            throw VPNJointUpdateCleanupError.invalidLayout
        }
    }

    private static func validateOneOf(parent: Int32, source: String,
                                      archiveParent: Int32, archiveName: String,
                                      release: VerifiedVPNRelease,
                                      sourceMayExist: Bool) throws {
        let sourceFD = try directory(parent, source)
        let archiveFD = try directory(archiveParent, archiveName)
        guard (sourceFD == nil) != (archiveFD == nil), sourceMayExist || sourceFD == nil else {
            if let sourceFD { close(sourceFD) }
            if let archiveFD { close(archiveFD) }
            throw VPNJointUpdateCleanupError.invalidLayout
        }
        let selected = sourceFD ?? archiveFD!
        defer {
            if let sourceFD { close(sourceFD) }
            if let archiveFD { close(archiveFD) }
        }
        try VPNStagedApplication.requireExclusiveBundle(inTrustedDirectory: selected)
        _ = try VPNStagedApplication.inspect(inTrustedDirectory: selected, release: release)
    }

    private static func retireExact(from sourceParent: Int32, source: String,
                                    to destinationParent: Int32, destination: String) throws {
        let sourceFD = try directory(sourceParent, source)
        let destinationFD = try directory(destinationParent, destination)
        if sourceFD == nil, destinationFD != nil {
            close(destinationFD!)
            return
        }
        guard let sourceFD, destinationFD == nil else {
            if let sourceFD { close(sourceFD) }
            if let destinationFD { close(destinationFD) }
            throw VPNJointUpdateCleanupError.invalidLayout
        }
        close(sourceFD)
        guard renameatx_np(sourceParent, source, destinationParent, destination,
                           UInt32(RENAME_EXCL)) == 0 else {
            throw VPNJointUpdateCleanupError.unsafeStorage
        }
        guard fsync(sourceParent) == 0,
              sourceParent == destinationParent || fsync(destinationParent) == 0 else {
            throw VPNJointUpdateCleanupError.commitUncertain
        }
    }

    private static func cleanupRoots(applications: Int32, archive: Int32,
                                     receipt: VPNUpdateCleanupReceiptSnapshot) throws
        -> [VPNUpdateCleanupRootIdentity] {
        let locations: [(String, Int32, String)] = [
            ("application", applications, applicationArchiveName(receipt)),
            ("candidate", archive, "candidate"),
            ("current", archive, "current"),
            ("executor", archive, "executor")
        ]
        return try locations.map { logical, parent, name in
            guard let descriptor = try directory(parent, name) else {
                throw VPNJointUpdateCleanupError.invalidLayout
            }
            defer { close(descriptor) }
            var value = stat()
            guard fstat(descriptor, &value) == 0 else {
                throw VPNJointUpdateCleanupError.unsafeStorage
            }
            return VPNUpdateCleanupRootIdentity(
                name: logical, device: UInt64(truncatingIfNeeded: value.st_dev),
                inode: UInt64(value.st_ino))
        }
    }

    /// Descriptor-relative deletion is allowed only after exact code/layout
    /// validation and durable publication of the four root identities. A crash
    /// leaves `gcAuthorized`, so retries accept an absent root or the same inode
    /// and can continue without trusting a partially deleted code signature.
    private static func removeTree(parent: Int32, name: String,
                                   identity: VPNUpdateCleanupRootIdentity,
                                   owner: uid_t, remainingEntries: inout Int) throws {
        var named = stat()
        if fstatat(parent, name, &named, AT_SYMLINK_NOFOLLOW) != 0 {
            guard errno == ENOENT else { throw VPNJointUpdateCleanupError.unsafeStorage }
            return
        }
        guard named.st_mode & S_IFMT == S_IFDIR,
              UInt64(truncatingIfNeeded: named.st_dev) == identity.device,
              UInt64(named.st_ino) == identity.inode else {
            throw VPNJointUpdateCleanupError.invalidLayout
        }
        let root = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard root >= 0 else { throw VPNJointUpdateCleanupError.unsafeStorage }
        var rootOpen = true
        do {
            try removeChildren(root, device: named.st_dev, owner: owner,
                               depth: 0, remainingEntries: &remainingEntries)
            guard fsync(root) == 0 else { throw VPNJointUpdateCleanupError.commitUncertain }
            close(root)
            rootOpen = false
            // Bind the final name removal to the same quarantined root. A
            // privileged concurrent rebind cannot turn the earlier open/fstat
            // into authority to remove a different empty directory.
            var rebound = stat()
            if fstatat(parent, name, &rebound, AT_SYMLINK_NOFOLLOW) != 0 {
                guard errno == ENOENT else {
                    throw VPNJointUpdateCleanupError.unsafeStorage
                }
                guard fsync(parent) == 0 else {
                    throw VPNJointUpdateCleanupError.commitUncertain
                }
                return
            }
            guard rebound.st_mode & S_IFMT == S_IFDIR,
                  UInt64(truncatingIfNeeded: rebound.st_dev) == identity.device,
                  UInt64(rebound.st_ino) == identity.inode else {
                throw VPNJointUpdateCleanupError.invalidLayout
            }
            guard unlinkat(parent, name, AT_REMOVEDIR) == 0 || errno == ENOENT,
                  fsync(parent) == 0 else {
                throw VPNJointUpdateCleanupError.commitUncertain
            }
        } catch {
            if rootOpen { close(root) }
            throw error
        }
    }

    private static func removeChildren(_ directory: Int32, device: dev_t,
                                       owner: uid_t, depth: Int,
                                       remainingEntries: inout Int) throws {
        guard depth < 64 else { throw VPNJointUpdateCleanupError.invalidLayout }
        let children = try names(directory)
        guard children.count <= remainingEntries else {
            throw VPNJointUpdateCleanupError.invalidLayout
        }
        remainingEntries -= children.count
        for name in children {
            var before = stat()
            guard fstatat(directory, name, &before, AT_SYMLINK_NOFOLLOW) == 0,
                  before.st_dev == device,
                  before.st_uid == geteuid() || before.st_uid == owner,
                  before.st_nlink > 0 else {
                throw VPNJointUpdateCleanupError.unsafeStorage
            }
            switch before.st_mode & S_IFMT {
            case S_IFDIR:
                guard before.st_mode & 0o0022 == 0 else {
                    throw VPNJointUpdateCleanupError.unsafeStorage
                }
                let child = openat(directory, name,
                                   O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
                guard child >= 0 else { throw VPNJointUpdateCleanupError.unsafeStorage }
                do {
                    var held = stat()
                    guard fstat(child, &held) == 0, held.st_dev == before.st_dev,
                          held.st_ino == before.st_ino else {
                        throw VPNJointUpdateCleanupError.unsafeStorage
                    }
                    try requireNoACL(child)
                    try removeChildren(child, device: device, owner: owner,
                                       depth: depth + 1,
                                       remainingEntries: &remainingEntries)
                    guard fsync(child) == 0 else {
                        throw VPNJointUpdateCleanupError.commitUncertain
                    }
                } catch {
                    close(child); throw error
                }
                close(child)
                guard unlinkat(directory, name, AT_REMOVEDIR) == 0 else {
                    throw VPNJointUpdateCleanupError.unsafeStorage
                }
            case S_IFREG:
                guard before.st_nlink == 1, before.st_mode & 0o0022 == 0 else {
                    throw VPNJointUpdateCleanupError.unsafeStorage
                }
                let child = openat(directory, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
                guard child >= 0 else { throw VPNJointUpdateCleanupError.unsafeStorage }
                var held = stat()
                let safe = fstat(child, &held) == 0 && held.st_dev == before.st_dev
                    && held.st_ino == before.st_ino
                if safe { try requireNoACL(child) }
                close(child)
                guard safe, unlinkat(directory, name, 0) == 0 else {
                    throw VPNJointUpdateCleanupError.unsafeStorage
                }
            case S_IFLNK:
                guard before.st_nlink == 1 else {
                    throw VPNJointUpdateCleanupError.unsafeStorage
                }
                let link = openat(directory, name, O_RDONLY | O_SYMLINK | O_CLOEXEC)
                guard link >= 0 else { throw VPNJointUpdateCleanupError.unsafeStorage }
                var held = stat()
                let safe = fstat(link, &held) == 0 && held.st_dev == before.st_dev
                    && held.st_ino == before.st_ino && held.st_mode & S_IFMT == S_IFLNK
                if safe { try requireNoACL(link) }
                close(link)
                guard safe, unlinkat(directory, name, 0) == 0 else {
                    throw VPNJointUpdateCleanupError.unsafeStorage
                }
            default:
                throw VPNJointUpdateCleanupError.unsafeStorage
            }
            guard fsync(directory) == 0 else {
                throw VPNJointUpdateCleanupError.commitUncertain
            }
            testCheckpoint("gc:after-child")
        }
    }

    private static func openArchive(parent: Int32, name: String) throws -> Int32 {
        if mkdirat(parent, name, 0o700) == 0 {
            guard fsync(parent) == 0 else { throw VPNJointUpdateCleanupError.commitUncertain }
        } else if errno != EEXIST {
            throw VPNJointUpdateCleanupError.unsafeStorage
        }
        guard let archive = try directory(parent, name) else {
            throw VPNJointUpdateCleanupError.unsafeStorage
        }
        do { try requirePrivateDirectory(archive); return archive }
        catch { close(archive); throw error }
    }

    private static func directory(_ parent: Int32, _ name: String) throws -> Int32? {
        var named = stat()
        if fstatat(parent, name, &named, AT_SYMLINK_NOFOLLOW) != 0 {
            guard errno == ENOENT else { throw VPNJointUpdateCleanupError.unsafeStorage }
            return nil
        }
        guard named.st_mode & S_IFMT == S_IFDIR, named.st_uid == geteuid(),
              named.st_mode & 0o7777 == 0o700, named.st_nlink > 0 else {
            throw VPNJointUpdateCleanupError.unsafeStorage
        }
        let opened = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard opened >= 0 else { throw VPNJointUpdateCleanupError.unsafeStorage }
        var held = stat(), parentState = stat()
        guard fstat(opened, &held) == 0, fstat(parent, &parentState) == 0,
              held.st_dev == parentState.st_dev,
              held.st_dev == named.st_dev, held.st_ino == named.st_ino else {
            close(opened); throw VPNJointUpdateCleanupError.unsafeStorage
        }
        do { try requireNoACL(opened); return opened }
        catch { close(opened); throw error }
    }

    private static func requirePrivateDirectory(_ descriptor: Int32) throws {
        var value = stat(), filesystem = statfs()
        guard fstat(descriptor, &value) == 0,
              value.st_mode & S_IFMT == S_IFDIR, value.st_nlink > 0,
              value.st_uid == geteuid(), value.st_mode & 0o7777 == 0o700,
              fstatfs(descriptor, &filesystem) == 0,
              filesystem.f_flags & UInt32(MNT_LOCAL) != 0 else {
            throw VPNJointUpdateCleanupError.unsafeStorage
        }
        try requireNoACL(descriptor)
    }

    private static func requireApplications(_ descriptor: Int32, production: Bool) throws {
        var value = stat(), filesystem = statfs()
        guard fstat(descriptor, &value) == 0,
              value.st_mode & S_IFMT == S_IFDIR, value.st_nlink > 0,
              fstatfs(descriptor, &filesystem) == 0,
              filesystem.f_flags & UInt32(MNT_LOCAL) != 0,
              value.st_mode & S_IWOTH == 0 else {
            throw VPNJointUpdateCleanupError.unsafeStorage
        }
        if production {
            guard value.st_uid == 0 else { throw VPNJointUpdateCleanupError.unsafeStorage }
            let fixed = open("/Applications", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard fixed >= 0 else { throw VPNJointUpdateCleanupError.unsafeStorage }
            defer { close(fixed) }
            var expected = stat()
            guard fstat(fixed, &expected) == 0, expected.st_dev == value.st_dev,
                  expected.st_ino == value.st_ino else {
                throw VPNJointUpdateCleanupError.unsafeStorage
            }
        } else {
            guard value.st_uid == geteuid(), value.st_mode & 0o7777 == 0o700 else {
                throw VPNJointUpdateCleanupError.unsafeStorage
            }
        }
        try requireNoACL(descriptor)
    }

    private static func requireNoACL(_ descriptor: Int32) throws {
        guard let security = filesec_init() else { throw VPNJointUpdateCleanupError.unsafeStorage }
        defer { filesec_free(security) }
        var attributes = stat()
        guard fstatx_np(descriptor, &attributes, security) == 0 else {
            throw VPNJointUpdateCleanupError.unsafeStorage
        }
        var acl: acl_t?
        errno = 0
        let result = filesec_get_property(security, FILESEC_ACL, &acl)
        if result == -1, errno == ENOENT { return }
        guard result == 0, let acl else { throw VPNJointUpdateCleanupError.unsafeStorage }
        defer { acl_free(UnsafeMutableRawPointer(acl)) }
        var entry: acl_entry_t?
        errno = 0
        guard acl_get_entry(acl, Int32(ACL_FIRST_ENTRY.rawValue), &entry) == -1,
              errno == EINVAL else { throw VPNJointUpdateCleanupError.unsafeStorage }
    }

    private static func names(_ directory: Int32) throws -> [String] {
        let copy = openat(directory, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard copy >= 0, let stream = fdopendir(copy) else {
            if copy >= 0 { close(copy) }
            throw VPNJointUpdateCleanupError.unsafeStorage
        }
        defer { closedir(stream) }
        var result: [String] = []
        let offset = MemoryLayout<dirent>.offset(of: \dirent.d_name)!
        while true {
            errno = 0
            guard let entry = readdir(stream) else {
                guard errno == 0 else { throw VPNJointUpdateCleanupError.unsafeStorage }
                return result.sorted()
            }
            let length = Int(entry.pointee.d_namlen)
            guard length > 0, offset + length < Int(entry.pointee.d_reclen) else {
                throw VPNJointUpdateCleanupError.unsafeStorage
            }
            let bytes = UnsafeRawPointer(entry).advanced(by: offset).assumingMemoryBound(to: UInt8.self)
            let view = UnsafeBufferPointer(start: bytes, count: length)
            guard bytes[length] == 0, !view.contains(0), !view.contains(47),
                  let name = String(bytes: view, encoding: .utf8) else {
                throw VPNJointUpdateCleanupError.unsafeStorage
            }
            if name != "." && name != ".." { result.append(name) }
        }
    }

    private static func requireDistinct(_ descriptors: [Int32]) throws {
        var identities = Set<String>()
        for descriptor in descriptors {
            var value = stat()
            guard fstat(descriptor, &value) == 0,
                  identities.insert("\(UInt64(truncatingIfNeeded: value.st_dev)):\(value.st_ino)").inserted else {
                throw VPNJointUpdateCleanupError.unsafeStorage
            }
        }
    }
}
