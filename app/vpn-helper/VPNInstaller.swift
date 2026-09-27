import Darwin
import Dispatch
import Foundation

enum VPNInstallerError: Error {
    case requiresRoot
    case busy
    case alreadyInstalled
    case notInstalled
    case unexpectedContent
    case removalFailed
    case coordinatedUpdateRequired
}

/// One authorized installation path, in a fixed order: authenticate the release
/// and our running app identity, provision the protected directory, take the
/// lifecycle lease, re-verify the signed release against storage, publish the
/// policy/binary transaction and only then activate through launchd. It is not
/// an entry point for IPC, an updater or a user command: the caller must already
/// hold the user's system installation authorization, and the trusted release
/// key must be embedded in this code, never read from storage or the network.
/// The installation-mode executable must itself be the exact hardened app build
/// pinned by this release: the helper authenticates it as root, readiness-only.
/// A separately built installer needs separately signed manifest pins, not a UID
/// bypass. Production packaging/authorization entry and key rotation remain open.
enum VPNInstaller {
    enum JointUpdateSourceAction {
        case beginReplacement, cancel, retireCancelled
    }

    /// First installation. Refuses when a policy already exists — an existing
    /// installation is changed by `update`, never re-bootstrapped over.
    static func install(payload: Data, signature: Data, helper: Data, engine: Data? = nil,
                        authority: VPNReleaseAuthority, trustedOwnerUserID: uid_t) throws -> VPNHelperReady {
        guard geteuid() == 0 else { throw VPNInstallerError.requiresRoot }
        try preflight(payload: payload, signature: signature, helper: helper, engine: engine, authority: authority)
        let directory = try VPNDirectoryProvisioner.openSystemDirectory(create: true)
        defer { close(directory) }
        let runtime = try VPNLaunchdRuntime.system(storageDirectory: directory)
        return try install(payload: payload, signature: signature, helper: helper, engine: engine, authority: authority,
                           trustedOwnerUserID: trustedOwnerUserID, directory: directory, runtime: runtime)
    }

    /// Change an existing installation. The store rejects rollbacks and stale
    /// revisions; the coordinator refuses to leave a service it cannot verify.
    static func update(payload: Data, signature: Data, helper: Data, engine: Data? = nil, authority: VPNReleaseAuthority,
                       expectedSequence: UInt64, intent: VPNActivationIntent) throws -> VPNHelperReady {
        guard geteuid() == 0 else { throw VPNInstallerError.requiresRoot }
        try preflight(payload: payload, signature: signature, helper: helper, engine: engine, authority: authority)
        let directory = try openInstalled { try VPNDirectoryProvisioner.openSystemDirectory(create: false) }
        defer { close(directory) }
        let runtime = try VPNLaunchdRuntime.system(storageDirectory: directory)
        return try update(payload: payload, signature: signature, helper: helper, engine: engine, authority: authority,
                          expectedSequence: expectedSequence, intent: intent,
                          directory: directory, runtime: runtime)
    }

    /// Authenticate the currently selected application and durably stage an
    /// exact signed A→B transition. This does not stop, select or start either
    /// release and never creates an absent installation.
    static func prepareJointUpdate(payload: Data, signature: Data, helper: Data, engine: Data? = nil,
                                   transitionPayload: Data, transitionSignature: Data,
                                   authority: VPNReleaseAuthority,
                                   expectedSequence: UInt64) throws -> VPNUpdateJournalSnapshot {
        guard geteuid() == 0 else { throw VPNInstallerError.requiresRoot }
        let directory = try openInstalled { try VPNDirectoryProvisioner.openSystemDirectory(create: false) }
        defer { close(directory) }
        return try prepareJointUpdate(payload: payload, signature: signature, helper: helper, engine: engine,
                                      transitionPayload: transitionPayload, transitionSignature: transitionSignature,
                                      authority: authority, expectedSequence: expectedSequence,
                                      directory: directory, testPolicy: false)
    }

    /// Source-A actions only, with fresh process authentication and lifecycle
    /// ownership. A returned journal is historical state, NOT a retained lease
    /// or permission to replace an app later. The future replacement executor
    /// must reacquire ownership, revalidate state and confirm drain again.
    /// There is deliberately no CLI/Sparkle entry for this boundary yet.
    @discardableResult
    static func managePreparedJointUpdate(_ action: JointUpdateSourceAction,
                                         transactionID: UUID, expectedRevision: UInt64,
                                         authority: VPNReleaseAuthority) throws -> VPNUpdateJournalSnapshot? {
        guard getuid() == 0, geteuid() == 0 else { throw VPNInstallerError.requiresRoot }
        let directory = try openInstalled { try VPNDirectoryProvisioner.openSystemDirectory(create: false) }
        defer { close(directory) }
        return try managePreparedJointUpdate(action, transactionID: transactionID,
            expectedRevision: expectedRevision, authority: authority, directory: directory,
            testPolicy: false, runtime: { try VPNLaunchdRuntime.system(storageDirectory: directory) })
    }

    /// Stop the service, take its launchd description away so no boot brings it
    /// back, then remove exactly the files this component created. Anything else
    /// in the directory aborts the removal instead of being deleted.
    static func uninstall() throws {
        guard geteuid() == 0 else { throw VPNInstallerError.requiresRoot }
        let directory = try openInstalled { try VPNDirectoryProvisioner.openSystemDirectory(create: false) }
        let runtime = try VPNLaunchdRuntime.system(storageDirectory: directory)
        let recovery = try VPNRecoveryLaunchdJob.system(storageDirectory: directory)
        try uninstall(directory: directory, runtime: runtime, recovery: recovery)
        try VPNEndpointDirectory.removeSystem()
        try VPNDirectoryProvisioner.removeSystemDirectories()
    }

    #if VPN_INSTALLER_TESTING
    static func testUninstall(base: Int32, label: String, plistDirectory: URL) throws {
        let directory = try openInstalled { try VPNDirectoryProvisioner.openBelowTrustedBase(base, create: false) }
        let runtime = try VPNLaunchdRuntime.testUserDomain(label: label, plistDirectory: plistDirectory,
                                                           storageDirectory: directory)
        let recovery = try VPNRecoveryLaunchdJob.testUserDomain(
            label: label + ".recovery", plistDirectory: plistDirectory,
            storageDirectory: directory)
        try uninstall(directory: directory, runtime: runtime, recovery: recovery)
        try VPNDirectoryProvisioner.removeBelowTrustedBase(base)
    }

    static func testRemovableNames(directory: Int32) throws -> [String] {
        try removableNames(directory)
    }

    /// Disposable per-user variant: the same order and the same components, in a
    /// private base directory and the user's launchd domain. Absent from normal
    /// builds; it proves the sequence, never a privileged system installation.
    static func testInstall(payload: Data, signature: Data, helper: Data, engine: Data? = nil, authority: VPNReleaseAuthority,
                            base: Int32, label: String, plistDirectory: URL) throws -> VPNHelperReady {
        try testPreflight(payload: payload, signature: signature, helper: helper, engine: engine, authority: authority)
        let directory = try VPNDirectoryProvisioner.openBelowTrustedBase(base, create: true)
        defer { close(directory) }
        let runtime = try VPNLaunchdRuntime.testUserDomain(label: label, plistDirectory: plistDirectory,
                                                          storageDirectory: directory)
        return try install(payload: payload, signature: signature, helper: helper, engine: engine, authority: authority,
                           trustedOwnerUserID: geteuid(), directory: directory, runtime: runtime)
    }

    static func testUpdate(payload: Data, signature: Data, helper: Data, engine: Data? = nil, authority: VPNReleaseAuthority,
                           expectedSequence: UInt64, intent: VPNActivationIntent,
                           base: Int32, label: String, plistDirectory: URL) throws -> VPNHelperReady {
        try testPreflight(payload: payload, signature: signature, helper: helper, engine: engine, authority: authority)
        let directory = try openInstalled { try VPNDirectoryProvisioner.openBelowTrustedBase(base, create: false) }
        defer { close(directory) }
        let runtime = try VPNLaunchdRuntime.testUserDomain(label: label, plistDirectory: plistDirectory,
                                                          storageDirectory: directory)
        return try update(payload: payload, signature: signature, helper: helper, engine: engine, authority: authority,
                          expectedSequence: expectedSequence, intent: intent,
                          directory: directory, runtime: runtime)
    }

    static func testPrepareJointUpdate(payload: Data, signature: Data, helper: Data, engine: Data? = nil,
                                       transitionPayload: Data, transitionSignature: Data,
                                       authority: VPNReleaseAuthority, expectedSequence: UInt64,
                                       base: Int32) throws -> VPNUpdateJournalSnapshot {
        guard getuid() != 0, geteuid() == getuid() else { throw VPNPeerAuthenticationError.denied }
        let directory = try openInstalled { try VPNDirectoryProvisioner.openBelowTrustedBase(base, create: false) }
        defer { close(directory) }
        return try prepareJointUpdate(payload: payload, signature: signature, helper: helper, engine: engine,
                                      transitionPayload: transitionPayload, transitionSignature: transitionSignature,
                                      authority: authority, expectedSequence: expectedSequence,
                                      directory: directory, testPolicy: true)
    }

    @discardableResult
    static func testManagePreparedJointUpdate(_ action: JointUpdateSourceAction,
                                             transactionID: UUID, expectedRevision: UInt64,
                                             authority: VPNReleaseAuthority, base: Int32,
                                             runtime: (Int32) throws -> VPNActivationRuntime) throws -> VPNUpdateJournalSnapshot? {
        guard getuid() != 0, geteuid() == getuid() else { throw VPNPeerAuthenticationError.denied }
        let directory = try openInstalled { try VPNDirectoryProvisioner.openBelowTrustedBase(base, create: false) }
        defer { close(directory) }
        return try managePreparedJointUpdate(action, transactionID: transactionID,
            expectedRevision: expectedRevision, authority: authority, directory: directory,
            testPolicy: true, runtime: { try runtime(directory) })
    }

    private static func testPreflight(payload: Data, signature: Data, helper: Data, engine: Data?, authority: VPNReleaseAuthority) throws {
        guard getuid() != 0, geteuid() == getuid() else { throw VPNPeerAuthenticationError.denied }
        let release = try authority.verify(payload: payload, signature: signature, previous: nil)
        try VPNPeerAuthentication.validateCurrentProcess(policy: release.clientPolicy(forTrustedUserID: geteuid()))
        try release.validateArtifacts(helper: helper, engine: engine)
    }
    #endif

    private static func prepareJointUpdate(payload: Data, signature: Data, helper: Data, engine: Data?,
                                           transitionPayload: Data, transitionSignature: Data,
                                           authority: VPNReleaseAuthority, expectedSequence: UInt64,
                                           directory: Int32, testPolicy: Bool) throws -> VPNUpdateJournalSnapshot {
        let lease = try lifecycleLease(directory)
        defer { lease.release() }
        let store = try VPNReleaseStore(trustedDirectoryDescriptor: directory, authority: authority)
        let current = try store.loadDeployment()
        guard current.release.sequence == expectedSequence else { throw VPNReleaseStoreError.staleRevision }
        try authenticateSource(current.release, owner: current.ownerUserID, testPolicy: testPolicy)
        // Authentication may be expensive; ensure lifecycle ownership was not
        // replaced before publishing the journal and staged artifacts.
        try lease.check()
        return try store.prepareUpdateJournal(payload: payload, signature: signature, helper: helper, engine: engine,
                                              transitionPayload: transitionPayload,
                                              transitionSignature: transitionSignature,
                                              expectedSequence: expectedSequence)
    }

    private static func authenticateSource(_ release: VerifiedVPNRelease, owner: uid_t, testPolicy: Bool) throws {
        #if VPN_INSTALLER_TESTING
        if testPolicy {
            try VPNPeerAuthentication.validateCurrentProcess(
                policy: release.clientPolicy(forTrustedUserID: owner))
        } else {
            try VPNPeerAuthentication.validateCurrentProcess(policy: release.installerPolicy())
        }
        #else
        _ = testPolicy
        try VPNPeerAuthentication.validateCurrentProcess(policy: release.installerPolicy())
        #endif
    }

    private static func managePreparedJointUpdate(_ action: JointUpdateSourceAction,
                                                 transactionID: UUID, expectedRevision: UInt64,
                                                 authority: VPNReleaseAuthority, directory: Int32,
                                                 testPolicy: Bool,
                                                 runtime: () throws -> VPNActivationRuntime) throws -> VPNUpdateJournalSnapshot? {
        let lease = try lifecycleLease(directory)
        defer { lease.release() }
        let store = try VPNReleaseStore(trustedDirectoryDescriptor: directory, authority: authority)
        guard let journal = try store.loadUpdateJournal() else { throw VPNReleaseStoreError.invalidUpdateJournal }
        guard journal.transactionID == transactionID, journal.revision == expectedRevision else {
            throw VPNReleaseStoreError.staleRevision
        }
        let expectedPhase: VPNUpdateJournalPhase = action == .retireCancelled ? .cancelled : .prepared
        guard journal.phase == expectedPhase else { throw VPNReleaseStoreError.invalidUpdateJournal }
        // The store proves the selector is still exact A in these phases.
        try authenticateSource(journal.previous.release, owner: journal.previous.ownerUserID, testPolicy: testPolicy)
        try lease.check()
        switch action {
        case .cancel:
            return try store.cancelUpdateJournal(transactionID: transactionID, expectedRevision: expectedRevision)
        case .retireCancelled:
            try store.retireUpdateJournal(transactionID: transactionID, expectedRevision: expectedRevision)
            return nil
        case .beginReplacement:
            // No runtime construction, endpoint provisioning or stop before all
            // identity/revision/phase checks above. Never charge activation here.
            let adapter = try runtime()
            try lease.check()
            let deadline = DispatchTime.now().uptimeNanoseconds + 20_000_000_000
            try adapter.stopAndDrain(deadline: deadline)
            guard DispatchTime.now().uptimeNanoseconds < deadline else { throw VPNLaunchdError.timeout }
            try lease.check()
            // The store rechecks the journal and both deployments after drain.
            // Failure/crash here may leave A stopped with `prepared` intact;
            // cancellation remains possible but does not implicitly restart it.
            return try store.markUpdateReplacementPending(transactionID: transactionID, expectedRevision: expectedRevision)
        }
    }

    /// Refuse an unlisted/old app or the updater before provisioning, selecting
    /// policy, charging the activation budget or stopping a working service.
    /// A new app must be pinned by the independently signed VPN release. Being
    /// installed by Sparkle conveys no VPN authority. Root alone also does not.
    /// `previous: nil` here checks ONLY candidate signature/identity; the store
    /// still enforces durable ownership, expected revision and rollback rules
    /// under its lock. A failed update never falls back to first installation.
    private static func preflight(payload: Data, signature: Data, helper: Data, engine: Data?, authority: VPNReleaseAuthority) throws {
        let release = try authority.verify(payload: payload, signature: signature, previous: nil)
        try VPNPeerAuthentication.validateCurrentProcess(policy: release.installerPolicy())
        try release.validateArtifacts(helper: helper, engine: engine)
    }

    private static func install(payload: Data, signature: Data, helper: Data, engine: Data?, authority: VPNReleaseAuthority,
                                trustedOwnerUserID: uid_t, directory: Int32,
                                runtime: VPNActivationRuntime) throws -> VPNHelperReady {
        // The lease first: an installation must not race a running supervisor
        // into stopping or starting the service behind its back.
        let lease = try lifecycleLease(directory)
        defer { lease.release() }
        let store = try VPNReleaseStore(trustedDirectoryDescriptor: directory, authority: authority)
        do { _ = try store.bootstrapDeployment(payload: payload, signature: signature,
                                               helper: helper, engine: engine, trustedOwnerUserID: trustedOwnerUserID) }
        catch VPNReleaseStoreError.alreadyInitialized { throw VPNInstallerError.alreadyInstalled }
        let budget = try VPNActivationBudget(trustedDirectoryDescriptor: directory)
        let coordinator = VPNActivationCoordinator(store: store, runtime: runtime, lease: lease, budget: budget)
        // Installing is an explicit owner action, so it may start the service
        // even after earlier failures; the published policy is already durable.
        return try coordinator.recoverSelected(intent: .explicit)
    }

    private static func update(payload: Data, signature: Data, helper: Data, engine: Data?, authority: VPNReleaseAuthority,
                               expectedSequence: UInt64, intent: VPNActivationIntent, directory: Int32,
                               runtime: VPNActivationRuntime) throws -> VPNHelperReady {
        let lease = try lifecycleLease(directory)
        defer { lease.release() }
        // Storage errors stay themselves here: a damaged installation must not
        // be reported as an absent one, and neither is repaired by an update.
        let store = try VPNReleaseStore(trustedDirectoryDescriptor: directory, authority: authority)
        let budget = try VPNActivationBudget(trustedDirectoryDescriptor: directory)
        let coordinator = VPNActivationCoordinator(store: store, runtime: runtime, lease: lease, budget: budget)
        return try coordinator.update(payload: payload, signature: signature, helper: helper, engine: engine,
                                      expectedSequence: expectedSequence, intent: intent)
    }

    private static func uninstall(directory: Int32, runtime: VPNLaunchdRuntime,
                                  recovery: VPNRecoveryLaunchdJob) throws {
        defer { close(directory) }
        let lease = try lifecycleLease(directory)
        defer { lease.release() }
        // Decide what may be removed before stopping anything: an unexpected
        // file must not leave a stopped service and a half-removed directory.
        let removable = try removableNames(directory)
        try recovery.remove(deadline: DispatchTime.now().uptimeNanoseconds + 20_000_000_000)
        try runtime.stopAndDrain(deadline: DispatchTime.now().uptimeNanoseconds + 20_000_000_000)
        try runtime.removeServiceDescription()
        try remove(removable, from: directory)
    }

    /// Only names this component creates may be removed, by exact name or by the
    /// content-addressed component patterns. Anything else aborts the uninstall.
    private static func removableNames(_ directory: Int32) throws -> [String] {
        // A duplicated directory fd shares its enumeration offset with the
        // original open file description. Use a fresh cursor instead.
        let copy = openat(directory, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard copy >= 0, let stream = fdopendir(copy) else {
            if copy >= 0 { close(copy) }
            throw VPNInstallerError.removalFailed
        }
        defer { closedir(stream) }
        var names: [String] = []
        let nameOffset = MemoryLayout<dirent>.offset(of: \.d_name)!
        while true {
            errno = 0
            guard let entry = readdir(stream) else {
                guard errno == 0 else { throw VPNInstallerError.removalFailed }
                break
            }
            // `readdir` returns a variable-size record. Taking bytes of the
            // imported 1024-byte tuple can read beyond d_reclen under ASan.
            // Decode only the bytes present in this record, including its NUL.
            let recordLength = Int(entry.pointee.d_reclen)
            let nameLength = Int(entry.pointee.d_namlen)
            guard nameLength > 0, nameLength <= 1023,
                  nameOffset <= recordLength, nameLength < recordLength - nameOffset else {
                throw VPNInstallerError.removalFailed
            }
            let bytes = UnsafeRawPointer(entry).advanced(by: nameOffset).assumingMemoryBound(to: UInt8.self)
            guard bytes[nameLength] == 0 else { throw VPNInstallerError.removalFailed }
            let nameBytes = UnsafeBufferPointer(start: bytes, count: nameLength)
            guard !nameBytes.contains(0), !nameBytes.contains(47),
                  let name = String(bytes: nameBytes, encoding: .utf8) else {
                throw VPNInstallerError.removalFailed
            }
            if name == "." || name == ".." { continue }
            guard removable(name) else { throw VPNInstallerError.unexpectedContent }
            names.append(name)
        }
        return names
    }

    /// The lifecycle lock goes last: removing it is the moment our exclusive
    /// ownership of this installation ends.
    private static func remove(_ names: [String], from directory: Int32) throws {
        for name in names.sorted(by: { $1 == VPNLifecycleLease.lockName && $0 != VPNLifecycleLease.lockName }) {
            guard unlinkat(directory, name, 0) == 0 || errno == ENOENT else {
                throw VPNInstallerError.removalFailed
            }
        }
    }

    private static func removable(_ name: String) -> Bool {
        if ["initialized", "release.json", "release.lock", "activation.json", VPNProfileVault.name,
            VPNLifecycleLease.lockName, VPNLifecycleLease.runtimeLockName, VPNHelperProtocol.socketName].contains(name) { return true }
        if name.hasPrefix("helper-") || name.hasPrefix("engine-"), name.count == 71,
           name.dropFirst(7).allSatisfy({ $0.isHexDigit && !$0.isUppercase }) { return true }
        if name.hasSuffix(".tmp"), name.hasPrefix(".release-") || name.hasPrefix(".activation-")
            || name.hasPrefix(".profile-") { return true }
        return false
    }

    /// An update never creates the directory. Absent and unreachable are the
    /// same answer here — there is nothing installed to change — while an unsafe
    /// directory still surfaces as itself and is never silently reprovisioned.
    private static func openInstalled(_ open: () throws -> Int32) throws -> Int32 {
        do { return try open() }
        catch VPNDirectoryError.unavailable { throw VPNInstallerError.notInstalled }
    }

    private static func lifecycleLease(_ directory: Int32) throws -> VPNLifecycleLease {
        do { return try VPNLifecycleOwnership.acquire(inTrustedDirectory: directory) }
        catch VPNLifecycleOwnershipError.busy { throw VPNInstallerError.busy }
    }
}
