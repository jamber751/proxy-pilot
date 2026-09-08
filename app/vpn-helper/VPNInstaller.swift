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

    /// Stop the service, take its launchd description away so no boot brings it
    /// back, then remove exactly the files this component created. Anything else
    /// in the directory aborts the removal instead of being deleted.
    static func uninstall() throws {
        guard geteuid() == 0 else { throw VPNInstallerError.requiresRoot }
        let directory = try openInstalled { try VPNDirectoryProvisioner.openSystemDirectory(create: false) }
        let runtime = try VPNLaunchdRuntime.system(storageDirectory: directory)
        try uninstall(directory: directory, runtime: runtime)
        try VPNEndpointDirectory.removeSystem()
        try VPNDirectoryProvisioner.removeSystemDirectories()
    }

    #if VPN_INSTALLER_TESTING
    static func testUninstall(base: Int32, label: String, plistDirectory: URL) throws {
        let directory = try openInstalled { try VPNDirectoryProvisioner.openBelowTrustedBase(base, create: false) }
        let runtime = try VPNLaunchdRuntime.testUserDomain(label: label, plistDirectory: plistDirectory,
                                                           storageDirectory: directory)
        try uninstall(directory: directory, runtime: runtime)
        try VPNDirectoryProvisioner.removeBelowTrustedBase(base)
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

    private static func testPreflight(payload: Data, signature: Data, helper: Data, engine: Data?, authority: VPNReleaseAuthority) throws {
        guard getuid() != 0, geteuid() == getuid() else { throw VPNPeerAuthenticationError.denied }
        let release = try authority.verify(payload: payload, signature: signature, previous: nil)
        try VPNPeerAuthentication.validateCurrentProcess(policy: release.clientPolicy(forTrustedUserID: geteuid()))
        try release.validateArtifacts(helper: helper, engine: engine)
    }
    #endif

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

    private static func uninstall(directory: Int32, runtime: VPNLaunchdRuntime) throws {
        defer { close(directory) }
        let lease = try lifecycleLease(directory)
        defer { lease.release() }
        // Decide what may be removed before stopping anything: an unexpected
        // file must not leave a stopped service and a half-removed directory.
        let removable = try removableNames(directory)
        try runtime.stopAndDrain(deadline: DispatchTime.now().uptimeNanoseconds + 20_000_000_000)
        try runtime.removeServiceDescription()
        try remove(removable, from: directory)
    }

    /// Only names this component creates may be removed, by exact name or by the
    /// content-addressed component patterns. Anything else aborts the uninstall.
    private static func removableNames(_ directory: Int32) throws -> [String] {
        let copy = fcntl(directory, F_DUPFD_CLOEXEC, 0)
        guard copy >= 0, let stream = fdopendir(copy) else {
            if copy >= 0 { close(copy) }
            throw VPNInstallerError.removalFailed
        }
        defer { closedir(stream) }
        var names: [String] = []
        while let entry = readdir(stream) {
            let name = withUnsafeBytes(of: entry.pointee.d_name) {
                String(cString: $0.baseAddress!.assumingMemoryBound(to: CChar.self))
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
