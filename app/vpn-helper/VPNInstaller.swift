import Darwin
import Foundation

enum VPNInstallerError: Error {
    case requiresRoot
    case busy
    case alreadyInstalled
    case notInstalled
}

/// One authorized installation path, in a fixed order: provision the protected
/// directory, take the lifecycle lease, verify the signed release, publish the
/// policy/binary transaction and only then activate through launchd. It is not
/// an entry point for IPC, an updater or a user command: the caller must already
/// hold the user's system installation authorization, and the trusted release
/// key must be embedded in this code, never read from storage or the network.
/// Trusted key rotation and uninstall are not implemented.
enum VPNInstaller {
    /// First installation. Refuses when a policy already exists — an existing
    /// installation is changed by `update`, never re-bootstrapped over.
    static func install(payload: Data, signature: Data, helper: Data,
                        authority: VPNReleaseAuthority, trustedOwnerUserID: uid_t) throws -> VPNHelperReady {
        guard geteuid() == 0 else { throw VPNInstallerError.requiresRoot }
        let directory = try VPNDirectoryProvisioner.openSystemDirectory(create: true)
        defer { close(directory) }
        let runtime = try VPNLaunchdRuntime.system(storageDirectory: directory)
        return try install(payload: payload, signature: signature, helper: helper, authority: authority,
                           trustedOwnerUserID: trustedOwnerUserID, directory: directory, runtime: runtime)
    }

    /// Change an existing installation. The store rejects rollbacks and stale
    /// revisions; the coordinator refuses to leave a service it cannot verify.
    static func update(payload: Data, signature: Data, helper: Data, authority: VPNReleaseAuthority,
                       expectedSequence: UInt64, intent: VPNActivationIntent) throws -> VPNHelperReady {
        guard geteuid() == 0 else { throw VPNInstallerError.requiresRoot }
        let directory = try openInstalled { try VPNDirectoryProvisioner.openSystemDirectory(create: false) }
        defer { close(directory) }
        let runtime = try VPNLaunchdRuntime.system(storageDirectory: directory)
        return try update(payload: payload, signature: signature, helper: helper, authority: authority,
                          expectedSequence: expectedSequence, intent: intent,
                          directory: directory, runtime: runtime)
    }

    #if VPN_INSTALLER_TESTING
    /// Disposable per-user variant: the same order and the same components, in a
    /// private base directory and the user's launchd domain. Absent from normal
    /// builds; it proves the sequence, never a privileged system installation.
    static func testInstall(payload: Data, signature: Data, helper: Data, authority: VPNReleaseAuthority,
                            base: Int32, label: String, plistDirectory: URL) throws -> VPNHelperReady {
        let directory = try VPNDirectoryProvisioner.openBelowTrustedBase(base, create: true)
        defer { close(directory) }
        let runtime = try VPNLaunchdRuntime.testUserDomain(label: label, plistDirectory: plistDirectory,
                                                          storageDirectory: directory)
        return try install(payload: payload, signature: signature, helper: helper, authority: authority,
                           trustedOwnerUserID: geteuid(), directory: directory, runtime: runtime)
    }

    static func testUpdate(payload: Data, signature: Data, helper: Data, authority: VPNReleaseAuthority,
                           expectedSequence: UInt64, intent: VPNActivationIntent,
                           base: Int32, label: String, plistDirectory: URL) throws -> VPNHelperReady {
        let directory = try openInstalled { try VPNDirectoryProvisioner.openBelowTrustedBase(base, create: false) }
        defer { close(directory) }
        let runtime = try VPNLaunchdRuntime.testUserDomain(label: label, plistDirectory: plistDirectory,
                                                          storageDirectory: directory)
        return try update(payload: payload, signature: signature, helper: helper, authority: authority,
                          expectedSequence: expectedSequence, intent: intent,
                          directory: directory, runtime: runtime)
    }
    #endif

    private static func install(payload: Data, signature: Data, helper: Data, authority: VPNReleaseAuthority,
                                trustedOwnerUserID: uid_t, directory: Int32,
                                runtime: VPNActivationRuntime) throws -> VPNHelperReady {
        // The lease first: an installation must not race a running supervisor
        // into stopping or starting the service behind its back.
        let lease = try lifecycleLease(directory)
        defer { lease.release() }
        let store = try VPNReleaseStore(trustedDirectoryDescriptor: directory, authority: authority)
        do { _ = try store.bootstrapDeployment(payload: payload, signature: signature,
                                               helper: helper, trustedOwnerUserID: trustedOwnerUserID) }
        catch VPNReleaseStoreError.alreadyInitialized { throw VPNInstallerError.alreadyInstalled }
        let budget = try VPNActivationBudget(trustedDirectoryDescriptor: directory)
        let coordinator = VPNActivationCoordinator(store: store, runtime: runtime, lease: lease, budget: budget)
        // Installing is an explicit owner action, so it may start the service
        // even after earlier failures; the published policy is already durable.
        return try coordinator.recoverSelected(intent: .explicit)
    }

    private static func update(payload: Data, signature: Data, helper: Data, authority: VPNReleaseAuthority,
                               expectedSequence: UInt64, intent: VPNActivationIntent, directory: Int32,
                               runtime: VPNActivationRuntime) throws -> VPNHelperReady {
        let lease = try lifecycleLease(directory)
        defer { lease.release() }
        // Storage errors stay themselves here: a damaged installation must not
        // be reported as an absent one, and neither is repaired by an update.
        let store = try VPNReleaseStore(trustedDirectoryDescriptor: directory, authority: authority)
        let budget = try VPNActivationBudget(trustedDirectoryDescriptor: directory)
        let coordinator = VPNActivationCoordinator(store: store, runtime: runtime, lease: lease, budget: budget)
        return try coordinator.update(payload: payload, signature: signature, helper: helper,
                                      expectedSequence: expectedSequence, intent: intent)
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
