import Darwin
import Dispatch
import Foundation

enum VPNUpdateBrokerInstallerCoordinatorError: Error {
    case selectedChanged
}

/// Coordinates installation work across the broker and VPN namespaces.
/// Global lock order is always `Broker -> service`. The coordinator keeps the
/// Broker lease through service reconciliation and old-job removal, then must
/// release Broker lease before installAndStart bootstraps the new daemon.
enum VPNUpdateBrokerInstallerCoordinator {
    static func install(
        payload: Data, signature: Data, helper: Data, engine: Data? = nil,
        authority: VPNReleaseAuthority, trustedOwnerUserID: uid_t
    ) throws -> VPNHelperReady {
        guard getuid() == 0, geteuid() == 0 else {
            throw VPNInstallerError.requiresRoot
        }
        let brokerDirectory = try VPNDirectoryProvisioner
            .openSystemBrokerDirectory(create: true)
        defer { close(brokerDirectory) }
        let brokerLease = try VPNLifecycleOwnership.acquire(
            inTrustedDirectory: brokerDirectory)
        var brokerLeaseHeld = true
        defer { if brokerLeaseHeld { brokerLease.release() } }

        // installForBroker makes `alreadyInstalled` retries converge only when
        // the authenticated package is the exact selected release and owner.
        // The same exact-selected rule is required for any future `stale` retry.
        let result = try VPNInstaller.installForBroker(
            payload: payload, signature: signature, helper: helper,
            engine: engine, authority: authority,
            trustedOwnerUserID: trustedOwnerUserID)
        try brokerLease.check()

        let service = try VPNDirectoryProvisioner.openSystemDirectory(create: false)
        defer { close(service) }
        let store = try VPNReleaseStore(
            trustedDirectoryDescriptor: service, authority: authority)
        let exact = try store.loadDeployment()
        guard exact.ownerUserID == result.deployment.ownerUserID,
              exact.release.isSameRelease(as: result.deployment.release) else {
            throw VPNUpdateBrokerInstallerCoordinatorError.selectedChanged
        }
        let endpoint = try VPNEndpointDirectory.openSystem(create: true)
        close(endpoint)
        let job = try VPNUpdateBrokerLaunchdJob.system(
            storageDirectory: service)
        try job.installAndStart(
            exact,
            deadline: DispatchTime.now().uptimeNanoseconds + 20_000_000_000,
            beforeBootstrap: {
                try brokerLease.check()
                brokerLease.release()
                brokerLeaseHeld = false
            })
        return result.ready
    }

    static func uninstall(authority: VPNReleaseAuthority) throws {
        guard getuid() == 0, geteuid() == 0 else {
            throw VPNInstallerError.requiresRoot
        }
        let brokerDirectory: Int32
        do {
            brokerDirectory = try VPNDirectoryProvisioner
                .openSystemBrokerDirectory(create: false)
        } catch VPNDirectoryError.unavailable {
            // Legacy installations predate the Broker namespace.
            try VPNInstaller.uninstall(authority: authority)
            return
        }
        defer { close(brokerDirectory) }
        let brokerLease = try VPNLifecycleOwnership.acquire(
            inTrustedDirectory: brokerDirectory)
        var brokerLeaseHeld = true
        defer { if brokerLeaseHeld { brokerLease.release() } }
        let state = try VPNUpdateBrokerStateRemoval(
            trustedDirectoryDescriptor: brokerDirectory)
        // Broker -> service. This is a read-only gate before any mutation.
        try state.preflight()

        try VPNInstaller.uninstall(
            authority: authority,
            beforeServiceRemoval: { service, serviceLease in
                try brokerLease.check()
                try serviceLease.check()
                let job = try VPNUpdateBrokerLaunchdJob.system(
                    storageDirectory: service)
                // remove broker before helper artifacts
                try job.remove(deadline:
                    DispatchTime.now().uptimeNanoseconds + 20_000_000_000)
            })
        try brokerLease.check()
        try state.removeAll(lease: brokerLease)
        brokerLease.release()
        brokerLeaseHeld = false
        try VPNDirectoryProvisioner.removeSystemBrokerDirectory()
    }
}
