import Darwin
import Dispatch
import Foundation

enum VPNInstalledUpdateResultError: Error {
    case requiresRoot, invalidState, changed, deadlineExceeded, childFailed, spawnFailed
}

/// Read-only hidden frontend role. The selected signed application is already
/// allowed to probe its helper; this adds no helper peer role or VPN command.
enum VPNInstalledUpdateResultEntry {
    static let argument = "--vpn-verify-update-result"
    static let helperReadyStatus: Int32 = 40
    static let remainedOffStatus: Int32 = 41

    static func runIfRequested(arguments: [String]) -> Int32? {
        guard arguments.dropFirst().contains(argument) else { return nil }
        guard arguments.count == 2, arguments[1] == argument else { return 64 }
        guard getuid() == 0, geteuid() == 0 else { return 77 }
        do {
            let deadline = DispatchTime.now().uptimeNanoseconds + 8_000_000_000
            let service = try VPNDirectoryProvisioner.openSystemDirectory(create: false)
            defer { close(service) }
            let store = try VPNReleaseStore(trustedDirectoryDescriptor: service,
                                            authority: VPNReleaseTrust.authority())
            let snapshot = try VPNInstalledUpdateResultSnapshot.capture(service: service, store: store)
            let installed = try VPNInstalledApplication.inspect(release: snapshot.selected.release)
            func validate() throws {
                try snapshot.validate(service: service, store: store)
                try VPNPeerAuthentication.validateCurrentProcess(policy: snapshot.selected.release.installerPolicy())
                try installed.validateProcess(getpid())
                try installed.revalidate()
                guard DispatchTime.now().uptimeNanoseconds < deadline else {
                    throw VPNInstalledUpdateResultError.deadlineExceeded
                }
            }
            try validate()
            let status: Int32
            if snapshot.desired {
                guard snapshot.failures == 0 else { throw VPNInstalledUpdateResultError.invalidState }
                let socket = try VPNEndpointDirectory.connectSystem(deadline: deadline)
                let now = DispatchTime.now().uptimeNanoseconds
                guard now < deadline else {
                    close(socket); throw VPNInstalledUpdateResultError.deadlineExceeded
                }
                _ = try VPNHelperReadiness.probe(takingSocket: socket, release: snapshot.selected.release,
                    timeoutMilliseconds: max(1, min(2000, Int((deadline - now) / 1_000_000))))
                status = helperReadyStatus
            } else {
                try VPNLaunchdRuntime.requireSystemStopped(deadline: deadline)
                status = remainedOffStatus
            }
            try validate()
            return status
        } catch { return 77 }
    }
}

/// Immutable observation shared by the installed child and rescue parent. All
/// reads require the existing lock file, so verification cannot create state.
struct VPNInstalledUpdateResultSnapshot {
    let selected: VPNAuthorizedDeployment
    let desired: Bool
    let failures: Int
    private let device: UInt64
    private let inode: UInt64

    static func capture(service: Int32, store: VPNReleaseStore) throws -> VPNInstalledUpdateResultSnapshot {
        let identity = try store.storageIdentity()
        guard try store.loadUpdatePreparation() == nil,
              try store.loadUpdateJournal() == nil,
              try store.loadUpdateCleanupReceipt() == nil else {
            throw VPNInstalledUpdateResultError.invalidState
        }
        let selected = try store.loadDeployment()
        guard selected.ownerUserID >= 500, selected.ownerUserID != uid_t.max else {
            throw VPNInstalledUpdateResultError.invalidState
        }
        let budget = try VPNActivationBudget(trustedDirectoryDescriptor: service).snapshot()
        let result = VPNInstalledUpdateResultSnapshot(selected: selected, desired: budget.desired,
            failures: budget.failures, device: identity.device, inode: identity.inode)
        try result.validate(service: service, store: store)
        return result
    }

    func validate(service: Int32, store: VPNReleaseStore) throws {
        let identity = try store.storageIdentity()
        var actual = stat()
        guard fstat(service, &actual) == 0,
              UInt64(actual.st_dev) == device, UInt64(actual.st_ino) == inode,
              identity.device == device, identity.inode == inode,
              try store.loadUpdatePreparation() == nil,
              try store.loadUpdateJournal() == nil,
              try store.loadUpdateCleanupReceipt() == nil else {
            throw VPNInstalledUpdateResultError.changed
        }
        let current = try store.loadDeployment()
        let budget = try VPNActivationBudget(trustedDirectoryDescriptor: service).snapshot()
        guard current.ownerUserID == selected.ownerUserID,
              current.release.isSameRelease(as: selected.release),
              budget.desired == desired, budget.failures == failures else {
            throw VPNInstalledUpdateResultError.changed
        }
    }
}
