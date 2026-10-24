import Darwin
import Dispatch
import Foundation

enum VPNInstalledUpdateResultError: Error {
    case requiresRoot, invalidState, changed, deadlineExceeded, childFailed, spawnFailed
}

/// Retries only a contended Store observation, never authentication, layout,
/// runtime or changed-state failures. Each retry starts the entire observation
/// again; no partial readiness or identity proof survives the failed attempt.
enum VPNInstalledUpdateObservation {
    static func run<Value>(deadline: UInt64, onBusy: () -> Void = {},
                           attempt: () throws -> Value) throws -> Value {
        for _ in 0..<401 {
            guard DispatchTime.now().uptimeNanoseconds < deadline else {
                throw VPNInstalledUpdateResultError.deadlineExceeded
            }
            do {
                let value = try attempt()
                guard DispatchTime.now().uptimeNanoseconds < deadline else {
                    throw VPNInstalledUpdateResultError.deadlineExceeded
                }
                return value
            } catch VPNReleaseStoreError.busy {
                onBusy()
                let now = DispatchTime.now().uptimeNanoseconds
                guard now < deadline else { throw VPNInstalledUpdateResultError.deadlineExceeded }
                // The failed attempt has unwound all Store locks and temporary
                // observations before this bounded pause. No service lease is
                // acquired by this read-only entry.
                usleep(UInt32(min(20_000, max(1, (deadline - now) / 1_000))))
            }
        }
        throw VPNInstalledUpdateResultError.deadlineExceeded
    }
}

/// Read-only hidden frontend role. The selected signed application is already
/// allowed to probe its helper; this adds no helper peer role or VPN command.
enum VPNInstalledUpdateResultEntry {
    static let argument = "--vpn-verify-update-result"
    static let helperReadyStatus: Int32 = 40
    static let remainedOffStatus: Int32 = 41

    enum DiagnosticStage: String {
        case openStore, snapshot, installedIdentity, selfIdentity, readiness, offState
        case finalSnapshot, finalSelfIdentity, finalInstalledIdentity
    }
    enum DiagnosticCategory: String {
        case storeBusy, store, state, changed, applicationIdentity, selfIdentity
        case directory, budget, runtime, timeout, other
    }
    #if VPN_INSTALLED_UPDATE_RESULT_DIAGNOSTICS
    /// Disposable VM probe only. Release builds have no callback or output.
    static var diagnostic: ((DiagnosticStage, DiagnosticCategory) -> Void)?
    #endif

    private static func report(_ stage: DiagnosticStage, _ category: DiagnosticCategory) {
        #if VPN_INSTALLED_UPDATE_RESULT_DIAGNOSTICS
        diagnostic?(stage, category)
        #endif
    }
    private static func category(_ error: Error) -> DiagnosticCategory {
        switch error {
        case VPNReleaseStoreError.busy: return .storeBusy
        case is VPNReleaseStoreError: return .store
        case VPNInstalledUpdateResultError.deadlineExceeded: return .timeout
        case VPNInstalledUpdateResultError.changed: return .changed
        case is VPNInstalledUpdateResultError: return .state
        case is VPNInstalledApplicationError, is VPNStagedApplicationError: return .applicationIdentity
        case is VPNPeerAuthenticationError: return .selfIdentity
        case is VPNDirectoryError: return .directory
        case is VPNActivationBudgetError: return .budget
        case is VPNLaunchdError, is VPNHelperReadinessError: return .runtime
        default: return .other
        }
    }

    static func runIfRequested(arguments: [String]) -> Int32? {
        guard arguments.dropFirst().contains(argument) else { return nil }
        guard arguments.count == 2, arguments[1] == argument else { return 64 }
        guard getuid() == 0, geteuid() == 0 else { return 77 }
        var stage = DiagnosticStage.openStore
        do {
            let deadline = DispatchTime.now().uptimeNanoseconds + 8_000_000_000
            let service = try VPNDirectoryProvisioner.openSystemDirectory(create: false)
            defer { close(service) }
            let store = try VPNReleaseStore(trustedDirectoryDescriptor: service,
                                            authority: VPNReleaseTrust.authority())
            var reportedBusy = false
            return try VPNInstalledUpdateObservation.run(deadline: deadline, onBusy: {
                if !reportedBusy { report(stage, .storeBusy); reportedBusy = true }
            }) {
                stage = .snapshot
                let snapshot = try VPNInstalledUpdateResultSnapshot.capture(service: service, store: store)
                stage = .installedIdentity
                let installed = try VPNInstalledApplication.inspect(release: snapshot.selected.release)
                func validate(final: Bool = false) throws {
                    stage = final ? .finalSnapshot : .snapshot
                    try snapshot.validate(service: service, store: store)
                    stage = final ? .finalSelfIdentity : .selfIdentity
                    try VPNPeerAuthentication.validateCurrentProcess(policy: snapshot.selected.release.installerPolicy())
                    try installed.validateProcess(getpid())
                    stage = final ? .finalInstalledIdentity : .installedIdentity
                    try installed.revalidate()
                    guard DispatchTime.now().uptimeNanoseconds < deadline else {
                        throw VPNInstalledUpdateResultError.deadlineExceeded
                    }
                }
                try validate()
                let status: Int32
                if snapshot.desired {
                    stage = .readiness
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
                    stage = .offState
                    try VPNLaunchdRuntime.requireSystemStopped(deadline: deadline)
                    status = remainedOffStatus
                }
                try validate(final: true)
                return status
            }
        } catch {
            report(stage, category(error))
            return 77
        }
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
