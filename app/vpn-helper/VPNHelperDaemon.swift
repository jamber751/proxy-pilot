import Darwin
import Foundation

enum VPNHelperDaemonError: Error { case requiresRoot, invalidArguments, selectionChanged }

enum VPNHelperDaemon {
    static let storagePath = "/Library/Application Support/ProxyPilot/VPN"
    typealias ProtectionFactory = (DispatchTime, () throws -> Void) throws -> VPNRetainedFenceRuntime

    static func runSystem(arguments: [String]) throws {
        guard getuid() == 0, geteuid() == 0 else { throw VPNHelperDaemonError.requiresRoot }
        guard arguments.count == 3, arguments[1] == "serve", arguments[2] == storagePath else {
            throw VPNHelperDaemonError.invalidArguments
        }
        let directory = try VPNDirectoryProvisioner.openSystemDirectory(create: false)
        defer { close(directory) }
        let endpoint = try VPNEndpointDirectory.openSystem(create: false)
        defer { close(endpoint) }
        try serve(directory: directory, endpoint: endpoint, shared: true,
                  authority: VPNReleaseTrust.authority(), policy: { try $0.helperPolicy() },
                  recoveryReadinessPolicies: nil,
                  recoveryFixtureInstaller: false,
                  restoreProtection: { deadline, current in
                      try VPNRetainedFenceRuntime.system(deadline:deadline,checkCurrent:current)
                  },
                  recoveryCleanup: { lease in
                      try VPNJointUpdateCleanup.completeSystem(
                        service: directory, lease: lease,
                        authority: try VPNReleaseTrust.authority())
                      let recovery = try VPNRecoveryLaunchdJob.system(
                        storageDirectory: directory)
                      try recovery.remove(
                        deadline: DispatchTime.now().uptimeNanoseconds + 2_000_000_000)
                  })
    }

    #if VPN_DAEMON_TESTING
    static func testServe(directory: Int32, endpoint: Int32, shared: Bool,
                          authority: VPNReleaseAuthority,
                          recoveryReadinessPolicies: ((VPNUpdateJournalSnapshot,
                              VPNAuthorizedDeployment) throws -> [VPNPeerPolicy])? = nil,
                          recoveryFixtureInstaller: Bool = false,
                          restoreProtection: ProtectionFactory? = nil,
                          recoveryCleanup: (VPNLifecycleLease) throws -> Void = { _ in }) throws {
        guard getuid() != 0, getuid() == geteuid() else { throw VPNPeerAuthenticationError.denied }
        try serve(directory: directory, endpoint: endpoint, shared: shared,
                  authority: authority, policy: { try $0.testHelperPolicy() },
                  recoveryReadinessPolicies: recoveryReadinessPolicies,
                  recoveryFixtureInstaller: recoveryFixtureInstaller,
                  restoreProtection:restoreProtection,
                  recoveryCleanup: recoveryCleanup)
    }
    #endif

    private static func serve(directory: Int32, endpoint: Int32, shared: Bool,
                              authority: VPNReleaseAuthority,
                              policy: (VerifiedVPNRelease) throws -> VPNPeerPolicy,
                              recoveryReadinessPolicies: ((VPNUpdateJournalSnapshot,
                                  VPNAuthorizedDeployment) throws -> [VPNPeerPolicy])?,
                              recoveryFixtureInstaller: Bool,
                              restoreProtection: ProtectionFactory?,
                              recoveryCleanup: (VPNLifecycleLease) throws -> Void) throws {
        try VPNActivationDiagnostics.run(role: .helper, stage: .openStore) { trace in
            let store = try VPNReleaseStore(trustedDirectoryDescriptor: directory, authority: authority)
            trace.mark(.selection)
            let stamp = try selectionStamp(directory)
            let selected = try store.loadDeployment()
            func recoveryJournal() throws -> VPNUpdateJournalSnapshot? {
                return try VPNActivationDiagnostics.run(role: .journal, stage: .journal) { _ in
                    guard let journal = try store.loadUpdateJournal() else { return nil }
                    let early = journal.phase == .prepared && journal.recovery == .canCancelOrReplace
                        || journal.phase == .replacementPending && journal.recovery == .inspectApplication
                    let late = journal.phase == .replacementPending && journal.recovery == .recoverCandidate
                        || journal.phase == .selected && journal.recovery == .recoverCandidate
                        || journal.phase == .completed && journal.recovery == .completed
                    let matches = early
                        ? journal.previous.ownerUserID == selected.ownerUserID
                            && journal.previous.release.isSameRelease(as: selected.release)
                        : journal.candidate.ownerUserID == selected.ownerUserID
                            && journal.candidate.release.isSameRelease(as: selected.release)
                    guard (early || late), matches else {
                        throw VPNReleaseStoreError.invalidUpdateJournal
                    }
                    return journal
                }
            }
            trace.mark(.journal)
            _ = try recoveryJournal()
            guard try selectionStamp(directory) == stamp else { throw VPNHelperDaemonError.selectionChanged }
            trace.mark(.identity)
            try VPNPeerAuthentication.validateCurrentProcess(policy: policy(selected.release))
            trace.mark(.runtime)
            let runtime = try VPNHelperRuntime(storageDirectory: directory)
            // A coordinator starting us already owns the lifecycle and accounts for
            // its attempt. At boot, own the short startup transaction ourselves.
            var bootLease: VPNLifecycleLease?
            do { bootLease = try VPNLifecycleOwnership.acquire(inTrustedDirectory: directory) }
            catch VPNLifecycleOwnershipError.busy { }
            defer { bootLease?.release() }
            trace.mark(.budget)
            let budget = try VPNActivationBudget(trustedDirectoryDescriptor: directory)
            // A selected/completed journal is allowed only as a readiness-only
            // recovery launch. Earlier, corrupt or mismatched journals fail before
            // endpoint creation and never spend an automatic attempt.
            let startsForRecovery = try recoveryJournal() != nil
            func mayServeReadiness() -> Bool {
                guard startsForRecovery else { return true }
                if (try? recoveryJournal()) != nil { return true }
                // Once the terminal journal is retired, this same selected helper
                // becomes the ordinary idle service. A corrupt or mismatched
                // journal still fails both checks and cannot cross this boundary.
                return (try? store.requireNoPendingUpdate()) != nil
            }
            if bootLease != nil, !startsForRecovery {
                // Close the window between the preflight above and lifecycle
                // acquisition: journal preparation can legitimately win that race.
                try budget.beginAttempt(intent: .automatic)
            }
            // Keep persistent deny/active custody alive for the daemon lifetime.
            // A failed restore exits before publishing any endpoint or readiness.
            // User-domain fixtures supply only their own private/injected runtime.
            let protection = try restoreProtection?(.now()+20) {
                try runtime.check()
                guard try selectionStamp(directory) == stamp else { throw VPNHelperDaemonError.selectionChanged }
            }
            var readProtection: ((DispatchTime) throws -> Data)?
            var readBridgeInventory: ((DispatchTime) throws -> Data)?
            if let protection {
                readProtection = { deadline in try protection.inventory(deadline:deadline).encoded() }
                let inventoryState = try VPNTunnelStateStore(trustedDirectoryDescriptor:directory)
                let inventoryJournal = try VPNRouteJournal(trustedDirectoryDescriptor:directory)
                readBridgeInventory = { deadline in
                    try VPNBridgeRootInventoryReader.read(deadline:deadline,
                        retained:{ try protection.inventory(deadline:deadline) },
                        state:{ try inventoryState.load() },journal:{ try inventoryJournal.loadIfPresent() },
                        checkCurrent:{
                            try runtime.check();try protection.check()
                            guard try selectionStamp(directory)==stamp else { throw VPNHelperDaemonError.selectionChanged }
                        }).encoded()
                }
            }
            trace.mark(.receipt)
            if shared {
                let publicReceipt = try store.loadDeploymentReceipt()
                try VPNPublicReleaseReceipt.publish(ownerUserID: publicReceipt.ownerUserID,
                    payload: publicReceipt.payload, signature: publicReceipt.signature,
                    inTrustedDirectory: endpoint)
            }
            trace.mark(.endpoint)
            try runtime.prepareEndpoint(directory: endpoint, shared: shared)
            func policiesForJournal(_ journal: VPNUpdateJournalSnapshot?) throws -> [VPNPeerPolicy] {
                guard let journal else { return [] }
                if let testing = recoveryReadinessPolicies { return try testing(journal, selected) }
                let early = journal.phase == .prepared && journal.recovery == .canCancelOrReplace
                    || journal.phase == .replacementPending && journal.recovery == .inspectApplication
                return [try journal.previous.release.installerPolicy(),
                        try (early ? journal.candidate.release : selected.release).helperPolicy()]
            }
            let readinessPolicies: () throws -> [VPNPeerPolicy] = {
                try VPNActivationDiagnostics.run(role: .readinessPolicy, stage: .readinessPolicy) { _ in
                    try policiesForJournal(recoveryJournal())
                }
            }
            trace.mark(.listener)
            let listener: VPNHelperListener
            #if VPN_DAEMON_TESTING && VPN_HELPER_LISTENER_TESTING
            if recoveryFixtureInstaller {
                listener = try VPNHelperListener.testBindInstaller(
                    inTrustedDirectory: directory, release: selected.release,
                    ownerUserID: selected.ownerUserID,
                    additionalReadinessPolicies: readinessPolicies,
                    readRetainedProtection:readProtection,
                    readBridgeRootInventory:readBridgeInventory)
            } else {
                listener = try VPNHelperListener.bind(
                    inTrustedDirectory: directory, release: selected.release,
                    ownerUserID: selected.ownerUserID,
                    endpointDirectory: shared ? endpoint : nil,
                    additionalReadinessPolicies: readinessPolicies,
                    readRetainedProtection:readProtection,
                    readBridgeRootInventory:readBridgeInventory)
            }
            #else
            _ = recoveryFixtureInstaller
            listener = try VPNHelperListener.bind(
                inTrustedDirectory: directory, deployment: selected,
                ownerUserID: selected.ownerUserID,
                endpointDirectory: shared ? endpoint : nil,
                runtimeLease: runtime.tunnelLifecycleLease,
                additionalReadinessPolicies: readinessPolicies,
                readRetainedProtection:readProtection,
                    readBridgeRootInventory:readBridgeInventory)
            #endif
            defer { listener.close() }
            func stillSelected() throws {
                try runtime.check()
                try protection?.check()
                // Selection was authenticated before binding. A legal replacement
                // stops this daemon first. Watch the protected atomic record without
                // acquiring its writer lock: repeatedly loading it here races the
                // installer's final check immediately after our readiness reply.
                guard try selectionStamp(directory) == stamp else {
                    throw VPNHelperDaemonError.selectionChanged
                }
            }
            try stillSelected()
            if let lease = bootLease {
                try lease.check()
                if !startsForRecovery {
                    // This signed, selected daemon has created its authenticated idle
                    // listener. No VPN/profile is applied on boot. External callers
                    // still perform their own mutual readiness authentication.
                    try budget.recordSuccess()
                }
                // A recovery-only helper must not keep the lifecycle lease needed by
                // the exact installed B coordinator that will reconcile the journal.
                lease.release(); bootLease = nil
            }
            trace.mark(.ready)
            trace.complete()
            var recoveryCleanupComplete = false
            var nextRecoveryCleanupAttempt: UInt64 = 0
            func cleanRetiredRecoveryJob() {
                let now = DispatchTime.now().uptimeNanoseconds
                guard !recoveryCleanupComplete, now >= nextRecoveryCleanupAttempt else { return }
                guard let cleanupLease = try? VPNLifecycleOwnership.acquire(
                        inTrustedDirectory: directory) else {
                    nextRecoveryCleanupAttempt = now + 1_000_000_000
                    return
                }
                defer { cleanupLease.release() }
                guard (try? store.requireNoPendingUpdate()) != nil else { return }
                // Cleanup is maintenance after the durable transaction has already
                // retired. It must never turn a successful update into an
                // unrecoverable failure; a later helper launch retries it.
                do {
                    try recoveryCleanup(cleanupLease)
                    recoveryCleanupComplete = true
                } catch {
                    nextRecoveryCleanupAttempt = now + 10_000_000_000
                }
            }
            while true {
                try stillSelected()
                _ = try? listener.serveOnce(
                    isReady: {
                        guard (try? stillSelected()) != nil else { return false }
                        return mayServeReadiness()
                    },
                    allowOwnerRequests: {
                        !startsForRecovery || (try? store.requireNoPendingUpdate()) != nil
                    },
                    rootReadinessContext: {
                        try VPNActivationDiagnostics.run(role: .readinessPolicy, stage: .readinessPolicy) { _ in
                            try stillSelected()
                            let journal = try recoveryJournal()
                            let ready = !startsForRecovery || journal != nil
                                || (try? store.requireNoPendingUpdate()) != nil
                            let policies = try policiesForJournal(journal)
                            try stillSelected()
                            return VPNHelperRootReadinessContext(ready: ready, additionalPolicies: policies)
                        }
                    })
                // Never delay the first readiness receipt with maintenance. The
                // lifecycle lease makes the no-journal check and job removal atomic
                // with respect to a following update's arm operation.
                cleanRetiredRecoveryJob()
            }
        }
    }

    private static func selectionStamp(_ directory: Int32) throws -> [UInt64] {
        var info = stat()
        guard fstatat(directory, "release.json", &info, AT_SYMLINK_NOFOLLOW) == 0,
              info.st_mode & S_IFMT == S_IFREG, info.st_uid == geteuid(),
              info.st_mode & 0o7777 == 0o600, info.st_nlink == 1 else {
            throw VPNHelperDaemonError.selectionChanged
        }
        return [UInt64(truncatingIfNeeded: info.st_dev), UInt64(info.st_ino),
                UInt64(truncatingIfNeeded: info.st_size),
                UInt64(truncatingIfNeeded: info.st_mtimespec.tv_sec), UInt64(info.st_mtimespec.tv_nsec),
                UInt64(truncatingIfNeeded: info.st_ctimespec.tv_sec), UInt64(info.st_ctimespec.tv_nsec)]
    }
}
