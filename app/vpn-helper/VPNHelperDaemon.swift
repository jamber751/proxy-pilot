import Darwin
import Foundation

enum VPNHelperDaemonError: Error { case requiresRoot, invalidArguments, selectionChanged }

enum VPNHelperDaemon {
    static let storagePath = "/Library/Application Support/ProxyPilot/VPN"

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
                  authority: VPNReleaseTrust.authority(), policy: { try $0.helperPolicy() })
    }

    #if VPN_DAEMON_TESTING
    static func testServe(directory: Int32, endpoint: Int32, shared: Bool,
                          authority: VPNReleaseAuthority) throws {
        guard getuid() != 0, getuid() == geteuid() else { throw VPNPeerAuthenticationError.denied }
        try serve(directory: directory, endpoint: endpoint, shared: shared,
                  authority: authority, policy: { try $0.testHelperPolicy() })
    }
    #endif

    private static func serve(directory: Int32, endpoint: Int32, shared: Bool,
                              authority: VPNReleaseAuthority,
                              policy: (VerifiedVPNRelease) throws -> VPNPeerPolicy) throws {
        let store = try VPNReleaseStore(trustedDirectoryDescriptor: directory, authority: authority)
        let stamp = try selectionStamp(directory)
        let selected = try store.loadDeployment()
        func recoveryOnly() throws -> Bool {
            guard let journal = try store.loadUpdateJournal() else { return false }
            let late = journal.phase == .selected && journal.recovery == .recoverCandidate
                || journal.phase == .completed && journal.recovery == .completed
            guard late,
                  journal.candidate.ownerUserID == selected.ownerUserID,
                  journal.candidate.release.isSameRelease(as: selected.release) else {
                throw VPNReleaseStoreError.invalidUpdateJournal
            }
            return true
        }
        _ = try recoveryOnly()
        guard try selectionStamp(directory) == stamp else { throw VPNHelperDaemonError.selectionChanged }
        try VPNPeerAuthentication.validateCurrentProcess(policy: policy(selected.release))
        let runtime = try VPNHelperRuntime(storageDirectory: directory)
        // A coordinator starting us already owns the lifecycle and accounts for
        // its attempt. At boot, own the short startup transaction ourselves.
        var bootLease: VPNLifecycleLease?
        do { bootLease = try VPNLifecycleOwnership.acquire(inTrustedDirectory: directory) }
        catch VPNLifecycleOwnershipError.busy { }
        defer { bootLease?.release() }
        let budget = try VPNActivationBudget(trustedDirectoryDescriptor: directory)
        // A selected/completed journal is allowed only as a readiness-only
        // recovery launch. Earlier, corrupt or mismatched journals fail before
        // endpoint creation and never spend an automatic attempt.
        let startsForRecovery = try recoveryOnly()
        if bootLease != nil, !startsForRecovery {
            // Close the window between the preflight above and lifecycle
            // acquisition: journal preparation can legitimately win that race.
            try budget.beginAttempt(intent: .automatic)
        }
        try runtime.prepareEndpoint(directory: endpoint, shared: shared)
        let listener = try VPNHelperListener.bind(inTrustedDirectory: directory, release: selected.release,
                                                  ownerUserID: selected.ownerUserID,
                                                  endpointDirectory: shared ? endpoint : nil)
        defer { listener.close() }
        func stillSelected() throws {
            try runtime.check()
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
        while true {
            try stillSelected()
            _ = try? listener.serveOnce(
                isReady: {
                    guard (try? stillSelected()) != nil else { return false }
                    return !startsForRecovery || (try? recoveryOnly()) != nil
                },
                allowOwnerRequests: {
                    !startsForRecovery || (try? store.requireNoPendingUpdate()) != nil
                })
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
