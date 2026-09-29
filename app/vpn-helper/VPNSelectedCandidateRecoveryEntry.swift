import Darwin
import Foundation

enum VPNSelectedCandidateRecoveryEntry {
    static let argument = "--vpn-selected-candidate-recovery"

    static func runIfRequested(arguments: [String]) -> Int32? {
        guard arguments.count == 2, arguments[1] == argument else { return nil }
        guard getuid() == 0, geteuid() == 0 else { return 77 }
        do {
            let authority = try VPNReleaseTrust.authority()
            let directory = try VPNDirectoryProvisioner.openSystemDirectory(create: false)
            defer { close(directory) }
            let store = try VPNReleaseStore(trustedDirectoryDescriptor: directory,
                                            authority: authority)
            guard let journal = try store.loadUpdateJournal() else {
                throw VPNSelectedCandidateRecoveryError.invalidJournal
            }
            let recoverable = journal.phase == .replacementPending && journal.recovery == .recoverCandidate
                || journal.phase == .selected && journal.recovery == .recoverCandidate
                || journal.phase == .completed && journal.recovery == .completed
            guard recoverable else { throw VPNSelectedCandidateRecoveryError.invalidJournal }
            try VPNPeerAuthentication.validateCurrentProcess(
                policy: journal.candidate.release.installerPolicy())
            let installed = try VPNInstalledApplication.inspect(
                release: journal.candidate.release)
            try installed.validateProcess(getpid())
            let lease = try VPNLifecycleOwnership.acquire(inTrustedDirectory: directory)
            defer { lease.release() }
            let runtime = try VPNLaunchdRuntime.system(storageDirectory: directory)
            let budget = try VPNActivationBudget(trustedDirectoryDescriptor: directory)
            var brokerCompletion: VPNUpdateBrokerRotation.Completion?
            _ = try VPNSelectedCandidateRecovery.recover(
                store: store, runtime: runtime, lease: lease, budget: budget,
                journal: journal,
                beforeJournalRetirement: { completed in
                    brokerCompletion = try VPNUpdateBrokerRotation.rotateIfRequired(
                        serviceDirectory: directory, store: store, lease: lease,
                        journal: completed, authority: authority)
                }, afterJournalRetirement: { _, lease in
                    if let brokerCompletion {
                        try VPNUpdateBrokerRotation.finish(
                            brokerCompletion, serviceDirectory: directory,
                            lease: lease, authority: authority)
                    }
                })
            return 0
        } catch { return 77 }
    }
}
