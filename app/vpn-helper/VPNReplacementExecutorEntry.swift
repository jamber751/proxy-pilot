import Darwin
import Foundation

/// Production-only composition for the fixed hidden A role. It obtains trust
/// and the previous-release policy from protected local state, never from argv,
/// the parent process, updater metadata or user preferences. The request still
/// has to match that same journal inside VPNJointApplicationReplacement.
enum VPNReplacementExecutorEntry {
    static func runIfRequested(arguments: [String]) -> Int32? {
        guard arguments.count == 2,
              arguments[1] == VPNReplacementExecutorHandoff.childArgument
                || arguments[1] == VPNReplacementExecutorHandoff.brokerChildArgument else {
            return nil
        }
        guard getuid() == 0, geteuid() == 0 else { return 77 }
        do {
            let authority = try VPNReleaseTrust.authority()
            let directory = try VPNDirectoryProvisioner.openSystemDirectory(create: false)
            let journal: VPNUpdateJournalSnapshot
            do {
                defer { close(directory) }
                let store = try VPNReleaseStore(trustedDirectoryDescriptor: directory,
                                                authority: authority)
                guard let loaded = try store.loadUpdateJournal() else {
                    throw VPNReleaseStoreError.invalidUpdateJournal
                }
                let prepared = loaded.phase == .prepared
                    && loaded.recovery == .canCancelOrReplace
                let pending = loaded.phase == .replacementPending
                    && loaded.recovery == .inspectApplication
                guard prepared || pending else {
                    throw VPNReleaseStoreError.invalidUpdateJournal
                }
                journal = loaded
            }
            let selfPolicy = try journal.previous.release.installerPolicy()
            let brokerRole = arguments[1]
                == VPNReplacementExecutorHandoff.brokerChildArgument
            let parentPolicy = try brokerRole
                ? journal.previous.release.helperPolicy()
                : journal.candidate.release.installerPolicy()
            let operation: (VPNExecutorHandoffRequest, Int32) throws
                -> VPNProtectedApplicationSwap.Outcome = { request, applicationDirectory in
                    try VPNJointApplicationReplacement.installPreparedOrPendingApplication(
                        applicationDirectory: applicationDirectory,
                        transactionID: request.transactionID,
                        expectedRevision: request.expectedRevision,
                        authority: authority)
                }
            if brokerRole {
                return VPNReplacementExecutorHandoff.runBrokerChildIfRequested(
                    arguments: arguments, selfPolicy: selfPolicy,
                    parentPolicy: parentPolicy,
                    failureDiagnostic: { error in
                        (error as? VPNJointApplicationReplacementFailure)?.diagnosticByte
                    }, operation: operation) ?? 77
            }
            return VPNReplacementExecutorHandoff.runChildIfRequested(
                arguments: arguments, selfPolicy: selfPolicy,
                parentPolicy: parentPolicy,
                failureDiagnostic: { error in
                    (error as? VPNJointApplicationReplacementFailure)?.diagnosticByte
                }, operation: operation) ?? 77
        } catch {
            return 77
        }
    }
}
