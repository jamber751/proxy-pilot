import Darwin
import Foundation

/// Production-only composition for the fixed hidden A role. It obtains trust
/// and the previous-release policy from protected local state, never from argv,
/// the parent process, updater metadata or user preferences. The request still
/// has to match that same journal inside VPNJointApplicationReplacement.
enum VPNReplacementExecutorEntry {
    static func runIfRequested(arguments: [String]) -> Int32? {
        guard arguments.count == 2,
              arguments[1] == VPNReplacementExecutorHandoff.childArgument else { return nil }
        guard getuid() == 0, geteuid() == 0 else { return 77 }
        do {
            let authority = try VPNReleaseTrust.authority()
            let directory = try VPNDirectoryProvisioner.openSystemDirectory(create: false)
            let journal: VPNUpdateJournalSnapshot
            do {
                defer { close(directory) }
                let store = try VPNReleaseStore(trustedDirectoryDescriptor: directory,
                                                authority: authority)
                guard let loaded = try store.loadUpdateJournal(),
                      loaded.phase == .replacementPending,
                      loaded.recovery == .inspectApplication else {
                    throw VPNReleaseStoreError.invalidUpdateJournal
                }
                journal = loaded
            }
            let policy = try journal.previous.release.installerPolicy()
            return VPNReplacementExecutorHandoff.runChildIfRequested(
                arguments: arguments, selfPolicy: policy, parentPolicy: policy,
                operation: { request, applicationDirectory in
                    try VPNJointApplicationReplacement.installPreparedApplication(
                        applicationDirectory: applicationDirectory,
                        transactionID: request.transactionID,
                        expectedRevision: request.expectedRevision,
                        authority: authority)
                }) ?? 77
        } catch {
            return 77
        }
    }
}
