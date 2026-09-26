import Darwin
import Foundation

/// Production hidden role for the newly installed B readiness child. All trust
/// comes from the protected journal; no release, UID, path, or operation is
/// accepted from argv or the parent.
enum VPNInstalledCandidateEntry {
    static func runIfRequested(arguments: [String]) -> Int32? {
        guard arguments.count == 2,
              arguments[1] == VPNInstalledCandidateHandoff.childArgument else { return nil }
        guard getuid() == 0, geteuid() == 0 else { return 77 }
        do {
            let authority = try VPNReleaseTrust.authority()
            let directory = try VPNDirectoryProvisioner.openSystemDirectory(create: false)
            defer { close(directory) }
            let store = try VPNReleaseStore(trustedDirectoryDescriptor: directory,
                                            authority: authority)
            guard let initial = try store.loadUpdateJournal(),
                  initial.phase == .replacementPending,
                  initial.recovery == .inspectApplication else {
                throw VPNReleaseStoreError.invalidUpdateJournal
            }
            let selfPolicy = try initial.candidate.release.installerPolicy()
            let parentPolicy = try initial.previous.release.installerPolicy()
            try VPNPeerAuthentication.validateCurrentProcess(policy: selfPolicy)
            return VPNInstalledCandidateHandoff.runChildIfRequested(
                arguments: arguments, selfPolicy: selfPolicy,
                parentPolicy: parentPolicy,
                validateContext: {
                    guard let fresh = try store.loadUpdateJournal(),
                          fresh.transactionID == initial.transactionID,
                          fresh.revision == initial.revision,
                          fresh.phase == .replacementPending,
                          fresh.recovery == .inspectApplication,
                          fresh.previous.ownerUserID == initial.previous.ownerUserID,
                          fresh.previous.release.isSameRelease(as: initial.previous.release),
                          fresh.candidate.release.isSameRelease(as: initial.candidate.release) else {
                        throw VPNReleaseStoreError.staleRevision
                    }
                }) ?? 77
        } catch { return 77 }
    }
}
