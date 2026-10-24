import Darwin
import Dispatch
import Foundation

/// Test bundle entry only. The result role and all its checks are production
/// code. This avoids GUI/OTP initialization while observing actual system C.
@main enum VPNRescueSystemProbeMain {
    static func main() {
        let args = CommandLine.arguments
        if let status = VPNInstalledUpdateResultEntry.runIfRequested(arguments: args) { exit(status) }
        // Setup-only fixture role; never compiled into the normal frontend.
        let seedBroker = args.count == 2 && args[1] == "--vm-seed-broker"
        let seedCompleted = args.count == 3 && args[1] == "--vm-seed-completed-broker"
        // Exercise the real signed frontend's executor/recovery roles. Exact
        // VM root setup modes remain outside its ordinary-root launch guard.
        if !seedBroker && !seedCompleted,
           let status = VPNInstallationEntry.runIfRequested(arguments: args) { exit(status) }
        if args.count >= 2 && args[1] == "--vm-submit-update" {
            guard ordinaryVMOwner(), args.count == 3, args[2].hasPrefix("/"),
                  VPNJointUpdateStartupStatus.sealedRelease()?.sequence == 141 else { exit(77) }
            do {
                let candidate = open(args[2], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
                guard candidate >= 0 else { exit(77) }
                defer { close(candidate) }
                var facts = stat()
                guard fstat(candidate, &facts) == 0, facts.st_uid == geteuid(),
                      facts.st_mode & 0o7777 == 0o700 else { exit(77) }
                let outcome = try VPNUpdateBrokerClient.submit(candidateDirectory: candidate,
                    expectedFromSequence: 141, deadline: deadline())
                switch outcome {
                case .indeterminate: print("submit:indeterminate"); exit(75)
                case .response(let response):
                    guard response.fromSequence == 141, response.toSequence == 142 else { exit(77) }
                    // A successful transport or `.ready` is never an installed
                    // receipt. Parent checks the actual startup-status role.
                    switch response.state {
                    case .accepted: print("submit:accepted")
                    case .checking: print("submit:checking")
                    case .ready: print("submit:ready")
                    case .installing: print("submit:installing")
                    case .complete: print("submit:complete")
                    case .failed: print("submit:failed")
                    case .busy: print("submit:busy")
                    case .stale: print("submit:stale")
                    }
                }
                return
            } catch { print("submit:rejected"); exit(77) }
        }
        if args.count >= 2 && args[1] == "--vm-update-status" {
            guard ordinaryVMOwner(), args.count == 2,
                  let sealed = VPNJointUpdateStartupStatus.sealedRelease(),
                  sealed.sequence == 141 || sealed.sequence == 142 else { exit(77) }
            do {
                switch try VPNJointUpdateStartupStatus.check(sealedRelease: sealed, deadline: deadline()) {
                case .idle: print("status:idle")
                case .verifying: print("status:verifying")
                case .installed: print("status:installed")
                case .failed: print("status:failed")
                }
                return
            } catch { print("status:unavailable"); exit(75) }
        }
        guard seedBroker || seedCompleted, getuid() == 0, geteuid() == 0,
              ProcessInfo.processInfo.environment["GITHUB_ACTIONS"] == "true",
              ProcessInfo.processInfo.environment["PROXYPILOT_VM_SYSTEM_RESCUE_TESTS"] == "1" else { exit(64) }
        do {
            let service = try VPNDirectoryProvisioner.openSystemDirectory(create: false)
            defer { close(service) }
            let store = try VPNReleaseStore(trustedDirectoryDescriptor: service,
                                            authority: VPNReleaseTrust.authority())
            if seedCompleted {
                let privateState = try VPNDirectoryProvisioner.openSystemBrokerDirectory(create: false)
                defer { close(privateState) }
                let brokerLease = try VPNLifecycleOwnership.acquire(inTrustedDirectory: privateState)
                defer { brokerLease.release() }
                let serviceLease = try VPNLifecycleOwnership.acquire(inTrustedDirectory: service)
                defer { serviceLease.release() }
                guard let pending = try store.loadUpdateJournal(), pending.phase == .replacementPending,
                      pending.revision == 1, pending.previous.release.sequence == 137,
                      pending.candidate.release.sequence == 139 else { exit(77) }
                _ = try VPNInstalledApplication.inspect(release: pending.candidate.release)
                let source = open(args[2], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
                guard source >= 0 else { exit(77) }
                defer { close(source) }
                let payload = try VPNJointUpdatePayload.loadForBroker(inTrustedDirectory: source,
                                                                      authority: VPNReleaseTrust.authority())
                guard payload.previous.isSameRelease(as: pending.previous.release),
                      payload.candidate.release.isSameRelease(as: pending.candidate.release),
                      pending.transition.matchesSource(payload.previous),
                      pending.transition.matchesDestination(payload.candidate.release) else { exit(77) }
                let inbox = try VPNUpdateBrokerInbox(trustedParent: privateState)
                let copied = try inbox.ingest(sourceDirectory: source, checkpoint: { _ in })
                let transactions = try VPNUpdateBrokerTransactionStore(trustedDirectoryDescriptor: privateState)
                var transaction = try transactions.begin(identity: copied.identity, fromSequence: 137, toSequence: 139)
                transaction = try transactions.advance(identity: copied.identity, expectedRevision: transaction.revision,
                    phase: .authorized, journal: nil, recovery: .inboxRetained, rotation: .notStarted)
                transaction = try transactions.advance(identity: copied.identity, expectedRevision: transaction.revision,
                    phase: .prepared, journal: VPNUpdateBrokerJournalReference(transactionID: pending.transactionID, revision: 0, phase: .prepared),
                    recovery: .journalRetained, rotation: .notStarted)
                transaction = try transactions.advance(identity: copied.identity, expectedRevision: transaction.revision,
                    phase: .handoffStarted, journal: VPNUpdateBrokerJournalReference(transactionID: pending.transactionID, revision: 1, phase: .replacementPending),
                    recovery: .journalRetained, rotation: .pending)
                let selected = try store.selectUpdateCandidate(transactionID: pending.transactionID, expectedRevision: 1)
                let completed = try store.completeUpdateJournal(transactionID: selected.transactionID, expectedRevision: 2)
                let reference = VPNUpdateBrokerJournalReference(transactionID: completed.transactionID, revision: 3, phase: .completed)
                transaction = try transactions.advance(identity: copied.identity, expectedRevision: transaction.revision,
                    phase: .handoffComplete, journal: reference, recovery: .executorCommitted, rotation: .pending)
                transaction = try transactions.advance(identity: copied.identity, expectedRevision: transaction.revision,
                    phase: .rotatingBroker, journal: reference, recovery: .executorCommitted, rotation: .complete)
                guard transaction.phase == .rotatingBroker, transaction.journal == reference else { exit(77) }
                print("Seeded exact completed service journal and broker phase6"); return
            }
            let selected = try store.loadDeployment()
            guard selected.release.sequence == 137 else { exit(77) }
            let endpoint = try VPNEndpointDirectory.openSystem(create: true)
            close(endpoint)
            let job = try VPNUpdateBrokerLaunchdJob.system(storageDirectory: service)
            try job.installAndStart(selected, deadline: DispatchTime.now().uptimeNanoseconds + 20_000_000_000)
            print("Seeded authenticated old system broker")
        } catch { exit(77) }
    }

    private static func ordinaryVMOwner() -> Bool {
        getuid() == geteuid() && getuid() >= 500 && getuid() != uid_t.max
            && ProcessInfo.processInfo.environment["GITHUB_ACTIONS"] == "true"
            && ProcessInfo.processInfo.environment["PROXYPILOT_VM_SYSTEM_RESCUE_TESTS"] == "1"
    }

    private static func deadline() -> UInt64 {
        DispatchTime.now().uptimeNanoseconds + 20_000_000_000
    }

}
