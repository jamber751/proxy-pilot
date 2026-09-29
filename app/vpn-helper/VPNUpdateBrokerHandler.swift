import Darwin
import Foundation

enum VPNUpdateBrokerHandlerError: Error {
    case invalidRequest
    case invalidJournal
    case brokerRotationNotReady
}

/// Owns one descriptor-only A→B broker transaction. The public request carries
/// only the selected sequence; all release identity is recovered from the
/// root-private inbox and authenticated signed records.
final class VPNUpdateBrokerHandler {
    private var serviceDirectory: Int32
    private var privateDirectory: Int32
    private let authority: VPNReleaseAuthority
    private let inbox: VPNUpdateBrokerInbox
    private let statusStore: VPNUpdateBrokerStatusStore
    private let transactionStore: VPNUpdateBrokerTransactionStore

    init(serviceDirectory: Int32, privateDirectory: Int32,
         authority: VPNReleaseAuthority) throws {
        self.serviceDirectory = fcntl(serviceDirectory, F_DUPFD_CLOEXEC, 0)
        self.privateDirectory = fcntl(privateDirectory, F_DUPFD_CLOEXEC, 0)
        guard self.serviceDirectory >= 0, self.privateDirectory >= 0 else {
            if self.serviceDirectory >= 0 { close(self.serviceDirectory) }
            if self.privateDirectory >= 0 { close(self.privateDirectory) }
            throw VPNUpdateBrokerHandlerError.invalidRequest
        }
        self.authority = authority
        do {
            inbox = try VPNUpdateBrokerInbox(trustedParent: privateDirectory)
            statusStore = try VPNUpdateBrokerStatusStore(
                trustedDirectoryDescriptor: privateDirectory)
            transactionStore = try VPNUpdateBrokerTransactionStore(
                trustedDirectoryDescriptor: privateDirectory)
        } catch {
            close(self.serviceDirectory)
            close(self.privateDirectory)
            self.serviceDirectory = -1
            self.privateDirectory = -1
            throw error
        }
    }

    deinit {
        if serviceDirectory >= 0 { close(serviceDirectory) }
        if privateDirectory >= 0 { close(privateDirectory) }
    }

    /// Consumes and closes `candidateDirectory`, including every failure path.
    func submit(_ request: VPNUpdateBrokerRequest,
                candidateDirectory: Int32) throws -> VPNUpdateBrokerResponse {
        try performSubmit(request, candidateDirectory: candidateDirectory,
                          checkpoint: { _ in })
    }

    func status(selectedSequence: UInt64) throws -> VPNUpdateBrokerResponse {
        if let response = try statusStore.load().response { return response }
        return VPNUpdateBrokerResponse(
            state: .complete, fromSequence: selectedSequence,
            toSequence: selectedSequence, revision: 0)
    }

    /// Restarts only a transaction already owned by this broker's private
    /// receipt and inbox. No caller connection, path, or descriptor is needed.
    func resumeIfNeeded() throws {
        guard let transaction = try transactionStore.load(),
              transaction.phase == .accepted
                || transaction.phase == .authorized
                || transaction.phase == .prepared
                || transaction.phase == .handoffStarted else { return }
        let ownership = try VPNLifecycleOwnership.acquire(
            inTrustedDirectory: privateDirectory)
        defer { ownership.release() }
        let published = try inbox.openPublished(identity: transaction.identity)
        defer { close(published) }
        let authorization = try VPNUpdateBroker.authorizePrivateInbox(
            published, expectedFromSequence: transaction.fromSequence,
            serviceDirectory: serviceDirectory, authority: authority)
        guard authorization.payload.candidate.release.sequence
                == transaction.toSequence else {
            throw VPNUpdateBrokerHandlerError.invalidRequest
        }
        _ = try continueAuthorized(
            identity: transaction.identity, published: published,
            authorization: authorization, checkpoint: { _ in })
    }

    #if VPN_UPDATE_BROKER_HANDLER_TESTING
    func testSubmit(_ request: VPNUpdateBrokerRequest,
                    candidateDirectory: Int32,
                    checkpoint: (String) throws -> Void) throws
        -> VPNUpdateBrokerResponse {
        try performSubmit(request, candidateDirectory: candidateDirectory,
                          checkpoint: checkpoint)
    }
    #endif

    private func performSubmit(
        _ request: VPNUpdateBrokerRequest, candidateDirectory: Int32,
        checkpoint: (String) throws -> Void
    ) throws -> VPNUpdateBrokerResponse {
        guard request.operation == .submit, request.expectedFromSequence > 0,
              candidateDirectory >= 0 else {
            if candidateDirectory >= 0 { close(candidateDirectory) }
            throw VPNUpdateBrokerHandlerError.invalidRequest
        }
        defer { close(candidateDirectory) }

        let ownership: VPNLifecycleLease
        do {
            ownership = try VPNLifecycleOwnership.acquire(
                inTrustedDirectory: privateDirectory)
        } catch VPNLifecycleOwnershipError.busy {
            return try transient(.busy, from: request.expectedFromSequence)
        }
        defer { ownership.release() }
        try retireCompletedTransactionIfPresent()

        let receipt: VPNUpdateBrokerInboxReceipt
        do {
            receipt = try inbox.ingest(
                sourceDirectory: candidateDirectory, checkpoint: { _ in })
        } catch VPNUpdateBrokerInboxError.rejectedConflict {
            return try transient(.busy, from: request.expectedFromSequence)
        }
        try checkpoint("afterInbox")
        _ = try statusStore.publish(
            state: .accepted, fromSequence: request.expectedFromSequence,
            toSequence: 0)
        _ = try statusStore.publish(
            state: .checking, fromSequence: request.expectedFromSequence,
            toSequence: 0)

        let published = try inbox.openPublished(identity: receipt.identity)
        defer { close(published) }
        let authorization: VPNUpdateBrokerAuthorization
        do {
            authorization = try VPNUpdateBroker.authorizePrivateInbox(
                published, expectedFromSequence: request.expectedFromSequence,
                serviceDirectory: serviceDirectory, authority: authority)
        } catch {
            try inbox.retirePublished(identity: receipt.identity)
            _ = try statusStore.publish(
                state: .failed,
                fromSequence: request.expectedFromSequence, toSequence: 0)
            throw error
        }
        try checkpoint("afterAuthorization")

        return try continueAuthorized(
            identity: receipt.identity, published: published,
            authorization: authorization, checkpoint: checkpoint)
    }

    private func continueAuthorized(
        identity: Data, published: Int32,
        authorization: VPNUpdateBrokerAuthorization,
        checkpoint: (String) throws -> Void
    ) throws -> VPNUpdateBrokerResponse {

        let from = authorization.selected.release.sequence
        let to = authorization.payload.candidate.release.sequence
        var transaction = try transactionStore.begin(
            identity: identity, fromSequence: from, toSequence: to)
        if transaction.phase == .accepted {
            transaction = try advance(
                transaction, phase: .authorized, journal: nil,
                recovery: .inboxRetained, rotation: .notStarted)
        }

        let preparation = try VPNJointUpdatePreparation.prepareFromBroker(
            candidateDirectory: published, payload: authorization.payload,
            authority: authority)
        try checkpoint("afterPreparation")
        let journal = try brokerJournal(preparation.journal)
        if transaction.phase == .authorized {
            transaction = try advance(
                transaction, phase: .prepared, journal: journal,
                recovery: .journalRetained, rotation: .notStarted)
        }

        // The signed journal plus the exact retained inbox are the recovery
        // evidence. The executor itself arms the launchd recovery job before it
        // drains A; no status or receipt is treated as authorization.
        try checkpoint("afterRecoveryArm")
        if transaction.phase == .prepared {
            transaction = try advance(
                transaction, phase: .prepared, journal: journal,
                recovery: .journalRetained, rotation: .pending)
        }
        try checkpoint("afterBrokerRotationReady")
        if transaction.phase == .prepared {
            _ = try statusStore.publish(
                state: .ready, fromSequence: from, toSequence: to)
        }
        try checkpoint("beforeHandoff")

        let update = try VPNDirectoryProvisioner.openSystemUpdateDirectory(create: false)
        defer { close(update) }
        _ = try statusStore.publish(
            state: .installing, fromSequence: from, toSequence: to)
        if transaction.phase != .handoffStarted {
            transaction = try advance(
                transaction, phase: .handoffStarted, journal: journal,
                recovery: .journalRetained, rotation: .pending)
        }
        _ = try VPNReplacementExecutorHandoff.launchPreparedFromBroker(
            inTrustedDirectory: update,
            release: authorization.payload.previous,
            request: VPNExecutorHandoffRequest(
                transactionID: preparation.journal.transactionID,
                expectedRevision: preparation.journal.revision))
        try checkpoint("afterHandoff")

        // Successful return means the protected child completed replacement.
        // Broker rotation/final status are committed by the child before the
        // journal is retired; re-read that durable result instead of inventing
        // authority in this process (which may already have been booted out).
        if let final = try statusStore.load().response,
           final.state == .complete { return final }
        throw VPNUpdateBrokerHandlerError.brokerRotationNotReady
    }

    private func advance(
        _ current: VPNUpdateBrokerTransactionSnapshot,
        phase: VPNUpdateBrokerTransactionPhase,
        journal: VPNUpdateBrokerJournalReference?,
        recovery: VPNUpdateBrokerRecoveryState,
        rotation: VPNUpdateBrokerRotationState
    ) throws -> VPNUpdateBrokerTransactionSnapshot {
        try transactionStore.advance(
            identity: current.identity, expectedRevision: current.revision,
            phase: phase, journal: journal,
            recovery: recovery, rotation: rotation)
    }

    private func retireCompletedTransactionIfPresent() throws {
        guard let current = try transactionStore.load(),
              current.phase == .complete else { return }
        try inbox.retirePublished(identity: current.identity)
        try transactionStore.retireCompleted(
            identity: current.identity, expectedRevision: current.revision)
    }

    private func transient(_ state: VPNUpdateBrokerState,
                           from: UInt64) throws -> VPNUpdateBrokerResponse {
        let current = try statusStore.load()
        return VPNUpdateBrokerResponse(
            state: state, fromSequence: from,
            toSequence: current.toSequence, revision: current.revision)
    }

    private func brokerJournal(_ value: VPNUpdateJournalSnapshot) throws
        -> VPNUpdateBrokerJournalReference {
        let phase: VPNUpdateBrokerJournalPhase
        switch value.phase {
        case .prepared: phase = .prepared
        case .replacementPending: phase = .replacementPending
        case .selected: phase = .selected
        case .completed: phase = .completed
        case .cancelled: phase = .cancelled
        case .cancellationApplicationRetired:
            phase = .cancellationApplicationRetired
        case .cancellationUpdateRetired:
            phase = .cancellationUpdateRetired
        case .cancellationGCAuthorized:
            phase = .cancellationGCAuthorized
        }
        return VPNUpdateBrokerJournalReference(
            transactionID: value.transactionID,
            revision: value.revision, phase: phase)
    }
}
