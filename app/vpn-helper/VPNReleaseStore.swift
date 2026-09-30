import Darwin
import Foundation

enum VPNReleaseStoreError: Error {
    case unsafeStorage
    case busy
    case invalidState
    case alreadyInitialized
    case staleRevision
    case writeFailed
    case commitUncertain
    case deploymentRequired
    case updateInProgress
    case invalidUpdateJournal
    case invalidUpdatePreparation
    case cleanupPending
    case invalidCleanupReceipt
}

enum VPNUpdateJournalPhase: String, Codable {
    case prepared, replacementPending, selected, completed, cancelled
    case cancellationApplicationRetired, cancellationUpdateRetired
    case cancellationGCAuthorized
}

enum VPNUpdateCleanupPhase: String, Codable {
    case pending, applicationRetired, updateRetired, gcAuthorized
}

enum VPNUpdatePreparationPhase: String, Codable { case staging, gcAuthorized }

struct VPNUpdateCleanupRootIdentity: Codable, Equatable {
    let name: String
    let device: UInt64
    let inode: UInt64
}

/// Recovery instructions for a future trusted coordinator, NOT runtime evidence
/// or authorization to replace an app/start a service.
enum VPNUpdateRecovery: String {
    case canCancelOrReplace, inspectApplication, recoverCandidate, completed, cancelled
}

struct VPNUpdateJournalSnapshot {
    let transactionID: UUID
    let revision: UInt64
    let phase: VPNUpdateJournalPhase
    let recovery: VPNUpdateRecovery
    let previous: VPNAuthorizedDeployment
    let candidate: VPNAuthorizedDeployment
    let transition: VerifiedVPNUpdateTransition
    let cancellationGCRoots: [VPNUpdateCleanupRootIdentity]?
    fileprivate init(_ record: VPNReleaseStore.UpdateJournal, previous: VPNAuthorizedDeployment,
                     candidate: VPNAuthorizedDeployment, recovery: VPNUpdateRecovery,
                     transition: VerifiedVPNUpdateTransition) {
        transactionID = record.transactionID; revision = record.revision
        phase = record.phase; self.previous = previous; self.candidate = candidate
        self.recovery = recovery
        self.transition = transition
        cancellationGCRoots = record.cleanupRoots
    }
}

struct VPNUpdatePreparationSnapshot {
    let transactionID: UUID
    let ownerUserID: uid_t
    let previous: VPNAuthorizedDeployment
    let candidate: VPNAuthorizedDeployment
    let transition: VerifiedVPNUpdateTransition
    let phase: VPNUpdatePreparationPhase
    let cleanupRoots: [VPNUpdateCleanupRootIdentity]?
    fileprivate init(_ record: VPNReleaseStore.UpdatePreparation,
                     previous: VPNAuthorizedDeployment,
                     candidate: VPNAuthorizedDeployment,
                     transition: VerifiedVPNUpdateTransition) {
        transactionID = record.transactionID; ownerUserID = record.owner
        self.previous = previous; self.candidate = candidate
        self.transition = transition; phase = record.phase
        cleanupRoots = record.cleanupRoots
    }
}

/// Durable evidence retained after a completed joint update. This is not
/// runtime readiness evidence and grants no authority to remove artifacts.
struct VPNUpdateCleanupReceiptSnapshot {
    let transactionID: UUID
    let revision: UInt64
    let phase: VPNUpdateJournalPhase
    let ownerUserID: uid_t
    let previous: VPNAuthorizedDeployment
    let candidate: VPNAuthorizedDeployment
    let transition: VerifiedVPNUpdateTransition
    let cleanupPhase: VPNUpdateCleanupPhase
    let gcRoots: [VPNUpdateCleanupRootIdentity]?
    fileprivate init(_ journal: VPNUpdateJournalSnapshot, cleanupPhase: VPNUpdateCleanupPhase,
                     gcRoots: [VPNUpdateCleanupRootIdentity]?) {
        transactionID = journal.transactionID; revision = journal.revision
        phase = journal.phase; ownerUserID = journal.candidate.ownerUserID
        previous = journal.previous; candidate = journal.candidate
        transition = journal.transition
        self.cleanupPhase = cleanupPhase
        self.gcRoots = gcRoots
    }
}

struct VPNAuthorizedRelease {
    let ownerUserID: uid_t
    let release: VerifiedVPNRelease
}

/// A verified on-disk selection, NOT evidence of a running/healthy service.
struct VPNAuthorizedDeployment {
    let ownerUserID: uid_t
    let release: VerifiedVPNRelease
    let helperFileName: String
    let engineFileName: String?
    fileprivate init(_ state: VPNAuthorizedRelease) {
        ownerUserID = state.ownerUserID
        release = state.release
        helperFileName = state.release.helperArtifactName
        engineFileName = state.release.engine?.artifactName
    }
}

/// Opaque, staged update. Possession does not authorize starting a process.
/// Commit always rechecks protected current state and the candidate file.
struct VPNPreparedDeployment {
    let previous: VPNAuthorizedDeployment
    let candidate: VPNAuthorizedDeployment
    fileprivate let payload: Data
    fileprivate let signature: Data
    fileprivate init(previous: VPNAuthorizedDeployment, candidate: VPNAuthorizedDeployment,
                     payload: Data, signature: Data) {
        self.previous = previous
        self.candidate = candidate
        self.payload = payload
        self.signature = signature
    }
}

/// A descriptor-relative policy store, NOT an installer or helper activator.
/// Production must supply a securely opened root-owned directory under fixed,
/// protected parents and run as root. Tests exercise the same checks using the
/// test process's UID and a private disposable directory. Never accept this fd
/// from IPC or use the unprivileged app's profile/preferences directory.
final class VPNReleaseStore {
    fileprivate struct UpdatePreparation: Codable {
        let schema: Int
        let transactionID: UUID
        let owner: uid_t
        let previousPayload: Data
        let previousSignature: Data
        let candidatePayload: Data
        let candidateSignature: Data
        let transitionPayload: Data
        let transitionSignature: Data
        var phase: VPNUpdatePreparationPhase
        var cleanupRoots: [VPNUpdateCleanupRootIdentity]? = nil
    }
    fileprivate struct UpdateJournal: Codable {
        let schema: Int
        let transactionID: UUID
        var revision: UInt64
        var phase: VPNUpdateJournalPhase
        let owner: uid_t
        let previousPayload: Data
        let previousSignature: Data
        let candidatePayload: Data
        let candidateSignature: Data
        let transitionPayload: Data
        let transitionSignature: Data
        var cleanupRoots: [VPNUpdateCleanupRootIdentity]? = nil
    }
    fileprivate struct CleanupReceipt: Codable {
        let schema: Int
        var phase: VPNUpdateCleanupPhase
        var gcRoots: [VPNUpdateCleanupRootIdentity]?
        let journal: UpdateJournal
    }
    private struct Envelope: Codable {
        let schema: Int
        let owner: uid_t
        let payload: Data
        let signature: Data
    }
    private var directory: Int32
    private let storageOwner = geteuid()
    private let authority: VPNReleaseAuthority
    private static let marker = Data("ProxyPilot VPN release policy v1\n".utf8)
    private static let maximumRecordBytes = 8192
    private let recordName = "release.json"
    private let markerName = "initialized"
    private let journalName = "update.json"
    private let preparationName = "preparation.json"
    private let cleanupName = "cleanup.json"
    private static let maximumJournalBytes = 32768
    private static let maximumPreparationBytes = 32768
    // A receipt nests one already size-bounded journal plus a small schema
    // envelope; every valid journal must remain representable.
    private static let maximumCleanupBytes = maximumJournalBytes + 1024

    #if VPN_RELEASE_STORE_TESTING
    // Compiled only into the crash-test executable, never into a release build.
    static var checkpoint: ((String) -> Void)?
    #endif

    init(trustedDirectoryDescriptor: Int32, authority: VPNReleaseAuthority) throws {
        directory = fcntl(trustedDirectoryDescriptor, F_DUPFD_CLOEXEC, 0)
        guard directory >= 0 else { throw VPNReleaseStoreError.unsafeStorage }
        self.authority = authority
        do { try checkDirectory() }
        catch { close(directory); directory = -1; throw error }
    }

    deinit { if directory >= 0 { close(directory) } }

    func load() throws -> VPNAuthorizedRelease {
        try withLock { try readCurrent().1 }
    }

    func loadDeployment() throws -> VPNAuthorizedDeployment {
        try withLock {
            let (envelope, state) = try readCurrent()
            guard envelope.schema == 2 else { throw VPNReleaseStoreError.deploymentRequired }
            return VPNAuthorizedDeployment(state)
        }
    }

    func loadDeploymentReceipt() throws
        -> (ownerUserID: uid_t, payload: Data, signature: Data) {
        try withLock {
            let (envelope, state) = try readCurrent()
            guard envelope.schema == 2 else { throw VPNReleaseStoreError.deploymentRequired }
            return (state.ownerUserID, envelope.payload, envelope.signature)
        }
    }

    /// Also rejects terminal/corrupt journals: retirement is a separate durable
    /// action. Read-only selection remains available for diagnosis/reconciliation.
    func requireNoPendingUpdate() throws {
        try withLock { try requireNoPreparation(); try requireNoJournal() }
    }

    func loadUpdateJournal() throws -> VPNUpdateJournalSnapshot? {
        try withLock { try readJournal()?.1 }
    }

    func loadUpdatePreparation() throws -> VPNUpdatePreparationSnapshot? {
        try withLock { try readPreparation()?.1 }
    }

    /// Completes the only valid two-record conversion state without requiring
    /// untrusted package input. Both records contain the exact signed bytes and
    /// transaction id, and journal validation rechecks the stored artifacts.
    @discardableResult
    func finishUpdatePreparationConversion() throws -> VPNUpdateJournalSnapshot? {
        try withLock {
            try requireNoCleanupReceipt()
            guard let (preparation, _) = try readPreparation() else { return nil }
            guard preparation.phase == .staging,
                  let (journal, snapshot) = try readJournal(),
                  journalMatchesPreparation(journal, preparation) else {
                // A preparation by itself is not a conversion to finish. Any
                // other coexistence is corrupt and must remain fail-closed.
                if try readFile(journalName, limit: Self.maximumJournalBytes) == nil {
                    return nil
                }
                throw VPNReleaseStoreError.invalidUpdatePreparation
            }
            _ = try validateJournal(journal)
            try unlinkPreparation()
            return snapshot
        }
    }

    @discardableResult
    func beginUpdatePreparation(payload: Data, signature: Data, helper: Data,
                                engine: Data? = nil, transitionPayload: Data,
                                transitionSignature: Data,
                                expectedSequence: UInt64) throws
        -> VPNUpdatePreparationSnapshot {
        try withLock {
            try requireNoCleanupReceipt()
            let (currentEnvelope, current) = try readCurrent()
            guard currentEnvelope.schema == 2 else { throw VPNReleaseStoreError.deploymentRequired }
            guard current.release.sequence == expectedSequence else {
                throw VPNReleaseStoreError.staleRevision
            }
            let transition = try authority.verifyUpdateTransition(
                payload: transitionPayload, signature: transitionSignature,
                previous: current.release, candidatePayload: payload,
                candidateSignature: signature)
            let candidate = try authority.verify(payload: payload, signature: signature,
                                                 previous: current.release)
            try candidate.validateArtifacts(helper: helper, engine: engine)
            let expected = UpdatePreparation(
                schema: 1, transactionID: UUID(), owner: current.ownerUserID,
                previousPayload: currentEnvelope.payload,
                previousSignature: currentEnvelope.signature,
                candidatePayload: payload, candidateSignature: signature,
                transitionPayload: transitionPayload,
                transitionSignature: transitionSignature, phase: .staging)
            if let (existing, snapshot) = try readPreparation() {
                guard existing.phase == .staging,
                      existing.owner == expected.owner,
                      existing.previousPayload == expected.previousPayload,
                      existing.previousSignature == expected.previousSignature,
                      existing.candidatePayload == expected.candidatePayload,
                      existing.candidateSignature == expected.candidateSignature,
                      existing.transitionPayload == expected.transitionPayload,
                      existing.transitionSignature == expected.transitionSignature else {
                    throw VPNReleaseStoreError.invalidUpdatePreparation
                }
                return snapshot
            }
            try requireNoJournal()
            _ = transition
            try replace(preparationName, with: encodePreparation(expected))
            #if VPN_RELEASE_STORE_TESTING
            Self.checkpoint?("preparation.json:after-commit")
            #endif
            return try validatePreparation(expected)
        }
    }

    @discardableResult
    func commitUpdatePreparation(transactionID: UUID, helper: Data,
                                 engine: Data? = nil) throws -> VPNUpdateJournalSnapshot {
        try withLock {
            try requireNoCleanupReceipt()
            guard let (preparation, snapshot) = try readPreparation(),
                  preparation.transactionID == transactionID,
                  preparation.phase == .staging else {
                throw VPNReleaseStoreError.invalidUpdatePreparation
            }
            if let (journal, result) = try readJournal() {
                guard journalMatchesPreparation(journal, preparation) else {
                    throw VPNReleaseStoreError.invalidUpdatePreparation
                }
                try validateStoredArtifacts(snapshot.candidate.release)
                try unlinkPreparation()
                return result
            }
            try snapshot.candidate.release.validateArtifacts(helper: helper, engine: engine)
            try stageArtifacts(helper: helper, engine: engine,
                               release: snapshot.candidate.release)
            #if VPN_RELEASE_STORE_TESTING
            Self.checkpoint?("preparation.json:after-artifacts")
            #endif
            let journal = UpdateJournal(
                schema: 1, transactionID: preparation.transactionID,
                revision: 0, phase: .prepared, owner: preparation.owner,
                previousPayload: preparation.previousPayload,
                previousSignature: preparation.previousSignature,
                candidatePayload: preparation.candidatePayload,
                candidateSignature: preparation.candidateSignature,
                transitionPayload: preparation.transitionPayload,
                transitionSignature: preparation.transitionSignature)
            try replace(journalName, with: encodeJournal(journal))
            #if VPN_RELEASE_STORE_TESTING
            Self.checkpoint?("preparation.json:after-journal")
            #endif
            guard journalMatchesPreparation(journal, preparation) else {
                throw VPNReleaseStoreError.invalidUpdatePreparation
            }
            let result = try validateJournal(journal)
            try unlinkPreparation()
            return result
        }
    }

    func loadUpdateCleanupReceipt() throws -> VPNUpdateCleanupReceiptSnapshot? {
        try withLock { try readCleanupReceipt()?.1 }
    }

    /// Disk-only preparation. The production caller must first authenticate the
    /// source app and hold lifecycle ownership. No IPC/installer entry calls this
    /// yet. Staging and journal persistence do not advance the selected floor.
    @discardableResult
    func prepareUpdateJournal(payload: Data, signature: Data, helper: Data, engine: Data? = nil,
                              transitionPayload: Data, transitionSignature: Data,
                              expectedSequence: UInt64) throws -> VPNUpdateJournalSnapshot {
        try withLock {
            try requireNoCleanupReceipt()
            try requireNoPreparation()
            try requireNoJournal()
            let (currentEnvelope, current) = try readCurrent()
            guard currentEnvelope.schema == 2 else { throw VPNReleaseStoreError.deploymentRequired }
            guard current.release.sequence == expectedSequence else { throw VPNReleaseStoreError.staleRevision }
            _ = try authority.verifyUpdateTransition(payload: transitionPayload, signature: transitionSignature,
                previous: current.release, candidatePayload: payload, candidateSignature: signature)
            let candidate = try authority.verify(payload: payload, signature: signature, previous: current.release)
            try stageArtifacts(helper: helper, engine: engine, release: candidate)
            let record = UpdateJournal(schema: 1, transactionID: UUID(), revision: 0, phase: .prepared,
                owner: current.ownerUserID, previousPayload: currentEnvelope.payload,
                previousSignature: currentEnvelope.signature, candidatePayload: payload,
                candidateSignature: signature, transitionPayload: transitionPayload,
                transitionSignature: transitionSignature)
            try replace(journalName, with: encodeJournal(record))
            return try validateJournal(record)
        }
    }

    /// Write-ahead boundary: after this succeeds cancellation is no longer safe.
    /// The future coordinator must confirm drain and app identity under its lease
    /// before allowing replacement. This method grants no system/IPC authority.
    @discardableResult
    func markUpdateReplacementPending(transactionID: UUID, expectedRevision: UInt64) throws -> VPNUpdateJournalSnapshot {
        try withLock {
            try requireNoCleanupReceipt()
            try requireNoPreparation()
            var (record, _) = try requireJournal(transactionID, revision: expectedRevision)
            guard record.phase == .prepared else { throw VPNReleaseStoreError.invalidUpdateJournal }
            try advanceJournal(&record, to: .replacementPending)
            return try validateJournal(record)
        }
    }

    /// Disk selection only. BEFORE calling, the future coordinator must freshly
    /// verify installed candidate app identity and confirmed service drain while
    /// holding lifecycle ownership. The journal alone never proves either fact.
    /// A crash between selector and phase writes is recovered only forward to B.
    @discardableResult
    func selectUpdateCandidate(transactionID: UUID, expectedRevision: UInt64) throws -> VPNUpdateJournalSnapshot {
        try withLock {
            try requireNoCleanupReceipt()
            try requireNoPreparation()
            var (record, snapshot) = try requireJournal(transactionID, revision: expectedRevision)
            guard record.phase == .replacementPending else { throw VPNReleaseStoreError.invalidUpdateJournal }
            let (_, current) = try readCurrent()
            if current.release.isSameRelease(as: snapshot.previous.release) {
                let envelope = Envelope(schema: 2, owner: record.owner,
                    payload: record.candidatePayload, signature: record.candidateSignature)
                try replace(recordName, with: encode(envelope))
            } else {
                // readJournal validated exact B, never a same-sequence substitute.
                guard fsync(directory) == 0 else { throw VPNReleaseStoreError.commitUncertain }
            }
            try advanceJournal(&record, to: .selected)
            return try validateJournal(record)
        }
    }

    /// Historical completion only, never a ready receipt. Caller must establish
    /// fresh candidate readiness (or explicit desired-off outcome) before this.
    @discardableResult
    func completeUpdateJournal(transactionID: UUID, expectedRevision: UInt64) throws -> VPNUpdateJournalSnapshot {
        try withLock {
            try requireNoCleanupReceipt()
            try requireNoPreparation()
            var (record, _) = try requireJournal(transactionID, revision: expectedRevision)
            guard record.phase == .selected else { throw VPNReleaseStoreError.invalidUpdateJournal }
            try advanceJournal(&record, to: .completed)
            return try validateJournal(record)
        }
    }

    @discardableResult
    func cancelUpdateJournal(transactionID: UUID, expectedRevision: UInt64) throws -> VPNUpdateJournalSnapshot {
        try withLock {
            try requireNoCleanupReceipt()
            try requireNoPreparation()
            var (record, _) = try requireJournal(transactionID, revision: expectedRevision)
            guard record.phase == .prepared else { throw VPNReleaseStoreError.invalidUpdateJournal }
            try advanceJournal(&record, to: .cancelled)
            return try validateJournal(record)
        }
    }

    @discardableResult
    func advanceCancelledUpdateCleanup(transactionID: UUID, expectedRevision: UInt64,
                                       expectedPhase: VPNUpdateJournalPhase,
                                       to phase: VPNUpdateJournalPhase) throws
        -> VPNUpdateJournalSnapshot {
        try withLock {
            try requireNoCleanupReceipt()
            try requireNoPreparation()
            var (record, _) = try requireJournal(transactionID, revision: expectedRevision)
            guard record.phase == expectedPhase else { throw VPNReleaseStoreError.invalidUpdateJournal }
            let valid = expectedPhase == .cancelled && phase == .cancellationApplicationRetired
                || expectedPhase == .cancellationApplicationRetired && phase == .cancellationUpdateRetired
            guard valid, record.cleanupRoots == nil else {
                throw VPNReleaseStoreError.invalidUpdateJournal
            }
            try advanceJournal(&record, to: phase)
            return try validateJournal(record)
        }
    }

    @discardableResult
    func authorizeCancelledUpdateCleanupGC(transactionID: UUID,
                                            expectedRevision: UInt64,
                                            roots: [VPNUpdateCleanupRootIdentity]) throws
        -> VPNUpdateJournalSnapshot {
        try withLock {
            try requireNoCleanupReceipt()
            try requireNoPreparation()
            var (record, _) = try requireJournal(transactionID, revision: expectedRevision)
            guard record.phase == .cancellationUpdateRetired,
                  record.cleanupRoots == nil,
                  validCancelledCleanupRoots(roots) else {
                throw VPNReleaseStoreError.invalidUpdateJournal
            }
            record.cleanupRoots = roots
            try advanceJournal(&record, to: .cancellationGCAuthorized)
            return try validateJournal(record)
        }
    }

    func retireUpdateJournal(transactionID: UUID, expectedRevision: UInt64) throws {
        try withLock {
            try requireNoPreparation()
            let cleanup = try readCleanupReceipt()
            guard let (record, _) = try readJournal() else {
                // A crash after unlink is an ordinary retry, not lost evidence.
                guard let (receipt, _) = cleanup else { throw VPNReleaseStoreError.invalidUpdateJournal }
                guard receipt.journal.transactionID == transactionID,
                      receipt.journal.revision == expectedRevision else {
                    throw VPNReleaseStoreError.staleRevision
                }
                guard fsync(directory) == 0 else { throw VPNReleaseStoreError.commitUncertain }
                return
            }
            guard record.transactionID == transactionID, record.revision == expectedRevision else {
                throw VPNReleaseStoreError.staleRevision
            }
            guard record.phase == .completed || record.phase == .cancellationGCAuthorized else {
                throw VPNReleaseStoreError.invalidUpdateJournal
            }
            if record.phase == .completed {
                let expected = CleanupReceipt(schema: 2, phase: .pending, gcRoots: nil, journal: record)
                if let (existing, _) = cleanup {
                    guard try encodeCleanupReceipt(existing) == encodeCleanupReceipt(expected) else {
                        throw VPNReleaseStoreError.invalidCleanupReceipt
                    }
                } else {
                    try replace(cleanupName, with: encodeCleanupReceipt(expected))
                }
                #if VPN_RELEASE_STORE_TESTING
                // replace() has fsynced both the receipt and its directory by
                // this point, so the journal unlink may safely follow.
                Self.checkpoint?("cleanup.json:after-commit")
                #endif
            } else if cleanup != nil {
                throw VPNReleaseStoreError.cleanupPending
            }
            #if VPN_RELEASE_STORE_TESTING
            Self.checkpoint?("update.json:before-unlink")
            #endif
            guard unlinkat(directory, journalName, 0) == 0 else { throw VPNReleaseStoreError.writeFailed }
            #if VPN_RELEASE_STORE_TESTING
            Self.checkpoint?("update.json:after-unlink")
            #endif
            guard fsync(directory) == 0 else { throw VPNReleaseStoreError.commitUncertain }
        }
    }

    private func requireNoJournal() throws {
        guard try readFile(journalName, limit: Self.maximumJournalBytes) == nil else {
            throw VPNReleaseStoreError.updateInProgress
        }
    }

    private func requireNoPreparation() throws {
        guard try readFile(preparationName, limit: Self.maximumPreparationBytes) == nil else {
            throw VPNReleaseStoreError.updateInProgress
        }
    }

    private func requireNoCleanupReceipt() throws {
        guard try readCleanupReceipt() == nil else { throw VPNReleaseStoreError.cleanupPending }
    }

    @discardableResult
    func authorizeUpdatePreparationCleanup(transactionID: UUID,
                                           roots: [VPNUpdateCleanupRootIdentity]) throws
        -> VPNUpdatePreparationSnapshot {
        try withLock {
            try requireNoCleanupReceipt(); try requireNoJournal()
            guard var (record, _) = try readPreparation(),
                  record.transactionID == transactionID,
                  record.phase == .staging,
                  validPreparationCleanupRoots(roots) else {
                throw VPNReleaseStoreError.invalidUpdatePreparation
            }
            record.phase = .gcAuthorized; record.cleanupRoots = roots
            try replace(preparationName, with: encodePreparation(record))
            return try validatePreparation(record)
        }
    }

    func retireUpdatePreparation(transactionID: UUID) throws {
        try withLock {
            try requireNoCleanupReceipt(); try requireNoJournal()
            guard let (record, _) = try readPreparation(),
                  record.transactionID == transactionID,
                  record.phase == .gcAuthorized else {
                throw VPNReleaseStoreError.invalidUpdatePreparation
            }
            try unlinkPreparation()
        }
    }

    private func unlinkPreparation() throws {
        guard unlinkat(directory, preparationName, 0) == 0 else {
            throw VPNReleaseStoreError.writeFailed
        }
        #if VPN_RELEASE_STORE_TESTING
        Self.checkpoint?("preparation.json:after-unlink")
        #endif
        guard fsync(directory) == 0 else { throw VPNReleaseStoreError.commitUncertain }
    }

    private func journalMatchesPreparation(_ journal: UpdateJournal,
                                           _ preparation: UpdatePreparation) -> Bool {
        journal.schema == 1 && journal.transactionID == preparation.transactionID
            && journal.revision == 0 && journal.phase == .prepared
            && journal.owner == preparation.owner
            && journal.previousPayload == preparation.previousPayload
            && journal.previousSignature == preparation.previousSignature
            && journal.candidatePayload == preparation.candidatePayload
            && journal.candidateSignature == preparation.candidateSignature
            && journal.transitionPayload == preparation.transitionPayload
            && journal.transitionSignature == preparation.transitionSignature
            && journal.cleanupRoots == nil
    }

    private func readPreparation() throws -> (UpdatePreparation, VPNUpdatePreparationSnapshot)? {
        guard let data = try readFile(preparationName,
                                      limit: Self.maximumPreparationBytes) else { return nil }
        do {
            let record = try JSONDecoder().decode(UpdatePreparation.self, from: data)
            guard try encodePreparation(record) == data else {
                throw VPNReleaseStoreError.invalidUpdatePreparation
            }
            return (record, try validatePreparation(record))
        } catch { throw VPNReleaseStoreError.invalidUpdatePreparation }
    }

    private func validatePreparation(_ record: UpdatePreparation) throws
        -> VPNUpdatePreparationSnapshot {
        guard record.schema == 1,
              (record.phase == .gcAuthorized) == (record.cleanupRoots != nil),
              record.cleanupRoots.map(validPreparationCleanupRoots) ?? true else {
            throw VPNReleaseStoreError.invalidUpdatePreparation
        }
        let previous = try authority.verify(payload: record.previousPayload,
                                            signature: record.previousSignature,
                                            previous: nil)
        let transition = try authority.verifyUpdateTransition(
            payload: record.transitionPayload, signature: record.transitionSignature,
            previous: previous, candidatePayload: record.candidatePayload,
            candidateSignature: record.candidateSignature)
        let candidate = try authority.verify(payload: record.candidatePayload,
                                             signature: record.candidateSignature,
                                             previous: previous)
        let (envelope, current) = try readCurrent()
        guard envelope.schema == 2, current.ownerUserID == record.owner,
              current.release.isSameRelease(as: previous) else {
            throw VPNReleaseStoreError.invalidUpdatePreparation
        }
        return VPNUpdatePreparationSnapshot(record,
            previous: VPNAuthorizedDeployment(VPNAuthorizedRelease(
                ownerUserID: record.owner, release: previous)),
            candidate: VPNAuthorizedDeployment(VPNAuthorizedRelease(
                ownerUserID: record.owner, release: candidate)), transition: transition)
    }

    private func validPreparationCleanupRoots(_ roots: [VPNUpdateCleanupRootIdentity]) -> Bool {
        let names = roots.map(\.name)
        let allowed = Set(["current", "candidate", "pending-current", "pending-candidate"])
        return names == names.sorted() && Set(names).count == names.count
            && Set(names).isSubset(of: allowed) && roots.count <= 4
            && roots.allSatisfy { $0.device != 0 && $0.inode != 0 }
    }

    @discardableResult
    func advanceUpdateCleanupReceipt(transactionID: UUID,
                                     expectedPhase: VPNUpdateCleanupPhase,
                                     to phase: VPNUpdateCleanupPhase) throws
        -> VPNUpdateCleanupReceiptSnapshot {
        try withLock {
            guard var (receipt, snapshot) = try readCleanupReceipt() else {
                throw VPNReleaseStoreError.invalidCleanupReceipt
            }
            guard snapshot.transactionID == transactionID else {
                throw VPNReleaseStoreError.staleRevision
            }
            guard receipt.phase == expectedPhase else {
                throw VPNReleaseStoreError.invalidCleanupReceipt
            }
            let valid = (expectedPhase == .pending && phase == .applicationRetired)
                || (expectedPhase == .applicationRetired && phase == .updateRetired)
            guard valid else { throw VPNReleaseStoreError.invalidCleanupReceipt }
            receipt.phase = phase
            try replace(cleanupName, with: encodeCleanupReceipt(receipt))
            snapshot = try validateCleanupReceipt(receipt)
            return snapshot
        }
    }

    @discardableResult
    func authorizeUpdateCleanupGC(transactionID: UUID,
                                  roots: [VPNUpdateCleanupRootIdentity]) throws
        -> VPNUpdateCleanupReceiptSnapshot {
        try withLock {
            guard let loaded = try readCleanupReceipt() else {
                throw VPNReleaseStoreError.invalidCleanupReceipt
            }
            var receipt = loaded.0
            let snapshot = loaded.1
            guard snapshot.transactionID == transactionID else {
                throw VPNReleaseStoreError.invalidCleanupReceipt
            }
            if receipt.phase == .gcAuthorized {
                guard receipt.gcRoots == roots else { throw VPNReleaseStoreError.invalidCleanupReceipt }
                return snapshot
            }
            guard receipt.phase == .updateRetired, validCleanupRoots(roots) else {
                throw VPNReleaseStoreError.invalidCleanupReceipt
            }
            receipt.phase = .gcAuthorized
            receipt.gcRoots = roots
            try replace(cleanupName, with: encodeCleanupReceipt(receipt))
            return try validateCleanupReceipt(receipt)
        }
    }

    func retireUpdateCleanupReceipt(transactionID: UUID) throws {
        try withLock {
            guard let (receipt, snapshot) = try readCleanupReceipt(),
                  snapshot.transactionID == transactionID else {
                throw VPNReleaseStoreError.invalidCleanupReceipt
            }
            guard receipt.phase == .gcAuthorized else {
                throw VPNReleaseStoreError.invalidCleanupReceipt
            }
            guard unlinkat(directory, cleanupName, 0) == 0 else {
                throw VPNReleaseStoreError.writeFailed
            }
            guard fsync(directory) == 0 else { throw VPNReleaseStoreError.commitUncertain }
        }
    }

    private func requireJournal(_ transactionID: UUID, revision: UInt64) throws -> (UpdateJournal, VPNUpdateJournalSnapshot) {
        guard let (record, snapshot) = try readJournal() else { throw VPNReleaseStoreError.invalidUpdateJournal }
        guard record.transactionID == transactionID, record.revision == revision else {
            throw VPNReleaseStoreError.staleRevision
        }
        return (record, snapshot)
    }

    private func readJournal() throws -> (UpdateJournal, VPNUpdateJournalSnapshot)? {
        guard let data = try readFile(journalName, limit: Self.maximumJournalBytes) else { return nil }
        do {
            let record = try JSONDecoder().decode(UpdateJournal.self, from: data)
            guard try encodeJournal(record) == data else { throw VPNReleaseStoreError.invalidUpdateJournal }
            return (record, try validateJournal(record))
        } catch { throw VPNReleaseStoreError.invalidUpdateJournal }
    }

    private func readCleanupReceipt() throws -> (CleanupReceipt, VPNUpdateCleanupReceiptSnapshot)? {
        guard let data = try readFile(cleanupName, limit: Self.maximumCleanupBytes) else { return nil }
        do {
            let receipt = try JSONDecoder().decode(CleanupReceipt.self, from: data)
            guard try encodeCleanupReceipt(receipt) == data else {
                throw VPNReleaseStoreError.invalidCleanupReceipt
            }
            return (receipt, try validateCleanupReceipt(receipt))
        } catch {
            throw VPNReleaseStoreError.invalidCleanupReceipt
        }
    }

    private func validateCleanupReceipt(_ receipt: CleanupReceipt) throws -> VPNUpdateCleanupReceiptSnapshot {
        guard receipt.schema == 2, receipt.journal.phase == .completed,
              receipt.journal.revision == 3 else {
            throw VPNReleaseStoreError.invalidCleanupReceipt
        }
        guard (receipt.phase == .gcAuthorized) == (receipt.gcRoots != nil),
              receipt.gcRoots.map(validCleanupRoots) ?? true else {
            throw VPNReleaseStoreError.invalidCleanupReceipt
        }
        do { return VPNUpdateCleanupReceiptSnapshot(try validateJournal(receipt.journal),
            cleanupPhase: receipt.phase, gcRoots: receipt.gcRoots) }
        catch { throw VPNReleaseStoreError.invalidCleanupReceipt }
    }

    private func validCleanupRoots(_ roots: [VPNUpdateCleanupRootIdentity]) -> Bool {
        guard roots.map(\.name) == roots.map(\.name).sorted(),
              Set(roots.map(\.name)).count == 4,
              Set(roots.map(\.name)) == Set(["application", "current", "candidate", "executor"]) else {
            return false
        }
        return roots.allSatisfy { $0.device != 0 && $0.inode != 0 }
    }

    private func validateJournal(_ record: UpdateJournal) throws -> VPNUpdateJournalSnapshot {
        let expectedRevision: UInt64
        switch record.phase {
        case .prepared: expectedRevision = 0
        case .replacementPending, .cancelled: expectedRevision = 1
        case .selected: expectedRevision = 2
        case .completed: expectedRevision = 3
        case .cancellationApplicationRetired: expectedRevision = 2
        case .cancellationUpdateRetired: expectedRevision = 3
        case .cancellationGCAuthorized: expectedRevision = 4
        }
        guard record.schema == 1, record.revision == expectedRevision else {
            throw VPNReleaseStoreError.invalidUpdateJournal
        }
        guard (record.phase == .cancellationGCAuthorized) == (record.cleanupRoots != nil),
              record.cleanupRoots.map(validCancelledCleanupRoots) ?? true else {
            throw VPNReleaseStoreError.invalidUpdateJournal
        }
        let previous = try authority.verify(payload: record.previousPayload, signature: record.previousSignature, previous: nil)
        let transition = try authority.verifyUpdateTransition(payload: record.transitionPayload, signature: record.transitionSignature,
            previous: previous, candidatePayload: record.candidatePayload, candidateSignature: record.candidateSignature)
        let candidate = try authority.verify(payload: record.candidatePayload, signature: record.candidateSignature, previous: previous)
        try validateStoredArtifacts(previous)
        try validateStoredArtifacts(candidate)
        let (envelope, current) = try readCurrent()
        guard envelope.schema == 2, current.ownerUserID == record.owner else { throw VPNReleaseStoreError.invalidUpdateJournal }
        let sourceSelected = current.release.isSameRelease(as: previous)
        let destinationSelected = current.release.isSameRelease(as: candidate)
        let recovery: VPNUpdateRecovery
        switch record.phase {
        case .prepared where sourceSelected: recovery = .canCancelOrReplace
        case .replacementPending where sourceSelected: recovery = .inspectApplication
        case .replacementPending where destinationSelected: recovery = .recoverCandidate
        case .selected where destinationSelected: recovery = .recoverCandidate
        case .completed where destinationSelected: recovery = .completed
        case .cancelled where sourceSelected: recovery = .cancelled
        case .cancellationApplicationRetired where sourceSelected: recovery = .cancelled
        case .cancellationUpdateRetired where sourceSelected: recovery = .cancelled
        case .cancellationGCAuthorized where sourceSelected: recovery = .cancelled
        default: throw VPNReleaseStoreError.invalidUpdateJournal
        }
        return VPNUpdateJournalSnapshot(record,
            previous: VPNAuthorizedDeployment(VPNAuthorizedRelease(ownerUserID: record.owner, release: previous)),
            candidate: VPNAuthorizedDeployment(VPNAuthorizedRelease(ownerUserID: record.owner, release: candidate)),
            recovery: recovery, transition: transition)
    }

    private func validCancelledCleanupRoots(_ roots: [VPNUpdateCleanupRootIdentity]) -> Bool {
        let names = roots.map(\.name)
        let allowed = Set(["application", "current", "candidate", "executor",
                           "pending-executor"])
        guard names == names.sorted(), Set(names).count == names.count,
              Set(names).isSubset(of: allowed), Set(names).isSuperset(of: ["current", "candidate"]),
              !(Set(names).contains("executor") && Set(names).contains("pending-executor")),
              roots.count >= 2, roots.count <= 4 else { return false }
        return roots.allSatisfy { $0.device != 0 && $0.inode != 0 }
    }

    private func advanceJournal(_ record: inout UpdateJournal, to phase: VPNUpdateJournalPhase) throws {
        guard record.revision < UInt64.max else { throw VPNReleaseStoreError.invalidUpdateJournal }
        record.revision += 1; record.phase = phase
        _ = try validateJournal(record)
        try replace(journalName, with: encodeJournal(record))
    }

    private func encodeJournal(_ record: UpdateJournal) throws -> Data {
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
        let data = try encoder.encode(record)
        guard data.count <= Self.maximumJournalBytes else { throw VPNReleaseStoreError.invalidUpdateJournal }
        return data
    }

    private func encodePreparation(_ record: UpdatePreparation) throws -> Data {
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
        let data = try encoder.encode(record)
        guard data.count <= Self.maximumPreparationBytes else {
            throw VPNReleaseStoreError.invalidUpdatePreparation
        }
        return data
    }

    private func encodeCleanupReceipt(_ receipt: CleanupReceipt) throws -> Data {
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
        let data = try encoder.encode(receipt)
        guard data.count <= Self.maximumCleanupBytes else {
            throw VPNReleaseStoreError.invalidCleanupReceipt
        }
        return data
    }

    /// Validate and stage BEFORE interrupting the running version. This does
    /// not change the selected security floor or imply a successful update.
    func prepareDeployment(payload: Data, signature: Data, helper: Data, engine: Data? = nil,
                           expectedSequence: UInt64) throws -> VPNPreparedDeployment {
        try withLock {
            try requireNoCleanupReceipt()
            try requireNoPreparation()
            try requireNoJournal()
            let (envelope, state) = try readCurrent()
            guard envelope.schema == 2 else { throw VPNReleaseStoreError.deploymentRequired }
            guard state.release.sequence == expectedSequence else { throw VPNReleaseStoreError.staleRevision }
            let release = try authority.verify(payload: payload, signature: signature, previous: state.release)
            try stageArtifacts(helper: helper, engine: engine, release: release)
            return VPNPreparedDeployment(previous: VPNAuthorizedDeployment(state),
                candidate: VPNAuthorizedDeployment(VPNAuthorizedRelease(ownerUserID: state.ownerUserID, release: release)),
                payload: payload, signature: signature)
        }
    }

    @discardableResult
    func commitPreparedDeployment(_ prepared: VPNPreparedDeployment) throws -> VPNAuthorizedDeployment {
        try withLock {
            try requireNoCleanupReceipt()
            try requireNoPreparation()
            try requireNoJournal()
            let (envelope, current) = try readCurrent()
            guard envelope.schema == 2 else { throw VPNReleaseStoreError.deploymentRequired }
            guard current.ownerUserID == prepared.previous.ownerUserID,
                  current.release.isSameRelease(as: prepared.previous.release) else { throw VPNReleaseStoreError.staleRevision }
            let release = try authority.verify(payload: prepared.payload, signature: prepared.signature, previous: current.release)
            try validateStoredArtifacts(release)
            let next = Envelope(schema: 2, owner: current.ownerUserID, payload: prepared.payload, signature: prepared.signature)
            if envelope.payload != next.payload { try replace(recordName, with: encode(next)) }
            else if fsync(directory) != 0 { throw VPNReleaseStoreError.commitUncertain }
            return VPNAuthorizedDeployment(VPNAuthorizedRelease(ownerUserID: current.ownerUserID, release: release))
        }
    }

    /// First-install authorization and protected parent provisioning are external.
    /// Both signatures and both architecture pins are checked before publishing
    /// a single record selecting the policy AND all content-addressed binaries.
    @discardableResult
    func bootstrapDeployment(payload: Data, signature: Data, helper: Data, engine: Data? = nil,
                             trustedOwnerUserID: uid_t) throws -> VPNAuthorizedDeployment {
        try withLock {
            try requireNoCleanupReceipt()
            try requireNoPreparation()
            try requireNoJournal()
            guard try readFile(markerName) == nil, try readFile(recordName) == nil else {
                throw VPNReleaseStoreError.alreadyInitialized
            }
            let release = try authority.verify(payload: payload, signature: signature, previous: nil)
            _ = try release.clientPolicy(forTrustedUserID: trustedOwnerUserID)
            try stageArtifacts(helper: helper, engine: engine, release: release)
            let envelope = Envelope(schema: 2, owner: trustedOwnerUserID, payload: payload, signature: signature)
            try replace(markerName, with: Self.marker)
            try replace(recordName, with: encode(envelope))
            return VPNAuthorizedDeployment(VPNAuthorizedRelease(ownerUserID: envelope.owner, release: release))
        }
    }

    /// Disk commit only. A future lifecycle coordinator must stop/drain old
    /// operations, check the candidate's startup and handle service recovery.
    /// No daemon or installer may interpret this return as "VPN connected".
    @discardableResult
    func commitDeployment(payload: Data, signature: Data, helper: Data, engine: Data? = nil,
                          expectedSequence: UInt64) throws -> VPNAuthorizedDeployment {
        try withLock {
            try requireNoCleanupReceipt()
            try requireNoPreparation()
            try requireNoJournal()
            let (previous, current) = try readCurrent()
            guard previous.schema == 2 else { throw VPNReleaseStoreError.deploymentRequired }
            guard current.release.sequence == expectedSequence else { throw VPNReleaseStoreError.staleRevision }
            let release = try authority.verify(payload: payload, signature: signature, previous: current.release)
            try stageArtifacts(helper: helper, engine: engine, release: release)
            if previous.payload == payload {
                guard fsync(directory) == 0 else { throw VPNReleaseStoreError.commitUncertain }
                return VPNAuthorizedDeployment(current)
            }
            let next = Envelope(schema: 2, owner: previous.owner, payload: payload, signature: signature)
            try replace(recordName, with: encode(next))
            return VPNAuthorizedDeployment(VPNAuthorizedRelease(ownerUserID: next.owner, release: release))
        }
    }

    /// An installer may call this only after explicit first-install authority.
    /// A damaged/missing record never triggers this method automatically.
    @discardableResult
    func bootstrap(payload: Data, signature: Data, trustedOwnerUserID: uid_t) throws -> VPNAuthorizedRelease {
        try withLock {
            try requireNoCleanupReceipt()
            try requireNoPreparation()
            try requireNoJournal()
            guard try readFile(markerName) == nil, try readFile(recordName) == nil else {
                throw VPNReleaseStoreError.alreadyInitialized
            }
            let verified = try authority.verify(payload: payload, signature: signature, previous: nil)
            guard verified.engine == nil else { throw VPNReleaseStoreError.deploymentRequired }
            _ = try verified.clientPolicy(forTrustedUserID: trustedOwnerUserID)
            let envelope = Envelope(schema: 1, owner: trustedOwnerUserID, payload: payload, signature: signature)
            let data = try encode(envelope)
            // Persist the marker first: interruption cannot turn an incomplete
            // installation into an apparently pristine store eligible for reset.
            try replace(markerName, with: Self.marker)
            try replace(recordName, with: data)
            return VPNAuthorizedRelease(ownerUserID: envelope.owner, release: verified)
        }
    }

    /// Persists an authorized policy only. It does not install/activate a helper.
    /// A future installer must coordinate this with binary activation/recovery;
    /// do not advance the floor merely because an update was downloaded.
    @discardableResult
    func accept(payload: Data, signature: Data, expectedSequence: UInt64) throws -> VPNAuthorizedRelease {
        try withLock {
            try requireNoCleanupReceipt()
            try requireNoPreparation()
            try requireNoJournal()
            let (previous, current) = try readCurrent()
            guard previous.schema == 1 else { throw VPNReleaseStoreError.deploymentRequired }
            guard current.release.sequence == expectedSequence else { throw VPNReleaseStoreError.staleRevision }
            let verified = try authority.verify(payload: payload, signature: signature, previous: current.release)
            guard verified.engine == nil else { throw VPNReleaseStoreError.deploymentRequired }
            // Verification above authenticates the supplied signature. Release
            // identity is the payload, not signature bytes: a signer can produce
            // another valid signature for the same description.
            if previous.payload == payload {
                guard fsync(directory) == 0 else { throw VPNReleaseStoreError.commitUncertain }
                return current
            }
            // Ownership is retained from protected storage, never changed by an update.
            let next = Envelope(schema: 1, owner: previous.owner, payload: payload, signature: signature)
            try replace(recordName, with: encode(next))
            return VPNAuthorizedRelease(ownerUserID: next.owner, release: verified)
        }
    }

    private func readCurrent() throws -> (Envelope, VPNAuthorizedRelease) {
        guard try readFile(markerName) == Self.marker, let data = try readFile(recordName) else {
            throw VPNReleaseStoreError.invalidState
        }
        do {
            let envelope = try JSONDecoder().decode(Envelope.self, from: data)
            // Strict envelope too: reject unknown/duplicate fields and alternate
            // encodings rather than parsing ambiguous protected state.
            guard [1, 2].contains(envelope.schema), try encode(envelope) == data else { throw VPNReleaseStoreError.invalidState }
            let verified = try authority.verify(payload: envelope.payload, signature: envelope.signature, previous: nil)
            _ = try verified.clientPolicy(forTrustedUserID: envelope.owner)
            if envelope.schema == 2 { try validateStoredArtifacts(verified) }
            else if verified.engine != nil { throw VPNReleaseStoreError.deploymentRequired }
            return (envelope, VPNAuthorizedRelease(ownerUserID: envelope.owner, release: verified))
        } catch { throw VPNReleaseStoreError.invalidState }
    }

    private func stageArtifacts(helper: Data, engine: Data?, release: VerifiedVPNRelease) throws {
        // Check the complete set before creating even an unselected artifact.
        try release.validateArtifacts(helper: helper, engine: engine)
        try stageArtifact(helper, name: release.helperArtifactName, limit: VPNReleaseAuthority.maximumHelperBytes) {
            try VPNHelperArtifact.validate(protectedFile: $0, data: $1, release: release)
        }
        if let identity = release.engine, let engine = engine {
            try stageArtifact(engine, name: identity.artifactName, limit: VPNReleaseAuthority.maximumEngineBytes) {
                try VPNEngineArtifact.validate(protectedFile: $0, data: $1, release: release)
            }
        }
        try validateStoredArtifacts(release)
        guard fsync(directory) == 0 else { throw VPNReleaseStoreError.commitUncertain }
    }

    private func stageArtifact(_ data: Data, name: String, limit: Int,
                               validate: (Int32, Data) throws -> Void) throws {
        if try readFile(name, limit: limit, permissions: 0o700) == nil {
            try replace(name, with: data, permissions: 0o700) { file in
                try validate(file, data)
            }
        }
        // Also recheck an existing content-addressed file. Never silently repair
        // corrupted/symlinked state or trust a file merely because its name fits.
        try validateStoredArtifact(name: name, limit: limit, validate: validate)
    }

    private func validateStoredArtifacts(_ release: VerifiedVPNRelease) throws {
        try validateStoredArtifact(name: release.helperArtifactName, limit: VPNReleaseAuthority.maximumHelperBytes) {
            try VPNHelperArtifact.validate(protectedFile: $0, data: $1, release: release)
        }
        if let engine = release.engine {
            try validateStoredArtifact(name: engine.artifactName, limit: VPNReleaseAuthority.maximumEngineBytes) {
                try VPNEngineArtifact.validate(protectedFile: $0, data: $1, release: release)
            }
        }
    }

    private func validateStoredArtifact(name: String, limit: Int,
                                        validate: (Int32, Data) throws -> Void) throws {
        guard let data = try readFile(name, limit: limit, permissions: 0o700) else {
            throw VPNReleaseStoreError.invalidState
        }
        let file = openat(directory, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard file >= 0 else { throw VPNReleaseStoreError.unsafeStorage }
        defer { close(file) }
        try checkFile(file, permissions: 0o700)
        try validate(file, data)
    }

    private func encode(_ envelope: Envelope) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let data = try encoder.encode(envelope)
        guard data.count <= Self.maximumRecordBytes else { throw VPNReleaseStoreError.invalidState }
        return data
    }

    private func checkDirectory() throws {
        var attributes = stat()
        guard geteuid() == storageOwner, fstat(directory, &attributes) == 0,
              attributes.st_mode & S_IFMT == S_IFDIR, attributes.st_nlink > 0,
              attributes.st_uid == storageOwner, attributes.st_mode & 0o7777 == 0o700 else {
            throw VPNReleaseStoreError.unsafeStorage
        }
        try checkNoACL(directory)
    }

    private func checkNoACL(_ file: Int32) throws {
        // Query the descriptor successfully first, then distinguish an absent
        // ACL property from a filesystem error. acl_get_fd_np conflates them.
        guard let security = filesec_init() else { throw VPNReleaseStoreError.unsafeStorage }
        defer { filesec_free(security) }
        var attributes = stat()
        guard fstatx_np(file, &attributes, security) == 0 else { throw VPNReleaseStoreError.unsafeStorage }
        var retrieved: acl_t?
        errno = 0
        let result = filesec_get_property(security, FILESEC_ACL, &retrieved)
        if result == -1, errno == ENOENT { return }
        guard result == 0, let acl = retrieved else { throw VPNReleaseStoreError.unsafeStorage }
        defer { acl_free(UnsafeMutableRawPointer(acl)) }
        var entry: acl_entry_t?
        errno = 0
        // Darwin returns -1/EINVAL when an otherwise valid ACL has no entries.
        guard acl_get_entry(acl, Int32(ACL_FIRST_ENTRY.rawValue), &entry) == -1, errno == EINVAL else {
            throw VPNReleaseStoreError.unsafeStorage
        }
    }

    private func checkFile(_ file: Int32, permissions: mode_t = 0o600) throws {
        var attributes = stat()
        guard fstat(file, &attributes) == 0, attributes.st_mode & S_IFMT == S_IFREG,
              attributes.st_nlink == 1, attributes.st_uid == storageOwner,
              attributes.st_mode & 0o7777 == permissions else { throw VPNReleaseStoreError.unsafeStorage }
        try checkNoACL(file)
    }

    private func withLock<T>(_ operation: () throws -> T) throws -> T {
        try checkDirectory()
        let lock = openat(directory, "release.lock", O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK, 0o600)
        guard lock >= 0 else { throw VPNReleaseStoreError.unsafeStorage }
        defer { close(lock) }
        try checkFile(lock)
        guard flock(lock, LOCK_EX | LOCK_NB) == 0 else { throw VPNReleaseStoreError.busy }
        defer { flock(lock, LOCK_UN) }
        return try operation()
    }

    private func readFile(_ name: String, limit: Int = VPNReleaseStore.maximumRecordBytes,
                          permissions: mode_t = 0o600) throws -> Data? {
        let file = openat(directory, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard file >= 0 else {
            if errno == ENOENT { return nil }
            throw VPNReleaseStoreError.unsafeStorage
        }
        defer { close(file) }
        try checkFile(file, permissions: permissions)
        var data = Data(), bytes = [UInt8](repeating: 0, count: 1024)
        while true {
            let count = read(file, &bytes, bytes.count)
            if count < 0, errno == EINTR { continue }
            guard count >= 0 else { throw VPNReleaseStoreError.invalidState }
            if count == 0 { return data }
            guard data.count + count <= limit else { throw VPNReleaseStoreError.invalidState }
            data.append(contentsOf: bytes.prefix(count))
        }
    }

    private func replace(_ name: String, with data: Data, permissions: mode_t = 0o600,
                         validating: (Int32) throws -> Void = { _ in }) throws {
        let temporary = ".release-\(UUID().uuidString).tmp"
        let file = openat(directory, temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, permissions)
        guard file >= 0 else { throw VPNReleaseStoreError.writeFailed }
        defer { close(file); unlinkat(directory, temporary, 0) }
        try checkFile(file, permissions: permissions)
        try data.withUnsafeBytes { bytes in
            var offset = 0
            while offset < bytes.count {
                let count = write(file, bytes.baseAddress!.advanced(by: offset), bytes.count - offset)
                if count < 0, errno == EINTR { continue }
                guard count > 0 else { throw VPNReleaseStoreError.writeFailed }
                offset += count
            }
        }
        try validating(file)
        guard fsync(file) == 0 else { throw VPNReleaseStoreError.writeFailed }
        #if VPN_RELEASE_STORE_TESTING
        Self.checkpoint?(name + ":before-rename")
        #endif
        guard renameat(directory, temporary, directory, name) == 0 else { throw VPNReleaseStoreError.writeFailed }
        #if VPN_RELEASE_STORE_TESTING
        Self.checkpoint?(name + ":after-rename")
        #endif
        // Rename committed. Report an uncertain commit, NOT "previous state
        // unchanged", if metadata sync fails; caller must reload/reconcile.
        guard fsync(directory) == 0 else { throw VPNReleaseStoreError.commitUncertain }
    }
}
