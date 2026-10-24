import Foundation

/// Opaque, process-local capabilities, NOT persisted kernel receipts. Only an
/// explicit authority owns an issuer. Minting is not evidence of an OS barrier:
/// a future adapter must establish/verify its durable exact resource fence and
/// route custody before minting. There is deliberately no production adapter.
final class VPNDNSAnswerPermitIssuer {
    fileprivate let identity = UUID()
    func barrier(for answer: VPNDNSValidatedAnswer) -> VPNDNSBarrierPermit {
        VPNDNSBarrierPermit(issuer: identity, answer: answer)
    }
    func routes(for answer: VPNDNSValidatedAnswer) -> VPNDNSAnswerRoutePermit {
        VPNDNSAnswerRoutePermit(issuer: identity, answer: answer)
    }
}

struct VPNDNSBarrierPermit {
    fileprivate let issuer: UUID
    fileprivate let answer: VPNDNSValidatedAnswer
}
struct VPNDNSAnswerRoutePermit {
    fileprivate let issuer: UUID
    fileprivate let answer: VPNDNSValidatedAnswer
}

enum VPNDNSAnswerCheckpoint: String {
    case received, denyEstablished, routesEstablished, verified, outputIssued, released
}

/// Implementations must durably checkpoint before returning, preserving unknown
/// mutations on error. This model provides ordering, not storage/crash recovery.
protocol VPNDNSAnswerCheckpointSink {
    func record(_ stage: VPNDNSAnswerCheckpoint, answer: VPNDNSValidatedAnswer) throws
}

protocol VPNDNSAnswerReleaseAuthority: AnyObject {
    var permitIssuer: VPNDNSAnswerPermitIssuer { get }
    /// Check exact active resource (including UUID), generation/revision,
    /// cancellation, current tunnel and caller's original absolute deadline.
    func checkCurrent(_ answer: VPNDNSValidatedAnswer) throws
    /// Must cover ALL answer addresses, both families over successive queries;
    /// retain preexisting live/cached IP obligations across TTL/revoke/crashes.
    /// Negative/error answers have no NEW addresses but MUST NOT clear, shorten,
    /// or bypass existing IP fences. They still require every permit/current
    /// check and the exact original-query lease; empty addresses are no approval.
    func establishDeny(_ answer: VPNDNSValidatedAnswer) throws -> VPNDNSBarrierPermit
    func establishRoutes(_ answer: VPNDNSValidatedAnswer,
                         barrier: VPNDNSBarrierPermit) throws -> VPNDNSAnswerRoutePermit
    /// Mandatory live full-proof verification and an authority/update lease held
    /// THROUGH the synchronous one-shot output callback. No upstream wait belongs
    /// in this lease. Releasing it before body returns violates this contract.
    /// A future lifecycle adapter must also cancel in-flight upstream work.
    func withVerifiedLease(answer: VPNDNSValidatedAnswer, barrier: VPNDNSBarrierPermit,
                           routes: VPNDNSAnswerRoutePermit, body: () throws -> Void) throws
}

/// Inert answer interposition transaction. Positive/negative/error bytes cannot escape by
/// return value: output is synchronous/non-escaping and protected by authority.
/// The future output adapter must itself use bounded nonblocking I/O and the
/// original deadline; this pure model does not implement a client socket.
/// A thrown output is indeterminate, NEVER retried by this transaction. Recovery
/// of a durable outputIssued/unknown checkpoint needs a future custody adapter;
/// constructing a fresh transaction is not permission to replay the old answer.
final class VPNDNSAnswerRelease {
    private let answer: VPNDNSValidatedAnswer
    private let authority: VPNDNSAnswerReleaseAuthority
    private let sink: VPNDNSAnswerCheckpointSink
    private let now: () throws -> VPNDNSContinuousInstant
    private let stateLock = NSLock()
    private var attempted = false
    private var lastClock: VPNDNSContinuousInstant?
    private var storedStage: VPNDNSAnswerCheckpoint?
    var stage: VPNDNSAnswerCheckpoint? {
        stateLock.lock(); defer { stateLock.unlock() }; return storedStage
    }

    init(answer: VPNDNSValidatedAnswer, authority: VPNDNSAnswerReleaseAuthority,
         sink: VPNDNSAnswerCheckpointSink, now: @escaping () throws -> VPNDNSContinuousInstant) {
        self.answer = answer; self.authority = authority; self.sink = sink; self.now = now
    }

    private func currentTime() throws -> VPNDNSContinuousInstant {
        let value = try now()
        stateLock.lock(); defer { stateLock.unlock() }
        if let previous = lastClock, value < previous { throw VPNDNSContinuousClockError.backwards }
        lastClock = value; return value
    }
    private func current() throws {
        try answer.checkTime(currentTime()); try authority.checkCurrent(answer)
        // A checker may consume the remaining budget; never reset it.
        try answer.checkTime(currentTime())
    }
    private func checkpoint(_ value: VPNDNSAnswerCheckpoint) throws {
        try sink.record(value, answer: answer)
        stateLock.lock(); storedStage = value; stateLock.unlock()
    }

    func release(output: (Data) throws -> Void) throws {
        stateLock.lock()
        guard !attempted else { stateLock.unlock(); throw VPNDNSAnswerError.outputAlreadyIssued }
        attempted = true; stateLock.unlock()
        try current(); try checkpoint(.received)
        try current()
        let issuer = authority.permitIssuer.identity
        let barrier = try authority.establishDeny(answer)
        guard barrier.issuer == issuer, barrier.answer == answer else { throw VPNDNSAnswerError.permit }
        try current(); try checkpoint(.denyEstablished)
        try current()
        let routes = try authority.establishRoutes(answer, barrier: barrier)
        guard routes.issuer == issuer, routes.answer == answer,
              authority.permitIssuer.identity == issuer else { throw VPNDNSAnswerError.permit }
        try current(); try checkpoint(.routesEstablished)
        let callbackLock = NSLock()
        var invoked = false, completed = false
        var callbackError: Error?
        try authority.withVerifiedLease(answer: answer, barrier: barrier, routes: routes) {
            callbackLock.lock()
            guard !invoked else {
                callbackError = callbackError ?? VPNDNSAnswerError.outputAlreadyIssued
                callbackLock.unlock(); throw VPNDNSAnswerError.outputAlreadyIssued
            }
            invoked = true; callbackLock.unlock()
            // Do not hold callbackLock through authority/output: reentrant or
            // concurrent provider callbacks must fail, never deadlock or output.
            do {
                guard authority.permitIssuer.identity == issuer else { throw VPNDNSAnswerError.permit }
                try current(); try checkpoint(.verified)
                try current(); try checkpoint(.outputIssued)
                // Recheck AFTER potentially slow durable write, under the same
                // required lease that protects the actual output.
                try current()
                let bytes = try answer.encoded(at: currentTime())
                try current()
                try output(bytes)
                try checkpoint(.released)
                callbackLock.lock(); completed = true; callbackLock.unlock()
            } catch {
                callbackLock.lock(); callbackError = callbackError ?? error; callbackLock.unlock()
                throw error
            }
        }
        callbackLock.lock()
        let didInvoke = invoked, didComplete = completed, failure = callbackError
        callbackLock.unlock()
        if let failure = failure { throw failure }
        guard didInvoke, didComplete, stage == .released else { throw VPNDNSAnswerError.checkpoint }
    }
}
