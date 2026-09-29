import Foundation

// Executable contract for VPNUpdateBrokerHandler.  The real handler has the
// same authority shape: the fixed request contains a sequence, while the
// candidate arrives only as an out-of-band directory descriptor.  Paths,
// caller transaction IDs and caller-selected UUIDs do not exist on this seam.
struct HandlerRequest: Equatable {
    let expectedFromSequence: UInt64
}

enum HandlerState: UInt16, Equatable {
    case accepted, checking, ready, installing, complete, failed, busy, stale
}

struct HandlerResponse: Equatable {
    let state: HandlerState
    let fromSequence: UInt64
    let toSequence: UInt64
    let revision: UInt64
}

enum HandlerCandidateKind {
    case signedAtoB, differentSigned, invalidSignature
}

enum HandlerFixtureError: Error, Equatable {
    case invalidDescriptor, invalidAuthorization, injectedCrash
    case recoveryNotArmed, brokerRotationNotReady
}

struct HandlerTransaction {
    let identity: UInt64
    let fromSequence: UInt64
    let toSequence: UInt64
    var response: HandlerResponse?
    var prepared = false
    var recoveryArmed = false
    var brokerRotationReady = false
    var handoffComplete = false
}

/// Disk state shared by newly-created model instances.  This deliberately
/// mirrors only durable facts; held locks and caller connection state are not
/// persisted across a simulated process crash.
final class HandlerDurableFixture {
    var inboxIdentity: UInt64?
    var transaction: HandlerTransaction?
    var revision: UInt64 = 0
    var events: [String] = []
    var protectedMutationCount = 0
    var drainCount = 0
    var handoffCount = 0
    var transactionHeld = false
}

final class HandlerSequencingModel {
    static let checkpoints = [
        "afterInbox", "afterAccepted", "afterChecking",
        "afterAuthorization", "afterPreparation", "afterRecoveryArm",
        "afterBrokerRotationReady", "afterReady", "beforeHandoff",
        "afterInstalling", "afterHandoff", "afterComplete",
    ]

    private let durable: HandlerDurableFixture
    private let crashAt: String?
    private var didCrash = false

    init(durable: HandlerDurableFixture, crashAt: String? = nil) {
        self.durable = durable
        self.crashAt = crashAt
    }

    func submit(_ request: HandlerRequest,
                candidateDirectory: Int32,
                candidate: HandlerCandidateKind) throws -> HandlerResponse {
        guard candidateDirectory >= 0 else { throw HandlerFixtureError.invalidDescriptor }
        let identity: UInt64
        let toSequence: UInt64
        switch candidate {
        case .signedAtoB, .invalidSignature:
            identity = 0xaabbccdd; toSequence = 42
        case .differentSigned:
            identity = 0x11223344; toSequence = 43
        }

        durable.events.append("receive.descriptor")
        durable.events.append("broker.owns.descriptor")

        if durable.transactionHeld {
            if let current = durable.transaction, current.identity == identity {
                return current.response ?? HandlerResponse(
                    state: .accepted, fromSequence: current.fromSequence,
                    toSequence: current.toSequence, revision: 0)
            }
            return transient(.busy, from: request.expectedFromSequence)
        }

        durable.transactionHeld = true
        defer { durable.transactionHeld = false }

        if let inbox = durable.inboxIdentity, inbox != identity {
            return transient(.busy, from: request.expectedFromSequence)
        }
        if durable.inboxIdentity == nil {
            durable.inboxIdentity = identity
            durable.events.append("inbox.publish")
        } else {
            durable.events.append("inbox.alreadyPublished")
        }

        if durable.transaction == nil {
            durable.transaction = HandlerTransaction(
                identity: identity, fromSequence: request.expectedFromSequence,
                toSequence: toSequence)
        }
        guard var transaction = durable.transaction else { fatalError() }
        guard transaction.identity == identity else {
            return transient(.busy, from: request.expectedFromSequence)
        }
        guard transaction.fromSequence == request.expectedFromSequence else {
            return transient(.stale, from: request.expectedFromSequence)
        }
        if let response = transaction.response, response.state == .complete {
            return response
        }

        try checkpoint("afterInbox")
        publish(.accepted)
        try checkpoint("afterAccepted")
        publish(.checking)
        try checkpoint("afterChecking")

        durable.events.append("authorize.signed.privateInbox")
        guard candidate != .invalidSignature else {
            publish(.failed)
            throw HandlerFixtureError.invalidAuthorization
        }
        try checkpoint("afterAuthorization")

        transaction = durable.transaction!
        if !transaction.prepared {
            transaction.prepared = true
            durable.transaction = transaction
            durable.events.append("prepare.joint")
        } else {
            durable.events.append("prepare.resume")
        }
        try checkpoint("afterPreparation")

        transaction = durable.transaction!
        if !transaction.recoveryArmed {
            transaction.recoveryArmed = true
            durable.transaction = transaction
            durable.events.append("recovery.arm")
        }
        try checkpoint("afterRecoveryArm")

        transaction = durable.transaction!
        if !transaction.brokerRotationReady {
            transaction.brokerRotationReady = true
            durable.transaction = transaction
            durable.events.append("broker.rotation.ready")
        }
        try checkpoint("afterBrokerRotationReady")
        publish(.ready)
        try checkpoint("afterReady")
        try checkpoint("beforeHandoff")

        transaction = durable.transaction!
        guard transaction.recoveryArmed else {
            throw HandlerFixtureError.recoveryNotArmed
        }
        guard transaction.brokerRotationReady else {
            throw HandlerFixtureError.brokerRotationNotReady
        }
        publish(.installing)
        try checkpoint("afterInstalling")

        transaction = durable.transaction!
        if !transaction.handoffComplete {
            // Protected application/service mutation starts only inside the
            // executor handoff, after both durable prerequisites above.
            durable.events.append("handoff.executor")
            durable.events.append("service.drain")
            durable.protectedMutationCount += 1
            durable.drainCount += 1
            durable.handoffCount += 1
            transaction.handoffComplete = true
            durable.transaction = transaction
        }
        try checkpoint("afterHandoff")
        publish(.complete)
        try checkpoint("afterComplete")
        return durable.transaction!.response!
    }

    /// Test-only seam for proving the handler cannot call the executor when
    /// either prerequisite has not durably completed.
    func attemptHandoffForGateTest() throws {
        guard let transaction = durable.transaction else {
            throw HandlerFixtureError.recoveryNotArmed
        }
        guard transaction.recoveryArmed else {
            throw HandlerFixtureError.recoveryNotArmed
        }
        guard transaction.brokerRotationReady else {
            throw HandlerFixtureError.brokerRotationNotReady
        }
        durable.events.append("handoff.executor")
    }

    private func publish(_ state: HandlerState) {
        guard var transaction = durable.transaction else { fatalError() }
        // Recovery may restart the pipeline from its first safe operation, but
        // the durable public receipt must never move backwards or mint another
        // revision for an already-published phase.
        if let current = transaction.response,
           current.state.rawValue >= state.rawValue { return }
        durable.revision += 1
        transaction.response = HandlerResponse(
            state: state, fromSequence: transaction.fromSequence,
            toSequence: transaction.toSequence, revision: durable.revision)
        durable.transaction = transaction
        durable.events.append("status.\(state)")
    }

    private func transient(_ state: HandlerState, from: UInt64) -> HandlerResponse {
        HandlerResponse(state: state, fromSequence: from,
            toSequence: durable.transaction?.toSequence ?? 0,
            revision: durable.transaction?.response?.revision ?? 0)
    }

    private func checkpoint(_ name: String) throws {
        durable.events.append("checkpoint.\(name)")
        if crashAt == name && !didCrash {
            didCrash = true
            throw HandlerFixtureError.injectedCrash
        }
    }
}

@main enum VPNUpdateBrokerHandlerChecks {
    static let request = HandlerRequest(expectedFromSequence: 41)

    static func require(_ value: @autoclosure () -> Bool) throws {
        guard value() else { throw NSError(domain: "broker-handler-contract", code: 1) }
    }

    static func pipeline() throws {
        let durable = HandlerDurableFixture()
        let response = try HandlerSequencingModel(durable: durable).submit(
            request, candidateDirectory: 19, candidate: .signedAtoB)
        try require(response.state == .complete)
        let ordered = ["receive.descriptor", "inbox.publish",
            "authorize.signed.privateInbox", "prepare.joint", "recovery.arm",
            "broker.rotation.ready", "handoff.executor"]
        var last = -1
        for event in ordered {
            guard let index = durable.events.firstIndex(of: event) else {
                throw NSError(domain: "broker-handler-contract", code: 2)
            }
            try require(index > last); last = index
        }
    }

    static func retryAndBusy() throws {
        let durable = HandlerDurableFixture()
        durable.transactionHeld = true
        durable.transaction = HandlerTransaction(
            identity: 0xaabbccdd, fromSequence: 41, toSequence: 42,
            response: HandlerResponse(state: .checking, fromSequence: 41,
                                      toSequence: 42, revision: 2))
        let model = HandlerSequencingModel(durable: durable)
        let same = try model.submit(request, candidateDirectory: 20,
                                    candidate: .signedAtoB)
        let other = try model.submit(request, candidateDirectory: 21,
                                     candidate: .differentSigned)
        try require(same.state == .checking)
        try require(other.state == .busy)
        durable.transactionHeld = false
        let completed = try model.submit(request, candidateDirectory: 22,
                                         candidate: .signedAtoB)
        let repeated = try HandlerSequencingModel(durable: durable).submit(
            request, candidateDirectory: 23, candidate: .signedAtoB)
        try require(completed == repeated)
        try require(durable.drainCount == 1 && durable.handoffCount == 1)
    }

    static func invalidSignedInput() throws {
        let durable = HandlerDurableFixture()
        do {
            _ = try HandlerSequencingModel(durable: durable).submit(
                request, candidateDirectory: 24, candidate: .invalidSignature)
            throw NSError(domain: "broker-handler-contract", code: 3)
        } catch HandlerFixtureError.invalidAuthorization { }
        try require(durable.drainCount == 0)
        try require(durable.handoffCount == 0)
        try require(durable.protectedMutationCount == 0)
        try require(!durable.events.contains("prepare.joint"))
        try require(!durable.events.contains("recovery.arm"))
        try require(!durable.events.contains("broker.rotation.ready"))
    }

    static func crashes() throws {
        for point in HandlerSequencingModel.checkpoints {
            let durable = HandlerDurableFixture()
            do {
                _ = try HandlerSequencingModel(durable: durable, crashAt: point)
                    .submit(request, candidateDirectory: 25, candidate: .signedAtoB)
                throw NSError(domain: "broker-handler-contract", code: 4)
            } catch HandlerFixtureError.injectedCrash { }
            let recovered = try HandlerSequencingModel(durable: durable).submit(
                request, candidateDirectory: 26, candidate: .signedAtoB)
            try require(recovered.state == .complete)
            try require(durable.drainCount == 1)
            try require(durable.handoffCount == 1)
        }
    }

    static func handoffGates() throws {
        let durable = HandlerDurableFixture()
        durable.transaction = HandlerTransaction(
            identity: 0xaabbccdd, fromSequence: 41, toSequence: 42,
            prepared: true)
        let model = HandlerSequencingModel(durable: durable)
        do { try model.attemptHandoffForGateTest(); throw NSError(domain: "gate", code: 1) }
        catch HandlerFixtureError.recoveryNotArmed { }
        durable.transaction!.recoveryArmed = true
        do { try model.attemptHandoffForGateTest(); throw NSError(domain: "gate", code: 2) }
        catch HandlerFixtureError.brokerRotationNotReady { }
        try require(!durable.events.contains("handoff.executor"))
        durable.transaction!.brokerRotationReady = true
        try model.attemptHandoffForGateTest()
        try require(durable.events.last == "handoff.executor")
    }

    static func main() throws {
        guard CommandLine.arguments.count == 2 else { exit(64) }
        let group = CommandLine.arguments[1]
        switch group {
        case "pipeline": try pipeline()
        case "retry-busy": try retryAndBusy()
        case "invalid-signed": try invalidSignedInput()
        case "crashes": try crashes()
        case "handoff-gates": try handoffGates()
        default: exit(64)
        }
        print("\(group) checks passed")
    }
}
