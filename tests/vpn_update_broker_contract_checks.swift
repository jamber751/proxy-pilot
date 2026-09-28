import Darwin
import Foundation

/// The complete submit authority crossing IPC. There is intentionally no path,
/// URL, argv, shell command, owner UID, updater token or opaque byte payload.
struct SubmitRequest {
    let expectedFromSequence: UInt64
    let candidateDirectory: Int32
}

enum ContractPhase: UInt8 {
    case idle, accepted, preparing, replacing, recovering, completed
}

/// The only status fields exposed to the ordinary app. Diagnostics remain an
/// allowlisted local enum in the broker and never return filesystem or secrets.
struct PublicStatus: Equatable {
    let phase: ContractPhase
    let fromSequence: UInt64?
    let toSequence: UInt64?
    let revision: UInt64

    init(phase: ContractPhase, fromSequence: UInt64?, toSequence: UInt64?,
         revision: UInt64 = 0) {
        self.phase = phase
        self.fromSequence = fromSequence
        self.toSequence = toSequence
        self.revision = revision
    }
}

enum Rejection: Equatable {
    case malformedRequest
    case missingDirectoryDescriptor
    case extraDirectoryDescriptor
    case unexpectedSibling
    case invalidLayout
    case wrongTransitionSignature
    case wrongTransitionSource
    case wrongTransitionDestination
    case tamperedApplication
    case tamperedHelper
    case tamperedEngine
    case staleExpectedSequence
}

enum SubmitResult: Equatable {
    case accepted(transaction: UInt64)
    case alreadyAccepted(transaction: UInt64)
    case rejected(Rejection)
}

enum CandidateMutation: CaseIterable {
    case none
    case unexpectedSibling
    case wrongTransitionSignature
    case wrongTransitionSource
    case wrongTransitionDestination
    case tamperedApplication
    case tamperedHelper
    case tamperedEngine
}

/// Implemented by a test-only adapter in the production broker. Fixtures
/// are created with ephemeral signing keys and inert artifacts. No root, system
/// service, installed app, network or release key is used by this executable.
protocol VPNUpdateBrokerContractDriving {
    static var fixedLayout: Set<String> { get }
    init() throws
    func submit(_ request: SubmitRequest, mutation: CandidateMutation) throws -> SubmitResult
    func malformedField(name: String, value: String) throws -> SubmitResult
    func submitWithoutDescriptor(expectedFromSequence: UInt64) throws -> SubmitResult
    func submitWithExtraDescriptor(expectedFromSequence: UInt64) throws -> SubmitResult
    func status() throws -> PublicStatus
    func encodedStatus() throws -> Data
}

/// This name resolves only in the narrow contract-test build.
typealias BrokerDriver = VPNUpdateBrokerContractHarness

@main enum VPNUpdateBrokerContractChecks {
    static let exactLayout: Set<String> = [
        "ProxyPilot.app",
        "vpn-helper",
        "vpn-engine",
        "vpn-release.manifest",
        "vpn-release.sig",
        "vpn-previous-release.manifest",
        "vpn-previous-release.sig",
        "vpn-update-transition",
        "vpn-update-transition.sig",
    ]

    static func require(_ value: @autoclosure () -> Bool) throws {
        guard value() else { throw NSError(domain: "broker-contract", code: 1) }
    }

    static func ipc(_ broker: BrokerDriver) throws {
        try require(BrokerDriver.fixedLayout == exactLayout)
        let missing = try broker.submitWithoutDescriptor(expectedFromSequence: 41)
        try require(missing == .rejected(.missingDirectoryDescriptor))
        let extra = try broker.submitWithExtraDescriptor(expectedFromSequence: 41)
        try require(extra == .rejected(.extraDirectoryDescriptor))
        for field in ["path", "url", "argv", "shell", "ownerUID", "token"] {
            let result = try broker.malformedField(
                name: field, value: "attacker-controlled")
            try require(result == .rejected(.malformedRequest))
        }
    }

    static func layout(_ broker: BrokerDriver) throws {
        let result = try broker.submit(
            SubmitRequest(expectedFromSequence: 41, candidateDirectory: 100),
            mutation: .unexpectedSibling)
        try require(result == .rejected(.unexpectedSibling))
    }

    static func authorization(_ broker: BrokerDriver) throws {
        let expected: [(CandidateMutation, Rejection)] = [
            (.wrongTransitionSignature, .wrongTransitionSignature),
            (.wrongTransitionSource, .wrongTransitionSource),
            (.wrongTransitionDestination, .wrongTransitionDestination),
            (.tamperedApplication, .tamperedApplication),
            (.tamperedHelper, .tamperedHelper),
            (.tamperedEngine, .tamperedEngine),
        ]
        for (mutation, rejection) in expected {
            let result = try broker.submit(
                SubmitRequest(expectedFromSequence: 41, candidateDirectory: 100),
                mutation: mutation)
            try require(result == .rejected(rejection))
        }
    }

    static func retry(_ broker: BrokerDriver) throws {
        let stale = try broker.submit(
            SubmitRequest(expectedFromSequence: 40, candidateDirectory: 100),
            mutation: .none)
        try require(stale == .rejected(.staleExpectedSequence))
        let first = try broker.submit(
            SubmitRequest(expectedFromSequence: 41, candidateDirectory: 100),
            mutation: .none)
        let second = try broker.submit(
            SubmitRequest(expectedFromSequence: 41, candidateDirectory: 100),
            mutation: .none)
        guard case .accepted(let original) = first,
              case .alreadyAccepted(let repeated) = second else {
            throw NSError(domain: "broker-contract", code: 2)
        }
        // An identical retry names the same transaction; it never starts a
        // second replacement or consumes a caller-provided transaction token.
        try require(original == repeated) // same transaction
    }

    static func status(_ broker: BrokerDriver) throws {
        let value = try broker.status()
        try require(value == PublicStatus(phase: .idle,
                                          fromSequence: 41,
                                          toSequence: nil))
        let text = String(data: try broker.encodedStatus(), encoding: .utf8) ?? ""
        for forbidden in ["/", "file:", "private", "profile", "key", "secret",
                          "token", "transaction", "error"] {
            try require(!text.lowercased().contains(forbidden))
        }
    }

    static func main() throws {
        guard CommandLine.arguments.count == 2 else { exit(64) }
        let group = CommandLine.arguments[1]
        let broker = try BrokerDriver()
        switch group {
        case "ipc": try ipc(broker)
        case "layout": try layout(broker)
        case "authorization": try authorization(broker)
        case "retry": try retry(broker)
        case "status": try status(broker)
        default: exit(64)
        }
        print("\(group) checks passed")
    }
}
