import Foundation

enum VPNScopedDNSAdapterError: Error, Equatable {
    case invalidPlan
    case invalidScope
    case invalidRecord
    case occupiedByForeignState
}

/// Canonical DNS entity intended for a future per-session SCDynamicStore
/// backend. This file is deliberately inert: it does not import or call
/// SystemConfiguration and cannot change the host resolver configuration.
struct VPNScopedDNSRecord: Codable, Equatable {
    static let schema = 1
    let schemaVersion: Int
    let dynamicStoreKey: String
    let serverAddresses: [String]
    let supplementalMatchDomains: [String]
    let supplementalMatchOrders: [Int]
    let interfaceName: String

    func validate(scope: VPNDNSResolverScope, generation: UInt64,
                  revision: UInt64, index: Int) throws {
        try scope.validate()
        guard schemaVersion == Self.schema,
              self == (try VPNScopedDNSCodec.record(scope: scope,
                                                    generation: generation,
                                                    revision: revision,
                                                    index: index)) else {
            throw VPNScopedDNSAdapterError.invalidRecord
        }
    }
}

enum VPNScopedDNSCodec {
    static let servicePrefix = "kz.documentolog.proxypilot.vpn"
    static let firstSupplementalOrder = 120_000

    static func record(scope: VPNDNSResolverScope, generation: UInt64,
                       revision: UInt64, index: Int) throws -> VPNScopedDNSRecord {
        do { try scope.validate() }
        catch { throw VPNScopedDNSAdapterError.invalidScope }
        guard generation > 0, revision > 0, (0..<1000).contains(index),
              firstSupplementalOrder <= Int.max - index else {
            throw VPNScopedDNSAdapterError.invalidRecord
        }
        let serviceID = "\(servicePrefix).\(generation).\(revision).\(index)"
        return VPNScopedDNSRecord(
            schemaVersion: VPNScopedDNSRecord.schema,
            dynamicStoreKey: "State:/Network/Service/\(serviceID)/DNS",
            serverAddresses: scope.servers.map(\.canonical),
            supplementalMatchDomains: [scope.domain],
            supplementalMatchOrders: [firstSupplementalOrder + index],
            interfaceName: scope.tunnelInterface.interfaceName)
    }

    static func records(plan: VPNDNSPlan) throws -> [VPNScopedDNSRecord] {
        do { try plan.validate() }
        catch { throw VPNScopedDNSAdapterError.invalidPlan }
        return try plan.scopes.enumerated().map {
            try record(scope: $0.element, generation: plan.generation,
                       revision: plan.revision, index: $0.offset)
        }
    }
}

/// A production backend should keep one SCDynamicStore session for the VPN
/// lifetime with kSCDynamicStoreUseSessionKeys enabled. `ownedByThisSession`
/// must only become true after that same session successfully added the key;
/// an equal value created by another session is never adopted.
struct VPNScopedDNSObservation: Equatable {
    let record: VPNScopedDNSRecord?
    let ownedByThisSession: Bool

    static let absent = VPNScopedDNSObservation(record: nil, ownedByThisSession: false)
}

enum VPNScopedDNSInstallDecision: Equatable {
    case addExpected
    case alreadyInstalledByThisSession
}

enum VPNScopedDNSRemoveDecision: Equatable {
    case alreadyAbsent
    case removeExact
}

/// Pure compare/ownership policy used between VPNDNSJournal checkpoints and a
/// future SystemConfiguration backend. It prevents adoption or deletion of an
/// equal-looking resolver record not created by the current store session.
enum VPNScopedDNSControllerSeam {
    static func installDecision(expected: VPNScopedDNSRecord,
                                observed: VPNScopedDNSObservation)
        throws -> VPNScopedDNSInstallDecision {
        if observed.record == nil {
            guard !observed.ownedByThisSession else {
                throw VPNScopedDNSAdapterError.invalidRecord
            }
            return .addExpected
        }
        guard observed.record == expected, observed.ownedByThisSession else {
            throw VPNScopedDNSAdapterError.occupiedByForeignState
        }
        return .alreadyInstalledByThisSession
    }

    static func removeDecision(expected: VPNScopedDNSRecord,
                               observed: VPNScopedDNSObservation)
        throws -> VPNScopedDNSRemoveDecision {
        guard let current = observed.record else {
            guard !observed.ownedByThisSession else {
                throw VPNScopedDNSAdapterError.invalidRecord
            }
            return .alreadyAbsent
        }
        guard current == expected, observed.ownedByThisSession else {
            throw VPNScopedDNSAdapterError.occupiedByForeignState
        }
        return .removeExact
    }
}
