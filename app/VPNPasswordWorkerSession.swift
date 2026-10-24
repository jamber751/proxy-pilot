import Foundation

/// One authenticated, one-operation worker. Coordinators remain inert until
/// their caller explicitly opts into this driver; construction does not enable
/// UI persistence or schedule cleanup work.
final class VPNPasswordWorkerSession: VPNPasswordPersistenceSession, VPNPasswordCleanupSession {
    private let prepared: VPNPasswordWorker.Prepared

    init(prepared: VPNPasswordWorker.Prepared) {
        self.prepared = prepared
    }

    static func prepare(store: VPNStore) throws -> VPNPasswordWorkerSession {
        try VPNPasswordWorkerSession(prepared: VPNPasswordWorker.prepare(store: store))
    }

    func read(store: VPNStore, reference: VPNPasswordReference, revision: UInt64) throws -> Data? {
        var response = try prepared.read(store: store, reference: reference, revision: revision)
        defer { VPNPasswordWorkerWire.clear(&response.secret) }
        try response.validate(operation: .read)
        guard response.status == .success else { return nil }
        // Give the consumer its own transient bytes before wiping our response.
        // Security/CFData/Data copies cannot all be guaranteed to be zeroed.
        return response.secret.withUnsafeBytes { Data($0) }
    }

    func addOnce(store: VPNStore, reference: VPNPasswordReference, revision: UInt64,
                 secret: inout Data) throws -> VPNPasswordAddOutcome {
        defer { VPNPasswordWorkerWire.clear(&secret) }
        return try prepared.addOnce(store: store, reference: reference, revision: revision, secret: &secret)
    }

    func deletePendingOutcome(store: VPNStore, reference: VPNPasswordReference) throws -> VPNPasswordDeleteOutcome {
        try prepared.deletePendingOutcome(store: store, reference: reference)
    }
}
