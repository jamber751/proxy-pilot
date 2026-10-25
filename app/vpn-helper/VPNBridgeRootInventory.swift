import CryptoKit
import Foundation

enum VPNBridgeRootInventoryError: Error { case expired, changed }

/// Reads all currently persisted root sources used by the bridge: retained
/// exact hosts, active/pending configuration and the legacy route journal.
/// This is an observation, not a lease across a future bridge listen or DNS
/// release. Callers must not turn equal consecutive observations into a lease.
enum VPNBridgeRootInventoryReader {
    static func read(deadline: DispatchTime,
                     retained: () throws -> VPNRetainedProtectionInventory,
                     state: () throws -> VPNTunnelSnapshot,
                     journal: () throws -> VPNRouteJournalSnapshot?,
                     checkCurrent: () throws -> Void) throws -> VPNBridgeRootInventory {
        func current() throws {
            guard DispatchTime.now() < deadline else { throw VPNBridgeRootInventoryError.expired }
            try checkCurrent()
            guard DispatchTime.now() < deadline else { throw VPNBridgeRootInventoryError.expired }
        }
        try current()
        let hosts = try retained(), configuration = try state(), routes = try journal()
        try hosts.validate();try configuration.validate();try routes?.validate();try current()
        var matchers = hosts.prefixes
        for application in [configuration.active, configuration.pending].compactMap({ $0 }) {
            matchers += try application.spec.resources.filter { $0.kind != .domain }
                .map { try VPNBridgeRootInventory.canonical($0.address) }
            matchers += try application.spec.corporateDNS.map(VPNBridgeRootInventory.canonical)
        }
        // Keep every planned prefix, including unknown/retired operations. A
        // journal's cleanup phase is not permission to discard App boot cache.
        if let routes {
            matchers += try routes.plan.routes.filter { $0.role != .peerBypass }
                .map { try VPNBridgeRootInventory.canonical($0.destination.canonical) }
        }
        let encoder = JSONEncoder();encoder.outputFormatting = [.sortedKeys]
        let stateHash = SHA256.hash(data: try configuration.encoded()).map { String(format:"%02x",$0) }.joined()
        let routeHash = try routes.map { value in
            SHA256.hash(data: try encoder.encode(value)).map { String(format:"%02x",$0) }.joined()
        }
        let result = try VPNBridgeRootInventory(bootID:hosts.bootID, stateSHA256:stateHash,
            routeJournalSHA256:routeHash, matchers:Set(matchers).sorted())
        try current()
        // Detect changes during collection. No retries with a renewed deadline.
        guard try retained() == hosts, try state() == configuration, try journal() == routes else {
            throw VPNBridgeRootInventoryError.changed
        }
        try current();return result
    }
}

/// Same store lock as retained-host mutations; the listener serializes static
/// configuration edits. Future dynamic/static writers must use this custody
/// boundary before their backend is enabled. No upstream DNS wait is allowed.
final class VPNRootBridgeBootstrapSource: VPNBridgeBootstrapSource {
    private let runtime: VPNRetainedFenceRuntime
    private let read: (DispatchTime) throws -> Data
    init(runtime: VPNRetainedFenceRuntime, read: @escaping (DispatchTime) throws -> Data) {
        self.runtime=runtime;self.read=read
    }
    func withInventory(deadline: DispatchTime,
                       body: (Data, () throws -> Void) throws -> Void) throws {
        func current() throws {
            guard DispatchTime.now()<deadline else { throw VPNBridgeRootInventoryError.expired }
            try runtime.check()
            guard DispatchTime.now()<deadline else { throw VPNBridgeRootInventoryError.expired }
        }
        try current()
        try runtime.store.withEntries { _ in
            try current()
            let before=try read(deadline)
            _=try VPNBridgeRootInventory.decodeCanonical(before)
            try current()
            try body(before,{
                try current()
                guard try self.read(deadline)==before else { throw VPNBridgeRootInventoryError.changed }
            })
        }
    }
}
