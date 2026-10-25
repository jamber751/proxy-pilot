import Dispatch
import Foundation

/// The real helper session implements this authenticated bounded transaction.
/// Injected sessions belong only to isolated tests; there is no default success.
protocol VPNBridgeBootstrapSession: AnyObject {
    func bootstrapBridge<T: VPNBridgeBootstrapOwnedRuntime>(
        activate: (VPNBridgeRootInventory, DispatchTime) throws -> T) throws -> T
}
extension VPNHelperSession: VPNBridgeBootstrapSession {}

/// Root custody is acquired BEFORE the App publication lock. The activation
/// factory must install the full supplied snapshot as GOST's initial policy
/// before any bridge listener, own/pin that process and honour its deadline.
/// A returned object is retired exactly once on a failed post-activation check.
/// Ongoing DNS answers need their separate live root/bridge ACK authority.
enum VPNBridgeBootstrap {
    static func start<T: VPNBridgeBootstrapOwnedRuntime>(
        session: VPNBridgeBootstrapSession, store: VPNBridgeProtectionStore,
        configuration: VPNConfiguration,
        checkConfiguration: (VPNConfiguration) throws -> Void,
        activate: (VPNBridgeProtectedSnapshot, DispatchTime) throws -> T) throws -> T {
        try configuration.validate()
        return try session.bootstrapBridge { root,deadline in
            func current() throws {
                guard DispatchTime.now()<deadline else { throw VPNBridgeProtectionError.expired }
                try checkConfiguration(configuration)
                guard DispatchTime.now()<deadline else { throw VPNBridgeProtectionError.expired }
            }
            try current();try root.validate()
            let numeric=configuration.resources.filter { $0.kind != .domain }.map(\.address)
            let addresses=root.matchers+numeric+configuration.corporateDNS
            return try store.withPreparedBoot(addresses,checkCurrent:current,activate:{ prepared in
                try activate(prepared,deadline)
            },retire:{ $0.retire() })
        }
    }
}
