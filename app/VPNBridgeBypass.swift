import Foundation

enum VPNBridgeBypassError: Error {
    case invalidSnapshot, unavailable, unsupportedResources
}

/// Pure projection of a freshly authenticated, route-proven helper snapshot.
/// Saved user intent is deliberately not an input. This value alone does not
/// mutate a bridge, configuration file, DNS or system proxy settings.
struct VPNBridgeBypass: Equatable {
    let generation: UInt64
    let revision: UInt64?
    let matchers: [String]

    init(snapshot: VPNTunnelSnapshot) throws {
        do { try snapshot.validate() }
        catch { throw VPNBridgeBypassError.invalidSnapshot }
        generation = snapshot.generation
        if snapshot.phase == .off {
            revision = nil
            matchers = []
            return
        }
        // A failed/transitioning/unavailable observation is not proof of
        // cleanup. Never silently turn it into an empty effective overlay.
        guard snapshot.phase == .connected, snapshot.generation > 0,
              let active = snapshot.active else {
            throw VPNBridgeBypassError.unavailable
        }
        do { try active.spec.validateCurrentRuntimeCapability() }
        catch { throw VPNBridgeBypassError.unsupportedResources }
        revision = active.spec.revision
        matchers = active.spec.resources.map(\.address).sorted()
    }

    /// Preserve the user's exact list as a prefix; append only missing exact
    /// matchers. Never widen a selected public IP to its containing network.
    func merging(with userList: String) -> String {
        let existing = Set(userList.split(separator: ",").map {
            $0.trimmingCharacters(in: .whitespaces)
        })
        let added = matchers.filter { !existing.contains($0) }
        guard !added.isEmpty else { return userList }
        return userList + (userList.isEmpty || userList.hasSuffix(",") ? "" : ",")
            + added.joined(separator: ",")
    }
}
