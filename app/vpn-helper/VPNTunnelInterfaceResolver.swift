import Foundation

enum VPNTunnelInterfaceResolutionError: Error, Equatable {
    case invalidConnectedEvidence, noCandidate, ambiguous, reusedIdentity
}

struct VPNTunnelInterfaceEvidence: Equatable {
    let index: UInt32
    let name: String
    let addresses: [OpenVPNIPAddress]

    fileprivate init(index: UInt32, name: String, addresses: [OpenVPNIPAddress]) {
        self.index = index
        self.name = name
        self.addresses = addresses
    }
}

enum VPNTunnelInterfaceResolver {
    static func resolve(baseline: VPNKernelInterfaceSnapshot,
                        after: VPNKernelInterfaceSnapshot,
                        management: OpenVPNConnectedEvidence) throws
        -> VPNTunnelInterfaceEvidence {
        let required = [management.tunnelLocalIPv4, management.tunnelLocalIPv6].compactMap { $0 }
        guard !required.isEmpty else {
            throw VPNTunnelInterfaceResolutionError.invalidConnectedEvidence
        }

        let baselineIndexes = Dictionary(uniqueKeysWithValues:
            baseline.interfaces.map { ($0.index, $0.name) })
        let baselineNames = Dictionary(uniqueKeysWithValues:
            baseline.interfaces.map { ($0.name, $0.index) })
        var candidates = [VPNKernelInterfaceRecord]()
        for item in after.interfaces where isUTUN(item.name) {
            if let oldName = baselineIndexes[item.index], oldName != item.name {
                throw VPNTunnelInterfaceResolutionError.reusedIdentity
            }
            if let oldIndex = baselineNames[item.name], oldIndex != item.index {
                throw VPNTunnelInterfaceResolutionError.reusedIdentity
            }
            guard baselineIndexes[item.index] == nil, baselineNames[item.name] == nil else { continue }
            guard item.isUp, item.isRunning, item.isPointToPoint,
                  required.allSatisfy(item.addresses.contains) else { continue }
            candidates.append(item)
        }
        guard !candidates.isEmpty else { throw VPNTunnelInterfaceResolutionError.noCandidate }
        guard candidates.count == 1 else { throw VPNTunnelInterfaceResolutionError.ambiguous }
        let match = candidates[0]
        return VPNTunnelInterfaceEvidence(index: match.index, name: match.name,
                                          addresses: match.addresses)
    }

    private static func isUTUN(_ name: String) -> Bool {
        let suffix = name.dropFirst(4)
        return name.hasPrefix("utun") && !suffix.isEmpty
            && suffix.utf8.allSatisfy { (48...57).contains($0) }
    }
}
