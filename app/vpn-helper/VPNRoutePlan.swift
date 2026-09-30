import Darwin
import Foundation

enum VPNRoutePlanError: Error, Equatable {
    case invalidGeneration, invalidRevision, unsupportedResource, duplicate, overlap
    case peerWouldBeCaptured, invalidPeerEvidence, invalidKernelEvidence, invalidTunnelEvidence
}

enum VPNRouteAddressFamily: UInt8, Codable, Comparable {
    case ipv4 = 4, ipv6 = 6
    static func < (left: Self, right: Self) -> Bool { left.rawValue < right.rawValue }
}

/// Canonical binary prefix. Text is retained only as a deterministic display
/// value; all containment and identity checks use the bytes and prefix length.
struct VPNRoutePrefix: Codable, Equatable, Comparable {
    let family: VPNRouteAddressFamily
    let bytes: [UInt8]
    let prefixLength: UInt8
    let canonical: String

    static func < (left: Self, right: Self) -> Bool {
        if left.family != right.family { return left.family < right.family }
        if left.bytes != right.bytes { return left.bytes.lexicographicallyPrecedes(right.bytes) }
        return left.prefixLength < right.prefixLength
    }

    init(resource: VPNResource) throws {
        try resource.validate()
        guard resource.kind != .domain else { throw VPNRoutePlanError.unsupportedResource }
        let parts = resource.address.split(separator: "/", omittingEmptySubsequences: false)
        let family: VPNRouteAddressFamily
        let size: Int
        switch resource.kind {
        case .ipv4, .network4: family = .ipv4; size = 4
        case .ipv6, .network6: family = .ipv6; size = 16
        case .domain: throw VPNRoutePlanError.unsupportedResource
        }
        var binary = [UInt8](repeating: 0, count: size)
        let nativeFamily = family == .ipv4 ? AF_INET : AF_INET6
        guard String(parts[0]).withCString({ pointer in
            binary.withUnsafeMutableBytes { inet_pton(nativeFamily, pointer, $0.baseAddress!) }
        }) == 1 else { throw VPNRoutePlanError.unsupportedResource }
        let prefix: Int
        if parts.count == 2, let parsed = Int(parts[1]) { prefix = parsed }
        else if parts.count == 1 { prefix = size * 8 }
        else { throw VPNRoutePlanError.unsupportedResource }
        guard prefix > 0, prefix <= size * 8 else { throw VPNRoutePlanError.unsupportedResource }
        self.family = family; bytes = binary; prefixLength = UInt8(prefix)
        canonical = resource.address
        try validate()
    }

    init(hostBytes: [UInt8], family: VPNRouteAddressFamily) throws {
        guard hostBytes.count == (family == .ipv4 ? 4 : 16) else {
            throw VPNRoutePlanError.invalidPeerEvidence
        }
        self.family = family; bytes = hostBytes
        prefixLength = UInt8(hostBytes.count * 8)
        canonical = try Self.format(hostBytes, family: family)
        try validate()
    }

    func validate() throws {
        let count = family == .ipv4 ? 4 : 16
        guard bytes.count == count, prefixLength > 0, prefixLength <= count * 8,
              canonical == (try Self.format(bytes, family: family))
                + (prefixLength == count * 8 ? "" : "/\(prefixLength)") else {
            throw VPNRoutePlanError.unsupportedResource
        }
        var masked = bytes
        Self.mask(&masked, prefix: Int(prefixLength))
        guard masked == bytes else { throw VPNRoutePlanError.unsupportedResource }
    }

    func contains(host: VPNRoutePrefix) -> Bool {
        guard family == host.family,
              host.prefixLength == (family == .ipv4 ? 32 : 128) else { return false }
        return Self.match(bytes, host.bytes, bits: Int(prefixLength))
    }

    func overlaps(_ other: VPNRoutePrefix) -> Bool {
        family == other.family
            && Self.match(bytes, other.bytes, bits: min(Int(prefixLength), Int(other.prefixLength)))
    }

    private static func mask(_ bytes: inout [UInt8], prefix: Int) {
        for index in bytes.indices {
            let remaining = max(0, min(8, prefix - index * 8))
            bytes[index] &= remaining == 0 ? 0 : UInt8(0xff << (8 - remaining) & 0xff)
        }
    }

    private static func match(_ first: [UInt8], _ second: [UInt8], bits: Int) -> Bool {
        guard first.count == second.count else { return false }
        let whole = bits / 8, remainder = bits % 8
        guard Array(first.prefix(whole)) == Array(second.prefix(whole)) else { return false }
        if remainder == 0 { return true }
        let mask = UInt8(0xff << (8 - remainder) & 0xff)
        return first[whole] & mask == second[whole] & mask
    }

    static func format(_ bytes: [UInt8], family: VPNRouteAddressFamily) throws -> String {
        var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        let result = bytes.withUnsafeBytes {
            inet_ntop(family == .ipv4 ? AF_INET : AF_INET6,
                      $0.baseAddress!, &buffer, socklen_t(buffer.count))
        }
        guard result != nil else { throw VPNRoutePlanError.invalidPeerEvidence }
        return String(cString: buffer)
    }
}

/// Typed output of a future trusted resolver + physical route snapshot. There
/// is intentionally no string/path/IPC initializer. Interface identity comes
/// from the kernel's index table at construction time.
struct VPNRoutePeerEvidence: Codable, Equatable {
    let peer: VPNRoutePrefix
    let gatewayBytes: [UInt8]?
    let interfaceIndex: UInt32
    let interfaceName: String

    init(peer: in_addr, gateway: in_addr?, interfaceIndex: UInt32) throws {
        try self.init(peerBytes: Self.bytes(peer), gatewayBytes: gateway.map(Self.bytes),
                      family: .ipv4, interfaceIndex: interfaceIndex)
    }

    init(peer: in6_addr, gateway: in6_addr?, interfaceIndex: UInt32) throws {
        try self.init(peerBytes: Self.bytes(peer), gatewayBytes: gateway.map(Self.bytes),
                      family: .ipv6, interfaceIndex: interfaceIndex)
    }

    private init(peerBytes: [UInt8], gatewayBytes: [UInt8]?, family: VPNRouteAddressFamily,
                 interfaceIndex: UInt32) throws {
        peer = try VPNRoutePrefix(hostBytes: peerBytes, family: family)
        guard !Self.invalidPeer(peerBytes, family: family),
              gatewayBytes == nil || gatewayBytes?.count == peerBytes.count,
              gatewayBytes == nil || Self.validGateway(gatewayBytes!, family: family),
              interfaceIndex > 0 else { throw VPNRoutePlanError.invalidPeerEvidence }
        var name = [CChar](repeating: 0, count: Int(IFNAMSIZ))
        guard if_indextoname(interfaceIndex, &name) != nil else {
            throw VPNRoutePlanError.invalidPeerEvidence
        }
        self.gatewayBytes = gatewayBytes
        self.interfaceIndex = interfaceIndex
        interfaceName = String(cString: name)
        try validate()
    }

    func validate() throws {
        try peer.validate()
        let size = peer.family == .ipv4 ? 4 : 16
        guard peer.prefixLength == size * 8,
              !Self.invalidPeer(peer.bytes, family: peer.family),
              gatewayBytes == nil || gatewayBytes?.count == size,
              gatewayBytes == nil || Self.validGateway(gatewayBytes!, family: peer.family),
              interfaceIndex > 0, !interfaceName.isEmpty,
              interfaceName.utf8.count < IFNAMSIZ else {
            throw VPNRoutePlanError.invalidPeerEvidence
        }
        var name = [CChar](repeating: 0, count: Int(IFNAMSIZ))
        guard if_indextoname(interfaceIndex, &name) != nil,
              String(cString: name) == interfaceName else {
            throw VPNRoutePlanError.invalidPeerEvidence
        }
    }

    private static func invalidPeer(_ bytes: [UInt8], family: VPNRouteAddressFamily) -> Bool {
        if family == .ipv4 {
            return bytes.count != 4 || bytes[0] == 0 || bytes[0] == 127 || bytes[0] >= 224
                || (bytes[0] == 169 && bytes[1] == 254)
        }
        return bytes.count != 16 || bytes.allSatisfy { $0 == 0 }
            || (bytes.dropLast().allSatisfy { $0 == 0 } && bytes.last == 1)
            || bytes[0] == 0xff || (bytes[0] == 0xfe && bytes[1] & 0xc0 == 0x80)
    }

    static func validGateway(_ bytes: [UInt8], family: VPNRouteAddressFamily) -> Bool {
        if family == .ipv4 {
            return bytes.count == 4 && bytes.contains(where: { $0 != 0 })
                && bytes[0] != 127 && bytes[0] < 224
        }
        return bytes.count == 16 && bytes.contains(where: { $0 != 0 })
            && !(bytes.dropLast().allSatisfy({ $0 == 0 }) && bytes.last == 1)
            && bytes[0] != 0xff
    }

    private static func bytes<T>(_ value: T) -> [UInt8] {
        var copy = value
        return withUnsafeBytes(of: &copy) { Array($0) }
    }
}

enum VPNPlannedRouteRole: UInt8, Codable { case peerBypass = 1, resource = 2 }

/// An interface identity may enter a route plan only through the resolver's
/// typed evidence. The serialized copy is retained so every resource route is
/// bound to that exact index/name pair during recovery and validation.
struct VPNTunnelRouteBinding: Codable, Equatable {
    let interfaceIndex: UInt32
    let interfaceName: String

    init(evidence: VPNTunnelInterfaceEvidence) throws {
        interfaceIndex = evidence.index
        interfaceName = evidence.name
        try validate()
    }

    func validate() throws {
        let suffix = interfaceName.dropFirst(4)
        guard interfaceIndex > 0, interfaceName.hasPrefix("utun"), !suffix.isEmpty,
              suffix.utf8.allSatisfy({ (48...57).contains($0) }),
              interfaceName.utf8.count < Int(IFNAMSIZ) else {
            throw VPNRoutePlanError.invalidTunnelEvidence
        }
    }
}

struct VPNPlannedRoute: Codable, Equatable, Comparable {
    let role: VPNPlannedRouteRole
    let destination: VPNRoutePrefix
    let physicalGatewayBytes: [UInt8]?
    let interfaceIndex: UInt32?
    let interfaceName: String?

    static func < (left: Self, right: Self) -> Bool {
        if left.role.rawValue != right.role.rawValue { return left.role.rawValue < right.role.rawValue }
        return left.destination < right.destination
    }

    func validate() throws {
        try destination.validate()
        if role == .peerBypass {
            let size = destination.family == .ipv4 ? 4 : 16
            guard destination.prefixLength == size * 8,
                  physicalGatewayBytes == nil || physicalGatewayBytes?.count == size,
                  physicalGatewayBytes == nil || VPNRoutePeerEvidence.validGateway(
                    physicalGatewayBytes!, family: destination.family),
                  interfaceIndex != nil, interfaceName?.isEmpty == false,
                  (interfaceName?.utf8.count ?? Int(IFNAMSIZ)) < Int(IFNAMSIZ),
                  interfaceName?.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains) == false else {
                throw VPNRoutePlanError.invalidPeerEvidence
            }
        } else {
            let suffix = interfaceName?.dropFirst(4) ?? Substring()
            guard physicalGatewayBytes == nil, (interfaceIndex ?? 0) > 0,
                  interfaceName?.hasPrefix("utun") == true, !suffix.isEmpty,
                  suffix.utf8.allSatisfy({ (48...57).contains($0) }),
                  (interfaceName?.utf8.count ?? Int(IFNAMSIZ)) < Int(IFNAMSIZ) else {
                throw VPNRoutePlanError.invalidTunnelEvidence
            }
        }
    }
}

/// Pure plan only. No route is installed and `routes` is not applied evidence.
struct VPNRoutePlan: Codable, Equatable {
    static let schema = 2
    let schemaVersion: Int
    let generation: UInt64
    let revision: UInt64
    let tunnelInterface: VPNTunnelRouteBinding
    let routes: [VPNPlannedRoute]

    init(generation: UInt64, revision: UInt64, resources: [VPNResource],
         peer: VPNRoutePeerEvidence, tunnel: VPNTunnelInterfaceEvidence) throws {
        guard generation > 0 else { throw VPNRoutePlanError.invalidGeneration }
        guard revision > 0 else { throw VPNRoutePlanError.invalidRevision }
        guard !resources.isEmpty, resources.count <= 1000 else {
            throw VPNRoutePlanError.unsupportedResource
        }
        try peer.validate()
        let tunnelBinding = try VPNTunnelRouteBinding(evidence: tunnel)
        guard peer.interfaceIndex != tunnelBinding.interfaceIndex,
              peer.interfaceName != tunnelBinding.interfaceName else {
            throw VPNRoutePlanError.invalidPeerEvidence
        }
        var prefixes = try resources.map(VPNRoutePrefix.init(resource:))
        prefixes.sort()
        for index in prefixes.indices {
            if index > 0 {
                guard prefixes[index] != prefixes[index - 1] else { throw VPNRoutePlanError.duplicate }
                guard !prefixes[index].overlaps(prefixes[index - 1]) else { throw VPNRoutePlanError.overlap }
            }
            guard !prefixes[index].contains(host: peer.peer) else {
                throw VPNRoutePlanError.peerWouldBeCaptured
            }
        }
        let bypass = VPNPlannedRoute(role: .peerBypass, destination: peer.peer,
            physicalGatewayBytes: peer.gatewayBytes, interfaceIndex: peer.interfaceIndex,
            interfaceName: peer.interfaceName)
        routes = [bypass] + prefixes.map {
            VPNPlannedRoute(role: .resource, destination: $0, physicalGatewayBytes: nil,
                            interfaceIndex: tunnelBinding.interfaceIndex,
                            interfaceName: tunnelBinding.interfaceName)
        }
        schemaVersion = Self.schema; self.generation = generation; self.revision = revision
        tunnelInterface = tunnelBinding
        try validate()
    }

    func validate() throws {
        guard schemaVersion == Self.schema, generation > 0, revision > 0,
              (2...1001).contains(routes.count), routes == routes.sorted(),
              routes.first?.role == .peerBypass,
              routes.dropFirst().allSatisfy({ $0.role == .resource }) else {
            throw VPNRoutePlanError.unsupportedResource
        }
        try tunnelInterface.validate()
        for route in routes { try route.validate() }
        guard let bypass = routes.first,
              bypass.interfaceIndex != tunnelInterface.interfaceIndex,
              bypass.interfaceName != tunnelInterface.interfaceName else {
            throw VPNRoutePlanError.invalidPeerEvidence
        }
        let resources = Array(routes.dropFirst())
        for index in resources.indices {
            guard resources[index].interfaceIndex == tunnelInterface.interfaceIndex,
                  resources[index].interfaceName == tunnelInterface.interfaceName else {
                throw VPNRoutePlanError.invalidTunnelEvidence
            }
            if index > 0 {
                guard resources[index].destination != resources[index - 1].destination,
                      !resources[index].destination.overlaps(resources[index - 1].destination) else {
                    throw VPNRoutePlanError.overlap
                }
            }
            guard !resources[index].destination.contains(host: routes[0].destination) else {
                throw VPNRoutePlanError.peerWouldBeCaptured
            }
        }
    }
}
