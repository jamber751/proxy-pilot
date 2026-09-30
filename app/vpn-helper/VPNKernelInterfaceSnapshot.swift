import Darwin
import Foundation

enum VPNKernelInterfaceSnapshotError: Error, Equatable {
    case inspectionFailed, invalidIdentity, duplicateIdentity
}

struct VPNKernelInterfaceRecord: Equatable {
    let index: UInt32
    let name: String
    let isUp: Bool
    let isRunning: Bool
    let isPointToPoint: Bool
    let addresses: [OpenVPNIPAddress]

    init(index: UInt32, name: String, isUp: Bool, isRunning: Bool,
         isPointToPoint: Bool, addresses: [OpenVPNIPAddress]) throws {
        guard index > 0, !name.isEmpty, name.utf8.count < Int(IFNAMSIZ),
              name.unicodeScalars.allSatisfy({ !CharacterSet.controlCharacters.contains($0) }) else {
            throw VPNKernelInterfaceSnapshotError.invalidIdentity
        }
        self.index = index
        self.name = name
        self.isUp = isUp
        self.isRunning = isRunning
        self.isPointToPoint = isPointToPoint
        self.addresses = Self.normalized(addresses)
    }

    private static func normalized(_ values: [OpenVPNIPAddress]) -> [OpenVPNIPAddress] {
        var result = [OpenVPNIPAddress]()
        for value in values.sorted(by: {
            $0.family.rawValue != $1.family.rawValue
                ? $0.family.rawValue < $1.family.rawValue
                : $0.bytes.lexicographicallyPrecedes($1.bytes)
        }) where !result.contains(value) { result.append(value) }
        return result
    }
}

/// Immutable kernel evidence captured only when `capture()` is explicitly
/// called. It uses getifaddrs/if_nametoindex and never changes an interface.
struct VPNKernelInterfaceSnapshot: Equatable {
    let interfaces: [VPNKernelInterfaceRecord]

    init(interfaces: [VPNKernelInterfaceRecord]) throws {
        var indexes = Set<UInt32>(), names = Set<String>()
        for item in interfaces {
            guard indexes.insert(item.index).inserted, names.insert(item.name).inserted else {
                throw VPNKernelInterfaceSnapshotError.duplicateIdentity
            }
        }
        self.interfaces = interfaces.sorted {
            $0.index != $1.index ? $0.index < $1.index : $0.name < $1.name
        }
    }

    static func capture() throws -> VPNKernelInterfaceSnapshot {
        var head: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&head) == 0, let first = head else {
            throw VPNKernelInterfaceSnapshotError.inspectionFailed
        }
        defer { freeifaddrs(first) }

        struct Accumulator {
            let index: UInt32
            let name: String
            var flags: UInt32
            var addresses: [OpenVPNIPAddress]
        }
        var values = [String: Accumulator]()
        var cursor: UnsafeMutablePointer<ifaddrs>? = first
        while let current = cursor {
            defer { cursor = current.pointee.ifa_next }
            guard let rawName = current.pointee.ifa_name,
                  let name = String(validatingUTF8: rawName) else {
                throw VPNKernelInterfaceSnapshotError.inspectionFailed
            }
            let index = if_nametoindex(rawName)
            guard index > 0 else { throw VPNKernelInterfaceSnapshotError.inspectionFailed }
            var stableName = [CChar](repeating: 0, count: Int(IFNAMSIZ))
            guard if_indextoname(index, &stableName) != nil,
                  String(cString: stableName) == name else {
                throw VPNKernelInterfaceSnapshotError.invalidIdentity
            }
            let key = "\(index):\(name)"
            var value = values[key] ?? Accumulator(index: index, name: name,
                flags: current.pointee.ifa_flags, addresses: [])
            value.flags |= current.pointee.ifa_flags
            if let address = current.pointee.ifa_addr {
                if address.pointee.sa_family == UInt8(AF_INET) {
                    let item = UnsafeRawPointer(address).assumingMemoryBound(to: sockaddr_in.self).pointee
                    let bytes = withUnsafeBytes(of: item.sin_addr) { Array($0) }
                    value.addresses.append(try OpenVPNIPAddress(family: .ipv4, bytes: bytes))
                } else if address.pointee.sa_family == UInt8(AF_INET6) {
                    let item = UnsafeRawPointer(address).assumingMemoryBound(to: sockaddr_in6.self).pointee
                    let bytes = withUnsafeBytes(of: item.sin6_addr) { Array($0) }
                    value.addresses.append(try OpenVPNIPAddress(family: .ipv6, bytes: bytes))
                }
            }
            values[key] = value
        }
        let records = try values.values.map { value in
            try VPNKernelInterfaceRecord(index: value.index, name: value.name,
                isUp: value.flags & UInt32(IFF_UP) != 0,
                isRunning: value.flags & UInt32(IFF_RUNNING) != 0,
                isPointToPoint: value.flags & UInt32(IFF_POINTOPOINT) != 0,
                addresses: value.addresses)
        }
        return try VPNKernelInterfaceSnapshot(interfaces: records)
    }
}
