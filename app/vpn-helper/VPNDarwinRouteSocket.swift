import Darwin
import Foundation

enum VPNRouteSocketTransportError: VPNFlowDiagnosticError, Equatable {
    case posix(Int32)
    case timeout
    case closed
    var vpnFlowFailureCode: VPNFlowFailureCode {
        switch self { case .posix: return .transport; case .timeout: return .timeout; case .closed: return .closed }
    }
    var vpnFlowErrorNumber: Int32 { if case .posix(let code) = self { return code }; return 0 }
}

protocol VPNRouteSocketTransport: AnyObject {
    func send(_ message: Data, deadline: DispatchTime) throws
    func receive(maximumBytes: Int, deadline: DispatchTime) throws -> Data
}

/// Injectable native boundary. Fake implementations must never open PF_ROUTE.
protocol VPNRouteSocketIO: AnyObject {
    func open() throws -> Int32
    func close(_ descriptor: Int32)
    func send(_ message: Data, descriptor: Int32, deadline: DispatchTime) throws
    func receive(descriptor: Int32, maximumBytes: Int, deadline: DispatchTime) throws -> Data
}

/// One controller owns a transport and serializes its request/reply exchanges.
/// An idle PF_ROUTE socket receives broadcasts too: a full old queue can drop a
/// newly generated reply before the controller can drain unrelated messages.
/// Fresh request sockets avoid carrying that idle backlog into the next write.
/// Broadcasts during the request can still cause refusal; no write is replayed.
final class VPNDarwinRouteSocketTransport: VPNRouteSocketTransport {
    private let io: VPNRouteSocketIO
    private var descriptor: Int32

    init(io: VPNRouteSocketIO = VPNDarwinRouteSocketIO()) throws {
        self.io = io
        descriptor = try io.open()
    }
    deinit { if descriptor >= 0 { io.close(descriptor) } }
    func send(_ message: Data, deadline: DispatchTime) throws {
        // Open/configure before retiring the previous owned descriptor. Failure
        // here issues no write and leaves its cleanup obligation with this owner.
        let fresh = try io.open()
        let previous = descriptor
        descriptor = fresh
        io.close(previous)
        try io.send(message, descriptor: descriptor, deadline: deadline)
    }
    func receive(maximumBytes: Int, deadline: DispatchTime) throws -> Data {
        try io.receive(descriptor: descriptor, maximumBytes: maximumBytes, deadline: deadline)
    }
}

final class VPNDarwinRouteSocketIO: VPNRouteSocketIO {
    func open() throws -> Int32 {
        let descriptor = socket(PF_ROUTE, SOCK_RAW, AF_UNSPEC)
        guard descriptor >= 0 else { throw VPNRouteSocketTransportError.posix(errno) }
        let flags = fcntl(descriptor, F_GETFL)
        guard flags >= 0, fcntl(descriptor, F_SETFD, FD_CLOEXEC) == 0,
              fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) == 0 else {
            let saved = errno; Darwin.close(descriptor)
            throw VPNRouteSocketTransportError.posix(saved)
        }
        return descriptor
    }

    func close(_ descriptor: Int32) { Darwin.close(descriptor) }

    func send(_ message: Data, descriptor: Int32, deadline: DispatchTime) throws {
        let written: Int = try message.withUnsafeBytes { bytes in
            while true {
                try wait(descriptor: descriptor, events: Int16(POLLOUT), deadline: deadline)
                let result = Darwin.write(descriptor, bytes.baseAddress!, bytes.count)
                if result < 0 && errno == EINTR { continue }
                if result < 0 && (errno == EAGAIN || errno == EWOULDBLOCK) { continue }
                if result < 0 { throw VPNRouteSocketTransportError.posix(errno) }
                return result
            }
        }
        guard written == message.count else { throw VPNRouteSocketTransportError.closed }
    }

    func receive(descriptor: Int32, maximumBytes: Int, deadline: DispatchTime) throws -> Data {
        var bytes = [UInt8](repeating: 0, count: maximumBytes)
        while true {
            try wait(descriptor: descriptor, events: Int16(POLLIN), deadline: deadline)
            let count = Darwin.read(descriptor, &bytes, bytes.count)
            if count < 0 && errno == EINTR { continue }
            if count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK) { continue }
            if count < 0 { throw VPNRouteSocketTransportError.posix(errno) }
            guard count > 0 else { throw VPNRouteSocketTransportError.closed }
            return Data(bytes.prefix(count))
        }
    }

    private func wait(descriptor: Int32, events: Int16, deadline: DispatchTime) throws {
        while true {
            let now = DispatchTime.now().uptimeNanoseconds
            let end = deadline.uptimeNanoseconds
            guard now < end else { throw VPNRouteSocketTransportError.timeout }
            let remaining = min(UInt64(Int32.max), (end - now + 999_999) / 1_000_000)
            var item = pollfd(fd: descriptor, events: events, revents: 0)
            let result = poll(&item, 1, Int32(remaining))
            if result < 0 && errno == EINTR { continue }
            if result < 0 { throw VPNRouteSocketTransportError.posix(errno) }
            if result == 0 { throw VPNRouteSocketTransportError.timeout }
            guard item.revents & (Int16(POLLERR) | Int16(POLLHUP) | Int16(POLLNVAL)) == 0,
                  item.revents & events != 0 else { throw VPNRouteSocketTransportError.closed }
            return
        }
    }
}

enum VPNDarwinRouteError: VPNFlowDiagnosticError, Equatable {
    case invalidIdentity
    case malformedMessage
    case responseLimit
    case timeout
    case transport(Int32)
    case closed
    case kernel(Int32)
    case preexistingNonIdentical
    case missingOrForeign
    case verificationFailed
    var vpnFlowFailureCode: VPNFlowFailureCode {
        switch self {
        case .invalidIdentity: return .invalidIdentity
        case .malformedMessage: return .malformedMessage
        case .responseLimit: return .responseLimit
        case .timeout: return .timeout
        case .transport: return .transport
        case .closed: return .closed
        case .kernel: return .kernel
        case .preexistingNonIdentical: return .preexistingNonIdentical
        case .missingOrForeign: return .missingOrForeign
        case .verificationFailed: return .verificationFailed
        }
    }
    var vpnFlowErrorNumber: Int32 {
        switch self { case .kernel(let code), .transport(let code): return code; default: return 0 }
    }
}

/// Separate identity for NET/full-mask blackholes. A /32 or /128 here is NOT
/// a legacy HOST/nil-mask key. Never persist this in VPNOwnedRouteIdentity or
/// reinterpret the old route journals. Shape alone is not an ownership receipt.
struct VPNExactRouteFenceIdentity: Codable, Equatable {
    static let schema = 1
    // in_addroute()/in6_addroute() derive PRCLONING for unicast NET routes.
    // Store that exact kernel profile; it is not an ignored/normalized bit.
    // apple-oss-distributions/xnu, bsd/netinet{,6}/in{,6}_rmx.c
    static let expectedFlags = UInt32(RTF_UP | RTF_STATIC | RTF_GATEWAY | RTF_BLACKHOLE | RTF_PROTO2 | RTF_PRCLONING)
    let schemaVersion: Int
    let address: VPNRoutePrefix
    let interfaceIndex: UInt32
    let gatewayBytes: [UInt8]
    let flags: UInt32
    var interfaceName: String { "lo0" }

    init(address: VPNRoutePrefix, loopbackIndex: UInt32) throws {
        schemaVersion = Self.schema; self.address = address; interfaceIndex = loopbackIndex
        gatewayBytes = Self.loopback(address.family); flags = Self.expectedFlags
        try validate()
    }
    func validate() throws {
        try address.validate()
        // Reuse the remote-service policy, not just a binary host parser. DNS
        // answers must never install a global rule over local/link/multicast IPs.
        let resource = try VPNResource(address: address.canonical)
        guard schemaVersion == Self.schema, interfaceIndex > 0, interfaceIndex <= UInt32(UInt16.max),
              address.prefixLength == address.bytes.count * 8,
              [.ipv4, .ipv6].contains(resource.kind),
              try VPNRoutePrefix(resource: resource) == address,
              flags == Self.expectedFlags, gatewayBytes == Self.loopback(address.family) else {
            throw VPNDarwinRouteError.invalidIdentity
        }
    }
    func matches(_ observed: VPNDarwinRouteSnapshot) -> Bool {
        // decode() requires a full netmask to produce a maximum-length prefix
        // without HOST. These exact flags also exclude scoped and HOST entries.
        observed.destination == address && observed.flags == flags &&
            observed.gatewayBytes == gatewayBytes && observed.interfaceIndex == interfaceIndex &&
            observed.interfaceName == interfaceName
    }
    private static func loopback(_ family: VPNRouteAddressFamily) -> [UInt8] {
        family == .ipv4 ? [127,0,0,1] : [UInt8](repeating:0,count:15)+[1]
    }
}

struct VPNDarwinRouteSnapshot: Equatable {
    let destination: VPNRoutePrefix
    let gatewayBytes: [UInt8]?
    let interfaceIndex: UInt32
    let interfaceName: String
    let flags: UInt32

    func matches(_ key: VPNRouteLookupKey) -> Bool {
        guard destination == key.destination else { return false }
        if let scope = key.interfaceScope {
            return flags & UInt32(RTF_IFSCOPE) != 0 && interfaceIndex == scope.interfaceIndex
                && interfaceName == scope.interfaceName
        }
        return flags & UInt32(RTF_IFSCOPE) == 0
    }

    func kernelEvidence() throws -> VPNRouteKernelEvidence {
        switch destination.family {
        case .ipv4:
            let gateway: in_addr? = try gatewayBytes.map { try Self.value($0, as: in_addr.self) }
            return try VPNRouteKernelEvidence(gateway: gateway, interfaceIndex: interfaceIndex,
                                              flags: flags)
        case .ipv6:
            let gateway: in6_addr? = try gatewayBytes.map { try Self.value($0, as: in6_addr.self) }
            return try VPNRouteKernelEvidence(gateway: gateway, interfaceIndex: interfaceIndex,
                                              flags: flags)
        }
    }

    func matches(_ identity: VPNOwnedRouteIdentity) -> Bool {
        destination == identity.destination && gatewayBytes == identity.gatewayBytes
            && interfaceIndex == identity.interfaceIndex && interfaceName == identity.interfaceName
            && flags == identity.flags
    }

    private static func value<T>(_ bytes: [UInt8], as: T.Type) throws -> T {
        guard bytes.count == MemoryLayout<T>.size else { throw VPNDarwinRouteError.malformedMessage }
        let value: T = bytes.withUnsafeBytes { raw in raw.loadUnaligned(as: T.self) }
        return value
    }
}

enum VPNDarwinRouteMutationResult: Equatable { case installed, alreadyPresent, removed }

enum VPNDarwinRouteCodec {
    static let maximumMessageBytes = 64 * 1024
    private static let headerSize = MemoryLayout<rt_msghdr>.size
    // PF_ROUTE uses ROUNDUP32 on both 64-bit Darwin architectures.
    private static let wordSize = MemoryLayout<UInt32>.size

    static func encode(type: UInt8, sequence: Int32, pid: Int32,
                       identity: VPNOwnedRouteIdentity) throws -> Data {
        try identity.validate()
        guard identity.interfaceIndex <= UInt32(UInt16.max) else {
            throw VPNDarwinRouteError.invalidIdentity
        }
        guard (try? interfaceName(identity.interfaceIndex)) == identity.interfaceName else {
            throw VPNDarwinRouteError.invalidIdentity
        }
        let isHost = Int(identity.destination.prefixLength) == identity.destination.bytes.count * 8
        guard isHost == (identity.flags & UInt32(RTF_HOST) != 0) else {
            throw VPNDarwinRouteError.invalidIdentity
        }
        // Stored identity is the exact KERNEL expectation. Strip the derived
        // neighbor bit only for this strict managed IPv6 direct-host profile.
        let requestFlags = VPNManagedIPv6HostRoute.isExact(identity) ? identity.flags & ~UInt32(RTF_LLINFO) : identity.flags
        let required = UInt32(RTF_UP | RTF_STATIC)
        let forbidden = UInt32(RTF_DYNAMIC | RTF_MODIFIED | RTF_DONE | RTF_LLINFO
            | RTF_WASCLONED | RTF_LOCAL | RTF_BROADCAST | RTF_MULTICAST | RTF_CONDEMNED | RTF_DEAD)
        guard requestFlags & required == required, requestFlags & forbidden == 0,
              (identity.gatewayBytes != nil) == (identity.flags & UInt32(RTF_GATEWAY) != 0) else {
            throw VPNDarwinRouteError.invalidIdentity
        }
        var addresses: [(Int32, Data)] = [(RTA_DST, address(identity.destination.bytes,
                                                             family: identity.destination.family))]
        if let gateway = identity.gatewayBytes {
            addresses.append((RTA_GATEWAY, address(gateway, family: identity.destination.family)))
        } else {
            addresses.append((RTA_GATEWAY, try link(index: identity.interfaceIndex,
                                                    name: identity.interfaceName)))
        }
        let host = isHost
        if !host { addresses.append((RTA_NETMASK, netmask(identity.destination))) }
        return try message(type: type, sequence: sequence, pid: pid, error: 0,
                           index: identity.interfaceIndex, flags: requestFlags,
                           addresses: addresses)
    }

    static func encodeLookup(destination: VPNRoutePrefix, sequence: Int32, pid: Int32) throws -> Data {
        try encodeLookup(key: VPNRouteLookupKey(destination: destination, interfaceScope: nil), sequence: sequence, pid: pid)
    }

    static func encodeLookup(key: VPNRouteLookupKey, sequence: Int32, pid: Int32) throws -> Data {
        try key.validate()
        if let scope = key.interfaceScope {
            guard (try? interfaceName(scope.interfaceIndex)) == scope.interfaceName else {
                throw VPNDarwinRouteError.invalidIdentity
            }
        }
        let destination = key.destination
        let host = Int(destination.prefixLength) == destination.bytes.count * 8
        var addresses: [(Int32, Data)] = [(RTA_DST, address(destination.bytes,
                                                             family: destination.family))]
        if !host { addresses.append((RTA_NETMASK, netmask(destination))) }
        return try message(type: UInt8(RTM_GET), sequence: sequence, pid: pid, error: 0,
                           index: key.interfaceScope?.interfaceIndex ?? 0,
                           flags: (host ? UInt32(RTF_HOST) : 0) | (key.interfaceScope == nil ? 0 : UInt32(RTF_IFSCOPE)),
                           addresses: addresses)
    }

    /// Explicit NET/full-mask selector; do not route through encodeLookup(),
    /// which deliberately maps a legacy maximum prefix to HOST/nil-mask.
    static func encodeExactFenceLookup(_ identity: VPNExactRouteFenceIdentity,
                                      sequence: Int32, pid: Int32) throws -> Data {
        try identity.validate()
        return try message(type: UInt8(RTM_GET), sequence: sequence, pid: pid, error: 0,
            index: 0, flags: 0, addresses: [
                (RTA_DST,address(identity.address.bytes,family: identity.address.family)),
                (RTA_NETMASK,netmask(identity.address))])
    }
    static func encodeExactFence(type: UInt8, sequence: Int32, pid: Int32,
                                 identity: VPNExactRouteFenceIdentity) throws -> Data {
        try identity.validate()
        guard type == UInt8(RTM_ADD) || type == UInt8(RTM_DELETE),
              (try? interfaceName(identity.interfaceIndex)) == identity.interfaceName else {
            throw VPNDarwinRouteError.invalidIdentity
        }
        return try message(type: type, sequence: sequence, pid: pid, error: 0,
            index: identity.interfaceIndex, flags: identity.flags & ~UInt32(RTF_PRCLONING), addresses: [
                (RTA_DST,address(identity.address.bytes,family: identity.address.family)),
                (RTA_GATEWAY,address(identity.gatewayBytes,family: identity.address.family)),
                (RTA_NETMASK,netmask(identity.address))])
    }

    /// Kept internal for deterministic fake-kernel tests; it performs no I/O.
    static func encodeReply(type: UInt8, sequence: Int32, pid: Int32, error: Int32,
                            identity: VPNOwnedRouteIdentity?, responseFlags: UInt32 = 0) throws -> Data {
        if let identity {
            var data = try encode(type: type, sequence: sequence, pid: pid, identity: identity)
            try mutateHeader(&data) {
                $0.rtm_errno = error
                // Synthetic KERNEL replies retain the exact expected flags;
                // encode() above intentionally produces request flags instead.
                $0.rtm_flags = Int32(bitPattern: identity.flags | responseFlags)
            }
            return data
        }
        return try message(type: type, sequence: sequence, pid: pid, error: error,
                           index: 0, flags: 0, addresses: [])
    }

    static func decode(_ data: Data) throws -> (type: UInt8, sequence: Int32, pid: Int32,
                                                 error: Int32, snapshot: VPNDarwinRouteSnapshot?) {
        let header = try identify(data)
        let length = Int(header.rtm_msglen)
        let body = data.subdata(in: headerSize..<length)
        let sockaddrs = try parseAddresses(body, mask: header.rtm_addrs)
        guard let destinationAddress = sockaddrs[Int(RTAX_DST)] else {
            return (header.rtm_type, header.rtm_seq, header.rtm_pid, header.rtm_errno, nil)
        }
        let destination = try prefix(destination: destinationAddress,
                                     mask: sockaddrs[Int(RTAX_NETMASK)], flags: header.rtm_flags)
        let index = UInt32(header.rtm_index)
        guard index > 0 else { throw VPNDarwinRouteError.malformedMessage }
        let name = try interfaceName(index)
        let family = try ipBytes(destinationAddress).family
        let routeFlags = UInt32(bitPattern: header.rtm_flags) & ~UInt32(RTF_DONE)
        if let destination, VPNManagedIPv6HostRoute.hasKernelShape(destination: destination,
            interfaceIndex: index, interfaceName: name, flags: routeFlags) {
            // A missing gateway is NOT a nil AF_LINK. New managed neighbor
            // profiles require a real direct link, never a numeric next hop.
            guard let link = sockaddrs[Int(RTAX_GATEWAY)], link.count >= 8,
                  Int32(link[1]) == AF_LINK, link[6] == 0, link[7] == 0 else {
                throw VPNDarwinRouteError.malformedMessage
            }
            // Our request has no LL address/selector; nd6_rtrequest's p2p path
            // skips link-layer resolution and adds LLINFO, not a MAC address.
            // https://github.com/apple-oss-distributions/xnu/blob/main/bsd/netinet6/nd6.c
        }
        let gateway = try gatewayBytes(sockaddrs[Int(RTAX_GATEWAY)], family: family,
                                       interfaceIndex: index, interfaceName: name)
        // RTM_GET returns the best route, including the default when the
        // requested exact route does not exist. A default is never an owned
        // route and must not enter VPNRoutePrefix (which forbids /0).
        guard let destination else {
            guard header.rtm_type == UInt8(RTM_GET), header.rtm_errno == 0 else {
                throw VPNDarwinRouteError.malformedMessage
            }
            return (header.rtm_type, header.rtm_seq, header.rtm_pid, header.rtm_errno, nil)
        }
        let snapshot = VPNDarwinRouteSnapshot(destination: destination, gatewayBytes: gateway,
            interfaceIndex: index, interfaceName: name, flags: routeFlags)
        return (header.rtm_type, header.rtm_seq, header.rtm_pid, header.rtm_errno, snapshot)
    }

    /// /0 deliberately has no owned snapshot; retain its actual family when
    /// ordinary lookup must distinguish a valid fallback from a contradiction.
    static func defaultLookupFamily(_ data: Data) throws -> VPNRouteAddressFamily? {
        let header = try identify(data)
        let addresses = try parseAddresses(data.subdata(in: headerSize..<Int(header.rtm_msglen)), mask: header.rtm_addrs)
        guard header.rtm_type == UInt8(RTM_GET), header.rtm_errno == 0,
              let destination = addresses[Int(RTAX_DST)],
              let mask = addresses[Int(RTAX_NETMASK)],
              header.rtm_flags & RTF_HOST == 0,
              try prefix(destination: destination, mask: mask, flags: header.rtm_flags) == nil else { return nil }
        return try ipBytes(destination).family
    }

    static func identify(_ data: Data) throws -> rt_msghdr {
        _ = try messageType(data)
        guard data.count >= headerSize, data.count <= maximumMessageBytes else {
            throw VPNDarwinRouteError.malformedMessage
        }
        let header = try readHeader(data)
        let length = Int(header.rtm_msglen)
        guard header.rtm_version == UInt8(RTM_VERSION), length >= headerSize,
              length == data.count, length <= maximumMessageBytes else {
            throw VPNDarwinRouteError.malformedMessage
        }
        return header
    }

    /// All routing-socket messages share only this four-byte prelude.
    /// Interface/address notifications use if*_msghdr, not rt_msghdr.
    static func messageType(_ data: Data) throws -> UInt8 {
        guard data.count >= 4, data.count <= maximumMessageBytes else {
            throw VPNDarwinRouteError.malformedMessage
        }
        let length = data.withUnsafeBytes { Int($0.loadUnaligned(as: UInt16.self)) }
        guard length == data.count, data[2] == UInt8(RTM_VERSION) else {
            throw VPNDarwinRouteError.malformedMessage
        }
        return data[3]
    }

    static func isInterfaceNotification(_ type: UInt8) -> Bool {
        [RTM_NEWADDR, RTM_DELADDR, RTM_IFINFO, RTM_IFINFO2,
         RTM_NEWMADDR, RTM_DELMADDR, RTM_NEWMADDR2].contains(Int32(type))
    }

    private static func message(type: UInt8, sequence: Int32, pid: Int32, error: Int32,
                                index: UInt32, flags: UInt32,
                                addresses: [(Int32, Data)]) throws -> Data {
        var mask: Int32 = 0, body = Data()
        for (bit, value) in addresses.sorted(by: { $0.0 < $1.0 }) {
            mask |= bit; body.append(value)
            let padding = aligned(value.count) - value.count
            if padding > 0 { body.append(Data(repeating: 0, count: padding)) }
        }
        let total = headerSize + body.count
        guard total <= maximumMessageBytes, total <= Int(UInt16.max), index <= UInt32(UInt16.max) else {
            throw VPNDarwinRouteError.invalidIdentity
        }
        var header = rt_msghdr()
        header.rtm_msglen = UInt16(total); header.rtm_version = UInt8(RTM_VERSION)
        header.rtm_type = type; header.rtm_index = UInt16(index)
        header.rtm_flags = Int32(bitPattern: flags); header.rtm_addrs = mask
        header.rtm_pid = pid; header.rtm_seq = sequence; header.rtm_errno = error
        var data = Data(bytes: &header, count: headerSize); data.append(body)
        return data
    }

    private static func address(_ bytes: [UInt8], family: VPNRouteAddressFamily) -> Data {
        if family == .ipv4 {
            var result = [UInt8](repeating: 0, count: MemoryLayout<sockaddr_in>.size)
            result[0] = UInt8(result.count); result[1] = UInt8(AF_INET)
            result.replaceSubrange(4..<8, with: bytes); return Data(result)
        }
        var result = [UInt8](repeating: 0, count: MemoryLayout<sockaddr_in6>.size)
        result[0] = UInt8(result.count); result[1] = UInt8(AF_INET6)
        result.replaceSubrange(8..<24, with: bytes); return Data(result)
    }

    private static func netmask(_ prefix: VPNRoutePrefix) -> Data {
        var bytes = [UInt8](repeating: 0, count: prefix.bytes.count)
        for bit in 0..<Int(prefix.prefixLength) { bytes[bit / 8] |= UInt8(0x80 >> (bit % 8)) }
        return address(bytes, family: prefix.family)
    }

    private static func link(index: UInt32, name: String) throws -> Data {
        let nameBytes = Array(name.utf8)
        guard index > 0, index <= UInt32(UInt16.max), !nameBytes.isEmpty, nameBytes.count < IFNAMSIZ,
              nameBytes.count <= 247 else { throw VPNDarwinRouteError.invalidIdentity }
        var bytes = [UInt8](repeating: 0, count: 8 + nameBytes.count)
        bytes[0] = UInt8(bytes.count); bytes[1] = UInt8(AF_LINK)
        let short = UInt16(index)
        bytes[2] = UInt8(short & 0xff); bytes[3] = UInt8(short >> 8)
        bytes[5] = UInt8(nameBytes.count); bytes.replaceSubrange(8..<bytes.count, with: nameBytes)
        return Data(bytes)
    }

    private static func parseAddresses(_ body: Data, mask: Int32) throws -> [Int: Data] {
        guard mask & ~Int32(0xff) == 0 else { throw VPNDarwinRouteError.malformedMessage }
        var result: [Int: Data] = [:], offset = 0
        for index in 0..<Int(RTAX_MAX) where mask & (1 << index) != 0 {
            guard offset + 2 <= body.count else { throw VPNDarwinRouteError.malformedMessage }
            let declared = Int(body[offset])
            // Darwin represents the default netmask with sa_len == 0,
            // occupying one aligned word. No other sockaddr may use it.
            guard declared != 0 || index == Int(RTAX_NETMASK) else {
                throw VPNDarwinRouteError.malformedMessage
            }
            let length = declared == 0 ? wordSize : declared
            guard length >= 2, length <= 255, offset + length <= body.count else {
                throw VPNDarwinRouteError.malformedMessage
            }
            let step = aligned(length)
            guard step >= length, offset + step <= body.count else {
                throw VPNDarwinRouteError.malformedMessage
            }
            result[index] = body.subdata(in: offset..<(offset + length)); offset += step
        }
        guard offset == body.count else { throw VPNDarwinRouteError.malformedMessage }
        return result
    }

    private static func prefix(destination: Data, mask: Data?, flags: Int32) throws -> VPNRoutePrefix? {
        let decoded = try ipBytes(destination)
        let maximum = decoded.family == .ipv4 ? 32 : 128
        let bits: Int
        if flags & RTF_HOST != 0 { bits = maximum }
        else {
            guard let mask else { throw VPNDarwinRouteError.malformedMessage }
            let parsed = try maskBytes(mask, family: decoded.family)
            var count = 0, sawZero = false
            for byte in parsed { for shift in (0..<8).reversed() {
                let set = byte & UInt8(1 << shift) != 0
                if set && sawZero { throw VPNDarwinRouteError.malformedMessage }
                if set { count += 1 } else { sawZero = true }
            }}
            if count == 0 {
                // Darwin may echo the queried host rather than a canonical
                // zero destination; the zero mask still identifies /0.
                return nil
            }
            bits = count
        }
        var network = decoded.bytes
        for bit in bits..<maximum { network[bit / 8] &= ~UInt8(0x80 >> (bit % 8)) }
        let base = try VPNRoutePrefix.format(network, family: decoded.family)
        let resource = try VPNResource(address: bits == maximum ? base : "\(base)/\(bits)")
        return try VPNRoutePrefix(resource: resource)
    }

    private static func ipBytes(_ data: Data) throws -> (family: VPNRouteAddressFamily, bytes: [UInt8]) {
        guard data.count >= 2 else { throw VPNDarwinRouteError.malformedMessage }
        switch Int32(data[1]) {
        case AF_INET:
            guard data.count >= 8 else { throw VPNDarwinRouteError.malformedMessage }
            return (.ipv4, Array(data[4..<8]))
        case AF_INET6:
            guard data.count >= 24 else { throw VPNDarwinRouteError.malformedMessage }
            return (.ipv6, Array(data[8..<24]))
        default: throw VPNDarwinRouteError.malformedMessage
        }
    }

    private static func maskBytes(_ data: Data, family: VPNRouteAddressFamily) throws -> [UInt8] {
        guard data.count >= 2 else { throw VPNDarwinRouteError.malformedMessage }
        if data[0] == 0 { return [UInt8](repeating: 0, count: family == .ipv4 ? 4 : 16) }
        let expectedFamily = family == .ipv4 ? AF_INET : AF_INET6
        // rn_addmask() canonicalizes skipped leading bytes (including this
        // opaque mask's sa_family byte) to ff. It is not an IP sockaddr family.
        // https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/net/radix.c
        guard data[1] == 0xff || Int32(data[1]) == AF_UNSPEC || Int32(data[1]) == expectedFamily else {
            throw VPNDarwinRouteError.malformedMessage
        }
        // Kernel netmasks may use AF_UNSPEC and/or omit trailing zero bytes.
        let size = family == .ipv4 ? 4 : 16
        let start = min(family == .ipv4 ? 4 : 8, data.count)
        var bytes = [UInt8](repeating: 0, count: size)
        let available = min(size, max(0, data.count - start))
        if available > 0 { bytes.replaceSubrange(0..<available, with: data[start..<(start + available)]) }
        return bytes
    }

    private static func gatewayBytes(_ data: Data?, family: VPNRouteAddressFamily,
                                     interfaceIndex: UInt32, interfaceName: String) throws -> [UInt8]? {
        guard let data else { return nil }
        guard data.count >= 2 else { throw VPNDarwinRouteError.malformedMessage }
        if Int32(data[1]) == AF_LINK {
            guard data.count >= 8 else { throw VPNDarwinRouteError.malformedMessage }
            let index = UInt32(data[2]) | UInt32(data[3]) << 8
            let nameLength = Int(data[5])
            guard index == interfaceIndex, nameLength <= data.count - 8 else {
                throw VPNDarwinRouteError.malformedMessage
            }
            if nameLength > 0 {
                guard String(bytes: data[8..<(8 + nameLength)], encoding: .utf8) == interfaceName else {
                    throw VPNDarwinRouteError.malformedMessage
                }
            }
            return nil
        }
        let value = try ipBytes(data)
        guard value.family == family else { throw VPNDarwinRouteError.malformedMessage }
        return value.bytes
    }

    private static func interfaceName(_ index: UInt32) throws -> String {
        var name = [CChar](repeating: 0, count: Int(IFNAMSIZ))
        guard if_indextoname(index, &name) != nil else { throw VPNDarwinRouteError.malformedMessage }
        return String(cString: name)
    }

    private static func aligned(_ count: Int) -> Int { (count + wordSize - 1) & ~(wordSize - 1) }

    private static func readHeader(_ data: Data) throws -> rt_msghdr {
        guard data.count >= headerSize else { throw VPNDarwinRouteError.malformedMessage }
        var header = rt_msghdr()
        _ = withUnsafeMutableBytes(of: &header) { data.copyBytes(to: $0, from: 0..<headerSize) }
        return header
    }

    private static func mutateHeader(_ data: inout Data,
                                     _ mutation: (inout rt_msghdr) -> Void) throws {
        var header = try readHeader(data); mutation(&header)
        withUnsafeBytes(of: &header) { data.replaceSubrange(0..<headerSize, with: $0) }
    }
}

/// Routing replies are broadcast to other PF_ROUTE sockets, and XNU sets
/// rtm_pid to the actual sender PID. Default controllers therefore need one
/// sequence namespace across sockets AND controller types, not one per FD.
/// https://github.com/apple-oss-distributions/xnu/blob/main/bsd/net/rtsock.c
final class VPNDarwinRouteSequenceAllocator {
    static let process = VPNDarwinRouteSequenceAllocator()
    private let lock = NSLock()
    private var sequence: Int32

    init(initialSequence: Int32 = 0) { sequence = max(0, initialSequence) }

    func next() -> Int32? {
        lock.lock(); defer { lock.unlock() }
        guard sequence < Int32.max else { return nil }
        sequence += 1
        return sequence
    }
}

final class VPNDarwinRouteSocket {
    private let transport: VPNRouteSocketTransport
    private let pid: Int32
    private let timeout: TimeInterval
    private let lock = NSLock()
    private let sequences: VPNDarwinRouteSequenceAllocator

    init(transport: VPNRouteSocketTransport, pid: Int32? = nil,
        initialSequence: Int32? = nil, timeout: TimeInterval = 2) {
        self.transport = transport; self.pid = pid.map { $0 > 0 ? $0 : getpid() } ?? getpid()
        // Explicit correlation inputs retain an isolated deterministic namespace.
        // No inference from pid equality: an explicitly supplied own PID is local too.
        sequences = pid == nil && initialSequence == nil ? .process
            : VPNDarwinRouteSequenceAllocator(initialSequence: initialSequence ?? 0)
        self.timeout = timeout.isFinite ? max(0.01, min(timeout, 30)) : 2
    }

    static func production(timeout: TimeInterval = 2) throws -> VPNDarwinRouteSocket {
        try VPNDarwinRouteSocket(transport: VPNDarwinRouteSocketTransport(), timeout: timeout)
    }

    func lookupExact(_ destination: VPNRoutePrefix) throws -> VPNDarwinRouteSnapshot? {
        try lookupExact(VPNRouteLookupKey(destination: destination, interfaceScope: nil))
    }

    func lookupExact(_ key: VPNRouteLookupKey) throws -> VPNDarwinRouteSnapshot? {
        try VPNFlowDiagnostics.run(.kernelLookup) {
            try serialized { deadline in try lookup(key, deadline: deadline) }
        }
    }

    func add(_ identity: VPNOwnedRouteIdentity) throws -> VPNDarwinRouteMutationResult {
        try VPNFlowDiagnostics.run(.kernelAdd) { try addLogged(identity) }
    }
    private func addLogged(_ identity: VPNOwnedRouteIdentity) throws -> VPNDarwinRouteMutationResult {
        try serialized { deadline in
            try identity.validate()
            if let existing = try lookup(identity.lookupKey, deadline: deadline) {
                guard existing.matches(identity) else { throw VPNDarwinRouteError.preexistingNonIdentical }
                return .alreadyPresent
            }
            let sequence = try nextSequence()
            let request = try VPNDarwinRouteCodec.encode(type: UInt8(RTM_ADD), sequence: sequence,
                                                         pid: pid, identity: identity)
            do { _ = try transact(request, sequence: sequence, type: UInt8(RTM_ADD), deadline: deadline) }
            catch VPNDarwinRouteError.kernel(let code) where code == EEXIST {
                guard let raced = try lookup(identity.lookupKey, deadline: deadline),
                      raced.matches(identity) else { throw VPNDarwinRouteError.preexistingNonIdentical }
                return .alreadyPresent
            }
            guard let installed = try lookup(identity.lookupKey, deadline: deadline),
                  installed.matches(identity) else { throw VPNDarwinRouteError.verificationFailed }
            return .installed
        }
    }

    func delete(_ identity: VPNOwnedRouteIdentity) throws -> VPNDarwinRouteMutationResult {
        try VPNFlowDiagnostics.run(.kernelDelete) { try deleteLogged(identity) }
    }
    private func deleteLogged(_ identity: VPNOwnedRouteIdentity) throws -> VPNDarwinRouteMutationResult {
        try serialized { deadline in
            try identity.validate()
            guard let existing = try lookup(identity.lookupKey, deadline: deadline),
                  existing.matches(identity) else { throw VPNDarwinRouteError.missingOrForeign }
            let sequence = try nextSequence()
            let request = try VPNDarwinRouteCodec.encode(type: UInt8(RTM_DELETE), sequence: sequence,
                                                         pid: pid, identity: identity)
            _ = try transact(request, sequence: sequence, type: UInt8(RTM_DELETE), deadline: deadline)
            guard try lookup(identity.lookupKey, deadline: deadline) == nil else {
                throw VPNDarwinRouteError.verificationFailed
            }
            return .removed
        }
    }

    /// A resource HOST and its NET/full-mask deny have different radix keys.
    /// Keep the deny verified throughout activation/removal. The caller owns
    /// both the persistent fence receipt and the active-route journal intent,
    /// and holds its lifecycle lease through this operation. No adoption or
    /// implicit cleanup after an indeterminate native write is performed here.
    func installFencedHost(_ identity: VPNOwnedRouteIdentity, fence: VPNExactRouteFenceIdentity,
                           deadline: DispatchTime, checkCurrent: () throws -> Void) throws {
        try mutateFencedHost(identity,fence:fence,install:true,deadline:deadline,checkCurrent:checkCurrent)
    }
    func deleteFencedHost(_ identity: VPNOwnedRouteIdentity, fence: VPNExactRouteFenceIdentity,
                          deadline: DispatchTime, checkCurrent: () throws -> Void) throws {
        try mutateFencedHost(identity,fence:fence,install:false,deadline:deadline,checkCurrent:checkCurrent)
    }
    /// Nil means the verified NET deny is selected instead of a HOST. Other
    /// same-key entries are returned for exact comparison, never hidden.
    func lookupFencedHost(_ identity: VPNOwnedRouteIdentity, fence: VPNExactRouteFenceIdentity,
                          deadline: DispatchTime) throws -> VPNDarwinRouteSnapshot? {
        try serialized(until:deadline) { end in
            try validateFencedHost(identity,fence:fence)
            guard let deny = try exactFenceLookup(fence,deadline:end), fence.matches(deny) else {
                throw VPNDarwinRouteError.missingOrForeign
            }
            let observed = try fencedHostLookup(identity,deadline:end)
            guard let observed, observed.destination == identity.destination else {
                throw VPNDarwinRouteError.verificationFailed
            }
            guard let after = try exactFenceLookup(fence,deadline:end), fence.matches(after) else {
                throw VPNDarwinRouteError.missingOrForeign
            }
            return fence.matches(observed) ? nil : observed
        }
    }
    private func validateFencedHost(_ identity: VPNOwnedRouteIdentity, fence: VPNExactRouteFenceIdentity) throws {
        try identity.validate(); try fence.validate()
        let planned = VPNPlannedRoute(role:identity.role,destination:identity.destination,
            physicalGatewayBytes:identity.gatewayBytes,interfaceIndex:identity.interfaceIndex,
            interfaceName:identity.interfaceName,interfaceScope:identity.interfaceScope)
        try planned.validate()
        guard identity.role == .resource, identity.destination == fence.address,
              identity.interfaceScope == nil, identity.gatewayBytes == nil,
              identity.flags == VPNManagedIPv6HostRoute.flags(for:planned) else {
            throw VPNDarwinRouteError.invalidIdentity
        }
    }
    private func fencedHostLookup(_ identity: VPNOwnedRouteIdentity, deadline: DispatchTime) throws -> VPNDarwinRouteSnapshot? {
        let sequence = try nextSequence()
        let request = try VPNDarwinRouteCodec.encodeLookup(key:identity.lookupKey,sequence:sequence,pid:pid)
        return try exactFenceTransact(request,sequence:sequence,type:UInt8(RTM_GET),
                                       deadline:deadline,family:identity.destination.family)
    }
    private func mutateFencedHost(_ identity: VPNOwnedRouteIdentity, fence: VPNExactRouteFenceIdentity,
                                  install: Bool, deadline: DispatchTime,
                                  checkCurrent: () throws -> Void) throws {
        try serialized(until:deadline) { end in
            try validateFencedHost(identity,fence:fence)
            func current() throws {
                guard DispatchTime.now().uptimeNanoseconds < end.uptimeNanoseconds else { throw VPNDarwinRouteError.timeout }
                try checkCurrent()
                guard DispatchTime.now().uptimeNanoseconds < end.uptimeNanoseconds else { throw VPNDarwinRouteError.timeout }
            }
            func protected() throws {
                try current()
                guard let observed = try exactFenceLookup(fence,deadline:end), fence.matches(observed) else {
                    throw VPNDarwinRouteError.missingOrForeign
                }
                try current()
            }
            func host() throws -> VPNDarwinRouteSnapshot? {
                // HOST GET may return the same-prefix NET deny. Validate the
                // global live reply, then distinguish the two radix key shapes.
                return try fencedHostLookup(identity,deadline:end)
            }
            try protected()
            let before = try host(); try current()
            if install {
                guard let before, fence.matches(before) else { throw VPNDarwinRouteError.preexistingNonIdentical }
            } else {
                guard let before, before.matches(identity) else { throw VPNDarwinRouteError.missingOrForeign }
            }
            try protected()
            let sequence = try nextSequence(), type = UInt8(install ? RTM_ADD : RTM_DELETE)
            let request = try VPNDarwinRouteCodec.encode(type:type,sequence:sequence,pid:pid,identity:identity)
            try current()
            _ = try exactFenceTransact(request,sequence:sequence,type:type,deadline:end)
            try protected()
            let after = try host(); try current()
            guard let after, install ? after.matches(identity) : fence.matches(after) else {
                throw VPNDarwinRouteError.verificationFailed
            }
            try protected()
        }
    }

    /// Low-level native boundary only. A caller must own a durable add-intent
    /// before installation and an explicit release-intent before deletion.
    /// There is no implicit adoption, TTL cleanup or production DNS wiring here.
    func lookupExactFence(_ identity: VPNExactRouteFenceIdentity,
                          deadline: DispatchTime) throws -> VPNDarwinRouteSnapshot? {
        try serialized(until: deadline) { try exactFenceLookup(identity, deadline: $0) }
    }
    func installExactFence(_ identity: VPNExactRouteFenceIdentity, deadline: DispatchTime) throws {
        try serialized(until: deadline) { end in
            // Even an identical preexisting entry is NOT ours. Crash recovery
            // must separately prove its retained intent before using lookup.
            guard try exactFenceLookup(identity, deadline: end) == nil else {
                throw VPNDarwinRouteError.preexistingNonIdentical
            }
            let sequence = try nextSequence()
            let request = try VPNDarwinRouteCodec.encodeExactFence(type: UInt8(RTM_ADD),
                sequence: sequence, pid: pid, identity: identity)
            _ = try exactFenceTransact(request, sequence: sequence, type: UInt8(RTM_ADD), deadline: end)
            guard let actual = try exactFenceLookup(identity, deadline: end), identity.matches(actual) else {
                throw VPNDarwinRouteError.verificationFailed
            }
        }
    }
    func deleteExactFence(_ identity: VPNExactRouteFenceIdentity, deadline: DispatchTime) throws {
        try serialized(until: deadline) { end in
            guard let actual = try exactFenceLookup(identity, deadline: end), identity.matches(actual) else {
                throw VPNDarwinRouteError.missingOrForeign
            }
            let sequence = try nextSequence()
            let request = try VPNDarwinRouteCodec.encodeExactFence(type: UInt8(RTM_DELETE),
                sequence: sequence, pid: pid, identity: identity)
            _ = try exactFenceTransact(request, sequence: sequence, type: UInt8(RTM_DELETE), deadline: end)
            guard try exactFenceLookup(identity, deadline: end) == nil else {
                throw VPNDarwinRouteError.verificationFailed
            }
        }
    }
    private func exactFenceLookup(_ identity: VPNExactRouteFenceIdentity,
                                  deadline: DispatchTime) throws -> VPNDarwinRouteSnapshot? {
        let sequence = try nextSequence()
        let request = try VPNDarwinRouteCodec.encodeExactFenceLookup(identity, sequence: sequence, pid: pid)
        do {
            guard let actual = try exactFenceTransact(request, sequence: sequence, type: UInt8(RTM_GET),
                deadline: deadline, family: identity.address.family) else { return nil }
            if actual.destination == identity.address && actual.flags & UInt32(RTF_HOST) == 0 { return actual }
            // A validated HOST or broader same-family fallback is a miss for
            // NET/full-mask only. Never mistake an unrelated/contradictory IP.
            guard actual.destination.family == identity.address.family,
                  actual.destination.contains(host: identity.address) else {
                throw VPNDarwinRouteError.verificationFailed
            }
            return nil
        } catch VPNDarwinRouteError.kernel(let code) where code == ESRCH || code == ENOENT { return nil }
    }
    private func exactFenceTransact(_ request: Data, sequence: Int32, type: UInt8,
                                    deadline: DispatchTime,
                                    family: VPNRouteAddressFamily? = nil) throws -> VPNDarwinRouteSnapshot? {
        guard DispatchTime.now().uptimeNanoseconds < deadline.uptimeNanoseconds else { throw VPNDarwinRouteError.timeout }
        let value = try transact(request,sequence: sequence,type: type,deadline: deadline,
                                 ordinaryLookupFamily: family, requireGlobalReply: type == UInt8(RTM_GET),
                                 headerOnlyReply: type != UInt8(RTM_GET))
        // A late reply after a possible mutation is indeterminate, not success.
        guard DispatchTime.now().uptimeNanoseconds < deadline.uptimeNanoseconds else { throw VPNDarwinRouteError.timeout }
        return value
    }
    private func serialized<T>(until original: DispatchTime, _ body: (DispatchTime) throws -> T) throws -> T {
        let began = DispatchTime.now().uptimeNanoseconds, budget = UInt64(timeout * 1_000_000_000)
        guard began <= UInt64.max - budget else { throw VPNDarwinRouteError.timeout }
        let end = DispatchTime(uptimeNanoseconds:min(original.uptimeNanoseconds,began+budget))
        lock.lock(); defer { lock.unlock() }
        guard DispatchTime.now().uptimeNanoseconds < end.uptimeNanoseconds else { throw VPNDarwinRouteError.timeout }
        return try body(end)
    }

    private func lookup(_ key: VPNRouteLookupKey,
                        deadline: DispatchTime) throws -> VPNDarwinRouteSnapshot? {
        let sequence = try nextSequence()
        let request = try VPNDarwinRouteCodec.encodeLookup(key: key,
                                                           sequence: sequence, pid: pid)
        do {
            let response = try transact(request, sequence: sequence, type: UInt8(RTM_GET),
                                        deadline: deadline,
                                        ordinaryLookupFamily: key.interfaceScope == nil ? key.destination.family : nil)
            // Ordinary host queries may return broader fallbacks; CIDR queries
            // carry a netmask. Contradictory replies never prove exact absence.
            // Scoped custody additionally requires the exact table scope: GET
            // can return an unscoped same-interface fallback when absent.
            // https://github.com/apple-oss-distributions/xnu/blob/main/bsd/net/route.c
            guard let scope = key.interfaceScope else {
                guard let response else { return nil } // Validated same-family default fallback.
                if response.destination == key.destination { return response }
                guard response.destination.family == key.destination.family,
                      response.destination.prefixLength < key.destination.prefixLength,
                      response.destination.overlaps(key.destination) else {
                    throw VPNDarwinRouteError.verificationFailed
                }
                return nil
            }
            // Success without a snapshot includes /0, whose family/interface
            // metadata this legacy decoder does not retain. That cannot prove
            // scoped absence. Neither can a wrong-interface/scoped reply.
            guard let response,
                  response.interfaceIndex == scope.interfaceIndex,
                  response.interfaceName == scope.interfaceName,
                  response.destination.family == key.destination.family,
                  response.destination.contains(host: key.destination),
                  response.flags & UInt32(RTF_UP) != 0,
                  response.flags & UInt32(RTF_REJECT | RTF_BLACKHOLE | RTF_DEAD | RTF_CONDEMNED) == 0,
                  (response.gatewayBytes != nil) == (response.flags & UInt32(RTF_GATEWAY) != 0) else {
                throw VPNDarwinRouteError.verificationFailed
            }
            if response.destination == key.destination {
                // The kernel may fall back to an unscoped route on this SAME
                // interface. It is not the requested scoped table entry.
                return response.flags & UInt32(RTF_IFSCOPE) == 0 ? nil : response
            }
            // Only a validated, strictly broader containing route on the same
            // interface proves no exact scoped host entry won the lookup.
            guard response.destination.prefixLength < key.destination.prefixLength else {
                throw VPNDarwinRouteError.verificationFailed
            }
            return nil
        } catch VPNDarwinRouteError.kernel(let code) where code == ESRCH || code == ENOENT {
            return nil
        }
    }

    private func transact(_ request: Data, sequence: Int32, type: UInt8,
                          deadline: DispatchTime,
                          ordinaryLookupFamily: VPNRouteAddressFamily? = nil,
                          requireGlobalReply: Bool = false,
                          headerOnlyReply: Bool = false) throws -> VPNDarwinRouteSnapshot? {
        do { try transport.send(request, deadline: deadline) }
        catch VPNRouteSocketTransportError.posix(let code) where type == UInt8(RTM_GET) && code == ESRCH {
            // Ordinary public RTM_GET misses can fail write() synchronously:
            // route_output -> senderr(ESRCH) -> flush -> return error.
            // https://github.com/apple-oss-distributions/xnu/blob/main/bsd/net/rtsock.c
            // ONLY this exact send-time result is kernel absence. Never apply
            // it to read errors, other errno values or ADD/DELETE uncertainty.
            // A queued old error is skipped by the existing PID/sequence gate;
            // no drain/wait is invented. Backlogs still fail at the 128 cap.
            throw VPNDarwinRouteError.kernel(ESRCH)
        }
        catch { throw translate(error) }
        for _ in 0..<128 {
            let data: Data
            do { data = try transport.receive(maximumBytes: VPNDarwinRouteCodec.maximumMessageBytes,
                                              deadline: deadline) }
            catch { throw translate(error) }
            let messageType = try VPNDarwinRouteCodec.messageType(data)
            if VPNDarwinRouteCodec.isInterfaceNotification(messageType) {
                VPNFlowDiagnostics.notificationSkipped(messageType)
                continue
            }
            let header: rt_msghdr
            do { header = try VPNDarwinRouteCodec.identify(data) }
            catch { throw VPNDarwinRouteError.malformedMessage }
            guard header.rtm_seq == sequence, header.rtm_pid == pid else { continue }
            // ADD acknowledges the request; it is not a live route snapshot.
            // Exact-fence callers MUST issue their separate GET verification.
            // rtsock.c route_output(): ADD does not take the GET report path.
            if headerOnlyReply {
                guard header.rtm_type == type else { throw VPNDarwinRouteError.malformedMessage }
                guard header.rtm_errno == 0 else { throw VPNDarwinRouteError.kernel(header.rtm_errno) }
                return nil
            }
            // Exact-fence GET errors can echo our request with index zero.
            // A correlated kernel errno needs no fabricated interface snapshot.
            // Keep legacy response decoding unchanged for all other callers.
            if requireGlobalReply && header.rtm_errno != 0 {
                guard header.rtm_type == type else { throw VPNDarwinRouteError.malformedMessage }
                throw VPNDarwinRouteError.kernel(header.rtm_errno)
            }
            let response: (type: UInt8, sequence: Int32, pid: Int32, error: Int32,
                           snapshot: VPNDarwinRouteSnapshot?)
            do { response = try VPNDarwinRouteCodec.decode(data) }
            catch { throw VPNDarwinRouteError.malformedMessage }
            guard response.type == type else { throw VPNDarwinRouteError.malformedMessage }
            guard response.error == 0 else { throw VPNDarwinRouteError.kernel(response.error) }
            if requireGlobalReply {
                guard header.rtm_flags & RTF_IFSCOPE == 0, header.rtm_flags & RTF_UP != 0 else {
                    throw VPNDarwinRouteError.verificationFailed
                }
            }
            if let expected = ordinaryLookupFamily {
                let actual = try response.snapshot?.destination.family ?? VPNDarwinRouteCodec.defaultLookupFamily(data)
                guard actual == expected else { throw VPNDarwinRouteError.verificationFailed }
            }
            return response.snapshot
        }
        throw VPNDarwinRouteError.responseLimit
    }

    private func serialized<T>(_ body: (DispatchTime) throws -> T) throws -> T {
        lock.lock(); defer { lock.unlock() }
        let nanoseconds = UInt64(timeout * 1_000_000_000)
        return try body(DispatchTime(uptimeNanoseconds: DispatchTime.now().uptimeNanoseconds
                                    &+ nanoseconds))
    }

    private func nextSequence() throws -> Int32 {
        guard let sequence = sequences.next() else { throw VPNDarwinRouteError.responseLimit }
        return sequence
    }

    private func translate(_ error: Error) -> VPNDarwinRouteError {
        switch error {
        case VPNRouteSocketTransportError.timeout: return .timeout
        case VPNRouteSocketTransportError.closed: return .closed
        case VPNRouteSocketTransportError.posix(let code): return .transport(code)
        default: return .closed
        }
    }
}
