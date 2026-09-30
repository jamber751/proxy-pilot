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

/// The production transport opens PF_ROUTE only when explicitly initialized.
/// Merely constructing the adapter around a fake transport cannot touch networking.
final class VPNDarwinRouteSocketTransport: VPNRouteSocketTransport {
    private var descriptor: Int32

    init() throws {
        descriptor = socket(PF_ROUTE, SOCK_RAW, AF_UNSPEC)
        guard descriptor >= 0 else { throw VPNRouteSocketTransportError.posix(errno) }
        let flags = fcntl(descriptor, F_GETFL)
        guard flags >= 0, fcntl(descriptor, F_SETFD, FD_CLOEXEC) == 0,
              fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) == 0 else {
            let saved = errno; close(descriptor); descriptor = -1
            throw VPNRouteSocketTransportError.posix(saved)
        }
    }

    deinit { if descriptor >= 0 { close(descriptor) } }

    func send(_ message: Data, deadline: DispatchTime) throws {
        let written: Int = try message.withUnsafeBytes { bytes in
            while true {
                try wait(events: Int16(POLLOUT), deadline: deadline)
                let result = Darwin.write(descriptor, bytes.baseAddress!, bytes.count)
                if result < 0 && errno == EINTR { continue }
                if result < 0 && (errno == EAGAIN || errno == EWOULDBLOCK) { continue }
                if result < 0 { throw VPNRouteSocketTransportError.posix(errno) }
                return result
            }
        }
        guard written == message.count else { throw VPNRouteSocketTransportError.closed }
    }

    func receive(maximumBytes: Int, deadline: DispatchTime) throws -> Data {
        var bytes = [UInt8](repeating: 0, count: maximumBytes)
        while true {
            try wait(events: Int16(POLLIN), deadline: deadline)
            let count = Darwin.read(descriptor, &bytes, bytes.count)
            if count < 0 && errno == EINTR { continue }
            if count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK) { continue }
            if count < 0 { throw VPNRouteSocketTransportError.posix(errno) }
            guard count > 0 else { throw VPNRouteSocketTransportError.closed }
            return Data(bytes.prefix(count))
        }
    }

    private func wait(events: Int16, deadline: DispatchTime) throws {
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

struct VPNDarwinRouteSnapshot: Equatable {
    let destination: VPNRoutePrefix
    let gatewayBytes: [UInt8]?
    let interfaceIndex: UInt32
    let interfaceName: String
    let flags: UInt32

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
        let required = UInt32(RTF_UP | RTF_STATIC)
        let forbidden = UInt32(RTF_DYNAMIC | RTF_MODIFIED | RTF_DONE | RTF_LLINFO
            | RTF_WASCLONED | RTF_LOCAL | RTF_BROADCAST | RTF_MULTICAST | RTF_CONDEMNED | RTF_DEAD)
        guard identity.flags & required == required, identity.flags & forbidden == 0,
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
                           index: identity.interfaceIndex, flags: identity.flags,
                           addresses: addresses)
    }

    static func encodeLookup(destination: VPNRoutePrefix, sequence: Int32, pid: Int32) throws -> Data {
        try destination.validate()
        let host = Int(destination.prefixLength) == destination.bytes.count * 8
        var addresses: [(Int32, Data)] = [(RTA_DST, address(destination.bytes,
                                                             family: destination.family))]
        if !host { addresses.append((RTA_NETMASK, netmask(destination))) }
        return try message(type: UInt8(RTM_GET), sequence: sequence, pid: pid, error: 0,
                           index: 0, flags: host ? UInt32(RTF_HOST) : 0, addresses: addresses)
    }

    /// Kept internal for deterministic fake-kernel tests; it performs no I/O.
    static func encodeReply(type: UInt8, sequence: Int32, pid: Int32, error: Int32,
                            identity: VPNOwnedRouteIdentity?, responseFlags: UInt32 = 0) throws -> Data {
        if let identity {
            var data = try encode(type: type, sequence: sequence, pid: pid, identity: identity)
            try mutateHeader(&data) {
                $0.rtm_errno = error
                $0.rtm_flags |= Int32(bitPattern: responseFlags)
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
        let routeFlags = UInt32(bitPattern: header.rtm_flags) & ~UInt32(RTF_DONE)
        let snapshot = VPNDarwinRouteSnapshot(destination: destination, gatewayBytes: gateway,
            interfaceIndex: index, interfaceName: name, flags: routeFlags)
        return (header.rtm_type, header.rtm_seq, header.rtm_pid, header.rtm_errno, snapshot)
    }

    static func identify(_ data: Data) throws -> rt_msghdr {
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
        guard Int32(data[1]) == AF_UNSPEC || Int32(data[1]) == expectedFamily else {
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

final class VPNDarwinRouteSocket {
    private let transport: VPNRouteSocketTransport
    private let pid: Int32
    private let timeout: TimeInterval
    private let lock = NSLock()
    private var sequence: Int32

    init(transport: VPNRouteSocketTransport, pid: Int32 = getpid(),
        initialSequence: Int32 = 0, timeout: TimeInterval = 2) {
        self.transport = transport; self.pid = pid > 0 ? pid : getpid()
        sequence = max(0, initialSequence)
        self.timeout = timeout.isFinite ? max(0.01, min(timeout, 30)) : 2
    }

    static func production(timeout: TimeInterval = 2) throws -> VPNDarwinRouteSocket {
        try VPNDarwinRouteSocket(transport: VPNDarwinRouteSocketTransport(), timeout: timeout)
    }

    func lookupExact(_ destination: VPNRoutePrefix) throws -> VPNDarwinRouteSnapshot? {
        try VPNFlowDiagnostics.run(.kernelLookup) {
            try serialized { deadline in try lookup(destination, deadline: deadline) }
        }
    }

    func add(_ identity: VPNOwnedRouteIdentity) throws -> VPNDarwinRouteMutationResult {
        try VPNFlowDiagnostics.run(.kernelAdd) { try addLogged(identity) }
    }
    private func addLogged(_ identity: VPNOwnedRouteIdentity) throws -> VPNDarwinRouteMutationResult {
        try serialized { deadline in
            try identity.validate()
            if let existing = try lookup(identity.destination, deadline: deadline) {
                guard existing.matches(identity) else { throw VPNDarwinRouteError.preexistingNonIdentical }
                return .alreadyPresent
            }
            let sequence = try nextSequence()
            let request = try VPNDarwinRouteCodec.encode(type: UInt8(RTM_ADD), sequence: sequence,
                                                         pid: pid, identity: identity)
            do { _ = try transact(request, sequence: sequence, type: UInt8(RTM_ADD), deadline: deadline) }
            catch VPNDarwinRouteError.kernel(let code) where code == EEXIST {
                guard let raced = try lookup(identity.destination, deadline: deadline),
                      raced.matches(identity) else { throw VPNDarwinRouteError.preexistingNonIdentical }
                return .alreadyPresent
            }
            guard let installed = try lookup(identity.destination, deadline: deadline),
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
            guard let existing = try lookup(identity.destination, deadline: deadline),
                  existing.matches(identity) else { throw VPNDarwinRouteError.missingOrForeign }
            let sequence = try nextSequence()
            let request = try VPNDarwinRouteCodec.encode(type: UInt8(RTM_DELETE), sequence: sequence,
                                                         pid: pid, identity: identity)
            _ = try transact(request, sequence: sequence, type: UInt8(RTM_DELETE), deadline: deadline)
            guard try lookup(identity.destination, deadline: deadline) == nil else {
                throw VPNDarwinRouteError.verificationFailed
            }
            return .removed
        }
    }

    private func lookup(_ destination: VPNRoutePrefix,
                        deadline: DispatchTime) throws -> VPNDarwinRouteSnapshot? {
        let sequence = try nextSequence()
        let request = try VPNDarwinRouteCodec.encodeLookup(destination: destination,
                                                           sequence: sequence, pid: pid)
        do {
            let response = try transact(request, sequence: sequence, type: UInt8(RTM_GET),
                                        deadline: deadline)
            guard response?.destination == destination else { return nil }
            return response
        } catch VPNDarwinRouteError.kernel(let code) where code == ESRCH || code == ENOENT {
            return nil
        }
    }

    private func transact(_ request: Data, sequence: Int32, type: UInt8,
                          deadline: DispatchTime) throws -> VPNDarwinRouteSnapshot? {
        do { try transport.send(request, deadline: deadline) }
        catch { throw translate(error) }
        for _ in 0..<128 {
            let data: Data
            do { data = try transport.receive(maximumBytes: VPNDarwinRouteCodec.maximumMessageBytes,
                                              deadline: deadline) }
            catch { throw translate(error) }
            let header: rt_msghdr
            do { header = try VPNDarwinRouteCodec.identify(data) }
            catch { throw VPNDarwinRouteError.malformedMessage }
            guard header.rtm_seq == sequence, header.rtm_pid == pid else { continue }
            let response: (type: UInt8, sequence: Int32, pid: Int32, error: Int32,
                           snapshot: VPNDarwinRouteSnapshot?)
            do { response = try VPNDarwinRouteCodec.decode(data) }
            catch { throw VPNDarwinRouteError.malformedMessage }
            guard response.type == type else { throw VPNDarwinRouteError.malformedMessage }
            guard response.error == 0 else { throw VPNDarwinRouteError.kernel(response.error) }
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
        guard sequence < Int32.max else { throw VPNDarwinRouteError.responseLimit }
        sequence += 1; return sequence
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
