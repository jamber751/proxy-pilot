import Darwin
import Foundation

enum VPNPeerRouteEvidenceError: VPNFlowDiagnosticError, Equatable {
    case invalidPeer
    case malformedMessage
    case responseLimit
    case timeout
    case transport(Int32)
    case closed
    case kernel(Int32)
    case unusableRoute
    var vpnFlowFailureCode: VPNFlowFailureCode {
        switch self {
        case .invalidPeer: return .invalidPeer
        case .malformedMessage: return .malformedMessage
        case .responseLimit: return .responseLimit
        case .timeout: return .timeout
        case .transport: return .transport
        case .closed: return .closed
        case .kernel: return .kernel
        case .unusableRoute: return .unusableRoute
        }
    }
    var vpnFlowErrorNumber: Int32 {
        switch self { case .kernel(let code), .transport(let code): return code; default: return 0 }
    }
}

/// Resolves the kernel's current best route to the OpenVPN transport peer.
/// This type sends RTM_GET only. It never installs or removes a route.
final class VPNPeerRouteEvidenceResolver {
    private let transport: VPNRouteSocketTransport
    private let pid: Int32
    private let timeout: TimeInterval
    private let lock = NSLock()
    private var sequence: Int32

    init(transport: VPNRouteSocketTransport, pid: Int32 = getpid(),
         initialSequence: Int32 = 0, timeout: TimeInterval = 2) {
        self.transport = transport
        self.pid = pid > 0 ? pid : getpid()
        sequence = max(0, initialSequence)
        self.timeout = timeout.isFinite ? max(0.01, min(timeout, 30)) : 2
    }

    static func production(timeout: TimeInterval = 2) throws -> VPNPeerRouteEvidenceResolver {
        try VPNPeerRouteEvidenceResolver(transport: VPNDarwinRouteSocketTransport(), timeout: timeout)
    }

    func resolve(peer: OpenVPNIPAddress) throws -> VPNRoutePeerEvidence {
        lock.lock()
        defer { lock.unlock() }
        return try VPNFlowDiagnostics.run(.peerLookup) { try resolveLogged(peer: peer) }
    }
    private func resolveLogged(peer: OpenVPNIPAddress) throws -> VPNRoutePeerEvidence {
        guard Self.validPeer(peer) else { throw VPNPeerRouteEvidenceError.invalidPeer }
        guard sequence < Int32.max else { throw VPNPeerRouteEvidenceError.responseLimit }
        sequence += 1
        let family: VPNRouteAddressFamily = peer.family == .ipv4 ? .ipv4 : .ipv6
        let destination: VPNRoutePrefix
        do { destination = try VPNRoutePrefix(hostBytes: peer.bytes, family: family) }
        catch { throw VPNPeerRouteEvidenceError.invalidPeer }
        let request: Data
        do {
            request = try VPNDarwinRouteCodec.encodeLookup(destination: destination,
                                                           sequence: sequence, pid: pid)
        } catch { throw VPNPeerRouteEvidenceError.invalidPeer }
        let deadline = DispatchTime(uptimeNanoseconds: DispatchTime.now().uptimeNanoseconds
            &+ UInt64(timeout * 1_000_000_000))
        do { try transport.send(request, deadline: deadline) }
        catch { throw translate(error) }

        for _ in 0..<128 {
            let data: Data
            do {
                data = try transport.receive(maximumBytes: VPNDarwinRouteCodec.maximumMessageBytes,
                                             deadline: deadline)
            } catch { throw translate(error) }
            let messageType: UInt8
            do { messageType = try VPNDarwinRouteCodec.messageType(data) }
            catch { throw VPNPeerRouteEvidenceError.malformedMessage }
            if VPNDarwinRouteCodec.isInterfaceNotification(messageType) {
                VPNFlowDiagnostics.notificationSkipped(messageType)
                continue
            }
            let header: rt_msghdr
            do { header = try VPNDarwinRouteCodec.identify(data) }
            catch { throw VPNPeerRouteEvidenceError.malformedMessage }
            guard header.rtm_seq == sequence, header.rtm_pid == pid else { continue }
            guard header.rtm_type == UInt8(RTM_GET) else {
                throw VPNPeerRouteEvidenceError.malformedMessage
            }
            guard header.rtm_errno == 0 else {
                throw VPNPeerRouteEvidenceError.kernel(header.rtm_errno)
            }
            return try VPNBestRouteReplyDecoder.decode(data, peer: peer)
        }
        throw VPNPeerRouteEvidenceError.responseLimit
    }

    private static func validPeer(_ peer: OpenVPNIPAddress) -> Bool {
        if peer.family == .ipv4 {
            return peer.bytes.count == 4 && peer.bytes[0] != 0 && peer.bytes[0] != 127
                && peer.bytes[0] < 224 && !(peer.bytes[0] == 169 && peer.bytes[1] == 254)
        }
        return peer.bytes.count == 16 && peer.bytes.contains(where: { $0 != 0 })
            && !(peer.bytes.dropLast().allSatisfy({ $0 == 0 }) && peer.bytes.last == 1)
            && peer.bytes[0] != 0xff
            && !(peer.bytes[0] == 0xfe && peer.bytes[1] & 0xc0 == 0x80)
    }

    private func translate(_ error: Error) -> VPNPeerRouteEvidenceError {
        switch error {
        case VPNRouteSocketTransportError.timeout: return .timeout
        case VPNRouteSocketTransportError.closed: return .closed
        case VPNRouteSocketTransportError.posix(let code): return .transport(code)
        default: return .closed
        }
    }
}

private enum VPNBestRouteReplyDecoder {
    private static let headerSize = MemoryLayout<rt_msghdr>.size
    private static let wordSize = MemoryLayout<UInt32>.size

    static func decode(_ data: Data, peer: OpenVPNIPAddress) throws -> VPNRoutePeerEvidence {
        let header: rt_msghdr
        do { header = try VPNDarwinRouteCodec.identify(data) }
        catch { throw VPNPeerRouteEvidenceError.malformedMessage }
        let flags = UInt32(bitPattern: header.rtm_flags)
        let forbidden = UInt32(RTF_REJECT | RTF_BLACKHOLE | RTF_DEAD | RTF_CONDEMNED)
        guard flags & UInt32(RTF_UP) != 0, flags & forbidden == 0,
              header.rtm_index > 0 else { throw VPNPeerRouteEvidenceError.unusableRoute }

        let addresses = try parseAddresses(data.subdata(in: headerSize..<data.count),
                                           mask: header.rtm_addrs)
        guard let destination = addresses[Int(RTAX_DST)] else {
            throw VPNPeerRouteEvidenceError.malformedMessage
        }
        let family: VPNRouteAddressFamily = peer.family == .ipv4 ? .ipv4 : .ipv6
        let destinationBytes = try ipBytes(destination, expected: family)
        let maximum = family == .ipv4 ? 32 : 128
        let prefixLength: Int
        if flags & UInt32(RTF_HOST) != 0 {
            prefixLength = maximum
        } else {
            guard let mask = addresses[Int(RTAX_NETMASK)] else {
                throw VPNPeerRouteEvidenceError.malformedMessage
            }
            prefixLength = try contiguousPrefix(mask, family: family)
        }
        guard isCanonical(destinationBytes, prefixLength: prefixLength),
              contains(route: destinationBytes, prefixLength: prefixLength, peer: peer.bytes) else {
            throw VPNPeerRouteEvidenceError.unusableRoute
        }

        let index = UInt32(header.rtm_index)
        var nameBuffer = [CChar](repeating: 0, count: Int(IFNAMSIZ))
        guard if_indextoname(index, &nameBuffer) != nil else {
            throw VPNPeerRouteEvidenceError.unusableRoute
        }
        let interfaceName = String(cString: nameBuffer)
        // An already-active WARP or corporate VPN may legitimately own the
        // pre-tunnel route to this peer. The separately captured baseline is
        // what distinguishes that interface from ProxyPilot's new utun.
        guard interfaceName != "lo0" else {
            throw VPNPeerRouteEvidenceError.unusableRoute
        }
        let gateway = try gatewayBytes(addresses[Int(RTAX_GATEWAY)], family: family,
                                       interfaceIndex: index, interfaceName: interfaceName)
        let usesGateway = flags & UInt32(RTF_GATEWAY) != 0
        guard usesGateway == (gateway != nil) else {
            throw VPNPeerRouteEvidenceError.unusableRoute
        }
        do {
            if family == .ipv4 {
                return try VPNRoutePeerEvidence(peer: value(peer.bytes, as: in_addr.self),
                    gateway: try gateway.map { try value($0, as: in_addr.self) },
                    interfaceIndex: index)
            }
            return try VPNRoutePeerEvidence(peer: value(peer.bytes, as: in6_addr.self),
                gateway: try gateway.map { try value($0, as: in6_addr.self) },
                interfaceIndex: index)
        } catch { throw VPNPeerRouteEvidenceError.unusableRoute }
    }

    private static func parseAddresses(_ body: Data, mask: Int32) throws -> [Int: Data] {
        let allowed = Int32((1 << Int(RTAX_MAX)) - 1)
        guard mask & ~allowed == 0 else { throw VPNPeerRouteEvidenceError.malformedMessage }
        var result: [Int: Data] = [:]
        var offset = 0
        for index in 0..<Int(RTAX_MAX) where mask & (1 << index) != 0 {
            guard offset < body.count else { throw VPNPeerRouteEvidenceError.malformedMessage }
            let declared = Int(body[offset])
            guard declared != 0 || index == Int(RTAX_NETMASK) else {
                throw VPNPeerRouteEvidenceError.malformedMessage
            }
            let stored = declared == 0 ? wordSize : declared
            let step = aligned(stored)
            guard stored >= (declared == 0 ? wordSize : 2), step >= stored,
                  offset + step <= body.count else {
                throw VPNPeerRouteEvidenceError.malformedMessage
            }
            result[index] = body.subdata(in: offset..<(offset + stored))
            offset += step
        }
        guard offset == body.count else { throw VPNPeerRouteEvidenceError.malformedMessage }
        return result
    }

    private static func ipBytes(_ data: Data,
                                expected: VPNRouteAddressFamily) throws -> [UInt8] {
        guard data.count >= 2 else { throw VPNPeerRouteEvidenceError.malformedMessage }
        if expected == .ipv4 {
            guard Int32(data[1]) == AF_INET, data.count >= 8 else {
                throw VPNPeerRouteEvidenceError.malformedMessage
            }
            return Array(data[4..<8])
        }
        guard Int32(data[1]) == AF_INET6, data.count >= 24 else {
            throw VPNPeerRouteEvidenceError.malformedMessage
        }
        return Array(data[8..<24])
    }

    private static func contiguousPrefix(_ data: Data,
                                         family: VPNRouteAddressFamily) throws -> Int {
        let size = family == .ipv4 ? 4 : 16
        let expectedFamily = family == .ipv4 ? AF_INET : AF_INET6
        guard !data.isEmpty else { throw VPNPeerRouteEvidenceError.malformedMessage }
        if data[0] == 0 { return 0 }
        guard data.count >= 2,
              Int32(data[1]) == AF_UNSPEC || Int32(data[1]) == expectedFamily else {
            throw VPNPeerRouteEvidenceError.malformedMessage
        }
        let start = min(family == .ipv4 ? 4 : 8, data.count)
        var bytes = [UInt8](repeating: 0, count: size)
        let available = min(size, max(0, data.count - start))
        if available > 0 {
            bytes.replaceSubrange(0..<available, with: data[start..<(start + available)])
        }
        var count = 0
        var sawZero = false
        for byte in bytes {
            for shift in (0..<8).reversed() {
                let set = byte & UInt8(1 << shift) != 0
                if set && sawZero { throw VPNPeerRouteEvidenceError.malformedMessage }
                if set { count += 1 } else { sawZero = true }
            }
        }
        return count
    }

    private static func gatewayBytes(_ data: Data?, family: VPNRouteAddressFamily,
                                     interfaceIndex: UInt32,
                                     interfaceName: String) throws -> [UInt8]? {
        guard let data else { return nil }
        guard data.count >= 2 else { throw VPNPeerRouteEvidenceError.malformedMessage }
        if Int32(data[1]) == AF_LINK {
            guard data.count >= 8 else { throw VPNPeerRouteEvidenceError.malformedMessage }
            let index = UInt32(data[2]) | UInt32(data[3]) << 8
            let nameLength = Int(data[5])
            guard (index == 0 || index == interfaceIndex), nameLength <= data.count - 8 else {
                throw VPNPeerRouteEvidenceError.malformedMessage
            }
            if nameLength > 0 {
                guard String(bytes: data[8..<(8 + nameLength)], encoding: .utf8) == interfaceName else {
                    throw VPNPeerRouteEvidenceError.malformedMessage
                }
            }
            return nil
        }
        return try ipBytes(data, expected: family)
    }

    private static func contains(route: [UInt8], prefixLength: Int,
                                 peer: [UInt8]) -> Bool {
        guard route.count == peer.count, prefixLength >= 0,
              prefixLength <= route.count * 8 else { return false }
        for bit in 0..<prefixLength {
            let mask = UInt8(0x80 >> (bit % 8))
            if route[bit / 8] & mask != peer[bit / 8] & mask { return false }
        }
        return true
    }

    private static func isCanonical(_ route: [UInt8], prefixLength: Int) -> Bool {
        guard prefixLength >= 0, prefixLength <= route.count * 8 else { return false }
        for bit in prefixLength..<(route.count * 8) {
            if route[bit / 8] & UInt8(0x80 >> (bit % 8)) != 0 { return false }
        }
        return true
    }

    private static func value<T>(_ bytes: [UInt8], as: T.Type) throws -> T {
        guard bytes.count == MemoryLayout<T>.size else {
            throw VPNPeerRouteEvidenceError.malformedMessage
        }
        return bytes.withUnsafeBytes { $0.loadUnaligned(as: T.self) }
    }

    private static func aligned(_ count: Int) -> Int {
        (count + wordSize - 1) & ~(wordSize - 1)
    }
}
