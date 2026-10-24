import Darwin
import Foundation

enum VPNBoundDNSUpstreamError: Error, Equatable {
    case invalidBinding, invalidMessage, invalidInterface, bindingFailed
    case timeout, busy, closed, truncated, posix(Int32)
}

enum VPNDNSUpstreamTransport { case udp, tcp }

/// Captured transaction evidence, NOT a live authority or an interface birth ID.
/// No endpoint/port may be supplied over IPC; corporate upstreams use port 53.
struct VPNDNSUpstreamBinding: Equatable {
    let networkPlan: VPNDomainNetworkPlan
    let routeProof: VPNRouteAppliedProof
    let tunnel: VPNTunnelInterfaceEvidence
    let serverEvidence: VPNTunnelDNSServerEvidence
    var generation: UInt64 { networkPlan.staticRoutes.generation }
    var revision: UInt64 { networkPlan.staticRoutes.revision }
    var server: VPNRoutePrefix { serverEvidence.server }
    var family: Int32 { server.family == .ipv4 ? AF_INET : AF_INET6 }
    static let port: UInt16 = 53

    init(networkPlan: VPNDomainNetworkPlan, routeProof: VPNRouteAppliedProof,
         tunnel: VPNTunnelInterfaceEvidence, server: VPNRoutePrefix) throws {
        let plan = try networkPlan.dnsPlan(tunnel: tunnel, routeProof: routeProof)
        guard networkPlan.corporateUpstreams.contains(server),
              let evidence = plan.serverEvidence.first(where: { $0.server == server }) else {
            throw VPNBoundDNSUpstreamError.invalidBinding
        }
        self.networkPlan = networkPlan; self.routeProof = routeProof
        self.tunnel = tunnel; serverEvidence = evidence
    }
}

/// REQUIRED integration boundary; deliberately no default approval or factory.
/// Obtain current authority per invocation, verify current generation/revision
/// AND the COMPLETE captured routeProof (including this exact server identity),
/// execute the operation exactly once while current, then release the acquired lease.
/// Do not retain a service/lifecycle lease for the socket's lifetime. Poll waits
/// occur outside this callback. A stale intent/deadline must throw.
///
/// The checker must honor the absolute deadline if its validation supports it.
/// Existing full verifyApplied can be costly: the socket's limit bounds IO
/// waits, NOT an arbitrary checker's execution time. Clock gates after checking
/// prevent traffic after expiry; this is no end-to-end 20-second promise.
protocol VPNDNSUpstreamAuthority: AnyObject {
    func withCurrentAuthority<T>(binding: VPNDNSUpstreamBinding, deadline: DispatchTime,
                                _ operation: () throws -> T) throws -> T
}

/// Narrow syscall boundary for deterministic tests; no fake is used by default.
protocol VPNDNSUpstreamSyscalls: AnyObject {
    func now() -> UInt64
    func interfaces() throws -> VPNKernelInterfaceSnapshot
    func socket(family: Int32, transport: VPNDNSUpstreamTransport) throws -> Int32
    func configure(_ descriptor: Int32) throws
    func bindInterface(_ descriptor: Int32, family: Int32, index: UInt32) throws
    func boundInterface(_ descriptor: Int32, family: Int32) throws -> (UInt32, Int)
    func connect(_ descriptor: Int32, binding: VPNDNSUpstreamBinding) throws
    func connectionError(_ descriptor: Int32) throws -> Int32
    func send(_ descriptor: Int32, bytes: Data, offset: Int) throws -> Int
    func receive(_ descriptor: Int32, maximum: Int, datagram: Bool) throws -> (Data, Bool)
    func poll(_ descriptor: Int32, events: Int16, milliseconds: Int32) throws -> Int16
    func close(_ descriptor: Int32)
}

/// Public SDK socket options: IP_BOUND_IF / IPV6_BOUND_IF. No IP_PKTINFO or
/// other ancillary outgoing control may override the bound interface.
/// https://github.com/apple-oss-distributions/xnu/blob/main/bsd/netinet/in.h
/// https://github.com/apple-oss-distributions/xnu/blob/main/bsd/netinet6/in6.h
final class VPNDarwinDNSUpstreamSyscalls: VPNDNSUpstreamSyscalls {
    func now() -> UInt64 { DispatchTime.now().uptimeNanoseconds }
    func interfaces() throws -> VPNKernelInterfaceSnapshot { try VPNKernelInterfaceSnapshot.capture() }
    func socket(family: Int32, transport: VPNDNSUpstreamTransport) throws -> Int32 {
        let fd = Darwin.socket(family, transport == .udp ? SOCK_DGRAM : SOCK_STREAM,
                               transport == .udp ? IPPROTO_UDP : IPPROTO_TCP)
        guard fd >= 0 else { throw VPNBoundDNSUpstreamError.posix(errno) }
        return fd
    }
    func configure(_ descriptor: Int32) throws {
        let flags = fcntl(descriptor, F_GETFL)
        guard flags >= 0, fcntl(descriptor, F_SETFD, FD_CLOEXEC) == 0,
              fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) == 0 else {
            throw VPNBoundDNSUpstreamError.posix(errno)
        }
        var enabled: Int32 = 1
        guard setsockopt(descriptor, SOL_SOCKET, SO_NOSIGPIPE, &enabled, socklen_t(MemoryLayout<Int32>.size)) == 0 else {
            throw VPNBoundDNSUpstreamError.posix(errno)
        }
    }
    private func option(_ family: Int32) -> (Int32, Int32) {
        family == AF_INET ? (IPPROTO_IP, IP_BOUND_IF) : (IPPROTO_IPV6, IPV6_BOUND_IF)
    }
    func bindInterface(_ descriptor: Int32, family: Int32, index: UInt32) throws {
        let (level, name) = option(family); var value = index
        guard setsockopt(descriptor, level, name, &value, socklen_t(MemoryLayout<UInt32>.size)) == 0 else {
            throw VPNBoundDNSUpstreamError.posix(errno)
        }
    }
    func boundInterface(_ descriptor: Int32, family: Int32) throws -> (UInt32, Int) {
        let (level, name) = option(family)
        var value: UInt32 = 0, size = socklen_t(MemoryLayout<UInt32>.size)
        guard getsockopt(descriptor, level, name, &value, &size) == 0 else {
            throw VPNBoundDNSUpstreamError.posix(errno)
        }
        return (value, Int(size))
    }
    func connect(_ descriptor: Int32, binding: VPNDNSUpstreamBinding) throws {
        let result: Int32
        if binding.family == AF_INET {
            var address = sockaddr_in()
            address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size); address.sin_family = sa_family_t(AF_INET)
            address.sin_port = VPNDNSUpstreamBinding.port.bigEndian
            withUnsafeMutableBytes(of: &address.sin_addr) { $0.copyBytes(from: binding.server.bytes) }
            result = withUnsafePointer(to: &address) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.connect(descriptor, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
            }
        } else {
            var address = sockaddr_in6()
            address.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size); address.sin6_family = sa_family_t(AF_INET6)
            address.sin6_port = VPNDNSUpstreamBinding.port.bigEndian
            withUnsafeMutableBytes(of: &address.sin6_addr) { $0.copyBytes(from: binding.server.bytes) }
            result = withUnsafePointer(to: &address) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.connect(descriptor, $0, socklen_t(MemoryLayout<sockaddr_in6>.size)) }
            }
        }
        if result != 0 { throw VPNBoundDNSUpstreamError.posix(errno) }
    }
    func connectionError(_ descriptor: Int32) throws -> Int32 {
        var value: Int32 = 0, size = socklen_t(MemoryLayout<Int32>.size)
        guard getsockopt(descriptor, SOL_SOCKET, SO_ERROR, &value, &size) == 0,
              size == MemoryLayout<Int32>.size else { throw VPNBoundDNSUpstreamError.closed }
        return value
    }
    func send(_ descriptor: Int32, bytes: Data, offset: Int) throws -> Int {
        let result = bytes.withUnsafeBytes { Darwin.send(descriptor, $0.baseAddress!.advanced(by: offset), bytes.count - offset, 0) }
        guard result >= 0 else { throw VPNBoundDNSUpstreamError.posix(errno) }
        return result
    }
    func receive(_ descriptor: Int32, maximum: Int, datagram: Bool) throws -> (Data, Bool) {
        var bytes = [UInt8](repeating: 0, count: maximum)
        var vector = iovec(iov_base: nil, iov_len: maximum), message = msghdr()
        let count = bytes.withUnsafeMutableBytes { raw -> Int in
            vector.iov_base = raw.baseAddress
            return withUnsafeMutablePointer(to: &vector) { pointer in
                message.msg_iov = pointer; message.msg_iovlen = 1
                return recvmsg(descriptor, &message, 0)
            }
        }
        guard count >= 0 else { throw VPNBoundDNSUpstreamError.posix(errno) }
        return (Data(bytes.prefix(min(count, maximum))), message.msg_flags & MSG_TRUNC != 0)
    }
    func poll(_ descriptor: Int32, events: Int16, milliseconds: Int32) throws -> Int16 {
        var item = pollfd(fd: descriptor, events: events, revents: 0)
        let result = Darwin.poll(&item, 1, milliseconds)
        guard result >= 0 else { throw VPNBoundDNSUpstreamError.posix(errno) }
        return result == 0 ? 0 : item.revents
    }
    func close(_ descriptor: Int32) { _ = Darwin.close(descriptor) } // Never retry close after EINTR.
}

/// Inert upstream transport only: no DNS publication, route changes, relay,
/// cache, protocol fallback, answer interposition or runtime activation.
final class VPNBoundDNSUpstreamSocket {
    static let maximumMessageBytes = 65_535
    // Shared with the inert UDP→TCP coordinator: one ceiling, never per-leg reset.
    static let maximumIOBudget: UInt64 = 20_000_000_000
    private let binding: VPNDNSUpstreamBinding
    private let transport: VPNDNSUpstreamTransport
    private let authority: VPNDNSUpstreamAuthority
    private let calls: VPNDNSUpstreamSyscalls
    private let gate = NSLock()
    private var descriptor: Int32 = -1

    private init(binding: VPNDNSUpstreamBinding, transport: VPNDNSUpstreamTransport,
                 authority: VPNDNSUpstreamAuthority, calls: VPNDNSUpstreamSyscalls) {
        self.binding = binding; self.transport = transport; self.authority = authority; self.calls = calls
    }
    deinit { closeOwned() }
    private func closeOwned() {
        if descriptor >= 0 { let owned = descriptor; descriptor = -1; calls.close(owned) }
    }
    /// Sole-owner completion after exchange unwinds. Busy refuses without
    /// touching the descriptor; a cancellation signal must NEVER close it from
    /// another thread. No raw descriptor escapes this API.
    func close() throws {
        guard gate.try() else { throw VPNBoundDNSUpstreamError.busy }
        defer { gate.unlock() }
        closeOwned()
    }
    private func budget(_ requested: DispatchTime) throws -> DispatchTime {
        let now = calls.now()
        let ceiling = now > UInt64.max - Self.maximumIOBudget ? UInt64.max : now + Self.maximumIOBudget
        let end = min(requested.uptimeNanoseconds, ceiling)
        guard now < end else { throw VPNBoundDNSUpstreamError.timeout }
        return DispatchTime(uptimeNanoseconds: end)
    }
    private func clock(_ deadline: DispatchTime) throws {
        guard calls.now() < deadline.uptimeNanoseconds else { throw VPNBoundDNSUpstreamError.timeout }
    }
    private func checkInterface() throws {
        let snapshot = try calls.interfaces()
        guard let current = snapshot.interfaces.first(where: { $0.index == binding.tunnel.index }),
              current.name == binding.tunnel.name, current.isUp, current.isRunning, current.isPointToPoint,
              binding.tunnel.addresses.allSatisfy(current.addresses.contains) else {
            throw VPNBoundDNSUpstreamError.invalidInterface
        }
    }
    private func checkBinding() throws {
        let (value, length) = try calls.boundInterface(descriptor, family: binding.family)
        guard value == binding.tunnel.index, length == MemoryLayout<UInt32>.size else {
            throw VPNBoundDNSUpstreamError.bindingFailed
        }
    }
    private func authorized<T>(_ deadline: DispatchTime, bound: Bool = true,
                               _ operation: () throws -> T) throws -> T {
        try clock(deadline)
        var entered = false
        let result = try authority.withCurrentAuthority(binding: binding, deadline: deadline) {
            guard !entered else { throw VPNBoundDNSUpstreamError.invalidBinding }
            entered = true
            try clock(deadline)
            try checkInterface()
            try clock(deadline)
            if bound { try checkBinding(); try clock(deadline) }
            return try operation()
        }
        guard entered else { throw VPNBoundDNSUpstreamError.invalidBinding }
        try clock(deadline)
        return result
    }
    static func prepare(binding: VPNDNSUpstreamBinding, transport: VPNDNSUpstreamTransport,
                        authority: VPNDNSUpstreamAuthority, deadline: DispatchTime,
                        syscalls: VPNDNSUpstreamSyscalls = VPNDarwinDNSUpstreamSyscalls()) throws -> VPNBoundDNSUpstreamSocket {
        let socket = VPNBoundDNSUpstreamSocket(binding: binding, transport: transport, authority: authority, calls: syscalls)
        do {
            let end = try socket.budget(deadline)
            try socket.authorized(end, bound: false) {
                socket.descriptor = try syscalls.socket(family: binding.family, transport: transport)
                guard socket.descriptor >= 0 else { throw VPNBoundDNSUpstreamError.closed }
                try socket.clock(end); try syscalls.configure(socket.descriptor)
                try socket.clock(end); try syscalls.bindInterface(socket.descriptor, family: binding.family, index: binding.tunnel.index)
                try socket.clock(end); try socket.checkBinding()
            }
            try socket.connect(end)
            return socket
        } catch { socket.closeOwned(); throw error }
    }
    private func wait(_ events: Int16, _ deadline: DispatchTime) throws {
        while true {
            let now = calls.now(), end = deadline.uptimeNanoseconds
            guard now < end else { throw VPNBoundDNSUpstreamError.timeout }
            let milliseconds = Int32(min(UInt64(Int32.max), (end - now + 999_999) / 1_000_000))
            do {
                let result = try calls.poll(descriptor, events: events, milliseconds: milliseconds)
                try clock(deadline)
                guard result != 0 else { throw VPNBoundDNSUpstreamError.timeout }
                guard result & Int16(POLLERR | POLLHUP | POLLNVAL) == 0 else { throw VPNBoundDNSUpstreamError.closed }
                if result & events != 0 { return }
            } catch VPNBoundDNSUpstreamError.posix(let error) where error == EINTR || error == EAGAIN { continue }
        }
    }
    private func connect(_ deadline: DispatchTime) throws {
        while true {
            do {
                try authorized(deadline) { try calls.connect(descriptor, binding: binding) }
                return
            } catch VPNBoundDNSUpstreamError.posix(let error) where error == EINPROGRESS || error == EALREADY || error == EINTR {
                try wait(Int16(POLLOUT), deadline)
                let error = try authorized(deadline) { try calls.connectionError(descriptor) }
                guard error == 0 else { throw VPNBoundDNSUpstreamError.posix(error) }
                return
            } catch VPNBoundDNSUpstreamError.posix(let error) where error == EAGAIN {
                try wait(Int16(POLLOUT), deadline)
            } catch VPNBoundDNSUpstreamError.posix(let error) where error == EISCONN {
                // This private descriptor has only ever targeted this one
                // immutable numeric endpoint; no caller can retarget it.
                return
            }
        }
    }
    private func write(_ bytes: Data, _ deadline: DispatchTime) throws {
        var offset = 0
        while offset < bytes.count {
            do {
                let count = try authorized(deadline) { try calls.send(descriptor, bytes: bytes, offset: offset) }
                guard count > 0, count <= bytes.count - offset else { throw VPNBoundDNSUpstreamError.closed }
                if transport == .udp && count != bytes.count { throw VPNBoundDNSUpstreamError.truncated }
                offset += count
            } catch VPNBoundDNSUpstreamError.posix(let error) where error == EINTR { continue }
            catch VPNBoundDNSUpstreamError.posix(let error) where error == EAGAIN || error == EWOULDBLOCK {
                try wait(Int16(POLLOUT), deadline)
            }
        }
    }
    private func read(_ maximum: Int, _ deadline: DispatchTime) throws -> Data {
        while true {
            do {
                let (bytes, truncated) = try authorized(deadline) {
                    try calls.receive(descriptor, maximum: maximum, datagram: transport == .udp)
                }
                guard !truncated, bytes.count <= maximum else { throw VPNBoundDNSUpstreamError.truncated }
                guard !bytes.isEmpty else { throw VPNBoundDNSUpstreamError.closed }
                return bytes
            } catch VPNBoundDNSUpstreamError.posix(let error) where error == EINTR { continue }
            catch VPNBoundDNSUpstreamError.posix(let error) where error == EAGAIN || error == EWOULDBLOCK {
                try wait(Int16(POLLIN), deadline)
            }
        }
    }
    private func readExactly(_ length: Int, _ deadline: DispatchTime) throws -> Data {
        var bytes = Data()
        while bytes.count < length { bytes.append(try read(length - bytes.count, deadline)) }
        return bytes
    }
    func exchange(question: Data, deadline: DispatchTime) throws -> Data {
        guard gate.try() else { throw VPNBoundDNSUpstreamError.busy }
        defer { gate.unlock() }
        do {
            guard descriptor >= 0 else { throw VPNBoundDNSUpstreamError.closed }
            let end = try budget(deadline)
            let queryHeader = Array(question.prefix(3))
            guard (12...Self.maximumMessageBytes).contains(question.count), queryHeader[2] & 0x80 == 0 else {
                throw VPNBoundDNSUpstreamError.invalidMessage
            }
            let response: Data
            if transport == .udp {
                try write(question, end)
                response = try read(Self.maximumMessageBytes, end)
            } else {
                var framed = Data([UInt8(question.count >> 8), UInt8(question.count & 255)])
                framed.append(question)
                try write(framed, end)
                let header = try readExactly(2, end)
                let length = Int(header[0]) * 256 + Int(header[1])
                guard (12...Self.maximumMessageBytes).contains(length) else { throw VPNBoundDNSUpstreamError.invalidMessage }
                response = try readExactly(length, end)
            }
            let responseHeader = Array(response.prefix(3))
            guard (12...Self.maximumMessageBytes).contains(response.count), responseHeader[2] & 0x80 != 0,
                  responseHeader[0] == queryHeader[0], responseHeader[1] == queryHeader[1] else { throw VPNBoundDNSUpstreamError.invalidMessage }
            // No CNAME/TTL/answer policy is inferred from this framing check.
            try authorized(end) {}
            return response
        } catch { closeOwned(); throw error }
    }
}
