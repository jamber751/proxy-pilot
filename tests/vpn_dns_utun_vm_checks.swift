// DISPOSABLE GITHUB VM ONLY. No production helper/test flags or runtime wiring.
// Two exclusively allocated utuns; never configure an existing interface.
// Public API source: xnu/bsd/net/if_utun.{h,c}, net/rtsock.c, netinet/in.h,
// netinet6/in6.h at https://github.com/apple-oss-distributions/xnu
// Own-interface -dad syntax: network_cmds/ifconfig.tproj/ifconfig.8 in Apple's
// https://github.com/apple-oss-distributions/network_cmds repository.
// Four-byte network-order family ABI:
// https://github.com/apple-oss-distributions/xnu/blob/main/bsd/net/if_utun.c#L2108
// TCP proof is initial SYN selection ONLY. Pending production TCP polling has
// no explicit cancellation API: future lifecycle integration must close pending
// TCPs on revocation. This fixture proves neither complete fail-closed behavior
// nor no leaks, CNAME/TTL/answer policy, system resolver binding or VPN readiness.
import Darwin
import Foundation

@_silgen_name("pp_dns_utun_open")
private func openOwnedUTUN(_ output: UnsafeMutablePointer<CChar>, _ size: Int) -> Int32

private let flag = "PROXYPILOT_VM_DNS_UTUN_TESTS"
private enum Failure: String, Error, CaseIterable {
    case guardDenied, arguments, namespace, context, interface, address, route, packet
    case path, child, timeout, sourcePort, sigpipe, receipt, cleanup
}
private func allowed(_ uid: uid_t, _ euid: uid_t, _ env: [String:String]) -> Bool {
    uid == 0 && euid == 0 && env["GITHUB_ACTIONS"] == "true" && env[flag] == "1"
}
private func validID(_ value: String) -> Bool { UUID(uuidString: value)?.uuidString.lowercased() == value }
private func check(_ condition: @autoclosure () throws -> Bool, _ failure: Failure) throws {
    if try !condition() { throw failure }
}
private func deadline(_ seconds: UInt64 = 20) -> UInt64 { DispatchTime.now().uptimeNanoseconds + seconds * 1_000_000_000 }
private func remaining(_ end: UInt64, maximum: Int32 = 100) throws -> Int32 {
    let now = DispatchTime.now().uptimeNanoseconds
    try check(now < end, .timeout)
    return Int32(min(UInt64(maximum), (end - now + 999_999) / 1_000_000))
}
// Closed, bounded VM-only diagnostics. Never include descriptors, paths or bytes.
private enum SocketDiagnostic {
    enum Role: String { case childControl, baseline, protected, operation }
    enum Stage: String {
        case configureBegin, configureOK, configureError, sendBegin, sendOK, sendError
        case getFL, getFD, getNoSigpipe, signalState, childLaunch
    }
    static var emitted = 0
    static func emit(_ role: Role, _ stage: Stage, _ value: Int32 = 0) {
        guard emitted < 64 else { return }; emitted += 1
        print("API socket role=\(role.rawValue) stage=\(stage.rawValue) value=\(value)"); fflush(stdout)
    }
    static func number(_ error: Error) -> Int32 {
        if case VPNBoundDNSUpstreamError.posix(let value) = error { return value }
        return -1
    }
    static func configure(_ calls: VPNDarwinDNSUpstreamSyscalls, _ fd: Int32, _ role: Role) throws {
        emit(role, .configureBegin)
        do { try calls.configure(fd); emit(role, .configureOK) }
        catch {
            emit(role, .configureError, number(error))
            // Read-only postconditions; no replay or repair of a failed syscall.
            let fl = fcntl(fd, F_GETFL), flags = fcntl(fd, F_GETFD)
            emit(role, .getFL, fl); emit(role, .getFD, flags)
            var option: Int32 = -1, size = socklen_t(MemoryLayout<Int32>.size)
            let status = getsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &option, &size)
            let captured = errno
            emit(role, .getNoSigpipe, status == 0 && size == 4 ? option : -max(1,captured))
            throw error
        }
    }
    static func accepts(_ line: String) -> Bool {
        line.range(of: #"^API socket role=(childControl|baseline|protected|operation) stage=(configureBegin|configureOK|configureError|sendBegin|sendOK|sendError|getFL|getFD|getNoSigpipe|signalState|childLaunch) value=-?[0-9]{1,10}$"#, options: .regularExpression) != nil
        && line.split(separator: " ").last.flatMap { Int32($0.dropFirst(6)) } != nil
    }
}

private func canonicalData<T: Encodable>(_ value: T) throws -> Data {
    let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
    return try encoder.encode(value)
}

private enum Wire {
    static func u16(_ bytes: [UInt8], _ offset: Int) -> Int { Int(bytes[offset]) * 256 + Int(bytes[offset + 1]) }
    static func put16(_ value: Int) -> [UInt8] { [UInt8(value >> 8), UInt8(value & 255)] }
    static func checksum(_ bytes: [UInt8]) -> UInt16 {
        var sum: UInt32 = 0
        for offset in stride(from: 0, to: bytes.count, by: 2) {
            sum += UInt32(bytes[offset]) << 8
            if offset + 1 < bytes.count { sum += UInt32(bytes[offset + 1]) }
        }
        while sum >> 16 != 0 { sum = (sum & 65535) + (sum >> 16) }
        return UInt16(~sum & 65535)
    }
    static func ip(_ text: String, _ family: Int32) -> [UInt8] {
        var bytes = [UInt8](repeating: 0, count: family == AF_INET ? 4 : 16)
        precondition(text.withCString { pointer in bytes.withUnsafeMutableBytes { inet_pton(family, pointer, $0.baseAddress!) } } == 1)
        return bytes
    }
    static func question(_ id: String, _ phase: String, _ family: Int32) -> Data {
        let labels = [phase, "q-" + id, "test"]
        var bytes = [UInt8](repeating: 0, count: 12)
        bytes[0] = 0x41; bytes[1] = 0x53; bytes[2] = 1; bytes[5] = 1
        for label in labels { bytes.append(UInt8(label.utf8.count)); bytes += label.utf8 }
        bytes += [0] + put16(family == AF_INET ? 1 : 28) + [0,1]
        return Data(bytes)
    }
    static func answer(_ question: Data, _ family: Int32) -> Data {
        var bytes = [UInt8](question); bytes[2] = 0x81; bytes[3] = 0x80; bytes[7] = 1
        let address = ip(family == AF_INET ? "192.0.2.53" : "2001:db8::53", family)
        bytes += [0xc0,0x0c] + put16(family == AF_INET ? 1 : 28) + [0,1,0,0,0,0] + put16(address.count) + address
        return Data(bytes)
    }
    struct Packet {
        let family: Int32
        let source: [UInt8], destination: [UInt8]
        let sourcePort: Int, destinationPort: Int
        let isUDP: Bool, isSYN: Bool
        let payload: Data
    }
    static func packet(_ data: Data) -> Packet? {
        let bytes = [UInt8](data)
        guard bytes.count >= 24 else { return nil }
        let tag = bytes.prefix(4).reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        let ipBytes = Array(bytes.dropFirst(4))
        let family: Int32, offset: Int, size: Int, proto: UInt8, source: [UInt8], destination: [UInt8]
        if tag == UInt32(AF_INET) {
            guard ipBytes.count >= 20, ipBytes[0] >> 4 == 4 else { return nil }
            offset = Int(ipBytes[0] & 15) * 4; size = u16(ipBytes, 2); proto = ipBytes[9]; family = AF_INET
            guard offset >= 20, size <= ipBytes.count, size >= offset + 8, u16(ipBytes, 6) & 0x3fff == 0 else { return nil }
            source = Array(ipBytes[12..<16]); destination = Array(ipBytes[16..<20])
        } else if tag == UInt32(AF_INET6) {
            guard ipBytes.count >= 48, ipBytes[0] >> 4 == 6 else { return nil }
            offset = 40; size = 40 + u16(ipBytes, 4); proto = ipBytes[6]; family = AF_INET6
            guard size <= ipBytes.count, size >= 48 else { return nil }
            source = Array(ipBytes[8..<24]); destination = Array(ipBytes[24..<40])
        } else { return nil }
        let sport = u16(ipBytes, offset), dport = u16(ipBytes, offset + 2)
        if proto == UInt8(IPPROTO_UDP) {
            let length = u16(ipBytes, offset + 4)
            guard length >= 8, offset + length <= size else { return nil }
            return Packet(family: family, source: source, destination: destination, sourcePort: sport,
                destinationPort: dport, isUDP: true, isSYN: false, payload: Data(ipBytes[(offset + 8)..<(offset + length)]))
        }
        if proto == UInt8(IPPROTO_TCP), offset + 20 <= size {
            let length = Int(ipBytes[offset + 12] >> 4) * 4
            guard length >= 20, offset + length <= size else { return nil }
            return Packet(family: family, source: source, destination: destination, sourcePort: sport,
                destinationPort: dport, isUDP: false, isSYN: ipBytes[offset + 13] & 0x12 == 2, payload: Data())
        }
        return nil
    }
    static func udp(family: Int32, source: [UInt8], destination: [UInt8], sport: Int, dport: Int, payload: Data) -> Data {
        let length = 8 + payload.count
        var udp: [UInt8] = put16(sport) + put16(dport) + put16(length)
        udp += [0,0]; udp += Array(payload)
        let pseudo = pseudoHeader(family, source, destination, length)
        let sum = checksum(pseudo + udp)
        udp.replaceSubrange(6..<8, with: put16(Int(sum == 0 ? 65535 : sum)))
        var header: [UInt8]
        if family == AF_INET {
            header = [0x45,0] + put16(20 + length) + [0,0,0,0,64,17,0,0] + source + destination
            header.replaceSubrange(10..<12, with: put16(Int(checksum(header))))
        } else { header = [0x60,0,0,0] + put16(length) + [17,64] + source + destination }
        let tag = UInt32(family)
        return Data([UInt8(tag >> 24),UInt8((tag >> 16) & 255),UInt8((tag >> 8) & 255),UInt8(tag & 255)] + header + udp)
    }
    static func pseudoHeader(_ family: Int32, _ source: [UInt8], _ destination: [UInt8], _ length: Int) -> [UInt8] {
        var bytes = source + destination
        if family == AF_INET { bytes += [0,17]; bytes += put16(length) }
        else { bytes += [0,0]; bytes += put16(length); bytes += [0,0,0,17] }
        return bytes
    }
}

private struct FileStamp: Equatable {
    let device: dev_t, inode: ino_t, size: off_t
    let seconds: Int, nanoseconds: Int
    init(_ value: stat) {
        device = value.st_dev; inode = value.st_ino; size = value.st_size
        seconds = value.st_mtimespec.tv_sec; nanoseconds = value.st_mtimespec.tv_nsec
    }
}
private final class Namespace {
    let descriptor: Int32, id: String
    let path: String
    var files: [String:(FileStamp,Data)] = [:]
    init(_ id: String, create: Bool) throws {
        try check(validID(id) && allowed(getuid(), geteuid(), ProcessInfo.processInfo.environment), .guardDenied)
        self.id = id; path = "/private/tmp/pp-dns-utun-" + id
        let parent = open("/private/tmp", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        try check(parent >= 0, .namespace); defer { close(parent) }
        if create { try check(mkdirat(parent, "pp-dns-utun-" + id, 0o700) == 0, .namespace) }
        descriptor = openat(parent, "pp-dns-utun-" + id, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        try check(descriptor >= 0, .namespace)
        var info = stat()
        try check(fstat(descriptor, &info) == 0 && info.st_uid == 0 && info.st_mode & S_IFMT == S_IFDIR
                  && info.st_mode & 0o7777 == 0o700, .namespace)
    }
    deinit { close(descriptor) }
    func read(_ name: String) throws -> (FileStamp,Data) {
        let fd = openat(descriptor, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        try check(fd >= 0, .context); defer { close(fd) }
        var info = stat()
        try check(fstat(fd, &info) == 0 && info.st_mode & S_IFMT == S_IFREG && info.st_uid == 0
                  && info.st_nlink == 1 && info.st_mode & 0o7777 == 0o600 && info.st_size <= 32768, .context)
        let stamp = FileStamp(info)
        var bytes = [UInt8](repeating: 0, count: Int(info.st_size))
        var offset = 0
        while offset < bytes.count {
            let count = bytes.withUnsafeMutableBytes { Darwin.read(fd, $0.baseAddress!.advanced(by: offset), $0.count - offset) }
            if count < 0 && errno == EINTR { continue }
            try check(count > 0, .context); offset += count
        }
        try check(fstat(fd, &info) == 0 && FileStamp(info) == stamp, .context)
        return (stamp,Data(bytes))
    }
    func remember(_ name: String) throws { files[name] = try read(name) }
    func write(_ name: String, _ data: Data) throws {
        try check(["context.json","baseline.json","receipt-preserved"].contains(name) && data.count <= 32768, .context)
        if let expected = files[name] { let current = try read(name); try check(current.0 == expected.0 && current.1 == expected.1, .receipt) }
        let temp = ".write-" + UUID().uuidString
        let fd = openat(descriptor, temp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        try check(fd >= 0, .context)
        defer { close(fd); unlinkat(descriptor, temp, 0) }
        try data.withUnsafeBytes { bytes in
            var offset = 0
            while offset < bytes.count {
                let count = Darwin.write(fd, bytes.baseAddress!.advanced(by: offset), bytes.count - offset)
                if count < 0 && errno == EINTR { continue }
                try check(count > 0, .context); offset += count
            }
        }
        try check(fsync(fd) == 0, .context)
        if files[name] == nil { try check(linkat(descriptor, temp, descriptor, name, 0) == 0, .context) }
        else { try check(renameat(descriptor, temp, descriptor, name) == 0, .context) }
        _ = unlinkat(descriptor, temp, 0)
        try check(fsync(descriptor) == 0, .context); try remember(name)
    }
    func remove(_ name: String) throws {
        guard let expected = files[name] else { throw Failure.receipt }
        let current = try read(name)
        try check(current.0 == expected.0 && current.1 == expected.1 && unlinkat(descriptor, name, 0) == 0, .receipt)
        files.removeValue(forKey: name)
    }
}

private final class UTUN {
    var descriptor: Int32
    let name: String, index: UInt32
    init() throws {
        var name = [CChar](repeating: 0, count: Int(IFNAMSIZ))
        descriptor = name.withUnsafeMutableBufferPointer { openOwnedUTUN($0.baseAddress!, $0.count) }
        if descriptor < 0 { print("API utun errno=\(errno)") }
        try check(descriptor >= 0, .interface)
        self.name = String(cString: name); index = if_nametoindex(name)
        try check(self.name.hasPrefix("utun") && !self.name.dropFirst(4).isEmpty
            && self.name.dropFirst(4).utf8.allSatisfy { (48...57).contains($0) } && index > 0, .interface)
    }
    deinit { if descriptor >= 0 { close(descriptor) } }
    func stop() throws {
        guard descriptor >= 0 else { return }
        let own = descriptor; descriptor = -1; try check(close(own) == 0, .interface)
        let end = deadline(2)
        while if_nametoindex(name) == index { _ = try remaining(end); usleep(5000) }
        try check(if_nametoindex(name) == 0, .interface) // Never destroy a reused name.
    }
}

private struct Context: Codable {
    let id: String, parent: Int32
    let aIndex: UInt32, aName: String, bIndex: UInt32, bName: String
    static let server4 = "198.51.100.53", server6 = "2001:db8:53::53", peer = "198.51.100.9"
    static let a4 = "192.0.2.1", b4 = "192.0.2.5", a6 = "2001:db8:aa::1", b6 = "2001:db8:bb::1"
    func evidence() throws -> VPNTunnelInterfaceEvidence {
        let snapshot = try VPNKernelInterfaceSnapshot.capture()
        guard let a = snapshot.interfaces.first(where: { $0.index == aIndex && $0.name == aName }),
              let b = snapshot.interfaces.first(where: { $0.index == bIndex && $0.name == bName }) else { throw Failure.interface }
        try check(b.isUp && b.isRunning && b.isPointToPoint
                  && b.addresses.contains(try OpenVPNIPAddress(parsing: Substring(Self.b4), family: .ipv4))
                  && b.addresses.contains(try OpenVPNIPAddress(parsing: Substring(Self.b6), family: .ipv6)), .interface)
        // Freshness comes from the parent's exclusively allocated control FD
        // and protected context, not from adopting a preexisting interface.
        return try VPNTunnelInterfaceResolver.resolve(baseline: VPNKernelInterfaceSnapshot(interfaces: []),
            after: VPNKernelInterfaceSnapshot(interfaces: [a]),
            management: OpenVPNConnectedEvidence(tunnelLocalIPv4: OpenVPNIPAddress(parsing: Substring(Self.a4), family: .ipv4),
                tunnelLocalIPv6: OpenVPNIPAddress(parsing: Substring(Self.a6), family: .ipv6),
                remoteAddress: OpenVPNIPAddress(parsing: Substring(Self.peer), family: .ipv4), remotePort: 443))
    }
    func plan() throws -> VPNDomainNetworkPlan {
        var peer = in_addr(); precondition(Self.peer.withCString { inet_pton(AF_INET, $0, &peer) } == 1)
        return try VPNDomainNetworkPlan(generation: 7, revision: 11,
            resources: [VPNResource(address: "fixture-" + id + ".test")], corporateDNS: [Self.server4,Self.server6],
            peer: VPNRoutePeerEvidence(peer: peer, gateway: nil, interfaceIndex: bIndex), tunnel: evidence())
    }
    static func load(_ namespace: Namespace) throws -> Context {
        let data = try namespace.read("context.json").1
        let value = try JSONDecoder().decode(Context.self, from: data)
        try check(try canonicalData(value) == data && value.id == namespace.id && value.parent == getppid()
                  && value.aIndex != value.bIndex && value.aName != value.bName, .context)
        return value
    }
}

private func withTransaction<T>(_ namespace: Namespace,
    _ operation: (VPNRouteTransaction, VPNRouteJournal, VPNDarwinRouteSocket) throws -> T) throws -> T {
    let lease = try VPNLifecycleOwnership.acquireRuntime(inTrustedDirectory: namespace.descriptor)
    defer { lease.release() }
    let journal = try VPNRouteJournal(trustedDirectoryDescriptor: namespace.descriptor)
    let kernel = try VPNDarwinRouteSocket.production()
    return try operation(VPNRouteTransaction(journal: journal, kernel: kernel, runtimeLease: lease), journal, kernel)
}
private func applied(_ namespace: Namespace) throws -> VPNRouteAppliedProof {
    let journal = try VPNRouteJournal(trustedDirectoryDescriptor: namespace.descriptor)
    let value = try journal.load()
    try check(value.phase == .applied, .receipt)
    return VPNRouteAppliedProof(generation: value.plan.generation, revision: value.plan.revision,
        identities: value.applied, preservedPeerRoute: value.plan.preservesPeerRoute == true ? value.plan.routes.first : nil)
}
private final class Authority: VPNDNSUpstreamAuthority {
    let namespace: Namespace, context: Context, plan: VPNDomainNetworkPlan, proof: VPNRouteAppliedProof
    init(_ namespace: Namespace, _ context: Context) throws {
        self.namespace = namespace; self.context = context; plan = try context.plan(); proof = try applied(namespace)
    }
    func binding(_ family: Int32) throws -> VPNDNSUpstreamBinding {
        try VPNDNSUpstreamBinding(networkPlan: plan, routeProof: proof, tunnel: context.evidence(),
            server: VPNRoutePrefix(resource: VPNResource(address: family == AF_INET ? Context.server4 : Context.server6)))
    }
    func withCurrentAuthority<T>(binding: VPNDNSUpstreamBinding, deadline: DispatchTime, _ operation: () throws -> T) throws -> T {
        try check(DispatchTime.now().uptimeNanoseconds < deadline.uptimeNanoseconds, .timeout)
        // Private fixture intent, not an actual service/profile/factory.
        let current = try Context.load(namespace)
        try check(current.id == context.id && current.aIndex == context.aIndex && current.bIndex == context.bIndex
                  && binding.generation == 7 && binding.revision == 11 && binding.routeProof == proof
                  && binding.networkPlan == plan, .context)
        return try withTransaction(namespace) { transaction, _, _ in
            try transaction.verifyApplied(proof) // COMPLETE proof, including preserved peer.
            try check(DispatchTime.now().uptimeNanoseconds < deadline.uptimeNanoseconds, .timeout)
            return try operation() // Lease releases here, before any socket poll.
        }
    }
}
private final class RecordingCalls: VPNDNSUpstreamSyscalls {
    let real = VPNDarwinDNSUpstreamSyscalls()
    private var tcp = false, announcedPoll = false
    func now() -> UInt64 { real.now() }
    func interfaces() throws -> VPNKernelInterfaceSnapshot { try real.interfaces() }
    func socket(family: Int32, transport: VPNDNSUpstreamTransport) throws -> Int32 {
        tcp = transport == .tcp; return try real.socket(family: family, transport: transport)
    }
    func configure(_ fd: Int32) throws { try SocketDiagnostic.configure(real, fd, .operation) }
    func bindInterface(_ fd: Int32, family: Int32, index: UInt32) throws { try real.bindInterface(fd, family: family, index: index) }
    func boundInterface(_ fd: Int32, family: Int32) throws -> (UInt32,Int) { try real.boundInterface(fd, family: family) }
    static func port(_ fd: Int32, _ family: Int32) throws -> Int {
        var address = sockaddr_storage(), size = socklen_t(MemoryLayout<sockaddr_storage>.size)
        let result = withUnsafeMutablePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &size) }
        }
        try check(result == 0 && address.ss_family == family, .sourcePort)
        let port: UInt16 = withUnsafePointer(to: &address) {
            if family == AF_INET { return $0.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { UInt16(bigEndian: $0.pointee.sin_port) } }
            return $0.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { UInt16(bigEndian: $0.pointee.sin6_port) }
        }
        try check(port > 0, .sourcePort); return Int(port)
    }
    func connect(_ fd: Int32, binding: VPNDNSUpstreamBinding) throws {
        do { try real.connect(fd, binding: binding) }
        catch {
            if case VPNBoundDNSUpstreamError.posix(let code) = error, [EINPROGRESS,EALREADY,EINTR].contains(code) {
                print("PORT\(binding.family == AF_INET ? 4 : 6) \(try Self.port(fd, binding.family))"); fflush(stdout)
            }
            throw error
        }
        print("PORT\(binding.family == AF_INET ? 4 : 6) \(try Self.port(fd, binding.family))"); fflush(stdout)
    }
    func connectionError(_ fd: Int32) throws -> Int32 { try real.connectionError(fd) }
    func send(_ fd: Int32, bytes: Data, offset: Int) throws -> Int { try real.send(fd, bytes: bytes, offset: offset) }
    func receive(_ fd: Int32, maximum: Int, datagram: Bool) throws -> (Data,Bool) { try real.receive(fd, maximum: maximum, datagram: datagram) }
    func poll(_ fd: Int32, events: Int16, milliseconds: Int32) throws -> Int16 {
        if tcp && !announcedPoll { announcedPoll = true; print("READY polling"); fflush(stdout) }
        return try real.poll(fd, events: events, milliseconds: milliseconds)
    }
    func close(_ fd: Int32) { real.close(fd) }
}
private final class CrashKernel: VPNRouteKernelController {
    let real: VPNDarwinRouteSocket
    init(_ real: VPNDarwinRouteSocket) { self.real = real }
    func lookupExact(_ prefix: VPNRoutePrefix) throws -> VPNDarwinRouteSnapshot? { try real.lookupExact(prefix) }
    func lookupExact(_ key: VPNRouteLookupKey) throws -> VPNDarwinRouteSnapshot? { try real.lookupExact(key) }
    func add(_ identity: VPNOwnedRouteIdentity) throws -> VPNDarwinRouteMutationResult {
        let result = try real.add(identity)
        if identity.role == .dnsDependency && result == .installed {
            print("READY mutation"); fflush(stdout)
            kill(getpid(), SIGKILL); _exit(71)
        }
        return result
    }
    func delete(_ identity: VPNOwnedRouteIdentity) throws -> VPNDarwinRouteMutationResult { try real.delete(identity) }
}
private struct BaselineState: Codable {
    let identities: [VPNOwnedRouteIdentity]
    var states: [String]
}
private final class Baseline {
    let namespace: Namespace, kernel: VPNDarwinRouteSocket
    var state: BaselineState
    init(_ namespace: Namespace, _ context: Context) throws {
        self.namespace = namespace; kernel = try VPNDarwinRouteSocket.production()
        var identities: [VPNOwnedRouteIdentity] = []
        for text in [Context.server4,Context.server6,Context.peer] {
            let prefix = try VPNRoutePrefix(resource: VPNResource(address: text))
            let role: VPNPlannedRouteRole = text == Context.peer ? .peerBypass : .resource
            let planned = VPNPlannedRoute(role: role, destination: prefix, physicalGatewayBytes: nil,
                interfaceIndex: context.bIndex, interfaceName: context.bName)
            // Relative to the A transaction, this is a foreign read-only peer.
            let flags = UInt32(RTF_UP | RTF_STATIC | RTF_HOST) | (role == .resource ? UInt32(RTF_PROTO2) : 0)
            let evidence: VPNRouteKernelEvidence
            if prefix.family == .ipv4 { evidence = try VPNRouteKernelEvidence(gateway: Optional<in_addr>.none, interfaceIndex: context.bIndex, flags: flags) }
            else { evidence = try VPNRouteKernelEvidence(gateway: Optional<in6_addr>.none, interfaceIndex: context.bIndex, flags: flags) }
            identities.append(try VPNOwnedRouteIdentity(planned: planned, evidence: evidence))
        }
        state = BaselineState(identities: identities, states: identities.map { _ in "planned" })
        try save()
    }
    private func save() throws { try namespace.write("baseline.json", canonicalData(state)) }
    func install() throws {
        for index in state.identities.indices {
            let identity = state.identities[index]
            try check(try kernel.lookupExact(identity.lookupKey) == nil, .route)
            state.states[index] = "issued"; try save()
            do {
                guard try kernel.add(identity) == .installed else {
                    // A raced identical/preexisting route is not our receipt.
                    state.states[index] = "foreign"; try save(); throw Failure.receipt
                }
                // Positive receipt is retained in memory BEFORE persistence.
                // If saving fails, cleanup may use this observed .installed;
                // a later process seeing only issued must never infer it.
                state.states[index] = "confirmed"; try save()
            } catch {
                if state.states[index] == "issued" {
                    state.states[index] = "unknown"; try? save()
                }
                diagnostic(identity, kernel); throw error
            }
        }
    }
    func verify() throws {
        for identity in state.identities { try check(try kernel.lookupExact(identity.lookupKey)?.matches(identity) == true, .route) }
    }
    func cleanup() throws {
        // Equality cannot upgrade issued/unknown/foreign to positive custody.
        // Only this process's confirmed .installed receipt permits DELETE.
        for index in state.identities.indices.reversed() where state.states[index] == "confirmed" {
            let identity = state.identities[index]
            if let current = try kernel.lookupExact(identity.lookupKey) {
                guard current.matches(identity) else { state.states[index] = "unknown"; try save(); throw Failure.receipt }
                try check(try kernel.delete(identity) == .removed, .cleanup)
            }
            state.states[index] = "removed"; try save()
        }
        // Preserve the ledger/namespace even if an uncertain candidate currently
        // matches or is absent. VM disposal may close its owned interface, but
        // that is never represented as an explicit owned-route deletion.
        try check(state.states.allSatisfy { $0 == "planned" || $0 == "removed" }, .receipt)
    }
}
private func diagnostic(_ identity: VPNOwnedRouteIdentity, _ kernel: VPNDarwinRouteSocket) {
    // Only metadata for the exact synthetic fixture key, no names/state dump.
    let observed = try? kernel.lookupExact(identity.lookupKey)
    print("API ownRoute expectedFlags=\(identity.flags) observedFlags=\(observed?.flags ?? 0) expectedIndex=\(identity.interfaceIndex) observedIndex=\(observed?.interfaceIndex ?? 0)")
}

private func childOperation(_ id: String, _ family: Int32, _ tcp: Bool, _ scope: String) throws {
    let namespace = try Namespace(id, create: false), context = try Context.load(namespace)
    let authority = try Authority(namespace, context), binding = try authority.binding(family)
    let end = deadline(), limit = DispatchTime(uptimeNanoseconds: end)
    let phase = (tcp ? "tcp" : "udp") + (family == AF_INET ? "4" : "6") + scope
    if scope == "a" {
        let socket = try VPNBoundDNSUpstreamSocket.prepare(binding: binding, transport: tcp ? .tcp : .udp,
            authority: authority, deadline: limit, syscalls: RecordingCalls())
        try check(!tcp, .child) // No userland TCP stack is implemented.
        let question = Wire.question(id, phase, family)
        try check(try socket.exchange(question: question, deadline: limit) == Wire.answer(question, family), .packet)
    } else {
        // Explicit control experiment, not an alternate production socket API.
        let calls = RecordingCalls(), fd = try calls.socket(family: family, transport: tcp ? .tcp : .udp)
        defer { calls.close(fd) }
        try calls.configure(fd)
        if scope == "b" { try calls.bindInterface(fd, family: family, index: context.bIndex) }
        let checkScope = {
            let (value, size) = try calls.boundInterface(fd, family: family)
            try check(size == 4 && value == (scope == "b" ? context.bIndex : 0), .path)
        }
        do { try authority.withCurrentAuthority(binding: binding, deadline: limit) { try checkScope(); try calls.connect(fd, binding: binding) } }
        catch VPNBoundDNSUpstreamError.posix(let code) where tcp && code == EINPROGRESS {}
        if tcp {
            print("READY control"); fflush(stdout)
            var byte: UInt8 = 0
            while Darwin.read(STDIN_FILENO, &byte, 1) > 0 {}
            throw Failure.child
        }
        let question = Wire.question(id, phase, family)
        try authority.withCurrentAuthority(binding: binding, deadline: limit) {
            try checkScope(); try check(try calls.send(fd, bytes: question, offset: 0) == question.count, .packet)
        }
        var answer: Data?
        while answer == nil {
            do {
                answer = try authority.withCurrentAuthority(binding: binding, deadline: limit) {
                    try checkScope(); let (data, truncated) = try calls.receive(fd, maximum: 4096, datagram: true)
                    try check(!truncated, .packet); return data
                }
            } catch VPNBoundDNSUpstreamError.posix(let code) where code == EAGAIN || code == EWOULDBLOCK || code == EINTR {
                _ = try calls.poll(fd, events: Int16(POLLIN), milliseconds: remaining(end))
            }
        }
        try check(answer == Wire.answer(question, family), .packet)
    }
    print("PASS exchange"); fflush(stdout)
}
private func childCrash(_ id: String) throws {
    let namespace = try Namespace(id, create: false), context = try Context.load(namespace)
    let plan = try context.plan()
    let lease = try VPNLifecycleOwnership.acquireRuntime(inTrustedDirectory: namespace.descriptor)
    defer { lease.release() }
    let journal = try VPNRouteJournal(trustedDirectoryDescriptor: namespace.descriptor)
    let kernel = try VPNDarwinRouteSocket.production()
    let crash = CrashKernel(kernel)
    do { _ = try VPNRouteTransaction(journal: journal, kernel: crash, runtimeLease: lease).install(plan.staticRoutes) }
    catch {
        if let entry = try? journal.load().operation?.entry { diagnostic(entry, kernel) }
        throw error
    }
    throw Failure.child
}
private func childDeath(_ id: String) throws {
    let namespace = try Namespace(id, create: false), context = try Context.load(namespace)
    let authority = try Authority(namespace, context)
    let limit = DispatchTime(uptimeNanoseconds: deadline())
    let pairs = try [AF_INET,AF_INET6].map { family in
        (family, try VPNBoundDNSUpstreamSocket.prepare(binding: authority.binding(family), transport: .udp,
            authority: authority, deadline: limit, syscalls: RecordingCalls()))
    }
    print("READY bound"); fflush(stdout)
    var byte: UInt8 = 0
    try check(Darwin.read(STDIN_FILENO, &byte, 1) == 1 && byte == 71, .child)
    for (family,socket) in pairs {
        do {
            _ = try socket.exchange(question: Wire.question(id, family == AF_INET ? "death4" : "death6", family), deadline: limit)
            throw Failure.path
        } catch VPNDarwinRouteError.invalidIdentity {}
        catch VPNRouteTransactionError.notApplied {}
        catch VPNBoundDNSUpstreamError.invalidInterface {}
        print("PASS rejected\(family == AF_INET ? 4 : 6)"); fflush(stdout)
    }
}
private func childSIGPIPE(_ protected: Bool) throws {
    var set = sigset_t(); sigemptyset(&set); sigaddset(&set, SIGPIPE)
    try check(pthread_sigmask(SIG_UNBLOCK, &set, nil) == 0, .sigpipe)
    signal(SIGPIPE, SIG_DFL)
    var pair: [Int32] = [-1,-1]
    try check(socketpair(AF_UNIX, SOCK_STREAM, 0, &pair) == 0, .sigpipe)
    defer { if pair[0] >= 0 { close(pair[0]) }; if pair[1] >= 0 { close(pair[1]) } }
    close(pair[1]); pair[1] = -1
    let calls = VPNDarwinDNSUpstreamSyscalls()
    let role: SocketDiagnostic.Role = protected ? .protected : .baseline
    SocketDiagnostic.emit(role, .signalState, 0) // Default/unblocked established above.
    if protected { try SocketDiagnostic.configure(calls, pair[0], role) }
    SocketDiagnostic.emit(role, .sendBegin)
    do {
        do { _ = try calls.send(pair[0], bytes: Data([1]), offset: 0) }
        catch { SocketDiagnostic.emit(role, .sendError, SocketDiagnostic.number(error)); throw error }
        SocketDiagnostic.emit(role, .sendOK); throw Failure.sigpipe
    } catch VPNBoundDNSUpstreamError.posix(let code) where protected && code == EPIPE {
        print("PASS protected-EPIPE"); fflush(stdout)
    }
}

private final class Child {
    let process = Process(), output = Pipe()
    private var control: Int32 = -1
    private var buffer = Data()
    private var diagnosticCount = 0
    var markers = Set<String>(), ports: [Int32:Int] = [:]
    init(_ arguments: [String]) throws {
        var pair: [Int32] = [-1,-1]
        try check(socketpair(AF_UNIX, SOCK_STREAM, 0, &pair) == 0, .child)
        control = pair[0]
        var inputFD = pair[1]
        defer { if inputFD >= 0 { close(inputFD) } }
        do {
            try SocketDiagnostic.configure(VPNDarwinDNSUpstreamSyscalls(), control, .childControl)
            try check(fcntl(inputFD, F_SETFD, FD_CLOEXEC) == 0, .child)
            let input = FileHandle(fileDescriptor: inputFD, closeOnDealloc: false)
            process.executableURL = URL(fileURLWithPath: CommandLine.arguments[0]).standardizedFileURL
            process.arguments = arguments; process.standardInput = input
            process.standardOutput = output; process.standardError = FileHandle.nullDevice
            SocketDiagnostic.emit(.childControl, .childLaunch)
            try process.run(); try input.close(); inputFD = -1
            let fd = output.fileHandleForReading.fileDescriptor, flags = fcntl(fd, F_GETFL)
            try check(flags >= 0 && fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0, .child)
        } catch {
            if process.isRunning { kill(process.processIdentifier, SIGKILL) }
            if process.processIdentifier > 0 { process.waitUntilExit() }
            if control >= 0 { close(control); control = -1 }
            throw error
        }
    }
    deinit {
        if process.isRunning { kill(process.processIdentifier, SIGKILL) }
        if control >= 0 { close(control) }
        try? output.fileHandleForReading.close()
    }
    func release() throws {
        let count = Data([71]).withUnsafeBytes { Darwin.send(control, $0.baseAddress, 1, 0) }
        try check(count == 1, .child)
    }
    func drain() throws {
        var bytes = [UInt8](repeating: 0, count: 512)
        while true {
            let count = bytes.withUnsafeMutableBytes { Darwin.read(output.fileHandleForReading.fileDescriptor, $0.baseAddress, $0.count) }
            if count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK) { break }
            if count < 0 && errno == EINTR { continue }
            try check(count >= 0, .child)
            if count == 0 { break }
            buffer.append(contentsOf: bytes.prefix(count)); try check(buffer.count <= 4096, .child)
            while let newline = buffer.firstIndex(of: 10) {
                guard let line = String(data: buffer.prefix(upTo: newline), encoding: .utf8) else { throw Failure.child }
                buffer.removeSubrange(...newline)
                let pieces = line.split(separator: " ")
                if pieces.count == 2, ["PORT4","PORT6"].contains(String(pieces[0])), let port = Int(pieces[1]), (1...65535).contains(port) {
                    let family = pieces[0] == "PORT4" ? AF_INET : AF_INET6
                    try check(ports[family] == nil, .child); ports[family] = port
                } else if ["PASS exchange","PASS rejected4","PASS rejected6","PASS protected-EPIPE","READY mutation","READY bound","READY polling","READY control"].contains(line) {
                    try check(!markers.contains(line), .child); markers.insert(line)
                } else if SocketDiagnostic.accepts(line) {
                    // Diagnostics are observations, never readiness/proof markers.
                    try check(diagnosticCount < 64, .child); diagnosticCount += 1
                    print(line); fflush(stdout)
                } else {
                    // Only a closed numeric diagnostic protocol is forwarded.
                    let allowedFailures = Failure.allCases.map(\.rawValue) + ["upstream","routeAPI","unexpected"]
                    if (pieces.count >= 2 && allowedFailures.contains(String(pieces[1]))
                        && line.range(of: #"^FAIL [A-Za-z]+( errno=[0-9]+)?$"#, options: .regularExpression) != nil)
                        || line.range(of: #"^API ownRoute expectedFlags=[0-9]+ observedFlags=[0-9]+ expectedIndex=[0-9]+ observedIndex=[0-9]+$"#, options: .regularExpression) != nil { print(line) }
                    throw Failure.child
                }
            }
        }
    }
    func stop() throws {
        if process.isRunning { try check(kill(process.processIdentifier, SIGKILL) == 0, .child) }
        let end = deadline(2)
        while process.isRunning { _ = try remaining(end); usleep(5000) }
        process.waitUntilExit()
    }
    func waitForExit(_ end: UInt64) throws {
        while process.isRunning { try drain(); _ = try remaining(end); usleep(5000) }
        process.waitUntilExit(); try drain()
        try check(buffer.isEmpty, .child)
    }
}

private func configure(_ interface: UTUN, _ v4: String, _ peer: String, _ v6: String) throws {
    // Only names obtained from our still-held exclusive control descriptors.
    for arguments in [[interface.name,"inet",v4,peer,"netmask","255.255.255.255","up"],
                      [interface.name,"inet6",v6,"prefixlen","128","-dad"]] {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/sbin/ifconfig"); process.arguments = arguments
        process.standardOutput = FileHandle.nullDevice; process.standardError = FileHandle.nullDevice
        try process.run()
        let end = deadline(5)
        while process.isRunning {
            if DispatchTime.now().uptimeNanoseconds >= end {
                kill(process.processIdentifier, SIGKILL); process.waitUntilExit(); throw Failure.timeout
            }
            usleep(5000)
        }
        process.waitUntilExit(); try check(process.terminationStatus == 0, .address)
    }
}
private func readPackets(_ interface: UTUN, _ handle: (Wire.Packet) throws -> Void) throws {
    guard interface.descriptor >= 0 else { return }
    for _ in 0..<256 {
        var bytes = [UInt8](repeating: 0, count: 4096)
        let count = bytes.withUnsafeMutableBytes { Darwin.read(interface.descriptor, $0.baseAddress, $0.count) }
        if count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK) { return }
        if count < 0 && errno == EINTR { continue }
        try check(count > 0 && count < bytes.count, .packet)
        if let packet = Wire.packet(Data(bytes.prefix(count))) { try handle(packet) }
    }
    throw Failure.packet // Never drain/capture an unbounded interface stream.
}
private func observe(_ id: String, _ family: Int32, _ tcp: Bool, _ scope: String,
                     _ a: UTUN, _ b: UTUN, _ namespace: Namespace) throws {
    let phase = (tcp ? "tcp" : "udp") + (family == AF_INET ? "4" : "6") + scope
    let child = try Child(["--operation",id,family == AF_INET ? "4" : "6",tcp ? "tcp" : "udp",scope])
    var observed = false, operationError: Error?
    let end = deadline()
    let expected = scope == "a" ? a.index : b.index
    let question = Wire.question(id, phase, family)
    let destination = Wire.ip(family == AF_INET ? Context.server4 : Context.server6, family)
    do {
        while true {
            try child.drain()
            for interface in (tcp && child.ports[family] == nil ? [] : [a,b]) {
                try readPackets(interface) { packet in
                    guard packet.family == family && packet.destination == destination && packet.destinationPort == 53 else { return }
                    // UDP requires the exact nonce DNS message; TCP requires
                    // the exact ephemeral port published by our own child FD.
                    if tcp {
                        guard !packet.isUDP && packet.isSYN && packet.sourcePort == child.ports[family] else { return }
                    } else { guard packet.isUDP && packet.payload == question else { return } }
                    let source = Wire.ip(family == AF_INET ? (interface === a ? Context.a4 : Context.b4)
                                         : (interface === a ? Context.a6 : Context.b6), family)
                    try check(interface.index == expected && packet.source == source, .path)
                    if let port = child.ports[family] { try check(packet.sourcePort == port, .sourcePort) }
                    observed = true
                    if !tcp {
                        let answer = Wire.udp(family: family, source: packet.destination, destination: packet.source,
                            sport: 53, dport: packet.sourcePort, payload: Wire.answer(question, family))
                        let count = answer.withUnsafeBytes { Darwin.write(interface.descriptor, $0.baseAddress, $0.count) }
                        try check(count == answer.count, .packet)
                    }
                }
            }
            if tcp && observed && child.markers.contains(scope == "a" ? "READY polling" : "READY control") {
                try check(child.process.isRunning, .child)
                // This must be obtainable while the real class is polling its
                // pending TCP connect: no service lease held for socket life.
                let lease = try VPNLifecycleOwnership.acquireRuntime(inTrustedDirectory: namespace.descriptor)
                lease.release()
                try child.stop()
                try check(child.process.terminationReason == .uncaughtSignal && child.process.terminationStatus == SIGKILL, .child)
                break
            }
            if !child.process.isRunning {
                try child.waitForExit(end)
                try check(!tcp && observed && child.process.terminationStatus == 0 && child.markers.contains("PASS exchange"), .child)
                break
            }
            let awaitingPort = tcp && child.ports[family] == nil
            var items = [pollfd(fd: awaitingPort ? -1 : a.descriptor, events: Int16(POLLIN), revents: 0),
                         pollfd(fd: awaitingPort ? -1 : b.descriptor, events: Int16(POLLIN), revents: 0),
                         pollfd(fd: child.output.fileHandleForReading.fileDescriptor, events: Int16(POLLIN), revents: 0)]
            let result = Darwin.poll(&items, nfds_t(items.count), try remaining(end))
            try check(result >= 0 || errno == EINTR, .packet)
        }
    } catch { operationError = error }
    do { try child.stop() } catch { operationError = operationError ?? error }
    if let operationError { throw operationError }
    print("PASS " + phase + (tcp ? "-own-first-SYN-only" : "-own-nonce-DNS-exchange"))
}
private func crashAndRecover(_ id: String, _ namespace: Namespace, _ baseline: Baseline) throws {
    let child = try Child(["--crash",id])
    var operationError: Error?
    do {
        try child.waitForExit(deadline())
        try check(child.process.terminationReason == .uncaughtSignal && child.process.terminationStatus == SIGKILL
                  && child.markers.contains("READY mutation"), .child)
        try withTransaction(namespace) { transaction, journal, _ in
            let snapshot = try journal.load()
            try check(snapshot.phase == .installing && snapshot.operation?.entry.role == .dnsDependency, .receipt)
            try transaction.recoverToIdle()
            do { _ = try journal.load(); throw Failure.receipt } catch VPNRouteJournalError.missing {}
        }
        try baseline.verify()
    } catch { operationError = error }
    do { try child.stop() } catch { operationError = operationError ?? error }
    if let operationError { throw operationError }
    print("PASS actual-child-SIGKILL-checkpoint-recovery-B-preserved")
}
private func death(_ id: String, _ namespace: Namespace, _ a: UTUN, _ b: UTUN) throws {
    let child = try Child(["--death",id])
    var operationError: Error?, released = false
    let before = try namespace.read(VPNRouteJournal.name)
    let end = deadline()
    do {
        while child.process.isRunning {
            try child.drain()
            if child.markers.contains("READY bound") && !released {
                try check(child.ports[AF_INET] != nil && child.ports[AF_INET6] != nil, .sourcePort)
                try a.stop()
                try namespace.write("receipt-preserved", Data("expected-dead-interface\n".utf8))
                try child.release(); released = true
            }
            try readPackets(b) { packet in
                if packet.isUDP && [AF_INET,AF_INET6].contains(packet.family)
                    && packet.payload == Wire.question(id, packet.family == AF_INET ? "death4" : "death6", packet.family) {
                    throw Failure.path
                }
            }
            var item = pollfd(fd: child.output.fileHandleForReading.fileDescriptor, events: Int16(POLLIN), revents: 0)
            let result = Darwin.poll(&item, 1, try remaining(end))
            try check(result >= 0 || errno == EINTR, .child)
        }
        try child.waitForExit(end)
        try check(released && child.process.terminationStatus == 0 && child.markers.contains("PASS rejected4")
                  && child.markers.contains("PASS rejected6"), .child)
        // Bounded final drain of only our B control FD and own nonce categories.
        try readPackets(b) { packet in
            if packet.isUDP && packet.payload == Wire.question(id, packet.family == AF_INET ? "death4" : "death6", packet.family) { throw Failure.path }
        }
        do {
            try withTransaction(namespace) { transaction, _, _ in try transaction.recoverToIdle() }
            throw Failure.receipt
        } catch VPNRouteTransactionError.recoveryRequired {}
        let after = try namespace.read(VPNRouteJournal.name)
        try check(before.0 == after.0 && before.1 == after.1, .receipt)
    } catch { operationError = error }
    do { try child.stop() } catch { operationError = operationError ?? error }
    if let operationError { throw operationError }
    print("PASS A-death-rejected-both-families-no-own-B-nonce")
    print("PASS dead-interface-recovery-blocked-receipt-preserved")
}
private func sigpipe() throws {
    for protected in [false,true] {
        let child = try Child([protected ? "--sigpipe-protected" : "--sigpipe-baseline"])
        var operationError: Error?
        do {
            try child.waitForExit(deadline(5))
            if protected { try check(child.process.terminationStatus == 0 && child.markers.contains("PASS protected-EPIPE"), .sigpipe) }
            else { try check(child.process.terminationReason == .uncaughtSignal && child.process.terminationStatus == SIGPIPE, .sigpipe) }
        } catch { operationError = error }
        do { try child.stop() } catch { operationError = operationError ?? error }
        if let operationError { throw operationError }
    }
    print("PASS production-configure-SIGPIPE-baseline-13-protected-EPIPE")
}

private func namespaceNames(_ namespace: Namespace) throws -> Set<String> {
    let fd = dup(namespace.descriptor)
    guard fd >= 0, let directory = fdopendir(fd) else { if fd >= 0 { close(fd) }; throw Failure.namespace }
    defer { closedir(directory) }
    var names = Set<String>()
    while let entry = readdir(directory) {
        let name = withUnsafePointer(to: &entry.pointee.d_name) {
            $0.withMemoryRebound(to: CChar.self, capacity: Int(MAXNAMLEN) + 1) { String(cString: $0) }
        }
        if name == "." || name == ".." { continue }
        names.insert(name); try check(names.count <= 16, .namespace)
    }
    return names
}
private func acceptance(_ id: String) throws {
    let namespace = try Namespace(id, create: true)
    var a: UTUN?, b: UTUN?, baseline: Baseline?
    var operationError: Error?, preserve = false
    do {
        // Own namespace only; no service lock/path from an installed helper.
        let lease = try VPNLifecycleOwnership.acquireRuntime(inTrustedDirectory: namespace.descriptor)
        lease.release(); try namespace.remember(VPNLifecycleLease.runtimeLockName)
        try sigpipe()
        let before = try VPNKernelInterfaceSnapshot.capture()
        let fixtureAddresses = try [Context.a4,Context.b4,Context.a6,Context.b6,Context.server4,Context.server6,Context.peer].map {
            try OpenVPNIPAddress(parsing: Substring($0), family: $0.contains(":") ? .ipv6 : .ipv4)
        }
        try check(!before.interfaces.contains(where: { interface in fixtureAddresses.contains(where: interface.addresses.contains) }), .address)
        a = try UTUN(); b = try UTUN()
        let ownedA = a!, ownedB = b!
        try check(ownedA.index != ownedB.index && ownedA.name != ownedB.name
            && !before.interfaces.contains(where: { $0.index == ownedA.index || $0.name == ownedA.name || $0.index == ownedB.index || $0.name == ownedB.name }), .interface)
        try configure(ownedA, Context.a4, "192.0.2.2", Context.a6)
        try configure(ownedB, Context.b4, "192.0.2.6", Context.b6)
        let context = Context(id: id, parent: getpid(), aIndex: ownedA.index, aName: ownedA.name,
            bIndex: ownedB.index, bName: ownedB.name)
        _ = try context.evidence()
        try namespace.write("context.json", canonicalData(context))
        baseline = try Baseline(namespace, context); try baseline!.install()
        let network = try context.plan()
        try withTransaction(namespace) { transaction, _, kernel in
            do { _ = try transaction.install(network.staticRoutes) }
            catch { for identity in try VPNRouteIdentityFactory.make(plan: network.staticRoutes) { diagnostic(identity, kernel) }; throw error }
        }
        try baseline!.verify()
        for family in [AF_INET,AF_INET6] {
            for tcp in [false,true] {
                for scope in ["n","b","a"] { try observe(id, family, tcp, scope, ownedA, ownedB, namespace) }
            }
        }
        try baseline!.verify()
        try withTransaction(namespace) { transaction, journal, _ in
            try transaction.recoverToIdle()
            do { _ = try journal.load(); throw Failure.receipt } catch VPNRouteJournalError.missing {}
        }
        try baseline!.verify()
        print("PASS live-A-complete-route-cleanup-B-foreign-tables-preserved")
        try crashAndRecover(id, namespace, baseline!)
        _ = try withTransaction(namespace) { transaction, _, _ in try transaction.install(network.staticRoutes) }
        try death(id, namespace, ownedA, ownedB)
        preserve = true
    } catch { operationError = error }
    // No recursive/prefix cleanup, and never delete an unknown route identity.
    // A-death has an EXPECTED unresolved production receipt until VM disposal.
    if a?.descriptor ?? -1 >= 0 {
        do { try withTransaction(namespace) { transaction, _, _ in try transaction.recoverToIdle() } }
        catch { preserve = true; operationError = operationError ?? error }
    }
    if let baseline {
        do { try baseline.cleanup() }
        catch { preserve = true; operationError = operationError ?? error }
    }
    do { try a?.stop(); try b?.stop() }
    catch { preserve = true; operationError = operationError ?? error }
    if operationError == nil {
        try check(preserve, .receipt)
        for name in ["baseline.json","context.json",VPNLifecycleLease.runtimeLockName] { try namespace.remove(name) }
        try check(try namespaceNames(namespace) == [VPNRouteJournal.name,"receipt-preserved"], .receipt)
        print("PASS B-baseline-exact-cleanup-owned-utuns-gone")
        print("PASS protected-pending-receipt-only-until-VM-disposal")
    } else {
        // The caller NEVER rmtree()s this namespace, including failure paths.
        if (try? namespaceNames(namespace).contains(VPNRouteJournal.name)) == true { preserve = true }
        if preserve { try? namespace.write("receipt-preserved", Data("unknown-preserve\n".utf8)) }
        if !preserve && (try? namespaceNames(namespace).contains(VPNRouteJournal.name)) == false {
            for name in ["baseline.json","context.json",VPNLifecycleLease.runtimeLockName] where namespace.files[name] != nil { try? namespace.remove(name) }
            if (try? namespaceNames(namespace).isEmpty) == true { _ = rmdir(namespace.path) }
            else { try? namespace.write("receipt-preserved", Data("unknown-preserve\n".utf8)) }
        }
    }
    if let operationError { throw operationError }
}

private func pure() throws {
    let environment = ["GITHUB_ACTIONS":"true",flag:"1"]
    try check(allowed(0,0,environment), .arguments)
    for ids: (uid_t,uid_t) in [(501,501),(0,501),(501,0)] { try check(!allowed(ids.0,ids.1,environment), .arguments) }
    for missing in [[:],["GITHUB_ACTIONS":"true"],[flag:"1"]] { try check(!allowed(0,0,missing), .arguments) }
    try check(SocketDiagnostic.accepts("API socket role=protected stage=sendError value=32"), .arguments)
    for invalid in ["API socket role=secret stage=sendError value=32", "API socket role=protected stage=path value=32",
                    "API socket role=protected stage=sendError value=2147483648", "API socket role=protected stage=sendError value=32 secret"] {
        try check(!SocketDiagnostic.accepts(invalid), .arguments)
    }
    let id = "12345678-1234-1234-1234-123456789abc"
    try check(validID(id) && !validID(id.uppercased()) && !validID("../route"), .arguments)
    // Independent known RFC1071 checksum vector, not just roundtripping encoder.
    try check(Wire.checksum([0,1,0xf2,3,0xf4,0xf5,0xf6,0xf7]) == 0x220d, .packet)
    for family in [AF_INET,AF_INET6] {
        let source = Wire.ip(family == AF_INET ? Context.a4 : Context.a6, family)
        let destination = Wire.ip(family == AF_INET ? Context.server4 : Context.server6, family)
        let question = Wire.question(id,"udp",family)
        let data = Wire.udp(family: family, source: source, destination: destination, sport: 12345, dport: 53, payload: question)
        guard let packet = Wire.packet(data) else { throw Failure.packet }
        try check(packet.family == family && packet.payload == question && packet.sourcePort == 12345 && packet.destinationPort == 53, .packet)
        let bytes = Array(data.dropFirst(4)), offset = family == AF_INET ? 20 : 40, length = bytes.count - offset
        if family == AF_INET { try check(Wire.checksum(Array(bytes.prefix(20))) == 0, .packet) }
        let pseudo = Wire.pseudoHeader(family, source, destination, length)
        try check(Wire.checksum(pseudo + Array(bytes.dropFirst(offset))) == 0, .packet)
        let response = Wire.answer(question,family)
        try check(response[2] & 0x80 != 0 && response[7] == 1 && response.count > question.count, .packet)
        try check(response.suffix(family == AF_INET ? 4 : 16) == Data(Wire.ip(family == AF_INET ? "192.0.2.53" : "2001:db8::53", family)), .packet)
        // TCP selection parser only; no TCP stack/handshake is simulated.
        var tcpHeader = [UInt8](repeating: 0, count: 20)
        tcpHeader.replaceSubrange(0..<2, with: Wire.put16(12345)); tcpHeader[3] = 53
        tcpHeader[12] = 0x50; tcpHeader[13] = 2
        var ipHeader = Array(bytes.prefix(offset))
        if family == AF_INET {
            ipHeader[9] = 6; ipHeader.replaceSubrange(2..<4, with: Wire.put16(40))
        } else { ipHeader[6] = 6; ipHeader.replaceSubrange(4..<6, with: Wire.put16(20)) }
        var syn = Data(data.prefix(4)); syn.append(contentsOf: ipHeader + tcpHeader)
        try check(Wire.packet(syn)?.isSYN == true && Wire.packet(syn)?.isUDP == false, .packet)
        syn[4 + offset + 13] = 0x12; try check(Wire.packet(syn)?.isSYN == false, .packet)
        for count in [0,3,12,23] { try check(Wire.packet(data.prefix(count)) == nil, .packet) }
        var wrongFamily = data; wrongFamily[3] = 99; try check(Wire.packet(wrongFamily) == nil, .packet)
    }
    print("PASS pure-guards-packets-checksums")
}
private func report(_ error: Error) {
    if let failure = error as? Failure { print("FAIL " + failure.rawValue) }
    else if case VPNBoundDNSUpstreamError.posix(let number) = error { print("FAIL upstream errno=\(max(0,number))") }
    else if let failure = error as? VPNBoundDNSUpstreamError {
        switch failure {
        case .timeout: print("FAIL timeout")
        case .invalidInterface: print("FAIL interface")
        case .bindingFailed: print("FAIL path")
        case .invalidMessage, .truncated: print("FAIL packet")
        case .invalidBinding: print("FAIL context")
        default: print("FAIL upstream")
        }
    }
    else if let failure = error as? VPNDarwinRouteError { print("FAIL routeAPI errno=\(max(0,failure.vpnFlowErrorNumber))") }
    else if error is VPNRouteTransactionError || error is VPNRouteJournalError { print("FAIL routeAPI") }
    else { print("FAIL unexpected") }
}
@main private struct Main {
    static func main() {
        do {
            let args = Array(CommandLine.arguments.dropFirst())
            if args == ["--pure-checks"] { try pure(); return }
            // Before C socket allocation, interface inspection/configuration,
            // PF_ROUTE, private AF_UNIX pairs, filesystem mutation or child IO.
            try check(allowed(getuid(),geteuid(),ProcessInfo.processInfo.environment), .guardDenied)
            if args.count == 2 && args[0] == "--acceptance" && validID(args[1]) { try acceptance(args[1]) }
            else if args.count == 5 && args[0] == "--operation" && validID(args[1])
                && ["4","6"].contains(args[2]) && ["udp","tcp"].contains(args[3]) && ["a","b","n"].contains(args[4]) {
                try childOperation(args[1], args[2] == "4" ? AF_INET : AF_INET6, args[3] == "tcp", args[4])
            } else if args.count == 2 && args[0] == "--crash" && validID(args[1]) { try childCrash(args[1]) }
            else if args.count == 2 && args[0] == "--death" && validID(args[1]) { try childDeath(args[1]) }
            else if args == ["--sigpipe-baseline"] { try childSIGPIPE(false) }
            else if args == ["--sigpipe-protected"] { try childSIGPIPE(true) }
            else { throw Failure.arguments }
        } catch { report(error); exit(1) }
    }
}
