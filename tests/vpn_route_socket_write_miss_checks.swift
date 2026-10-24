import Darwin
import Foundation

// Test binary only: no host interface lookup, even for scoped codec validation.
@_cdecl("if_indextoname")
func writeMissInterface(_ index: UInt32, _ output: UnsafeMutablePointer<CChar>?) -> UnsafeMutablePointer<CChar>? {
    guard let output, let name = [7:"en7",42:"utun42"][index] else { return nil }
    for (i,c) in name.utf8CString.enumerated() { output[i] = c }; return output
}
private final class Transport: VPNRouteSocketTransport {
    var sent = [rt_msghdr](), queue = [Data](), reads = 0, deadlines = [UInt64]()
    var onSend: ((rt_msghdr) throws -> Void)?, readError: Int32?
    func send(_ bytes: Data, deadline: DispatchTime) throws {
        let header = try VPNDarwinRouteCodec.identify(bytes)
        sent.append(header); deadlines.append(deadline.uptimeNanoseconds)
        try onSend?(header)
    }
    func receive(maximumBytes: Int, deadline: DispatchTime) throws -> Data {
        reads += 1; deadlines.append(deadline.uptimeNanoseconds)
        if let readError { throw VPNRouteSocketTransportError.posix(readError) }
        guard !queue.isEmpty else { throw VPNRouteSocketTransportError.timeout }
        return queue.removeFirst()
    }
    func enqueue(_ header: rt_msghdr, error: Int32 = ESRCH, identity: VPNOwnedRouteIdentity? = nil,
                 pid: Int32? = nil, sequence: Int32? = nil, type: UInt8? = nil) throws {
        queue.append(try VPNDarwinRouteCodec.encodeReply(type: type ?? header.rtm_type,
            sequence: sequence ?? header.rtm_seq, pid: pid ?? header.rtm_pid, error: error, identity: identity))
    }
}
@main private enum Checks {
    enum Failure: Error { case check }
    static func check(_ value: @autoclosure () throws -> Bool) throws { if try !value() { throw Failure.check } }
    static func ip(_ text: String) -> in_addr {
        var value = in_addr(); precondition(text.withCString { inet_pton(AF_INET,$0,&value) } == 1); return value
    }
    static func plan(_ family: VPNRouteAddressFamily, dependency: Bool = false) throws -> VPNRoutePlan {
        let v4 = try OpenVPNIPAddress(parsing:"10.255.254.1",family:.ipv4)
        let v6 = try OpenVPNIPAddress(parsing:"fd00::1",family:.ipv6)
        let tunnel = try VPNTunnelInterfaceResolver.resolve(baseline:VPNKernelInterfaceSnapshot(interfaces:[]),
            after:VPNKernelInterfaceSnapshot(interfaces:[VPNKernelInterfaceRecord(index:42,name:"utun42",isUp:true,isRunning:true,isPointToPoint:true,addresses:[v4,v6])]),
            management:OpenVPNConnectedEvidence(tunnelLocalIPv4:v4,tunnelLocalIPv6:v6,
                remoteAddress:OpenVPNIPAddress(parsing:"198.51.100.9",family:.ipv4),remotePort:443))
        let resources = dependency ? [] : [try VPNResource(address:family == .ipv4 ? "10.0.0.0/8":"2001:db8::/32")]
        let dependencies = dependency ? [try VPNRoutePrefix(resource:VPNResource(address:family == .ipv4 ? "10.0.0.1":"2001:db8::1"))] : []
        return try VPNRoutePlan(generation:7,revision:11,resources:resources,
            peer:VPNRoutePeerEvidence(peer:ip("198.51.100.9"),gateway:ip("192.0.2.1"),interfaceIndex:7),
            tunnel:tunnel,dnsDependencies:dependencies)
    }
    static func identity(_ family: VPNRouteAddressFamily, scoped: Bool) throws -> VPNOwnedRouteIdentity {
        let prefix = try VPNRoutePrefix(resource:VPNResource(address:family == .ipv4 ? "10.0.0.1":"2001:db8::1"))
        let scope = scoped ? try plan(family).tunnelInterface : nil
        let route = VPNPlannedRoute(role:scoped ? .dnsDependency:.resource,destination:prefix,
            physicalGatewayBytes:nil,interfaceIndex:42,interfaceName:"utun42",interfaceScope:scope)
        let flags = UInt32(RTF_UP | RTF_STATIC | RTF_HOST | RTF_PROTO2) | (scoped ? UInt32(RTF_IFSCOPE):0)
        if family == .ipv4 { return try VPNOwnedRouteIdentity(planned:route,evidence:VPNRouteKernelEvidence(gateway:Optional<in_addr>.none,interfaceIndex:42,flags:flags)) }
        return try VPNOwnedRouteIdentity(planned:route,evidence:VPNRouteKernelEvidence(gateway:Optional<in6_addr>.none,interfaceIndex:42,flags:flags))
    }
    static func transportFailure(_ code: Int32, _ body: () throws -> Void) throws {
        do { try body(); throw Failure.check } catch VPNDarwinRouteError.transport(let actual) { try check(actual == code) }
    }
    static func recover(_ path: String) throws {
        for family in [VPNRouteAddressFamily.ipv4,.ipv6] { for scoped in [false,true] { for applied in [false,true] {
            let name = "\(family.rawValue)-\(scoped)-\(applied)"
            let folder = URL(fileURLWithPath:path).appendingPathComponent(name)
            try FileManager.default.createDirectory(at:folder,withIntermediateDirectories:false,attributes:[.posixPermissions:0o700])
            let fd = open(folder.path,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC); try check(fd >= 0); defer { close(fd) }
            let journal = try VPNRouteJournal(trustedDirectoryDescriptor:fd), plan = try plan(family,dependency:scoped)
            let entries = try VPNRouteIdentityFactory.make(plan:plan)
            try journal.create(plan)
            for (ordinal, entry) in entries.enumerated() {
                try journal.beginInstall(entry,generation:7,revision:11)
                if applied || ordinal < entries.count - 1 {
                    try journal.resolveInstall(entry,present:true,generation:7,revision:11)
                }
            }
            let snapshot = try journal.load()
            try check(applied ? snapshot.phase == .applied : snapshot.operation?.action == .install)
            let file = folder.appendingPathComponent(VPNRouteJournal.name), before = try Data(contentsOf:file)
            let fake = Transport(); fake.readError = ESRCH
            let lease = try VPNLifecycleOwnership.acquireRuntime(inTrustedDirectory:fd); defer { lease.release() }
            let transaction = VPNRouteTransaction(journal:journal,kernel:VPNDarwinRouteSocket(transport:fake,pid:414),runtimeLease:lease)
            do { try transaction.recoverToIdle(); throw Failure.check } catch VPNRouteTransactionError.recoveryRequired {}
            try check(before == Data(contentsOf:file) && fake.sent.map(\.rtm_type) == [UInt8(RTM_GET)])
        }}}
    }
    static func run(_ mode: String) throws {
        if mode == "recovery" { try recover(CommandLine.arguments[2]); return }
        for family in [VPNRouteAddressFamily.ipv4,.ipv6] { for scoped in [false,true] {
            let desired = try identity(family,scoped:scoped), fake = Transport()
            let adapter = VPNDarwinRouteSocket(transport:fake,pid:414)
            switch mode {
            case "absence":
                fake.onSend = { _ in throw VPNRouteSocketTransportError.posix(ESRCH) }
                try check(adapter.lookupExact(desired.lookupKey) == nil)
                try check(fake.sent.count == 1 && fake.reads == 0)
            case "receive":
                fake.readError = ESRCH
                try transportFailure(ESRCH) { _ = try adapter.lookupExact(desired.lookupKey) }
                try check(fake.sent.count == 1 && fake.reads == 1)
            case "enoent", "permission":
                let code = mode == "enoent" ? ENOENT:EPERM
                fake.onSend = { _ in throw VPNRouteSocketTransportError.posix(code) }
                try transportFailure(code) { _ = try adapter.lookupExact(desired.lookupKey) }
                try check(fake.reads == 0)
            case "kernel":
                fake.onSend = { try fake.enqueue($0) }
                try check(adapter.lookupExact(desired.lookupKey) == nil && fake.reads == 1)
            case "add", "delete":
                fake.onSend = { header in
                    if header.rtm_type == RTM_GET { try fake.enqueue(header,error:mode == "delete" ? 0:ESRCH,identity:mode == "delete" ? desired:nil) }
                    else { throw VPNRouteSocketTransportError.posix(ESRCH) }
                }
                try transportFailure(ESRCH) {
                    if mode == "add" { _ = try adapter.add(desired) } else { _ = try adapter.delete(desired) }
                }
                try check(fake.sent.map(\.rtm_type) == [UInt8(RTM_GET),UInt8(mode == "add" ? RTM_ADD:RTM_DELETE)])
            case "stale", "stale-add":
                fake.onSend = { header in
                    if header.rtm_seq == 1 {
                        try fake.enqueue(header)
                        try fake.enqueue(header,error:0,identity:desired) // Stale success is not current evidence.
                        throw VPNRouteSocketTransportError.posix(ESRCH)
                    }
                    if header.rtm_type == RTM_GET {
                        try fake.enqueue(header,error:0,identity:desired,pid:999) // Foreign process cannot authorize anything.
                        try fake.enqueue(header)
                    } else { throw VPNRouteSocketTransportError.posix(ESRCH) }
                }
                try check(adapter.lookupExact(desired.lookupKey) == nil && fake.reads == 0)
                if mode == "stale" {
                    try check(adapter.lookupExact(desired.lookupKey) == nil && fake.reads == 4)
                } else {
                    try transportFailure(ESRCH) { _ = try adapter.add(desired) }
                    try check(fake.sent.map(\.rtm_type) == [UInt8(RTM_GET),UInt8(RTM_GET),UInt8(RTM_ADD)] && fake.reads == 4)
                }
            case "limit":
                fake.onSend = { header in
                    if header.rtm_seq == 1 {
                        for _ in 0..<128 { try fake.enqueue(header) }
                        throw VPNRouteSocketTransportError.posix(ESRCH)
                    }
                    try fake.enqueue(header)
                }
                try check(adapter.lookupExact(desired.lookupKey) == nil)
                let start = fake.deadlines.count
                do { _ = try adapter.lookupExact(desired.lookupKey); throw Failure.check } catch VPNDarwinRouteError.responseLimit {}
                try check(fake.reads == 128 && Set(fake.deadlines.dropFirst(start)).count == 1)
                try check(adapter.lookupExact(desired.lookupKey) == nil && fake.reads == 130)
            case "repeated":
                fake.onSend = { header in
                    try fake.enqueue(header)
                    if header.rtm_seq <= 256 { throw VPNRouteSocketTransportError.posix(ESRCH) }
                }
                for _ in 0..<256 { try check(adapter.lookupExact(desired.lookupKey) == nil) }
                try check(fake.reads == 0)
                for _ in 0..<2 {
                    let before = fake.reads
                    do { _ = try adapter.lookupExact(desired.lookupKey); throw Failure.check } catch VPNDarwinRouteError.responseLimit {}
                    try check(fake.reads - before == 128)
                }
                try check(adapter.lookupExact(desired.lookupKey) == nil && fake.reads == 259)
            default: throw Failure.check
            }
        }}
    }
    static func main() {
        do { try run(CommandLine.arguments[1]); print("pure route write-miss checks passed") }
        catch VPNDarwinRouteError.transport(let code) { print("pure route write-miss failure transport=\(code)"); exit(1) }
        catch { print("pure route write-miss failure category=check"); exit(1) }
    }
}
