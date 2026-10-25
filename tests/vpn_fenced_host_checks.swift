import Darwin
import Foundation

// Test executable only. No host interface lookup or kernel/network mutations.
@_cdecl("if_indextoname")
func pairInterface(_ index: UInt32, _ output: UnsafeMutablePointer<CChar>?) -> UnsafeMutablePointer<CChar>? {
    guard let output, let name = [1:"lo0",42:"utun42"][index] else { return nil }
    for (i,c) in name.utf8CString.enumerated() { output[i] = c }; return output
}
private func check(_ value: @autoclosure () throws -> Bool) throws {
    if try !value() { throw NSError(domain:"pair",code:1) }
}
private final class Kernel: VPNRouteSocketTransport {
    let active: VPNOwnedRouteIdentity, fence: VPNExactRouteFenceIdentity
    var hasFence = true, hasHost = false, foreign = false, loseFence = false
    var acknowledgeOnly = false, unknown = false, race = false, late = false, foreignFence = false
    var request = Data(), sent = [rt_msghdr](), deadlines = [UInt64]()
    var onMutation: (() throws -> Void)?
    init(_ active: VPNOwnedRouteIdentity, _ fence: VPNExactRouteFenceIdentity) { self.active=active;self.fence=fence }
    func send(_ message: Data, deadline: DispatchTime) throws {
        request=message;let h=try VPNDarwinRouteCodec.identify(message);sent.append(h);deadlines.append(deadline.uptimeNanoseconds)
        if h.rtm_type != RTM_GET {
            try onMutation?()
            if h.rtm_flags & RTF_HOST == 0 { hasFence = h.rtm_type == RTM_ADD;return }
            if race { hasHost=true;throw VPNRouteSocketTransportError.posix(EEXIST) }
            if !acknowledgeOnly { hasHost = h.rtm_type == RTM_ADD }
            if loseFence { hasFence=false }
        }
    }
    func receive(maximumBytes: Int, deadline: DispatchTime) throws -> Data {
        let h=try VPNDarwinRouteCodec.identify(request)
        if late { usleep(30_000) }
        if h.rtm_type != RTM_GET {
            if unknown { throw VPNRouteSocketTransportError.timeout }
            // Deliberately sparse ACK. Separate GET must prove both keys.
            return try VPNDarwinRouteCodec.encodeReply(type:h.rtm_type,sequence:h.rtm_seq,pid:h.rtm_pid,error:0,identity:nil)
        }
        if h.rtm_flags & RTF_HOST != 0 && hasHost {
            return try VPNDarwinRouteCodec.encodeReply(type:h.rtm_type,sequence:h.rtm_seq,pid:h.rtm_pid,error:0,
                identity:active,responseFlags:foreign ? UInt32(RTF_REJECT):0)
        }
        if !hasFence { return try VPNDarwinRouteCodec.encodeReply(type:h.rtm_type,sequence:h.rtm_seq,pid:h.rtm_pid,error:ESRCH,identity:nil) }
        var data=try VPNDarwinRouteCodec.encodeExactFence(type:UInt8(RTM_ADD),sequence:h.rtm_seq,pid:h.rtm_pid,identity:fence)
        var header=try VPNDarwinRouteCodec.identify(data)
        header.rtm_type=h.rtm_type;header.rtm_flags=Int32(bitPattern:fence.flags | (foreignFence ? UInt32(RTF_REJECT):0))
        withUnsafeBytes(of:&header) { data.replaceSubrange(0..<$0.count,with:$0) }
        return data
    }
}
@main private enum Checks {
    static func journal(_ mode: String, active: VPNOwnedRouteIdentity, fence: VPNExactRouteFenceIdentity,
                        fake: Kernel, socket: VPNDarwinRouteSocket) throws {
        let path=CommandLine.arguments[2]+"/"+String(active.destination.family.rawValue)
        try FileManager.default.createDirectory(atPath:path,withIntermediateDirectories:false,attributes:[.posixPermissions:0o700])
        let fd=open(path,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC)
        try check(fd >= 0);defer { close(fd) }
        let claim=VPNExactFenceClaim(resourceID:UUID(uuidString:"12345678-1234-1234-1234-123456789abc")!,profileSHA256:String(repeating:"a",count:64),generation:1,revision:1)
        fake.hasFence=false
        let end=DispatchTime.now()+5
        func create(_ store: VPNExactFenceStore) throws -> VPNExactFenceEntry {
            try VPNExactFenceTransaction(store:store,kernel:socket).ensure(fence,claim:claim,deadline:end,checkCurrent:{})
        }
        if mode == "journal-reopen" {
            func first() throws -> VPNExactFenceEntry {
                let store=try VPNExactFenceStore(trustedDirectoryDescriptor:fd)
                let initial=try create(store)
                return try VPNExactFenceTransaction(store:store,kernel:socket).activateHost(initial,identity:active,claim:claim,deadline:end,checkCurrent:{})
            }
            let before=try first(), store=try VPNExactFenceStore(trustedDirectoryDescriptor:fd)
            let tx=VPNExactFenceTransaction(store:store,kernel:socket)
            try check(try store.load(fence.address) == before)
            let restored=try tx.restoreRetained(deadline:end,checkOwner:{})
            try check(restored.count == 1 && restored[0].active == nil && restored[0].installationID == before.installationID)
            try check(!fake.hasHost && fake.hasFence);return
        }
        let store=try VPNExactFenceStore(trustedDirectoryDescriptor:fd), tx=VPNExactFenceTransaction(store:store,kernel:socket)
        let initial=try create(store)
        try check(initial.schemaVersion == 1 && initial.active == nil)
        func activate() throws -> VPNExactFenceEntry { try tx.activateHost(initial,identity:active,claim:claim,deadline:end,checkCurrent:{}) }
        func failure(_ expected: VPNExactFenceStoreError, _ body: () throws -> Void) throws {
            do { try body();throw NSError(domain:"no-error",code:1) }
            catch let actual as VPNExactFenceStoreError { try check(actual == expected) }
        }
        switch mode {
        case "journal-shared":
            let other=VPNExactFenceClaim(resourceID:UUID(uuidString:"22345678-1234-1234-1234-123456789abc")!,profileSHA256:claim.profileSHA256,generation:1,revision:1)
            let shared=try tx.ensure(fence,claim:other,deadline:end,checkCurrent:{})
            let applied=try tx.activateHost(shared,identity:active,claim:claim,deadline:end,checkCurrent:{})
            let retained=try tx.releaseClaims(applied,removing:[other],deadline:end,checkCurrent:{})
            try check(retained.claims == [claim] && retained.active == applied.active && fake.hasHost && fake.hasFence)
            try failure(.recoveryRequired) { _=try tx.releaseClaims(retained,removing:[claim],deadline:end,checkCurrent:{}) }
            try check(store.load(fence.address) == retained && fake.hasHost && fake.hasFence)
        case "journal-schema":
            let encoded=try JSONEncoder().encode(initial)
            let object=try JSONSerialization.jsonObject(with:encoded) as! [String:Any]
            try check(object["active"] == nil)
            try check(try JSONDecoder().decode(VPNExactFenceEntry.self,from:encoded) == initial)
            let activeEntry=VPNFencedHostEntry(identity:active,claim:claim,phase:.applied)
            func invalid(_ schema: Int, _ phase: VPNExactFencePhase, _ claims: [VPNExactFenceClaim]) throws {
                let bad=VPNExactFenceEntry(schemaVersion:schema,installationID:initial.installationID,
                    identity:fence,phase:phase,claims:claims,active:activeEntry)
                try failure(.invalidState) { try bad.validate() }
            }
            try invalid(1,.applied,[claim]);try invalid(3,.applied,[claim]);try invalid(2,.retired,[claim])
            let other=VPNExactFenceClaim(resourceID:UUID(),profileSHA256:String(repeating:"b",count:64),generation:1,revision:1)
            try invalid(2,.applied,[other])
            try check(store.load(fence.address) == initial && !fake.hasHost && fake.hasFence)
        case "journal-lifecycle":
            fake.onMutation={ try check(try store.load(fence.address)?.active?.phase == .installing) }
            let applied=try activate()
            try check(applied.schemaVersion == 2 && applied.active?.phase == .applied)
            try tx.verifyHost(applied,deadline:end,checkCurrent:{})
            let count=fake.sent.count
            try check(try tx.activateHost(applied,identity:active,claim:claim,deadline:end,checkCurrent:{}) == applied)
            try check(fake.sent.dropFirst(count).allSatisfy { $0.rtm_type == RTM_GET })
            fake.onMutation={ try check(try store.load(fence.address)?.active?.phase == .removing) }
            let cleared=try tx.withdrawHost(applied,deadline:end,checkCurrent:{})
            try check(cleared.active == nil && cleared.claims == initial.claims && cleared.installationID == initial.installationID)
            try check(!fake.hasHost && fake.hasFence)
            fake.onMutation=nil
            _=try tx.retire(cleared,deadline:end,checkCurrent:{})
            try check(!fake.hasFence)
        case "journal-unknown-add":
            fake.unknown=true
            do { _=try activate();throw NSError(domain:"no-timeout",code:1) } catch VPNDarwinRouteError.timeout {}
            let pending=try store.load(fence.address)!
            try check(pending.active?.phase == .installing && fake.hasHost && fake.hasFence)
            try failure(.recoveryRequired) { _=try tx.withdrawHost(pending,deadline:end,checkCurrent:{}) }
            try check(!fake.sent.contains { $0.rtm_type == RTM_DELETE })
            fake.hasHost=false
            let cleared=try tx.withdrawHost(pending,deadline:end,checkCurrent:{})
            try check(cleared.active == nil && fake.hasFence)
        case "journal-unknown-delete", "journal-unknown-delete-present":
            let applied=try activate();fake.unknown=true
            fake.acknowledgeOnly = mode == "journal-unknown-delete-present"
            do { _=try tx.withdrawHost(applied,deadline:end,checkCurrent:{});throw NSError(domain:"no-timeout",code:1) } catch VPNDarwinRouteError.timeout {}
            let pending=try store.load(fence.address)!, deletes=fake.sent.filter { $0.rtm_type == RTM_DELETE }.count
            try check(pending.active?.phase == .removing && fake.hasFence)
            if fake.hasHost { try failure(.recoveryRequired) { _=try tx.withdrawHost(pending,deadline:end,checkCurrent:{}) } }
            else { try check(try tx.withdrawHost(pending,deadline:end,checkCurrent:{}).active == nil) }
            try check(fake.sent.filter { $0.rtm_type == RTM_DELETE }.count == deletes)
        case "journal-cancel-intent":
            do {
                _=try tx.activateHost(initial,identity:active,claim:claim,deadline:end,checkCurrent:{
                    if try store.load(fence.address)?.active?.phase == .installing { throw VPNExactFenceStoreError.stale }
                });throw NSError(domain:"no-cancel",code:1)
            } catch VPNExactFenceStoreError.stale {}
            let pending=try store.load(fence.address)!
            try check(pending.active?.phase == .installing && !fake.hasHost && fake.hasFence)
            try check(try tx.withdrawHost(pending,deadline:end,checkCurrent:{}).active == nil)
        case "journal-stale":
            let applied=try activate(), count=fake.sent.count
            try failure(.stale) { _=try activate() }
            try check(fake.sent.count == count && store.load(fence.address) == applied)
        case "journal-no-retire-active":
            let applied=try activate(), count=fake.sent.count
            try failure(.recoveryRequired) { _=try tx.retire(applied,deadline:end,checkCurrent:{}) }
            try check(fake.sent.count == count && fake.hasFence && fake.hasHost)
        case "journal-foreign":
            let applied=try activate();fake.foreign=true
            do { _=try tx.withdrawHost(applied,deadline:end,checkCurrent:{});throw NSError(domain:"no-failure",code:1) }
            catch VPNDarwinRouteError.missingOrForeign {}
            try check(store.load(fence.address) == applied && fake.hasHost && fake.hasFence)
        case "journal-boot-unknown":
            fake.unknown=true
            do { _=try activate();throw NSError(domain:"no-timeout",code:1) } catch VPNDarwinRouteError.timeout {}
            let pending=try store.load(fence.address)!
            try failure(.recoveryRequired) { _=try tx.restoreRetained(deadline:end,checkOwner:{}) }
            try check(fake.hasHost && fake.hasFence && store.load(fence.address) == pending)
        default:throw NSError(domain:"journal-mode",code:1)
        }
    }
    static func run() throws {
        let mode=CommandLine.arguments[1]
        for family in [VPNRouteAddressFamily.ipv4,.ipv6] {
            let prefix=try VPNRoutePrefix(resource:VPNResource(address:family == .ipv4 ? "198.19.253.201":"2001:db8:fff:fd::c9"))
            let route=VPNPlannedRoute(role:.resource,destination:prefix,physicalGatewayBytes:nil,interfaceIndex:42,interfaceName:"utun42")
            let flags=VPNManagedIPv6HostRoute.flags(for:route)
            let evidence: VPNRouteKernelEvidence
            if family == .ipv4 { evidence=try VPNRouteKernelEvidence(gateway:Optional<in_addr>.none,interfaceIndex:42,flags:flags) }
            else { evidence=try VPNRouteKernelEvidence(gateway:Optional<in6_addr>.none,interfaceIndex:42,flags:flags) }
            let active=try VPNOwnedRouteIdentity(planned:route,evidence:evidence)
            let fence=try VPNExactRouteFenceIdentity(address:prefix,loopbackIndex:1)
            let fake=Kernel(active,fence), socket=VPNDarwinRouteSocket(transport:fake,pid:817)
            if mode.hasPrefix("journal-") { try journal(mode,active:active,fence:fence,fake:fake,socket:socket);continue }
            let end=DispatchTime.now()+2
            func install(_ current: () throws -> Void = {}) throws { try socket.installFencedHost(active,fence:fence,deadline:end,checkCurrent:current) }
            func remove() throws { try socket.deleteFencedHost(active,fence:fence,deadline:end,checkCurrent:{}) }
            func fails(_ code: VPNDarwinRouteError, _ body: () throws -> Void) throws {
                do { try body();throw NSError(domain:"no-failure",code:1) }
                catch let error as VPNDarwinRouteError { try check(error == code) }
            }
            switch mode {
            case "lifecycle":
                try install();try check(fake.hasHost && fake.hasFence)
                try remove();try check(!fake.hasHost && fake.hasFence)
                try check(fake.sent.filter { $0.rtm_type != RTM_GET }.map(\.rtm_type) == [UInt8(RTM_ADD),UInt8(RTM_DELETE)])
                try check(Set(fake.deadlines).count == 1 && fake.deadlines.allSatisfy { $0 <= end.uptimeNanoseconds })
            case "no-adoption":
                fake.hasHost=true;try fails(.preexistingNonIdentical) { try install() }
                try check(fake.sent.allSatisfy { $0.rtm_type == RTM_GET })
            case "missing-fence":
                fake.hasFence=false;try fails(.missingOrForeign) { try install() };try check(fake.sent.count == 1)
            case "foreign-fence":
                fake.foreignFence=true;try fails(.missingOrForeign) { try install() };try check(fake.sent.count == 1)
            case "foreign-host":
                fake.hasHost=true;fake.foreign=true;try fails(.missingOrForeign) { try remove() }
                try check(fake.hasHost && fake.sent.allSatisfy { $0.rtm_type == RTM_GET })
            case "fence-loss":
                fake.loseFence=true;try fails(.missingOrForeign) { try install() }
                try check(fake.hasHost && fake.sent.filter { $0.rtm_type == RTM_DELETE }.isEmpty)
            case "ack-without-state":
                fake.acknowledgeOnly=true;try fails(.verificationFailed) { try install() };try check(!fake.hasHost && fake.hasFence)
            case "unknown-write":
                fake.unknown=true;try fails(.timeout) { try install() };try check(fake.hasHost && fake.hasFence)
                try check(fake.sent.filter { $0.rtm_type != RTM_GET }.count == 1)
            case "unknown-delete":
                fake.hasHost=true;fake.unknown=true;try fails(.timeout) { try remove() }
                try check(!fake.hasHost && fake.hasFence && fake.sent.filter { $0.rtm_type != RTM_GET }.count == 1)
            case "delete-ack-without-state":
                fake.hasHost=true;fake.acknowledgeOnly=true;try fails(.verificationFailed) { try remove() }
                try check(fake.hasHost && fake.hasFence)
            case "race":
                fake.race=true;try fails(.transport(EEXIST)) { try install() };try check(fake.hasHost && fake.hasFence)
            case "cancelled":
                var calls=0
                do { try install { calls+=1;if calls == 6 { throw VPNExactFenceStoreError.stale } };throw NSError(domain:"no-cancel",code:1) }
                catch VPNExactFenceStoreError.stale {}
                try check(!fake.hasHost && fake.sent.allSatisfy { $0.rtm_type == RTM_GET })
            case "cancelled-after-write":
                var calls=0
                do { try install { calls+=1;if calls == 7 { throw VPNExactFenceStoreError.stale } };throw NSError(domain:"no-cancel",code:1) }
                catch VPNExactFenceStoreError.stale {}
                try check(fake.hasHost && fake.hasFence && fake.sent.filter { $0.rtm_type != RTM_GET }.count == 1)
            case "expired":
                try fails(.timeout) { try socket.installFencedHost(active,fence:fence,deadline:.now(),checkCurrent:{}) }
                try check(fake.sent.isEmpty)
            case "late":
                fake.late=true
                try fails(.timeout) { try socket.installFencedHost(active,fence:fence,deadline:.now()+0.01,checkCurrent:{}) }
                try check(!fake.hasHost)
            case "delete-absent":
                try fails(.missingOrForeign) { try remove() };try check(fake.hasFence)
                try check(fake.sent.allSatisfy { $0.rtm_type == RTM_GET })
            default: throw NSError(domain:"mode",code:1)
            }
        }
        print("PASS fenced-host-"+mode)
    }
    static func main() { do { try run() } catch { fputs("FAIL fenced-host\n",stderr);exit(1) } }
}
