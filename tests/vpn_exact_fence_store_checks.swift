import Darwin
import Foundation
private func check(_ value: @autoclosure () throws -> Bool) throws {
    if try !value() { throw NSError(domain:"store-check",code:1) }
}
private final class Kernel: VPNExactFenceKernel {
    var present = [String:VPNExactRouteFenceIdentity](), adds = 0, deletes = 0, reads = 0
    var unknownAdd = false, unknownDelete = false, foreign = false
    var beforeAdd: (() throws -> Void)?
    func lookupExactFence(_ identity: VPNExactRouteFenceIdentity, deadline: DispatchTime) throws -> VPNDarwinRouteSnapshot? {
        reads += 1
        guard let value = present[identity.address.canonical] else { return nil }
        return VPNDarwinRouteSnapshot(destination:value.address,gatewayBytes:value.gatewayBytes,
            interfaceIndex:value.interfaceIndex,interfaceName:"lo0",flags:foreign ? value.flags ^ UInt32(RTF_PROTO2) : value.flags)
    }
    func installExactFence(_ identity: VPNExactRouteFenceIdentity, deadline: DispatchTime) throws {
        try beforeAdd?(); adds += 1; present[identity.address.canonical] = identity
        if unknownAdd { throw VPNDarwinRouteError.timeout }
    }
    func deleteExactFence(_ identity: VPNExactRouteFenceIdentity, deadline: DispatchTime) throws {
        deletes += 1; present.removeValue(forKey:identity.address.canonical)
        if unknownDelete { throw VPNDarwinRouteError.timeout }
    }
}
private func id(_ family: Int) throws -> VPNExactRouteFenceIdentity {
    try VPNExactRouteFenceIdentity(address:VPNRoutePrefix(resource:VPNResource(address:family == 4 ? "198.19.253.201" : "2001:db8:fff:fd::c9")),loopbackIndex:if_nametoindex("lo0"))
}
private func claim(_ resource: String = "12345678-1234-1234-1234-123456789abc", _ generation: UInt64 = 1, _ revision: UInt64 = 1) -> VPNExactFenceClaim {
    VPNExactFenceClaim(resourceID:UUID(uuidString:resource)!,profileSHA256:String(repeating:"a",count:64),generation:generation,revision:revision)
}
private func until() -> DispatchTime { .now() + 5 }
private func expect(_ error: VPNExactFenceStoreError, _ body: () throws -> Void) throws {
    do { try body(); throw NSError(domain:"expected-error",code:1) }
    catch let actual as VPNExactFenceStoreError { try check(actual == error) }
}
private func store(_ fd: Int32) throws -> VPNExactFenceStore { try VPNExactFenceStore(trustedDirectoryDescriptor:fd) }
@main private enum Main {
    static func main() {
        do { try run() }
        catch { fputs("FAIL exact-fence-store-check\n",stderr); exit(1) }
    }
    static func run() throws {
        let mode = CommandLine.arguments[1], path = CommandLine.arguments[2]
        let fd = open(path,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC)
        try check(fd >= 0); defer { close(fd) }
        if mode == "reopen" {
            let kernel = Kernel(), identity = try id(4)
            func create() throws {
                let s = try store(fd), tx = VPNExactFenceTransaction(store:s,kernel:kernel)
                _ = try tx.ensure(identity,claim:claim(),deadline:until(),checkCurrent:{})
            }
            try create()
            let s = try store(fd), tx = VPNExactFenceTransaction(store:s,kernel:kernel)
            let old = try s.load(identity.address)
            try check(old?.phase == .applied)
            let value = try tx.ensure(identity,claim:claim(),deadline:until(),checkCurrent:{})
            try check(value == old && kernel.adds == 1)
        } else {
            let s = try store(fd), kernel = Kernel(), tx = VPNExactFenceTransaction(store:s,kernel:kernel)
            let identity = try id(4)
            switch mode {
            case "startup-restore":
                var old = [VPNExactFenceEntry]()
                for f in [4,6] { old.append(try tx.ensure(id(f),claim:claim(),deadline:until(),checkCurrent:{})) }
                kernel.present.removeAll()
                let restored = try tx.restoreRetained(deadline:until(),checkOwner:{})
                try check(restored.count == 2 && kernel.adds == 4)
                try check(restored.map(\.claims) == old.map(\.claims))
                try check(zip(restored,old).allSatisfy { $0.installationID != $1.installationID })
                try check(try tx.restoreRetained(deadline:until(),checkOwner:{}) == restored && kernel.adds == 4)
            case "startup-partial":
                kernel.unknownAdd = true
                do { _ = try tx.ensure(identity,claim:claim(),deadline:until(),checkCurrent:{}); throw NSError(domain:"missing",code:1) }
                catch VPNDarwinRouteError.timeout {}
                kernel.unknownAdd = false
                let v6 = try id(6)
                _ = try tx.ensure(v6,claim:claim(),deadline:until(),checkCurrent:{})
                kernel.present.removeValue(forKey:v6.address.canonical)
                try expect(.recoveryRequired) { _ = try tx.restoreRetained(deadline:until(),checkOwner:{}) }
                try check(kernel.present[v6.address.canonical] != nil && kernel.adds == 3 && kernel.deletes == 0)
                try check(try s.load(identity.address)?.phase == .adding)
            case "startup-release":
                let entry = try tx.ensure(identity,claim:claim(),deadline:until(),checkCurrent:{})
                kernel.unknownDelete = true
                do { _ = try tx.retire(entry,deadline:until(),checkCurrent:{}); throw NSError(domain:"missing",code:1) }
                catch VPNDarwinRouteError.timeout {}
                try check(try s.load(identity.address)?.phase == .releasing)
                try check(try tx.restoreRetained(deadline:until(),checkOwner:{}).isEmpty)
                try check(try s.load(identity.address)?.phase == .retired)
                try check(kernel.deletes == 1)
            case "startup-retired":
                let entry = try tx.ensure(identity,claim:claim(),deadline:until(),checkCurrent:{})
                _ = try tx.retire(entry,deadline:until(),checkCurrent:{})
                try check(try tx.restoreRetained(deadline:until(),checkOwner:{}).isEmpty)
                try check(kernel.adds == 1 && kernel.deletes == 1)
            case "startup-cancelled":
                _ = try tx.ensure(identity,claim:claim(),deadline:until(),checkCurrent:{})
                kernel.present.removeAll()
                try expect(.stale) { _ = try tx.restoreRetained(deadline:until(),checkOwner:{ throw VPNExactFenceStoreError.stale }) }
                try check(kernel.adds == 1)
            case "write-order":
                kernel.beforeAdd = { try check(try s.load(identity.address)?.phase == .adding) }
                let entry = try tx.ensure(identity,claim:claim(),deadline:until(),checkCurrent:{})
                try check(entry.phase == .applied && kernel.adds == 1 && s.load(identity.address) == entry)
            case "claims":
                let first = try tx.ensure(identity,claim:claim(),deadline:until(),checkCurrent:{})
                let second = try tx.ensure(identity,claim:claim("22345678-1234-1234-1234-123456789abc"),deadline:until(),checkCurrent:{})
                try check(second.claims.count == 2 && first.installationID == second.installationID && kernel.adds == 1)
                try expect(.stale) { _ = try tx.retire(first,deadline:until(),checkCurrent:{}) }
                try check(kernel.deletes == 0)
            case "release-shared":
                _ = try tx.ensure(identity,claim:claim(),deadline:until(),checkCurrent:{})
                let secondClaim = claim("22345678-1234-1234-1234-123456789abc")
                let shared = try tx.ensure(identity,claim:secondClaim,deadline:until(),checkCurrent:{})
                let remaining = try tx.releaseClaims(shared,removing:[claim()],deadline:until(),checkCurrent:{})
                try check(remaining.phase == .applied && remaining.claims == [secondClaim] && kernel.deletes == 0)
                try expect(.stale) { _ = try tx.retire(shared,deadline:until(),checkCurrent:{}) }
                let retired = try tx.releaseClaims(remaining,removing:[secondClaim],deadline:until(),checkCurrent:{})
                try check(retired.phase == .retired && kernel.deletes == 1)
            case "generation":
                let first = try tx.ensure(identity,claim:claim(),deadline:until(),checkCurrent:{})
                let next = try tx.ensure(identity,claim:claim("12345678-1234-1234-1234-123456789abc",2,2),deadline:until(),checkCurrent:{})
                try check(next.claims.count == 1 && next.installationID == first.installationID && kernel.adds == 1)
                try expect(.stale) { _ = try tx.ensure(identity,claim:claim(),deadline:until(),checkCurrent:{}) }
            case "unknown-add":
                kernel.unknownAdd = true
                do { _ = try tx.ensure(identity,claim:claim(),deadline:until(),checkCurrent:{}); throw NSError(domain:"missing",code:1) }
                catch VPNDarwinRouteError.timeout {}
                try check(try s.load(identity.address)?.phase == .adding)
                try expect(.recoveryRequired) { _ = try tx.ensure(identity,claim:claim(),deadline:until(),checkCurrent:{}) }
                try check(kernel.adds == 1 && kernel.deletes == 0)
            case "absent-recovery":
                kernel.unknownAdd = true
                do { _ = try tx.ensure(identity,claim:claim(),deadline:until(),checkCurrent:{}); throw NSError(domain:"missing",code:1) }
                catch VPNDarwinRouteError.timeout {}
                let pending = try s.load(identity.address)
                kernel.unknownAdd = false; kernel.present.removeAll()
                let value = try tx.ensure(identity,claim:claim(),deadline:until(),checkCurrent:{})
                try check(value.phase == .applied && value.installationID != pending?.installationID && kernel.adds == 2)
            case "restore-applied":
                let first = try tx.ensure(identity,claim:claim(),deadline:until(),checkCurrent:{})
                kernel.present.removeAll()
                let next = try tx.ensure(identity,claim:claim(),deadline:until(),checkCurrent:{})
                try check(next.installationID != first.installationID && next.claims == first.claims && kernel.adds == 2)
            case "foreign":
                kernel.present[identity.address.canonical] = identity
                try expect(.recoveryRequired) { _ = try tx.ensure(identity,claim:claim(),deadline:until(),checkCurrent:{}) }
                try check(kernel.adds == 0 && s.load(identity.address) == nil)
            case "retire":
                let first = try tx.ensure(identity,claim:claim(),deadline:until(),checkCurrent:{})
                let retired = try tx.retire(first,deadline:until(),checkCurrent:{})
                try check(retired.phase == .retired && kernel.deletes == 1 && retired.claims == first.claims)
                let again = try tx.ensure(identity,claim:claim(),deadline:until(),checkCurrent:{})
                try check(again.phase == .applied && again.installationID != first.installationID)
            case "unknown-delete":
                let first = try tx.ensure(identity,claim:claim(),deadline:until(),checkCurrent:{})
                kernel.unknownDelete = true
                do { _ = try tx.retire(first,deadline:until(),checkCurrent:{}); throw NSError(domain:"missing",code:1) }
                catch VPNDarwinRouteError.timeout {}
                let pending = try s.load(identity.address)!
                try check(pending.phase == .releasing)
                kernel.present[identity.address.canonical] = identity
                try expect(.recoveryRequired) { _ = try tx.retire(pending,deadline:until(),checkCurrent:{}) }
                kernel.present.removeAll()
                let retired = try tx.retire(pending,deadline:until(),checkCurrent:{})
                try check(retired.phase == .retired && kernel.deletes == 1)
            case "cancel-after-intent":
                var cancelled = false
                kernel.beforeAdd = { cancelled = true }
                do { _ = try tx.ensure(identity,claim:claim(),deadline:until(),checkCurrent:{ if cancelled { throw VPNExactFenceStoreError.stale } }); throw NSError(domain:"missing",code:1) }
                catch VPNExactFenceStoreError.stale {}
                try check(try s.load(identity.address)?.phase == .adding)
                try check(kernel.adds == 1 && kernel.deletes == 0)
            case "cancel-before-write":
                var count = 0
                do { _ = try tx.ensure(identity,claim:claim(),deadline:until(),checkCurrent:{
                    count += 1; if count == 4 { throw VPNExactFenceStoreError.stale }
                }); throw NSError(domain:"missing",code:1) } catch VPNExactFenceStoreError.stale {}
                try check(try s.load(identity.address)?.phase == .adding)
                try check(kernel.adds == 0)
            case "foreign-release":
                let entry = try tx.ensure(identity,claim:claim(),deadline:until(),checkCurrent:{})
                kernel.foreign = true
                do { _ = try tx.retire(entry,deadline:until(),checkCurrent:{}); throw NSError(domain:"missing",code:1) }
                catch VPNDarwinRouteError.missingOrForeign {}
                try check(kernel.deletes == 0 && s.load(identity.address) == entry)
            case "expired":
                do { _ = try tx.ensure(identity,claim:claim(),deadline:DispatchTime(uptimeNanoseconds:1),checkCurrent:{}); throw NSError(domain:"missing",code:1) }
                catch VPNDarwinRouteError.timeout {}
                try check(kernel.reads == 0 && kernel.adds == 0 && s.entries().isEmpty)
            case "lock":
                for _ in 0..<3 { try expect(.recoveryRequired) { _ = try store(fd) } }
            case "concurrent":
                let group = DispatchGroup(), lock = NSLock()
                var failures = 0
                let deadline = until()
                for index in 0..<8 {
                    group.enter()
                    DispatchQueue.global().async {
                        defer { group.leave() }
                        do {
                            let raw = String(format:"%08x-1234-1234-1234-123456789abc",index+1)
                            _ = try tx.ensure(identity,claim:claim(raw),deadline:deadline,checkCurrent:{})
                        } catch { lock.lock(); failures += 1; lock.unlock() }
                    }
                }
                try check(group.wait(timeout:.now()+5) == .success)
                try check(failures == 0 && kernel.adds == 1 && s.load(identity.address)?.claims.count == 8)
            case "canonical":
                _ = try tx.ensure(identity,claim:claim(),deadline:until(),checkCurrent:{})
                let name = try VPNExactFenceStore.name(identity.address)
                let file = openat(fd,name,O_WRONLY|O_APPEND|O_NOFOLLOW|O_CLOEXEC)
                try check(file >= 0); try check(write(file,"\n",1) == 1); close(file)
                let reads = kernel.reads
                try expect(.invalidState) { _ = try tx.ensure(identity,claim:claim(),deadline:until(),checkCurrent:{}) }
                try check(kernel.reads == reads && kernel.adds == 1)
            case "symlink":
                let name = try VPNExactFenceStore.name(identity.address)
                try check(symlinkat("unrelated",fd,name) == 0)
                try expect(.unsafeStorage) { _ = try s.load(identity.address) }
                try check(kernel.reads == 0)
            case "hardlink":
                _ = try tx.ensure(identity,claim:claim(),deadline:until(),checkCurrent:{})
                let name = try VPNExactFenceStore.name(identity.address)
                try check(linkat(fd,name,fd,"alias",0) == 0)
                try expect(.unsafeStorage) { _ = try s.load(identity.address) }
            case "lock-replaced":
                try check(unlinkat(fd,"owner.lock",0) == 0)
                let replacement = openat(fd,"owner.lock",O_CREAT|O_EXCL|O_RDWR|O_CLOEXEC,0o600)
                try check(replacement >= 0); close(replacement)
                try expect(.unsafeStorage) { _ = try tx.ensure(identity,claim:claim(),deadline:until(),checkCurrent:{}) }
                try check(kernel.adds == 0)
            case "families":
                for f in [4,6] { _ = try tx.ensure(id(f),claim:claim(),deadline:until(),checkCurrent:{}) }
                try check(try s.entries().map(\.identity.address.family) == [.ipv4,.ipv6])
            default: throw NSError(domain:"mode",code:1)
            }
        }
        print("PASS exact-fence-store-"+mode)
    }
}
