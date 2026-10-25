import Darwin
import Foundation
@_cdecl("if_indextoname")
func runtimeInterface(_ index: UInt32,_ output: UnsafeMutablePointer<CChar>?) -> UnsafeMutablePointer<CChar>? {
    guard let output,let name=[1:"lo0",42:"utun42"][index] else { return nil }
    for (i,c) in name.utf8CString.enumerated() { output[i]=c };return output
}
private func require(_ value: @autoclosure () throws -> Bool) throws {
    if try !value() { throw VPNExactFenceStoreError.invalidState }
}
private final class Kernel: VPNFencedHostKernel {
    var denies=[String:VPNDarwinRouteSnapshot](),active: VPNDarwinRouteSnapshot?
    var adds=0,deletes=0,foreign=false
    func lookupExactFence(_ id: VPNExactRouteFenceIdentity,deadline: DispatchTime) throws -> VPNDarwinRouteSnapshot? {
        if foreign && id.address.family == .ipv6 {
            return VPNDarwinRouteSnapshot(destination:id.address,gatewayBytes:id.gatewayBytes,interfaceIndex:1,interfaceName:"lo0",flags:id.flags|UInt32(RTF_REJECT))
        }
        return denies[id.address.canonical]
    }
    func installExactFence(_ id: VPNExactRouteFenceIdentity,deadline: DispatchTime) throws {
        adds+=1;denies[id.address.canonical]=VPNDarwinRouteSnapshot(destination:id.address,gatewayBytes:id.gatewayBytes,interfaceIndex:1,interfaceName:"lo0",flags:id.flags)
    }
    func deleteExactFence(_ id: VPNExactRouteFenceIdentity,deadline: DispatchTime) throws { deletes+=1;denies[id.address.canonical]=nil }
    func lookupFencedHost(_ id: VPNOwnedRouteIdentity,fence: VPNExactRouteFenceIdentity,deadline: DispatchTime) throws -> VPNDarwinRouteSnapshot? { active }
    func installFencedHost(_ id: VPNOwnedRouteIdentity,fence: VPNExactRouteFenceIdentity,deadline: DispatchTime,checkCurrent: () throws -> Void) throws {
        try checkCurrent();active=VPNDarwinRouteSnapshot(destination:id.destination,gatewayBytes:nil,interfaceIndex:id.interfaceIndex,interfaceName:id.interfaceName,flags:id.flags)
    }
    func deleteFencedHost(_ id: VPNOwnedRouteIdentity,fence: VPNExactRouteFenceIdentity,deadline: DispatchTime,checkCurrent: () throws -> Void) throws { try checkCurrent();active=nil }
}
@main private enum Checks {
    static func main() {
        guard getuid()==geteuid(),getuid() != 0,CommandLine.arguments.count==3 else { exit(77) }
        do { try run();print("PASS retained-runtime-"+CommandLine.arguments[1]) }
        catch { fputs("FAIL retained-runtime\n",stderr);exit(1) }
    }
    static func fails(_ expected: VPNExactFenceStoreError,_ body: () throws -> Void) throws {
        do { try body();throw VPNDarwinRouteError.verificationFailed }
        catch let error as VPNExactFenceStoreError { try require(error==expected) }
    }
    static func run() throws {
        let mode=CommandLine.arguments[1]
        if mode=="root-guard" {
            do { _=try VPNRetainedFenceRuntime.system(deadline:.now()+2,checkCurrent:{ throw VPNExactFenceStoreError.invalidState });throw VPNDarwinRouteError.verificationFailed }
            catch VPNDirectoryError.requiresRoot {}
            do { _=try VPNDirectoryProvisioner.openSystemFenceDirectory(create:true);throw VPNDarwinRouteError.verificationFailed }
            catch VPNDirectoryError.requiresRoot {}
            do { try VPNDirectoryProvisioner.requireSystemFenceDirectory(-1);throw VPNDarwinRouteError.verificationFailed }
            catch VPNDirectoryError.requiresRoot {}
            return
        }
        let base=open(CommandLine.arguments[2],O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC)
        try require(base>=0);defer { close(base) }
        let fd=try VPNDirectoryProvisioner.testOpenFencesBelowTrustedBase(base,create:true)
        defer { close(fd) }
        let fake=Kernel(),end=DispatchTime.now()+5
        let claim=VPNExactFenceClaim(resourceID:UUID(),profileSHA256:String(repeating:"a",count:64),generation:1,revision:1)
        let identities=try ["198.19.253.201","2001:db8:fff:fd::c9"].map {
            try VPNExactRouteFenceIdentity(address:VPNRoutePrefix(resource:VPNResource(address:$0)),loopbackIndex:1)
        }
        func seed() throws {
            let store=try VPNExactFenceStore(trustedDirectoryDescriptor:fd)
            let transaction=VPNExactFenceTransaction(store:store,kernel:fake)
            for id in identities {
                let entry=try transaction.ensure(id,claim:claim,deadline:end,checkCurrent:{})
                if mode=="active-withdraw", id.address.family == .ipv4 {
                    let planned=VPNPlannedRoute(role:.resource,destination:id.address,physicalGatewayBytes:nil,interfaceIndex:42,interfaceName:"utun42")
                    let evidence=try VPNRouteKernelEvidence(gateway:Optional<in_addr>.none,interfaceIndex:42,flags:VPNManagedIPv6HostRoute.flags(for:planned))
                    _=try transaction.activateHost(entry,identity:VPNOwnedRouteIdentity(planned:planned,evidence:evidence),claim:claim,deadline:end,checkCurrent:{})
                }
            }
        }
        if ["retained","active-withdraw","foreign","cancel","inventory-retained","inventory-retired","inventory-corrupt"].contains(mode) { try seed() }
        if ["retained","foreign","cancel"].contains(mode) { fake.denies=[:] }
        if mode=="foreign" { fake.foreign=true }
        let inventoryQueue=DispatchQueue(label:"inventory-reader")
        let inventoryKey=DispatchSpecificKey<Bool>()
        inventoryQueue.setSpecific(key:inventoryKey,value:true)
        let namespaceVisited=DispatchSemaphore(value:0)
        func make() throws -> VPNRetainedFenceRuntime {
            try VPNRetainedFenceRuntime(trustedDirectoryDescriptor:fd,kernel:fake,
                checkNamespace:{ owned in
                    try VPNDirectoryProvisioner.testRequireFenceDirectory(owned,belowTrustedBase:base)
                    if DispatchQueue.getSpecific(key:inventoryKey)==true { namespaceVisited.signal() }
                })
        }
        let runtime=try make()
        if mode=="before-restore" { try fails(.recoveryRequired) { try runtime.check() };return }
        if mode=="expired" {
            do { _=try runtime.restore(deadline:.now()-1,checkCurrent:{});throw VPNDarwinRouteError.verificationFailed }
            catch VPNDarwinRouteError.timeout {}
            try fails(.recoveryRequired) { try runtime.check() }
            try fails(.recoveryRequired) { _=try runtime.restore(deadline:end,checkCurrent:{}) }
            try require(fake.adds==0);return
        }
        if mode=="foreign" {
            do { _=try runtime.restore(deadline:end,checkCurrent:{});throw VPNDarwinRouteError.verificationFailed }
            catch VPNDarwinRouteError.missingOrForeign {}
            try fails(.recoveryRequired) { try runtime.check() }
            try require(fake.denies[identities[0].address.canonical] != nil && fake.deletes==0);return
        }
        if mode=="cancel" {
            let before=fake.adds
            try fails(.stale) { _=try runtime.restore(deadline:end,checkCurrent:{ if fake.adds>before { throw VPNExactFenceStoreError.stale } }) }
            try fails(.recoveryRequired) { try runtime.check() }
            try require(fake.adds==before+1 && fake.deletes==0)
            try require(try runtime.store.entries().contains { $0.phase == .adding });return
        }
        let restored=try runtime.restore(deadline:end,checkCurrent:{})
        try runtime.check()
        switch mode {
        case "inventory-retained":
            let first=try runtime.inventory(deadline:end),second=try runtime.inventory(deadline:end)
            try require(first==second && first.scope==VPNRetainedProtectionInventory.namespace)
            try require(first.prefixes==["198.19.253.201/32","2001:db8:fff:fd::c9/128"])
            try require(try VPNRetainedProtectionInventory.decodeCanonical(first.encoded())==first)
        case "inventory-retired":
            let tx=VPNExactFenceTransaction(store:runtime.store,kernel:fake)
            _=try tx.retire(restored[0],deadline:end,checkCurrent:{})
            try require(try runtime.inventory(deadline:end).prefixes.count==1)
        case "inventory-corrupt":
            let name=try VPNExactFenceStore.name(identities[0].address)
            let file=openat(fd,name,O_WRONLY|O_TRUNC|O_NOFOLLOW|O_CLOEXEC)
            try require(file>=0);try require(write(file,"{}",2)==2);close(file)
            do { _=try runtime.inventory(deadline:end);throw VPNDarwinRouteError.verificationFailed }
            catch VPNDarwinRouteError.verificationFailed { throw VPNDarwinRouteError.verificationFailed }
            catch {}
            try fails(.recoveryRequired) { try runtime.check() }
        case "inventory-expired":
            do { _=try runtime.inventory(deadline:.now()-1);throw VPNExactFenceStoreError.invalidState }
            catch VPNDarwinRouteError.timeout {}
            try runtime.check()
        case "inventory-lock-order":
            let entered=DispatchSemaphore(value:0),proceed=DispatchSemaphore(value:0),group=DispatchGroup(),resultLock=NSLock()
            var failed=false
            group.enter()
            DispatchQueue.global().async {
                defer { group.leave() }
                do {
                    _=try runtime.store.withEntries { _ in
                        entered.signal()
                        try require(proceed.wait(timeout:.now()+2) == .success)
                        try runtime.check()
                    }
                } catch { resultLock.lock();failed=true;resultLock.unlock() }
            }
            try require(entered.wait(timeout:.now()+2) == .success)
            group.enter()
            inventoryQueue.async {
                defer { group.leave() }
                do { _=try runtime.inventory(deadline:end) }
                catch { resultLock.lock();failed=true;resultLock.unlock() }
            }
            try require(namespaceVisited.wait(timeout:.now()+2) == .success)
            proceed.signal()
            try require(group.wait(timeout:.now()+3) == .success)
            resultLock.lock();let failure=failed;resultLock.unlock();try require(!failure)
        case "inventory-codec":
            let boot=UUID(),value=try VPNRetainedProtectionInventory(bootID:boot,prefixes:["198.19.253.201/32"])
            let bytes=try value.encoded()
            try require(try VPNRetainedProtectionInventory.decodeCanonical(bytes)==value)
            for prefixes in [["company.example/32"],["127.0.0.1/32"],["198.19.253.201/24"],["198.19.253.201/32","198.19.253.201/32"],Array(repeating:"198.19.253.201/32",count:4097)] {
                do { _=try VPNRetainedProtectionInventory(bootID:boot,prefixes:prefixes);throw VPNDarwinRouteError.verificationFailed }
                catch VPNDarwinRouteError.verificationFailed { throw VPNDarwinRouteError.verificationFailed }
                catch {}
            }
            var object=try JSONSerialization.jsonObject(with:bytes) as! [String:Any]
            for key in ["scope","schemaVersion","extra"] {
                var altered=object
                if key=="schemaVersion" { altered[key]=2 } else { altered[key]="unrecognized" }
                let data=try JSONSerialization.data(withJSONObject:altered,options:[.sortedKeys])
                do { _=try VPNRetainedProtectionInventory.decodeCanonical(data);throw VPNDarwinRouteError.verificationFailed }
                catch VPNDarwinRouteError.verificationFailed { throw VPNDarwinRouteError.verificationFailed }
                catch {}
            }
            object.removeAll()
        case "retained":try require(restored.count==2 && restored.allSatisfy { $0.phase == .applied && $0.claims==[claim] } && fake.denies.count==2)
        case "active-withdraw":try require(restored.count==2 && restored.allSatisfy { $0.active==nil } && fake.active==nil && fake.denies.count==2)
        case "empty":try require(restored.isEmpty && fake.adds==0 && fake.deletes==0)
        case "lock":
            try fails(.recoveryRequired) { _=try make() }
            try runtime.check()
        case "one-shot":
            try fails(.recoveryRequired) { _=try runtime.restore(deadline:end,checkCurrent:{}) }
            try runtime.check();try require(fake.adds==0)
        case "namespace-change":
            try require(fchmod(fd,0o750)==0)
            do { try runtime.check();throw VPNDarwinRouteError.verificationFailed } catch VPNDirectoryError.unsafeDirectory {}
            try require(fchmod(fd,0o700)==0)
            try fails(.recoveryRequired) { try runtime.check() }
        default:throw VPNExactFenceStoreError.invalidState
        }
    }
}
