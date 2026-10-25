import Darwin
import Foundation

@_cdecl("if_indextoname")
func inventoryInterface(_ index: UInt32,_ output: UnsafeMutablePointer<CChar>?) -> UnsafeMutablePointer<CChar>? {
    guard let output,let name=[7:"en7",42:"utun42"][index] else { return nil }
    for (i,c) in name.utf8CString.enumerated() { output[i]=c };return output
}
private final class NoBootstrapKernel: VPNExactFenceKernel {
    func lookupExactFence(_ identity: VPNExactRouteFenceIdentity,deadline: DispatchTime) throws -> VPNDarwinRouteSnapshot? { throw Checks.Failure.injected }
    func installExactFence(_ identity: VPNExactRouteFenceIdentity,deadline: DispatchTime) throws { throw Checks.Failure.injected }
    func deleteExactFence(_ identity: VPNExactRouteFenceIdentity,deadline: DispatchTime) throws { throw Checks.Failure.injected }
}
@main private enum Checks {
    enum Failure: Error { case assertion, injected }
    static func check(_ value: @autoclosure () throws -> Bool) throws { if try !value() { throw Failure.assertion } }
    static func refused(_ body: () throws -> Void) throws {
        do { try body();throw Failure.assertion } catch Failure.assertion { throw Failure.assertion } catch {}
    }
    static func application(_ address: String,_ revision: UInt64) throws -> VPNValidatedApplication {
        let spec=try VPNApplicationSpec(revision:revision,profileSHA256:String(repeating:"a",count:64),
            resources:[VPNResource(address:address),VPNResource(address:"corp.example")],
            corporateDNS:["10.30.0.53"],authentication:VPNAuthentication(mode:.certificate))
        return VPNValidatedApplication(spec:spec,requiresVPNCredentials:false,requiresPrivateKeyPassword:false)
    }
    static func routePlan() throws -> VPNRoutePlan {
        var peer=in_addr(),gateway=in_addr()
        _="198.51.100.9".withCString { inet_pton(AF_INET,$0,&peer) }
        _="192.0.2.1".withCString { inet_pton(AF_INET,$0,&gateway) }
        let local=try OpenVPNIPAddress(parsing:"10.255.254.1",family:.ipv4)
        let remote=try OpenVPNIPAddress(parsing:"198.51.100.9",family:.ipv4)
        let tunnel=try VPNTunnelInterfaceResolver.resolve(baseline:VPNKernelInterfaceSnapshot(interfaces:[]),
            after:VPNKernelInterfaceSnapshot(interfaces:[VPNKernelInterfaceRecord(index:42,name:"utun42",
                isUp:true,isRunning:true,isPointToPoint:true,addresses:[local])]),
            management:OpenVPNConnectedEvidence(tunnelLocalIPv4:local,tunnelLocalIPv6:nil,remoteAddress:remote,remotePort:443))
        return try VPNRoutePlan(generation:1,revision:1,resources:[VPNResource(address:"10.40.0.0/16")],
            peer:VPNRoutePeerEvidence(peer:peer,gateway:gateway,interfaceIndex:7),tunnel:tunnel,
            dnsDependencies:[VPNRoutePrefix(resource:VPNResource(address:"10.50.0.53"))])
    }
    static func main() {
        guard getuid()==geteuid(),getuid() != 0,CommandLine.arguments.count==3 else { exit(77) }
        do { try run();print("PASS root-inventory-"+CommandLine.arguments[1]) }
        catch { fputs("FAIL root-inventory\n",stderr);exit(1) }
    }
    static func run() throws {
        let mode=CommandLine.arguments[1],boot=UUID()
        let old=try application("10.10.0.0/16",1),new=try application("10.20.0.0/16",2)
        let state=VPNTunnelSnapshot(schemaVersion:2,generation:1,desiredEnabled:false,phase:.off,
            active:old,pending:new,challenge:nil)
        let empty=VPNTunnelSnapshot(schemaVersion:2,generation:0,desiredEnabled:false,phase:.off,
            active:nil,pending:nil,challenge:nil)
        let hosts=try VPNRetainedProtectionInventory(bootID:boot,prefixes:["198.19.253.201/32","2001:db8:fff:fd::c9/128"])
        let plan=try routePlan()
        let journal=VPNRouteJournalSnapshot(schemaVersion:VPNRouteJournalSnapshot.schema(for:plan),plan:plan,phase:.retired,applied:[],operation:nil)
        var stateReads=0,hostReads=0,journalReads=0
        func read() throws -> VPNBridgeRootInventory {
            try VPNBridgeRootInventoryReader.read(deadline:mode=="expired" ? .now()-1:.now()+2,
                retained:{
                    hostReads+=1
                    if mode=="invalid-retained" {
                        let data=try hosts.encoded()
                        var object=try JSONSerialization.jsonObject(with:data) as! [String:Any]
                        object["scope"]="foreign"
                        return try JSONDecoder().decode(VPNRetainedProtectionInventory.self,
                            from:JSONSerialization.data(withJSONObject:object,options:[.sortedKeys]))
                    }
                    if mode=="boot-race",hostReads==2 { return try VPNRetainedProtectionInventory(bootID:UUID(),prefixes:hosts.prefixes) }
                    return hosts
                },state:{
                    stateReads+=1
                    if mode=="failure" { throw Failure.injected }
                    return mode=="state-race" && stateReads==2 ? empty:state
                },journal:{
                    journalReads+=1
                    return mode=="journal-race" && journalReads==2 ? nil:journal
                },checkCurrent:{ if mode=="cancelled" { throw Failure.injected } })
        }
        if mode.hasPrefix("custody-") {
            let fd=open(CommandLine.arguments[2],O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC)
            try check(fd>=0);defer { close(fd) }
            let fences=try VPNDirectoryProvisioner.testOpenFencesBelowTrustedBase(fd,create:true)
            defer { close(fences) }
            let runtime=try VPNRetainedFenceRuntime(trustedDirectoryDescriptor:fences,kernel:NoBootstrapKernel(),
                checkNamespace:{ try VPNDirectoryProvisioner.testRequireFenceDirectory($0,belowTrustedBase:fd) })
            _=try runtime.restore(deadline:.now()+2,checkCurrent:{})
            let initial=try read(),different=try VPNBridgeRootInventory(bootID:initial.bootID,
                stateSHA256:String(repeating:"b",count:64),routeJournalSHA256:initial.routeJournalSHA256,matchers:initial.matchers)
            var changed=false,called=false
            let source=VPNRootBridgeBootstrapSource(runtime:runtime,read:{ _ in try (changed ? different:initial).encoded() })
            if mode=="custody-expired" {
                try refused { try source.withInventory(deadline:.now()-1) { _,_ in called=true } }
                try check(!called);return
            }
            if mode=="custody-changed" {
                try refused { try source.withInventory(deadline:.now()+2) { _,verify in changed=true;try verify() } };return
            }
            if mode=="custody-throw" {
                try refused { try source.withInventory(deadline:.now()+2) { _,_ in throw Failure.injected } }
                try runtime.store.withEntries { _ in };return
            }
            let attempted=DispatchSemaphore(value:0),finished=DispatchSemaphore(value:0)
            try source.withInventory(deadline:.now()+2) { data,verify in
                try check(try VPNBridgeRootInventory.decodeCanonical(data)==initial)
                DispatchQueue.global().async {
                    attempted.signal()
                    _=try? runtime.store.withEntries { _ in finished.signal() }
                }
                try check(attempted.wait(timeout:.now()+1) == .success)
                try check(finished.wait(timeout:.now()+0.05) == .timedOut)
                try verify()
            }
            try check(finished.wait(timeout:.now()+1) == .success);return
        }
        switch mode {
        case "union":
            let value=try read()
            try check(value.matchers==["10.10.0.0/16","10.20.0.0/16","10.30.0.53/32","10.40.0.0/16","10.50.0.53/32","198.19.253.201/32","2001:db8:fff:fd::c9/128"])
            try check(value.bootID==boot && value.routeJournalSHA256 != nil)
            try check(try VPNBridgeRootInventory.decodeCanonical(value.encoded())==value)
            try check(stateReads==2 && hostReads==2 && journalReads==2)
        case "state-race","journal-race","boot-race","expired","failure","cancelled","invalid-retained":
            try refused { _=try read() }
            if mode=="expired" || mode=="cancelled" { try check(stateReads==0 && hostReads==0 && journalReads==0) }
        case "journal-read":
            let fd=open(CommandLine.arguments[2],O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC)
            try check(fd>=0);defer { close(fd) }
            let store=try VPNRouteJournal(trustedDirectoryDescriptor:fd)
            try check(try store.loadIfPresent()==nil)
            _=try store.create(plan);_=try store.abandonUnapplied(generation:1,revision:1)
            try check(try store.loadIfPresent()==journal)
            let file=openat(fd,VPNRouteJournal.name,O_WRONLY|O_TRUNC|O_NOFOLLOW|O_CLOEXEC)
            try check(file>=0);try check(write(file,"{}",2)==2);close(file)
            try refused { _=try store.loadIfPresent() }
        case "offer":
            let value=try read(),a=VPNBridgeBootstrapOffer(inventory:value),b=VPNBridgeBootstrapOffer(inventory:value)
            try check(a.nonce != b.nonce && (try a.acknowledgement()) != (try b.acknowledgement()))
            try check(try VPNBridgeBootstrapOffer.decodeCanonical(a.encoded())==a)
        case "codec":
            let value=try read(),bytes=try value.encoded()
            let object=try JSONSerialization.jsonObject(with:bytes) as! [String:Any]
            for key in ["scope","schemaVersion","stateSHA256","routeJournalSHA256","extra"] {
                var changed=object;changed[key]="bad"
                let data=try JSONSerialization.data(withJSONObject:changed,options:[.sortedKeys])
                try refused { _=try VPNBridgeRootInventory.decodeCanonical(data) }
            }
            try refused { _=try VPNBridgeRootInventory.decodeCanonical(Data(repeating:32,count:VPNBridgeRootInventory.maximumBytes+1)) }
            try refused { _=try VPNBridgeRootInventory(bootID:boot,stateSHA256:String(repeating:"a",count:64),
                routeJournalSHA256:nil,matchers:Array(repeating:"10.10.0.0/16",count:VPNBridgeRootInventory.maximumMatchers+1)) }
            for invalid in [["corp.example"],["10.10.0.1"],["10.10.0.0/16","10.10.0.0/16"],["2001:DB8::/32"]] {
                try refused { _=try VPNBridgeRootInventory(bootID:boot,stateSHA256:String(repeating:"a",count:64),routeJournalSHA256:nil,matchers:invalid) }
            }
        default:throw Failure.assertion
        }
    }
}
