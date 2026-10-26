import Darwin
import Foundation

@main enum Joint {
    static var stage="inputs"
    static func require(_ value: @autoclosure () throws -> Bool) throws {
        if try !value() { throw VPNBridgeRuntimeError.invalid }
    }
    static func main() {
        if let status=VPNBridgeWorkerSupervisorEntry.runIfRequested(arguments:CommandLine.arguments) { exit(status) }
        let env=ProcessInfo.processInfo.environment
        guard getuid()==geteuid(),getuid()>=500,env["GITHUB_ACTIONS"]=="true",
              env["PROXYPILOT_VM_JOINT_BRIDGE"]=="1",env["PROXYPILOT_VM_GOST_RESOLVER_TESTS"]=="1",
              CommandLine.arguments.count==5 else { exit(77) }
        do { try run() } catch {
            let raw=String(describing:error),allowed=["invalid","expired","transport","unavailable","cleanupUnknown","retired"]
            fputs("FAIL joint-bridge category="+(allowed.contains(raw) ? raw:"other")+" stage="+stage+"\n",stderr);exit(1)
        }
    }
    static func run() throws {
        let folder=CommandLine.arguments[1]
        let directory=open(folder,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC)
        try require(directory>=0);defer { close(directory) }
        guard let port=Int(CommandLine.arguments[4]) else { throw VPNBridgeRuntimeError.invalid }
        let gost=try VPNBridgeWorkerSelection(path:CommandLine.arguments[2])
        let native=try VPNBridgeWorkerSelection.systemResolver(path:CommandLine.arguments[3])
        let store=try VPNBridgeProtectionStore(trustedDirectoryDescriptor:directory)
        var current=true
        func check() throws { guard current else { throw VPNBridgeRuntimeError.invalid } }
        stage="activate"
        let deadline=DispatchTime.now()+5
        let runtime=try store.withPreparedBoot(["198.19.253.201/32"],checkCurrent:check,activate:{ snapshot in
            // Explicit component fixture: durable App union, NOT root custody.
            // Production enters this function only through RuntimeBootstrap.
            try VPNBridgeRuntime.activatePrepared(snapshot:snapshot,route:.direct,bypass:["127.0.0.1/32","::1/128"],
                port:port,gostImage:gost,nativeImage:native,trustedDirectoryDescriptor:directory,path:folder,
                deadline:deadline,checkIntent:check)
        },retire:{ $0.retire() })
        defer { runtime.retire() }
        try require(try store.snapshot()==runtime.initialProtection)
        try require(runtime.initialProtection.matchers==["198.19.253.201/32"])
        print("READY \(runtime.port) \(runtime.resolverPort) \(runtime.ownedWorkers.gost.pid) \(runtime.ownedWorkers.native.pid)");fflush(stdout)
        while true {
            var command:UInt8=0
            guard read(STDIN_FILENO,&command,1)==1 else { return }
            if command==65 {
                stage="validate";try runtime.validate(deadline:.now()+2)
                print("VALIDATED");fflush(stdout)
            } else if command==83 {
                stage="stop";try runtime.stop(deadline:.now()+4)
                print("STOPPED");fflush(stdout);return
            } else if command==73 {
                stage="invalidate";current=false
                var refused=false
                do { try runtime.validate(deadline:.now()+2) } catch { refused=true }
                try require(refused);try runtime.stop(deadline:.now()+2)
                print("INVALIDATED");fflush(stdout);return
            } else { throw VPNBridgeRuntimeError.invalid }
        }
    }
}
