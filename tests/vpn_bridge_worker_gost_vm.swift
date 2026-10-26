// Fresh disposable VM only. Supervisor role is production capability code.
import Darwin
import Foundation

@main private enum Worker {
    static var stage="inputs"
    static var phase="none",launchStarted:UInt64=0
    static func require(_ value: @autoclosure () throws -> Bool) throws {
        if try !value() { throw VPNBridgeWorkerError.invalid }
    }
    static func main() {
        if let status=VPNBridgeWorkerSupervisorEntry.runIfRequested(arguments:CommandLine.arguments) { exit(status) }
        let environment=ProcessInfo.processInfo.environment
        guard getuid()==geteuid(),getuid()>=500,environment["GITHUB_ACTIONS"]=="true",
              environment["PROXYPILOT_VM_BRIDGE_WORKER_GOST"]=="1",
              environment["PROXYPILOT_VM_GOST_ATOMIC_TESTS"]=="1",
              environment["PROXYPILOT_VM_GOST_RESOLVER_TESTS"]=="1",
              (CommandLine.arguments.count==3 || (CommandLine.arguments.count==4 && CommandLine.arguments[3]=="--production-configuration")) else { exit(77) }
        do { try run() } catch {
            let allowed=["invalid","expired","transport","unavailable","cleanupUnknown"]
            let category=String(describing:error)
            let elapsed=launchStarted==0 ? 0:(DispatchTime.now().uptimeNanoseconds-launchStarted)/1_000_000
            fputs("FAIL owned-gost-worker category="+(allowed.contains(category) ? category:"other")+" stage="+stage+" phase="+phase+" elapsedMs=\(elapsed)\n",stderr);exit(1)
        }
    }
    static func run() throws {
        let folder=CommandLine.arguments[1],image=CommandLine.arguments[2]
        let directory=open(folder,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC)
        try require(directory>=0);defer { close(directory) }
        var info=stat()
        try require(fstat(directory,&info)==0 && info.st_uid==getuid() && info.st_mode&0o7777==0o700)
        let production=CommandLine.arguments.count==4
        let filename=production ? "recipe.json":"gost.json"
        let input=openat(directory,filename,O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC)
        try require(input>=0);defer { close(input) }
        try require(fstat(input,&info)==0 && info.st_mode&S_IFMT==S_IFREG && info.st_mode&0o7777==0o600 && info.st_uid==getuid() && info.st_nlink==1)
        try require(unlinkat(directory,filename,0)==0)
        let deadline=DispatchTime.now()+4
        var ownedConfiguration: VPNBridgeConfigurationFile?
        if production {
            struct Recipe: Decodable { let port: Int, apiPassword: String, resolverPassword: String }
            try require(info.st_size>0 && info.st_size<=1024)
            var bytes=[UInt8](repeating:0,count:1024)
            let count=read(input,&bytes,bytes.count);try require(count==info.st_size)
            let recipe=try JSONDecoder().decode(Recipe.self,from:Data(bytes.prefix(count)))
            let protected=VPNBridgeProtectedSnapshot(schemaVersion:1,revision:1,
                matchers:["198.19.253.201/32","2001:db8:fff:fd::c9/128"])
            let config=try VPNBridgeGOSTConfiguration(route:.http(host:"192.0.2.1",port:9),port:recipe.port,
                bypass:["127.0.0.1/32"],protected:protected,epochDirectory:folder,
                resolverPort:recipe.port==55557 ? 55558:55557,
                apiPassword:Data(recipe.apiPassword.utf8),resolverPassword:Data(recipe.resolverPassword.utf8))
            ownedConfiguration=try config.materialize(trustedDirectoryDescriptor:directory,deadline:deadline,checkCurrent:{})
        }
        defer { withExtendedLifetime(ownedConfiguration) {} }
        let configuration=ownedConfiguration?.descriptor ?? input
        stage="selection"
        let selection=try VPNBridgeWorkerSelection(path:image,deadline:deadline)
        stage="launch"
        launchStarted=DispatchTime.now().uptimeNanoseconds
        let worker=try VPNBridgeWorkerProcess.launch(selection:selection,configuration:configuration,deadline:deadline,
            trace:{ phase=$0.rawValue })
        // Parent holds this object through external API checks; no secrets are
        // emitted. Native audit/code validation is exercised by a private probe.
        print("READY \(worker.child.pid) \(worker.child.parent)");fflush(stdout)
        while true {
            var command:UInt8=0
            guard read(STDIN_FILENO,&command,1)==1 else { return }
            if command==65 {
                stage="authentication"
                let clock=VPNDarwinDNSContinuousClock()
                let connections=try VPNBridgeUnixAPIConnections(trustedDirectoryDescriptor:directory,clock:clock,
                    authenticatePeer:{ try worker.authenticate($0) })
                let connection=try connections.open(deadline:clock.now().addingChecked(2_000_000_000),checkCurrent:{ try worker.checkLive() })
                try connection.authenticate();connection.close()
                var wrong=audit_token_t();wrong.val.5=UInt32(getpid())
                var refused=false;do { try worker.authenticate(wrong) } catch { refused=true }
                try require(refused)
                print("AUTHENTICATED");fflush(stdout)
            } else if command==83 {
                stage="stop"
                try worker.checkLive();try worker.stop(deadline:.now()+2)
                print("STOPPED");fflush(stdout);return
            } else { throw VPNBridgeWorkerError.invalid }
        }
    }
}
