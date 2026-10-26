import Darwin
import Foundation

@main enum Owner {
    static var stage="inputs"
    static func require(_ value: @autoclosure () throws -> Bool) throws {
        if try !value() { throw VPNBridgeWorkerError.invalid }
    }
    static func main() {
        if let status=VPNBridgeWorkerSupervisorEntry.runIfRequested(arguments:CommandLine.arguments) { exit(status) }
        let env=ProcessInfo.processInfo.environment
        guard getuid()==geteuid(),getuid()>=500,env["GITHUB_ACTIONS"]=="true",
              env["PROXYPILOT_VM_NATIVE_RESOLVER_OWNER"]=="1",
              env["PROXYPILOT_VM_GOST_RESOLVER_TESTS"]=="1",CommandLine.arguments.count==3 else { exit(77) }
        do { try run() } catch {
            let raw=String(describing:error),allowed=["invalid","expired","transport","unavailable","cleanupUnknown"]
            fputs("FAIL native-resolver-owner category="+(allowed.contains(raw) ? raw:"other")+" stage="+stage+"\n",stderr);exit(1)
        }
    }
    static func run() throws {
        let folder=CommandLine.arguments[1],image=CommandLine.arguments[2]
        let directory=open(folder,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC)
        try require(directory>=0);defer { close(directory) }
        _=try VPNBridgeConfigurationFile.checkDirectory(directory,path:folder)
        let input=openat(directory,"recipe.json",O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC)
        try require(input>=0);defer { close(input) }
        var info=stat()
        try require(fstat(input,&info)==0 && info.st_mode&S_IFMT==S_IFREG && info.st_uid==getuid()
                    && info.st_nlink==1 && info.st_mode&0o7777==0o600 && info.st_size>0 && info.st_size<=256)
        try require(unlinkat(directory,"recipe.json",0)==0)
        var data=[UInt8](repeating:0,count:256)
        let count=read(input,&data,data.count);try require(count==info.st_size)
        struct Recipe: Decodable { let password: String }
        let recipe=try JSONDecoder().decode(Recipe.self,from:Data(data.prefix(count)))
        stage="selection"
        let deadline=DispatchTime.now()+4
        let selection=try VPNBridgeWorkerSelection.systemResolver(path:image,deadline:deadline)
        stage="start"
        let native=try VPNSystemResolverWorker.start(selection:selection,password:Data(recipe.password.utf8),
            trustedDirectoryDescriptor:directory,path:folder,deadline:deadline,checkCurrent:{})
        var stopped=false
        defer { if !stopped { try? native.stop(deadline:.now()+2) } }
        print("READY \(native.port) \(native.child.pid) \(native.child.parent)");fflush(stdout)
        while true {
            var command:UInt8=0
            guard read(STDIN_FILENO,&command,1)==1 else { return }
            if command==65 {
                stage="validate";try native.validate(deadline:.now()+2,checkCurrent:{})
                print("AUTHENTICATED");fflush(stdout)
            } else if command==83 {
                stage="stop";try native.stop(deadline:.now()+2);stopped=true
                print("STOPPED");fflush(stdout);return
            } else { throw VPNBridgeWorkerError.invalid }
        }
    }
}
