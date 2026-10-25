// Fresh disposable VM only. Supervisor role is production capability code.
import Darwin
import Foundation

@main private enum Worker {
    static var stage="inputs"
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
              CommandLine.arguments.count==3 else { exit(77) }
        do { try run() } catch {
            let allowed=["invalid","expired","transport","unavailable","cleanupUnknown"]
            let category=String(describing:error)
            fputs("FAIL owned-gost-worker category="+(allowed.contains(category) ? category:"other")+" stage="+stage+"\n",stderr);exit(1)
        }
    }
    static func run() throws {
        let folder=CommandLine.arguments[1],image=CommandLine.arguments[2]
        let directory=open(folder,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC)
        try require(directory>=0);defer { close(directory) }
        var info=stat()
        try require(fstat(directory,&info)==0 && info.st_uid==getuid() && info.st_mode&0o7777==0o700)
        let configuration=openat(directory,"gost.json",O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC)
        try require(configuration>=0);defer { close(configuration) }
        try require(fstat(configuration,&info)==0 && info.st_mode&S_IFMT==S_IFREG && info.st_mode&0o7777==0o600 && info.st_uid==getuid() && info.st_nlink==1)
        try require(unlinkat(directory,"gost.json",0)==0)
        stage="selection"
        let selection=try VPNBridgeWorkerSelection(path:image)
        stage="launch"
        let worker=try VPNBridgeWorkerProcess.launch(selection:selection,configuration:configuration,deadline:.now()+4)
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
