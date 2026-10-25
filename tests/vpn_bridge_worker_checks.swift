import Darwin
import Foundation

@main private enum Checks {
    static func require(_ value: @autoclosure () throws -> Bool) throws {
        if try !value() { throw VPNBridgeWorkerError.invalid }
    }
    static func rejected(_ body: () throws -> Void) throws {
        var refused=false;do { try body() } catch { refused=true };try require(refused)
    }
    static func main() {
        if let result=VPNBridgeWorkerSupervisorEntry.runIfRequested(arguments:CommandLine.arguments) { exit(result) }
        guard getuid()==geteuid(),getuid()>=500,CommandLine.arguments.count==4 else { exit(77) }
        do { try run() } catch { fputs("FAIL bridge-worker category=\(error)\n",stderr);exit(1) }
    }
    static func run() throws {
        let mode=CommandLine.arguments[1],folder=CommandLine.arguments[2],path=CommandLine.arguments[3]
        let marker=folder+"/child"
        let data=Data((marker+"\n"+(mode=="force" ? "ignore":mode=="early-exit" ? "exit":"normal")+"\n").utf8)
        let config=open(folder+"/config",O_RDWR|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0o600)
        try require(config>=0);defer { close(config) }
        try data.withUnsafeBytes { try require(write(config,$0.baseAddress!,$0.count)==$0.count) }
        if mode != "named-config" { try require(unlink(folder+"/config")==0) }
        if mode=="production-pin" {
            try rejected { _=try VPNBridgeWorkerSelection(path:path) }
            try require(access(marker,F_OK) != 0);print("PASS bridge-worker-"+mode);return
        }
        let selection=try VPNBridgeWorkerSelection.test(path:path)
        if mode=="dead-owner" || mode=="datagram" {
            var pair:[Int32]=[-1,-1]
            try require(socketpair(AF_UNIX,mode=="datagram" ? SOCK_DGRAM:SOCK_STREAM,0,&pair)==0)
            defer { for fd in pair where fd>=0 { close(fd) } }
            let deadline=DispatchTime.now()+3
            let pid=try VPNBridgeWorkerIO.spawn(path:CommandLine.arguments[0],
                argv:[VPNBridgeWorkerSupervisorEntry.processName,VPNBridgeWorkerSupervisorEntry.argument],
                mappings:[(pair[1],20),(config,21),(selection.descriptor,22)])
            close(pair[1]);pair[1] = -1
            if mode=="dead-owner" {
                let frame=Array("PPBGST01".utf8)+VPNBridgeWorkerIO.encode(deadline.uptimeNanoseconds)
                    + VPNBridgeWorkerIO.encode(selection.bytes)+Array(selection.digest)
                _=try VPNBridgeWorkerIO.transfer(pair[0],bytes:frame,count:frame.count,deadline:deadline)
            }
            close(pair[0]);pair[0] = -1
            var status:Int32=0,result: pid_t=0
            while DispatchTime.now()<deadline {
                result=waitpid(pid,&status,WNOHANG)
                if result==pid { break };usleep(1_000)
            }
            try require(result==pid && status==(69<<8) && access(marker,F_OK) != 0)
            print("PASS bridge-worker-"+mode);return
        }
        if mode=="changed-image" { _=chmod(path,0o777) }
        if ["named-config","changed-image","expired"].contains(mode) {
            try rejected { _=try VPNBridgeWorkerProcess.launch(selection:selection,configuration:config,
                deadline:mode=="expired" ? .now()-1:.now()+3) }
            try require(access(marker,F_OK) != 0);print("PASS bridge-worker-"+mode);return
        }
        var worker: VPNBridgeWorkerProcess? = try .launch(selection:selection,configuration:config,deadline:.now()+3)
        let stamp=worker!.child,deadline=DispatchTime.now()+2
        while access(marker,F_OK) != 0,DispatchTime.now()<deadline { usleep(1_000) }
        let fields=try String(contentsOfFile:marker,encoding:.utf8).split(separator:" ").compactMap { Int32($0.trimmingCharacters(in:.whitespacesAndNewlines)) }
        try require(fields==[stamp.pid,stamp.parent])
        if mode=="crash" {
            print("READY \(stamp.pid) \(stamp.parent)");fflush(stdout)
            while true { sleep(1) }
        }
        if mode=="early-exit" {
            usleep(400_000);try rejected { try worker!.checkLive() }
            try worker!.stop(deadline:.now()+2)
        } else if mode=="drop" {
            worker=nil
        } else {
            try worker!.checkLive()
            try worker!.stop(deadline:.now()+2)
            try worker!.stop(deadline:.now()+2)
            try rejected { try worker!.checkLive() }
        }
        let end=DispatchTime.now()+3
        while (try? VPNBridgeWorkerStamp.live(stamp.pid))==stamp,DispatchTime.now()<end { usleep(1_000) }
        try require((try? VPNBridgeWorkerStamp.live(stamp.pid)) != stamp)
        print("PASS bridge-worker-"+mode)
    }
}
