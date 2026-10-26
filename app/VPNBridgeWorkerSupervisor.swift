import Darwin
import Foundation

/// Private ordinary-user role of the same signed frontend. One inherited Unix
/// capability owns one fixed GOST child. Nothing from argv/environment supplies
/// a command, path, credential or executable choice. Parent EOF always stops it.
enum VPNBridgeWorkerSupervisorEntry {
    static let argument="--proxypilot-private-bridge-worker-v1"
    static let processName="proxypilot-bridge-worker"
    static let resolverArgument="--proxypilot-private-resolver-worker-v1"
    static let resolverProcessName="proxypilot-resolver-worker"
    static func runIfRequested(arguments: [String]) -> Int32? {
        guard arguments.contains(argument) || arguments.first==processName
                || arguments.contains(resolverArgument) || arguments.first==resolverProcessName else { return nil }
        let native=arguments==[resolverProcessName,resolverArgument]
        guard (arguments==[processName,argument] || native),getuid()==geteuid(),getuid()>=500 else { return 77 }
        signal(SIGPIPE,SIG_IGN);signal(SIGTERM,SIG_IGN);signal(SIGINT,SIG_IGN);signal(SIGHUP,SIG_IGN)
        umask(0o077) // Only this private process; GOST Unix API must stay owner-private.
        var child: pid_t?
        defer { if let child { stop(child) } }
        var pipes=[Int32]()
        defer { for fd in pipes { close(fd) } }
        do {
            var control=stat(),configuration=stat(),executable=stat(),uid: uid_t=0,gid: gid_t=0
            var type:Int32=0,typeSize=socklen_t(MemoryLayout<Int32>.size)
            guard fstat(20,&control)==0,control.st_mode&S_IFMT==S_IFSOCK,
                  getsockopt(20,SOL_SOCKET,SO_TYPE,&type,&typeSize)==0,type==SOCK_STREAM,
                  fcntl(20,F_SETFL,O_NONBLOCK)==0,
                  getpeereid(20,&uid,&gid)==0,uid==getuid(),
                  fstat(21,&configuration)==0,configuration.st_mode&S_IFMT==S_IFREG,
                  configuration.st_uid==getuid(),configuration.st_mode&0o7777==0o600,
                  configuration.st_nlink==0,configuration.st_size>0,configuration.st_size<=1024*1024,
                  fstat(22,&executable)==0 else { throw VPNBridgeWorkerError.invalid }
            let initial=DispatchTime.now()+5
            let frame=try VPNBridgeWorkerIO.transfer(20,bytes:nil,count:56,deadline:initial)
            guard Array(frame.prefix(8))==Array((native ? "PPBRSV01":"PPBGST01").utf8) else { throw VPNBridgeWorkerError.invalid }
            let deadline=DispatchTime(uptimeNanoseconds:VPNBridgeWorkerIO.number(frame[8..<16]))
            guard deadline<=initial else { throw VPNBridgeWorkerError.invalid }
            var path=[CChar](repeating:0,count:Int(MAXPATHLEN))
            guard fcntl(22,F_GETPATH,&path)==0 else { throw VPNBridgeWorkerError.invalid }
            let choice: VPNBridgeWorkerSelection
            #if VPN_BRIDGE_WORKER_TESTING
            choice=try .test(path:String(cString:path),role:native ? .systemResolver:.gost,deadline:deadline)
            #else
            choice=try native ? .systemResolver(path:String(cString:path),deadline:deadline)
                              : VPNBridgeWorkerSelection(path:String(cString:path),deadline:deadline)
            #endif
            var named=stat()
            guard choice.bytes==VPNBridgeWorkerIO.number(frame[16..<24]),choice.digest==Data(frame[24..<56]),
                  fstat(choice.descriptor,&named)==0,VPNBridgeWorkerSelection.same(executable,named),
                  lseek(21,0,SEEK_SET)==0 else { throw VPNBridgeWorkerError.invalid }
            try VPNBridgeWorkerIO.current(deadline)
            // If the owner already disappeared while validation was running,
            // do not briefly create a listener just to stop it again.
            var byte:UInt8=0
            let peek=recv(20,&byte,1,MSG_PEEK|MSG_DONTWAIT)
            guard peek<0,(errno==EAGAIN || errno==EWOULDBLOCK) else { throw VPNBridgeWorkerError.unavailable }
            func ownerCurrent() throws {
                var byte:UInt8=0
                let peek=recv(20,&byte,1,MSG_PEEK|MSG_DONTWAIT)
                guard peek<0,(errno==EAGAIN || errno==EWOULDBLOCK) else { throw VPNBridgeWorkerError.unavailable }
            }
            var startup:[Int32]=[-1,-1],output:[Int32]=[-1,-1]
            if native {
                guard configuration.st_size<=512,pipe(&startup)==0 else { throw VPNBridgeWorkerError.invalid }
                pipes+=startup
                guard pipe(&output)==0 else { throw VPNBridgeWorkerError.transport };pipes+=output
                for fd in pipes {
                    guard fcntl(fd,F_SETFD,FD_CLOEXEC)==0 else { throw VPNBridgeWorkerError.transport }
                }
                for fd in [startup[1],output[0]] {
                    guard fcntl(fd,F_SETFL,O_NONBLOCK)==0 else { throw VPNBridgeWorkerError.transport }
                }
            }
            let mappings:[(Int32,Int32)]
            if native { mappings=[(startup[0],0),(output[1],1)] } else { mappings=[(21,0)] }
            let pid=try VPNBridgeWorkerIO.spawn(path:choice.path,
                argv:native ? ["system-resolver"]:["gost","-C","-"],
                mappings:mappings)
            child=pid
            var nativeReady=[UInt8]()
            if native {
                close(startup[0]);pipes.removeAll { $0==startup[0] }
                close(output[1]);pipes.removeAll { $0==output[1] }
                var message=try VPNBridgeWorkerIO.transfer(21,bytes:nil,count:Int(configuration.st_size),deadline:deadline,checkCurrent:ownerCurrent)
                defer { message.withUnsafeMutableBufferPointer { $0.initialize(repeating:0) } }
                guard message.last==10 else { throw VPNBridgeWorkerError.invalid }
                _=try VPNBridgeWorkerIO.transfer(startup[1],bytes:message,count:message.count,deadline:deadline,checkCurrent:ownerCurrent)
                close(21)
                while nativeReady.last != 10 {
                    guard nativeReady.count<4096 else { throw VPNBridgeWorkerError.invalid }
                    nativeReady+=try VPNBridgeWorkerIO.transfer(output[0],bytes:nil,count:1,deadline:deadline,checkCurrent:ownerCurrent)
                }
                // Keep startup writer open for the whole child lifetime. Parent
                // loss still reaches this sole owner/reaper through control20.
            }
            try choice.validate(deadline:deadline)
            let stamp=try VPNBridgeWorkerStamp.live(pid)
            guard stamp.parent==getpid() else { throw VPNBridgeWorkerError.unavailable }
            var ready=Array((native ? "PPBRRD01":"PPBGRD01").utf8)+VPNBridgeWorkerIO.encode(UInt64(pid))
                + VPNBridgeWorkerIO.encode(stamp.seconds)+VPNBridgeWorkerIO.encode(stamp.microseconds)
            if native { ready+=VPNBridgeWorkerIO.encode(UInt64(nativeReady.count))+nativeReady }
            _=try VPNBridgeWorkerIO.transfer(20,bytes:ready,count:ready.count,deadline:deadline)
            while true {
                if ended(pid) { child=nil;return 0 }
                var item=pollfd(fd:20,events:Int16(POLLIN|POLLHUP|POLLERR),revents:0)
                let result=poll(&item,1,20)
                if result<0 && errno==EINTR { continue }
                if result<0 || item.revents != 0 { return 0 } // EOF, stop byte or invalid channel.
            }
        } catch { return 69 }
    }
    private static func ended(_ pid: pid_t) -> Bool {
        var status: Int32=0
        var result: pid_t
        repeat { result=waitpid(pid,&status,WNOHANG) } while result<0 && errno==EINTR
        // A failed wait never grants permission to signal an unowned PID.
        return result != 0
    }
    private static func stop(_ pid: pid_t) {
        guard !ended(pid) else { return }
        _=kill(pid,SIGTERM)
        let deadline=DispatchTime.now() + .milliseconds(500)
        while DispatchTime.now()<deadline {
            if ended(pid) { return };usleep(1_000)
        }
        _=kill(pid,SIGKILL)
        var status: Int32=0
        while waitpid(pid,&status,0)<0 && errno==EINTR {}
    }
}
