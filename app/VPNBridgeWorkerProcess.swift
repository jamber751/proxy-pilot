import CryptoKit
import Darwin
import Foundation
import MachO

// No profiles, proxy credentials, paths or raw system errors in diagnostics.
enum VPNBridgeWorkerError: Error { case invalid, expired, transport, unavailable, cleanupUnknown }
struct VPNBridgeWorkerStamp: Equatable {
    let pid: pid_t, parent: pid_t
    let seconds: UInt64, microseconds: UInt64
    static func live(_ pid: pid_t) throws -> Self {
        var value=proc_bsdinfo();let size=Int32(MemoryLayout.size(ofValue:value))
        guard pid>0,proc_pidinfo(pid,PROC_PIDTBSDINFO,0,&value,size)==size,
              value.pbi_uid==getuid(),value.pbi_ruid==getuid(),value.pbi_svuid==getuid(),
              value.pbi_status != UInt32(SZOMB) else { throw VPNBridgeWorkerError.unavailable }
        return Self(pid:pid,parent:pid_t(value.pbi_ppid),seconds:value.pbi_start_tvsec,microseconds:value.pbi_start_tvusec)
    }
}

/// The production executable is the fixed signed Universal candidate. The
/// descriptor and named inode stay bound across validation/spawn. No IPC path.
final class VPNBridgeWorkerSelection {
    enum Role { case gost, systemResolver }
    let role: Role
    private(set) var descriptor: Int32
    let path: String, bytes: UInt64, digest: Data
    private let attributes: stat
    convenience init(path: String,deadline: DispatchTime = .now()+5) throws {
        try self.init(path:path,role:.gost,bytes:70633296,
            deadline:deadline,digest:Data([0x28,0x66,0x64,0x49,0xb5,0x4a,0xc0,0xe6,0x3c,0x70,0x07,0x3b,0xb7,0x58,0x44,0xfc,0xa6,0x47,0x14,0x88,0xb7,0x45,0x24,0x0d,0xbe,0x40,0x1e,0xc2,0xcf,0xa4,0x05,0xe7]))
    }
    static func systemResolver(path: String,deadline: DispatchTime = .now()+5) throws -> VPNBridgeWorkerSelection {
        try VPNBridgeWorkerSelection(path:path,role:.systemResolver,bytes:12059104,deadline:deadline,
            digest:Data([0x32,0x6f,0xe7,0x70,0xb0,0x1e,0x36,0x08,0x52,0x89,0x55,0xb2,0x38,0x53,0x12,0xec,
                         0x5f,0x6c,0x9f,0xa2,0x69,0x08,0x6e,0x57,0x50,0x41,0x7b,0x86,0x29,0xef,0x69,0x64]))
    }
    #if VPN_BRIDGE_WORKER_TESTING
    static func test(path: String,role: Role = .gost,deadline: DispatchTime = .now()+5) throws -> VPNBridgeWorkerSelection {
        let data=try Data(contentsOf:URL(fileURLWithPath:path))
        return try VPNBridgeWorkerSelection(path:path,role:role,bytes:UInt64(data.count),deadline:deadline,digest:Data(SHA256.hash(data:data)))
    }
    #endif
    private init(path: String,role: Role,bytes: UInt64,deadline: DispatchTime,digest: Data) throws {
        guard path.hasPrefix("/"),!path.utf8.contains(0),digest.count==32,bytes>0,bytes<=80*1024*1024 else { throw VPNBridgeWorkerError.invalid }
        let fd=open(path,O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC)
        guard fd>=0 else { throw VPNBridgeWorkerError.invalid }
        var info=stat()
        guard fstat(fd,&info)==0,info.st_mode&S_IFMT==S_IFREG,info.st_nlink==1,
              [uid_t(0),getuid()].contains(info.st_uid),info.st_mode&0o022==0,
              info.st_mode&0o111 != 0,info.st_size==Int64(bytes) else { close(fd);throw VPNBridgeWorkerError.invalid }
        descriptor=fd;self.path=path;self.role=role;self.bytes=bytes;self.digest=digest;attributes=info
        do { try validate(deadline:deadline) } catch { close(fd);descriptor = -1;throw error }
    }
    deinit { if descriptor>=0 { close(descriptor) } }
    func validate(deadline: DispatchTime) throws {
        try VPNBridgeWorkerIO.current(deadline)
        var held=stat(),named=stat()
        guard fstat(descriptor,&held)==0,lstat(path,&named)==0,
              Self.same(attributes,held),Self.same(held,named),lseek(descriptor,0,SEEK_SET)==0 else { throw VPNBridgeWorkerError.invalid }
        var hash=SHA256(),remaining=Int(bytes),buffer=[UInt8](repeating:0,count:64*1024)
        while remaining>0 {
            try VPNBridgeWorkerIO.current(deadline)
            let count=Darwin.read(descriptor,&buffer,min(buffer.count,remaining))
            if count<0 && errno==EINTR { continue }
            guard count>0 else { throw VPNBridgeWorkerError.invalid }
            hash.update(data:Data(buffer.prefix(count)));remaining-=count
        }
        guard Darwin.read(descriptor,&buffer,1)==0,Data(hash.finalize())==digest,
              fstat(descriptor,&held)==0,lstat(path,&named)==0,
              Self.same(attributes,held),Self.same(held,named) else { throw VPNBridgeWorkerError.invalid }
        try VPNBridgeWorkerIO.current(deadline)
    }
    static func same(_ a: stat,_ b: stat) -> Bool {
        a.st_dev==b.st_dev && a.st_ino==b.st_ino && a.st_uid==b.st_uid && a.st_mode==b.st_mode
        && a.st_nlink==b.st_nlink && a.st_size==b.st_size
        && a.st_mtimespec.tv_sec==b.st_mtimespec.tv_sec && a.st_mtimespec.tv_nsec==b.st_mtimespec.tv_nsec
        && a.st_ctimespec.tv_sec==b.st_ctimespec.tv_sec && a.st_ctimespec.tv_nsec==b.st_ctimespec.tv_nsec
    }
}

enum VPNBridgeWorkerIO {
    static func current(_ deadline: DispatchTime) throws {
        guard DispatchTime.now()<deadline else { throw VPNBridgeWorkerError.expired }
    }
    static func number(_ bytes: ArraySlice<UInt8>) -> UInt64 { bytes.reduce(0) { ($0<<8)|UInt64($1) } }
    static func encode(_ value: UInt64) -> [UInt8] { (0..<8).reversed().map { UInt8(truncatingIfNeeded:value>>($0*8)) } }
    static func transfer(_ fd: Int32,bytes: [UInt8]?,count: Int,deadline: DispatchTime,
                         checkCurrent: () throws -> Void = {}) throws -> [UInt8] {
        var result=[UInt8]();var buffer=[UInt8](repeating:0,count:4096),offset=0
        while offset<count {
            try current(deadline);try checkCurrent()
            var item=pollfd(fd:fd,events:Int16(bytes==nil ? POLLIN:POLLOUT),revents:0)
            let wait=poll(&item,1,20)
            if wait<0 && errno==EINTR { continue }
            guard wait>=0,item.revents&Int16(POLLERR|POLLNVAL)==0 else { throw VPNBridgeWorkerError.transport }
            if wait==0 { continue }
            let size=min(4096,count-offset)
            let n: Int
            if let bytes {
                n=bytes.withUnsafeBytes { Darwin.write(fd,$0.baseAddress!.advanced(by:offset),size) }
            } else {
                n=Darwin.read(fd,&buffer,size)
                if n>0 { result+=buffer.prefix(n) }
            }
            if n<0 && (errno==EINTR || errno==EAGAIN) { continue }
            guard n>0 else { throw VPNBridgeWorkerError.transport };offset+=n
        }
        try current(deadline);try checkCurrent();return result
    }
    static func validateConfiguration(_ descriptor: Int32) throws {
        var info=stat()
        guard fstat(descriptor,&info)==0,info.st_mode&S_IFMT==S_IFREG,info.st_uid==getuid(),
              info.st_mode&0o7777==0o600,info.st_nlink==0,info.st_size>0,info.st_size<=1024*1024 else {
            throw VPNBridgeWorkerError.invalid
        }
    }
    static func spawn(path: String,argv: [String],mappings: [(Int32,Int32)]) throws -> pid_t {
        // Relocate every source above every fixed target before any dup2.
        var staged=[(Int32,Int32)]()
        defer { staged.forEach { close($0.0) } }
        for (source,target) in mappings {
            let copy=fcntl(source,F_DUPFD_CLOEXEC,64)
            guard copy>=0 else { throw VPNBridgeWorkerError.transport };staged.append((copy,target))
        }
        var actions: posix_spawn_file_actions_t?,attributes: posix_spawnattr_t?
        guard posix_spawn_file_actions_init(&actions)==0 else { throw VPNBridgeWorkerError.transport }
        defer { posix_spawn_file_actions_destroy(&actions) }
        guard posix_spawnattr_init(&attributes)==0 else { throw VPNBridgeWorkerError.transport }
        defer { posix_spawnattr_destroy(&attributes) }
        guard posix_spawn_file_actions_addopen(&actions,0,"/dev/null",O_RDONLY,0)==0,
              posix_spawn_file_actions_addopen(&actions,1,"/dev/null",O_WRONLY,0)==0,
              posix_spawn_file_actions_addopen(&actions,2,"/dev/null",O_WRONLY,0)==0 else { throw VPNBridgeWorkerError.transport }
        for (source,target) in staged {
            guard posix_spawn_file_actions_adddup2(&actions,source,target)==0 else { throw VPNBridgeWorkerError.transport }
        }
        var mask=sigset_t(),defaults=sigset_t();sigemptyset(&mask);sigfillset(&defaults)
        guard posix_spawnattr_setflags(&attributes,Int16(POSIX_SPAWN_CLOEXEC_DEFAULT|POSIX_SPAWN_SETSIGDEF|POSIX_SPAWN_SETSIGMASK))==0,
              posix_spawnattr_setsigmask(&attributes,&mask)==0,posix_spawnattr_setsigdefault(&attributes,&defaults)==0 else { throw VPNBridgeWorkerError.transport }
        let strings=argv.map { strdup($0) }
        defer { strings.forEach { if let value=$0 { free(value) } } }
        guard strings.allSatisfy({ $0 != nil }) else { throw VPNBridgeWorkerError.transport }
        var arguments=strings+[nil],environment:[UnsafeMutablePointer<CChar>?]=[nil],pid: pid_t=0
        let status=arguments.withUnsafeMutableBufferPointer { args in
            environment.withUnsafeMutableBufferPointer { env in
                posix_spawn(&pid,path,&actions,&attributes,args.baseAddress!,env.baseAddress!)
            }
        }
        guard status==0,pid>0 else { throw VPNBridgeWorkerError.transport };return pid
    }
}

/// Owns/reaps only its direct supervisor. The supervisor exclusively owns the
/// GOST PID, preventing reuse while signalling/reaping. No process-group kills.
final class VPNBridgeWorkerProcess {
    private var supervisor: pid_t,control: Int32
    private var confirmedStopped=false
    private enum Wait { case alive, exited(Int32), lost }
    let child: VPNBridgeWorkerStamp
    let role: VPNBridgeWorkerSelection.Role
    let resolverReady: Data?
    private let lock=NSRecursiveLock()
    private init(supervisor: pid_t,control: Int32,child: VPNBridgeWorkerStamp,
                 role: VPNBridgeWorkerSelection.Role,resolverReady: Data?) {
        self.supervisor=supervisor;self.control=control;self.child=child;self.role=role;self.resolverReady=resolverReady
    }
    deinit {
        if control>=0 { close(control) }
        if supervisor>0 {
            let owned=supervisor
            DispatchQueue.global(qos:.utility).async {
                var status:Int32=0
                while waitpid(owned,&status,0)<0 && errno==EINTR {}
            }
        }
    }
    static func launch(selection: VPNBridgeWorkerSelection,configuration: Int32,
                       deadline: DispatchTime) throws -> VPNBridgeWorkerProcess {
        guard getuid()==geteuid(),getuid()>=500 else { throw VPNBridgeWorkerError.invalid }
        try VPNBridgeWorkerIO.validateConfiguration(configuration)
        try selection.validate(deadline:deadline)
        var pair:[Int32]=[-1,-1]
        guard socketpair(AF_UNIX,SOCK_STREAM,0,&pair)==0 else { throw VPNBridgeWorkerError.transport }
        defer { if pair[0]>=0 { close(pair[0]) };if pair[1]>=0 { close(pair[1]) } }
        for fd in pair {
            var yes:Int32=1
            guard fcntl(fd,F_SETFD,FD_CLOEXEC)==0,fcntl(fd,F_SETFL,O_NONBLOCK)==0,
                  setsockopt(fd,SOL_SOCKET,SO_NOSIGPIPE,&yes,socklen_t(MemoryLayout<Int32>.size))==0 else { throw VPNBridgeWorkerError.transport }
        }
        var bytes=[CChar](repeating:0,count:Int(MAXPATHLEN)),size=UInt32(MAXPATHLEN)
        guard _NSGetExecutablePath(&bytes,&size)==0 else { throw VPNBridgeWorkerError.invalid }
        var resolved=[CChar](repeating:0,count:Int(MAXPATHLEN))
        guard realpath(bytes,&resolved) != nil else { throw VPNBridgeWorkerError.invalid }
        let ownPath=String(cString:resolved)
        let own=open(ownPath,O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC)
        guard own>=0 else { throw VPNBridgeWorkerError.invalid };defer { close(own) }
        var before=stat(),after=stat()
        guard fstat(own,&before)==0,before.st_mode&S_IFMT==S_IFREG,before.st_nlink==1,
              [uid_t(0),getuid()].contains(before.st_uid),before.st_mode&0o022==0 else { throw VPNBridgeWorkerError.invalid }
        let native=selection.role == .systemResolver
        let pid=try VPNBridgeWorkerIO.spawn(path:ownPath,
            argv:native ? [VPNBridgeWorkerSupervisorEntry.resolverProcessName,VPNBridgeWorkerSupervisorEntry.resolverArgument]
                        : [VPNBridgeWorkerSupervisorEntry.processName,VPNBridgeWorkerSupervisorEntry.argument],
            mappings:[(pair[1],20),(configuration,21),(selection.descriptor,22)])
        close(pair[1]);pair[1] = -1
        do {
            guard lstat(ownPath,&after)==0,VPNBridgeWorkerSelection.same(before,after) else { throw VPNBridgeWorkerError.invalid }
            let frame=Array((native ? "PPBRSV01":"PPBGST01").utf8)+VPNBridgeWorkerIO.encode(deadline.uptimeNanoseconds)
                + VPNBridgeWorkerIO.encode(selection.bytes)+Array(selection.digest)
            _=try VPNBridgeWorkerIO.transfer(pair[0],bytes:frame,count:frame.count,deadline:deadline)
            let ready=try VPNBridgeWorkerIO.transfer(pair[0],bytes:nil,count:32,deadline:deadline)
            let rawPID=VPNBridgeWorkerIO.number(ready[8..<16])
            guard Array(ready.prefix(8))==Array((native ? "PPBRRD01":"PPBGRD01").utf8),rawPID>0,rawPID<=UInt64(Int32.max) else { throw VPNBridgeWorkerError.invalid }
            var resolverReady: Data?
            if native {
                let size=try VPNBridgeWorkerIO.transfer(pair[0],bytes:nil,count:8,deadline:deadline)
                let count=VPNBridgeWorkerIO.number(size[...])
                guard count>0,count<=4096 else { throw VPNBridgeWorkerError.invalid }
                resolverReady=Data(try VPNBridgeWorkerIO.transfer(pair[0],bytes:nil,count:Int(count),deadline:deadline))
            }
            let child=VPNBridgeWorkerStamp(pid:pid_t(rawPID),parent:pid,
                seconds:VPNBridgeWorkerIO.number(ready[16..<24]),microseconds:VPNBridgeWorkerIO.number(ready[24..<32]))
            guard try VPNBridgeWorkerStamp.live(child.pid)==child else { throw VPNBridgeWorkerError.unavailable }
            try selection.validate(deadline:deadline)
            let result=VPNBridgeWorkerProcess(supervisor:pid,control:pair[0],child:child,role:selection.role,resolverReady:resolverReady)
            pair[0] = -1;try result.checkLive();return result
        } catch {
            close(pair[0]);pair[0] = -1
            if case .alive = probe(pid) {
                _=kill(pid,SIGCONT) // Only our still-unreaped direct child.
                _=waitFor(pid,deadline:.now()+2)
            }
            throw error
        }
    }
    func checkLive() throws {
        lock.lock();defer { lock.unlock() }
        guard supervisor>0,control>=0 else { throw VPNBridgeWorkerError.unavailable }
        switch Self.probe(supervisor) {
        case .alive:
            guard try VPNBridgeWorkerStamp.live(child.pid)==child else { throw VPNBridgeWorkerError.unavailable }
        case .exited(let status):
            supervisor = -1;confirmedStopped=status==0;throw VPNBridgeWorkerError.unavailable
        case .lost:
            supervisor = -1;throw VPNBridgeWorkerError.unavailable
        }
    }
    /// EOF triggers graceful stop then forced stop inside the owner/reaper.
    /// Unknown cleanup is an explicit failure; it is never reported as success.
    func stop(deadline: DispatchTime) throws {
        lock.lock();defer { lock.unlock() }
        if control>=0 { close(control);control = -1 }
        guard supervisor>0 else {
            guard confirmedStopped else { throw VPNBridgeWorkerError.cleanupUnknown };return
        }
        var state=Self.probe(supervisor)
        if case .alive = state {
            _=kill(supervisor,SIGCONT) // A stopped owner must receive EOF and reap its child.
            state=Self.waitFor(supervisor,deadline:deadline)
        }
        switch state {
        case .exited(let status):
            supervisor = -1;confirmedStopped=status==0
            guard confirmedStopped else { throw VPNBridgeWorkerError.cleanupUnknown }
        case .lost:
            supervisor = -1;throw VPNBridgeWorkerError.cleanupUnknown
        case .alive:throw VPNBridgeWorkerError.cleanupUnknown
        }
    }
    private static func probe(_ pid: pid_t) -> Wait {
        var status:Int32=0;var result: pid_t
        repeat { result=waitpid(pid,&status,WNOHANG) } while result<0 && errno==EINTR
        if result==pid { return .exited(status) }
        return result==0 ? .alive:.lost
    }
    private static func waitFor(_ pid: pid_t,deadline: DispatchTime) -> Wait {
        while DispatchTime.now()<deadline {
            let result=probe(pid)
            if case .alive = result { usleep(1_000);continue }
            return result
        }
        return .alive
    }
}
