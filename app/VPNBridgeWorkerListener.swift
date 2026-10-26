import Darwin
import Foundation

/// Kernel evidence from the already owned child, never a probe of an arbitrary
/// port. API/code authentication remains a separate mandatory runtime gate.
enum VPNBridgeWorkerListener {
    static func matches(_ value: socket_fdinfo,port: Int) -> Bool {
        guard (1024...65535).contains(port) else { return false }
        let socket=value.psi,tcp=socket.soi_proto.pri_tcp,ip=tcp.tcpsi_ini
        // XNU leaves soi_stat zeroed for this flavor. UID ownership comes from
        // the mandatory owned-process checks, never that reserved socket stat.
        return socket.soi_family==AF_INET && socket.soi_type==SOCK_STREAM
            && (socket.soi_protocol==IPPROTO_TCP || socket.soi_protocol==0)
            && socket.soi_kind==Int32(SOCKINFO_TCP) && tcp.tcpsi_state==Int32(TSI_S_LISTEN)
            && ip.insi_vflag==UInt8(INI_IPV4) && ip.insi_fport==0
            && UInt16(bigEndian:UInt16(truncatingIfNeeded:ip.insi_lport))==UInt16(port)
            && ip.insi_laddr.ina_46.i46a_addr4.s_addr==UInt32(0x7f000001).bigEndian
    }
    static func same(_ a: socket_fdinfo,_ b: socket_fdinfo,port: Int) -> Bool {
        matches(a,port:port) && matches(b,port:port)
            && a.psi.soi_so==b.psi.soi_so && a.psi.soi_pcb==b.psi.soi_pcb
            && a.psi.soi_proto.pri_tcp.tcpsi_ini.insi_gencnt==b.psi.soi_proto.pri_tcp.tcpsi_ini.insi_gencnt
    }
    static func probe(process: VPNBridgeWorkerProcess,port: Int,deadline: DispatchTime) throws -> Bool {
        guard (1024...65535).contains(port) else { throw VPNBridgeWorkerError.invalid }
        func current() throws { try VPNBridgeWorkerIO.current(deadline);try process.checkLive() }
        try current()
        let stride=MemoryLayout<proc_fdinfo>.stride
        let required=proc_pidinfo(process.child.pid,PROC_PIDLISTFDS,0,nil,0)
        guard required>=0,required<=4096*stride else { throw VPNBridgeWorkerError.unavailable }
        let capacity=min(4096,Int(required)/stride+32)
        var descriptors=[proc_fdinfo](repeating:proc_fdinfo(),count:capacity)
        let bytes=descriptors.withUnsafeMutableBytes { proc_pidinfo(process.child.pid,PROC_PIDLISTFDS,0,$0.baseAddress,Int32($0.count)) }
        guard bytes>=0,Int(bytes)%stride==0,Int(bytes)<capacity*stride else { throw VPNBridgeWorkerError.unavailable }
        func socket(_ fd: Int32) throws -> socket_fdinfo? {
            try current();var info=socket_fdinfo()
            let size=Int32(MemoryLayout.size(ofValue:info))
            return proc_pidfdinfo(process.child.pid,fd,PROC_PIDFDSOCKETINFO,&info,size)==size ? info:nil
        }
        for fd in descriptors.prefix(Int(bytes)/stride) where fd.proc_fdtype==UInt32(PROX_FDTYPE_SOCKET) {
            guard let first=try socket(fd.proc_fd),matches(first,port:port),
                  let second=try socket(fd.proc_fd),same(first,second,port:port) else { continue }
            try current();return true
        }
        try current();return false
    }
    static func require(process: VPNBridgeWorkerProcess,port: Int,deadline: DispatchTime) throws {
        while try !probe(process:process,port:port,deadline:deadline) {
            try VPNBridgeWorkerIO.current(deadline);usleep(5_000)
        }
    }
}
