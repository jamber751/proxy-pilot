import Darwin
import Foundation

enum VPNBridgeProtectionAPIError: Error, Equatable {
    case invalidRequest, invalidResponse, transport, eof, expired, authentication, unsafeEndpoint
}
protocol VPNBridgeAPIConnection: AnyObject {
    func authenticate() throws
    func writeSome(_ bytes: Data, deadline: VPNDNSContinuousInstant, checkCurrent: () throws -> Void) throws -> Int
    func readSome(maximum: Int, deadline: VPNDNSContinuousInstant, checkCurrent: () throws -> Void) throws -> Data
    func close()
}
protocol VPNBridgeAPIConnections: AnyObject {
    func open(deadline: VPNDNSContinuousInstant, checkCurrent: () throws -> Void) throws -> VPNBridgeAPIConnection
}

/// One fixed positive-policy PUT, one authenticated connection, no retry.
/// Credentials stay outside Codable/debug descriptions and never enter a URL.
final class VPNBridgeProtectionAPI: VPNBridgeProtectionTransport, CustomDebugStringConvertible {
    static let groupName = "proxypilot-protected-v1"
    private let epoch: UUID, connections: VPNBridgeAPIConnections, clock: VPNDNSContinuousClock
    private var authorization: Data
    var debugDescription: String { "VPNBridgeProtectionAPI(redacted)" }
    init(epoch: UUID, password: Data, connections: VPNBridgeAPIConnections,
         clock: VPNDNSContinuousClock = VPNDarwinDNSContinuousClock()) throws {
        guard password.count == 64, password.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }) else {
            throw VPNBridgeProtectionAPIError.invalidRequest
        }
        self.epoch=epoch;self.connections=connections;self.clock=clock
        authorization=(Data("proxypilot:".utf8)+password).base64EncodedData()
    }
    deinit { authorization.resetBytes(in:0..<authorization.count) }
    private struct Policy: Encodable {
        let name: String
        let matchers: [String]
        let reverse = false
        let whitelist = false
    }
    func replace(_ snapshot: VPNBridgeProtectedSnapshot, epoch: UUID, deadline: VPNDNSContinuousInstant,
                 checkCurrent: () throws -> Void) throws {
        guard epoch == self.epoch else { throw VPNBridgeProtectionAPIError.authentication }
        try snapshot.validate()
        let encoder=JSONEncoder();encoder.outputFormatting=[.sortedKeys]
        let payload=try encoder.encode(Policy(name:Self.groupName,matchers:snapshot.matchers))
        guard payload.count <= 512*1024 else { throw VPNBridgeProtectionAPIError.invalidRequest }
        var request=Data(("PUT /config/bypasses/"+Self.groupName+" HTTP/1.1\r\nHost: localhost\r\nAuthorization: Basic ").utf8)
        request+=authorization
        request+=Data(("\r\nContent-Type: application/json\r\nContent-Length: \(payload.count)\r\nConnection: close\r\n\r\n").utf8)
        request+=payload
        defer { request.resetBytes(in:0..<request.count) }
        var previous: VPNDNSContinuousInstant?
        func current() throws {
            let now=try clock.now()
            guard previous == nil || now >= previous! else { throw VPNDNSContinuousClockError.backwards }
            previous=now
            guard now < deadline else { throw VPNBridgeProtectionAPIError.expired }
            try checkCurrent()
            let after=try clock.now()
            guard after >= now else { throw VPNDNSContinuousClockError.backwards }
            previous=after
            guard after < deadline else { throw VPNBridgeProtectionAPIError.expired }
        }
        try current()
        let connection=try connections.open(deadline:deadline,checkCurrent:current)
        defer { connection.close() }
        var offset=0
        while offset < request.count {
            try current();try connection.authenticate();try current()
            let bytes=request.subdata(in:offset..<min(request.count,offset+4096))
            let n=try connection.writeSome(bytes,deadline:deadline,checkCurrent:current)
            try current()
            guard n>0, n<=bytes.count else { throw VPNBridgeProtectionAPIError.transport }
            offset+=n
        }
        var response=Data()
        while true {
            try current();try connection.authenticate();try current()
            let bytes=try connection.readSome(maximum:1024,deadline:deadline,checkCurrent:current)
            try current()
            guard bytes.count<=1024, response.count+bytes.count<=4160 else { throw VPNBridgeProtectionAPIError.invalidResponse }
            if bytes.isEmpty { break }
            response+=bytes
            // Bound and validate the header as soon as complete, but never
            // accept success until exact body AND EOF (Connection: close).
            if let boundary=response.range(of:Data([13,10,13,10])) {
                guard boundary.lowerBound<=4096 else { throw VPNBridgeProtectionAPIError.invalidResponse }
            } else if response.count>=4096 { throw VPNBridgeProtectionAPIError.invalidResponse }
        }
        try Self.accept(response);try current()
    }
    private static func accept(_ response: Data) throws {
        guard let boundary=response.range(of:Data([13,10,13,10])), boundary.lowerBound<=4096,
              let header=String(data:response[..<boundary.lowerBound],encoding:.ascii) else { throw VPNBridgeProtectionAPIError.invalidResponse }
        let rows=header.components(separatedBy:"\r\n")
        guard rows.first == "HTTP/1.1 200 OK" else { throw VPNBridgeProtectionAPIError.invalidResponse }
        var fields=[String:String]()
        for row in rows.dropFirst() {
            guard let at=row.firstIndex(of:":") else { throw VPNBridgeProtectionAPIError.invalidResponse }
            let name=String(row[..<at]).lowercased(),raw=String(row[row.index(after:at)...])
            guard !name.isEmpty,name.utf8.allSatisfy({ (97...122).contains($0) || (48...57).contains($0) || $0==45 }),
                  fields[name]==nil,raw.utf8.allSatisfy({ $0>=32 && $0<127 }) else { throw VPNBridgeProtectionAPIError.invalidResponse }
            fields[name]=raw.trimmingCharacters(in:CharacterSet(charactersIn:" "))
        }
        guard fields["transfer-encoding"]==nil,fields["content-encoding"]==nil,
              fields["content-type"]?.lowercased()=="application/json; charset=utf-8",
              fields["connection"]==nil || fields["connection"]?.lowercased()=="close",
              fields["content-length"]=="12",
              response[boundary.upperBound...]==Data("{\"msg\":\"OK\"}".utf8) else { throw VPNBridgeProtectionAPIError.invalidResponse }
    }
}

/// Rootless connection factory for one private GOST epoch. A mandatory caller
/// authenticator validates the kernel audit token against the owned/pinned child
/// (including incarnation/code identity); UID alone is never that proof.
final class VPNBridgeUnixAPIConnections: VPNBridgeAPIConnections {
    private var directory: Int32 = -1
    private let clock: VPNDNSContinuousClock, authenticatePeer: (audit_token_t) throws -> Void
    init(trustedDirectoryDescriptor: Int32, clock: VPNDNSContinuousClock = VPNDarwinDNSContinuousClock(),
         authenticatePeer: @escaping (audit_token_t) throws -> Void) throws {
        guard getuid()==geteuid(), geteuid() != 0 else { throw VPNBridgeProtectionAPIError.unsafeEndpoint }
        self.clock=clock;self.authenticatePeer=authenticatePeer
        directory=fcntl(trustedDirectoryDescriptor,F_DUPFD_CLOEXEC,64)
        do { _=try path() } catch { if directory>=0 { close(directory);directory = -1 };throw error }
    }
    deinit { if directory>=0 { close(directory) } }
    private func path() throws -> String {
        var a=stat(),b=stat(),bytes=[CChar](repeating:0,count:Int(MAXPATHLEN))
        guard directory>=0,fstat(directory,&a)==0,a.st_mode&S_IFMT==S_IFDIR,a.st_uid==geteuid(),a.st_mode&0o7777==0o700,
              fcntl(directory,F_GETPATH,&bytes)==0 else { throw VPNBridgeProtectionAPIError.unsafeEndpoint }
        let result=String(cString:bytes)
        guard lstat(result,&b)==0,a.st_dev==b.st_dev,a.st_ino==b.st_ino,b.st_mode&S_IFMT==S_IFDIR else { throw VPNBridgeProtectionAPIError.unsafeEndpoint }
        return result+"/api.sock"
    }
    private func endpoint() throws -> stat {
        var info=stat()
        guard fstatat(directory,"api.sock",&info,AT_SYMLINK_NOFOLLOW)==0,info.st_mode&S_IFMT==S_IFSOCK,
              info.st_uid==geteuid(),info.st_nlink==1,info.st_mode&0o7077==0,info.st_mode&0o200 != 0 else {
            throw VPNBridgeProtectionAPIError.unsafeEndpoint
        }
        return info
    }
    func open(deadline: VPNDNSContinuousInstant, checkCurrent: () throws -> Void) throws -> VPNBridgeAPIConnection {
        try checkCurrent()
        let name=try path(),before=try endpoint(),bytes=Array(name.utf8)+[0]
        var address=sockaddr_un()
        guard bytes.count<=MemoryLayout.size(ofValue:address.sun_path) else { throw VPNBridgeProtectionAPIError.unsafeEndpoint }
        address.sun_family=sa_family_t(AF_UNIX);address.sun_len=UInt8(MemoryLayout<sockaddr_un>.size)
        withUnsafeMutableBytes(of:&address.sun_path) { $0.copyBytes(from:bytes) }
        let fd=socket(AF_UNIX,SOCK_STREAM,0)
        guard fd>=0 else { throw VPNBridgeProtectionAPIError.transport }
        let connection=VPNBridgeUnixAPIConnection(fd:fd,clock:clock,authenticatePeer:authenticatePeer)
        do {
            var yes: Int32=1
            guard fcntl(fd,F_SETFD,FD_CLOEXEC)==0,fcntl(fd,F_SETFL,O_NONBLOCK)==0,
                  setsockopt(fd,SOL_SOCKET,SO_NOSIGPIPE,&yes,socklen_t(MemoryLayout.size(ofValue:yes)))==0 else { throw VPNBridgeProtectionAPIError.transport }
            try checkCurrent()
            let result=withUnsafePointer(to:&address) { $0.withMemoryRebound(to:sockaddr.self,capacity:1) { connect(fd,$0,socklen_t(MemoryLayout<sockaddr_un>.size)) } }
            if result != 0 {
                guard errno==EINPROGRESS || errno==EAGAIN else { throw VPNBridgeProtectionAPIError.transport }
                try connection.wait(events:Int16(POLLOUT),deadline:deadline,checkCurrent:checkCurrent,authenticate:false)
                var error: Int32=0,size=socklen_t(MemoryLayout<Int32>.size)
                guard getsockopt(fd,SOL_SOCKET,SO_ERROR,&error,&size)==0,size==MemoryLayout<Int32>.size,error==0 else { throw VPNBridgeProtectionAPIError.transport }
            }
            try checkCurrent();try connection.authenticate();try checkCurrent()
            let after=try endpoint()
            guard before.st_dev==after.st_dev,before.st_ino==after.st_ino else { throw VPNBridgeProtectionAPIError.unsafeEndpoint }
            _=try path();return connection
        } catch { connection.close();throw error }
    }
}

private final class VPNBridgeUnixAPIConnection: VPNBridgeAPIConnection {
    private var fd: Int32
    private let clock: VPNDNSContinuousClock, authenticatePeer: (audit_token_t) throws -> Void
    init(fd: Int32,clock: VPNDNSContinuousClock,authenticatePeer: @escaping (audit_token_t) throws -> Void) {
        self.fd=fd;self.clock=clock;self.authenticatePeer=authenticatePeer
    }
    deinit { close() }
    func close() { let original=fd;fd = -1;if original>=0 { Darwin.close(original) } }
    func authenticate() throws {
        var user: uid_t=0,group: gid_t=0,token=audit_token_t(),size=socklen_t(MemoryLayout<audit_token_t>.size)
        guard fd>=0,getpeereid(fd,&user,&group)==0,user==geteuid(),
              getsockopt(fd,SOL_LOCAL,LOCAL_PEERTOKEN,&token,&size)==0,size==MemoryLayout<audit_token_t>.size else { throw VPNBridgeProtectionAPIError.authentication }
        try authenticatePeer(token)
    }
    func wait(events: Int16,deadline: VPNDNSContinuousInstant,checkCurrent: () throws -> Void,authenticate: Bool=true) throws {
        while true {
            try checkCurrent()
            let now=try clock.now();guard now<deadline else { throw VPNBridgeProtectionAPIError.expired }
            if authenticate { try self.authenticate();try checkCurrent() }
            let left=deadline.nanoseconds-now.nanoseconds
            let milliseconds=Int32(min(100,left/1_000_000 + (left%1_000_000==0 ? 0:1)))
            var item=pollfd(fd:fd,events:events,revents:0)
            let result=poll(&item,1,milliseconds)
            let savedErrno=errno
            try checkCurrent()
            if result<0 && savedErrno==EINTR { continue }
            guard result>=0,item.revents&Int16(POLLNVAL|POLLERR)==0 else { throw VPNBridgeProtectionAPIError.transport }
            if result>0,item.revents&(events|Int16(POLLHUP)) != 0 { return }
        }
    }
    func writeSome(_ bytes: Data,deadline: VPNDNSContinuousInstant,checkCurrent: () throws -> Void) throws -> Int {
        while true {
            try wait(events:Int16(POLLOUT),deadline:deadline,checkCurrent:checkCurrent)
            let n=bytes.withUnsafeBytes { send(fd,$0.baseAddress,$0.count,MSG_DONTWAIT) }
            if n<0 && [EINTR,EAGAIN,EWOULDBLOCK].contains(errno) { continue }
            guard n>0 else { throw VPNBridgeProtectionAPIError.transport };return n
        }
    }
    func readSome(maximum: Int,deadline: VPNDNSContinuousInstant,checkCurrent: () throws -> Void) throws -> Data {
        guard maximum>0,maximum<=4096 else { throw VPNBridgeProtectionAPIError.invalidRequest }
        while true {
            try wait(events:Int16(POLLIN),deadline:deadline,checkCurrent:checkCurrent)
            var bytes=[UInt8](repeating:0,count:maximum)
            let n=recv(fd,&bytes,maximum,MSG_DONTWAIT)
            if n<0 && [EINTR,EAGAIN,EWOULDBLOCK].contains(errno) { continue }
            guard n>=0 else { throw VPNBridgeProtectionAPIError.transport };return Data(bytes.prefix(n))
        }
    }
}
