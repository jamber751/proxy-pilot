import Darwin
import Foundation

enum VPNBridgeConfigurationError: Error { case invalid, unsafeStorage, writeFailed, expired }

/// A closed configuration recipe, not authority to start a listener. The runtime
/// factory must retain root bootstrap custody, the durable protected snapshot and
/// the authenticated native resolver epoch throughout activation.
final class VPNBridgeGOSTConfiguration: CustomStringConvertible, CustomDebugStringConvertible {
    enum Route { case direct, http(host: String, port: Int), socks5(host: String, port: Int) }
    private let route: Route, port: Int, resolverPort: Int, epochDirectory: String
    private let bypass: [String], protected: VPNBridgeProtectedSnapshot
    private var apiPassword: Data, resolverPassword: Data
    var description: String { "VPNBridgeGOSTConfiguration(redacted)" }
    var debugDescription: String { description }

    init(route: Route, port: Int = 3129, bypass: [String], protected: VPNBridgeProtectedSnapshot,
         epochDirectory: String, resolverPort: Int, apiPassword: Data, resolverPassword: Data) throws {
        guard (1024...65535).contains(port), (1024...65535).contains(resolverPort), port != resolverPort,
              Self.secret(apiPassword), Self.secret(resolverPassword), apiPassword != resolverPassword,
              epochDirectory.hasPrefix("/"), !epochDirectory.hasSuffix("/"),
              epochDirectory.dropFirst().split(separator:"/",omittingEmptySubsequences:false)
                .allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." }),
              epochDirectory.utf8.allSatisfy({ $0 >= 32 && $0 < 127 }),
              (epochDirectory+"/api.sock").utf8.count < 100, bypass.count <= 4096 else {
            throw VPNBridgeConfigurationError.invalid
        }
        try protected.validate()
        switch route {
        case .direct: break
        case let .http(host,p), let .socks5(host,p): _ = try Self.endpoint(host,p)
        }
        var entries=[String]()
        for value in bypass {
            guard !value.isEmpty, value.utf8.count <= 2048,
                  value.utf8.allSatisfy({ $0 > 32 && $0 < 127 && $0 != 44 }) else {
                throw VPNBridgeConfigurationError.invalid
            }
            entries.append(value.hasPrefix(".") ? "*"+value : value)
        }
        self.route=route;self.port=port;self.bypass=Array(Set(entries)).sorted();self.protected=protected
        self.epochDirectory=epochDirectory;self.resolverPort=resolverPort
        self.apiPassword=apiPassword;self.resolverPassword=resolverPassword
    }
    deinit {
        apiPassword.resetBytes(in:0..<apiPassword.count)
        resolverPassword.resetBytes(in:0..<resolverPassword.count)
    }
    private static func secret(_ value: Data) -> Bool {
        value.count==64 && value.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) })
    }
    private static func endpoint(_ raw: String,_ port: Int) throws -> String {
        guard (1...65535).contains(port), !raw.isEmpty, raw.utf8.count<=254,
              raw.utf8.allSatisfy({ $0>32 && $0<127 }) else { throw VPNBridgeConfigurationError.invalid }
        // Numeric inputs use the same remote-address policy as VPN resources.
        // Hostnames deliberately also accept single-label office proxy names.
        for family in [AF_INET,AF_INET6] {
            var address=in6_addr()
            if raw.withCString({ inet_pton(family,$0,&address) })==1 {
                let value=try VPNResource(address:raw)
                guard value.kind == .ipv4 || value.kind == .ipv6 else { throw VPNBridgeConfigurationError.invalid }
                return (family==AF_INET6 ? "["+value.address+"]" : value.address)+":\(port)"
            }
        }
        let host=raw.lowercased(), trimmed=host.hasSuffix(".") ? String(host.dropLast()) : host
        let labels=trimmed.split(separator:".",omittingEmptySubsequences:false)
        guard trimmed.utf8.count<=253, trimmed != "localhost", !trimmed.hasSuffix(".localhost"),
              !labels.allSatisfy({ $0.allSatisfy({ $0.isNumber }) }),
              !labels.allSatisfy({ $0.hasPrefix("0x") || $0.allSatisfy({ $0.isNumber }) }),
              labels.allSatisfy({ label in
                  !label.isEmpty && label.utf8.count<=63 && label.first != "-" && label.last != "-"
                  && label.utf8.allSatisfy({ (97...122).contains($0) || (48...57).contains($0) || $0==45 })
              }) else { throw VPNBridgeConfigurationError.invalid }
        return host+":\(port)"
    }
    private func encoded() throws -> Data {
        var handler: [String:Any] = ["type":"auto"]
        var chains=[[String:Any]]()
        let upstream: (String,String)?
        switch route {
        case .direct: upstream=nil
        case let .http(host,port): upstream=(try Self.endpoint(host,port),"http")
        case let .socks5(host,port): upstream=(try Self.endpoint(host,port),"socks5")
        }
        if let (address,connector)=upstream {
            handler["chain"]="c0"
            chains=[["name":"c0","hops":[["name":"h0","resolver":"r0",
                "bypasses":["b0",VPNBridgeProtectedSnapshot.groupName],
                "nodes":[["name":"n0","addr":address,"resolver":"r0",
                          "connector":["type":connector],"dialer":["type":"tcp"]]]]]]]
        }
        // Stock GOST's HTTP resolver plugin uses URL Basic auth. This URL exists
        // only inside the unlinked configuration FD, never argv/env/settings/logs.
        let resolver="https://proxypilot:"+String(decoding:resolverPassword,as:UTF8.self)+"@127.0.0.1:\(resolverPort)/resolve"
        var value: [String:Any] = [
            "services":[["name":"bridge","addr":"127.0.0.1:\(port)","handler":handler,
                         "listener":["type":"tcp"],"resolver":"r0"]],
            "bypasses":[["name":"b0","matchers":bypass,"reverse":false,"whitelist":false],
                        ["name":VPNBridgeProtectedSnapshot.groupName,"matchers":protected.matchers,
                         "reverse":false,"whitelist":false]],
            "resolvers":[["name":"r0","plugin":["type":"http","addr":resolver,"timeout":2_000_000_000,
                          "tls":["secure":true,"serverName":"127.0.0.1","caFile":epochDirectory+"/ca.pem"]]]],
            "api":["addr":"unix://"+epochDirectory+"/api.sock",
                   "auth":["username":"proxypilot","password":String(decoding:apiPassword,as:UTF8.self)]],
            "log":["level":"error"]]
        if !chains.isEmpty { value["chains"]=chains }
        let data=try JSONSerialization.data(withJSONObject:value,options:[.sortedKeys])
        guard !data.isEmpty, data.count<=1024*1024 else { throw VPNBridgeConfigurationError.invalid }
        return data
    }

    /// No secret bytes reach a named file, even on cancellation or write failure.
    /// Caller supplies its trusted epoch directory FD and retains its lease. The
    /// original deadline and configuration generation check are never refreshed.
    func materialize(trustedDirectoryDescriptor directory: Int32, deadline: DispatchTime,
                     checkCurrent: () throws -> Void) throws -> VPNBridgeConfigurationFile {
        try VPNBridgeConfigurationFile.create(trustedDirectoryDescriptor:directory,path:epochDirectory,
            deadline:deadline,checkCurrent:checkCurrent,encode:encoded)
    }
}

final class VPNBridgeConfigurationFile: CustomStringConvertible, CustomDebugStringConvertible {
    let descriptor: Int32
    private init(descriptor: Int32) { self.descriptor=descriptor }
    deinit { close(descriptor) }
    var description: String { "VPNBridgeConfigurationFile(redacted)" }
    var debugDescription: String { description }
    static func checkDirectory(_ directory: Int32,path: String) throws -> stat {
        var info=stat(),named=stat()
        guard path.hasPrefix("/"),path.dropFirst().split(separator:"/",omittingEmptySubsequences:false)
                .allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." }),!path.utf8.contains(0),
              getuid()==geteuid(),getuid()>=500,fstat(directory,&info)==0,
              info.st_mode&S_IFMT==S_IFDIR,info.st_uid==getuid(),info.st_mode&0o7777==0o700,
              lstat(path,&named)==0,info.st_dev==named.st_dev,info.st_ino==named.st_ino,
              info.st_uid==named.st_uid,info.st_mode==named.st_mode else { throw VPNBridgeConfigurationError.unsafeStorage }
        return info
    }
    static func create(trustedDirectoryDescriptor directory: Int32,path: String,deadline: DispatchTime,
                       checkCurrent: () throws -> Void,encode: () throws -> Data) throws -> VPNBridgeConfigurationFile {
        func current() throws {
            guard DispatchTime.now()<deadline else { throw VPNBridgeConfigurationError.expired }
            try checkCurrent()
            guard DispatchTime.now()<deadline else { throw VPNBridgeConfigurationError.expired }
        }
        try current();let original=try checkDirectory(directory,path:path)
        var bytes=try encode();defer { bytes.resetBytes(in:0..<bytes.count) }
        guard !bytes.isEmpty,bytes.count<=1024*1024 else { throw VPNBridgeConfigurationError.invalid }
        try current()
        let name=".bridge-config-"+UUID().uuidString
        let fd=openat(directory,name,O_RDWR|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0o600)
        guard fd>=0 else { throw VPNBridgeConfigurationError.writeFailed }
        var returned=false
        defer { if !returned { close(fd) } }
        guard unlinkat(directory,name,0)==0 else { throw VPNBridgeConfigurationError.writeFailed }
        var info=stat()
        guard fstat(fd,&info)==0,info.st_mode&S_IFMT==S_IFREG,info.st_uid==getuid(),
              info.st_nlink==0,info.st_mode&0o7777==0o600 else { throw VPNBridgeConfigurationError.unsafeStorage }
        var offset=0
        while offset<bytes.count {
            try current()
            let n=bytes.withUnsafeBytes { Darwin.write(fd,$0.baseAddress!.advanced(by:offset),min(4096,bytes.count-offset)) }
            if n<0 && errno==EINTR { continue }
            guard n>0 else { throw VPNBridgeConfigurationError.writeFailed };offset+=n
        }
        let final=try checkDirectory(directory,path:path)
        guard original.st_dev==final.st_dev,original.st_ino==final.st_ino,
              lseek(fd,0,SEEK_SET)==0 else { throw VPNBridgeConfigurationError.unsafeStorage }
        try current();returned=true
        return VPNBridgeConfigurationFile(descriptor:fd)
    }
}
