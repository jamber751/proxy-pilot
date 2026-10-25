import Darwin
import Foundation

@main struct Checks {
    enum Failure: Error { case assertion(Int) }
    static func require(_ value: Bool, line: Int = #line) throws { if !value { throw Failure.assertion(line) } }
    static func rejects(_ body: () throws -> Void) throws {
        do { try body() } catch { return };throw VPNBridgeConfigurationError.invalid
    }
    static func main() throws {
        let mode=CommandLine.arguments[1],path=CommandLine.arguments[2]
        let fd=open(path,O_RDONLY|O_DIRECTORY|O_CLOEXEC);defer { close(fd) }
        let a=Data(repeating:97,count:64),b=Data(repeating:98,count:64)
        let snapshot=VPNBridgeProtectedSnapshot(schemaVersion:1,revision:3,matchers:["10.20.0.0/16","198.19.253.201/32","2001:db8::/32"])
        func recipe(_ route: VPNBridgeGOSTConfiguration.Route = .http(host:"office-proxy",port:3128),
                    _ protected: VPNBridgeProtectedSnapshot? = nil) throws -> VPNBridgeGOSTConfiguration {
            try VPNBridgeGOSTConfiguration(route:route,bypass:[".local","127.0.0.1/32"],protected:protected ?? snapshot,
                epochDirectory:path,resolverPort:45678,apiPassword:a,resolverPassword:b)
        }
        func load(_ config: VPNBridgeGOSTConfiguration) throws -> [String:Any] {
            let file=try config.materialize(trustedDirectoryDescriptor:fd,deadline:.now()+3,checkCurrent:{})
            var st=stat();try require(fstat(file.descriptor,&st)==0 && st.st_nlink==0 && st.st_mode&0o7777==0o600)
            try require(fcntl(file.descriptor,F_GETFD)&FD_CLOEXEC != 0)
            var bytes=[UInt8](repeating:0,count:1024*1024)
            let n=read(file.descriptor,&bytes,bytes.count);try require(n>0)
            try require(try FileManager.default.contentsOfDirectory(atPath:path).isEmpty)
            return try JSONSerialization.jsonObject(with:Data(bytes.prefix(n))) as! [String:Any]
        }
        switch mode {
        case "routes":
            for (route,connector,address) in [
                (VPNBridgeGOSTConfiguration.Route.http(host:"Office-Proxy",port:3128),"http","office-proxy:3128"),
                (.socks5(host:"proxy.example.",port:1080),"socks5","proxy.example.:1080"),
                (.socks5(host:"2001:db8::4",port:1080),"socks5","[2001:db8::4]:1080")
            ] {
                let config=try recipe(route),json=try load(config)
                let services=json["services"] as! [[String:Any]]
                try require(services.count==1 && services[0]["addr"] as? String=="127.0.0.1:3129")
                try require((services[0]["handler"] as? [String:String])==["type":"auto","chain":"c0"])
                try require(services[0]["resolver"] as? String=="r0")
                let hop=((json["chains"] as! [[String:Any]])[0]["hops"] as! [[String:Any]])[0]
                try require(hop["bypass"]==nil && hop["bypasses"] as? [String]==["b0",VPNBridgeProtectedSnapshot.groupName])
                let node=(hop["nodes"] as! [[String:Any]])[0]
                try require(node["addr"] as? String==address && (node["connector"] as? [String:String])?["type"]==connector)
                try require(node["resolver"] as? String=="r0" && hop["resolver"] as? String=="r0")
                let bypass=json["bypasses"] as! [[String:Any]]
                try require(bypass[0]["matchers"] as? [String]==["*.local","127.0.0.1/32"])
                try require(bypass[1]["matchers"] as? [String]==snapshot.matchers && bypass[1]["reverse"] as? Bool==false)
                let plugin=(json["resolvers"] as! [[String:Any]])[0]["plugin"] as! [String:Any]
                try require(plugin["type"] as? String=="http" && plugin["addr"] as? String=="https://proxypilot:"+String(repeating:"b",count:64)+"@127.0.0.1:45678/resolve")
                let tls=plugin["tls"] as! [String:Any]
                try require(tls["secure"] as? Bool==true && tls["caFile"] as? String==path+"/ca.pem")
                let api=json["api"] as! [String:Any]
                try require(api["addr"] as? String=="unix://"+path+"/api.sock")
                try require(String(describing:config)=="VPNBridgeGOSTConfiguration(redacted)" && String(reflecting:config)==String(describing:config))
            }
        case "direct":
            let json=try load(recipe(.direct))
            try require(json["chains"]==nil)
            let service=(json["services"] as! [[String:Any]])[0]
            try require(service["resolver"] as? String=="r0" && (service["handler"] as! [String:String])==["type":"auto"])
            try require((json["bypasses"] as! [[String:Any]])[1]["matchers"] as? [String]==snapshot.matchers)
        case "invalid":
            for host in ["", "localhost", "x.localhost.", "127.0.0.1", "::1", "0.0.0.0", "127.1", "2130706433", "0x7f000001", "http://proxy", "u:p@proxy", "proxy/a", "a..b", "-proxy", "proxy\n", "proxy:8080", "[2001:db8::1]", "fe80::1%en0"] {
                try rejects { _=try recipe(.http(host:host,port:1080)) }
            }
            for port in [0,-1,65536] { try rejects { _=try recipe(.socks5(host:"office",port:port)) } }
            let malformed=VPNBridgeProtectedSnapshot(schemaVersion:1,revision:1,matchers:["example.com"])
            try rejects { _=try recipe(.direct,malformed) }
            for pair in [(a,a),(Data("secret".utf8),b)] {
                try rejects { _=try VPNBridgeGOSTConfiguration(route:.direct,bypass:[],protected:snapshot,
                    epochDirectory:path,resolverPort:45678,apiPassword:pair.0,resolverPassword:pair.1) }
            }
        case "expired":
            let config=try recipe();var called=false
            try rejects { _=try config.materialize(trustedDirectoryDescriptor:fd,deadline:.now(),checkCurrent:{ called=true }) }
            try require(!called && (try FileManager.default.contentsOfDirectory(atPath:path)).isEmpty)
        case "cancelled":
            let config=try recipe();var calls=0
            try rejects { _=try config.materialize(trustedDirectoryDescriptor:fd,deadline:.now()+3,checkCurrent:{
                calls+=1;if calls==3 { throw VPNBridgeConfigurationError.invalid }
            }) }
            try require(calls==3 && (try FileManager.default.contentsOfDirectory(atPath:path)).isEmpty)
        case "directory":
            let config=try recipe();try require(chmod(path,0o755)==0)
            try rejects { _=try config.materialize(trustedDirectoryDescriptor:fd,deadline:.now()+3,checkCurrent:{}) }
            try require(chmod(path,0o700)==0)
            let other=path+"-other";try FileManager.default.createDirectory(atPath:other,withIntermediateDirectories:false,attributes:[.posixPermissions:0o700])
            defer { try? FileManager.default.removeItem(atPath:other) }
            let wrong=open(other,O_RDONLY|O_DIRECTORY|O_CLOEXEC);defer { close(wrong) }
            try rejects { _=try config.materialize(trustedDirectoryDescriptor:wrong,deadline:.now()+3,checkCurrent:{}) }
        case "directory-change":
            let config=try recipe();var calls=0
            try rejects { _=try config.materialize(trustedDirectoryDescriptor:fd,deadline:.now()+3,checkCurrent:{
                calls+=1;if calls==3 { try require(chmod(path,0o755)==0) }
            }) }
            try require(chmod(path,0o700)==0 && (try FileManager.default.contentsOfDirectory(atPath:path)).isEmpty)
        case "lifetime":
            let config=try recipe()
            var file: VPNBridgeConfigurationFile?=try config.materialize(trustedDirectoryDescriptor:fd,deadline:.now()+3,checkCurrent:{})
            let owned=file!.descriptor
            try require(String(reflecting:file!)=="VPNBridgeConfigurationFile(redacted)")
            file=nil
            try require(fcntl(owned,F_GETFD)==(-1) && errno==EBADF)
            try require(try FileManager.default.contentsOfDirectory(atPath:path).isEmpty)
        case "capacity":
            let hosts=(1...6000).map { "10.\($0/256).\($0%256).1/32" }.sorted()
            let json=try load(recipe(.socks5(host:"office",port:1080),VPNBridgeProtectedSnapshot(schemaVersion:1,revision:1,matchers:hosts)))
            try require((json["bypasses"] as! [[String:Any]])[1]["matchers"] as? [String]==hosts)
        default: throw VPNBridgeConfigurationError.invalid
        }
        print("PASS bridge-configuration-"+mode)
    }
}
