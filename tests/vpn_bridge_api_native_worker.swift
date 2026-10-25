// Own signed AF_UNIX test worker only. No TCP/UDP, GOST, VPN or system settings.
import Darwin
import Foundation
import Security
private struct Input: Decodable {
    let mode: String
    let serverPassword: String
    let clientPassword: String
    let expectedPID: Int32
    let expectedCDHash: String
}
private func require(_ value: @autoclosure () throws -> Bool) throws {
    if try !value() { throw VPNBridgeProtectionAPIError.authentication }
}
@main private enum Worker {
    static var authStage=0
    static func main() {
        do { try run() } catch { fputs("FAIL bridge-api-native\n",stderr);exit(1) }
    }
    static func run() throws {
        guard getuid()==geteuid(), geteuid() != 0, CommandLine.arguments.count==3,
              ["server","client"].contains(CommandLine.arguments[1]) else { exit(77) }
        let path=CommandLine.arguments[2]
        guard path.hasPrefix("/"), URL(fileURLWithPath:path).lastPathComponent.hasPrefix("pp-bridge-api-native-") else { exit(77) }
        let directory=open(path,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC)
        try require(directory>=0);defer { close(directory) }
        var info=stat()
        try require(fstat(directory,&info)==0 && info.st_uid==geteuid() && info.st_mode&0o7777==0o700)
        let config=openat(directory,"request.json",O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC)
        try require(config>=0);defer { close(config) }
        try require(fstat(config,&info)==0 && info.st_mode&S_IFMT==S_IFREG && info.st_uid==geteuid() && info.st_nlink==1 && info.st_mode&0o7777==0o600 && info.st_size>0 && info.st_size<=4096)
        var bytes=[UInt8](repeating:0,count:Int(info.st_size))
        try require(read(config,&bytes,bytes.count)==bytes.count)
        let input=try JSONDecoder().decode(Input.self,from:Data(bytes))
        try require(["success","wrong-credential","wrong-peer"].contains(input.mode))
        if CommandLine.arguments[1]=="server" { try serve(path,directory,input);return }
        let expected=input.expectedCDHash
        try require(expected.count==40 && expected.allSatisfy { $0.isHexDigit })
        let factory=try VPNBridgeUnixAPIConnections(trustedDirectoryDescriptor:directory) { token in
            authStage=1
            try require(Int32(bitPattern:token.val.5)==input.expectedPID)
            authStage=2
            let audit=withUnsafeBytes(of:token) { Data($0) }
            let attrs=[kSecGuestAttributeAudit as String:audit] as CFDictionary
            var code: SecCode?
            try require(SecCodeCopyGuestWithAttributes(nil,attrs,[],&code)==errSecSuccess && code != nil)
            authStage=3
            try require(SecCodeCheckValidity(code!,SecCSFlags(rawValue:kSecCSStrictValidate),nil)==errSecSuccess)
            authStage=4
            var details: CFDictionary?
            // Same dynamic-reference bridge as VPNPeerAuthentication; retain
            // the kernel guest object rather than substituting a disk path.
            let dynamic=unsafeBitCast(code!,to:SecStaticCode.self)
            try require(SecCodeCopySigningInformation(dynamic,SecCSFlags(rawValue:kSecCSSigningInformation),&details)==errSecSuccess)
            authStage=5
            let hash=(details as? [String:Any])?[kSecCodeInfoUnique as String] as? Data
            try require(hash?.map { String(format:"%02x",$0) }.joined()==expected)
            authStage=6
        }
        let clock=VPNDarwinDNSContinuousClock(),epoch=UUID()
        let transport=try VPNBridgeProtectionAPI(epoch:epoch,password:Data(input.clientPassword.utf8),connections:factory,clock:clock)
        let store=try VPNBridgeProtectionStore(trustedDirectoryDescriptor:directory)
        let publisher=VPNBridgeProtectionPublisher(store:store,transport:transport,epoch:epoch,clock:clock,checkEpoch:{ try require($0==epoch) })
        let deadline=try clock.now().addingChecked(3_000_000_000)
        var output=false,failed=false
        do {
            _=try publisher.withPublished(["198.19.253.201"],deadline:deadline,checkCurrent:{}) { _ in output=true }
        } catch {
            failed=true
            if input.mode=="success" {
                let category=(error as? VPNBridgeProtectionAPIError).map { String(describing:$0) } ?? "other"
                fputs("FAIL native-api-exchange category="+category+" authStage=\(authStage)\n",stderr)
            } else {
                let expected: VPNBridgeProtectionAPIError=input.mode=="wrong-peer" ? .authentication:.invalidResponse
                try require(error as? VPNBridgeProtectionAPIError==expected)
            }
        }
        try require(output==(input.mode=="success") && failed==(input.mode != "success"))
        try require(try store.snapshot()?.matchers==["198.19.253.201/32"])
        print("PASS bridge-api-native-"+input.mode)
    }
    static func serve(_ path: String,_ directory: Int32,_ input: Input) throws {
        umask(0o077)
        let fd=socket(AF_UNIX,SOCK_STREAM,0);try require(fd>=0);defer { close(fd) }
        let name=Array((path+"/api.sock").utf8)+[0];var address=sockaddr_un()
        try require(name.count<=MemoryLayout.size(ofValue:address.sun_path))
        address.sun_family=sa_family_t(AF_UNIX);address.sun_len=UInt8(MemoryLayout<sockaddr_un>.size)
        withUnsafeMutableBytes(of:&address.sun_path) { $0.copyBytes(from:name) }
        let result=withUnsafePointer(to:&address) { $0.withMemoryRebound(to:sockaddr.self,capacity:1) { bind(fd,$0,socklen_t(MemoryLayout<sockaddr_un>.size)) } }
        try require(result==0 && listen(fd,1)==0)
        print("READY");fflush(stdout)
        var item=pollfd(fd:fd,events:Int16(POLLIN),revents:0)
        try require(poll(&item,1,5000)>0)
        let client=accept(fd,nil,nil);try require(client>=0)
        do {
            var yes: Int32=1
            try require(setsockopt(client,SOL_SOCKET,SO_NOSIGPIPE,&yes,socklen_t(MemoryLayout<Int32>.size))==0)
            var request=Data(),buffer=[UInt8](repeating:0,count:1024),length: Int?
            while true {
                var ready=pollfd(fd:client,events:Int16(POLLIN),revents:0)
                try require(poll(&ready,1,5000)>0)
                let count=recv(client,&buffer,buffer.count,0)
                try require(count>=0)
                if count==0 { break }
                request+=buffer.prefix(count);try require(request.count<=4096)
                if let boundary=request.range(of:Data([13,10,13,10])),let header=String(data:request[..<boundary.lowerBound],encoding:.ascii) {
                    if length==nil {
                        let rows=header.components(separatedBy:"\r\n")
                        length=rows.first(where:{ $0.hasPrefix("Content-Length: ") }).flatMap { Int($0.dropFirst(16)) }
                        try require(length != nil && length!<=2048)
                    }
                    if request.count==boundary.upperBound+length! { break }
                }
            }
            let text=String(data:request,encoding:.utf8) ?? ""
            let secret=Data(("proxypilot:"+input.serverPassword).utf8).base64EncodedString()
            let authorized=text.contains("Authorization: Basic "+secret+"\r\n")
            var valid=false
            if let boundary=request.range(of:Data([13,10,13,10])),let object=try? JSONSerialization.jsonObject(with:request[boundary.upperBound...]) as? [String:Any] {
                valid=text.hasPrefix("PUT /config/bypasses/proxypilot-protected-v1 HTTP/1.1\r\n") &&
                    object["name"] as? String==VPNBridgeProtectionAPI.groupName &&
                    object["matchers"] as? [String]==["198.19.253.201/32"] &&
                    object["reverse"] as? Bool==false && object["whitelist"] as? Bool==false
            }
            let event=try JSONSerialization.data(withJSONObject:["hadRequest":!request.isEmpty,"authorized":authorized,"valid":valid],options:[.sortedKeys])
            let witness=openat(directory,".witness.tmp",O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0o600)
            try require(witness>=0);defer { close(witness) }
            try event.withUnsafeBytes { try require(write(witness,$0.baseAddress,$0.count)==$0.count) }
            try require(fsync(witness)==0 && renameat(directory,".witness.tmp",directory,"witness.json")==0)
            if !request.isEmpty {
                let status=authorized && valid ? "200 OK":"401 Unauthorized"
                let body=authorized && valid ? "{\"msg\":\"OK\"}":"{\"msg\":\"NO\"}"
                let response=Data(("HTTP/1.1 "+status+"\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: 12\r\nConnection: close\r\n\r\n"+body).utf8)
                try response.withUnsafeBytes { try require(send(client,$0.baseAddress,$0.count,0)==$0.count) }
            }
            close(client)
        } catch { close(client);throw error }
        // Keep the authenticated incarnation alive through the client's EOF and
        // protected callback. The parent terminates only this owned worker.
        for _ in 0..<100 { usleep(100_000) }
    }
}
