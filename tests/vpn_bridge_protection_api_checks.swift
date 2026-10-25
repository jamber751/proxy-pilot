import Darwin
import Foundation
private func check(_ value: @autoclosure () throws -> Bool) throws { if try !value() { throw NSError(domain:"api-check",code:1) } }
private final class Clock: VPNDNSContinuousClock {
    var value: UInt64=1
    func now() throws -> VPNDNSContinuousInstant { VPNDNSContinuousInstant(nanoseconds:value) }
}
private final class Connection: VPNBridgeAPIConnection {
    var written=Data(),response=Data("HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: 12\r\nConnection: close\r\n\r\n{\"msg\":\"OK\"}".utf8)
    var maximumWrite=4096,maximumRead=1024,closeCount=0,authCount=0,reads=0,writes=0
    var authFailure=false,zeroWrite=false,overWrite=false,unknownWrite=false,noEOF=false,overRead=false
    var deadlines=[UInt64](),onWrite: (() throws -> Void)?,onRead: (() throws -> Void)?
    func authenticate() throws { authCount+=1;if authFailure { throw VPNBridgeProtectionAPIError.authentication } }
    func writeSome(_ bytes: Data,deadline: VPNDNSContinuousInstant,checkCurrent: () throws -> Void) throws -> Int {
        try checkCurrent();deadlines.append(deadline.nanoseconds);writes+=1;try onWrite?()
        if zeroWrite { return 0 }
        if overWrite { return bytes.count+1 }
        let count=min(bytes.count,maximumWrite);written+=bytes.prefix(count)
        if unknownWrite { throw VPNBridgeProtectionAPIError.transport };return count
    }
    func readSome(maximum: Int,deadline: VPNDNSContinuousInstant,checkCurrent: () throws -> Void) throws -> Data {
        try checkCurrent();deadlines.append(deadline.nanoseconds);reads+=1;try onRead?()
        if overRead { return Data(repeating:65,count:maximum+1) }
        if response.isEmpty && noEOF { throw VPNBridgeProtectionAPIError.expired }
        let count=min(maximum,maximumRead,response.count),result=response.prefix(count);response.removeFirst(count);return Data(result)
    }
    func close() { closeCount+=1 }
}
private final class Connections: VPNBridgeAPIConnections {
    let connection=Connection();var opens=0
    var beforeOpen: (() throws -> Void)?
    func open(deadline: VPNDNSContinuousInstant,checkCurrent: () throws -> Void) throws -> VPNBridgeAPIConnection {
        try checkCurrent();opens+=1;try beforeOpen?();return connection
    }
}
@main private enum Checks {
    static func run() throws {
        let mode=CommandLine.arguments[1],clock=Clock(),factory=Connections(),epoch=UUID()
        let client=try VPNBridgeProtectionAPI(epoch:epoch,password:Data(String(repeating:"a",count:64).utf8),connections:factory,clock:clock)
        let snapshot=VPNBridgeProtectedSnapshot(schemaVersion:1,revision:1,matchers:["198.19.253.201/32","2001:db8:fff:fd::c9/128"])
        let end=VPNDNSContinuousInstant(nanoseconds:100),connection=factory.connection
        func call(_ current: () throws -> Void = {}) throws { try client.replace(snapshot,epoch:epoch,deadline:end,checkCurrent:current) }
        func fails(_ code: VPNBridgeProtectionAPIError, _ action: () throws -> Void) throws {
            do { try action();throw NSError(domain:"accepted",code:1) }
            catch let actual as VPNBridgeProtectionAPIError { try check(actual==code) }
        }
        switch mode {
        case "request", "fragmented":
            if mode=="fragmented" { connection.maximumWrite=7;connection.maximumRead=1 }
            try call()
            let boundary=connection.written.range(of:Data([13,10,13,10]))!
            let header=String(data:connection.written[..<boundary.lowerBound],encoding:.utf8)!
            try check(header.hasPrefix("PUT /config/bypasses/proxypilot-protected-v1 HTTP/1.1\r\nHost: localhost\r\n"))
            let token=Data(("proxypilot:"+String(repeating:"a",count:64)).utf8).base64EncodedString()
            try check(header.contains("Authorization: Basic "+token) && header.contains("Connection: close"))
            let body=connection.written[boundary.upperBound...]
            let object=try JSONSerialization.jsonObject(with:body) as! [String:Any]
            try check(Set(object.keys)==Set(["name","matchers","reverse","whitelist"]))
            try check(object["name"] as? String==VPNBridgeProtectionAPI.groupName && object["matchers"] as? [String]==snapshot.matchers)
            try check(object["reverse"] as? Bool==false && object["whitelist"] as? Bool==false)
            try check(header.contains("Content-Length: \(body.count)") && factory.opens==1 && connection.closeCount==1)
            try check(connection.deadlines.allSatisfy { $0==end.nanoseconds })
        case "wrong-epoch":
            try fails(.authentication) { try client.replace(snapshot,epoch:UUID(),deadline:end,checkCurrent:{}) };try check(factory.opens==0)
        case "credentials":
            for raw in ["",String(repeating:"a",count:63),String(repeating:"g",count:64),String(repeating:"A",count:64)] {
                try fails(.invalidRequest) { _=try VPNBridgeProtectionAPI(epoch:epoch,password:Data(raw.utf8),connections:factory,clock:clock) }
            }
            try check(factory.opens==0 && client.debugDescription=="VPNBridgeProtectionAPI(redacted)")
        case "peer":
            connection.authFailure=true;try fails(.authentication) { try call() };try check(connection.written.isEmpty && connection.closeCount==1)
        case "expired":
            clock.value=100;try fails(.expired) { try call() };try check(factory.opens==0)
        case "late":
            connection.onRead={ clock.value=100 };try fails(.expired) { try call() };try check(connection.closeCount==1)
        case "backwards":
            connection.onRead={ clock.value=0 }
            do { try call();throw NSError(domain:"accepted",code:1) } catch VPNDNSContinuousClockError.backwards {}
            try check(connection.closeCount==1)
        case "cancel-before":
            try fails(.authentication) { try call { throw VPNBridgeProtectionAPIError.authentication } };try check(factory.opens==0)
        case "cancel-partial":
            var valid=true;connection.maximumWrite=7;connection.onWrite={ valid=false }
            try fails(.authentication) { try call { if !valid { throw VPNBridgeProtectionAPIError.authentication } } }
            try check(connection.writes==1 && connection.written.count==7 && connection.closeCount==1)
        case "unknown-write":
            connection.unknownWrite=true;try fails(.transport) { try call() }
            try check(factory.opens==1 && connection.writes==1 && connection.closeCount==1)
        case "zero-write", "over-write":
            connection.zeroWrite=mode=="zero-write";connection.overWrite=mode=="over-write"
            try fails(.transport) { try call() };try check(connection.writes==1 && connection.closeCount==1)
        case "no-eof":
            connection.noEOF=true;try fails(.expired) { try call() };try check(connection.closeCount==1)
        case "publisher-order", "publisher-unknown":
            let fd=open(CommandLine.arguments[2],O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);try check(fd>=0);defer { close(fd) }
            let store=try VPNBridgeProtectionStore(trustedDirectoryDescriptor:fd)
            let publisher=VPNBridgeProtectionPublisher(store:store,transport:client,epoch:epoch,clock:clock,checkEpoch:{ try check($0==epoch) })
            var outputs=0
            factory.beforeOpen={ try check(try store.snapshot()?.matchers==snapshot.matchers && outputs==0) }
            connection.unknownWrite=mode=="publisher-unknown"
            func publish() throws { _=try publisher.withPublished(snapshot.matchers,deadline:end,checkCurrent:{}) { _ in outputs+=1 } }
            if mode=="publisher-unknown" { try fails(.transport) { try publish() };try check(outputs==0 && store.snapshot()?.matchers==snapshot.matchers) }
            else { try publish();try check(outputs==1 && connection.response.isEmpty && connection.reads>=2) }
            try check(factory.opens==1 && connection.closeCount==1)
        default:
            let original=String(data:connection.response,encoding:.utf8)!
            switch mode {
            case "redirect":connection.response=Data(original.replacingOccurrences(of:"200 OK",with:"302 Found").utf8)
            case "unauthorized":connection.response=Data(original.replacingOccurrences(of:"200 OK",with:"401 Unauthorized").utf8)
            case "duplicate-length":connection.response=Data(original.replacingOccurrences(of:"Content-Length: 12",with:"Content-Length: 12\r\ncontent-length: 12").utf8)
            case "chunked":connection.response=Data(original.replacingOccurrences(of:"Content-Length: 12",with:"Content-Length: 12\r\nTransfer-Encoding: chunked").utf8)
            case "encoded":connection.response=Data(original.replacingOccurrences(of:"Content-Length: 12",with:"Content-Length: 12\r\nContent-Encoding: gzip").utf8)
            case "extra":connection.response.append(65)
            case "truncated":connection.response.removeLast()
            case "error-body":connection.response=Data(original.replacingOccurrences(of:"{\"msg\":\"OK\"}",with:"{\"msg\":\"NO\"}").utf8)
            case "header-cap":connection.response=Data(repeating:65,count:4200)
            case "over-read":connection.overRead=true
            case "missing-length":connection.response=Data(original.replacingOccurrences(of:"Content-Length: 12\r\n",with:"").utf8)
            case "empty":connection.response=Data()
            default:throw NSError(domain:"mode",code:1)
            }
            try fails(.invalidResponse) { try call() };try check(factory.opens==1 && connection.closeCount==1)
        }
        print("PASS bridge-api-"+mode)
    }
    static func main() { do { try run() } catch { fputs("FAIL bridge-api-check\n",stderr);exit(1) } }
}
