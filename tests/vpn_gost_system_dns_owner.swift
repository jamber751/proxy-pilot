// Disposable root GHA VM ONLY. One random session-owned supplemental DNS key.
// No existing service, interface, route, default DNS or installed App changes.
import Foundation
import Darwin
import SystemConfiguration

private enum Failure: String, Error { case arguments, occupied, create, read, add, verify, control, cleanup }
private func validID(_ value: String) -> Bool { UUID(uuidString:value)?.uuidString.lowercased() == value }
private func require(_ value: Bool, _ failure: Failure) throws { if !value { throw failure } }
private func session(_ temporary: Bool) throws -> SCDynamicStore {
    guard let store = SCDynamicStoreCreateWithOptions(nil,"ProxyPilotGostDNSCanary" as CFString,
        [kSCDynamicStoreUseSessionKeys as String:temporary] as CFDictionary,nil,nil) else { throw Failure.create }
    return store
}
private func copy(_ store: SCDynamicStore, _ key: String) throws -> CFPropertyList? {
    let value = SCDynamicStoreCopyValue(store,key as CFString)
    if value == nil { try require(SCError() == kSCStatusNoKey,.read) }
    return value
}
@inline(never) private func hold(_ key: String, _ id: String) throws {
    let owner = try session(true)
    let record = [kSCPropNetDNSServerAddresses as String:["127.0.0.1"],
                  kSCPropNetDNSSupplementalMatchDomains as String:["pp-"+id+".test"],
                  kSCPropNetDNSSupplementalMatchOrders as String:[120000]] as CFDictionary
    try require(SCDynamicStoreAddValue(owner,key as CFString,record),.add)
    guard let observed = try copy(owner,key) else { throw Failure.verify }
    try require(CFEqual(observed,record),.verify)
    usleep(3_000_000) // configd -> mDNSResponder propagation; no pre-install lookup.
    print("READY"); fflush(stdout)
    var p = pollfd(fd:STDIN_FILENO,events:Int16(POLLIN),revents:0)
    let end = DispatchTime.now().uptimeNanoseconds + 60_000_000_000
    while true {
        let now = DispatchTime.now().uptimeNanoseconds
        try require(now < end,.control)
        let timeout = Int32(min(1000,(end-now+999_999)/1_000_000))
        let n = poll(&p,1,timeout)
        if n < 0 && errno == EINTR { continue }
        try require(n >= 0,.control)
        if n == 0 { continue }
        try require(p.revents & Int16(POLLIN) != 0,.control)
        var byte: UInt8 = 0
        try require(Darwin.read(STDIN_FILENO,&byte,1) == 1 && byte == 82,.control)
        break
    }
    withExtendedLifetime(owner) {}
}
@main private struct Main {
    static func main() {
        let args = Array(CommandLine.arguments.dropFirst())
        if args == ["--pure"] {
            if !validID("12345678-1234-1234-1234-123456789abc") || validID("../DNS") || validID("12345678-1234-1234-1234-123456789ABC") { exit(1) }
            return
        }
        let env = ProcessInfo.processInfo.environment
        // Before any SC API or resolver/network operation.
        guard getuid() == 0, geteuid() == 0, env["GITHUB_ACTIONS"] == "true",
              env["PROXYPILOT_VM_GOST_SYSTEM_RESOLVER_TESTS"] == "1" else { exit(77) }
        do {
            try require(args.count == 2 && args[0] == "--hold" && validID(args[1]),.arguments)
            let id = args[1], key = "State:/Network/Service/kz.documentolog.proxypilot.gost-dns."+args[1]+"/DNS"
            let observer = try session(false)
            try require(try copy(observer,key) == nil,.occupied)
            var failure: Error?
            do { try hold(key,id) } catch { failure = error }
            var absent = false
            for _ in 0..<100 {
                if try copy(observer,key) == nil { absent = true; break }
                usleep(50_000)
            }
            try require(absent,.cleanup)
            if let failure { throw failure }
            print("PASS gost-system-dns-owner-session-cleanup")
        } catch {
            print("FAIL gost-system-dns-owner category="+((error as? Failure)?.rawValue ?? "unexpected"))
            exit(1)
        }
    }
}
