// VM-only public resolver experiment, not a production DNS backend.
// Public schema constants (also in installed SDK SCSchemaDefinitions.h):
// https://github.com/apple-oss-distributions/configd/blob/main/SystemConfiguration.fproj/SCSchemaDefinitions.h
// Session ownership: SDK SCDynamicStore.h / SCDynamicStoreCreateWithOptions.
// https://developer.apple.com/documentation/systemconfiguration/scdynamicstorecreatewithoptions(_:_:_:_:_:)
// getaddrinfo: https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man3/getaddrinfo.3.html
import Foundation
import Dispatch
import SystemConfiguration
import Darwin

private func allowed(_ uid: uid_t, _ euid: uid_t, _ env: [String: String]) -> Bool {
    uid == 0 && euid == 0 && env["GITHUB_ACTIONS"] == "true"
        && env["PROXYPILOT_VM_DNS_RESOLVER_TESTS"] == "1"
}
private func validID(_ text: String) -> Bool {
    UUID(uuidString: text)?.uuidString.lowercased() == text
}
private enum Failure: String, Error {
    case guardDenied, arguments, pureGuard, create, occupied, read, add, copy
    case resolve, answer, child, timeout, cleanup
}
private func check(_ condition: @autoclosure () throws -> Bool, _ failure: Failure) throws {
    if try !condition() { throw failure }
}
private func read(_ session: SCDynamicStore, _ key: String) throws -> CFPropertyList? {
    let result = SCDynamicStoreCopyValue(session, key as CFString)
    if result == nil { try check(SCError() == kSCStatusNoKey, .read) }
    return result
}
private func makeSession(_ temporary: Bool) throws -> SCDynamicStore {
    guard let session = SCDynamicStoreCreateWithOptions(nil, "ProxyPilotResolverAcceptance" as CFString,
        [kSCDynamicStoreUseSessionKeys as String: temporary] as CFDictionary, nil, nil) else {
        throw Failure.create
    }
    return session
}
private func resolve(_ id: String, _ label: String, _ family: Int32) throws {
    var hints = addrinfo()
    hints.ai_family = family
    hints.ai_socktype = SOCK_STREAM
    var result: UnsafeMutablePointer<addrinfo>?
    // Absolute names and no AI_ADDRCONFIG: both families must actually resolve.
    let status = getaddrinfo(label + ".pp-" + id + ".test.", nil, &hints, &result)
    try check(status == 0 && result != nil, .resolve)
    defer { if let result { freeaddrinfo(result) } }
    var current = result
    var answers = Set<String>()
    while let item = current {
        var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
        try check(getnameinfo(item.pointee.ai_addr, item.pointee.ai_addrlen,
                             &host, socklen_t(host.count), nil, 0, NI_NUMERICHOST) == 0, .answer)
        answers.insert(String(cString: host))
        current = item.pointee.ai_next
    }
    try check(answers == [family == AF_INET ? "192.0.2.53" : "2001:db8::53"], .answer)
    print("PASS resolved")
}
private func child(_ id: String, _ label: String, _ family: String) throws {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: CommandLine.arguments[0]).standardizedFileURL
    process.arguments = ["--resolve", id, label, family]
    let output = Pipe()
    process.standardOutput = output
    process.standardError = FileHandle.nullDevice
    try process.run()
    let deadline = DispatchTime.now().uptimeNanoseconds + 20_000_000_000
    while process.isRunning {
        let now = DispatchTime.now().uptimeNanoseconds
        if now >= deadline { break }
        usleep(50_000)
    }
    if process.isRunning {
        kill(process.processIdentifier, SIGKILL)
        process.waitUntilExit()
        throw Failure.timeout
    }
    process.waitUntilExit()
    try check(process.terminationStatus == 0, .child)
    try check(output.fileHandleForReading.readDataToEndOfFile() == Data("PASS resolved\n".utf8), .child)
}
@inline(never)
private func installed(_ id: String, _ key: String) throws {
    let owner = try makeSession(true)
    let suffix = "pp-" + id + ".test"
    // Standard port 53; no ServerPort override, default/global resolver changes,
    // interface entity, routes, DNS proxy, or resolver-daemon restart.
    let record: CFDictionary = [
        kSCPropNetDNSServerAddresses as String: ["127.0.0.1"],
        kSCPropNetDNSSupplementalMatchDomains as String: [suffix],
        kSCPropNetDNSSupplementalMatchOrders as String: [120000]
    ] as CFDictionary
    try check(SCDynamicStoreAddValue(owner, key as CFString, record), .add)
    guard let stored = try read(owner, key) else { throw Failure.copy }
    try check(CFEqual(stored, record), .copy)
    // configd -> mDNSResponder propagation is asynchronous. Do not query the
    // canary before installation or prime a cached negative result.
    usleep(3_000_000)
    for label in ["udp", "tcp"] {
        for family in ["4", "6"] { try child(id, label, family) }
        print("PASS " + label + "-A-AAAA-system-getaddrinfo")
    }
    withExtendedLifetime(owner) {}
}
private func acceptance(_ id: String) throws {
    // Key is constructed only from a validated canonical UUID, never supplied.
    let key = "State:/Network/Service/kz.documentolog.proxypilot.acceptance." + id + "/DNS"
    let observer = try makeSession(false)
    try check(try read(observer, key) == nil, .occupied)
    // Scope exit owns removal on success or error; no blind RemoveValue.
    var operationError: Error?
    do { try installed(id, key) } catch { operationError = error }
    var absent = false
    for _ in 0..<100 {
        if try read(observer, key) == nil { absent = true; break }
        usleep(50_000)
    }
    try check(absent, .cleanup)
    if let operationError { throw operationError }
    print("PASS owner-session-close-cleanup")
}
private func pure() throws {
    let env = ["GITHUB_ACTIONS": "true", "PROXYPILOT_VM_DNS_RESOLVER_TESTS": "1"]
    try check(allowed(0, 0, env), .pureGuard)
    for ids: (uid_t, uid_t) in [(501,501), (0,501), (501,0)] {
        try check(!allowed(ids.0, ids.1, env), .pureGuard)
    }
    for missing in [[:], ["GITHUB_ACTIONS":"true"], ["PROXYPILOT_VM_DNS_RESOLVER_TESTS":"1"]] {
        try check(!allowed(0, 0, missing), .pureGuard)
    }
    try check(validID("12345678-1234-1234-1234-123456789abc"), .pureGuard)
    for bad in ["", "../DNS", "12345678-1234-1234-1234-123456789ABC", "real.example"] {
        try check(!validID(bad), .pureGuard)
    }
    print("PASS pure-guards")
}
@main private struct Main {
    static func main() {
        do {
            let args = Array(CommandLine.arguments.dropFirst())
            if args == ["--pure-checks"] { try pure(); return }
            // Before all SC calls AND before getaddrinfo (which emits traffic).
            try check(allowed(getuid(), geteuid(), ProcessInfo.processInfo.environment), .guardDenied)
            if args.count == 2 && args[0] == "--acceptance" && validID(args[1]) {
                try acceptance(args[1])
            } else if args.count == 4 && args[0] == "--resolve" && validID(args[1])
                && ["udp", "tcp"].contains(args[2]) && ["4", "6"].contains(args[3]) {
                try resolve(args[1], args[2], args[3] == "4" ? AF_INET : AF_INET6)
            } else { throw Failure.arguments }
        } catch {
            print("FAIL " + ((error as? Failure)?.rawValue ?? "unexpected"))
            exit(1)
        }
    }
}
