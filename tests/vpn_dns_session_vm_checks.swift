// Disposable GitHub VM experiment, not a production DNS backend.
// Public API contract: SDK SCDynamicStore.h, AddTemporaryValue and CreateWithOptions.
// Reference implementation (not proof of the installed OS behavior):
// https://github.com/apple-oss-distributions/configd/blob/main/configd.tproj/_configset.c
import Foundation
import SystemConfiguration
import Darwin

private let prefix = "State:/ProxyPilotAcceptance/"
private let fixture = ["ProxyPilotSyntheticFixture": "dns-session-v1"] as CFDictionary

private func authorized(uid: uid_t, euid: uid_t, environment: [String: String]) -> Bool {
    uid == 0 && euid == 0 && environment["GITHUB_ACTIONS"] == "true"
        && environment["PROXYPILOT_VM_DNS_SESSION_TESTS"] == "1"
}

private func validKey(_ key: String) -> Bool {
    guard key.hasPrefix(prefix) else { return false }
    let parts = key.dropFirst(prefix.count).split(separator: "/", omittingEmptySubsequences: false)
    return parts.count == 2 && UUID(uuidString: String(parts[0])) != nil
        && ["close", "termination", "equal-overwrite"].contains(String(parts[1]))
}

private enum Failure: String, Error {
    case guardDenied, invalidArguments, sessionCreation, fixtureOccupied, add, copy
    case missingReadError, closeCleanup, childStart, childTermination, foreignWrite
    case foreignUpdateLost, cleanup, pureGuard
}

private func require(_ condition: @autoclosure () throws -> Bool, _ failure: Failure) throws {
    if try !condition() { throw failure }
}

private func session(temporary: Bool) throws -> SCDynamicStore {
    let options = [kSCDynamicStoreUseSessionKeys as String: temporary] as CFDictionary
    guard let store = SCDynamicStoreCreateWithOptions(nil, "ProxyPilotSyntheticAcceptance" as CFString,
                                                    options, nil, nil) else {
        throw Failure.sessionCreation
    }
    return store
}

// Read only the exact fixture key. A missing key must be kSCStatusNoKey,
// otherwise a configd/read error must not masquerade as successful cleanup.
private func value(_ store: SCDynamicStore, _ key: String) throws -> CFPropertyList? {
    let result = SCDynamicStoreCopyValue(store, key as CFString)
    if result == nil { try require(SCError() == kSCStatusNoKey, .missingReadError) }
    return result
}

private func matches(_ store: SCDynamicStore, _ key: String) throws -> Bool {
    guard let current = try value(store, key) else { return false }
    return CFEqual(current, fixture)
}

private func waitAbsent(_ observer: SCDynamicStore, _ key: String) throws -> Bool {
    for _ in 0..<100 {
        if try value(observer, key) == nil { return true }
        usleep(50_000)
    }
    return false
}

// Scope exit releases the only strong reference. No RemoveValue is used to
// manufacture the close-cleanup evidence.
@inline(never)
private func addThenClose(_ key: String) throws {
    let owner = try session(temporary: true)
    try require(SCDynamicStoreAddValue(owner, key as CFString, fixture), .add)
    try require(try matches(owner, key), .copy)
    withExtendedLifetime(owner) {}
}

@inline(never)
private func addThenForeignOverwrite(_ key: String, writer: SCDynamicStore) throws {
    let owner = try session(temporary: true)
    try require(SCDynamicStoreAddValue(owner, key as CFString, fixture), .add)
    try require(try matches(owner, key), .copy)
    // Equal data deliberately challenges ownership inference from value equality.
    // The foreign writer is a normal (non-session-key) session.
    try require(SCDynamicStoreSetValue(writer, key as CFString, fixture), .foreignWrite)
    try require(try matches(writer, key), .copy)
    withExtendedLifetime(owner) {}
}

private func child(_ key: String) throws {
    let owner = try session(temporary: true)
    // Explicit temporary-add API complements the session-option AddValue test.
    try require(SCDynamicStoreAddTemporaryValue(owner, key as CFString, fixture), .add)
    try require(try matches(owner, key), .copy)
    FileHandle.standardOutput.write(Data("ready\n".utf8))
    withExtendedLifetime(owner) { while true { pause() } }
}

private func acceptance() throws {
    let observer = try session(temporary: false)
    let run = prefix + UUID().uuidString + "/"
    let closeKey = run + "close"
    let terminationKey = run + "termination"
    let equalKey = run + "equal-overwrite"
    let keys = [closeKey, terminationKey, equalKey]
    for key in keys {
        try require(validKey(key), .invalidArguments)
        try require(try value(observer, key) == nil, .fixtureOccupied)
    }
    try addThenClose(closeKey)
    try require(try waitAbsent(observer, closeKey), .closeCleanup)
    print("PASS same-session-add-copy-close")

    let process = Process()
    process.executableURL = URL(fileURLWithPath: CommandLine.arguments[0]).standardizedFileURL
    process.arguments = ["--child", terminationKey]
    process.environment = ProcessInfo.processInfo.environment
    // No child output is forwarded, and no host state is collected.
    process.standardOutput = FileHandle.nullDevice
    process.standardError = FileHandle.nullDevice
    try process.run()
    defer {
        if process.isRunning { kill(process.processIdentifier, SIGKILL); process.waitUntilExit() }
    }
    var childReady = false
    for _ in 0..<100 {
        if try matches(observer, terminationKey) { childReady = true; break }
        if !process.isRunning { break }
        usleep(50_000)
    }
    try require(childReady && process.isRunning, .childStart)
    try require(kill(process.processIdentifier, SIGKILL) == 0, .childTermination)
    process.waitUntilExit()
    try require(process.terminationReason == .uncaughtSignal && process.terminationStatus == SIGKILL,
                .childTermination)
    try require(try waitAbsent(observer, terminationKey), .closeCleanup)
    print("PASS child-SIGKILL-session-cleanup")

    try addThenForeignOverwrite(equalKey, writer: observer)
    // Wait beyond the close cleanup window before accepting persistence.
    for _ in 0..<100 {
        try require(try matches(observer, equalKey), .foreignUpdateLost)
        usleep(50_000)
    }
    print("PASS equal-foreign-update-survives-owner-close")
    // Exact test-created key only; this fixture teardown is not a production
    // compare-and-swap/remove algorithm. Never enumerate or delete by prefix.
    try require(SCDynamicStoreRemoveValue(observer, equalKey as CFString), .cleanup)
    for key in keys { try require(try value(observer, key) == nil, .cleanup) }
    print("PASS exact-fixture-cleanup")
}

private func pureChecks() throws {
    let enabled = ["GITHUB_ACTIONS": "true", "PROXYPILOT_VM_DNS_SESSION_TESTS": "1"]
    try require(authorized(uid: 0, euid: 0, environment: enabled), .pureGuard)
    for ids: (uid_t, uid_t) in [(501, 501), (501, 0), (0, 501)] {
        try require(!authorized(uid: ids.0, euid: ids.1, environment: enabled), .pureGuard)
    }
    for env in [[:], ["GITHUB_ACTIONS": "true"], ["PROXYPILOT_VM_DNS_SESSION_TESTS": "1"],
                ["GITHUB_ACTIONS": "false", "PROXYPILOT_VM_DNS_SESSION_TESTS": "1"]] {
        try require(!authorized(uid: 0, euid: 0, environment: env), .pureGuard)
    }
    let run = UUID().uuidString
    try require(validKey(prefix + run + "/termination"), .pureGuard)
    for key in ["State:/Network/Service/fixture/DNS", prefix + "bad/close",
                prefix + run + "/close/extra", prefix + run + "/DNS", prefix + run + "/../close"] {
        try require(!validKey(key), .pureGuard)
    }
    print("PASS pure-root-ci-opt-in-and-exact-namespace-guards")
}

@main
private struct Main {
    static func main() {
        do {
            let arguments = Array(CommandLine.arguments.dropFirst())
            if arguments == ["--pure-checks"] {
                // This path calls no SystemConfiguration API, even reads.
                try pureChecks()
            } else {
                try require(authorized(uid: getuid(), euid: geteuid(),
                                       environment: ProcessInfo.processInfo.environment), .guardDenied)
                if arguments == ["--acceptance"] { try acceptance() }
                else if arguments.count == 2 && arguments[0] == "--child" && validKey(arguments[1]) {
                    try child(arguments[1])
                } else { throw Failure.invalidArguments }
            }
        } catch {
            // Fixed categories only; no argv, key, environment, SC error text,
            // dynamic-store contents, or arbitrary child diagnostics.
            let category = (error as? Failure)?.rawValue ?? "unexpected"
            print("FAIL " + category)
            exit(1)
        }
    }
}
