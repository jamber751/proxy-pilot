// Pure injected logging only. No OSLog sink, Keychain, launchd or system paths.
import Darwin
import Foundation

@main enum VPNActivationDiagnosticsChecks {
    enum Failure: Error { case check }
    struct PrivateError: Error, CustomStringConvertible {
        var description: String { fatalError("An arbitrary error description must never be evaluated") }
    }
    static func check(_ condition: @autoclosure () -> Bool) throws {
        guard condition() else { throw Failure.check }
    }
    static func main() throws {
        try check(VPNActivationDiagnostics.category(VPNReleaseStoreError.busy) == .storeBusy)
        try check(VPNActivationDiagnostics.category(VPNReleaseStoreError.invalidState) == .storeState)
        try check(VPNActivationDiagnostics.category(VPNActivationBudgetError.exhausted) == .activationExhausted)
        try check(VPNActivationDiagnostics.category(VPNActivationBudgetError.turnedOff) == .activationOff)
        try check(VPNActivationDiagnostics.category(VPNLaunchdError.timeout) == .launchTimeout)
        try check(VPNActivationDiagnostics.category(VPNHelperReadinessError.timeout) == .readinessTimeout)
        try check(VPNActivationDiagnostics.category(VPNHelperReadinessError.transport) == .readinessTransport)
        try check(VPNActivationDiagnostics.category(VPNHelperReadinessError.invalidResponse) == .readinessResponse)
        try check(VPNActivationDiagnostics.category(VPNPeerAuthenticationError.denied) == .identity)
        try check(VPNActivationDiagnostics.category(PrivateError()) == .other)
        for (nanos, bucket) in [(UInt64(0), VPNActivationDiagnostics.Elapsed.lt50),
                (50_000_000, .lt250), (250_000_000, .lt1000), (1_000_000_000, .lt2000),
                (2_000_000_000, .lt5000), (5_000_000_000, .ge5000), (UInt64.max, .ge5000)] {
            try check(VPNActivationDiagnostics.elapsed(nanos) == bucket)
        }
        var now: UInt64 = 0
        var records: [VPNActivationDiagnostics.Record] = []
        let trace = VPNActivationDiagnostics.Trace(role: .finalizer, clock: { now }, output: { records.append($0) })
        now = 2_100_000_000
        trace.mark(.readiness)
        now += 100_000_000
        trace.fail(VPNReleaseStoreError.busy)
        trace.complete(); trace.mark(.complete); trace.fail(PrivateError())
        try check(records.count == 4)
        try check(records[1].elapsed == .lt5000 && records[1].event == .complete)
        try check(records[3].stage == .readiness && records[3].category == .storeBusy && records[3].elapsed == .lt250)
        let bounded = VPNActivationDiagnostics.Trace(role: .helper, clock: { 0 }, output: { records.append($0) })
        let baseline = records.count - 1
        for _ in 0..<1000 { bounded.mark(.journal) }
        bounded.fail(PrivateError())
        try check(records.count - baseline == VPNActivationDiagnostics.Trace.maximumRecords)
        for record in records {
            try check(record.line.hasPrefix("ProxyPilot VPN activation role: "))
            try check(!record.line.contains("PRIVATE") && !record.line.contains("/"))
            try check(record.line.utf8.count < 220)
        }
        let folder = FileManager.default.temporaryDirectory.appendingPathComponent("pp-regular-diagnostic-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: false,
                                                attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: folder) }
        let file = open(folder.appendingPathComponent("log").path, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard file >= 0 else { throw Failure.check }; defer { close(file) }
        var path = [CChar](repeating: 0, count: Int(MAXPATHLEN))
        guard fcntl(file, F_GETPATH, &path) == 0 else { throw Failure.check }
        let allowed: Set<String> = [String(cString: path)]
        let record = records[0]
        try check(VPNActivationDiagnostics.testWriteRegular(record, descriptor: file, owner: geteuid(), allowedPaths: allowed))
        var before = stat(); guard fstat(file, &before) == 0 else { throw Failure.check }
        try check(before.st_size == record.line.utf8.count)
        try check(!VPNActivationDiagnostics.testWriteRegular(record, descriptor: file, owner: uid_t.max, allowedPaths: allowed))
        try check(!VPNActivationDiagnostics.testWriteRegular(record, descriptor: file, owner: geteuid(), allowedPaths: []))
        guard fchmod(file, 0o644) == 0 else { throw Failure.check }
        try check(!VPNActivationDiagnostics.testWriteRegular(record, descriptor: file, owner: geteuid(), allowedPaths: allowed))
        guard fchmod(file, 0o600) == 0 else { throw Failure.check }
        var closedPipe: [Int32] = [-1, -1]
        guard pipe(&closedPipe) == 0 else { throw Failure.check }
        close(closedPipe[0]); defer { close(closedPipe[1]) }
        // This disposable test process deliberately retains default SIGPIPE.
        // A mistaken write to the closed pipe must kill the test rather than
        // being hidden by an ignored process-wide signal.
        signal(SIGPIPE, SIG_DFL)
        try check(!VPNActivationDiagnostics.testWriteRegular(record, descriptor: closedPipe[1], owner: geteuid(), allowedPaths: allowed))
        var after = stat(); guard fstat(file, &after) == 0 else { throw Failure.check }
        try check(before.st_size == after.st_size)
        print("closed activation diagnostics passed")
    }
}
