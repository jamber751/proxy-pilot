import Darwin
import Dispatch
import Foundation
import os.log

/// Closed, credential-free lifecycle breadcrumbs. These are observations only:
/// a logged stage or elapsed bucket never authorizes a release or operation.
enum VPNActivationDiagnostics {
    enum LaunchdRole: String { case recovery, broker }
    enum LaunchdCommand: String { case bootout, bootstrap, print, other }
    enum LaunchdOutcome: String { case enter, exit, timeout, signal, spawn, submitted }
    struct LaunchdRecord {
        let role: LaunchdRole
        let command: LaunchdCommand
        let outcome: LaunchdOutcome
        let status: Int32
        var line: String {
            "ProxyPilot VPN launchd role: \(role.rawValue); command: \(command.rawValue); outcome: \(outcome.rawValue); status: \(status)"
        }
    }
    /// Pure closed projection. No command arguments, labels, paths, stderr or
    /// arbitrary Error descriptions enter this diagnostic vocabulary.
    static func launchdRecord(role: LaunchdRole, command: LaunchdCommand,
                              outcome: LaunchdOutcome, status: Int32 = -1) -> LaunchdRecord? {
        guard (-1...255).contains(status) else { return nil }
        if outcome == .exit || outcome == .signal { guard status >= 0 else { return nil } }
        else { guard status == -1 else { return nil } }
        return LaunchdRecord(role:role,command:command,outcome:outcome,status:status)
    }
    private static var launchdEmitted = 0
    static func observeLaunchd(role: LaunchdRole, command: LaunchdCommand,
                               outcome: LaunchdOutcome, status: Int32 = -1) {
        #if VPN_SYSTEM_ACTIVATION_DIAGNOSTICS
        guard getuid() == 0, geteuid() == 0 else { return }
        // Successful polling would obscure the failing command and exhaust
        // the bounded record budget. Keep only unexpected print failures.
        if command == .print && (outcome == .enter || (outcome == .exit && (status == 0 || status == 113))) { return }
        guard let record=launchdRecord(role:role,command:command,outcome:outcome,status:status) else { return }
        outputLock.lock()
        guard launchdEmitted < 64 else { outputLock.unlock();return }
        launchdEmitted += 1;outputLock.unlock()
        let sink=OSLog(subsystem:"kz.documentolog.proxypilot.vm",category:"launchd-command")
        os_log("%{public}@",log:sink,type:.error,record.line)
        #endif
    }
    enum Role: String, CaseIterable { case helper, finalizer, runtime, journal, readinessPolicy }
    enum Stage: String, CaseIterable {
        case openStore, selection, journal, identity, runtime, budget, receipt, endpoint, listener, ready
        case charge, drain, start, readiness, finalValidation, budgetSuccess, complete
        case helperPath, description, bootstrap, connect, readinessPolicy
    }
    enum Event: String, CaseIterable { case enter, complete, failure }
    enum Category: String, CaseIterable {
        case none, storeBusy, storeState, activationOff, activationExhausted, activationState
        case launchTimeout, launchFailed, launchStorage, launchCleanup
        case readiness, readinessTimeout, readinessTransport, readinessResponse, endpoint
        case identity, journal, application, directory, other
    }
    enum Elapsed: String, CaseIterable { case lt50, lt250, lt1000, lt2000, lt5000, ge5000 }
    struct Record {
        let role: Role
        let stage: Stage
        let event: Event
        let category: Category
        let elapsed: Elapsed
        var line: String {
            "ProxyPilot VPN activation role: \(role.rawValue); stage: \(stage.rawValue); event: \(event.rawValue); category: \(category.rawValue); elapsed: \(elapsed.rawValue)\n"
        }
    }
    static func elapsed(_ nanos: UInt64) -> Elapsed {
        switch nanos {
        case ..<50_000_000: return .lt50
        case ..<250_000_000: return .lt250
        case ..<1_000_000_000: return .lt1000
        case ..<2_000_000_000: return .lt2000
        case ..<5_000_000_000: return .lt5000
        default: return .ge5000
        }
    }
    static func category(_ error: Error) -> Category {
        switch error {
        case VPNReleaseStoreError.busy: return .storeBusy
        case is VPNReleaseStoreError: return .storeState
        case VPNActivationBudgetError.turnedOff: return .activationOff
        case VPNActivationBudgetError.exhausted: return .activationExhausted
        case is VPNActivationBudgetError: return .activationState
        case VPNLaunchdError.timeout: return .launchTimeout
        case VPNLaunchdError.launchFailed: return .launchFailed
        case VPNLaunchdError.cleanupNotConfirmed: return .launchCleanup
        case is VPNLaunchdError: return .launchStorage
        case VPNHelperReadinessError.timeout: return .readinessTimeout
        case VPNHelperReadinessError.transport: return .readinessTransport
        case VPNHelperReadinessError.invalidResponse: return .readinessResponse
        case is VPNHelperReadinessError: return .readiness
        case is VPNEndpointError: return .endpoint
        case is VPNPeerAuthenticationError: return .identity
        default: return .other
        }
    }

    final class Trace {
        private let role: Role
        private let clock: () -> UInt64
        private let output: (Record) -> Void
        private var stage: Stage
        private var began: UInt64
        private var records = 0
        private var finished = false
        static let maximumRecords = 64
        init(role: Role, stage: Stage = .selection,
             clock: @escaping () -> UInt64 = { DispatchTime.now().uptimeNanoseconds },
             output: @escaping (Record) -> Void = VPNActivationDiagnostics.emit) {
            self.role = role; self.stage = stage; self.clock = clock; self.output = output
            self.began = clock()
            record(.enter, category: .none)
        }
        private func record(_ event: Event, category: Category) {
            guard records < Self.maximumRecords else { return }
            records += 1
            let now = clock()
            output(Record(role: role, stage: stage, event: event, category: category,
                          elapsed: VPNActivationDiagnostics.elapsed(now >= began ? now - began : 0)))
        }
        func mark(_ next: Stage) {
            guard !finished else { return }
            record(.complete, category: .none)
            stage = next; began = clock()
            record(.enter, category: .none)
        }
        func complete() {
            guard !finished else { return }
            record(.complete, category: .none); finished = true
        }
        func fail(_ error: Error) {
            guard !finished else { return }
            record(.failure, category: VPNActivationDiagnostics.category(error)); finished = true
        }
    }
    static func run<Value>(role: Role, stage: Stage = .selection,
                           _ work: (Trace) throws -> Value) rethrows -> Value {
        let trace = Trace(role: role, stage: stage)
        do { let value = try work(trace); trace.complete(); return value }
        catch { trace.fail(error); throw error }
    }

    private static let log = OSLog(subsystem: "kz.documentolog.proxypilot.vpn", category: "activation")
    private static let outputLock = NSLock()
    private static var emitted = 0
    static let maximumProcessRecords = 128
    static func emit(_ record: Record) {
        outputLock.lock()
        guard emitted < maximumProcessRecords else { outputLock.unlock(); return }
        emitted += 1; outputLock.unlock()
        os_log("%{public}@", log: log, type: record.event == .failure ? .error : .info, record.line)
        #if VPN_SYSTEM_ACTIVATION_DIAGNOSTICS
        _ = writeRegular(record, descriptor: STDERR_FILENO, owner: 0, allowedPaths: [
            "/private/tmp/kz.documentolog.proxypilot-vpn-activation-diagnostics/helper.log",
            "/private/tmp/kz.documentolog.proxypilot-vpn-activation-diagnostics/recovery.log"])
        #endif
    }

    /// Diagnostics must never turn a closed Installer/parent pipe into SIGPIPE.
    /// Duplicate first so the checked file description cannot be replaced by a
    /// concurrent close/reuse of the inherited stderr number. No global signal
    /// disposition or protocol socket option is changed.
    private static func writeRegular(_ record: Record, descriptor: Int32,
                                     owner: uid_t, allowedPaths: Set<String>) -> Bool {
        let owned = fcntl(descriptor, F_DUPFD_CLOEXEC, 0)
        guard owned >= 0 else { return false }
        defer { close(owned) }
        var info = stat()
        guard fstat(owned, &info) == 0, info.st_mode & S_IFMT == S_IFREG,
              info.st_uid == owner, info.st_mode & 0o7777 == 0o600, info.st_nlink == 1 else { return false }
        var path = [CChar](repeating: 0, count: Int(MAXPATHLEN))
        guard fcntl(owned, F_GETPATH, &path) == 0, allowedPaths.contains(String(cString: path)) else { return false }
        let bytes = Data(record.line.utf8)
        return bytes.withUnsafeBytes { Darwin.write(owned, $0.baseAddress, $0.count) == $0.count }
    }
    #if VPN_ACTIVATION_DIAGNOSTICS_TESTING
    static func testWriteRegular(_ record: Record, descriptor: Int32,
                                 owner: uid_t, allowedPaths: Set<String>) -> Bool {
        writeRegular(record, descriptor: descriptor, owner: owner, allowedPaths: allowedPaths)
    }
    #endif

    #if VPN_SYSTEM_ACTIVATION_DIAGNOSTICS
    /// Fixture-only stderr files live outside every production storage/removal
    /// namespace. The disposable root VM must precreate these exact private
    /// nodes; this function never creates or repairs diagnostic storage.
    static func privateLogPath(recovery: Bool) throws -> String {
        guard getuid() == 0, geteuid() == 0 else { throw VPNLaunchdError.requiresRoot }
        let parent = open("/private/tmp", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard parent >= 0 else { throw VPNLaunchdError.unsafeStorage }
        defer { close(parent) }
        var tmp = stat()
        guard fstat(parent, &tmp) == 0, tmp.st_uid == 0,
              tmp.st_mode & S_IFMT == S_IFDIR, tmp.st_mode & 0o7777 == 0o1777 else {
            throw VPNLaunchdError.unsafeStorage
        }
        let name = "kz.documentolog.proxypilot-vpn-activation-diagnostics"
        let directory = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard directory >= 0 else { throw VPNLaunchdError.unsafeStorage }
        defer { close(directory) }
        var held = stat(), named = stat(), filesystem = statfs()
        guard fstat(directory, &held) == 0, held.st_uid == 0,
              held.st_mode & S_IFMT == S_IFDIR, held.st_mode & 0o7777 == 0o700,
              held.st_nlink > 0, fstatfs(directory, &filesystem) == 0,
              filesystem.f_flags & UInt32(MNT_LOCAL) != 0,
              fstatat(parent, name, &named, AT_SYMLINK_NOFOLLOW) == 0,
              held.st_dev == named.st_dev, held.st_ino == named.st_ino else {
            throw VPNLaunchdError.unsafeStorage
        }
        try noACL(directory)
        let leaf = recovery ? "recovery.log" : "helper.log"
        let file = openat(directory, leaf, O_WRONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard file >= 0 else { throw VPNLaunchdError.unsafeStorage }
        defer { close(file) }
        guard fstat(file, &held) == 0, held.st_uid == 0,
              held.st_mode & S_IFMT == S_IFREG, held.st_mode & 0o7777 == 0o600,
              held.st_nlink == 1,
              fstatat(directory, leaf, &named, AT_SYMLINK_NOFOLLOW) == 0,
              held.st_dev == named.st_dev, held.st_ino == named.st_ino else {
            throw VPNLaunchdError.unsafeStorage
        }
        try noACL(file)
        return "/private/tmp/" + name + "/" + leaf
    }
    private static func noACL(_ descriptor: Int32) throws {
        guard let security = filesec_init() else { throw VPNLaunchdError.unsafeStorage }
        defer { filesec_free(security) }
        var value = stat()
        guard fstatx_np(descriptor, &value, security) == 0 else { throw VPNLaunchdError.unsafeStorage }
        var acl: acl_t?
        errno = 0
        let result = filesec_get_property(security, FILESEC_ACL, &acl)
        if result == -1, errno == ENOENT { return }
        guard result == 0, let acl else { throw VPNLaunchdError.unsafeStorage }
        defer { acl_free(UnsafeMutableRawPointer(acl)) }
        var entry: acl_entry_t?
        errno = 0
        guard acl_get_entry(acl, Int32(ACL_FIRST_ENTRY.rawValue), &entry) == -1, errno == EINVAL else {
            throw VPNLaunchdError.unsafeStorage
        }
    }
    #endif
}
