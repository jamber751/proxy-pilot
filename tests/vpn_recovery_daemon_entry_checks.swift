import CryptoKit
import Darwin
import Dispatch
import Foundation

/// Test-only process boundary used by the real ServiceMain. Every path is
/// derived from a disposable test root; production builds never link this type.
enum VPNRecoveryDaemonEntryTestHarness {
    private struct Context {
        let root: URL
        let storage: URL
        let applications: URL
        let plists: URL
        let helperLabel: String
        let recoveryLabel: String
    }

    private static func authority() throws -> (VPNReleaseAuthority, Curve25519.Signing.PrivateKey) {
        let key = try Curve25519.Signing.PrivateKey(rawRepresentation: Data(repeating: 0x42, count: 32))
        return (try VPNReleaseAuthority(
            trustedPublicKey: key.publicKey.rawRepresentation,
            minimumSequence: 1, supportedProtocol: 1), key)
    }

    private static func context(storage: URL) -> Context {
        let resolvedStorage = storage.resolvingSymlinksInPath()
        let root = resolvedStorage.deletingLastPathComponent()
        var attributes = stat()
        _ = lstat(resolvedStorage.path, &attributes)
        let identity = "\(UInt64(attributes.st_dev)):\(UInt64(attributes.st_ino))"
        let digest = SHA256.hash(data: Data(identity.utf8)).prefix(8)
            .map { String(format: "%02x", $0) }.joined()
        return Context(
            root: root, storage: resolvedStorage,
            applications: root.appendingPathComponent("Applications", isDirectory: true),
            plists: root.appendingPathComponent("plists", isDirectory: true),
            helperLabel: "kz.documentolog.proxypilot.vpn-helper.e2e-\(digest)",
            recoveryLabel: "kz.documentolog.proxypilot.vpn-recovery.e2e-\(digest)")
    }

    private static func openDirectory(_ url: URL) throws -> Int32 {
        let descriptor = open(url.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else { throw VPNLaunchdError.unsafeStorage }
        return descriptor
    }

    private static func manifest(sequence: UInt64, version: String,
                                 appARM: String, appIntel: String,
                                 helperARM: String, helperIntel: String,
                                 helper: Data) -> Data {
        let hash = SHA256.hash(data: helper).map { String(format: "%02x", $0) }.joined()
        return Data("""
        format=1
        product=kz.documentolog.proxypilot
        sequence=\(sequence)
        version=\(version)
        protocol=1
        app-arm64=\(appARM)
        app-x86_64=\(appIntel)
        helper-arm64=\(helperARM)
        helper-x86_64=\(helperIntel)
        helper-sha256=\(hash)
        helper-bytes=\(helper.count)

        """.utf8)
    }

    private static func prepare(_ arguments: [String]) throws -> Int32 {
        guard arguments.count == 9 else { return 64 }
        let storage = URL(fileURLWithPath: arguments[2], isDirectory: true)
        let directory = try openDirectory(storage)
        defer { close(directory) }
        let (authority, key) = try authority()
        let store = try VPNReleaseStore(trustedDirectoryDescriptor: directory, authority: authority)
        let helper = try Data(contentsOf: URL(fileURLWithPath: arguments[0]))
        let previous = manifest(sequence: 10, version: "1.6.0",
            appARM: arguments[3], appIntel: arguments[4],
            helperARM: arguments[7], helperIntel: arguments[8], helper: helper)
        let candidate = manifest(sequence: 11, version: "1.7.0",
            appARM: arguments[5], appIntel: arguments[6],
            helperARM: arguments[7], helperIntel: arguments[8], helper: helper)
        let previousSignature = try key.signature(
            for: VPNReleaseAuthority.signatureDomain + previous)
        let candidateSignature = try key.signature(
            for: VPNReleaseAuthority.signatureDomain + candidate)
        let previousDigest = SHA256.hash(data: previous).map { String(format: "%02x", $0) }.joined()
        let candidateDigest = SHA256.hash(data: candidate).map { String(format: "%02x", $0) }.joined()
        let transition = Data("""
        format=1
        product=kz.documentolog.proxypilot
        from-sequence=10
        from-sha256=\(previousDigest)
        to-sequence=11
        to-sha256=\(candidateDigest)

        """.utf8)
        let transitionSignature = try key.signature(
            for: VPNReleaseAuthority.updateTransitionDomain + transition)
        _ = try store.bootstrapDeployment(
            payload: previous, signature: previousSignature,
            helper: helper, trustedOwnerUserID: geteuid())
        let prepared = try store.prepareUpdateJournal(
            payload: candidate, signature: candidateSignature, helper: helper,
            transitionPayload: transition, transitionSignature: transitionSignature,
            expectedSequence: 10)
        let pending = try store.markUpdateReplacementPending(
            transactionID: prepared.transactionID, expectedRevision: prepared.revision)
        let selected = try store.selectUpdateCandidate(
            transactionID: pending.transactionID, expectedRevision: pending.revision)
        print("prepared:selected:\(selected.revision)")
        return 0
    }

    private static func arm(_ arguments: [String], holdLease: Bool) throws -> Int32 {
        guard arguments.count == 3 else { return 64 }
        let context = context(storage: URL(fileURLWithPath: arguments[2], isDirectory: true))
        let directory = try openDirectory(context.storage)
        defer { close(directory) }
        let (authority, _) = try authority()
        let store = try VPNReleaseStore(trustedDirectoryDescriptor: directory, authority: authority)
        let candidate = try store.loadUpdateJournal()!.candidate
        var lease: VPNLifecycleLease?
        if holdLease { lease = try VPNLifecycleOwnership.acquire(inTrustedDirectory: directory) }
        defer { lease?.release() }
        let recovery = try VPNRecoveryLaunchdJob.testUserDomain(
            label: context.recoveryLabel, plistDirectory: context.plists,
            storageDirectory: directory)
        try recovery.installAndArm(
            candidate, deadline: DispatchTime.now().uptimeNanoseconds + 20_000_000_000)
        print(holdLease ? "armed:held" : "armed"); fflush(stdout)
        if holdLease { sleep(3) }
        return 0
    }

    private static func serve(_ arguments: [String]) throws -> Int32 {
        guard arguments.count == 3 else { return 64 }
        let context = context(storage: URL(fileURLWithPath: arguments[2], isDirectory: true))
        let directory = try openDirectory(context.storage)
        defer { close(directory) }
        let (authority, _) = try authority()
        try VPNHelperDaemon.testServe(
            directory: directory, endpoint: directory, shared: false,
            authority: authority,
            recoveryReadinessPolicies: { _, selected in
                [try selected.release.testHelperPolicy()]
            }, recoveryFixtureInstaller: true,
            recoveryCleanup: { _ in
                let recovery = try VPNRecoveryLaunchdJob.testUserDomain(
                    label: context.recoveryLabel, plistDirectory: context.plists,
                    storageDirectory: directory)
                try recovery.remove(
                    deadline: DispatchTime.now().uptimeNanoseconds + 5_000_000_000)
            })
        return 0
    }

    private static func recover(_ arguments: [String]) throws -> Int32 {
        let executable = URL(fileURLWithPath: arguments[0])
        let context = context(storage: executable.deletingLastPathComponent())
        let directory = try openDirectory(context.storage)
        let applications = try openDirectory(context.applications)
        defer { close(directory); close(applications) }
        let (authority, _) = try authority()
        return VPNSelectedCandidateRecoveryDaemonEntry.testRunIfRequested(
            arguments: arguments, directory: directory, authority: authority,
            applicationsDirectory: applications,
            runtime: { service in
                try VPNLaunchdRuntime.testUserDomain(
                    label: context.helperLabel, plistDirectory: context.plists,
                    storageDirectory: service)
            }, removeRecoveryJob: { service, deadline in
                let recovery = try VPNRecoveryLaunchdJob.testUserDomain(
                    label: context.recoveryLabel, plistDirectory: context.plists,
                    storageDirectory: service)
                try recovery.removeCurrent(deadline: deadline)
            }) ?? 64
    }

    static func runIfRequested(arguments: [String]) -> Int32? {
        guard arguments.count >= 2 else { return nil }
        do {
            switch arguments[1] {
            case "fixture-prepare": return try prepare(arguments)
            case "fixture-arm": return try arm(arguments, holdLease: false)
            case "fixture-arm-held": return try arm(arguments, holdLease: true)
            case "serve": return try serve(arguments)
            case VPNRecoveryLaunchdJob.recoveryArgument: return try recover(arguments)
            default: return nil
            }
        } catch {
            FileHandle.standardError.write(Data("fixture:\(error)\n".utf8))
            if arguments.count == 3, arguments[1] == "serve" {
                try? Data("\(error)".utf8).write(to: URL(
                    fileURLWithPath: arguments[2], isDirectory: true)
                    .appendingPathComponent("fixture-error.txt"))
            }
            return 77
        }
    }
}
