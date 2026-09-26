import Darwin
import Dispatch
import Foundation
import SystemConfiguration

/// Same executable as the signed frontend. Dispatched BEFORE NSApplication,
/// ProxyModel, any CLI lookup or updater is initialized. No arbitrary arguments,
/// inherited trust, paths, owner UID or shell command is accepted by this entry.
enum VPNInstallationEntry {
    enum Action: String {
        case verify = "--vpn-support-verify"
        case status = "--vpn-support-status"
        case install = "--vpn-support-install"
        case update = "--vpn-support-update"
        case remove = "--vpn-support-remove"
    }

    static func runIfRequested(arguments: [String]) -> Int32? {
        if let status = VPNSelectedCandidateRecoveryEntry.runIfRequested(arguments: arguments) {
            return status
        }
        if let status = VPNInstalledCandidateEntry.runIfRequested(arguments: arguments) {
            return status
        }
        if let status = VPNReplacementExecutorEntry.runIfRequested(arguments: arguments) {
            return status
        }
        let options = Array(arguments.dropFirst())
        let installationOption = options.contains(where: {
            $0.hasPrefix("--vpn-support") || $0.hasPrefix("--vpn-protected")
        })
        guard installationOption else {
            // Exact hidden modes were dispatched above. A malformed or future
            // --vpn-* role must never continue into ordinary GUI bootstrap.
            if options.contains(where: { $0.hasPrefix("--vpn-") }) { return 64 }
            // Running the normal proxy UI/worker as root is never supported.
            return getuid() == 0 || geteuid() == 0 ? 77 : nil
        }
        guard options.count == 1, let action = Action(rawValue: options[0]) else { return 64 }
        guard getuid() == geteuid(), action == .verify || action == .status || geteuid() == 0 else { return 77 }
        guard action != .status || geteuid() != 0 else { return 77 }
        do {
            let authority = try VPNReleaseTrust.authority()
            guard Bundle.main.bundleIdentifier == "kz.documentolog.proxypilot",
                  Bundle.main.object(forInfoDictionaryKey: "ProxyPilotVPNInstaller") as? Bool == true,
                  let version = Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String,
                  Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String == version else {
                throw VPNInstallationPayloadError.versionMismatch
            }
            let payload = try VPNInstallationPayload.load(directory: Bundle.main.bundleURL.deletingLastPathComponent(),
                                                            version: version, authority: authority)
            let policy = try geteuid() == 0 ? payload.release.installerPolicy()
                : payload.release.clientPolicy(forTrustedUserID: geteuid())
            try VPNPeerAuthentication.validateCurrentProcess(policy: policy)
            switch action {
            case .verify:
                // Integrity preflight only. Does not open installed storage,
                // contact a helper, show UI, or claim that VPN is available.
                print("VPN support package verified.")
            case .status:
                // Ordinary-user cross-UID readiness; not a VPN connect action.
                let socket = try VPNEndpointDirectory.connectSystem(deadline: DispatchTime.now().uptimeNanoseconds + 2_000_000_000)
                let session = try VPNHelperSession.open(takingSocket: socket, release: payload.release)
                defer { session.close() }
                let (status, body) = try session.request(.status)
                guard status == .ok, body.count == 16,
                      VPNHelperProtocol.number(body[0..<8]) == payload.release.sequence,
                      VPNHelperProtocol.number(body[8..<16]) == payload.release.protocolVersion else {
                    throw VPNHelperSessionError.invalidResponse
                }
                print("VPN support is available. Release \(payload.release.sequence).")
            case .install:
                let owner = try consoleOwner()
                _ = try VPNInstaller.install(payload: payload.manifest, signature: payload.signature,
                                              helper: payload.helper, engine: payload.engine, authority: authority, trustedOwnerUserID: owner)
                print("VPN support installed.")
            case .update:
                let directory = try VPNDirectoryProvisioner.openSystemDirectory(create: false)
                let sequence: UInt64
                do {
                    defer { close(directory) }
                    sequence = try VPNReleaseStore(trustedDirectoryDescriptor: directory, authority: authority)
                        .loadDeployment().release.sequence
                }
                _ = try VPNInstaller.update(payload: payload.manifest, signature: payload.signature,
                                             helper: payload.helper, engine: payload.engine, authority: authority, expectedSequence: sequence,
                                             intent: .explicit)
                print("VPN support updated.")
            case .remove:
                try VPNInstaller.uninstall()
                print("VPN support removed.")
            }
            return 0
        } catch {
            // Stable error codes, no personal paths, payloads or key material.
            FileHandle.standardError.write(Data("VPN support operation failed. No authorization was bypassed.\n".utf8))
            return 77
        }
    }

    private static func consoleOwner() throws -> uid_t {
        var user: uid_t = 0, group: gid_t = 0
        guard let name = SCDynamicStoreCopyConsoleUser(nil, &user, &group) as String?,
              name != "loginwindow", !name.isEmpty, user >= 500, user != uid_t.max,
              let account = getpwuid(user), account.pointee.pw_uid == user,
              String(cString: account.pointee.pw_name) == name else { throw VPNPeerAuthenticationError.denied }
        // The owner comes from the local console session, never SUDO_UID, argv,
        // updater IPC or a package field. Updates preserve the stored owner.
        return user
    }
}
