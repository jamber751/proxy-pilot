import Darwin
import Foundation

/// A conservative, read-only veto for the staging updater, not VPN authority.
/// Until app/helper replacement is coordinated, an ordinary Sparkle app update
/// must not strand an installed helper with pins for the previous app only.
enum VPNUpdateAdmission {
    enum Decision: String {
        case allowed, requiresCoordinatedUpdate, inspectionFailed

        var error: NSError? {
            switch self {
            case .allowed: return nil
            case .requiresCoordinatedUpdate:
                return NSError(domain: "kz.documentolog.proxypilot.update-admission", code: 1,
                    userInfo: [NSLocalizedDescriptionKey: "Нужно совместное обновление ProxyPilot и VPN-компонента.",
                               NSLocalizedRecoverySuggestionErrorKey: "Обычное обновление пока приостановлено. Текущая версия и настройки сохранены."])
            case .inspectionFailed:
                return NSError(domain: "kz.documentolog.proxypilot.update-admission", code: 2,
                    userInfo: [NSLocalizedDescriptionKey: "Не удалось проверить VPN-компонент перед обновлением.",
                               NSLocalizedRecoverySuggestionErrorKey: "Текущая версия сохранена. Повторите проверку позже."])
            }
        }
    }

    static func inspectSystem() -> Decision {
        inspect(applicationSupport: "/Library/Application Support", launchDaemons: "/Library/LaunchDaemons")
    }

    // Separate bases permit disposable filesystem tests. Neither these paths nor
    // a decision can arrive through worker IPC, a feed, argv, or environment.
    static func inspect(applicationSupport: String, launchDaemons: String) -> Decision {
        let support = open(applicationSupport, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard support >= 0 else { return .inspectionFailed }
        defer { close(support) }
        let daemons = open(launchDaemons, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard daemons >= 0 else { return .inspectionFailed }
        defer { close(daemons) }

        var failed = false
        for (directory, name) in [(support, "ProxyPilot"),
                                   (support, "kz.documentolog.proxypilot.vpn"),
                                   (daemons, "kz.documentolog.proxypilot.vpn-helper.plist")] {
            var attributes = stat()
            if fstatat(directory, name, &attributes, AT_SYMLINK_NOFOLLOW) == 0 {
                // A stopped, incomplete, stale or symlinked installation is
                // still not evidence of absence. Never enter private storage.
                return .requiresCoordinatedUpdate
            }
            if errno != ENOENT { failed = true }
        }
        return failed ? .inspectionFailed : .allowed
    }
}
