import AppKit
import Darwin
import Foundation

/// A one-shot liveness bridge from the already authenticated app A to the
/// fixed installed app B. It carries no path or install authority and is armed
/// only after Broker has accepted the joint update.
final class JointRelaunchSentinel {
    private static let installedApplication = URL(fileURLWithPath: "/Applications/ProxyPilot.app", isDirectory: true)
    private static let maximumWait: TimeInterval = 120

    private let parentPID: pid_t
    private let queue = DispatchQueue(label: "kz.documentolog.proxypilot.joint-relaunch")
    private var armed = false
    private var sawEOF = false // EOF from the frontend-owned update channel.
    private var oneShot = false
    private var deadline = DispatchTime.now()

    init(parentPID: pid_t) {
        self.parentPID = parentPID
    }

    func arm() -> Bool {
        dispatchPrecondition(condition: .onQueue(.main))
        guard !armed, !oneShot, parentPID > 1 else { return false }
        armed = true
        deadline = .now() + Self.maximumWait
        return true
    }

    func frontendEOF() {
        dispatchPrecondition(condition: .onQueue(.main))
        guard armed, !oneShot, !sawEOF else { return }
        sawEOF = true
        waitForParentExit()
    }

    private func waitForParentExit() {
        queue.async { [weak self] in
            guard let self = self else { return }
            while DispatchTime.now() < self.deadline {
                errno = 0
                if kill(self.parentPID, 0) == -1 && errno == ESRCH {
                    DispatchQueue.main.async { self.openInstalledApplication() }
                    return
                }
                usleep(100_000)
            }
            DispatchQueue.main.async { exit(70) }
        }
    }

    private func openInstalledApplication() {
        dispatchPrecondition(condition: .onQueue(.main))
        guard armed, sawEOF, !oneShot, DispatchTime.now() < deadline else { exit(70) }
        oneShot = true
        armed = false
        let configuration = NSWorkspace.OpenConfiguration()
        configuration.activates = true
        NSWorkspace.shared.openApplication(at: Self.installedApplication,
                                            configuration: configuration) { _, error in
            exit(error == nil ? 0 : 70)
        }
    }
}
