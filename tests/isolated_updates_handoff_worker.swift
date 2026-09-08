import Foundation

// Scripted unprivileged peer for frontend lifecycle tests. No Sparkle installer.
final class HandoffWorker {
    private var channel: UpdateChannel!
    private let token = UUID()
    private var resumed = false
    private let mode: String
    init(mode: String) { self.mode = mode }

    func start() throws {
        channel = try UpdateChannel(read: STDIN_FILENO, write: STDOUT_FILENO, receivesCommands: true,
                                    receive: { [weak self] message in
            DispatchQueue.main.async { self?.receive(message) }
        }, disconnected: { exit(0) })
        channel.start()
        if mode == "handoff-unsolicited" {
            state(canCheck: false, inProgress: false)
            channel.send(.prepare(token))
        } else { state(canCheck: true, inProgress: false) }
    }

    private func state(canCheck: Bool, inProgress: Bool, version: String? = nil) {
        channel.send(.state(UpdateSnapshot(canCheck: canCheck, automatic: false, inProgress: inProgress, availableVersion: version)))
    }

    private func receive(_ message: UpdateMessage) {
        switch message {
        case .check:
            state(canCheck: false, inProgress: true)
            channel.send(.prepare(token))
            if mode == "handoff-duplicate" { channel.send(.prepare(token)) }
            if mode == "handoff-abort" {
                DispatchQueue.main.asyncAfter(deadline: .now() + 0.1) { [self] in
                    channel.send(.aborted)
                    DispatchQueue.main.asyncAfter(deadline: .now() + 0.2) { [self] in
                        state(canCheck: true, inProgress: false, version: "ABORT_OK")
                    }
                }
            }
        case .resume(let returned):
            precondition(mode == "handoff-good" && returned == token && !resumed, "Duplicate/stale relaunch permission")
            resumed = true
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.2) { [self] in
                channel.send(.aborted) // Synthetic completion: never installs.
                state(canCheck: true, inProgress: false, version: "HANDOFF_OK")
            }
        default: fatalError("Unexpected command")
        }
    }
}
