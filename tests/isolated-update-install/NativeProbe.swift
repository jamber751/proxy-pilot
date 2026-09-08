import AppKit

// Observations only. Native acceptance uses the real SPUStandardUserDriver;
// this probe never chooses a button or changes a production callback's result.
enum NativeProbe {
    static var manualCheck = false
    private static var activationObserver: NSObjectProtocol?

    static func observeActivation() {
        activationObserver = NSWorkspace.shared.notificationCenter.addObserver(forName: NSWorkspace.didActivateApplicationNotification, object: nil, queue: .main) { notification in
            guard let application = notification.userInfo?[NSWorkspace.applicationUserInfoKey] as? NSRunningApplication,
                  application.processIdentifier == getpid() else { return }
            record("native-focus \(manualCheck ? "manual" : "background")")
        }
    }

    static func record(_ event: String) {
        guard let host = UpdateWorker.enclosingHost(),
              let directory = host.object(forInfoDictionaryKey: "TestDirectory") as? String else { exit(64) }
        let url = URL(fileURLWithPath: directory).appendingPathComponent("worker.events")
        if !FileManager.default.fileExists(atPath: url.path) { FileManager.default.createFile(atPath: url.path, contents: nil) }
        let file = try! FileHandle(forWritingTo: url)
        file.seekToEndOfFile(); file.write(Data((event + "\n").utf8)); file.closeFile()
    }

    static func error(_ error: Error) {
        var current: NSError? = error as NSError
        while let value = current {
            record("error \(value.domain) \(value.code)")
            current = value.userInfo[NSUnderlyingErrorKey] as? NSError
        }
    }

    static func quietWindowCheck() {
        DispatchQueue.main.asyncAfter(deadline: .now() + 1) {
            record("background-visible-windows=\(NSApp.windows.filter { $0.isVisible }.count) active=\(NSApp.isActive)")
        }
    }
}
