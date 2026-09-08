import AppKit
import Security

func record(_ event: String) {
    let directory = Bundle.main.object(forInfoDictionaryKey: "TestDirectory") as! String
    let path = URL(fileURLWithPath: directory).appendingPathComponent("host.events")
    if !FileManager.default.fileExists(atPath: path.path) { FileManager.default.createFile(atPath: path.path, contents: nil) }
    let file = try! FileHandle(forWritingTo: path)
    file.seekToEndOfFile(); file.write(Data((event + "\n").utf8)); file.closeFile()
}

final class InstallHost: NSObject, NSApplicationDelegate {
    let model = UpdateModel()
    var requested = false
    var timer: Timer?

    func applicationDidFinishLaunching(_ notification: Notification) {
        record("launched \(Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion")!) pid=\(getpid())")
        if model.currentVersion == "2.0.0" {
            precondition(UserDefaults.standard.string(forKey: "TestRoute") == "socks")
            precondition(UserDefaults.standard.bool(forKey: "TestEnabled"))
            record("relaunched 2.0.0 preferences-preserved")
            NSApp.terminate(nil); return
        }
        UserDefaults.standard.set("socks", forKey: "TestRoute")
        UserDefaults.standard.set(true, forKey: "TestEnabled")
        model.prepareRelaunch = { completion in
            record("prepare")
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.1) { completion(); completion() }
        }
        model.onAbort = { record("abort") }
        model.start(preview: false)
        timer = Timer.scheduledTimer(withTimeInterval: 0.05, repeats: true) { [self] _ in
            if model.checkTitle == "Повторить проверку" { record("worker-unavailable"); NSApp.terminate(nil); return }
            if model.canCheck && !requested {
                requested = true; record("check"); model.check()
            } else if requested && model.canCheck && !model.sessionInProgress {
                // The driver has finished a declined/failed update. Exit only
                // after state has propagated back through the real channel.
                record("idle"); NSApp.terminate(nil)
            }
        }
        let timeout = Bundle.main.object(forInfoDictionaryKey: "TestMode") as? String == "native" ? 180.0 : 40.0
        DispatchQueue.main.asyncAfter(deadline: .now() + timeout) { record("timeout"); NSApp.terminate(nil) }
    }

    func applicationWillTerminate(_ notification: Notification) { record("terminated") }
}

@main enum Frontend {
    static func main() {
        guard Bundle.main.bundleIdentifier?.hasPrefix("kz.documentolog.proxypilot.workercheck.") == true else { exit(64) }
        var own: SecCode?
        guard SecCodeCopySelf([], &own) == errSecSuccess, let own = own,
              SecCodeCheckValidity(own, [], nil) == errSecSuccess else { exit(77) }
        var dictionary: CFDictionary?
        guard SecCodeCopySigningInformation(unsafeBitCast(own, to: SecStaticCode.self), SecCSFlags(rawValue: kSecCSDynamicInformation), &dictionary) == errSecSuccess,
              let info = dictionary as? [String: Any], let flags = info[kSecCodeInfoFlags as String] as? NSNumber,
              let status = info[kSecCodeInfoStatus as String] as? NSNumber else { exit(77) }
        let required = SecCodeSignatureFlags.runtime.rawValue | SecCodeSignatureFlags.forceHard.rawValue | SecCodeSignatureFlags.forceKill.rawValue
        precondition(flags.uint32Value & required == required && info[kSecCodeInfoEntitlementsDict as String] == nil)
        precondition(status.uint32Value & SecCodeStatus.debugged.rawValue == 0)
        let app = NSApplication.shared
        let delegate = InstallHost()
        app.delegate = delegate
        app.setActivationPolicy(.accessory)
        withExtendedLifetime(delegate) { app.run() }
    }
}
