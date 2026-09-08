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
    let proxy = ProxyModel(preview: false) // This fixture links only the inert CLI.
    var requested = false
    var timer: Timer?

    func applicationDidFinishLaunching(_ notification: Notification) {
        record("launched \(Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion")!) pid=\(getpid())")
        let initial = Bundle.main.object(forInfoDictionaryKey: "TestInitialVersion") as? String ?? "1.0.0"
        let final = Bundle.main.object(forInfoDictionaryKey: "TestFinalVersion") as? String ?? "2.0.0"
        if model.currentVersion != initial {
            precondition(UserDefaults.standard.string(forKey: "TestRoute") == "socks")
            precondition(UserDefaults.standard.bool(forKey: "TestEnabled"))
            precondition(UserDefaults.standard.object(forKey: "SUEnableAutomaticChecks") as? Bool == false)
            record("relaunched \(model.currentVersion) preferences-preserved")
            if model.currentVersion == final { NSApp.terminate(nil); return }
        } else {
            UserDefaults.standard.set("socks", forKey: "TestRoute")
            UserDefaults.standard.set(true, forKey: "TestEnabled")
            UserDefaults.standard.set(false, forKey: "SUEnableAutomaticChecks")
        }
        proxy.state = CLI.state(); proxy.loading = false
        model.prepareRelaunch = { [self] completion in
            record("prepare")
            let finished = CLI.finishedRoutes
            proxy.selectRoute("socks")
            proxy.prepareForUpdate {
                precondition(CLI.finishedRoutes == finished + 1, "Relaunch raced an in-flight command")
                precondition(proxy.busy && proxy.state?.enabled == true && proxy.state?.selected == "socks")
                precondition(proxy.state?.socks_endpoint == "192.0.2.47:1080" && proxy.state?.http_endpoint == "192.0.2.48:3128")
                record("commands-drained state-preserved")
                completion()
                #if !LEGACY_UPDATER_TESTING
                completion() // The isolated model must suppress duplicate completion.
                #endif
            }
        }
        model.onAbort = { [self] in proxy.cancelUpdatePreparation(); record("abort") }
        model.start(preview: false)
        timer = Timer.scheduledTimer(withTimeInterval: 0.05, repeats: true) { [self] _ in
            if model.checkTitle == "Повторить проверку" { record("worker-unavailable"); NSApp.terminate(nil); return }
            if model.canCheck && !requested {
                precondition(!model.automaticChecks, "Update migration reset automatic checks")
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
        #if LEGACY_UPDATER_TESTING
        // Match the released in-process updater's ad-hoc signing model; this
        // binary is only installed as the initial disposable 1.5.1 fixture.
        precondition(Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String == "1.5.1")
        precondition(flags.uint32Value & required == 0 && info[kSecCodeInfoEntitlementsDict as String] == nil)
        #else
        precondition(flags.uint32Value & required == required && info[kSecCodeInfoEntitlementsDict as String] == nil)
        #endif
        precondition(status.uint32Value & SecCodeStatus.debugged.rawValue == 0)
        let app = NSApplication.shared
        let delegate = InstallHost()
        app.delegate = delegate
        app.setActivationPolicy(.accessory)
        withExtendedLifetime(delegate) { app.run() }
    }
}
