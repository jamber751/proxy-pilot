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
    var attempts = 0
    var presentations = 0
    var backgroundObserved = false
    var testWindow: NSWindow?
    var updateButton: NSButton?

    @objc func showBackgroundUpdate() {
        guard backgroundObserved, model.canCheck, !requested else { return }
        requested = true; record("manual-background-check"); model.check()
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        let mode = Bundle.main.object(forInfoDictionaryKey: "TestMode") as! String
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
            UserDefaults.standard.set(mode == "native-background", forKey: "SUEnableAutomaticChecks")
            // The separate test worker must see the seed before Sparkle starts.
            UserDefaults.standard.synchronize()
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
        model.onPresent = { [self] in presentations += 1; record("present") }
        if mode == "native-background" {
            let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 440, height: 150), styleMask: [.titled], backing: .buffered, defer: false)
            window.title = "ProxyPilot Background TEST"
            let label = NSTextField(labelWithString: "Disposable update test — no proxy or VPN changes")
            label.frame = NSRect(x: 24, y: 98, width: 400, height: 24)
            let button = NSButton(title: "Waiting for background check…", target: self, action: #selector(showBackgroundUpdate))
            button.frame = NSRect(x: 24, y: 32, width: 390, height: 44); button.bezelStyle = .rounded; button.isEnabled = false
            window.contentView?.addSubview(label); window.contentView?.addSubview(button)
            testWindow = window; updateButton = button
            window.center(); window.makeKeyAndOrderFront(nil); NSApp.activate(ignoringOtherApps: true)
        }
        model.start(preview: false)
        timer = Timer.scheduledTimer(withTimeInterval: 0.05, repeats: true) { [self] _ in
            if model.checkTitle == "Повторить проверку" { record("worker-unavailable"); NSApp.terminate(nil); return }
            if mode == "native-background" && !requested {
                if model.availableVersion == "2.0.0" && model.canCheck && !backgroundObserved {
                    backgroundObserved = true
                    precondition(presentations == 0 && model.automaticChecks)
                    precondition(model.checkTitle == "Обновить до 2.0.0")
                    DispatchQueue.main.asyncAfter(deadline: .now() + 2) { [self] in
                        precondition(presentations == 0, "Background update requested presentation")
                        // Focus is observed in the worker for the whole phase,
                        // not inferred from whether macOS activated this host.
                        record("background-state badge=2.0.0 no-presentation")
                        updateButton?.title = "Show update 2.0.0"; updateButton?.isEnabled = true
                    }
                }
                return
            }
            if model.canCheck && !requested {
                precondition(!model.automaticChecks, "Update migration reset automatic checks")
                requested = true; attempts += 1; record("check"); model.check()
            } else if requested && model.canCheck && !model.sessionInProgress {
                if mode == "native-network" && attempts == 1 {
                    record("retry-enabled"); requested = false; return
                }
                // The driver has finished a declined/failed update. Exit only
                // after state has propagated back through the real channel.
                record("idle"); NSApp.terminate(nil)
            }
        }
        let timeout = mode.hasPrefix("native") ? 180.0 : 40.0
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
