import AppKit
import Security

// Test-only driver for the complete production App/ProxyModel/PilotView.
// No UI choices or lifecycle hooks are added to the shipping application.
func record(_ event: String) {
    let directory = Bundle.main.object(forInfoDictionaryKey: "TestDirectory") as! String
    let url = URL(fileURLWithPath: directory).appendingPathComponent("host.events")
    if !FileManager.default.fileExists(atPath: url.path) { FileManager.default.createFile(atPath: url.path, contents: nil) }
    let file = try! FileHandle(forWritingTo: url)
    file.seekToEndOfFile(); file.write(Data((event + "\n").utf8)); file.closeFile()
}

func validateFullAppFixture() {
    precondition(geteuid() != 0 && getuid() == geteuid())
    precondition(Bundle.main.bundleIdentifier?.hasPrefix("kz.documentolog.proxypilot.workercheck.") == true)
    var own: SecCode?, dictionary: CFDictionary?
    precondition(SecCodeCopySelf([], &own) == errSecSuccess)
    precondition(SecCodeCheckValidity(own!, [], nil) == errSecSuccess)
    precondition(SecCodeCopySigningInformation(unsafeBitCast(own!, to: SecStaticCode.self), SecCSFlags(rawValue: kSecCSDynamicInformation), &dictionary) == errSecSuccess)
    let info = dictionary as! [String: Any]
    let flags = (info[kSecCodeInfoFlags as String] as! NSNumber).uint32Value
    let required = SecCodeSignatureFlags.runtime.rawValue | SecCodeSignatureFlags.forceHard.rawValue | SecCodeSignatureFlags.forceKill.rawValue
    precondition(flags & required == required && info[kSecCodeInfoEntitlementsDict as String] == nil)
    precondition((info[kSecCodeInfoStatus as String] as! NSNumber).uint32Value & SecCodeStatus.debugged.rawValue == 0)
}

final class FullAppLifecycle {
    private var timer: Timer?
    private var requested = false
    private var routed = false
    private var closed = false
    private var verifiedAt: Date?

    init(model: ProxyModel, updates: UpdateModel, popover: NSPopover) {
        let version = updates.currentVersion
        let mode = Bundle.main.object(forInfoDictionaryKey: "TestMode") as! String
        let initialState = Bundle.main.object(forInfoDictionaryKey: "TestInitialState") as! String
        let enabled = initialState == "on"
        let running = enabled ? "socks" : initialState == "off-running" ? "direct" : "none"
        record("launched \(version) pid=\(getpid())")
        timer = Timer.scheduledTimer(withTimeInterval: 0.05, repeats: true) { [self] _ in
            if updates.checkTitle == "Повторить проверку" { record("worker-unavailable"); NSApp.terminate(nil); return }
            if requested && !popover.isShown && !closed { closed = true; record("popover-closed") }
            guard !model.loading && !model.busy, let state = model.state else { return }
            precondition(state.socks_endpoint == Bundle.main.object(forInfoDictionaryKey: "TestSOCKS") as? String)
            precondition(state.http_endpoint == Bundle.main.object(forInfoDictionaryKey: "TestHTTP") as? String)
            precondition(model.error.isEmpty, model.error)
            if routed {
                guard state.selected == "http" && state.running == "http" else { return }
                guard closed else { return } // NSPopover closes with an animation.
                precondition(state.enabled && state.system_proxy)
                record("controls-restored"); record("idle"); NSApp.terminate(nil); return
            }
            precondition(state.enabled == enabled && state.system_proxy == enabled && state.selected == "socks")
            guard state.running == running else { return }
            if version == "2.0.0" {
                // Let the real five-second App timer refresh again. The new
                // CLI must replace an old engine only once, not on every poll.
                if verifiedAt == nil { verifiedAt = Date(); record("new-state-ready") }
                if Date().timeIntervalSince(verifiedAt!) >= 6 {
                    record("relaunched 2.0.0 preferences-preserved"); NSApp.terminate(nil)
                }
                return
            }
            if mode == "quit" && !requested {
                requested = true; record("idle"); model.quit(); return
            }
            if !requested && updates.canCheck {
                guard popover.isShown else { return }
                record("launch-ready"); requested = true; updates.check()
            } else if requested && updates.canCheck && !updates.sessionInProgress {
                precondition(mode == "cancel-offer")
                routed = true; model.selectRoute("http")
            }
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + 45) { record("timeout"); NSApp.terminate(nil) }
    }
}
