import AppKit
import Security

@main
enum FrontendChecks {
    static func main() throws {
        guard Bundle.main.bundleIdentifier?.hasPrefix("kz.documentolog.proxypilot.workercheck.") == true else { exit(64) }
        var own: SecCode?
        guard SecCodeCopySelf([], &own) == errSecSuccess, let own = own,
              SecCodeCheckValidity(own, [], nil) == errSecSuccess else { exit(77) }
        var information: CFDictionary?
        guard SecCodeCopySigningInformation(unsafeBitCast(own, to: SecStaticCode.self), SecCSFlags(rawValue: kSecCSDynamicInformation), &information) == errSecSuccess,
              let info = information as? [String: Any],
              let flags = info[kSecCodeInfoFlags as String] as? NSNumber,
              let status = info[kSecCodeInfoStatus as String] as? NSNumber else { exit(77) }
        let required = SecCodeSignatureFlags.runtime.rawValue | SecCodeSignatureFlags.forceHard.rawValue | SecCodeSignatureFlags.forceKill.rawValue
        precondition(flags.uint32Value & required == required)
        precondition(status.uint32Value & SecCodeStatus.debugged.rawValue == 0)
        precondition(info[kSecCodeInfoEntitlementsDict as String] == nil)
        let app = NSApplication.shared
        app.setActivationPolicy(.accessory)
        let model = UpdateModel()
        let mode = Bundle.main.object(forInfoDictionaryKey: "TestMode") as! String
        let expected = Bundle.main.object(forInfoDictionaryKey: "TestExpected") as! String
        var presentations = 0
        var requested = false
        var retried = false
        var changedPreference = false
        var preparations = 0
        var aborts = 0
        var completion: (() -> Void)?
        model.prepareRelaunch = { block in
            preparations += 1; completion = block
            if mode == "handoff-good" { block(); block() }
        }
        model.onAbort = {
            aborts += 1
            if mode == "handoff-abort" { completion?(); completion?() }
        }
        model.onPresent = {
            presentations += 1
            if presentations >= 3 && !mode.hasPrefix("handoff-") {
                precondition(requested && model.availableVersion == expected, "Wrong native result: \(model.availableVersion ?? "nil")")
                print("RESULT \(expected)"); exit(0)
            }
        }
        model.start(preview: mode == "preview")
        if mode == "preview" {
            model.check(); model.setAutomaticChecks(true)
            precondition(!model.canCheck && !model.sessionInProgress && presentations == 0)
            precondition(model.checkTitle == "Недоступно в превью")
            print("PREVIEW_DISABLED"); exit(0)
        }
        let timer = Timer.scheduledTimer(withTimeInterval: 0.02, repeats: true) { _ in
            guard model.canCheck else { return }
            if model.checkTitle == "Повторить проверку" {
                if mode == "failure" { print("RETRY_AVAILABLE"); exit(0) }
                if mode == "handoff-duplicate" || mode == "handoff-unsolicited" {
                    precondition(preparations == (mode == "handoff-duplicate" ? 1 : 0) && aborts == 1)
                    print("HANDOFF_REJECTED"); exit(0)
                }
                precondition(mode == "retry" && !retried)
                retried = true; requested = true; model.check()
                return
            }
            if mode.hasPrefix("handoff-"), model.availableVersion == expected {
                precondition(preparations == 1 && aborts == 1)
                print("HANDOFF \(expected)"); exit(0)
            }
            if mode == "preferences" {
                if !changedPreference {
                    precondition(model.automaticChecks == (expected == "false"), "Preference was not loaded from host")
                    changedPreference = true; model.setAutomaticChecks(expected == "true")
                } else if model.automaticChecks == (expected == "true") {
                    print("PREFERENCE \(expected)"); exit(0)
                }
                return
            }
            guard !requested else { return }
            requested = true; model.check()
            precondition(model.sessionInProgress && !model.canCheck)
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + 18) { print("TIMEOUT"); exit(3) }
        withExtendedLifetime((model, timer)) { app.run() }
    }
}
