import Foundation
import Security

// Disposable proof only. No Sparkle link, IPC server, VPN or installation.
@main
enum Frontend {
    static func main() throws {
        guard CommandLine.arguments.count == 1,
              Bundle.main.bundleIdentifier?.hasPrefix("kz.documentolog.proxypilot.isolationtest.") == true else { exit(64) }
        var ownCode: SecCode?
        guard SecCodeCopySelf([], &ownCode) == errSecSuccess, let ownCode = ownCode,
              SecCodeCheckValidity(ownCode, [], nil) == errSecSuccess else { exit(77) }
        var information: CFDictionary?
        let reference = unsafeBitCast(ownCode, to: SecStaticCode.self)
        guard SecCodeCopySigningInformation(reference, SecCSFlags(rawValue: kSecCSDynamicInformation), &information) == errSecSuccess,
              let info = information as? [String: Any],
              let flags = info[kSecCodeInfoFlags as String] as? NSNumber,
              let status = info[kSecCodeInfoStatus as String] as? NSNumber else { exit(77) }
        let requiredFlags = SecCodeSignatureFlags.runtime.rawValue | SecCodeSignatureFlags.forceHard.rawValue | SecCodeSignatureFlags.forceKill.rawValue
        let requiredStatus = SecCodeStatus.valid.rawValue | SecCodeStatus.hard.rawValue | SecCodeStatus.kill.rawValue
        guard flags.uint32Value & requiredFlags == requiredFlags,
              status.uint32Value & requiredStatus == requiredStatus,
              status.uint32Value & SecCodeStatus.debugged.rawValue == 0,
              info[kSecCodeInfoEntitlementsDict as String] == nil else { exit(77) }
        let worker = Bundle.main.bundleURL.appendingPathComponent("Contents/Helpers/Update Probe.app/Contents/MacOS/UpdateProbe")
        let process = Process()
        let output = Pipe()
        process.executableURL = worker
        process.arguments = []
        process.standardOutput = output
        // Do not forward arbitrary DYLD, proxy, feed or configuration variables.
        process.environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin"]
        try process.run()
        output.fileHandleForWriting.closeFile()
        // The trusted fixture emits one fixed result. A production worker needs
        // bounded asynchronous framing/cancellation, not this blocking proof.
        let data = output.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        guard data.count < 256, process.terminationReason == .exit else { exit(70) }
        print("FRONTEND_HARDENED")
        FileHandle.standardOutput.write(data)
        exit(process.terminationStatus)
    }
}
