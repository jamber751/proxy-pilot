// Synthetic installed child only. No system service or network is touched.
import CryptoKit
import Darwin
import Dispatch
import Foundation

@main enum VPNInstalledUpdateResultChecks {
    static func main() throws {
        let a = CommandLine.arguments
        if a.count == 2, a[1] == "guards" {
            precondition(VPNInstalledUpdateResultEntry.runIfRequested(arguments: ["app", VPNInstalledUpdateResultEntry.argument]) == 77)
            precondition(VPNInstalledUpdateResultEntry.runIfRequested(arguments: ["app", VPNInstalledUpdateResultEntry.argument, "extra"]) == 64)
            do { try VPNLaunchdRuntime.requireSystemStopped(deadline: DispatchTime.now().uptimeNanoseconds + 1_000_000_000); exit(66) }
            catch VPNLaunchdError.requiresRoot {}
            print("guarded"); return
        }
        guard a.count == 8 else { exit(64) }
        let key = try Curve25519.Signing.PrivateKey(rawRepresentation: Data(repeating: 0x42, count: 32))
        let helper = Data("inert helper".utf8)
        let sha = SHA256.hash(data: helper).map { String(format: "%02x", $0) }.joined()
        let payload = Data("""
        format=1
        product=kz.documentolog.proxypilot
        sequence=141
        version=1.7.0
        protocol=1
        app-arm64=\(a[3])
        app-x86_64=\(a[4])
        helper-arm64=\(String(repeating: "33", count: 20))
        helper-x86_64=\(String(repeating: "44", count: 20))
        helper-sha256=\(sha)
        helper-bytes=\(helper.count)

        """.utf8)
        let authority = try VPNReleaseAuthority(trustedPublicKey: key.publicKey.rawRepresentation,
            minimumSequence: 1, supportedProtocol: 1)
        let release = try authority.verify(payload: payload,
            signature: key.signature(for: VPNReleaseAuthority.signatureDomain + payload), previous: nil)
        let apps = open(a[2], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard apps >= 0 else { exit(65) }
        defer { close(apps) }
        do {
            let installed = try VPNInstalledApplication.testInspect(inApplicationsDirectory: apps, release: release)
            var checks = 0
            let outcome = try VPNRescueInstalledResultVerifier.testObserve(installed: installed, release: release,
                desired: a[5] == "on", failures: Int(a[6])!,
                deadline: DispatchTime.now().uptimeNanoseconds + UInt64(a[7])! * 1_000_000,
                validate: {
                    checks += 1
                    if checks == 2, a[1] == "deny-before-resume" { throw VPNInstalledUpdateResultError.changed }
                    if checks == 2, a[1] == "mutate-before-resume" {
                        try Data("tampered".utf8).write(to: URL(fileURLWithPath: a[2] + "/ProxyPilot.app/Contents/Resources/data.txt"))
                    }
                })
            print("\(outcome)")
        } catch { print("rejected:\(error)"); exit(77) }
    }
}
