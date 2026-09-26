import CryptoKit
import Darwin
import Foundation

@main enum VPNInstalledApplicationChecks {
    static func main() throws {
        let arguments = CommandLine.arguments
        guard arguments.count == 5 else { exit(64) }
        let operation = arguments[1]
        let key = try Curve25519.Signing.PrivateKey(rawRepresentation: Data(repeating: 0x42, count: 32))
        let authority = try VPNReleaseAuthority(trustedPublicKey: key.publicKey.rawRepresentation,
                                                minimumSequence: 1, supportedProtocol: 1)
        let helper = Data("inert helper".utf8)
        let sha = SHA256.hash(data: helper).map { String(format: "%02x", $0) }.joined()
        let payload = Data("""
        format=1
        product=kz.documentolog.proxypilot
        sequence=11
        version=1.7.0
        protocol=1
        app-arm64=\(arguments[3])
        app-x86_64=\(arguments[4])
        helper-arm64=\(String(repeating: "33", count: 20))
        helper-x86_64=\(String(repeating: "44", count: 20))
        helper-sha256=\(sha)
        helper-bytes=\(helper.count)

        """.utf8)
        let signature = try key.signature(for: VPNReleaseAuthority.signatureDomain + payload)
        let release = try authority.verify(payload: payload, signature: signature, previous: nil)
        do {
            if operation == "production" {
                _ = try VPNInstalledApplication.inspect(release: release)
            } else {
                let destination = open(arguments[2], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
                guard destination >= 0 else { exit(65) }
                defer { close(destination) }
                let installed = try VPNInstalledApplication.testInspect(
                    inApplicationsDirectory: destination, release: release)
                if operation == "mutate" {
                    try Data("changed".utf8).write(to: URL(fileURLWithPath:
                        arguments[2] + "/ProxyPilot.app/Contents/Resources/data.txt"))
                    try installed.revalidate()
                } else if operation == "replace" {
                    try FileManager.default.moveItem(
                        atPath: arguments[2] + "/ProxyPilot.app",
                        toPath: arguments[2] + "/Old.app")
                    try installed.revalidate()
                } else if operation == "self" {
                    try installed.validateProcess(getpid())
                } else {
                    print("path:\(try installed.path())")
                    return
                }
            }
            print("accepted")
        } catch {
            print("rejected:\(error)")
            exit(77)
        }
    }
}
