import CryptoKit
import Darwin
import Foundation

@main enum VPNRecoveryProbe {
    static func main() throws {
        let arguments = CommandLine.arguments
        guard arguments.count == 3 else { exit(64) }
        let socket = Darwin.socket(AF_UNIX, SOCK_STREAM, 0)
        guard socket >= 0 else { exit(77) }
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        let endpoint = Array(arguments[1].utf8) + [0]
        guard endpoint.count <= MemoryLayout.size(ofValue: address.sun_path) else { exit(64) }
        withUnsafeMutableBytes(of: &address.sun_path) { $0.copyBytes(from: endpoint) }
        let connected = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.connect(socket, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard connected == 0 else { close(socket); exit(77) }
        guard arguments[2].utf8.count == 40 else { close(socket); exit(64) }
        let payload = Data(([
            "format=1", "product=kz.documentolog.proxypilot", "sequence=11",
            "version=1.7.0", "protocol=1",
            "app-arm64=\(String(repeating: "11", count: 20))",
            "app-x86_64=\(String(repeating: "22", count: 20))",
            "helper-arm64=\(arguments[2])", "helper-x86_64=\(arguments[2])",
            "helper-sha256=\(String(repeating: "55", count: 32))", "helper-bytes=1", ""
        ].joined(separator: "\n")).utf8)
        let key = Curve25519.Signing.PrivateKey()
        let authority = try VPNReleaseAuthority(
            trustedPublicKey: key.publicKey.rawRepresentation,
            minimumSequence: 1, supportedProtocol: 1)
        let release = try authority.verify(
            payload: payload,
            signature: key.signature(for: VPNReleaseAuthority.signatureDomain + payload),
            previous: nil)
        do {
            let ready = try VPNHelperReadiness.testProbe(
                takingSocket: socket, release: release, timeoutMilliseconds: 2000)
            print("ready:\(ready.release.sequence)")
        } catch {
            print("rejected:\(error)")
            exit(77)
        }
    }
}
