import Darwin
import Foundation
import CryptoKit

// Test-only local socket client/verifier. No root, service registration, profile
// input, shell commands or network configuration. Python owns socket lifetime.
@main
enum VPNPeerChecks {
    static func main() {
        do {
            let args = CommandLine.arguments
            guard args.count >= 2 else { exit(64) }
            if args[1] == "client", args.count == 3 {
                let socket = Darwin.socket(AF_UNIX, SOCK_STREAM, 0)
                guard socket >= 0 else { exit(70) }
                defer { close(socket) }
                var address = sockaddr_un()
                address.sun_family = sa_family_t(AF_UNIX)
                address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
                let bytes = Array(args[2].utf8) + [0]
                guard bytes.count <= MemoryLayout.size(ofValue: address.sun_path) else { exit(64) }
                withUnsafeMutableBytes(of: &address.sun_path) { $0.copyBytes(from: bytes) }
                let result = withUnsafePointer(to: &address) {
                    $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                        connect(socket, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
                    }
                }
                guard result == 0 else { exit(69) }
                var byte: UInt8 = 1
                guard write(socket, &byte, 1) == 1 else { exit(70) }
                // Wait for the harness to complete authentication before exiting.
                _ = read(socket, &byte, 1)
                return
            }
            guard ["verify", "verify-release", "verify-installer"].contains(args[1]), args.count == 6,
                  let socket = Int32(args[2]), let userID = uid_t(args[3]) else { exit(64) }
            let hashes: Set<Data> = Set(args[5].split(separator: ",").map { hex in
                var bytes = Data()
                var index = hex.startIndex
                while index < hex.endIndex {
                    let end = hex.index(index, offsetBy: 2, limitedBy: hex.endIndex) ?? hex.endIndex
                    guard hex.distance(from: index, to: end) == 2,
                          let byte = UInt8(hex[index..<end], radix: 16) else { return Data() }
                    bytes.append(byte)
                    index = end
                }
                return bytes
            })
            let policy: VPNPeerPolicy
            if args[1] == "verify-release" {
                // TEST ONLY: ephemeral authority and caller-supplied fixture
                // pins. This CLI is not a production source of trusted policy.
                guard hashes.count == 1, let pin = hashes.first, pin.count == 20 else { exit(64) }
                let hex = pin.map { String(format: "%02x", $0) }.joined()
                let payload = Data(([
                    "format=1", "product=kz.documentolog.proxypilot", "sequence=1", "version=1.6.0", "protocol=1",
                    "app-arm64=\(hex)", "app-x86_64=\(hex)",
                    "helper-arm64=\(String(repeating: "33", count: 20))",
                    "helper-x86_64=\(String(repeating: "44", count: 20))",
                    "helper-sha256=\(String(repeating: "55", count: 32))", "helper-bytes=1", ""
                ].joined(separator: "\n")).utf8)
                let key = Curve25519.Signing.PrivateKey()
                let signature = try key.signature(for: VPNReleaseAuthority.signatureDomain + payload)
                let authority = try VPNReleaseAuthority(trustedPublicKey: key.publicKey.rawRepresentation,
                                                        minimumSequence: 1, supportedProtocol: 1)
                let release = try authority.verify(payload: payload, signature: signature, previous: nil)
                policy = try release.clientPolicy(forTrustedUserID: userID)
            } else if args[1] == "verify-installer" {
                policy = try VPNPeerPolicy.installer(codeDirectoryHashes: hashes)
            } else {
                policy = try VPNPeerPolicy(userID: userID, signingIdentifier: args[4], codeDirectoryHashes: hashes)
            }
            try VPNPeerAuthentication.validate(connectedSocket: socket, policy: policy)
            print("allowed")
        } catch VPNPeerAuthenticationError.invalidPolicy {
            print("invalid-policy")
            exit(64)
        } catch {
            print("denied")
            exit(77)
        }
    }
}
