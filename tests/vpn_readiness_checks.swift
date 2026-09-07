import CryptoKit
import Darwin
import Foundation

// Inert local server and probe client; no launchd, root, VPN or real keys.
@main
enum VPNReadinessChecks {
    static func address(_ path: String) -> sockaddr_un {
        var result = sockaddr_un()
        result.sun_family = sa_family_t(AF_UNIX)
        result.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        let bytes = Array(path.utf8) + [0]
        guard bytes.count <= MemoryLayout.size(ofValue: result.sun_path) else { exit(64) }
        withUnsafeMutableBytes(of: &result.sun_path) { $0.copyBytes(from: bytes) }
        return result
    }

    static func connect(_ path: String) -> Int32 {
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        var endpoint = address(path)
        let result = withUnsafePointer(to: &endpoint) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard result == 0 else { close(fd); return -1 }
        return fd
    }

    static func serve(_ path: String, mode: String) {
        guard geteuid() != 0 else { exit(77) }
        let listener = socket(AF_UNIX, SOCK_STREAM, 0)
        defer { close(listener) }
        var endpoint = address(path)
        let result = withUnsafePointer(to: &endpoint) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(listener, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard result == 0, listen(listener, 1) == 0 else { exit(70) }
        print("listening"); fflush(stdout)
        let fd = accept(listener, nil, nil)
        guard fd >= 0 else { exit(70) }
        defer { close(fd) }
        var enabled: Int32 = 1
        _ = setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &enabled, 4)
        if mode == "silent" { sleep(5); return }
        var request = [UInt8](repeating: 0, count: 56), offset = 0
        while offset < request.count {
            let count = request.withUnsafeMutableBytes { read(fd, $0.baseAddress!.advanced(by: offset), 56 - offset) }
            guard count > 0 else { return }
            offset += count
        }
        if mode == "eof" { return }
        var reply = Array("PPVNOK01".utf8) + request.dropFirst(8)
        switch mode {
        case "magic": reply[0] ^= 1
        case "protocol": reply[15] ^= 1
        case "sequence": reply[23] ^= 1
        case "nonce": reply[24] ^= 1
        case "replay": reply.replaceSubrange(24..<56, with: repeatElement(UInt8(0), count: 32))
        case "short": reply = Array(reply.prefix(10))
        default: break
        }
        if mode == "fragmented" || mode == "trickle" {
            for var byte in reply {
                guard write(fd, &byte, 1) == 1 else { return }
                usleep(mode == "trickle" ? 50_000 : 1_000)
            }
        } else {
            _ = reply.withUnsafeBytes { write(fd, $0.baseAddress, $0.count) }
        }
        if mode == "short" || mode == "dead" { return }
        var byte: UInt8 = 0
        _ = read(fd, &byte, 1) // stay alive for the final dynamic signature check
    }

    static func main() {
        let args = CommandLine.arguments
        guard args.count >= 4 else { exit(64) }
        if args[1] == "serve" { serve(args[2], mode: args[3]); return }
        guard args.count == 5, let timeout = Int(args[4]) else { exit(64) }
        let fd = connect(args[2])
        do {
            // Fixture-only self-contained trusted authority. Pins supplied by
            // this harness MUST NOT become production trust provisioning.
            let payload = Data(([
                "format=1", "product=kz.documentolog.proxypilot", "sequence=10", "version=1.6.0", "protocol=1",
                "app-arm64=\(String(repeating: "11", count: 20))", "app-x86_64=\(String(repeating: "22", count: 20))",
                "helper-arm64=\(args[3])", "helper-x86_64=\(args[3])",
                "helper-sha256=\(String(repeating: "55", count: 32))", "helper-bytes=1", ""
            ].joined(separator: "\n")).utf8)
            let key = Curve25519.Signing.PrivateKey()
            let authority = try VPNReleaseAuthority(trustedPublicKey: key.publicKey.rawRepresentation,
                                                    minimumSequence: 1, supportedProtocol: 1)
            let release = try authority.verify(payload: payload,
                signature: key.signature(for: VPNReleaseAuthority.signatureDomain + payload), previous: nil)
            let ready: VPNHelperReady
            #if VPN_HELPER_READINESS_TESTING
            ready = try VPNHelperReadiness.testProbe(takingSocket: fd, release: release, timeoutMilliseconds: timeout)
            #else
            ready = try VPNHelperReadiness.probe(takingSocket: fd, release: release, timeoutMilliseconds: timeout)
            #endif
            guard fd >= 0, fcntl(fd, F_GETFD) == -1, errno == EBADF else { exit(70) }
            print("ready:\(ready.release.sequence) closed")
        } catch {
            guard fd < 0 || (fcntl(fd, F_GETFD) == -1 && errno == EBADF) else { exit(70) }
            print("rejected:\(error) closed")
            exit(77)
        }
    }
}
