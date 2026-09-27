import CryptoKit
import Darwin
import Dispatch
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

    /// Fixture-only trusted authority, matching what the helper fixture seeds.
    static func fixtureRelease(pin: String) throws -> VerifiedVPNRelease {
        #if VPN_PREVIOUS_CLIENT
        let fixtureVersion = "1.6.1"
        #else
        let fixtureVersion = "1.6.0"
        #endif
        let payload = Data(([
            "format=1", "product=kz.documentolog.proxypilot", "sequence=10", "version=\(fixtureVersion)", "protocol=1",
            "app-arm64=\(String(repeating: "11", count: 20))", "app-x86_64=\(String(repeating: "22", count: 20))",
            "helper-arm64=\(pin)", "helper-x86_64=\(pin)",
            "helper-sha256=\(String(repeating: "55", count: 32))", "helper-bytes=1", ""
        ].joined(separator: "\n")).utf8)
        let key = Curve25519.Signing.PrivateKey()
        let authority = try VPNReleaseAuthority(trustedPublicKey: key.publicKey.rawRepresentation,
                                                minimumSequence: 1, supportedProtocol: 1)
        return try authority.verify(payload: payload,
            signature: key.signature(for: VPNReleaseAuthority.signatureDomain + payload), previous: nil)
    }

    #if VPN_HELPER_READINESS_TESTING
    /// Exercises the typed request protocol, including frames a well-behaved
    /// client would never send. Nothing here is production code.
    static func session(_ path: String, pin: String, timeout: Int, scenario: String) {
        let fd = connect(path)
        do {
            let release = try fixtureRelease(pin: pin)
            if scenario.hasPrefix("profile=") {
                let path = String(scenario.dropFirst("profile=".count))
                let bytes = [UInt8](try Data(contentsOf: URL(fileURLWithPath: path)))
                let session = try VPNHelperSession.testOpen(takingSocket: fd, release: release,
                                                            timeoutMilliseconds: timeout)
                do {
                    let (status, body) = try session.request(.storeProfile, payload: bytes)
                    print("answer:\(status.rawValue) body:\(body.count)")
                } catch { print("request:\(error)") }
                return
            }
            if ["status", "twice", "limit"].contains(scenario) {
                let session = try VPNHelperSession.testOpen(takingSocket: fd, release: release,
                                                            timeoutMilliseconds: timeout)
                let count = scenario == "status" ? 1 : (scenario == "twice" ? 2 : 9)
                for index in 1...count {
                    do {
                        let (status, body) = try session.request(.status)
                        guard status == .ok, body.count == 16 else { print("answer:\(status)"); continue }
                        print("answer:ok sequence:\(VPNHelperProtocol.number(body[0..<8]))"
                              + " protocol:\(VPNHelperProtocol.number(body[8..<16]))")
                    } catch { print("request\(index):\(error)"); break }
                }
                return
            }
            _ = try VPNHelperReadiness.exchange(onSocket: fd, release: release,
                                                policy: release.testHelperPolicy(), timeoutMilliseconds: timeout)
            let deadline = DispatchTime.now().uptimeNanoseconds + UInt64(timeout) * 1_000_000
            if scenario == "flood" {
                // Ignores the client-side budget on purpose: the helper's own
                // limit is what must end the conversation.
                var answered = 0
                for _ in 0..<(VPNHelperProtocol.maximumRequestsPerConnection + 1) {
                    let request = VPNHelperProtocol.request(.status, revision: 10, payload: [])
                    do { try VPNHelperProtocol.write(request, socket: fd, deadline: deadline) }
                    catch { break }
                    guard let header = (try? VPNHelperProtocol.read(count: 14, socket: fd, deadline: deadline,
                                                                    allowingClose: true)) ?? nil else { break }
                    // Drain the body too, or its bytes would look like the next answer.
                    let length = Int(VPNHelperProtocol.number(header[10..<14]))
                    if length > 0, (try? VPNHelperProtocol.read(count: length, socket: fd, deadline: deadline)) == nil { break }
                    answered += 1
                }
                print("answered:\(answered)")
                close(fd)
                return
            }
            var frame: [UInt8]
            switch scenario {
            case "unknown":
                frame = VPNHelperProtocol.requestMagic + VPNHelperProtocol.encode(UInt16(4242))
                    + VPNHelperProtocol.encode(UInt64(10)) + VPNHelperProtocol.encode(UInt32(0))
            case "revision":
                frame = VPNHelperProtocol.requestMagic + VPNHelperProtocol.encode(UInt16(1))
                    + VPNHelperProtocol.encode(UInt64(99)) + VPNHelperProtocol.encode(UInt32(0))
            case "payload":
                frame = VPNHelperProtocol.request(.status, revision: 10, payload: [1, 2, 3])
            case "oversize":
                frame = VPNHelperProtocol.requestMagic + VPNHelperProtocol.encode(UInt16(1))
                    + VPNHelperProtocol.encode(UInt64(10)) + VPNHelperProtocol.encode(UInt32(VPNHelperProtocol.maximumPayloadBytes + 1))
            default:
                frame = Array("GARBAGE!".utf8) + [UInt8](repeating: 0, count: 14)
            }
            try VPNHelperProtocol.write(frame, socket: fd, deadline: deadline)
            if let header = try VPNHelperProtocol.read(count: 14, socket: fd, deadline: deadline, allowingClose: true) {
                print("answer:\(VPNHelperProtocol.number(header[8..<10]))")
            } else {
                print("answer:closed")
            }
        } catch { print("rejected:\(error)") }
        close(fd)
    }
    #endif

    static func main() {
        let args = CommandLine.arguments
        guard args.count >= 4 else { exit(64) }
        if args[1] == "serve" { serve(args[2], mode: args[3]); return }
        #if VPN_HELPER_READINESS_TESTING
        if args[1] == "session" {
            guard args.count == 6, let timeout = Int(args[4]) else { exit(64) }
            session(args[2], pin: args[3], timeout: timeout, scenario: args[5])
            return
        }
        #endif
        guard args.count == 5, let timeout = Int(args[4]) else { exit(64) }
        let fd = connect(args[2])
        do {
            // Fixture-only self-contained trusted authority. Pins supplied by
            // this harness MUST NOT become production trust provisioning.
            let release = try fixtureRelease(pin: args[3])
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
