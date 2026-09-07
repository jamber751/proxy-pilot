import Darwin

// Inert service fixture started by launchd in the user's own domain: it binds
// the socket path it is given, answers the readiness challenge and keeps
// listening. No root, no profile, no routes, no DNS, no VPN operation at all.
// The production helper will own this role; this only exercises the adapter.
@main
enum VPNLaunchdServer {
    static func main() {
        let args = CommandLine.arguments
        guard args.count == 3, args[1] == "serve", geteuid() != 0 else { exit(64) }
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        let bytes = Array(args[2].utf8) + [0]
        guard bytes.count <= MemoryLayout.size(ofValue: address.sun_path) else { exit(64) }
        withUnsafeMutableBytes(of: &address.sun_path) { $0.copyBytes(from: bytes) }
        let listener = socket(AF_UNIX, SOCK_STREAM, 0)
        guard listener >= 0 else { exit(70) }
        // Never unlink here: the adapter owns removal after a confirmed stop, so
        // a stale socket must fail loudly instead of stealing a live endpoint.
        let bound = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(listener, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard bound == 0, listen(listener, 4) == 0 else { exit(70) }
        while true {
            let client = accept(listener, nil, nil)
            guard client >= 0 else { continue }
            answer(client)
            close(client)
        }
    }

    static func answer(_ client: Int32) {
        var enabled: Int32 = 1
        _ = setsockopt(client, SOL_SOCKET, SO_NOSIGPIPE, &enabled, 4)
        var request = [UInt8](repeating: 0, count: 56), offset = 0
        while offset < request.count {
            let count = request.withUnsafeMutableBytes { read(client, $0.baseAddress!.advanced(by: offset), 56 - offset) }
            guard count > 0 else { return }
            offset += count
        }
        guard Array(request.prefix(8)) == Array("PPVNRQ01".utf8) else { return }
        let reply = Array("PPVNOK01".utf8) + request.dropFirst(8)
        _ = reply.withUnsafeBytes { write(client, $0.baseAddress, $0.count) }
        var byte: UInt8 = 0
        _ = read(client, &byte, 1) // stay alive for the caller's final signature check
    }
}
