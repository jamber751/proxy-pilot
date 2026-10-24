// Disposable VM experiment only. Public persistent resolver-file syntax:
// https://github.com/apple-oss-distributions/libresolv/blob/main/resolver.5
// https://github.com/apple-oss-distributions/configd/blob/main/dnsinfo/dnsinfo_flatfile.c
// Directory monitoring: Plugins/IPMonitor/dns-configuration.c in the same Apple repository.
// A suffix binding is not exact-host isolation or a no-fallback guarantee.
import Darwin
import Foundation

private enum Failure: String, Error {
    case guardDenied, arguments, directory, create, write, resolve, answer, unexpected
}
private func allowed(_ uid: uid_t, _ euid: uid_t, _ env: [String: String]) -> Bool {
    uid == 0 && euid == 0 && env["GITHUB_ACTIONS"] == "true"
        && env["PROXYPILOT_VM_DNS_FILE_RESOLVER_TESTS"] == "1"
}
private func validID(_ value: String) -> Bool {
    UUID(uuidString: value)?.uuidString.lowercased() == value
}
private func contents(_ port: UInt16) -> Data {
    Data("nameserver 127.0.0.1\nport \(port)\ntimeout 2\n".utf8)
}
private func check(_ condition: @autoclosure () -> Bool, _ error: Failure) throws {
    if !condition() { throw error }
}
private func writer(_ id: String, _ port: UInt16) throws {
    let directory = open("/private/etc/resolver", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
    try check(directory >= 0, .directory)
    defer { close(directory) }
    var info = stat()
    try check(fstat(directory, &info) == 0 && info.st_uid == 0
              && info.st_mode & S_IFMT == S_IFDIR && info.st_mode & 0o022 == 0, .directory)
    let name = "pp-file-" + id + ".test"
    var fd = openat(directory, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
    try check(fd >= 0, .create)
    var published = false
    defer {
        // Ordinary error cleanup owns only the exact newly-created inode.
        // Published files deliberately survive writer exit/SIGKILL.
        if !published {
            var own = stat(), current = stat()
            if fstat(fd, &own) == 0 && fstatat(directory, name, &current, AT_SYMLINK_NOFOLLOW) == 0
                && own.st_dev == current.st_dev && own.st_ino == current.st_ino {
                _ = unlinkat(directory, name, 0)
            }
        }
        if fd >= 0 { close(fd) }
    }
    let bytes = contents(port)
    try bytes.withUnsafeBytes { raw in
        var offset = 0
        while offset < raw.count {
            let count = Darwin.write(fd, raw.baseAddress!.advanced(by: offset), raw.count - offset)
            if count < 0 && errno == EINTR { continue }
            try check(count > 0, .write)
            offset += count
        }
    }
    try check(fsync(fd) == 0 && fsync(directory) == 0, .write)
    print("READY owned-file"); fflush(stdout)
    var byte: UInt8 = 0
    // Leave an unacknowledged publication owned by this writer's error/EOF
    // cleanup. The parent acknowledges only after capturing the exact inode.
    let count = Darwin.read(STDIN_FILENO, &byte, 1)
    if count == 0 { return }
    try check(count == 1 && byte == 71, .write)
    published = true
    close(fd); fd = -1
    print("READY persistent"); fflush(stdout)
    // The parent keeps this pipe open until killing this exact child.
    while Darwin.read(STDIN_FILENO, &byte, 1) > 0 {}
}
private func resolve(_ id: String, _ label: String, _ family: Int32, _ negative: Bool) throws {
    var hints = addrinfo()
    hints.ai_family = family
    hints.ai_socktype = SOCK_STREAM
    var result: UnsafeMutablePointer<addrinfo>?
    // Absolute unique names; no AI_ADDRCONFIG and no connection to answers.
    let status = getaddrinfo(label + ".pp-file-" + id + ".test.", nil, &hints, &result)
    defer { if let result { freeaddrinfo(result) } }
    if negative {
        try check(status != 0 && result == nil, .resolve)
        print("PASS negative"); return
    }
    try check(status == 0 && result != nil, .resolve)
    var answers = Set<String>(), cursor = result
    while let item = cursor {
        var text = [CChar](repeating: 0, count: Int(NI_MAXHOST))
        try check(getnameinfo(item.pointee.ai_addr, item.pointee.ai_addrlen,
                             &text, socklen_t(text.count), nil, 0, NI_NUMERICHOST) == 0, .answer)
        answers.insert(String(cString: text))
        cursor = item.pointee.ai_next
    }
    try check(answers == [family == AF_INET ? "192.0.2.53" : "2001:db8::53"], .answer)
    print("PASS answer")
}
private func pure() throws {
    let env = ["GITHUB_ACTIONS":"true", "PROXYPILOT_VM_DNS_FILE_RESOLVER_TESTS":"1"]
    try check(allowed(0, 0, env), .unexpected)
    for ids: (uid_t, uid_t) in [(501,501), (501,0), (0,501)] {
        try check(!allowed(ids.0, ids.1, env), .unexpected)
    }
    for missing in [[:], ["GITHUB_ACTIONS":"true"], ["PROXYPILOT_VM_DNS_FILE_RESOLVER_TESTS":"1"]] {
        try check(!allowed(0, 0, missing), .unexpected)
    }
    try check(validID("12345678-1234-1234-1234-123456789abc"), .unexpected)
    for bad in ["", "../other", "12345678-1234-1234-1234-123456789ABC"] {
        try check(!validID(bad), .unexpected)
    }
    try check(contents(12345) == Data("nameserver 127.0.0.1\nport 12345\ntimeout 2\n".utf8), .unexpected)
    print("PASS pure-guards")
}
@main private struct Main {
    static func main() {
        do {
            let args = Array(CommandLine.arguments.dropFirst())
            if args == ["--pure-checks"] { try pure(); return }
            // Before any file open/mutation or network-emitting resolver API.
            try check(allowed(getuid(), geteuid(), ProcessInfo.processInfo.environment), .guardDenied)
            if args.count == 3 && args[0] == "--writer", validID(args[1]),
               let port = UInt16(args[2]), port > 0 {
                try writer(args[1], port)
            } else if args.count == 4 && args[0] == "--resolve", validID(args[1]),
                      ["before-udp", "before-tcp", "after-udp", "after-tcp", "closed4", "closed6"].contains(args[2]),
                      ["4", "6"].contains(args[3]) {
                try resolve(args[1], args[2], args[3] == "4" ? AF_INET : AF_INET6, args[2].hasPrefix("closed"))
            } else { throw Failure.arguments }
        } catch {
            print("FAIL " + ((error as? Failure)?.rawValue ?? "unexpected")); exit(1)
        }
    }
}
