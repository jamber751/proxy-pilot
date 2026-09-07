import Foundation
import Darwin

enum VPNImportError: Error, LocalizedError, Equatable {
    case oneFileRequired, invalidFile, tooLarge, malformed, unsupported, externalFilesRequired
    case missingServer, missingIdentity, missingServerVerification

    var errorDescription: String? {
        switch self {
        case .oneFileRequired: return "Добавьте один файл .ovpn."
        case .invalidFile: return "Выберите непустой файл OpenVPN (.ovpn), а не папку или ссылку."
        case .tooLarge: return "Файл VPN слишком большой. Максимальный размер — 1 МБ."
        case .malformed: return "Не удалось прочитать конфигурацию OpenVPN. Исходный файл не изменён."
        case .unsupported: return "В этом профиле есть неподдерживаемые настройки. Он не был импортирован."
        case .externalFilesRequired: return "Профилю нужны отдельные сертификаты или ключи. Попросите файл .ovpn со встроенными сертификатами."
        case .missingServer: return "В файле не указан сервер VPN."
        case .missingIdentity: return "В профиле не хватает сертификата, ключа или способа входа."
        case .missingServerVerification: return "В профиле не настроена проверка сертификата сервера."
        }
    }
}

/// A structurally inspected import candidate, NOT an executable configuration.
/// TLS validity, real corporate compatibility and helper approval are separate gates.
struct VPNImportedProfile: CustomStringConvertible, CustomDebugStringConvertible {
    let name: String
    let requiresCredentials: Bool
    let requiresKeyPassword: Bool
    let suggestedDNS: [String]
    let suggestedResources: [VPNResource]
    let hasIgnoredRoutes: Bool
    fileprivate let validatedData: Data
    var description: String { "VPNImportedProfile(contents: redacted)" }
    var debugDescription: String { description }

    // Kept internal: only the protected store should persist these bytes.
    var protectedContents: Data { validatedData }
}

enum VPNProfileImporter {
    static let maximumBytes = 1_048_576
    private static let blocks: Set<String> = ["ca", "cert", "key", "tls-auth", "tls-crypt", "tls-crypt-v2"]
    private static let transports: Set<String> = ["udp", "udp4", "udp6", "tcp-client", "tcp4-client", "tcp6-client"]
    // Explicit suites only: never pass OpenSSL expressions such as ALL,
    // @SECLEVEL=0, exclusions or arbitrary provider settings from a profile.
    private static let tlsCiphers: Set<String> = [
        "TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256", "TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384",
        "TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256", "TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384",
        "ECDHE-ECDSA-AES128-GCM-SHA256", "ECDHE-ECDSA-AES256-GCM-SHA384",
        "ECDHE-RSA-AES128-GCM-SHA256", "ECDHE-RSA-AES256-GCM-SHA384"
    ]

    /// Picker and drop delegates share this entry point. Never invokes OpenVPN,
    /// resolves DNS, follows file references, or modifies the supplied file.
    static func inspect(files: [URL]) throws -> VPNImportedProfile {
        guard files.count == 1 else { throw VPNImportError.oneFileRequired }
        let url = files[0]
        guard url.isFileURL, url.pathExtension.lowercased() == "ovpn" else { throw VPNImportError.invalidFile }
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }
        let descriptor = open(url.path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK)
        guard descriptor >= 0 else { throw VPNImportError.invalidFile }
        defer { close(descriptor) }
        var attributes = stat()
        guard fstat(descriptor, &attributes) == 0, attributes.st_mode & S_IFMT == S_IFREG, attributes.st_size > 0
        else { throw VPNImportError.invalidFile }
        guard attributes.st_size <= maximumBytes else { throw VPNImportError.tooLarge }
        var data = Data(), buffer = [UInt8](repeating: 0, count: 16384)
        while true {
            let count = read(descriptor, &buffer, buffer.count)
            if count < 0 { if errno == EINTR { continue }; throw VPNImportError.invalidFile }
            if count == 0 { break }
            guard data.count + count <= maximumBytes else { throw VPNImportError.tooLarge }
            data.append(contentsOf: buffer.prefix(count))
        }
        return try inspect(data: data, name: url.lastPathComponent)
    }

    static func inspect(data: Data, name: String) throws -> VPNImportedProfile {
        guard !data.isEmpty else { throw VPNImportError.invalidFile }
        guard data.count <= maximumBytes else { throw VPNImportError.tooLarge }
        var nameCheck = VPNConfiguration()
        do { try nameCheck.setProfile(name: name) } catch { throw VPNImportError.invalidFile }
        guard var text = String(data: data, encoding: .utf8) else { throw VPNImportError.malformed }
        if text.hasPrefix("\u{feff}") { text.removeFirst() }
        guard !text.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) && ![9, 10, 13].contains($0.value) })
        else { throw VPNImportError.malformed }
        let lines = text.replacingOccurrences(of: "\r\n", with: "\n").replacingOccurrences(of: "\r", with: "\n").components(separatedBy: "\n")
        var seen = Set<String>(), inline = Set<String>(), safe: [String] = [], dns: [String] = []
        var resources: [VPNResource] = []
        var block: String?, blockLines: [String] = []
        var servers = 0, credentials = false, encrypted = false, ignoredRoutes = false
        var client = false, tun = false, verifiedServer = false
        for raw in lines {
            guard raw.utf8.count <= 16384 else { throw VPNImportError.malformed }
            let line = raw.trimmingCharacters(in: .whitespaces)
            if let current = block {
                if line == "</\(current)>" {
                    try validateBlock(current, lines: blockLines)
                    encrypted = encrypted || (current == "key" && blockLines.contains(where: { $0.contains("ENCRYPTED") }))
                    safe += ["<\(current)>"] + blockLines + ["</\(current)>"]
                    block = nil; blockLines = []; continue
                }
                guard !line.contains("<"), !line.contains(">") else { throw VPNImportError.malformed }
                blockLines.append(line); continue
            }
            if line.isEmpty || line.hasPrefix("#") || line.hasPrefix(";") { continue }
            if line.hasPrefix("<") {
                guard line.hasSuffix(">"), blocks.contains(String(line.dropFirst().dropLast())) else { throw VPNImportError.unsupported }
                let tag = String(line.dropFirst().dropLast())
                guard inline.insert(tag).inserted else { throw VPNImportError.malformed }
                block = tag; continue
            }
            var tokens = try tokenize(line)
            guard !tokens.isEmpty else { continue }
            var option = tokens.removeFirst()
            if option.hasPrefix("--") { option = String(option.dropFirst(2)) }
            guard option.range(of: "^[a-z][a-z0-9-]*$", options: .regularExpression) != nil else { throw VPNImportError.malformed }
            let args = tokens
            if !["remote", "route", "route-ipv6", "dhcp-option"].contains(option), !seen.insert(option).inserted {
                throw VPNImportError.malformed
            }
            switch option {
            case "client": try arity(args, 0); client = true
            case "dev": guard args == ["tun"] else { throw VPNImportError.unsupported }; tun = true
            case "dev-type": guard args == ["tun"] else { throw VPNImportError.unsupported }
            case "remote":
                guard (1...3).contains(args.count), servers < 16 else { throw VPNImportError.malformed }
                let normalized = try? VPNResource.normalize(args[0])
                guard let host = normalized, [.domain, .ipv4, .ipv6].contains(host.1), host.0 == args[0].lowercased()
                else { throw VPNImportError.malformed }
                if args.count >= 2 { try number(args[1], range: 1...65535) }
                if args.count == 3 { guard transports.contains(args[2]) else { throw VPNImportError.unsupported } }
                servers += 1
            case "proto": guard args.count == 1, transports.contains(args[0]) else { throw VPNImportError.unsupported }
            case "port": try arity(args, 1); try number(args[0], range: 1...65535)
            case "auth-user-pass": guard args.isEmpty else { throw VPNImportError.externalFilesRequired }; credentials = true
            case "ca", "cert", "key", "tls-auth", "tls-crypt", "tls-crypt-v2", "pkcs12", "askpass":
                throw VPNImportError.externalFilesRequired
            case "remote-cert-tls": guard args == ["server"] else { throw VPNImportError.missingServerVerification }; verifiedServer = true
            case "verify-x509-name":
                guard (1...2).contains(args.count), !args[0].isEmpty,
                      args.count == 1 || ["subject", "name", "name-prefix"].contains(args[1]) else { throw VPNImportError.malformed }
            case "auth-nocache", "route-nopull": try arity(args, 0); continue
            case "script-security": guard args == ["1"] else { throw VPNImportError.unsupported }; continue
            case "nobind", "persist-key", "persist-tun", "remote-random", "pull", "tls-client":
                try arity(args, 0)
            case "resolv-retry":
                try arity(args, 1); if args[0] != "infinite" { try number(args[0], range: 0...86400) }
            case "verb": try arity(args, 1); try number(args[0], range: 0...4)
            case "explicit-exit-notify":
                guard args.count <= 1 else { throw VPNImportError.malformed }
                if let attempts = args.first { try number(attempts, range: 0...5) }
            case "key-direction": guard args == ["0"] || args == ["1"] else { throw VPNImportError.malformed }
            case "cipher", "data-ciphers", "data-ciphers-fallback":
                try arity(args, 1)
                let allowed = ["AES-128-GCM", "AES-256-GCM", "CHACHA20-POLY1305", "AES-128-CBC", "AES-256-CBC"]
                let values = args[0].split(separator: ":", omittingEmptySubsequences: false)
                guard (option == "data-ciphers" || values.count == 1), values.allSatisfy({ allowed.contains(String($0)) }) else { throw VPNImportError.unsupported }
            case "auth": guard args.count == 1, ["SHA256", "SHA384", "SHA512"].contains(args[0]) else { throw VPNImportError.unsupported }
            case "tls-version-min": guard args == ["1.2"] || args == ["1.3"] else { throw VPNImportError.unsupported }
            case "tls-cipher":
                try arity(args, 1)
                let suites = args[0].split(separator: ":", omittingEmptySubsequences: false)
                guard !suites.isEmpty, suites.count <= 8, suites.allSatisfy({ tlsCiphers.contains(String($0)) })
                else { throw VPNImportError.unsupported }
            case "allow-compression": guard args == ["no"] else { throw VPNImportError.unsupported }
            case "route", "route-ipv6", "redirect-gateway", "redirect-private":
                ignoredRoutes = true
                if let resource = suggestedRoute(option: option, args: args), !resources.contains(where: { $0.address == resource.address }) {
                    guard resources.count < 1000 else { throw VPNImportError.unsupported }
                    resources.append(resource)
                }
                continue // Suggestions require user review; never emit raw routes into engine config.
            case "dhcp-option":
                guard args.count == 2, args[0] == "DNS", let address = try? VPNResource.normalize(args[1]),
                      [.ipv4, .ipv6].contains(address.1) else { throw VPNImportError.unsupported }
                if !dns.contains(address.0) { dns.append(address.0) }
                guard dns.count <= 4 else { throw VPNImportError.unsupported }
                continue // Suggestions only; no global DNS settings are emitted.
            case "setenv":
                guard args == ["opt", "block-outside-dns"] else { throw VPNImportError.unsupported }
                continue // Windows-only option is not a macOS operation.
            case "ignore-unknown-option":
                guard args == ["block-outside-dns"] else { throw VPNImportError.unsupported }
                continue // Drop this single Windows compatibility directive, not validation of unknown options.
            default:
                // Fail closed: config/up/down/plugin/management/log/status/cd,
                // SSO/MFA hooks, TAP and future options need explicit support.
                throw VPNImportError.unsupported
            }
            safe.append(([option] + args.map(quote)).joined(separator: " "))
        }
        guard block == nil, client, tun else { throw VPNImportError.malformed }
        guard servers > 0 else { throw VPNImportError.missingServer }
        guard inline.contains("ca"), inline.contains("cert") == inline.contains("key"), credentials || inline.contains("key")
        else { throw VPNImportError.missingIdentity }
        guard verifiedServer else { throw VPNImportError.missingServerVerification }
        guard inline.intersection(["tls-auth", "tls-crypt", "tls-crypt-v2"]).count <= 1,
              !seen.contains("key-direction") || inline.contains("tls-auth") else { throw VPNImportError.malformed }
        // Defense in depth for the eventual config builder. This candidate alone
        // cannot handle pushed options, DNS, route ownership or helper permissions.
        safe += ["route-nopull", "script-security 1", "auth-nocache"]
        return VPNImportedProfile(name: name, requiresCredentials: credentials, requiresKeyPassword: encrypted,
                                  suggestedDNS: dns, suggestedResources: resources, hasIgnoredRoutes: ignoredRoutes,
                                  validatedData: Data((safe.joined(separator: "\n") + "\n").utf8))
    }

    private static func suggestedRoute(option: String, args: [String]) -> VPNResource? {
        if option == "route-ipv6", args.count == 1,
           let resource = try? VPNResource(address: args[0]), resource.kind == .network6 {
            return resource
        }
        // Custom gateway/metric rules are not equivalent to a VPN resource.
        guard option == "route", (1...2).contains(args.count),
              let host = try? VPNResource(address: args[0]), host.kind == .ipv4 else { return nil }
        guard args.count == 2 else { return host }
        let octets = args[1].split(separator: ".", omittingEmptySubsequences: false)
        guard octets.count == 4 else { return nil }
        var mask: UInt32 = 0
        for octet in octets {
            guard let value = UInt8(octet), String(value) == octet else { return nil }
            mask = (mask << 8) | UInt32(value)
        }
        let bits = mask.nonzeroBitCount
        guard bits > 0, mask == UInt32.max << (32 - bits) else { return nil }
        // A host route uses the same canonical identity as a manually added IP.
        return bits == 32 ? host : try? VPNResource(address: host.address + "/\(bits)")
    }

    private static func arity(_ values: [String], _ count: Int) throws {
        guard values.count == count else { throw VPNImportError.malformed }
    }
    private static func number(_ value: String, range: ClosedRange<Int>) throws {
        guard !value.isEmpty, value.allSatisfy({ $0.isASCII && $0.isNumber }), let integer = Int(value), range.contains(integer)
        else { throw VPNImportError.malformed }
    }
    private static func quote(_ value: String) -> String {
        "\"" + value.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"") + "\""
    }
    private static func tokenize(_ line: String) throws -> [String] {
        var result: [String] = [], token = "", quote: Character?, escaped = false, started = false
        for character in line {
            if escaped { token.append(character); escaped = false; started = true; continue }
            if character == "\\", quote != "'" { escaped = true; continue }
            if let delimiter = quote {
                if character == delimiter { quote = nil } else { token.append(character) }
                started = true; continue
            }
            if character == "\"" || character == "'" { quote = character; started = true; continue }
            if character == " " || character == "\t" {
                if started { result.append(token); token = ""; started = false }
            } else if (character == "#" || character == ";") && !started { break }
            else { token.append(character); started = true }
        }
        guard quote == nil, !escaped else { throw VPNImportError.malformed }
        if started { result.append(token) }
        return result
    }
    private static func validateBlock(_ name: String, lines: [String]) throws {
        let content = lines.filter { !$0.isEmpty && !$0.hasPrefix("#") }
        guard let first = content.first, let last = content.last, content.count >= 3,
              first.hasPrefix("-----BEGIN "), first.hasSuffix("-----") else { throw VPNImportError.malformed }
        let label = String(first.dropFirst(11).dropLast(5))
        let allowed: [String]
        switch name {
        case "ca", "cert": allowed = ["CERTIFICATE"]
        case "key": allowed = ["PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY", "ENCRYPTED PRIVATE KEY"]
        case "tls-auth", "tls-crypt": allowed = ["OpenVPN Static key V1"]
        default: allowed = ["OpenVPN tls-crypt-v2 client key"]
        }
        guard allowed.contains(label), last == "-----END \(label)-----" else { throw VPNImportError.malformed }
        let payload = content.dropFirst().dropLast().joined()
        if name == "tls-auth" || name == "tls-crypt" {
            guard payload.count == 512, payload.allSatisfy({ $0.isASCII && $0.isHexDigit }) else { throw VPNImportError.malformed }
        } else {
            guard let bytes = Data(base64Encoded: payload), !bytes.isEmpty else { throw VPNImportError.malformed }
        }
    }
}
