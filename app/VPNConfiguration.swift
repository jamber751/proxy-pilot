import Foundation
import Darwin

enum VPNValidationError: Error, LocalizedError, Equatable {
    case invalidAddress, defaultRoute, duplicateResource, missingResource
    case missingProfile, resourcesRequired, lastResourceRequiresConfirmation
    case invalidConfiguration, staleRevision, storageUnavailable

    var errorDescription: String? {
        switch self {
        case .invalidAddress: return "Укажите домен, IP-адрес или сеть."
        case .defaultRoute: return "Добавьте рабочие ресурсы, а не маршрут для всего интернета."
        case .duplicateResource: return "Этот адрес уже добавлен."
        case .missingResource: return "Ресурс уже удалён. Откройте список заново."
        case .missingProfile: return "Сначала добавьте файл VPN."
        case .resourcesRequired: return "Добавьте хотя бы один ресурс."
        case .lastResourceRequiresConfirmation: return "Удаление последнего ресурса выключит VPN."
        case .invalidConfiguration: return "Не удалось прочитать настройки VPN. Сохранённый файл не изменён."
        case .staleRevision: return "Настройки уже изменились. Откройте их заново."
        case .storageUnavailable: return "Не удалось сохранить настройки VPN. Предыдущие настройки не изменены."
        }
    }
}

struct VPNResource: Codable, Equatable, Identifiable {
    enum Kind: String, Codable { case domain, ipv4, ipv6, network4, network6 }
    let id: UUID
    let name: String
    let address: String
    let kind: Kind

    init(id: UUID = UUID(), name: String = "", address: String) throws {
        let normalized = try Self.normalize(address)
        let cleanName = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard cleanName.count <= 60, !cleanName.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains)
        else { throw VPNValidationError.invalidAddress }
        self.id = id; self.name = cleanName
        self.address = normalized.0; self.kind = normalized.1
    }

    static func normalize(_ value: String) throws -> (String, Kind) {
        var address = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !address.isEmpty, address.utf8.count <= 2048,
              !address.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains)
        else { throw VPNValidationError.invalidAddress }
        if address.lowercased().hasPrefix("https://") || address.lowercased().hasPrefix("http://") {
            guard let url = URLComponents(string: address), let host = url.host,
                  url.user == nil, url.password == nil, url.port == nil
            else { throw VPNValidationError.invalidAddress }
            address = host
            if address.hasPrefix("["), address.hasSuffix("]") { address = String(address.dropFirst().dropLast()) }
        }
        address = address.lowercased()
        let parts = address.split(separator: "/", omittingEmptySubsequences: false)
        guard parts.count <= 2 else { throw VPNValidationError.invalidAddress }
        let host = String(parts[0])
        for (family, size) in [(AF_INET, 4), (AF_INET6, 16)] {
            var bytes = [UInt8](repeating: 0, count: size)
            let valid = bytes.withUnsafeMutableBytes { target in
                host.withCString { inet_pton(family, $0, target.baseAddress!) }
            }
            guard valid == 1 else { continue }
            if family == AF_INET, host != format(bytes, family: family) { throw VPNValidationError.invalidAddress }
            if parts.count == 2 {
                let raw = String(parts[1])
                guard !raw.isEmpty, raw.allSatisfy({ $0.isASCII && $0.isNumber }),
                      let prefix = Int(raw), prefix <= size * 8 else { throw VPNValidationError.invalidAddress }
                guard prefix > 0 else { throw VPNValidationError.defaultRoute }
                for index in bytes.indices {
                    let remaining = max(0, min(8, prefix - index * 8))
                    bytes[index] &= remaining == 0 ? 0 : UInt8(0xff << (8 - remaining) & 0xff)
                }
                return (format(bytes, family: family) + "/\(prefix)", family == AF_INET ? .network4 : .network6)
            }
            // Loopback, unspecified, multicast and link-local addresses cannot
            // describe a remote corporate service. No DNS lookup is performed.
            if family == AF_INET {
                guard bytes[0] != 0, bytes[0] != 127, bytes[0] < 224,
                      !(bytes[0] == 169 && bytes[1] == 254) else { throw VPNValidationError.invalidAddress }
            } else {
                guard bytes.contains(where: { $0 != 0 }),
                      !(bytes.dropLast().allSatisfy({ $0 == 0 }) && bytes.last == 1),
                      bytes[0] != 0xff, !(bytes[0] == 0xfe && bytes[1] & 0xc0 == 0x80),
                      !(bytes.prefix(10).allSatisfy({ $0 == 0 }) && bytes[10] == 0xff && bytes[11] == 0xff)
                else { throw VPNValidationError.invalidAddress }
            }
            return (format(bytes, family: family), family == AF_INET ? .ipv4 : .ipv6)
        }
        guard parts.count == 1 else { throw VPNValidationError.invalidAddress }
        if address.hasSuffix(".") { address.removeLast() }
        let labels = address.split(separator: ".", omittingEmptySubsequences: false)
        guard address.utf8.count <= 253, labels.count >= 2,
              labels.allSatisfy({ label in
                  !label.isEmpty && label.utf8.count <= 63 && !label.hasPrefix("-") && !label.hasSuffix("-") &&
                  label.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-") })
              }), !labels.last!.allSatisfy({ $0.isNumber })
        else { throw VPNValidationError.invalidAddress }
        return (address, .domain)
    }

    private static func format(_ bytes: [UInt8], family: Int32) -> String {
        var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        bytes.withUnsafeBytes { _ = inet_ntop(family, $0.baseAddress!, &buffer, socklen_t(buffer.count)) }
        return String(cString: buffer)
    }

    func validate() throws {
        guard try Self(id: id, name: name, address: address) == self else { throw VPNValidationError.invalidConfiguration }
    }
}

/// Saved intent only. This is never evidence that a tunnel is connected.
struct VPNConfiguration: Codable, Equatable {
    let schemaVersion: Int
    private(set) var revision: UInt64
    private(set) var profileName: String?
    private(set) var resources: [VPNResource]
    private(set) var desiredEnabled: Bool
    private(set) var corporateDNS: [String]

    init() {
        schemaVersion = 1; revision = 0; profileName = nil
        resources = []; desiredEnabled = false; corporateDNS = []
    }

    mutating func setProfile(name: String) throws {
        guard name.lowercased().hasSuffix(".ovpn"), !name.contains("/"), !name.contains("\\"),
              name.utf8.count <= 255, !name.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains)
        else { throw VPNValidationError.invalidConfiguration }
        try advance(); profileName = name
    }

    mutating func saveResource(_ resource: VPNResource, replacing id: UUID? = nil) throws {
        try resource.validate()
        if let id = id { guard resource.id == id, resources.contains(where: { $0.id == id }) else { throw VPNValidationError.missingResource } }
        guard !resources.contains(where: { ($0.address == resource.address || $0.id == resource.id) && $0.id != id })
        else { throw VPNValidationError.duplicateResource }
        guard resources.count < 1000 || id != nil else { throw VPNValidationError.invalidConfiguration }
        try advance()
        if let id = id, let index = resources.firstIndex(where: { $0.id == id }) { resources[index] = resource }
        else { resources.append(resource) }
    }

    mutating func removeResource(id: UUID, confirmingVPNOff: Bool = false) throws {
        guard resources.contains(where: { $0.id == id }) else { throw VPNValidationError.missingResource }
        guard resources.count > 1 || confirmingVPNOff else { throw VPNValidationError.lastResourceRequiresConfirmation }
        try advance(); resources.removeAll { $0.id == id }
        if resources.isEmpty { desiredEnabled = false }
    }

    mutating func setEnabled(_ enabled: Bool) throws {
        if enabled {
            guard profileName != nil else { throw VPNValidationError.missingProfile }
            guard !resources.isEmpty else { throw VPNValidationError.resourcesRequired }
        }
        guard desiredEnabled != enabled else { return }
        try advance(); desiredEnabled = enabled
    }

    mutating func setDNS(_ addresses: [String]) throws {
        guard addresses.count <= 4 else { throw VPNValidationError.invalidAddress }
        let normalized = try addresses.map { try VPNResource.normalize($0) }
        guard normalized.allSatisfy({ [.ipv4, .ipv6].contains($0.1) }), Set(normalized.map { $0.0 }).count == addresses.count
        else { throw VPNValidationError.invalidAddress }
        try advance(); corporateDNS = normalized.map { $0.0 }
    }

    /// The controller must stop and verify cleanup before persisting this change.
    mutating func removeProfile() throws {
        try advance(); profileName = nil; resources = []; corporateDNS = []; desiredEnabled = false
    }

    func validate() throws {
        guard schemaVersion == 1, resources.count <= 1000, corporateDNS.count <= 4,
              !desiredEnabled || (profileName != nil && !resources.isEmpty),
              Set(resources.map { $0.id }).count == resources.count,
              Set(resources.map { $0.address }).count == resources.count
        else { throw VPNValidationError.invalidConfiguration }
        for resource in resources { try resource.validate() }
        var probe = VPNConfiguration()
        if let name = profileName { try probe.setProfile(name: name) }
        try probe.setDNS(corporateDNS)
        guard probe.corporateDNS == corporateDNS else { throw VPNValidationError.invalidConfiguration }
    }

    private mutating func advance() throws {
        guard revision < UInt64.max else { throw VPNValidationError.invalidConfiguration }
        revision += 1
    }
}
