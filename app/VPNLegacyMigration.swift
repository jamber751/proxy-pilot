import Foundation

enum VPNMigrationError: Error, Equatable { case alreadyConfigured }

/// One-way, read-only import of the CLI's `VPN_ROUTES` into the new resource
/// list. It reads text that is already on this machine and writes nothing back:
/// the legacy config file is never modified, no shell is involved, no value from
/// it is executed, and the VPN is never enabled or given a profile by migrating.
enum VPNLegacyMigration {
    struct Result: Equatable {
        let migrated: [VPNResource]
        let skipped: Int
    }

    /// Only the last `VPN_ROUTES=` assignment counts, the way a shell would read
    /// the file — an old commented-out line must not resurrect old routes.
    static func routes(inLegacyConfiguration text: String) -> String? {
        var value: String?
        for rawLine in text.components(separatedBy: "\n") {
            var line = Substring(rawLine).drop { $0 == " " || $0 == "\t" }
            if line.hasPrefix("export ") { line = line.dropFirst(7).drop { $0 == " " } }
            guard line.hasPrefix("VPN_ROUTES=") else { continue }
            value = unquoted(line.dropFirst("VPN_ROUTES=".count))
        }
        return value
    }

    /// Everything the CLI could route was an IPv4 host or network. Anything else
    /// — a domain, IPv6, junk, a command substitution — is skipped, not guessed
    /// at. Default and near-default routes are skipped too: the first version
    /// does not migrate "send everything through the tunnel".
    static func resources(inLegacyConfiguration text: String) -> Result {
        guard let value = routes(inLegacyConfiguration: text) else { return Result(migrated: [], skipped: 0) }
        var migrated: [VPNResource] = []
        var skipped = 0
        for candidate in value.split(whereSeparator: { $0 == " " || $0 == "," || $0 == "\t" }) {
            guard let resource = try? VPNResource(address: String(candidate)),
                  [.ipv4, .network4].contains(resource.kind), !isTooBroad(resource),
                  !migrated.contains(where: { $0.address == resource.address }),
                  migrated.count < 1000 else {
                skipped += 1
                continue
            }
            migrated.append(resource)
        }
        return Result(migrated: migrated, skipped: skipped)
    }

    /// Refuses to touch a configuration that already has resources: a migration
    /// may fill an empty list once, never overwrite what the owner has edited.
    @discardableResult
    static func migrate(into configuration: inout VPNConfiguration,
                        legacyConfiguration text: String) throws -> Result {
        guard configuration.resources.isEmpty else { throw VPNMigrationError.alreadyConfigured }
        let result = resources(inLegacyConfiguration: text)
        for resource in result.migrated { try configuration.saveResource(resource) }
        return result
    }

    private static func isTooBroad(_ resource: VPNResource) -> Bool {
        guard resource.kind == .network4, let prefix = resource.address.split(separator: "/").last,
              let bits = Int(prefix) else { return false }
        return bits < 8
    }

    private static func unquoted(_ raw: Substring) -> String {
        let value = raw.drop { $0 == " " }
        if let quote = value.first, quote == "\"" || quote == "'" {
            let body = value.dropFirst()
            guard let end = body.firstIndex(of: quote) else { return String(body) }
            return String(body[body.startIndex..<end])
        }
        // Unquoted values end at whitespace or a comment, as the shell reads them.
        return String(value.prefix { $0 != " " && $0 != "\t" && $0 != "#" })
    }
}
