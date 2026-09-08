import Darwin
import Foundation
import Security

/// Static validation only; never starts the candidate. Call only for a file in
/// a protected, locally provisioned directory while holding the store lock, or
/// an owner-only-writable installation package with before/after file snapshots.
/// Security's path-based API is not safe against concurrent file modification.
enum VPNHelperArtifact {
    static let signingIdentifier = "kz.documentolog.proxypilot.vpn-helper"

    static func validate(protectedFile file: Int32, data: Data, release: VerifiedVPNRelease) throws {
        try release.validateHelperArtifact(data)
        try validateUniversalExecutable(data)
        var path = [CChar](repeating: 0, count: Int(MAXPATHLEN))
        guard fcntl(file, F_GETPATH, &path) == 0 else { throw VPNReleaseAuthorizationError.invalidHelperArtifact }
        let url = URL(fileURLWithPath: String(cString: path))
        var opened = stat(), named = stat()
        guard fstat(file, &opened) == 0, lstat(url.path, &named) == 0,
              opened.st_dev == named.st_dev, opened.st_ino == named.st_ino,
              named.st_mode & S_IFMT == S_IFREG else { throw VPNReleaseAuthorizationError.invalidHelperArtifact }

        let required = SecCodeSignatureFlags.runtime.rawValue | SecCodeSignatureFlags.forceHard.rawValue | SecCodeSignatureFlags.forceKill.rawValue
        let checks = SecCSFlags(rawValue: kSecCSCheckAllArchitectures | kSecCSStrictValidate).union(.noNetworkAccess)
        for architecture in ["arm64", "x86_64"] {
            var code: SecStaticCode?
            let attributes = [kSecCodeAttributeArchitecture as String: architecture] as CFDictionary
            guard SecStaticCodeCreateWithPathAndAttributes(url as CFURL, [], attributes, &code) == errSecSuccess,
                  let code = code,
                  SecStaticCodeCheckValidity(code, checks, nil) == errSecSuccess else {
                throw VPNReleaseAuthorizationError.invalidHelperArtifact
            }
            var information: CFDictionary?
            guard SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &information) == errSecSuccess,
                  let info = information as? [String: Any],
                  info[kSecCodeInfoIdentifier as String] as? String == signingIdentifier,
                  let hash = info[kSecCodeInfoUnique as String] as? Data,
                  hash == release.helperHash(forArchitecture: architecture),
                  let flags = info[kSecCodeInfoFlags as String] as? NSNumber,
                  flags.uint32Value & required == required else {
                throw VPNReleaseAuthorizationError.invalidHelperArtifact
            }
            if let entitlements = info[kSecCodeInfoEntitlementsDict as String] {
                guard let dictionary = entitlements as? [String: Any], dictionary.isEmpty else {
                    throw VPNReleaseAuthorizationError.invalidHelperArtifact
                }
            }
        }
    }

    private static func validateUniversalExecutable(_ data: Data) throws {
        func reject() throws -> Never { throw VPNReleaseAuthorizationError.invalidHelperArtifact }
        let bytes = Array(data.prefix(48))
        guard bytes.count == 48 else { try reject() }
        func big(_ offset: Int) -> UInt32 {
            bytes[offset..<offset + 4].reduce(0) { ($0 << 8) | UInt32($1) }
        }
        // Only the two-slice FAT32 format emitted by our lipo build is accepted.
        // Explicitly reject extra architectures, thin files and non-executables.
        guard big(0) == 0xcafebabe, big(4) == 2 else { try reject() }
        var architectures = Set<UInt32>(), ranges: [Range<Int>] = []
        for index in 0..<2 {
            let base = 8 + index * 20
            let cpu = big(base), subtype = big(base + 4)
            let offset = Int(big(base + 8)), size = Int(big(base + 12)), alignment = big(base + 16)
            guard (cpu == 0x0100000c && subtype == 0) || (cpu == 0x01000007 && subtype == 3),
                  architectures.insert(cpu).inserted,
                  alignment <= 20, offset >= 48, offset % (1 << alignment) == 0,
                  size >= 32, offset <= data.count, size <= data.count - offset else { try reject() }
            let range = offset..<offset + size
            guard !ranges.contains(where: { $0.overlaps(range) }) else { try reject() }
            ranges.append(range)
            let header = Array(data[offset..<offset + 16])
            func little(_ start: Int) -> UInt32 {
                header[start..<start + 4].reversed().reduce(0) { ($0 << 8) | UInt32($1) }
            }
            guard little(0) == 0xfeedfacf, little(4) == cpu, little(8) == subtype,
                  little(12) == 2 else { try reject() } // MH_EXECUTE
        }
    }
}
