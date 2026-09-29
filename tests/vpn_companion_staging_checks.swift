import CryptoKit
import Darwin
import Foundation

@main enum VPNCompanionStagingChecks {
    static func require(_ condition: @autoclosure () -> Bool) throws {
        guard condition() else { throw NSError(domain: "companion-staging", code: 1) }
    }

    static func metadata(_ bytes: Data, count: Int? = nil,
                         digest: Data? = nil) throws -> VerifiedVPNCompanionMetadata {
        let key = Curve25519.Signing.PrivateKey()
        let hash = digest ?? Data(SHA256.hash(data: bytes))
        let text = "format=1\nproduct=kz.documentolog.proxypilot\nversion=2.0.0\n"
            + "from-sequence=9\nto-sequence=10\nartifact-sha256="
            + hash.map { String(format: "%02x", $0) }.joined()
            + "\nartifact-bytes=\(count ?? bytes.count)\n"
        let payload = Data(text.utf8)
        let signature = try key.signature(
            for: VPNCompanionMetadataAuthority.signatureDomain + payload)
        return try VPNCompanionMetadataAuthority(
            trustedPublicKey: key.publicKey.rawRepresentation)
            .verify(payload: payload, signature: signature)
    }

    static func stagedDirectories() -> Set<String> {
        let root = URL(fileURLWithPath: NSTemporaryDirectory())
        return Set((try? FileManager.default.contentsOfDirectory(
            atPath: root.path))?.filter {
                $0.hasPrefix("ProxyPilot-Companion.")
            } ?? [])
    }

    static func main() throws {
        let before = stagedDirectories()
        let bytes = Data((0..<8193).map { UInt8($0 % 251) })
        do {
            let staging = try VPNCompanionStaging(
                expectedBytes: UInt64(bytes.count))
            try staging.append(bytes.prefix(17))
            try staging.append(bytes.dropFirst(17))
            let result = try staging.finish(metadata: metadata(bytes))
            try result.withFileDescriptor { descriptor in
                var info = stat()
                try require(fstat(descriptor, &info) == 0)
                try require(info.st_mode & 0o7777 == 0o600)
                try require(info.st_uid == geteuid())
                try require(fcntl(descriptor, F_GETFD) & FD_CLOEXEC != 0)
                try require(lseek(descriptor, 0, SEEK_SET) == 0)
                var loaded = Data(count: bytes.count)
                let count = loaded.withUnsafeMutableBytes {
                    read(descriptor, $0.baseAddress, $0.count)
                }
                try require(count == bytes.count && loaded == bytes)
            }
        }
        try require(stagedDirectories() == before)

        do {
            let staging = try VPNCompanionStaging(expectedBytes: 4)
            do {
                try staging.append(Data(repeating: 1, count: 5))
                throw NSError(domain: "accepted oversized", code: 2)
            } catch VPNCompanionStagingError.oversized { }
        }
        try require(stagedDirectories() == before)

        do {
            let staging = try VPNCompanionStaging(expectedBytes: 4)
            try staging.append(Data([1, 2]))
            do {
                _ = try staging.finish(metadata: metadata(Data([1, 2, 3, 4])))
                throw NSError(domain: "accepted incomplete", code: 3)
            } catch VPNCompanionStagingError.incomplete { }
        }
        try require(stagedDirectories() == before)

        do {
            let contents = Data([1, 2, 3, 4])
            let staging = try VPNCompanionStaging(expectedBytes: 4)
            try staging.append(contents)
            let wrong = Data(SHA256.hash(data: Data([4, 3, 2, 1])))
            do {
                _ = try staging.finish(metadata: metadata(contents, digest: wrong))
                throw NSError(domain: "accepted wrong digest", code: 4)
            } catch VPNCompanionMetadataError.invalidArtifact { }
        }
        try require(stagedDirectories() == before)
        print("vpn companion staging checks passed")
    }
}
