import CryptoKit
import Foundation

final class CompanionURLProtocol: URLProtocol {
    static var status = 200
    static var headers: [String: String] = [:]
    static var chunks: [Data] = []

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() {
        let response = HTTPURLResponse(
            url: request.url!, statusCode: Self.status,
            httpVersion: "HTTP/1.1", headerFields: Self.headers)!
        client?.urlProtocol(self, didReceive: response,
                            cacheStoragePolicy: .notAllowed)
        for chunk in Self.chunks { client?.urlProtocol(self, didLoad: chunk) }
        client?.urlProtocolDidFinishLoading(self)
    }
    override func stopLoading() { }
}

@main enum VPNCompanionDownloaderChecks {
    static func require(_ condition: @autoclosure () -> Bool) throws {
        guard condition() else { throw NSError(domain: "companion-download", code: 1) }
    }

    static func metadata(bytes: Data, digest: Data? = nil,
                         count: Int? = nil) throws -> VerifiedVPNCompanionMetadata {
        let key = Curve25519.Signing.PrivateKey()
        let hash = digest ?? Data(SHA256.hash(data: bytes))
        let payload = Data(("format=1\nproduct=kz.documentolog.proxypilot\n"
            + "version=2.0.0\nfrom-sequence=9\nto-sequence=10\n"
            + "artifact-sha256=" + hash.map { String(format: "%02x", $0) }.joined()
            + "\nartifact-bytes=\(count ?? bytes.count)\n").utf8)
        let signature = try key.signature(
            for: VPNCompanionMetadataAuthority.signatureDomain + payload)
        return try VPNCompanionMetadataAuthority(
            trustedPublicKey: key.publicKey.rawRepresentation)
            .verify(payload: payload, signature: signature)
    }

    static func run(metadata: VerifiedVPNCompanionMetadata,
                    status: Int = 200, headers: [String: String] = [:],
                    chunks: [Data]) throws -> Result<VPNDownloadedCompanion, Error> {
        CompanionURLProtocol.status = status
        CompanionURLProtocol.headers = headers
        CompanionURLProtocol.chunks = chunks
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [CompanionURLProtocol.self]
        let semaphore = DispatchSemaphore(value: 0)
        var outcome: Result<VPNDownloadedCompanion, Error>?
        var download: VPNCompanionDownloader? = try .testStart(
            metadata: metadata, configuration: configuration) {
                outcome = $0; semaphore.signal()
            }
        guard semaphore.wait(timeout: .now() + 10) == .success,
              let result = outcome else {
            throw NSError(domain: "download timed out", code: 2)
        }
        withExtendedLifetime(download) { }
        download = nil
        return result
    }

    static func mustFail(_ result: Result<VPNDownloadedCompanion, Error>) throws {
        if case .success = result {
            throw NSError(domain: "accepted invalid download", code: 3)
        }
    }

    static func main() throws {
        let bytes = Data((0..<4097).map { UInt8($0 % 239) })
        let valid = try metadata(bytes: bytes)
        let success = try run(
            metadata: valid,
            headers: ["Content-Length": String(bytes.count)],
            chunks: [bytes.prefix(13), bytes.dropFirst(13)])
        switch success {
        case .failure(let error): throw error
        case .success(let artifact):
            try artifact.withFileDescriptor { descriptor in
                var loaded = Data(count: bytes.count)
                let count = loaded.withUnsafeMutableBytes {
                    read(descriptor, $0.baseAddress, $0.count)
                }
                try require(count == bytes.count && loaded == bytes)
            }
        }

        try mustFail(run(metadata: valid, status: 500, chunks: [bytes]))
        try mustFail(run(metadata: valid,
                         headers: ["Content-Encoding": "gzip"],
                         chunks: [bytes]))
        try mustFail(run(metadata: valid,
                         headers: ["Content-Length": String(bytes.count + 1)],
                         chunks: [bytes]))
        try mustFail(run(metadata: valid, chunks: [bytes.dropLast()]))
        try mustFail(run(metadata: valid, chunks: [bytes, Data([1])]))
        let wrong = Data(SHA256.hash(data: Data(repeating: 9, count: bytes.count)))
        try mustFail(run(metadata: try metadata(bytes: bytes, digest: wrong),
                         chunks: [bytes]))

        let initial = valid.artifactURL
        let cdn = URL(string: "https://release-assets.githubusercontent.com/github-production-release-asset/a?x=1")!
        try require(VPNCompanionDownloader.testRedirect(
            from: initial, to: cdn, method: "GET"))
        for bad in [
            URL(string: "http://release-assets.githubusercontent.com/a")!,
            URL(string: "https://evil.example/a")!,
            URL(string: "https://release-assets.githubusercontent.com.evil/a")!,
            URL(string: "https://user@release-assets.githubusercontent.com/a")!,
        ] {
            try require(!VPNCompanionDownloader.testRedirect(
                from: initial, to: bad, method: "GET"))
        }
        try require(!VPNCompanionDownloader.testRedirect(
            from: initial, to: cdn, method: "POST"))
        print("vpn companion downloader checks passed")
    }
}
