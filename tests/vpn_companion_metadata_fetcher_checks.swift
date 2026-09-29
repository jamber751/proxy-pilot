import CryptoKit
import Foundation

final class MetadataURLProtocol: URLProtocol {
    static var metadata = Data()
    static var signature = Data()
    static var status = 200
    static var encoding: String?

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() {
        var headers: [String: String] = [:]
        if let encoding = Self.encoding { headers["Content-Encoding"] = encoding }
        let response = HTTPURLResponse(
            url: request.url!, statusCode: Self.status,
            httpVersion: "HTTP/1.1", headerFields: headers)!
        client?.urlProtocol(self, didReceive: response,
                            cacheStoragePolicy: .notAllowed)
        let bytes = request.url!.lastPathComponent.hasSuffix(".sig")
            ? Self.signature : Self.metadata
        client?.urlProtocol(self, didLoad: bytes)
        client?.urlProtocolDidFinishLoading(self)
    }
    override func stopLoading() { }
}

@main enum VPNCompanionMetadataFetcherChecks {
    static func require(_ value: @autoclosure () -> Bool) throws {
        guard value() else { throw NSError(domain: "metadata-fetch", code: 1) }
    }

    static func payload(from: UInt64 = 9, version: String = "2.0.0") -> Data {
        Data(("format=1\nproduct=kz.documentolog.proxypilot\nversion=\(version)\n"
            + "from-sequence=\(from)\nto-sequence=10\nartifact-sha256="
            + String(repeating: "aa", count: 32)
            + "\nartifact-bytes=4096\n").utf8)
    }

    static func run(payload: Data, signedBy key: Curve25519.Signing.PrivateKey,
                    authority: VPNCompanionMetadataAuthority,
                    releaseID: String = "2.0.0", sequence: UInt64 = 9,
                    mutateSignature: Bool = false, status: Int = 200,
                    encoding: String? = nil) throws
        -> Result<VerifiedVPNCompanionMetadata, Error> {
        MetadataURLProtocol.metadata = payload
        var signed = try key.signature(
            for: VPNCompanionMetadataAuthority.signatureDomain + payload)
        if mutateSignature { signed[0] ^= 1 }
        MetadataURLProtocol.signature = Data(
            (signed.base64EncodedString() + "\n").utf8)
        MetadataURLProtocol.status = status
        MetadataURLProtocol.encoding = encoding
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [MetadataURLProtocol.self]
        let semaphore = DispatchSemaphore(value: 0)
        var outcome: Result<VerifiedVPNCompanionMetadata, Error>?
        var fetcher: VPNCompanionMetadataFetcher? = try .testStart(
            releaseID: releaseID, currentSequence: sequence,
            authority: authority, configuration: configuration) {
                outcome = $0; semaphore.signal()
            }
        try require(semaphore.wait(timeout: .now() + 10) == .success)
        withExtendedLifetime(fetcher) { }
        fetcher = nil
        return outcome!
    }

    static func mustFail(_ value: Result<VerifiedVPNCompanionMetadata, Error>) throws {
        if case .success = value {
            throw NSError(domain: "accepted invalid metadata", code: 2)
        }
    }

    static func main() throws {
        let key = Curve25519.Signing.PrivateKey()
        let authority = try VPNCompanionMetadataAuthority(
            trustedPublicKey: key.publicKey.rawRepresentation)
        let valid = try run(payload: payload(), signedBy: key,
                            authority: authority)
        switch valid {
        case .failure(let error): throw error
        case .success(let metadata):
            try require(metadata.version == "2.0.0")
            try require(metadata.fromSequence == 9 && metadata.toSequence == 10)
        }
        try mustFail(run(payload: payload(from: 8), signedBy: key,
                         authority: authority))
        try mustFail(run(payload: payload(version: "2.0.1"), signedBy: key,
                         authority: authority))
        try mustFail(run(payload: payload(), signedBy: key,
                         authority: authority, mutateSignature: true))
        try mustFail(run(payload: payload(), signedBy: key,
                         authority: authority, status: 500))
        try mustFail(run(payload: payload(), signedBy: key,
                         authority: authority, encoding: "gzip"))
        try mustFail(run(payload: Data(repeating: 1, count: 513),
                         signedBy: key, authority: authority))
        do {
            let configuration = URLSessionConfiguration.ephemeral
            _ = try VPNCompanionMetadataFetcher.testStart(
                releaseID: "2.00.0", currentSequence: 9,
                authority: authority, configuration: configuration) { _ in }
            throw NSError(domain: "accepted version", code: 3)
        } catch VPNCompanionMetadataFetcherError.invalidRequest { }
        print("vpn companion metadata fetcher checks passed")
    }
}
