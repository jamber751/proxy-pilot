import Foundation

enum VPNCompanionMetadataFetcherError: Error {
    case invalidRequest, invalidResponse, oversized, invalidSignature
    case redirectRefused, cancelled, transport
}

/// Fetches two fixed, bounded release sidecars. Neither response can choose a
/// host, path, artifact URL or VPN sequence; all such values are derived or
/// checked against the sealed application A and the embedded release key.
final class VPNCompanionMetadataFetcher: NSObject, URLSessionDataDelegate,
    URLSessionTaskDelegate {
    typealias Completion = (Result<VerifiedVPNCompanionMetadata, Error>) -> Void
    private enum Phase { case metadata, signature }

    private let releaseID: String
    private let currentSequence: UInt64
    private let authority: VPNCompanionMetadataAuthority
    private let completion: Completion
    private let delegateQueue: OperationQueue
    private var phase = Phase.metadata
    private var buffer = Data()
    private var metadataPayload: Data?
    private var initialURL: URL
    private var redirectCount = 0
    private var finished = false
    private var session: URLSession!
    private var task: URLSessionDataTask!

    static func start(releaseID: String, currentSequence: UInt64,
                      timeout: TimeInterval = 30,
                      completion: @escaping Completion) throws
        -> VPNCompanionMetadataFetcher {
        guard timeout >= 1, timeout <= 120 else {
            throw VPNCompanionMetadataFetcherError.invalidRequest
        }
        let configuration = URLSessionConfiguration.ephemeral
        configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
        configuration.urlCache = nil
        configuration.httpCookieStorage = nil
        configuration.httpShouldSetCookies = false
        configuration.urlCredentialStorage = nil
        configuration.httpMaximumConnectionsPerHost = 1
        configuration.timeoutIntervalForRequest = min(timeout, 15)
        configuration.timeoutIntervalForResource = timeout
        return try Self(
            releaseID: releaseID, currentSequence: currentSequence,
            authority: VPNCompanionMetadataAuthority.trusted(),
            configuration: configuration, completion: completion)
    }

    private init(releaseID: String, currentSequence: UInt64,
                 authority: VPNCompanionMetadataAuthority,
                 configuration: URLSessionConfiguration,
                 completion: @escaping Completion) throws {
        guard Self.canonicalVersion(releaseID), currentSequence > 0 else {
            throw VPNCompanionMetadataFetcherError.invalidRequest
        }
        self.releaseID = releaseID
        self.currentSequence = currentSequence
        self.authority = authority
        self.completion = completion
        initialURL = Self.url(releaseID: releaseID, signature: false)
        delegateQueue = OperationQueue()
        delegateQueue.name = "kz.documentolog.proxypilot.companion-metadata"
        delegateQueue.maxConcurrentOperationCount = 1
        delegateQueue.qualityOfService = .utility
        super.init()
        session = URLSession(configuration: configuration, delegate: self,
                             delegateQueue: delegateQueue)
        startTask()
    }

    func cancel() {
        delegateQueue.addOperation { [weak self] in
            self?.fail(VPNCompanionMetadataFetcherError.cancelled)
        }
    }

    private func startTask() {
        var request = URLRequest(url: initialURL)
        request.httpMethod = "GET"
        request.cachePolicy = .reloadIgnoringLocalCacheData
        request.setValue("identity", forHTTPHeaderField: "Accept-Encoding")
        task = session.dataTask(with: request)
        task.resume()
    }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask,
                    didReceive response: URLResponse,
                    completionHandler: @escaping (URLSession.ResponseDisposition) -> Void) {
        let limit = phase == .metadata
            ? VPNCompanionMetadataAuthority.maximumPayloadBytes : 89
        guard !finished, dataTask.taskIdentifier == task.taskIdentifier,
              let http = response as? HTTPURLResponse,
              http.statusCode == 200, let finalURL = http.url,
              Self.validResponseURL(finalURL, initial: initialURL),
              Self.identityEncoding(http.value(
                forHTTPHeaderField: "Content-Encoding")),
              http.expectedContentLength == NSURLSessionTransferSizeUnknown
                || (http.expectedContentLength > 0
                    && http.expectedContentLength <= Int64(limit)) else {
            completionHandler(.cancel)
            fail(VPNCompanionMetadataFetcherError.invalidResponse)
            return
        }
        completionHandler(.allow)
    }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask,
                    didReceive data: Data) {
        let limit = phase == .metadata
            ? VPNCompanionMetadataAuthority.maximumPayloadBytes : 89
        guard !finished, dataTask.taskIdentifier == task.taskIdentifier,
              data.count <= limit - buffer.count else {
            fail(VPNCompanionMetadataFetcherError.oversized)
            return
        }
        buffer.append(data)
    }

    func urlSession(_ session: URLSession, task: URLSessionTask,
                    willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest,
                    completionHandler: @escaping (URLRequest?) -> Void) {
        guard !finished, let source = response.url, let target = request.url,
              redirectCount < 3,
              Self.validRedirect(from: source, to: target,
                                 method: request.httpMethod ?? "") else {
            completionHandler(nil)
            fail(VPNCompanionMetadataFetcherError.redirectRefused)
            return
        }
        redirectCount += 1
        var clean = request
        clean.httpMethod = "GET"
        clean.setValue(nil, forHTTPHeaderField: "Authorization")
        clean.setValue(nil, forHTTPHeaderField: "Cookie")
        clean.setValue("identity", forHTTPHeaderField: "Accept-Encoding")
        completionHandler(clean)
    }

    func urlSession(_ session: URLSession, task completedTask: URLSessionTask,
                    didCompleteWithError error: Error?) {
        guard !finished, completedTask.taskIdentifier == task.taskIdentifier else { return }
        guard error == nil, !buffer.isEmpty else {
            fail(error ?? VPNCompanionMetadataFetcherError.transport)
            return
        }
        switch phase {
        case .metadata:
            metadataPayload = buffer
            buffer.removeAll(keepingCapacity: true)
            phase = .signature
            redirectCount = 0
            initialURL = Self.url(releaseID: releaseID, signature: true)
            startTask()
        case .signature:
            guard let payload = metadataPayload,
                  let text = String(data: buffer, encoding: .utf8),
                  text.utf8.count == 89, text.last == "\n",
                  let signature = Data(base64Encoded: String(text.dropLast())),
                  signature.count == 64,
                  signature.base64EncodedString() + "\n" == text,
                  let metadata = try? authority.verify(
                    payload: payload, signature: signature),
                  metadata.version == releaseID,
                  metadata.fromSequence == currentSequence else {
                fail(VPNCompanionMetadataFetcherError.invalidSignature)
                return
            }
            finish(.success(metadata))
        }
    }

    private func fail(_ error: Error) {
        guard !finished else { return }
        task?.cancel()
        finish(.failure(error))
    }

    private func finish(_ result: Result<VerifiedVPNCompanionMetadata, Error>) {
        guard !finished else { return }
        finished = true
        buffer.removeAll(); metadataPayload = nil
        completion(result)
        session?.finishTasksAndInvalidate()
    }

    private static func url(releaseID: String, signature: Bool) -> URL {
        let name = "ProxyPilot-\(releaseID)-vpn-joint.metadata"
            + (signature ? ".sig" : "")
        return URL(string: "https://github.com/jamber751/proxy-pilot/releases/download/v\(releaseID)/\(name)")!
    }

    private static func canonicalVersion(_ value: String) -> Bool {
        let parts = value.components(separatedBy: ".")
        return parts.count == 3 && parts.allSatisfy { part in
            !part.isEmpty && part.utf8.count <= 19
                && (part == "0" || !part.hasPrefix("0"))
                && part.utf8.allSatisfy { (48...57).contains($0) }
                && UInt64(part).map { $0 <= UInt64(Int64.max) } == true
        }
    }

    private static func validResponseURL(_ url: URL, initial: URL) -> Bool {
        url == initial || validCDN(url)
    }

    private static func validRedirect(from: URL, to: URL,
                                      method: String) -> Bool {
        guard method == "GET", from.scheme == "https" else { return false }
        if from.host == "github.com" {
            return (to == from || validCDN(to))
        }
        return validCDN(from) && validCDN(to)
    }

    private static func validCDN(_ url: URL) -> Bool {
        url.scheme == "https"
            && url.host == "release-assets.githubusercontent.com"
            && (url.port == nil || url.port == 443)
            && url.user == nil && url.password == nil
            && url.fragment == nil && !url.path.isEmpty
    }

    private static func identityEncoding(_ value: String?) -> Bool {
        guard let value else { return true }
        return value.trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased() == "identity"
    }

    #if VPN_COMPANION_METADATA_FETCHER_TESTING
    static func testStart(releaseID: String, currentSequence: UInt64,
                          authority: VPNCompanionMetadataAuthority,
                          configuration: URLSessionConfiguration,
                          completion: @escaping Completion) throws -> Self {
        try Self(releaseID: releaseID, currentSequence: currentSequence,
                 authority: authority, configuration: configuration,
                 completion: completion)
    }
    #endif
}
