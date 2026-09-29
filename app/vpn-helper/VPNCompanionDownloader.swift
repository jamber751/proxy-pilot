import Foundation

enum VPNCompanionDownloaderError: Error {
    case invalidRequest, invalidResponse, redirectRefused, cancelled, transport
}

/// Transport integrity only. Root authority remains the signed payload that the
/// Broker revalidates after read-only mount.
final class VPNCompanionDownloader: NSObject, URLSessionDataDelegate,
    URLSessionTaskDelegate {
    typealias Completion = (Result<VPNDownloadedCompanion, Error>) -> Void

    private let metadata: VerifiedVPNCompanionMetadata
    private let initialURL: URL
    private let completion: Completion
    private let delegateQueue: OperationQueue
    private var staging: VPNCompanionStaging?
    private var session: URLSession!
    private var task: URLSessionDataTask!
    private var redirectCount = 0
    private var finished = false

    static func start(metadata: VerifiedVPNCompanionMetadata,
                      timeout: TimeInterval = 120,
                      completion: @escaping Completion) throws
        -> VPNCompanionDownloader {
        guard timeout >= 1, timeout <= 300 else {
            throw VPNCompanionDownloaderError.invalidRequest
        }
        let configuration = URLSessionConfiguration.ephemeral
        configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
        configuration.urlCache = nil
        configuration.httpCookieStorage = nil
        configuration.httpShouldSetCookies = false
        configuration.urlCredentialStorage = nil
        configuration.httpMaximumConnectionsPerHost = 1
        configuration.timeoutIntervalForRequest = min(timeout, 30)
        configuration.timeoutIntervalForResource = timeout
        return try VPNCompanionDownloader(
            metadata: metadata, configuration: configuration,
            completion: completion)
    }

    private init(metadata: VerifiedVPNCompanionMetadata,
                 configuration: URLSessionConfiguration,
                 completion: @escaping Completion) throws {
        self.metadata = metadata
        initialURL = metadata.artifactURL
        self.completion = completion
        staging = try VPNCompanionStaging(expectedBytes: metadata.artifactBytes)
        delegateQueue = OperationQueue()
        delegateQueue.name = "kz.documentolog.proxypilot.companion-download"
        delegateQueue.maxConcurrentOperationCount = 1
        delegateQueue.qualityOfService = .utility
        super.init()
        guard Self.validInitial(initialURL) else {
            throw VPNCompanionDownloaderError.invalidRequest
        }
        session = URLSession(
            configuration: configuration, delegate: self,
            delegateQueue: delegateQueue)
        var request = URLRequest(url: initialURL)
        request.httpMethod = "GET"
        request.cachePolicy = .reloadIgnoringLocalCacheData
        request.setValue("identity", forHTTPHeaderField: "Accept-Encoding")
        task = session.dataTask(with: request)
        task.resume()
    }

    func cancel() {
        delegateQueue.addOperation { [weak self] in
            self?.fail(VPNCompanionDownloaderError.cancelled)
        }
    }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask,
                    didReceive response: URLResponse,
                    completionHandler: @escaping (URLSession.ResponseDisposition) -> Void) {
        guard !finished,
              let http = response as? HTTPURLResponse,
              http.statusCode == 200,
              let finalURL = http.url,
              Self.validResponseURL(finalURL, initial: initialURL),
              Self.identityEncoding(http.value(
                forHTTPHeaderField: "Content-Encoding")),
              http.expectedContentLength == NSURLSessionTransferSizeUnknown
                || UInt64(http.expectedContentLength) == metadata.artifactBytes else {
            completionHandler(.cancel)
            fail(VPNCompanionDownloaderError.invalidResponse)
            return
        }
        completionHandler(.allow)
    }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask,
                    didReceive data: Data) {
        guard !finished, let staging else { return }
        do { try staging.append(data) }
        catch { fail(error) }
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
            fail(VPNCompanionDownloaderError.redirectRefused)
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

    func urlSession(_ session: URLSession, task: URLSessionTask,
                    didCompleteWithError error: Error?) {
        guard !finished else { return }
        guard error == nil, let staging else {
            fail(error ?? VPNCompanionDownloaderError.transport)
            return
        }
        do {
            let artifact = try staging.finish(metadata: metadata)
            self.staging = nil
            finish(.success(artifact))
        } catch { fail(error) }
    }

    private func fail(_ error: Error) {
        guard !finished else { return }
        staging = nil
        task?.cancel()
        finish(.failure(error))
    }

    private func finish(_ result: Result<VPNDownloadedCompanion, Error>) {
        guard !finished else { return }
        finished = true
        completion(result)
        session?.finishTasksAndInvalidate()
    }

    private static func validInitial(_ url: URL) -> Bool {
        guard url.scheme == "https", url.host == "github.com",
              url.port == nil || url.port == 443,
              url.user == nil, url.password == nil,
              url.query == nil, url.fragment == nil else { return false }
        return url.path.hasPrefix("/jamber751/proxy-pilot/releases/download/v")
            && url.lastPathComponent.hasPrefix("ProxyPilot-")
            && url.lastPathComponent.hasSuffix("-vpn-joint.dmg")
    }

    private static func validResponseURL(_ url: URL, initial: URL) -> Bool {
        if url == initial { return true }
        return validCDN(url)
    }

    private static func validRedirect(from: URL, to: URL,
                                      method: String) -> Bool {
        guard method == "GET", from.scheme == "https" else { return false }
        if from.host == "github.com" {
            return validInitial(from) && (to == from || validCDN(to))
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

    #if VPN_COMPANION_DOWNLOADER_TESTING
    static func testStart(metadata: VerifiedVPNCompanionMetadata,
                          configuration: URLSessionConfiguration,
                          completion: @escaping Completion) throws -> Self {
        try Self(metadata: metadata, configuration: configuration,
                 completion: completion)
    }

    static func testRedirect(from: URL, to: URL, method: String) -> Bool {
        validRedirect(from: from, to: to, method: method)
    }
    #endif
}
