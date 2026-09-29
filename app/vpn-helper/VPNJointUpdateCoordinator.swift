import Dispatch
import Foundation

enum VPNJointUpdateCoordinatorError: Error {
    case alreadyStarted, cancelled, brokerRefused, indeterminate
    case mismatchedReady
}

/// Ordinary-user orchestration only. It owns transport resources but receives
/// no path, URL, command or VPN authority from the updater worker.
final class VPNJointUpdateCoordinator {
    enum Progress { case metadata, downloading, verifying, submitting }
    typealias ProgressHandler = (Progress) -> Void
    typealias Completion = (Result<Void, Error>) -> Void

    private let queue = DispatchQueue(
        label: "kz.documentolog.proxypilot.joint-update")
    private let releaseID: String
    private let sealedSequence: UInt64
    private let progressHandler: ProgressHandler
    private let completion: Completion
    private var metadataFetcher: VPNCompanionMetadataFetcher?
    private var downloader: VPNCompanionDownloader?
    private var downloaded: VPNDownloadedCompanion?
    private var mount: VPNJointArtifactMount?
    private var started = false
    private var finished = false
    private var submitting = false

    init(releaseID: String, sealedSequence: UInt64,
         progress: @escaping ProgressHandler,
         completion: @escaping Completion) {
        self.releaseID = releaseID
        self.sealedSequence = sealedSequence
        progressHandler = progress
        self.completion = completion
    }

    func start() {
        queue.async { [weak self] in self?.startOnQueue() }
    }

    func cancel() {
        queue.async { [weak self] in
            guard let self, !self.finished else { return }
            // Once SCM_RIGHTS was sent, cancellation cannot prove whether the
            // Broker copied the inbox. Keep the mount for a bounded grace and
            // report an indeterminate result instead of pretending to cancel.
            if self.submitting {
                self.retainIndeterminateMount()
                return
            }
            self.metadataFetcher?.cancel()
            self.downloader?.cancel()
            self.finish(.failure(VPNJointUpdateCoordinatorError.cancelled))
        }
    }

    private func startOnQueue() {
        guard !started, !finished else {
            finish(.failure(VPNJointUpdateCoordinatorError.alreadyStarted)); return
        }
        started = true
        report(.metadata)
        do {
            metadataFetcher = try VPNCompanionMetadataFetcher.start(
                releaseID: releaseID, currentSequence: sealedSequence) {
                    [weak self] result in
                    self?.queue.async { self?.receivedMetadata(result) }
                }
        } catch { finish(.failure(error)) }
    }

    private func receivedMetadata(
        _ result: Result<VerifiedVPNCompanionMetadata, Error>) {
        guard !finished else { return }
        metadataFetcher = nil
        switch result {
        case .failure(let error): finish(.failure(error))
        case .success(let metadata):
            report(.downloading)
            do {
                downloader = try VPNCompanionDownloader.start(
                    metadata: metadata) { [weak self] result in
                        self?.queue.async {
                            self?.receivedDownload(result, metadata: metadata)
                        }
                    }
            } catch { finish(.failure(error)) }
        }
    }

    private func receivedDownload(
        _ result: Result<VPNDownloadedCompanion, Error>,
        metadata: VerifiedVPNCompanionMetadata) {
        guard !finished else { return }
        downloader = nil
        switch result {
        case .failure(let error): finish(.failure(error))
        case .success(let artifact):
            downloaded = artifact
            report(.verifying)
            do {
                mount = try artifact.withFileDescriptor {
                    try VPNJointArtifactMount.open(
                        artifactFile: $0,
                        deadline: DispatchTime.now().uptimeNanoseconds
                            + 30_000_000_000)
                }
            } catch { finish(.failure(error)); return }
            report(.submitting)
            submitting = true
            guard let directory = mount?.directory else {
                finish(.failure(VPNJointUpdateCoordinatorError.brokerRefused)); return
            }
            do {
                let outcome = try VPNUpdateBrokerClient.submit(
                    candidateDirectory: directory,
                    expectedFromSequence: sealedSequence,
                    deadline: DispatchTime.now().uptimeNanoseconds
                        + 120_000_000_000)
                submitting = false
                switch outcome {
                case .response(let response):
                    guard response.state == .ready,
                          response.fromSequence == metadata.fromSequence,
                          response.toSequence == metadata.toSequence,
                          response.revision > 0 else {
                        finish(.failure(
                            VPNJointUpdateCoordinatorError.mismatchedReady)); return
                    }
                    // Broker no longer depends on the mount after durable ready.
                    mount = nil; downloaded = nil
                    finish(.success(()))
                case .indeterminate:
                    retainIndeterminateMount()
                }
            } catch {
                submitting = false
                finish(.failure(error))
            }
        }
    }

    private func retainIndeterminateMount() {
        guard !finished else { return }
        submitting = false
        // Do not terminate A or retry. The bounded retention lets a Broker that
        // already received SCM_RIGHTS finish copying before detach cleanup.
        finished = true
        DispatchQueue.main.async {
            self.completion(.failure(VPNJointUpdateCoordinatorError.indeterminate))
        }
        queue.asyncAfter(deadline: .now() + 120) { [self] in
            mount = nil; downloaded = nil
            metadataFetcher = nil; downloader = nil
        }
    }

    private func report(_ progress: Progress) {
        DispatchQueue.main.async { [progressHandler] in progressHandler(progress) }
    }

    private func finish(_ result: Result<Void, Error>) {
        guard !finished else { return }
        finished = true
        metadataFetcher = nil; downloader = nil
        mount = nil; downloaded = nil
        DispatchQueue.main.async { [completion] in completion(result) }
    }
}
