import CryptoKit
import Darwin
import Dispatch
import Foundation

final class CoordinatorURLProtocol: URLProtocol {
    static var metadata = Data()
    static var signature = Data()
    static var artifact = Data()

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest {
        request
    }

    override func startLoading() {
        let name = request.url!.lastPathComponent
        let body: Data
        if name.hasSuffix(".metadata.sig") { body = Self.signature }
        else if name.hasSuffix(".metadata") { body = Self.metadata }
        else { body = Self.artifact }
        let response = HTTPURLResponse(
            url: request.url!, statusCode: 200, httpVersion: "HTTP/1.1",
            headerFields: ["Content-Length": String(body.count)])!
        client?.urlProtocol(self, didReceive: response,
                            cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: body)
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() { }
}

@main
enum VPNJointUpdateCoordinatorRuntimeChecks {
    private static let fromSequence: UInt64 = 122
    private static let toSequence: UInt64 = 123
    private static let releaseID = "2.0.0"
    private static let expectedNames: Set<String> = [
        "ProxyPilot.app", "vpn-helper", "vpn-engine",
        "vpn-release.manifest", "vpn-release.sig",
        "vpn-previous-release.manifest", "vpn-previous-release.sig",
        "vpn-update-transition", "vpn-update-transition.sig",
    ]

    final class BrokerObservation {
        private let lock = NSLock()
        private var calls = 0
        private var serverResult: Result<Void, Error>?

        func called() { lock.withLock { calls += 1 } }
        func completed(_ result: Result<Void, Error>) {
            lock.withLock { serverResult = result }
        }
        func snapshot() -> (Int, Result<Void, Error>?) {
            lock.withLock { (calls, serverResult) }
        }
    }

    static func require(_ condition: @autoclosure () -> Bool,
                        _ message: String) throws {
        guard condition() else {
            throw NSError(domain: "joint-coordinator-runtime", code: 1,
                          userInfo: [NSLocalizedDescriptionKey: message])
        }
    }

    static func configuration() -> URLSessionConfiguration {
        let value = URLSessionConfiguration.ephemeral
        value.protocolClasses = [CoordinatorURLProtocol.self]
        return value
    }

    static func metadata(artifact: Data,
                         key: Curve25519.Signing.PrivateKey,
                         corruptDigest: Bool = false) throws
        -> (Data, Data, VPNCompanionMetadataAuthority) {
        var digest = Data(SHA256.hash(data: artifact))
        if corruptDigest { digest[0] ^= 1 }
        let hex = digest.map { String(format: "%02x", $0) }.joined()
        let payload = Data((
            "format=1\nproduct=kz.documentolog.proxypilot\n"
            + "version=\(releaseID)\nfrom-sequence=\(fromSequence)\n"
            + "to-sequence=\(toSequence)\nartifact-sha256=\(hex)\n"
            + "artifact-bytes=\(artifact.count)\n").utf8)
        let signed = try key.signature(
            for: VPNCompanionMetadataAuthority.signatureDomain + payload)
        return (payload, Data((signed.base64EncodedString() + "\n").utf8),
                try VPNCompanionMetadataAuthority(
                    trustedPublicKey: key.publicKey.rawRepresentation))
    }

    static func brokerSocket(observation: BrokerObservation) throws -> Int32 {
        var pair: [Int32] = [-1, -1]
        guard socketpair(AF_UNIX, SOCK_STREAM, 0, &pair) == 0 else {
            throw NSError(domain: "socketpair", code: Int(errno))
        }
        do {
            for descriptor in pair {
                guard fcntl(descriptor, F_SETFD, FD_CLOEXEC) == 0,
                      fcntl(descriptor, F_SETFL, O_NONBLOCK) == 0 else {
                    throw NSError(domain: "socket-flags", code: Int(errno))
                }
            }
        } catch {
            close(pair[0]); close(pair[1]); throw error
        }
        observation.called()
        let server = pair[1]
        DispatchQueue.global(qos: .userInitiated).async {
            defer { close(server) }
            do {
                let deadline = DispatchTime.now().uptimeNanoseconds
                    + 30_000_000_000
                let received = try VPNUpdateBrokerTransport.testReceive(
                    socket: server, authenticatedPeerUserID: geteuid(),
                    deadline: deadline)
                try require(received.request.operation == .submit,
                            "broker received a non-submit request")
                try require(received.request.expectedFromSequence == fromSequence,
                            "broker received the wrong source sequence")
                let directory = try received.takeCandidateDirectory()
                defer { close(directory) }
                var filesystem = statfs()
                try require(fstatfs(directory, &filesystem) == 0,
                            "cannot inspect mounted filesystem")
                let required = UInt32(MNT_LOCAL | MNT_RDONLY)
                try require(filesystem.f_flags & required == required,
                            "candidate is not a local read-only mount")
                let names = try directoryNames(directory)
                try require(names == expectedNames,
                            "mounted joint payload has an unexpected layout")
                try VPNUpdateBrokerTransport.send(
                    VPNUpdateBrokerResponse(
                        state: .ready, fromSequence: fromSequence,
                        toSequence: toSequence, revision: 1),
                    socket: server, deadline: deadline)
                observation.completed(.success(()))
            } catch {
                observation.completed(.failure(error))
            }
        }
        return pair[0]
    }

    static func directoryNames(_ directory: Int32) throws -> Set<String> {
        let copy = openat(directory, ".",
            O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard copy >= 0, let stream = fdopendir(copy) else {
            if copy >= 0 { close(copy) }
            throw NSError(domain: "directory", code: Int(errno))
        }
        defer { closedir(stream) }
        var result = Set<String>()
        while let entry = readdir(stream) {
            let name = withUnsafePointer(to: &entry.pointee.d_name) {
                $0.withMemoryRebound(to: CChar.self, capacity: 1024) {
                    String(cString: $0)
                }
            }
            if name != "." && name != ".." { result.insert(name) }
        }
        return result
    }

    static func waitForCompletion(
        artifact: Data, authority: VPNCompanionMetadataAuthority,
        observation: BrokerObservation) throws
        -> (Result<Void, Error>, [VPNJointUpdateCoordinator.Progress]) {
        CoordinatorURLProtocol.artifact = artifact
        let runtime = VPNJointUpdateCoordinator.TestRuntime(
            metadataConfiguration: configuration(),
            metadataAuthority: authority,
            downloadConfiguration: configuration(),
            brokerSocket: { try brokerSocket(observation: observation) })
        var result: Result<Void, Error>?
        var progress: [VPNJointUpdateCoordinator.Progress] = []
        var coordinator: VPNJointUpdateCoordinator? =
            VPNJointUpdateCoordinator(
                releaseID: releaseID, sealedSequence: fromSequence,
                testRuntime: runtime,
                progress: { progress.append($0) },
                completion: { result = $0 })
        coordinator!.start()
        let deadline = Date().addingTimeInterval(60)
        while result == nil && Date() < deadline {
            RunLoop.current.run(mode: .default,
                                before: Date().addingTimeInterval(0.02))
        }
        withExtendedLifetime(coordinator) { }
        coordinator = nil
        guard let result else {
            throw NSError(domain: "coordinator-timeout", code: 1)
        }
        return (result, progress)
    }

    static func assertSuccess(_ result: Result<Void, Error>) throws {
        if case .failure(let error) = result { throw error }
    }

    static func assertFailure(_ result: Result<Void, Error>) throws {
        if case .success = result {
            throw NSError(domain: "unexpected-success", code: 1)
        }
    }

    static func waitForServer(_ observation: BrokerObservation) throws
        -> (Int, Result<Void, Error>) {
        let deadline = Date().addingTimeInterval(5)
        while Date() < deadline {
            let current = observation.snapshot()
            if let result = current.1 { return (current.0, result) }
            RunLoop.current.run(mode: .default,
                                before: Date().addingTimeInterval(0.01))
        }
        throw NSError(domain: "broker-timeout", code: 1)
    }

    static func progressName(_ progress: VPNJointUpdateCoordinator.Progress)
        -> String {
        switch progress {
        case .metadata: return "metadata"
        case .downloading: return "downloading"
        case .verifying: return "verifying"
        case .submitting: return "submitting"
        }
    }

    static func main() throws {
        guard CommandLine.arguments.count == 2 else { exit(64) }
        let artifact = try Data(contentsOf:
            URL(fileURLWithPath: CommandLine.arguments[1]))
        let key = Curve25519.Signing.PrivateKey()

        let valid = try metadata(artifact: artifact, key: key)
        CoordinatorURLProtocol.metadata = valid.0
        CoordinatorURLProtocol.signature = valid.1
        let observation = BrokerObservation()
        let successful = try waitForCompletion(
            artifact: artifact, authority: valid.2,
            observation: observation)
        try assertSuccess(successful.0)
        try require(successful.1.map(progressName) == [
            "metadata", "downloading", "verifying", "submitting"],
                    "coordinator progress order changed")
        let accepted = try waitForServer(observation)
        try require(accepted.0 == 1, "broker was not called exactly once")
        try assertSuccess(accepted.1)

        let corrupt = try metadata(
            artifact: artifact, key: key, corruptDigest: true)
        CoordinatorURLProtocol.metadata = corrupt.0
        CoordinatorURLProtocol.signature = corrupt.1
        let refusedObservation = BrokerObservation()
        let refused = try waitForCompletion(
            artifact: artifact, authority: corrupt.2,
            observation: refusedObservation)
        try assertFailure(refused.0)
        try require(refusedObservation.snapshot().0 == 0,
                    "invalid artifact reached the broker")
        try require(refused.1.map(progressName) == ["metadata", "downloading"],
                    "invalid artifact advanced beyond download verification")

        print("vpn joint update coordinator runtime checks passed")
    }
}
