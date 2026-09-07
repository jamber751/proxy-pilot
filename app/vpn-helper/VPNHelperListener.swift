import Darwin
import Dispatch
import Foundation

enum VPNHelperListenerError: Error { case unsafeStorage, unavailable, invalidTimeout }

/// Server side of the readiness handshake, inside the privileged helper. It is
/// not a command dispatcher: the only reachable behaviour is answering one fixed
/// 56-byte challenge with 56 bytes, and there is no path, argument, profile or
/// operation a caller can name. Every connection is authenticated as the owner's
/// signed application, bounded by a deadline, and served one at a time.
final class VPNHelperListener {
    static let socketName = VPNHelperProtocol.socketName
    private static let request = Array("PPVNRQ01".utf8)
    private static let response = Array("PPVNOK01".utf8)
    private var listener: Int32
    private let release: VerifiedVPNRelease
    private let policy: VPNPeerPolicy
    private let vault: VPNProfileVault

    /// Creates the fixed endpoint inside an already-protected directory. It never
    /// unlinks an existing socket: a stale endpoint means the supervisor did not
    /// confirm the previous stop, and quietly stealing it would hide that.
    static func bind(inTrustedDirectory trusted: Int32, release: VerifiedVPNRelease,
                     ownerUserID: uid_t) throws -> VPNHelperListener {
        let policy = try release.clientPolicy(forTrustedUserID: ownerUserID)
        let directory = fcntl(trusted, F_DUPFD_CLOEXEC, 0)
        guard directory >= 0 else { throw VPNHelperListenerError.unsafeStorage }
        defer { Darwin.close(directory) }
        var attributes = stat()
        guard fstat(directory, &attributes) == 0, attributes.st_mode & S_IFMT == S_IFDIR,
              attributes.st_uid == geteuid(), attributes.st_mode & 0o7777 == 0o700 else {
            throw VPNHelperListenerError.unsafeStorage
        }
        // bind(2) has no descriptor-relative form: resolve the path from the
        // checked descriptor and confirm the name still means that directory.
        var path = [CChar](repeating: 0, count: Int(MAXPATHLEN))
        var named = stat()
        guard fcntl(directory, F_GETPATH, &path) == 0 else { throw VPNHelperListenerError.unsafeStorage }
        let folder = String(cString: path)
        guard lstat(folder, &named) == 0, named.st_dev == attributes.st_dev,
              named.st_ino == attributes.st_ino else { throw VPNHelperListenerError.unsafeStorage }
        let endpoint = folder + "/" + socketName
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        let bytes = Array(endpoint.utf8) + [0]
        guard bytes.count <= MemoryLayout.size(ofValue: address.sun_path) else {
            throw VPNHelperListenerError.unsafeStorage
        }
        withUnsafeMutableBytes(of: &address.sun_path) { $0.copyBytes(from: bytes) }
        let socketDescriptor = socket(AF_UNIX, SOCK_STREAM, 0)
        guard socketDescriptor >= 0, fcntl(socketDescriptor, F_SETFD, FD_CLOEXEC) == 0 else {
            if socketDescriptor >= 0 { Darwin.close(socketDescriptor) }
            throw VPNHelperListenerError.unavailable
        }
        let previous = umask(0o177)
        let bound = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.bind(socketDescriptor, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        umask(previous)
        var created = stat()
        guard bound == 0, listen(socketDescriptor, 4) == 0,
              fstatat(directory, socketName, &created, AT_SYMLINK_NOFOLLOW) == 0,
              created.st_mode & S_IFMT == S_IFSOCK, created.st_uid == geteuid(),
              created.st_mode & 0o7777 == 0o600 else {
            Darwin.close(socketDescriptor)
            throw VPNHelperListenerError.unavailable
        }
        do {
            let vault = try VPNProfileVault(trustedDirectoryDescriptor: directory)
            return VPNHelperListener(listener: socketDescriptor, release: release, policy: policy, vault: vault)
        } catch {
            Darwin.close(socketDescriptor)
            throw VPNHelperListenerError.unsafeStorage
        }
    }

    private init(listener: Int32, release: VerifiedVPNRelease, policy: VPNPeerPolicy, vault: VPNProfileVault) {
        self.listener = listener
        self.release = release
        self.policy = policy
        self.vault = vault
    }

    deinit { close() }

    func close() {
        if listener >= 0 { Darwin.close(listener); listener = -1 }
    }

    /// Waits for one connection and answers at most one challenge. A rejected,
    /// slow or malformed peer costs that connection only: nothing is retried,
    /// nothing is remembered, and the listener stays available for the next one.
    /// `isReady` is asked immediately before replying, so the receipt reflects
    /// the helper's state at that moment rather than the fact it is running.
    @discardableResult
    func serveOnce(timeoutMilliseconds: Int = 2000, isReady: () -> Bool) throws -> Bool {
        guard (1...5000).contains(timeoutMilliseconds) else { throw VPNHelperListenerError.invalidTimeout }
        guard listener >= 0 else { throw VPNHelperListenerError.unavailable }
        let deadline = DispatchTime.now().uptimeNanoseconds + UInt64(timeoutMilliseconds) * 1_000_000
        try VPNHelperProtocol.wait(listener, events: Int16(POLLIN), deadline: deadline)
        let client = accept(listener, nil, nil)
        guard client >= 0 else { throw VPNHelperListenerError.unavailable }
        defer { Darwin.close(client) }
        guard fcntl(client, F_SETFD, FD_CLOEXEC) == 0 else { return false }
        var enabled: Int32 = 1
        guard setsockopt(client, SOL_SOCKET, SO_NOSIGPIPE, &enabled,
                         socklen_t(MemoryLayout.size(ofValue: enabled))) == 0 else { return false }
        do {
            try VPNPeerAuthentication.validate(connectedSocket: client, policy: policy)
            let challenge = try VPNHelperProtocol.read(count: 56, socket: client, deadline: deadline)
            guard Array(challenge.prefix(8)) == Self.request,
                  Array(challenge[8..<16]) == Self.encoded(release.protocolVersion),
                  Array(challenge[16..<24]) == Self.encoded(release.sequence) else { return false }
            // Answer only for the state at this instant. A running process is
            // not readiness, and a rejected answer must not be a stale success.
            guard isReady() else { return false }
            try VPNPeerAuthentication.validate(connectedSocket: client, policy: policy)
            try VPNHelperProtocol.write(Self.response + challenge.dropFirst(8), socket: client, deadline: deadline)
            // The peer re-checks our running signature and may then spend a
            // bounded number of typed requests; either way it closes first.
            try serveRequests(client, isReady: isReady)
            return true
        } catch { return false }
    }

    /// A bounded conversation: at most `maximumRequestsPerConnection` frames,
    /// each within the connection deadline, each re-authenticated and each bound
    /// to the release this helper is running. Anything unexpected ends it — the
    /// listener answers the next connection instead of parsing further.
    private func serveRequests(_ client: Int32, isReady: () -> Bool) throws {
        let conversation = DispatchTime.now().uptimeNanoseconds
            + UInt64(VPNHelperProtocol.conversationTimeoutMilliseconds) * 1_000_000
        for _ in 0..<VPNHelperProtocol.maximumRequestsPerConnection {
            let deadline = min(conversation, DispatchTime.now().uptimeNanoseconds
                + UInt64(VPNHelperProtocol.requestTimeoutMilliseconds) * 1_000_000)
            guard let header = try VPNHelperProtocol.read(count: VPNHelperProtocol.headerBytes, socket: client,
                                                          deadline: deadline, allowingClose: true) else { return }
            guard Array(header.prefix(8)) == VPNHelperProtocol.requestMagic else { return }
            let length = Int(VPNHelperProtocol.number(header[18..<22]))
            guard length <= VPNHelperProtocol.maximumPayloadBytes else { return }
            let payload = length == 0 ? []
                : try VPNHelperProtocol.read(count: length, socket: client, deadline: deadline)
            try VPNPeerAuthentication.validate(connectedSocket: client, policy: policy)
            // A client that believes it is talking to another build is answered
            // with a refusal, never with an operation meant for that build.
            // A refusal is still an answer: break to the farewell below rather
            // than closing here, or the reset would lose the answer we just sent.
            guard VPNHelperProtocol.number(header[10..<18]) == release.sequence else {
                try answer(.invalidRequest, payload: [], to: client, deadline: deadline)
                break
            }
            guard let operation = VPNHelperOperation(rawValue: UInt16(VPNHelperProtocol.number(header[8..<10]))) else {
                try answer(.unsupported, payload: [], to: client, deadline: deadline)
                break
            }
            switch operation {
            case .status:
                guard payload.isEmpty else {
                    try answer(.invalidRequest, payload: [], to: client, deadline: deadline)
                    break
                }
                // Reaching this point already means the helper answered its
                // readiness challenge, so the answer is the release it serves.
                _ = isReady()
                let body = VPNHelperProtocol.encode(release.sequence)
                    + VPNHelperProtocol.encode(release.protocolVersion)
                try answer(.ok, payload: body, to: client, deadline: deadline)
            case .storeProfile:
                // The client's own import decided nothing: the helper inspects
                // the bytes again with the same importer before keeping them.
                // Rejection leaves the previously stored profile untouched.
                guard !payload.isEmpty,
                      let profile = try? VPNProfileImporter.inspect(data: Data(payload), name: "profile.ovpn"),
                      (try? vault.save(profile.protectedContents)) != nil else {
                    try answer(.invalidRequest, payload: [], to: client, deadline: deadline)
                    break
                }
                try answer(.ok, payload: [], to: client, deadline: deadline)
            }
        }
        // The budget is spent, but the peer still has to read the last answer.
        // Closing here would reset the connection and lose it, so wait briefly
        // for the peer to hang up first; a peer that lingers only costs itself.
        let farewell = DispatchTime.now().uptimeNanoseconds
            + UInt64(VPNHelperProtocol.requestTimeoutMilliseconds) * 1_000_000
        _ = try? VPNHelperProtocol.read(count: 1, socket: client, deadline: farewell, allowingClose: true)
    }

    private func answer(_ status: VPNHelperStatus, payload: [UInt8], to client: Int32, deadline: UInt64) throws {
        try VPNPeerAuthentication.validate(connectedSocket: client, policy: policy)
        try VPNHelperProtocol.write(VPNHelperProtocol.response(status, payload: payload),
                                    socket: client, deadline: deadline)
    }

    private static func encoded(_ value: UInt64) -> [UInt8] {
        (0..<8).reversed().map { UInt8(truncatingIfNeeded: value >> ($0 * 8)) }
    }
}
