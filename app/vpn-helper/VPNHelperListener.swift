import Darwin
import Dispatch
import Foundation

enum VPNHelperListenerError: Error { case unsafeStorage, unavailable, invalidTimeout }

/// Authenticated readiness and bounded owner commands inside the helper. The
/// root installation role gets readiness only. The owner's signed application
/// may then use the typed protocol; no shell/path/launch arguments are accepted.
final class VPNHelperListener {
    static let socketName = VPNHelperProtocol.socketName
    private static let request = Array("PPVNRQ01".utf8)
    private static let response = Array("PPVNOK01".utf8)
    private var listener: Int32
    private let release: VerifiedVPNRelease
    private let policy: VPNPeerPolicy
    private let installerPolicy: VPNPeerPolicy
    private let additionalReadinessPolicies: () throws -> [VPNPeerPolicy]
    private let vault: VPNProfileVault
    private let tunnelState: VPNTunnelStateStore
    private let startTunnel: () throws -> Bool
    private let startManagedTunnel: ((VPNConnectAttemptBinding, VPNTunnelStateStore) throws -> Bool)?
    private let submitManagedCredential: ((inout VPNCredentialResponse, VPNTunnelStateStore) throws -> Void)?
    private let stopTunnel: () throws -> Void
    private let tunnelIsOwned: () -> Bool
    private var tunnelStopped = true

    #if VPN_HELPER_LISTENER_TESTING
    private var fixtureInstaller = false
    // Exercises the readiness-only dispatch path without elevating a fixture.
    // Production still authenticates root UID + exact app pin for this role.
    static func testBindInstaller(inTrustedDirectory directory: Int32, release: VerifiedVPNRelease,
                                  ownerUserID: uid_t,
                                  additionalReadinessPolicies: @escaping () throws -> [VPNPeerPolicy] = { [] },
                                  startTunnel: @escaping () throws -> Bool = { false },
                                  startManagedTunnel: ((VPNConnectAttemptBinding, VPNTunnelStateStore) throws -> Bool)? = nil,
                                  submitManagedCredential: ((inout VPNCredentialResponse, VPNTunnelStateStore) throws -> Void)? = nil,
                                  stopTunnel: @escaping () throws -> Void = {},
                                  tunnelIsOwned: @escaping () -> Bool = { false }) throws
        -> VPNHelperListener {
        let listener = try bind(inTrustedDirectory: directory, release: release,
                                ownerUserID: ownerUserID,
                                additionalReadinessPolicies: additionalReadinessPolicies,
                                startTunnel: startTunnel,
                                startManagedTunnel: startManagedTunnel,
                                submitManagedCredential: submitManagedCredential,
                                stopTunnel: stopTunnel,
                                tunnelIsOwned: tunnelIsOwned)
        listener.fixtureInstaller = true
        return listener
    }

    /// Fixture-only runtime seam. It tests ordering at the authenticated
    /// listener boundary without starting OpenVPN or changing the system.
    static func bind(inTrustedDirectory trusted: Int32, release: VerifiedVPNRelease,
                     ownerUserID: uid_t, endpointDirectory: Int32? = nil,
                     additionalReadinessPolicies: @escaping () throws -> [VPNPeerPolicy] = { [] },
                     startTunnel: @escaping () throws -> Bool = { false },
                     startManagedTunnel: ((VPNConnectAttemptBinding, VPNTunnelStateStore) throws -> Bool)? = nil,
                     submitManagedCredential: ((inout VPNCredentialResponse, VPNTunnelStateStore) throws -> Void)? = nil,
                     stopTunnel: @escaping () throws -> Void = {},
                     tunnelIsOwned: @escaping () -> Bool = { false }) throws -> VPNHelperListener {
        try bindCommon(inTrustedDirectory: trusted, release: release,
                       ownerUserID: ownerUserID, endpointDirectory: endpointDirectory,
                       additionalReadinessPolicies: additionalReadinessPolicies,
                       startTunnel: startTunnel,
                       startManagedTunnel: startManagedTunnel,
                       submitManagedCredential: submitManagedCredential,
                       stopTunnel: stopTunnel,
                       tunnelIsOwned: tunnelIsOwned)
    }
    #endif

    /// Keeps the vault private; root uses the separate fixed IPC directory. It never
    /// unlinks an existing socket: a stale endpoint means the supervisor did not
    /// confirm the previous stop, and quietly stealing it would hide that.
    #if !VPN_HELPER_LISTENER_TESTING
    static func bind(inTrustedDirectory trusted: Int32, deployment: VPNAuthorizedDeployment,
                     ownerUserID: uid_t, endpointDirectory: Int32? = nil,
                     runtimeLease: VPNLifecycleLease,
                     additionalReadinessPolicies: @escaping () throws -> [VPNPeerPolicy] = { [] }) throws
        -> VPNHelperListener {
        guard deployment.ownerUserID == ownerUserID else {
            throw VPNHelperListenerError.unsafeStorage
        }
        let coordinator: VPNTunnelCoordinator?
        if deployment.engineFileName == nil { coordinator = nil }
        else {
            let state = try VPNTunnelStateStore(trustedDirectoryDescriptor: trusted)
            let journal = try VPNRouteJournal(trustedDirectoryDescriptor: trusted)
            let kernel = try VPNDarwinRouteSocket.production()
            let transaction = VPNRouteTransaction(journal: journal, kernel: kernel,
                                                  runtimeLease: runtimeLease)
            let resolver = try VPNPeerRouteEvidenceResolver.production()
            let routes = VPNTunnelRouteController(state: state, resolver: resolver,
                transaction: transaction, runtimeLease: runtimeLease)
            coordinator = try VPNTunnelCoordinator(
                trustedDirectoryDescriptor: trusted, deployment: deployment,
                state: state, routeController: routes)
        }
        return try bindCommon(inTrustedDirectory: trusted, release: deployment.release,
                              ownerUserID: ownerUserID, endpointDirectory: endpointDirectory,
                              additionalReadinessPolicies: additionalReadinessPolicies,
                              startTunnel: { false },
                              startManagedTunnel: { _, _ in
                                  guard let coordinator = coordinator else { return false }
                                  // Leave time inside the authenticated request
                                  // deadline to return a deterministic refusal.
                                  switch try coordinator.start(timeoutMilliseconds: 4_000) {
                                  case .bootstrapReady, .blocked(.credentialRequired): return true
                                  default: return false
                                  }
                              }, submitManagedCredential: { response, _ in
                                  guard let coordinator = coordinator else {
                                      response.secret.resetBytes(in: 0..<response.secret.count)
                                      response.secret.removeAll(keepingCapacity: false)
                                      throw VPNHelperListenerError.unavailable
                                  }
                                  _ = try coordinator.submitCredential(&response,
                                      timeoutMilliseconds: 4_000)
                              }, stopTunnel: { _ = try coordinator?.stop() },
                              tunnelIsOwned: { coordinator?.ownsProcess() == true })
    }
    #endif

    private static func bindCommon(inTrustedDirectory trusted: Int32, release: VerifiedVPNRelease,
                     ownerUserID: uid_t, endpointDirectory: Int32?,
                     additionalReadinessPolicies: @escaping () throws -> [VPNPeerPolicy],
                     startTunnel: @escaping () throws -> Bool,
                     startManagedTunnel: ((VPNConnectAttemptBinding, VPNTunnelStateStore) throws -> Bool)?,
                     submitManagedCredential: ((inout VPNCredentialResponse, VPNTunnelStateStore) throws -> Void)?,
                     stopTunnel: @escaping () throws -> Void,
                     tunnelIsOwned: @escaping () -> Bool) throws -> VPNHelperListener {
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
        let shared = endpointDirectory != nil || geteuid() == 0
        let endpointFD: Int32
        if let supplied = endpointDirectory { endpointFD = fcntl(supplied, F_DUPFD_CLOEXEC, 0) }
        else if geteuid() == 0 { endpointFD = try VPNEndpointDirectory.openSystem(create: true) }
        else { endpointFD = fcntl(directory, F_DUPFD_CLOEXEC, 0) }
        guard endpointFD >= 0 else { throw VPNHelperListenerError.unsafeStorage }
        defer { Darwin.close(endpointFD) }
        let endpointFolder = try VPNEndpointDirectory.checkedPath(endpointFD, owner: geteuid(), shared: shared)
        let endpoint = endpointFolder + "/" + socketName
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
        let previous = umask(shared ? 0o111 : 0o177)
        let bound = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.bind(socketDescriptor, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        umask(previous)
        var created = stat()
        guard bound == 0, listen(socketDescriptor, 4) == 0,
              fstatat(endpointFD, socketName, &created, AT_SYMLINK_NOFOLLOW) == 0,
              created.st_mode & S_IFMT == S_IFSOCK, created.st_uid == geteuid(),
              created.st_mode & 0o7777 == (shared ? 0o666 : 0o600) else {
            Darwin.close(socketDescriptor)
            throw VPNHelperListenerError.unavailable
        }
        do {
            let vault = try VPNProfileVault(trustedDirectoryDescriptor: directory)
            let tunnelState = try VPNTunnelStateStore(trustedDirectoryDescriptor: directory)
            _ = try tunnelState.invalidateChallengeAfterRestart()
            return VPNHelperListener(listener: socketDescriptor, release: release, policy: policy,
                                     installerPolicy: try release.installerPolicy(),
                                     additionalReadinessPolicies: additionalReadinessPolicies,
                                     vault: vault, tunnelState: tunnelState,
                                     startTunnel: startTunnel,
                                     startManagedTunnel: startManagedTunnel,
                                     submitManagedCredential: submitManagedCredential,
                                     stopTunnel: stopTunnel,
                                     tunnelIsOwned: tunnelIsOwned)
        } catch {
            Darwin.close(socketDescriptor)
            throw VPNHelperListenerError.unsafeStorage
        }
    }

    private init(listener: Int32, release: VerifiedVPNRelease, policy: VPNPeerPolicy,
                 installerPolicy: VPNPeerPolicy,
                 additionalReadinessPolicies: @escaping () throws -> [VPNPeerPolicy],
                 vault: VPNProfileVault, tunnelState: VPNTunnelStateStore,
                 startTunnel: @escaping () throws -> Bool,
                 startManagedTunnel: ((VPNConnectAttemptBinding, VPNTunnelStateStore) throws -> Bool)?,
                 submitManagedCredential: ((inout VPNCredentialResponse, VPNTunnelStateStore) throws -> Void)?,
                 stopTunnel: @escaping () throws -> Void,
                 tunnelIsOwned: @escaping () -> Bool) {
        self.listener = listener
        self.release = release
        self.policy = policy
        self.installerPolicy = installerPolicy
        self.additionalReadinessPolicies = additionalReadinessPolicies
        self.vault = vault
        self.tunnelState = tunnelState
        self.startTunnel = startTunnel
        self.startManagedTunnel = startManagedTunnel
        self.submitManagedCredential = submitManagedCredential
        self.stopTunnel = stopTunnel
        self.tunnelIsOwned = tunnelIsOwned
    }

    deinit { close() }

    func close() {
        if !tunnelStopped {
            try? stopTunnel()
            tunnelStopped = !tunnelIsOwned()
        }
        if listener >= 0 { Darwin.close(listener); listener = -1 }
    }

    /// Waits for one connection and answers at most one challenge. A rejected,
    /// slow or malformed peer costs that connection only: nothing is retried,
    /// nothing is remembered, and the listener stays available for the next one.
    /// `isReady` is asked immediately before replying, so the receipt reflects
    /// the helper's state at that moment rather than the fact it is running.
    @discardableResult
    func serveOnce(timeoutMilliseconds: Int = 2000, isReady: () -> Bool,
                   allowOwnerRequests: () -> Bool = { true }) throws -> Bool {
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
            var peerUID: uid_t = 0, peerGID: gid_t = 0
            guard getpeereid(client, &peerUID, &peerGID) == 0 else { return false }
            var installationProbe = peerUID == 0
            func rootReadinessPolicy() throws -> VPNPeerPolicy {
                if (try? VPNPeerAuthentication.validate(
                        connectedSocket: client, policy: installerPolicy)) != nil {
                    return installerPolicy
                }
                let additional = try additionalReadinessPolicies()
                guard additional.count <= 2 else {
                    throw VPNPeerAuthenticationError.denied
                }
                for candidate in additional {
                    if (try? VPNPeerAuthentication.validate(
                            connectedSocket: client, policy: candidate)) != nil {
                        return candidate
                    }
                }
                throw VPNPeerAuthenticationError.denied
            }
            var connectionPolicy = installationProbe ? try rootReadinessPolicy() : policy
            #if VPN_HELPER_LISTENER_TESTING
            if fixtureInstaller {
                installationProbe = true
                if (try? VPNPeerAuthentication.validate(
                        connectedSocket: client, policy: policy)) != nil {
                    connectionPolicy = policy
                } else {
                    let additional = try additionalReadinessPolicies()
                    guard additional.count <= 2,
                          let matched = additional.first(where: {
                              (try? VPNPeerAuthentication.validate(
                                  connectedSocket: client, policy: $0)) != nil
                          }) else {
                        throw VPNPeerAuthenticationError.denied
                    }
                    connectionPolicy = matched
                }
            }
            #endif
            if !installationProbe {
                try VPNPeerAuthentication.validate(
                    connectedSocket: client, policy: connectionPolicy)
            }
            let challenge = try VPNHelperProtocol.read(count: 56, socket: client, deadline: deadline)
            guard Array(challenge.prefix(8)) == Self.request,
                  Array(challenge[8..<16]) == Self.encoded(release.protocolVersion),
                  Array(challenge[16..<24]) == Self.encoded(release.sequence) else { return false }
            // During late update recovery, only the authenticated root installer
            // may obtain readiness. The ordinary owner must not cross from a
            // provisional helper into status/profile operations until the
            // terminal journal has been retired.
            guard installationProbe || allowOwnerRequests() else { return false }
            // Answer only for the state at this instant. A running process is
            // not readiness, and a rejected answer must not be a stale success.
            guard isReady() else { return false }
            if installationProbe {
                #if VPN_HELPER_LISTENER_TESTING
                if fixtureInstaller {
                    let baseStillMatches = (try? VPNPeerAuthentication.validate(
                        connectedSocket: client, policy: policy)) != nil
                    if !baseStillMatches {
                        let current = try additionalReadinessPolicies()
                        guard current.count <= 2,
                              current.contains(where: {
                                  (try? VPNPeerAuthentication.validate(
                                      connectedSocket: client, policy: $0)) != nil
                              }) else { throw VPNPeerAuthenticationError.denied }
                    }
                } else {
                    connectionPolicy = try rootReadinessPolicy()
                }
                #else
                connectionPolicy = try rootReadinessPolicy()
                #endif
            } else {
                try VPNPeerAuthentication.validate(connectedSocket: client, policy: connectionPolicy)
            }
            try VPNHelperProtocol.write(Self.response + challenge.dropFirst(8), socket: client, deadline: deadline)
            // The root installation role ends here. It never enters the owner's
            // command dispatcher, even if extra request bytes are already queued.
            if installationProbe {
                _ = try? VPNHelperProtocol.read(count: 1, socket: client, deadline: deadline, allowingClose: true)
                return true
            }
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
            var payload = length == 0 ? []
                : try VPNHelperProtocol.read(count: length, socket: client, deadline: deadline)
            defer { Self.wipe(&payload) }
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
            case .applyConfiguration:
                guard tunnelStopped else {
                    try answer(.failed, payload: [], to: client, deadline: deadline)
                    break
                }
                guard let spec = try? VPNApplicationSpec.decodeCanonical(Data(payload)),
                      let profileBytes = try? vault.load(digest: spec.profileSHA256),
                      let profile = try? VPNProfileImporter.inspect(data: profileBytes, name: "profile.ovpn"),
                      profile.supports(authentication: spec.authentication),
                      (try? tunnelState.stage(VPNValidatedApplication(
                        spec: spec, requiresVPNCredentials: profile.requiresCredentials,
                        requiresPrivateKeyPassword: profile.requiresKeyPassword))) != nil else {
                    try answer(.invalidRequest, payload: [], to: client, deadline: deadline)
                    break
                }
                try answer(.ok, payload: [], to: client, deadline: deadline)
            case .connect:
                guard payload.isEmpty, let snapshot = try? tunnelState.load(),
                      let application = snapshot.pending ?? snapshot.active else {
                    try answer(.invalidRequest, payload: [], to: client, deadline: deadline)
                    break
                }
                if !tunnelStopped {
                    try answer(.notReady, payload: [], to: client, deadline: deadline)
                    break
                }
                if let startManagedTunnel = startManagedTunnel {
                    guard let binding = try? tunnelState.beginConnect() else {
                        try answer(.failed, payload: [], to: client, deadline: deadline)
                        break
                    }
                    let started: Bool
                    do {
                        started = try startManagedTunnel(binding, tunnelState)
                    } catch {
                        if tunnelIsOwned() { try? stopTunnel() }
                        tunnelStopped = !tunnelIsOwned()
                        _ = try? tunnelState.failCurrent()
                        try answer(.failed, payload: [], to: client, deadline: deadline)
                        break
                    }
                    tunnelStopped = !tunnelIsOwned()
                    guard started, let fresh = try? tunnelState.load() else {
                        if tunnelIsOwned() { try? stopTunnel() }
                        tunnelStopped = !tunnelIsOwned()
                        _ = try? tunnelState.failCurrent()
                        try answer(.failed, payload: [], to: client, deadline: deadline)
                        break
                    }
                    if fresh.phase == .needsCredential,
                       let challenge = fresh.challenge,
                       let body = try? challenge.encoded() {
                        try answer(.needsCredential, payload: [UInt8](body),
                                   to: client, deadline: deadline)
                    } else {
                        try answer(.notReady, payload: [], to: client, deadline: deadline)
                    }
                    break
                }
                let kind: VPNCredentialKind? = application.requiresPrivateKeyPassword
                    ? .privateKeyPassword
                    : (application.requiresVPNCredentials ? .vpnPassword : nil)
                guard let begun = try? tunnelState.beginConnect(challengeKind: kind) else {
                    try answer(.failed, payload: [], to: client, deadline: deadline)
                    break
                }
                if let challenge = begun.challenge, let body = try? challenge.encoded() {
                    try answer(.needsCredential, payload: [UInt8](body), to: client, deadline: deadline)
                } else {
                    let started: Bool
                    do {
                        started = try startTunnel()
                    } catch {
                        tunnelStopped = !tunnelIsOwned()
                        _ = try? tunnelState.failCurrent()
                        try answer(.failed, payload: [], to: client, deadline: deadline)
                        break
                    }
                    guard started else {
                        tunnelStopped = !tunnelIsOwned()
                        _ = try? tunnelState.failCurrent()
                        try answer(.failed, payload: [], to: client, deadline: deadline)
                        break
                    }
                    tunnelStopped = false
                    // Bootstrap proof is internal only. Routes and scoped DNS
                    // are not yet committed, so the public state stays not ready.
                    try answer(.notReady, payload: [], to: client, deadline: deadline)
                }
            case .disconnect:
                guard payload.isEmpty else {
                    try answer(.invalidRequest, payload: [], to: client, deadline: deadline)
                    break
                }
                do {
                    if submitManagedCredential == nil || tunnelIsOwned() {
                        try stopTunnel()
                    }
                    tunnelStopped = !tunnelIsOwned()
                    guard tunnelStopped else { throw VPNHelperListenerError.unavailable }
                    try tunnelState.disconnect()
                } catch {
                    try answer(.failed, payload: [], to: client, deadline: deadline)
                    break
                }
                try answer(.ok, payload: [], to: client, deadline: deadline)
            case .tunnelStatus:
                guard payload.isEmpty, let snapshot = try? tunnelState.load(),
                      let body = try? snapshot.encoded() else {
                    try answer(.failed, payload: [], to: client, deadline: deadline)
                    break
                }
                try answer(.ok, payload: [UInt8](body), to: client, deadline: deadline)
            case .submitCredential:
                guard var response = try? VPNCredentialResponse.decode(Data(payload)) else {
                    try answer(.invalidRequest, payload: [], to: client, deadline: deadline)
                    break
                }
                if let submitManagedCredential = submitManagedCredential {
                    do {
                        try submitManagedCredential(&response, tunnelState)
                        tunnelStopped = !tunnelIsOwned()
                        let fresh = try tunnelState.load()
                        if fresh.phase == .needsCredential,
                           let challenge = fresh.challenge,
                           let body = try? challenge.encoded() {
                            try answer(.needsCredential, payload: [UInt8](body),
                                       to: client, deadline: deadline)
                        } else {
                            try answer(.notReady, payload: [], to: client, deadline: deadline)
                        }
                    } catch {
                        response.secret.resetBytes(in: 0..<response.secret.count)
                        response.secret.removeAll(keepingCapacity: false)
                        if tunnelIsOwned() { try? stopTunnel() }
                        tunnelStopped = !tunnelIsOwned()
                        _ = try? tunnelState.failCurrent()
                        try answer(.failed, payload: [], to: client, deadline: deadline)
                    }
                    break
                }
                // Consume first. Even an unusable credential can never be retried
                // against this challenge, and its bytes never enter durable state.
                guard (try? tunnelState.consume(response.challenge)) != nil else {
                    response.secret.resetBytes(in: 0..<response.secret.count)
                    try answer(.invalidRequest, payload: [], to: client, deadline: deadline)
                    break
                }
                response.secret.resetBytes(in: 0..<response.secret.count)
                try answer(.notReady, payload: [], to: client, deadline: deadline)
            case .cancelCredential:
                guard let challenge = try? VPNCredentialChallenge.decodeCanonical(Data(payload)) else {
                    try answer(.invalidRequest, payload: [], to: client, deadline: deadline)
                    break
                }
                if submitManagedCredential != nil {
                    guard let snapshot = try? tunnelState.load(),
                          snapshot.challenge == challenge,
                          let binding = snapshot.attempt else {
                        try answer(.invalidRequest, payload: [], to: client, deadline: deadline)
                        break
                    }
                    do {
                        if tunnelIsOwned() { try stopTunnel() }
                        tunnelStopped = !tunnelIsOwned()
                        guard tunnelStopped else { throw VPNHelperListenerError.unavailable }
                        _ = try tunnelState.cancelAttempt(binding)
                    } catch {
                        tunnelStopped = !tunnelIsOwned()
                        try answer(.failed, payload: [], to: client, deadline: deadline)
                        break
                    }
                } else if (try? tunnelState.cancel(challenge)) == nil {
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

    private static func wipe(_ bytes: inout [UInt8]) {
        bytes.withUnsafeMutableBytes { buffer in
            if let base = buffer.baseAddress, !buffer.isEmpty {
                _ = memset_s(base, buffer.count, 0, buffer.count)
            }
        }
        bytes.removeAll(keepingCapacity: false)
    }
}
