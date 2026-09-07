import Darwin
import Foundation

enum VPNReleaseStoreError: Error {
    case unsafeStorage
    case busy
    case invalidState
    case alreadyInitialized
    case staleRevision
    case writeFailed
    case commitUncertain
    case deploymentRequired
}

struct VPNAuthorizedRelease {
    let ownerUserID: uid_t
    let release: VerifiedVPNRelease
}

/// A verified on-disk selection, NOT evidence of a running/healthy service.
struct VPNAuthorizedDeployment {
    let ownerUserID: uid_t
    let release: VerifiedVPNRelease
    let helperFileName: String
    fileprivate init(_ state: VPNAuthorizedRelease) {
        ownerUserID = state.ownerUserID
        release = state.release
        helperFileName = state.release.helperArtifactName
    }
}

/// Opaque, staged update. Possession does not authorize starting a process.
/// Commit always rechecks protected current state and the candidate file.
struct VPNPreparedDeployment {
    let previous: VPNAuthorizedDeployment
    let candidate: VPNAuthorizedDeployment
    fileprivate let payload: Data
    fileprivate let signature: Data
    fileprivate init(previous: VPNAuthorizedDeployment, candidate: VPNAuthorizedDeployment,
                     payload: Data, signature: Data) {
        self.previous = previous
        self.candidate = candidate
        self.payload = payload
        self.signature = signature
    }
}

/// A descriptor-relative policy store, NOT an installer or helper activator.
/// Production must supply a securely opened root-owned directory under fixed,
/// protected parents and run as root. Tests exercise the same checks using the
/// test process's UID and a private disposable directory. Never accept this fd
/// from IPC or use the unprivileged app's profile/preferences directory.
final class VPNReleaseStore {
    private struct Envelope: Codable {
        let schema: Int
        let owner: uid_t
        let payload: Data
        let signature: Data
    }
    private var directory: Int32
    private let storageOwner = geteuid()
    private let authority: VPNReleaseAuthority
    private static let marker = Data("ProxyPilot VPN release policy v1\n".utf8)
    private static let maximumRecordBytes = 8192
    private let recordName = "release.json"
    private let markerName = "initialized"

    #if VPN_RELEASE_STORE_TESTING
    // Compiled only into the crash-test executable, never into a release build.
    static var checkpoint: ((String) -> Void)?
    #endif

    init(trustedDirectoryDescriptor: Int32, authority: VPNReleaseAuthority) throws {
        directory = fcntl(trustedDirectoryDescriptor, F_DUPFD_CLOEXEC, 0)
        guard directory >= 0 else { throw VPNReleaseStoreError.unsafeStorage }
        self.authority = authority
        do { try checkDirectory() }
        catch { close(directory); directory = -1; throw error }
    }

    deinit { if directory >= 0 { close(directory) } }

    func load() throws -> VPNAuthorizedRelease {
        try withLock { try readCurrent().1 }
    }

    func loadDeployment() throws -> VPNAuthorizedDeployment {
        try withLock {
            let (envelope, state) = try readCurrent()
            guard envelope.schema == 2 else { throw VPNReleaseStoreError.deploymentRequired }
            return VPNAuthorizedDeployment(state)
        }
    }

    /// Validate and stage BEFORE interrupting the running version. This does
    /// not change the selected security floor or imply a successful update.
    func prepareDeployment(payload: Data, signature: Data, helper: Data,
                           expectedSequence: UInt64) throws -> VPNPreparedDeployment {
        try withLock {
            let (envelope, state) = try readCurrent()
            guard envelope.schema == 2 else { throw VPNReleaseStoreError.deploymentRequired }
            guard state.release.sequence == expectedSequence else { throw VPNReleaseStoreError.staleRevision }
            let release = try authority.verify(payload: payload, signature: signature, previous: state.release)
            try stageArtifact(helper, release: release)
            return VPNPreparedDeployment(previous: VPNAuthorizedDeployment(state),
                candidate: VPNAuthorizedDeployment(VPNAuthorizedRelease(ownerUserID: state.ownerUserID, release: release)),
                payload: payload, signature: signature)
        }
    }

    @discardableResult
    func commitPreparedDeployment(_ prepared: VPNPreparedDeployment) throws -> VPNAuthorizedDeployment {
        try withLock {
            let (envelope, current) = try readCurrent()
            guard envelope.schema == 2 else { throw VPNReleaseStoreError.deploymentRequired }
            guard current.ownerUserID == prepared.previous.ownerUserID,
                  current.release.isSameRelease(as: prepared.previous.release) else { throw VPNReleaseStoreError.staleRevision }
            let release = try authority.verify(payload: prepared.payload, signature: prepared.signature, previous: current.release)
            try validateStoredArtifact(release)
            let next = Envelope(schema: 2, owner: current.ownerUserID, payload: prepared.payload, signature: prepared.signature)
            if envelope.payload != next.payload { try replace(recordName, with: encode(next)) }
            else if fsync(directory) != 0 { throw VPNReleaseStoreError.commitUncertain }
            return VPNAuthorizedDeployment(VPNAuthorizedRelease(ownerUserID: current.ownerUserID, release: release))
        }
    }

    /// First-install authorization and protected parent provisioning are external.
    /// Both signatures and both architecture pins are checked before publishing
    /// a single record that selects the policy AND its content-addressed binary.
    @discardableResult
    func bootstrapDeployment(payload: Data, signature: Data, helper: Data,
                             trustedOwnerUserID: uid_t) throws -> VPNAuthorizedDeployment {
        try withLock {
            guard try readFile(markerName) == nil, try readFile(recordName) == nil else {
                throw VPNReleaseStoreError.alreadyInitialized
            }
            let release = try authority.verify(payload: payload, signature: signature, previous: nil)
            _ = try release.clientPolicy(forTrustedUserID: trustedOwnerUserID)
            try stageArtifact(helper, release: release)
            let envelope = Envelope(schema: 2, owner: trustedOwnerUserID, payload: payload, signature: signature)
            try replace(markerName, with: Self.marker)
            try replace(recordName, with: encode(envelope))
            return VPNAuthorizedDeployment(VPNAuthorizedRelease(ownerUserID: envelope.owner, release: release))
        }
    }

    /// Disk commit only. A future lifecycle coordinator must stop/drain old
    /// operations, check the candidate's startup and handle service recovery.
    /// No daemon or installer may interpret this return as "VPN connected".
    @discardableResult
    func commitDeployment(payload: Data, signature: Data, helper: Data,
                          expectedSequence: UInt64) throws -> VPNAuthorizedDeployment {
        try withLock {
            let (previous, current) = try readCurrent()
            guard previous.schema == 2 else { throw VPNReleaseStoreError.deploymentRequired }
            guard current.release.sequence == expectedSequence else { throw VPNReleaseStoreError.staleRevision }
            let release = try authority.verify(payload: payload, signature: signature, previous: current.release)
            try stageArtifact(helper, release: release)
            if previous.payload == payload {
                guard fsync(directory) == 0 else { throw VPNReleaseStoreError.commitUncertain }
                return VPNAuthorizedDeployment(current)
            }
            let next = Envelope(schema: 2, owner: previous.owner, payload: payload, signature: signature)
            try replace(recordName, with: encode(next))
            return VPNAuthorizedDeployment(VPNAuthorizedRelease(ownerUserID: next.owner, release: release))
        }
    }

    /// An installer may call this only after explicit first-install authority.
    /// A damaged/missing record never triggers this method automatically.
    @discardableResult
    func bootstrap(payload: Data, signature: Data, trustedOwnerUserID: uid_t) throws -> VPNAuthorizedRelease {
        try withLock {
            guard try readFile(markerName) == nil, try readFile(recordName) == nil else {
                throw VPNReleaseStoreError.alreadyInitialized
            }
            let verified = try authority.verify(payload: payload, signature: signature, previous: nil)
            _ = try verified.clientPolicy(forTrustedUserID: trustedOwnerUserID)
            let envelope = Envelope(schema: 1, owner: trustedOwnerUserID, payload: payload, signature: signature)
            let data = try encode(envelope)
            // Persist the marker first: interruption cannot turn an incomplete
            // installation into an apparently pristine store eligible for reset.
            try replace(markerName, with: Self.marker)
            try replace(recordName, with: data)
            return VPNAuthorizedRelease(ownerUserID: envelope.owner, release: verified)
        }
    }

    /// Persists an authorized policy only. It does not install/activate a helper.
    /// A future installer must coordinate this with binary activation/recovery;
    /// do not advance the floor merely because an update was downloaded.
    @discardableResult
    func accept(payload: Data, signature: Data, expectedSequence: UInt64) throws -> VPNAuthorizedRelease {
        try withLock {
            let (previous, current) = try readCurrent()
            guard previous.schema == 1 else { throw VPNReleaseStoreError.deploymentRequired }
            guard current.release.sequence == expectedSequence else { throw VPNReleaseStoreError.staleRevision }
            let verified = try authority.verify(payload: payload, signature: signature, previous: current.release)
            // Verification above authenticates the supplied signature. Release
            // identity is the payload, not signature bytes: a signer can produce
            // another valid signature for the same description.
            if previous.payload == payload {
                guard fsync(directory) == 0 else { throw VPNReleaseStoreError.commitUncertain }
                return current
            }
            // Ownership is retained from protected storage, never changed by an update.
            let next = Envelope(schema: 1, owner: previous.owner, payload: payload, signature: signature)
            try replace(recordName, with: encode(next))
            return VPNAuthorizedRelease(ownerUserID: next.owner, release: verified)
        }
    }

    private func readCurrent() throws -> (Envelope, VPNAuthorizedRelease) {
        guard try readFile(markerName) == Self.marker, let data = try readFile(recordName) else {
            throw VPNReleaseStoreError.invalidState
        }
        do {
            let envelope = try JSONDecoder().decode(Envelope.self, from: data)
            // Strict envelope too: reject unknown/duplicate fields and alternate
            // encodings rather than parsing ambiguous protected state.
            guard [1, 2].contains(envelope.schema), try encode(envelope) == data else { throw VPNReleaseStoreError.invalidState }
            let verified = try authority.verify(payload: envelope.payload, signature: envelope.signature, previous: nil)
            _ = try verified.clientPolicy(forTrustedUserID: envelope.owner)
            if envelope.schema == 2 { try validateStoredArtifact(verified) }
            return (envelope, VPNAuthorizedRelease(ownerUserID: envelope.owner, release: verified))
        } catch { throw VPNReleaseStoreError.invalidState }
    }

    private func stageArtifact(_ data: Data, release: VerifiedVPNRelease) throws {
        try release.validateHelperArtifact(data)
        let name = release.helperArtifactName
        if try readFile(name, limit: VPNReleaseAuthority.maximumHelperBytes, permissions: 0o700) == nil {
            try replace(name, with: data, permissions: 0o700) { file in
                try VPNHelperArtifact.validate(protectedFile: file, data: data, release: release)
            }
        }
        // Also recheck an existing content-addressed file. Never silently repair
        // corrupted/symlinked state or trust a file merely because its name fits.
        try validateStoredArtifact(release)
        guard fsync(directory) == 0 else { throw VPNReleaseStoreError.commitUncertain }
    }

    private func validateStoredArtifact(_ release: VerifiedVPNRelease) throws {
        let name = release.helperArtifactName
        guard let data = try readFile(name, limit: VPNReleaseAuthority.maximumHelperBytes, permissions: 0o700) else {
            throw VPNReleaseStoreError.invalidState
        }
        let file = openat(directory, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard file >= 0 else { throw VPNReleaseStoreError.unsafeStorage }
        defer { close(file) }
        try checkFile(file, permissions: 0o700)
        try VPNHelperArtifact.validate(protectedFile: file, data: data, release: release)
    }

    private func encode(_ envelope: Envelope) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let data = try encoder.encode(envelope)
        guard data.count <= Self.maximumRecordBytes else { throw VPNReleaseStoreError.invalidState }
        return data
    }

    private func checkDirectory() throws {
        var attributes = stat()
        guard geteuid() == storageOwner, fstat(directory, &attributes) == 0,
              attributes.st_mode & S_IFMT == S_IFDIR, attributes.st_nlink > 0,
              attributes.st_uid == storageOwner, attributes.st_mode & 0o7777 == 0o700 else {
            throw VPNReleaseStoreError.unsafeStorage
        }
        try checkNoACL(directory)
    }

    private func checkNoACL(_ file: Int32) throws {
        // Query the descriptor successfully first, then distinguish an absent
        // ACL property from a filesystem error. acl_get_fd_np conflates them.
        guard let security = filesec_init() else { throw VPNReleaseStoreError.unsafeStorage }
        defer { filesec_free(security) }
        var attributes = stat()
        guard fstatx_np(file, &attributes, security) == 0 else { throw VPNReleaseStoreError.unsafeStorage }
        var retrieved: acl_t?
        errno = 0
        let result = filesec_get_property(security, FILESEC_ACL, &retrieved)
        if result == -1, errno == ENOENT { return }
        guard result == 0, let acl = retrieved else { throw VPNReleaseStoreError.unsafeStorage }
        defer { acl_free(UnsafeMutableRawPointer(acl)) }
        var entry: acl_entry_t?
        errno = 0
        // Darwin returns -1/EINVAL when an otherwise valid ACL has no entries.
        guard acl_get_entry(acl, Int32(ACL_FIRST_ENTRY.rawValue), &entry) == -1, errno == EINVAL else {
            throw VPNReleaseStoreError.unsafeStorage
        }
    }

    private func checkFile(_ file: Int32, permissions: mode_t = 0o600) throws {
        var attributes = stat()
        guard fstat(file, &attributes) == 0, attributes.st_mode & S_IFMT == S_IFREG,
              attributes.st_nlink == 1, attributes.st_uid == storageOwner,
              attributes.st_mode & 0o7777 == permissions else { throw VPNReleaseStoreError.unsafeStorage }
        try checkNoACL(file)
    }

    private func withLock<T>(_ operation: () throws -> T) throws -> T {
        try checkDirectory()
        let lock = openat(directory, "release.lock", O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK, 0o600)
        guard lock >= 0 else { throw VPNReleaseStoreError.unsafeStorage }
        defer { close(lock) }
        try checkFile(lock)
        guard flock(lock, LOCK_EX | LOCK_NB) == 0 else { throw VPNReleaseStoreError.busy }
        defer { flock(lock, LOCK_UN) }
        return try operation()
    }

    private func readFile(_ name: String, limit: Int = VPNReleaseStore.maximumRecordBytes,
                          permissions: mode_t = 0o600) throws -> Data? {
        let file = openat(directory, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard file >= 0 else {
            if errno == ENOENT { return nil }
            throw VPNReleaseStoreError.unsafeStorage
        }
        defer { close(file) }
        try checkFile(file, permissions: permissions)
        var data = Data(), bytes = [UInt8](repeating: 0, count: 1024)
        while true {
            let count = read(file, &bytes, bytes.count)
            if count < 0, errno == EINTR { continue }
            guard count >= 0 else { throw VPNReleaseStoreError.invalidState }
            if count == 0 { return data }
            guard data.count + count <= limit else { throw VPNReleaseStoreError.invalidState }
            data.append(contentsOf: bytes.prefix(count))
        }
    }

    private func replace(_ name: String, with data: Data, permissions: mode_t = 0o600,
                         validating: ((Int32) throws -> Void)? = nil) throws {
        let temporary = ".release-\(UUID().uuidString).tmp"
        let file = openat(directory, temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, permissions)
        guard file >= 0 else { throw VPNReleaseStoreError.writeFailed }
        defer { close(file); unlinkat(directory, temporary, 0) }
        try checkFile(file, permissions: permissions)
        try data.withUnsafeBytes { bytes in
            var offset = 0
            while offset < bytes.count {
                let count = write(file, bytes.baseAddress!.advanced(by: offset), bytes.count - offset)
                if count < 0, errno == EINTR { continue }
                guard count > 0 else { throw VPNReleaseStoreError.writeFailed }
                offset += count
            }
        }
        try validating?(file)
        guard fsync(file) == 0 else { throw VPNReleaseStoreError.writeFailed }
        #if VPN_RELEASE_STORE_TESTING
        Self.checkpoint?(name + ":before-rename")
        #endif
        guard renameat(directory, temporary, directory, name) == 0 else { throw VPNReleaseStoreError.writeFailed }
        #if VPN_RELEASE_STORE_TESTING
        Self.checkpoint?(name + ":after-rename")
        #endif
        // Rename committed. Report an uncertain commit, NOT "previous state
        // unchanged", if metadata sync fails; caller must reload/reconcile.
        guard fsync(directory) == 0 else { throw VPNReleaseStoreError.commitUncertain }
    }
}
