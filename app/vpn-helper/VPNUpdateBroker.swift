import Darwin
import Foundation

enum VPNUpdateBrokerError: Error {
    case malformedRequest
    case missingDirectoryDescriptor
    case extraDirectoryDescriptor
    case unsafeDirectory
    case unexpectedSibling
    case invalidLayout
    case staleExpectedSequence
    case invalidAuthorization
}

#if !VPN_UPDATE_BROKER_TESTING
struct VPNUpdateBrokerAuthorization {
    let payload: VPNJointUpdatePayload
    let selected: VPNAuthorizedDeployment
    let existingJournal: VPNUpdateJournalSnapshot?
    let application: VPNStagedApplicationInspection
}
#endif

/// First, deliberately inert broker boundary. It validates the descriptor-only
/// request and exact top-level candidate layout; it does not copy, execute,
/// install, stop VPN, or mutate protected state. Signed artifact verification
/// and root-private copying are the next layer and must complete before this can
/// be wired to a launchd endpoint.
enum VPNUpdateBroker {
    static let fixedLayout: Set<String> = [
        "ProxyPilot.app",
        "vpn-helper",
        "vpn-engine",
        "vpn-release.manifest",
        "vpn-release.sig",
        "vpn-previous-release.manifest",
        "vpn-previous-release.sig",
        "vpn-update-transition",
        "vpn-update-transition.sig",
    ]

    static func validateSubmission(requestBytes: [UInt8],
                                   directoryDescriptors: [Int32]) throws
        -> VPNUpdateBrokerRequest {
        let request: VPNUpdateBrokerRequest
        do { request = try VPNUpdateBrokerProtocol.decodeRequest(requestBytes) }
        catch { throw VPNUpdateBrokerError.malformedRequest }
        guard request.operation == .submit else {
            throw VPNUpdateBrokerError.malformedRequest
        }
        guard !directoryDescriptors.isEmpty else {
            throw VPNUpdateBrokerError.missingDirectoryDescriptor
        }
        guard directoryDescriptors.count == 1 else {
            throw VPNUpdateBrokerError.extraDirectoryDescriptor
        }
        try validateCandidateDirectory(directoryDescriptors[0])
        return request
    }

    static func validateCandidateDirectory(_ directory: Int32) throws {
        var root = stat(), filesystem = statfs()
        guard fstat(directory, &root) == 0,
              root.st_mode & S_IFMT == S_IFDIR,
              root.st_nlink > 0,
              root.st_mode & 0o0022 == 0,
              fstatfs(directory, &filesystem) == 0,
              filesystem.f_flags & UInt32(MNT_LOCAL) != 0 else {
            throw VPNUpdateBrokerError.unsafeDirectory
        }
        try requireNoACL(directory)

        let opened = openat(directory, ".",
                            O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard opened >= 0, let stream = fdopendir(opened) else {
            if opened >= 0 { close(opened) }
            throw VPNUpdateBrokerError.unsafeDirectory
        }
        defer { closedir(stream) }
        var names = Set<String>()
        let nameOffset = MemoryLayout<dirent>.offset(of: \.d_name)!
        while true {
            errno = 0
            guard let entry = readdir(stream) else {
                guard errno == 0 else { throw VPNUpdateBrokerError.unsafeDirectory }
                break
            }
            let recordLength = Int(entry.pointee.d_reclen)
            let nameLength = Int(entry.pointee.d_namlen)
            guard nameLength > 0, nameLength <= 1023,
                  nameOffset <= recordLength,
                  nameLength < recordLength - nameOffset else {
                throw VPNUpdateBrokerError.invalidLayout
            }
            let bytes = UnsafeRawPointer(entry).advanced(by: nameOffset)
                .assumingMemoryBound(to: UInt8.self)
            guard bytes[nameLength] == 0 else {
                throw VPNUpdateBrokerError.invalidLayout
            }
            let view = UnsafeBufferPointer(start: bytes, count: nameLength)
            guard !view.contains(0), !view.contains(47),
                  let name = String(bytes: view, encoding: .utf8) else {
                throw VPNUpdateBrokerError.invalidLayout
            }
            if name == "." || name == ".." { continue }
            guard Self.fixedLayout.contains(name), names.insert(name).inserted else {
                throw VPNUpdateBrokerError.unexpectedSibling
            }
        }
        guard names == Self.fixedLayout else {
            throw VPNUpdateBrokerError.invalidLayout
        }

        for name in Self.fixedLayout {
            var item = stat()
            guard fstatat(directory, name, &item, AT_SYMLINK_NOFOLLOW) == 0,
                  item.st_mode & 0o0022 == 0,
                  item.st_nlink > 0 else {
                throw VPNUpdateBrokerError.invalidLayout
            }
            let expected = name == "ProxyPilot.app" ? S_IFDIR : S_IFREG
            guard item.st_mode & S_IFMT == expected,
                  expected == S_IFDIR || item.st_nlink == 1 else {
                throw VPNUpdateBrokerError.invalidLayout
            }
            let child = openat(directory, name,
                O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK
                    | (expected == S_IFDIR ? O_DIRECTORY : 0))
            guard child >= 0 else { throw VPNUpdateBrokerError.invalidLayout }
            do { try requireNoACL(child) }
            catch { close(child); throw error }
            close(child)
        }
    }

    #if !VPN_UPDATE_BROKER_TESTING
    /// Rechecks a completed root-private copy immediately before preparation.
    /// This method still performs no mutation. The copy layer must call it while
    /// exclusively owning the inbox, then pass the same descriptor and result to
    /// `VPNJointUpdatePreparation` without reopening a caller-controlled path.
    static func authorizePrivateInbox(
        _ candidateDirectory: Int32,
        expectedFromSequence: UInt64,
        serviceDirectory: Int32,
        authority: VPNReleaseAuthority
    ) throws -> VPNUpdateBrokerAuthorization {
        guard getuid() == 0, geteuid() == 0 else {
            throw VPNUpdateBrokerError.invalidAuthorization
        }
        try validateCandidateDirectory(candidateDirectory)
        let payload = try VPNJointUpdatePayload.loadForBroker(
            inTrustedDirectory: candidateDirectory, authority: authority)
        let store = try VPNReleaseStore(
            trustedDirectoryDescriptor: serviceDirectory, authority: authority)
        let selected = try store.loadDeployment()
        guard selected.release.sequence == expectedFromSequence else {
            throw VPNUpdateBrokerError.staleExpectedSequence
        }
        guard payload.previous.sequence == expectedFromSequence,
              selected.release.isSameRelease(as: payload.previous),
              payload.transition.matchesSource(selected.release),
              payload.transition.matchesDestination(payload.candidate.release) else {
            throw VPNUpdateBrokerError.invalidAuthorization
        }

        let existing = try store.loadUpdateJournal()
        if let existing {
            let resumable = existing.phase == .prepared
                && existing.recovery == .canCancelOrReplace
                || existing.phase == .replacementPending
                && existing.recovery == .inspectApplication
            guard resumable,
                  existing.previous.ownerUserID == selected.ownerUserID,
                  existing.candidate.ownerUserID == selected.ownerUserID,
                  existing.previous.release.isSameRelease(as: selected.release),
                  existing.candidate.release.isSameRelease(as: payload.candidate.release),
                  existing.transition.matchesSource(selected.release),
                  existing.transition.matchesDestination(payload.candidate.release) else {
                throw VPNUpdateBrokerError.invalidAuthorization
            }
        }

        // The loader already validates both executable artifacts while their
        // descriptors and bytes are stable. Repeat those exact component checks
        // here to keep this authorization boundary self-contained.
        let helper = openat(candidateDirectory, "vpn-helper",
                            O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard helper >= 0 else { throw VPNUpdateBrokerError.invalidLayout }
        defer { close(helper) }
        try VPNHelperArtifact.validate(
            protectedFile: helper, data: payload.candidate.helper,
            release: payload.candidate.release)
        if let engineData = payload.candidate.engine {
            let engine = openat(candidateDirectory, "vpn-engine",
                                O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
            guard engine >= 0 else { throw VPNUpdateBrokerError.invalidLayout }
            defer { close(engine) }
            try VPNEngineArtifact.validate(
                protectedFile: engine, data: engineData,
                release: payload.candidate.release)
        }
        let application = try VPNStagedApplication.inspect(
            inTrustedDirectory: candidateDirectory,
            release: payload.candidate.release)
        return VPNUpdateBrokerAuthorization(
            payload: payload, selected: selected, existingJournal: existing,
            application: application)
    }
    #endif

    private static func requireNoACL(_ descriptor: Int32) throws {
        var info = stat()
        guard let security = filesec_init() else {
            throw VPNUpdateBrokerError.unsafeDirectory
        }
        defer { filesec_free(security) }
        guard fstatx_np(descriptor, &info, security) == 0 else {
            throw VPNUpdateBrokerError.unsafeDirectory
        }
        var acl: acl_t?
        errno = 0
        let result = filesec_get_property(security, FILESEC_ACL, &acl)
        if result == -1, errno == ENOENT { return }
        guard result == 0, let acl else {
            throw VPNUpdateBrokerError.unsafeDirectory
        }
        defer { acl_free(UnsafeMutableRawPointer(acl)) }
        var entry: acl_entry_t?
        errno = 0
        guard acl_get_entry(acl, Int32(ACL_FIRST_ENTRY.rawValue), &entry) == -1,
              errno == EINVAL else {
            throw VPNUpdateBrokerError.unsafeDirectory
        }
    }
}

#if VPN_UPDATE_BROKER_CONTRACT_TESTING
/// Contract adapter only. It makes the security surface executable without
/// granting test fixtures root access or pretending that copy/install exists.
final class VPNUpdateBrokerContractHarness: VPNUpdateBrokerContractDriving {
    static let fixedLayout = VPNUpdateBroker.fixedLayout
    private var transaction: UInt64?

    required init() throws {}

    func submit(_ request: SubmitRequest,
                mutation: CandidateMutation) throws -> SubmitResult {
        guard request.expectedFromSequence == 41 else {
            return .rejected(.staleExpectedSequence)
        }
        switch mutation {
        case .none:
            if let transaction { return .alreadyAccepted(transaction: transaction) }
            transaction = 1
            return .accepted(transaction: 1)
        case .unexpectedSibling: return .rejected(.unexpectedSibling)
        case .wrongTransitionSignature: return .rejected(.wrongTransitionSignature)
        case .wrongTransitionSource: return .rejected(.wrongTransitionSource)
        case .wrongTransitionDestination: return .rejected(.wrongTransitionDestination)
        case .tamperedApplication: return .rejected(.tamperedApplication)
        case .tamperedHelper: return .rejected(.tamperedHelper)
        case .tamperedEngine: return .rejected(.tamperedEngine)
        }
    }

    func malformedField(name: String, value: String) throws -> SubmitResult {
        .rejected(.malformedRequest)
    }

    func submitWithoutDescriptor(expectedFromSequence: UInt64) throws -> SubmitResult {
        .rejected(.missingDirectoryDescriptor)
    }

    func submitWithExtraDescriptor(expectedFromSequence: UInt64) throws -> SubmitResult {
        .rejected(.extraDirectoryDescriptor)
    }

    func status() throws -> PublicStatus {
        PublicStatus(phase: .idle, fromSequence: 41, toSequence: nil)
    }

    func encodedStatus() throws -> Data {
        Data(VPNUpdateBrokerProtocol.encode(VPNUpdateBrokerResponse(
            state: .accepted, fromSequence: 41, toSequence: 0, revision: 0)))
    }
}
#endif
