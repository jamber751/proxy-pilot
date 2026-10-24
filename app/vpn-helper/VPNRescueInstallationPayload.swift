import Darwin
import Foundation

enum VPNRescueInstallationPayloadError: Error { case unsafePackage, changed, missingCapability }

/// Immutable static package evidence only. Neither loading nor revalidation
/// authenticates a live process, grants root authority, chooses a leg, or reads
/// release-store state. A future system entry must provide fixed protected
/// ancestors; these descriptors are owner-private and bound to their child names.
final class VPNRescueInstallationPayload {
    let source: VerifiedVPNRelease
    let intermediate: VerifiedVPNRelease
    let firstTransition: VerifiedVPNUpdateTransition
    let finishFirst: VerifiedVPNRescueAuthorization
    let prepareSecond: VerifiedVPNRescuePreparationAuthorization
    let finishSecond: VerifiedVPNRescueAuthorization
    let second: VPNJointUpdatePayload
    private let authority: VPNReleaseAuthority
    private let root: Int32, executable: Int32, metadata: Int32, candidate: Int32
    private let identities: [String: Facts]
    private let sidecars: [String: Data]
    private let candidateInspection: VPNStagedApplicationInspection

    private static let metadataNames: Set<String> = [
        "source-release.manifest", "source-release.sig", "first-transition", "first-transition.sig",
        "finish-first", "finish-first.sig", "prepare-second", "prepare-second.sig",
        "finish-second", "finish-second.sig"]
    private static let candidateNames: Set<String> = [
        "ProxyPilot.app", "vpn-release.manifest", "vpn-release.sig", "vpn-helper",
        "vpn-previous-release.manifest", "vpn-previous-release.sig",
        "vpn-update-transition", "vpn-update-transition.sig"]

    private init(root: Int32, executable: Int32, metadata: Int32, candidate: Int32,
                 authority: VPNReleaseAuthority, identities: [String: Facts], sidecars: [String: Data],
                 source: VerifiedVPNRelease, firstTransition: VerifiedVPNUpdateTransition,
                 finishFirst: VerifiedVPNRescueAuthorization,
                 prepareSecond: VerifiedVPNRescuePreparationAuthorization,
                 finishSecond: VerifiedVPNRescueAuthorization, second: VPNJointUpdatePayload,
                 candidateInspection: VPNStagedApplicationInspection) {
        self.root = root; self.executable = executable; self.metadata = metadata; self.candidate = candidate
        self.authority = authority; self.identities = identities; self.sidecars = sidecars
        self.source = source; intermediate = second.previous; self.firstTransition = firstTransition
        self.finishFirst = finishFirst; self.prepareSecond = prepareSecond; self.finishSecond = finishSecond
        self.second = second; self.candidateInspection = candidateInspection
    }
    deinit { close(candidate); close(metadata); close(executable); close(root) }

    static func load(inTrustedDirectory parent: Int32, authority: VPNReleaseAuthority) throws
        -> VPNRescueInstallationPayload {
        let root = fcntl(parent, F_DUPFD_CLOEXEC, 0)
        guard root >= 0 else { throw VPNRescueInstallationPayloadError.unsafePackage }
        var children: [String: Int32] = [:], transferred = false
        defer { if !transferred { for fd in children.values { close(fd) }; close(root) } }
        var identities = [".": try checkDirectory(root)]
        try requireNames(root, ["Executable", "Metadata", "Candidate"])
        for name in ["Executable", "Metadata", "Candidate"] {
            let fd = openat(root, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard fd >= 0 else { throw VPNRescueInstallationPayloadError.unsafePackage }
            children[name] = fd; identities[name] = try checkDirectory(fd)
        }
        let executable = children["Executable"]!, metadata = children["Metadata"]!, candidate = children["Candidate"]!
        try requireNames(executable, ["vpn-rescue"])
        try requireNames(metadata, metadataNames)
        let second = try VPNJointUpdatePayload.loadForBroker(inTrustedDirectory: candidate, authority: authority)
        try requireNames(candidate, candidateNames.union(second.candidate.engine == nil ? [] : ["vpn-engine"]))
        let app = try VPNStagedApplication.inspect(inTrustedDirectory: candidate, release: second.candidate.release)
        try requireCapability(candidate: candidate, inspection: app)

        var sidecars: [String: Data] = [:]
        func bytes(_ name: String, _ limit: Int) throws -> Data {
            let value = try VPNInstallationPayload.read(name, in: metadata, limit: limit)
            sidecars[name] = value; return value
        }
        func signature(_ name: String) throws -> Data {
            let value = try VPNInstallationPayload.readSignature(name, in: metadata)
            sidecars[name] = value; return value
        }
        let a = try bytes("source-release.manifest", VPNReleaseAuthority.maximumPayloadBytes)
        let aSignature = try signature("source-release.sig")
        let source = try authority.verify(payload: a, signature: aSignature, previous: nil)
        let firstEdge = try bytes("first-transition", VPNReleaseAuthority.maximumUpdateTransitionBytes)
        let firstSignature = try signature("first-transition.sig")
        let firstTransition = try authority.verifyUpdateTransition(payload: firstEdge, signature: firstSignature,
            previous: source, candidatePayload: second.previousManifest, candidateSignature: second.previousSignature)
        let finishFirst = try VPNRescueAuthorization.verify(
            payload: bytes("finish-first", VPNReleaseAuthority.maximumRescueAuthorizationBytes),
            signature: signature("finish-first.sig"), authority: authority, previous: source,
            previousPayload: a, previousSignature: aSignature,
            candidatePayload: second.previousManifest, candidateSignature: second.previousSignature,
            transitionPayload: firstEdge, transitionSignature: firstSignature)
        let prepareSecond = try VPNRescuePreparationAuthorization.verify(
            payload: bytes("prepare-second", VPNReleaseAuthority.maximumRescuePreparationAuthorizationBytes),
            signature: signature("prepare-second.sig"), authority: authority, previous: second.previous,
            previousPayload: second.previousManifest, previousSignature: second.previousSignature,
            candidatePayload: second.candidate.manifest, candidateSignature: second.candidate.signature,
            transitionPayload: second.transitionPayload, transitionSignature: second.transitionSignature)
        let finishSecond = try VPNRescueAuthorization.verify(
            payload: bytes("finish-second", VPNReleaseAuthority.maximumRescueAuthorizationBytes),
            signature: signature("finish-second.sig"), authority: authority, previous: second.previous,
            previousPayload: second.previousManifest, previousSignature: second.previousSignature,
            candidatePayload: second.candidate.manifest, candidateSignature: second.candidate.signature,
            transitionPayload: second.transitionPayload, transitionSignature: second.transitionSignature)
        _ = try VPNInstallationPayload.read("vpn-rescue", in: executable,
            limit: VPNRescueAuthorization.maximumArtifactBytes) { file, data in
                var info = stat()
                guard fstat(file, &info) == 0, info.st_mode & 0o7777 == 0o700, info.st_flags == 0 else {
                    throw VPNRescueInstallationPayloadError.unsafePackage
                }
                try finishFirst.validateArtifact(data)
                try prepareSecond.validateArtifact(data)
                try finishSecond.validateArtifact(data)
                try VPNUniversalArtifact.validate(protectedFile: file, data: data,
                    identifier: "kz.documentolog.proxypilot.vpn-rescue", hash: finishFirst.hash,
                    error: VPNRescueInstallationPayloadError.unsafePackage)
                try VPNUniversalArtifact.validate(protectedFile: file, data: data,
                    identifier: "kz.documentolog.proxypilot.vpn-rescue", hash: prepareSecond.hash,
                    error: VPNRescueInstallationPayloadError.unsafePackage)
                try VPNUniversalArtifact.validate(protectedFile: file, data: data,
                    identifier: "kz.documentolog.proxypilot.vpn-rescue", hash: finishSecond.hash,
                    error: VPNRescueInstallationPayloadError.unsafePackage)
            }
        let result = VPNRescueInstallationPayload(root: root, executable: executable,
            metadata: metadata, candidate: candidate, authority: authority, identities: identities,
            sidecars: sidecars, source: source, firstTransition: firstTransition, finishFirst: finishFirst,
            prepareSecond: prepareSecond, finishSecond: finishSecond, second: second, candidateInspection: app)
        transferred = true
        try result.checkBindings()
        return result
    }

    func revalidate() throws {
        try checkBindings()
        let fresh = try Self.load(inTrustedDirectory: root, authority: authority)
        guard sidecars == fresh.sidecars,
              second.previousManifest == fresh.second.previousManifest,
              second.previousSignature == fresh.second.previousSignature,
              second.transitionPayload == fresh.second.transitionPayload,
              second.transitionSignature == fresh.second.transitionSignature,
              second.candidate.manifest == fresh.second.candidate.manifest,
              second.candidate.signature == fresh.second.candidate.signature,
              second.candidate.helper == fresh.second.candidate.helper,
              second.candidate.engine == fresh.second.candidate.engine else {
            throw VPNRescueInstallationPayloadError.changed
        }
        try checkBindings()
    }

    func duplicateCandidateDirectory() throws -> Int32 { try duplicate(candidate) }
    func duplicateExecutableDirectory() throws -> Int32 { try duplicate(executable) }
    private func duplicate(_ fd: Int32) throws -> Int32 {
        try revalidate()
        let copy = fcntl(fd, F_DUPFD_CLOEXEC, 0)
        guard copy >= 0 else { throw VPNRescueInstallationPayloadError.unsafePackage }
        return copy
    }

    private func checkBindings() throws {
        guard try Self.checkDirectory(root) == identities["."] else { throw VPNRescueInstallationPayloadError.changed }
        try Self.requireNames(root, ["Executable", "Metadata", "Candidate"])
        for (name, fd) in [("Executable", executable), ("Metadata", metadata), ("Candidate", candidate)] {
            var named = stat()
            guard fstatat(root, name, &named, AT_SYMLINK_NOFOLLOW) == 0,
                  Facts(named) == identities[name], try Self.checkDirectory(fd) == identities[name] else {
                throw VPNRescueInstallationPayloadError.changed
            }
        }
        try Self.requireNames(executable, ["vpn-rescue"])
        try Self.requireNames(metadata, Self.metadataNames)
        try Self.requireNames(candidate, Self.candidateNames.union(second.candidate.engine == nil ? [] : ["vpn-engine"]))
        try VPNStagedApplication.revalidate(candidateInspection, inTrustedDirectory: candidate)
    }

    private static func requireCapability(candidate: Int32, inspection: VPNStagedApplicationInspection) throws {
        let app = openat(candidate, "ProxyPilot.app", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard app >= 0 else { throw VPNRescueInstallationPayloadError.unsafePackage }
        defer { close(app) }
        let contents = openat(app, "Contents", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard contents >= 0 else { throw VPNRescueInstallationPayloadError.unsafePackage }
        defer { close(contents) }
        let bytes = try VPNInstallationPayload.read("Info.plist", in: contents, limit: 1024 * 1024)
        let info = try PropertyListSerialization.propertyList(from: bytes, options: [], format: nil) as? [String: Any]
        guard info?["ProxyPilotVPNRootOwnedUpdateExecutor"] as? String == "1" else {
            throw VPNRescueInstallationPayloadError.missingCapability
        }
        try VPNStagedApplication.revalidate(inspection, inTrustedDirectory: candidate)
    }

    private static func checkDirectory(_ fd: Int32) throws -> Facts {
        try VPNInstallationPayload.check(fd, directory: true)
        var info = stat()
        guard fstat(fd, &info) == 0, info.st_mode & 0o7777 == 0o700, info.st_flags == 0 else {
            throw VPNRescueInstallationPayloadError.unsafePackage
        }
        return Facts(info)
    }

    private static func requireNames(_ fd: Int32, _ expected: Set<String>) throws {
        let copy = openat(fd, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard copy >= 0 else { throw VPNRescueInstallationPayloadError.unsafePackage }
        guard let stream = fdopendir(copy) else { close(copy); throw VPNRescueInstallationPayloadError.unsafePackage }
        defer { closedir(stream) }
        var names: Set<String> = []
        let offset = MemoryLayout<dirent>.offset(of: \.d_name)!
        while true {
            errno = 0
            guard let entry = readdir(stream) else {
                guard errno == 0 else { throw VPNRescueInstallationPayloadError.unsafePackage }
                break
            }
            let name = String(cString: UnsafeRawPointer(entry).advanced(by: offset).assumingMemoryBound(to: CChar.self))
            if name == "." || name == ".." { continue }
            guard expected.contains(name), names.insert(name).inserted else { throw VPNRescueInstallationPayloadError.unsafePackage }
        }
        guard names == expected else { throw VPNRescueInstallationPayloadError.unsafePackage }
    }

    private struct Facts: Equatable {
        let device: dev_t, inode: ino_t, owner: uid_t, mode: mode_t, flags: UInt32
        init(_ info: stat) {
            device = info.st_dev; inode = info.st_ino; owner = info.st_uid
            mode = info.st_mode; flags = info.st_flags
        }
    }
}
