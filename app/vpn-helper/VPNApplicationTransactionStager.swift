import Darwin
import Foundation

enum VPNApplicationTransactionStagingError: Error {
    case requiresRoot, unsafeStorage, invalidLayout, cloneUnavailable
    case publicationFailed, commitUncertain
}

/// Builds the protected A/B application namespace used by the replacement
/// executor. Production fixes A to literal /Applications, fixes the destination
/// to ProxyPilot/Update, and accepts B only from a root-private descriptor
/// supplied by the trusted package layer. No path is accepted by this type.
enum VPNApplicationTransactionStager {
    // Runtime flag from <sys/clonefile.h>; spell out the stable ABI value because
    // the macOS 14 SDK Swift overlay used by CI does not export the macro.
    private static let cloneResolveBeneath: UInt32 = 0x0010
    enum Outcome { case staged, resumed, alreadyStaged }
    enum Layout { case prepared, exchanged }
    private static let app = "ProxyPilot.app"

    static func prepare(candidateDirectory: Int32,
                        previousOwnerUserID: uid_t,
                        previous: VerifiedVPNRelease,
                        candidate: VerifiedVPNRelease,
                        transition: VerifiedVPNUpdateTransition) throws -> Outcome {
        guard getuid() == 0, geteuid() == 0 else {
            throw VPNApplicationTransactionStagingError.requiresRoot
        }
        let base = try VPNDirectoryProvisioner.openSystemUpdateDirectory(create: true)
        defer { close(base) }
        let applications = open("/Applications", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard applications >= 0 else { throw VPNApplicationTransactionStagingError.unsafeStorage }
        defer { close(applications) }
        let old = try VPNStagedApplication.inspectInstalled(
            inApplicationsDirectory: applications, ownerUserID: previousOwnerUserID,
            productionParent: true, release: previous)
        let next = try VPNStagedApplication.inspect(
            inTrustedDirectory: candidateDirectory, release: candidate)
        return try perform(base: base,
                           previousSource: applications, previousInspection: old,
                           candidateSource: candidateDirectory, candidateInspection: next,
                           previous: previous, candidate: candidate, transition: transition,
                           checkpoint: { _ in })
    }

    /// Reopens only the fixed, protected A/B slots. This is the retry path
    /// after replacement has been authorized: the mutable Applications tree is
    /// no longer a trustworthy source for A, and must not be consulted again.
    static func validatePreparedOrExchanged(inTrustedDirectory base: Int32,
                                            previous: VerifiedVPNRelease,
                                            candidate: VerifiedVPNRelease,
                                            transition: VerifiedVPNUpdateTransition) throws -> Layout {
        guard getuid() == 0, geteuid() == 0 else {
            throw VPNApplicationTransactionStagingError.requiresRoot
        }
        return try validate(base: base, previous: previous,
                            candidate: candidate, transition: transition)
    }

    #if VPN_APPLICATION_TRANSACTION_STAGING_TESTING
    static func testPrepare(base: Int32,
                            previousSource: Int32,
                            candidateSource: Int32,
                            previous: VerifiedVPNRelease,
                            candidate: VerifiedVPNRelease,
                            transition: VerifiedVPNUpdateTransition,
                            checkpoint: (String) throws -> Void = { _ in }) throws -> Outcome {
        guard getuid() != 0, geteuid() == getuid() else {
            throw VPNPeerAuthenticationError.denied
        }
        let old = try VPNStagedApplication.inspect(
            inTrustedDirectory: previousSource, release: previous)
        let next = try VPNStagedApplication.inspect(
            inTrustedDirectory: candidateSource, release: candidate)
        return try perform(base: base,
                           previousSource: previousSource, previousInspection: old,
                           candidateSource: candidateSource, candidateInspection: next,
                           previous: previous, candidate: candidate, transition: transition,
                           checkpoint: checkpoint)
    }

    static func testValidatePreparedOrExchanged(inTrustedDirectory base: Int32,
                                                previous: VerifiedVPNRelease,
                                                candidate: VerifiedVPNRelease,
                                                transition: VerifiedVPNUpdateTransition) throws -> Layout {
        guard getuid() != 0, geteuid() == getuid() else {
            throw VPNPeerAuthenticationError.denied
        }
        return try validate(base: base, previous: previous,
                            candidate: candidate, transition: transition)
    }
    #endif

    private static func validate(base: Int32,
                                 previous: VerifiedVPNRelease,
                                 candidate: VerifiedVPNRelease,
                                 transition: VerifiedVPNUpdateTransition) throws -> Layout {
        guard !previous.isSameRelease(as: candidate),
              transition.matchesSource(previous),
              transition.matchesDestination(candidate) else {
            throw VPNApplicationTransactionStagingError.invalidLayout
        }
        try checkBase(base)
        let lease = try VPNLifecycleOwnership.acquire(inTrustedDirectory: base)
        defer { lease.release() }
        try lease.check()
        let prepared = matches(base: base, current: previous, candidate: candidate)
        let exchanged = matches(base: base, current: candidate, candidate: previous)
        guard prepared != exchanged else {
            throw VPNApplicationTransactionStagingError.invalidLayout
        }
        try lease.check()
        return prepared ? .prepared : .exchanged
    }

    private static func matches(base: Int32, current: VerifiedVPNRelease,
                                candidate: VerifiedVPNRelease) -> Bool {
        do {
            try validatePublished(base: base, name: "current", release: current)
            try validatePublished(base: base, name: "candidate", release: candidate)
            return true
        } catch {
            return false
        }
    }

    private static func perform(base: Int32,
                                previousSource: Int32,
                                previousInspection: VPNStagedApplicationInspection,
                                candidateSource: Int32,
                                candidateInspection: VPNStagedApplicationInspection,
                                previous: VerifiedVPNRelease,
                                candidate: VerifiedVPNRelease,
                                transition: VerifiedVPNUpdateTransition,
                                checkpoint: (String) throws -> Void) throws -> Outcome {
        guard !previous.isSameRelease(as: candidate),
              transition.matchesSource(previous),
              transition.matchesDestination(candidate) else {
            throw VPNApplicationTransactionStagingError.invalidLayout
        }
        try checkBase(base)
        try distinct([base, previousSource, candidateSource])
        let lease = try VPNLifecycleOwnership.acquire(inTrustedDirectory: base)
        defer { lease.release() }

        let current = try prepareSlot(
            base: base, name: "current", source: previousSource,
            sourceInspection: previousInspection, release: previous,
            lease: lease, checkpoint: checkpoint)
        let staged = try prepareSlot(
            base: base, name: "candidate", source: candidateSource,
            sourceInspection: candidateInspection, release: candidate,
            lease: lease, checkpoint: checkpoint)
        try lease.check()
        try checkBase(base)
        try validatePublished(base: base, name: "current", release: previous)
        try validatePublished(base: base, name: "candidate", release: candidate)
        guard fsync(base) == 0 else {
            throw VPNApplicationTransactionStagingError.commitUncertain
        }
        if current == .alreadyStaged && staged == .alreadyStaged { return .alreadyStaged }
        if current != .staged || staged != .staged { return .resumed }
        return .staged
    }

    private static func prepareSlot(base: Int32, name: String,
                                    source: Int32,
                                    sourceInspection: VPNStagedApplicationInspection,
                                    release: VerifiedVPNRelease,
                                    lease: VPNLifecycleLease,
                                    checkpoint: (String) throws -> Void) throws -> Outcome {
        let pendingName = ".\(name).preparing"
        let published = try directory(base, name)
        let pending = try directory(base, pendingName)
        guard published == nil || pending == nil else {
            if let published { close(published) }
            if let pending { close(pending) }
            throw VPNApplicationTransactionStagingError.invalidLayout
        }
        if let published {
            defer { close(published) }
            try validateSlot(published, release: release)
            try lease.check()
            try VPNStagedApplication.revalidate(sourceInspection,
                                                 inTrustedDirectory: source)
            return .alreadyStaged
        }

        var resumed = false
        let staging: Int32
        if let pending {
            staging = pending
            resumed = true
        } else {
            guard mkdirat(base, pendingName, 0o700) == 0,
                  fsync(base) == 0,
                  let created = try directory(base, pendingName) else {
                throw VPNApplicationTransactionStagingError.unsafeStorage
            }
            staging = created
        }
        defer { close(staging) }
        let contents = try names(staging)
        if contents.isEmpty {
            try lease.check()
            try VPNStagedApplication.revalidate(sourceInspection,
                                                 inTrustedDirectory: source)
            guard cloneDirectChild(source, app, staging, app) == 0 else {
                if errno == ENOTSUP || errno == EXDEV {
                    throw VPNApplicationTransactionStagingError.cloneUnavailable
                }
                throw VPNApplicationTransactionStagingError.unsafeStorage
            }
            try checkpoint("afterClone:\(name)")
        } else {
            guard contents == [app] else {
                throw VPNApplicationTransactionStagingError.invalidLayout
            }
        }
        try validateSlot(staging, release: release)
        let copy = try VPNStagedApplication.inspect(
            inTrustedDirectory: staging, release: release)
        try VPNStagedApplication.synchronize(copy, inTrustedDirectory: staging)
        try checkpoint("beforePublish:\(name)")
        try lease.check()
        try VPNStagedApplication.revalidate(sourceInspection,
                                             inTrustedDirectory: source)
        try VPNStagedApplication.revalidate(copy, inTrustedDirectory: staging)
        guard renameat(base, pendingName, base, name) == 0 else {
            throw VPNApplicationTransactionStagingError.publicationFailed
        }
        do {
            guard fsync(base) == 0 else {
                throw VPNApplicationTransactionStagingError.commitUncertain
            }
            try checkpoint("afterPublish:\(name)")
            try lease.check()
            try validatePublished(base: base, name: name, release: release)
        } catch {
            throw VPNApplicationTransactionStagingError.commitUncertain
        }
        return resumed ? .resumed : .staged
    }

    /// Compatibility for macOS 14. The fallback is limited to EINVAL from the
    /// unsupported beneath flag, fixed direct-child names and an absent target.
    private static func cloneDirectChild(_ source: Int32, _ sourceName: String,
                                         _ destination: Int32, _ destinationName: String) -> Int32 {
        let basic = UInt32(CLONE_NOFOLLOW | CLONE_NOOWNERCOPY)
        if clonefileat(source, sourceName, destination, destinationName,
                       basic | cloneResolveBeneath) == 0 { return 0 }
        guard errno == EINVAL else { return -1 }
        var attributes = stat()
        guard fstatat(destination, destinationName, &attributes, AT_SYMLINK_NOFOLLOW) != 0,
              errno == ENOENT else {
            errno = EEXIST
            return -1
        }
        return clonefileat(source, sourceName, destination, destinationName, basic)
    }

    private static func validatePublished(base: Int32, name: String,
                                          release: VerifiedVPNRelease) throws {
        guard let slot = try directory(base, name) else {
            throw VPNApplicationTransactionStagingError.commitUncertain
        }
        defer { close(slot) }
        try validateSlot(slot, release: release)
    }

    private static func validateSlot(_ slot: Int32,
                                     release: VerifiedVPNRelease) throws {
        try VPNStagedApplication.requireExclusiveBundle(inTrustedDirectory: slot)
        _ = try VPNStagedApplication.inspect(inTrustedDirectory: slot,
                                              release: release)
    }

    private static func directory(_ base: Int32, _ name: String) throws -> Int32? {
        var named = stat()
        if fstatat(base, name, &named, AT_SYMLINK_NOFOLLOW) != 0 {
            guard errno == ENOENT else {
                throw VPNApplicationTransactionStagingError.unsafeStorage
            }
            return nil
        }
        guard named.st_mode & S_IFMT == S_IFDIR, named.st_uid == geteuid(),
              named.st_mode & 0o7777 == 0o700, named.st_nlink > 0 else {
            throw VPNApplicationTransactionStagingError.unsafeStorage
        }
        let opened = openat(base, name,
                            O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard opened >= 0 else {
            throw VPNApplicationTransactionStagingError.unsafeStorage
        }
        var actual = stat(), root = stat()
        guard fstat(opened, &actual) == 0, fstat(base, &root) == 0,
              actual.st_dev == root.st_dev,
              actual.st_dev == named.st_dev, actual.st_ino == named.st_ino else {
            close(opened)
            throw VPNApplicationTransactionStagingError.unsafeStorage
        }
        return opened
    }

    private static func names(_ directory: Int32) throws -> [String] {
        let copy = openat(directory, ".",
                          O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard copy >= 0, let stream = fdopendir(copy) else {
            if copy >= 0 { close(copy) }
            throw VPNApplicationTransactionStagingError.unsafeStorage
        }
        defer { closedir(stream) }
        var result: [String] = []
        let offset = MemoryLayout<dirent>.offset(of: \.d_name)!
        while true {
            errno = 0
            guard let entry = readdir(stream) else {
                guard errno == 0 else {
                    throw VPNApplicationTransactionStagingError.unsafeStorage
                }
                return result.sorted()
            }
            let length = Int(entry.pointee.d_namlen)
            guard length > 0, length < Int(MAXPATHLEN),
                  offset + length < Int(entry.pointee.d_reclen) else {
                throw VPNApplicationTransactionStagingError.unsafeStorage
            }
            let bytes = UnsafeRawPointer(entry).advanced(by: offset)
                .assumingMemoryBound(to: UInt8.self)
            let view = UnsafeBufferPointer(start: bytes, count: length)
            guard bytes[length] == 0, !view.contains(0), !view.contains(47),
                  let name = String(bytes: view, encoding: .utf8) else {
                throw VPNApplicationTransactionStagingError.unsafeStorage
            }
            if name != "." && name != ".." { result.append(name) }
        }
    }

    private static func distinct(_ descriptors: [Int32]) throws {
        var identities = Set<String>()
        for descriptor in descriptors {
            var value = stat()
            guard fstat(descriptor, &value) == 0,
                  value.st_mode & S_IFMT == S_IFDIR else {
                throw VPNApplicationTransactionStagingError.unsafeStorage
            }
            let key = "\(UInt64(truncatingIfNeeded: value.st_dev)):\(value.st_ino)"
            guard identities.insert(key).inserted else {
                throw VPNApplicationTransactionStagingError.unsafeStorage
            }
        }
    }

    private static func checkBase(_ base: Int32) throws {
        var value = stat(), filesystem = statfs()
        guard fstat(base, &value) == 0,
              value.st_mode & S_IFMT == S_IFDIR,
              value.st_uid == geteuid(), value.st_mode & 0o7777 == 0o700,
              value.st_nlink > 0,
              fstatfs(base, &filesystem) == 0,
              filesystem.f_flags & UInt32(MNT_LOCAL) != 0,
              let security = filesec_init() else {
            throw VPNApplicationTransactionStagingError.unsafeStorage
        }
        defer { filesec_free(security) }
        guard fstatx_np(base, &value, security) == 0 else {
            throw VPNApplicationTransactionStagingError.unsafeStorage
        }
        var acl: acl_t?
        errno = 0
        let result = filesec_get_property(security, FILESEC_ACL, &acl)
        if result == -1, errno == ENOENT { return }
        guard result == 0, let acl else {
            throw VPNApplicationTransactionStagingError.unsafeStorage
        }
        defer { acl_free(UnsafeMutableRawPointer(acl)) }
        var entry: acl_entry_t?
        errno = 0
        guard acl_get_entry(acl, Int32(ACL_FIRST_ENTRY.rawValue), &entry) == -1,
              errno == EINVAL else {
            throw VPNApplicationTransactionStagingError.unsafeStorage
        }
    }
}
