import Darwin
import Foundation

enum VPNExecutorProvisioningError: Error {
    case requiresRoot, unsafeStorage, cloneUnavailable, publicationFailed, commitUncertain
}

/// Creates the fixed protected A executor copy. This does not launch it,
/// replace Applications, advance the journal or contact the VPN service.
/// Production callers must supply the fixed, root-private transaction base;
/// no IPC or user-provided path reaches this descriptor-relative primitive.
enum VPNReplacementExecutorProvisioner {
    enum Outcome { case prepared, recoveredPrepared, alreadyPrepared }
    private static let preparing = ".executor.preparing"
    private static let executor = "executor"
    // Runtime flag from <sys/clonefile.h>; older SDK Swift overlays omit the
    // macro even though the supported macOS runtime implements it.
    private static let cloneResolveBeneath: UInt32 = 0x0010

    static func prepare(inTrustedDirectory base: Int32,
                        release: VerifiedVPNRelease) throws -> Outcome {
        guard getuid() == 0, geteuid() == 0 else { throw VPNExecutorProvisioningError.requiresRoot }
        return try perform(base: base, release: release, checkpoint: { _ in })
    }

    #if VPN_EXECUTOR_PROVISIONING_TESTING
    static func testPrepare(inTrustedDirectory base: Int32, release: VerifiedVPNRelease,
                            checkpoint: (String) throws -> Void = { _ in }) throws -> Outcome {
        guard getuid() != 0, geteuid() == getuid() else { throw VPNPeerAuthenticationError.denied }
        return try perform(base: base, release: release, checkpoint: checkpoint)
    }
    #endif

    private static func perform(base: Int32, release: VerifiedVPNRelease,
                                checkpoint: (String) throws -> Void) throws -> Outcome {
        let lease = try VPNLifecycleOwnership.acquire(inTrustedDirectory: base)
        defer { lease.release() }
        let current = openat(base, "current", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard current >= 0 else { throw VPNExecutorProvisioningError.unsafeStorage }
        defer { close(current) }
        try VPNStagedApplication.requireExclusiveBundle(inTrustedDirectory: current)
        let source = try VPNStagedApplication.inspect(inTrustedDirectory: current, release: release)

        let published = try directory(base, executor)
        defer { if let published { close(published) } }
        let pending = try directory(base, preparing)
        defer { if let pending { close(pending) } }
        guard published == nil || pending == nil else {
            throw VPNExecutorProvisioningError.unsafeStorage
        }
        if let published {
            try VPNStagedApplication.requireExclusiveBundle(inTrustedDirectory: published)
            _ = try VPNStagedApplication.inspect(inTrustedDirectory: published, release: release)
            try VPNStagedApplication.requireExclusiveBundle(inTrustedDirectory: current)
            try VPNStagedApplication.revalidate(source, inTrustedDirectory: current)
            try lease.check()
            return .alreadyPrepared
        }
        if let pending {
            try VPNStagedApplication.requireExclusiveBundle(inTrustedDirectory: pending)
            let copy = try VPNStagedApplication.inspect(inTrustedDirectory: pending, release: release)
            try VPNStagedApplication.requireExclusiveBundle(inTrustedDirectory: current)
            try VPNStagedApplication.revalidate(source, inTrustedDirectory: current)
            try publish(base: base, current: current, source: source,
                        pending: pending, copy: copy, release: release,
                        lease: lease, checkpoint: checkpoint)
            return .recoveredPrepared
        }

        let flags = UInt32(CLONE_NOFOLLOW | CLONE_NOOWNERCOPY) | cloneResolveBeneath
        guard clonefileat(base, "current", base, preparing, flags) == 0 else {
            if errno == ENOTSUP || errno == EXDEV { throw VPNExecutorProvisioningError.cloneUnavailable }
            throw VPNExecutorProvisioningError.unsafeStorage
        }
        try checkpoint("afterClone")
        guard let cloned = try directory(base, preparing) else {
            throw VPNExecutorProvisioningError.unsafeStorage
        }
        defer { close(cloned) }
        try VPNStagedApplication.requireExclusiveBundle(inTrustedDirectory: cloned)
        let copy = try VPNStagedApplication.inspect(inTrustedDirectory: cloned, release: release)
        try VPNStagedApplication.requireExclusiveBundle(inTrustedDirectory: current)
        try VPNStagedApplication.revalidate(source, inTrustedDirectory: current)
        try publish(base: base, current: current, source: source,
                    pending: cloned, copy: copy, release: release,
                    lease: lease, checkpoint: checkpoint)
        return .prepared
    }

    private static func publish(base: Int32, current: Int32,
                                source: VPNStagedApplicationInspection,
                                pending: Int32,
                                copy: VPNStagedApplicationInspection,
                                release: VerifiedVPNRelease,
                                lease: VPNLifecycleLease,
                                checkpoint: (String) throws -> Void) throws {
        try VPNStagedApplication.synchronize(copy, inTrustedDirectory: pending)
        try checkpoint("beforePublish")
        try lease.check()
        try VPNStagedApplication.requireExclusiveBundle(inTrustedDirectory: current)
        try VPNStagedApplication.revalidate(source, inTrustedDirectory: current)
        try VPNStagedApplication.requireExclusiveBundle(inTrustedDirectory: pending)
        try VPNStagedApplication.revalidate(copy, inTrustedDirectory: pending)
        guard renameat(base, preparing, base, executor) == 0 else {
            throw VPNExecutorProvisioningError.publicationFailed
        }
        do {
            guard fsync(base) == 0 else { throw VPNExecutorProvisioningError.commitUncertain }
            try checkpoint("afterPublish")
            try lease.check()
            guard let published = try directory(base, executor) else {
                throw VPNExecutorProvisioningError.commitUncertain
            }
            defer { close(published) }
            try VPNStagedApplication.requireExclusiveBundle(inTrustedDirectory: published)
            _ = try VPNStagedApplication.inspect(inTrustedDirectory: published, release: release)
        } catch {
            throw VPNExecutorProvisioningError.commitUncertain
        }
    }

    private static func directory(_ base: Int32, _ name: String) throws -> Int32? {
        var attributes = stat()
        if fstatat(base, name, &attributes, AT_SYMLINK_NOFOLLOW) != 0 {
            guard errno == ENOENT else { throw VPNExecutorProvisioningError.unsafeStorage }
            return nil
        }
        guard attributes.st_mode & S_IFMT == S_IFDIR else {
            throw VPNExecutorProvisioningError.unsafeStorage
        }
        let opened = openat(base, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard opened >= 0 else { throw VPNExecutorProvisioningError.unsafeStorage }
        var actual = stat()
        guard fstat(opened, &actual) == 0, actual.st_dev == attributes.st_dev,
              actual.st_ino == attributes.st_ino else {
            close(opened); throw VPNExecutorProvisioningError.unsafeStorage
        }
        return opened
    }
}
