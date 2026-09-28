import Darwin
import Foundation

enum VPNApplicationDestinationStageError: Error {
    case requiresRoot, unsafeDestination, unsafeStorage, cloneUnavailable, stagingUncertain
}

/// Prepares exact B below a fixed private directory in Applications without
/// touching the installed app. The Applications parent remains mutable, so no
/// result from this type is durable authority: callers must re-open, re-bind and
/// revalidate the stage at the later atomic replacement boundary.
enum VPNApplicationDestinationStage {
    enum Outcome { case staged, alreadyStaged }
    static let stageName = ".ProxyPilot.vpn-update"
    // Present at runtime since macOS 10.12, but older SDK Swift overlays do not
    // export the C macro even when targeting macOS 11. Keep the ABI value from
    // <sys/clonefile.h> so release builds compile on the macOS 14 CI image.
    private static let cloneResolveBeneath: UInt32 = 0x0010

    static func prepare(inTrustedDirectory base: Int32,
                        release: VerifiedVPNRelease) throws -> Outcome {
        guard getuid() == 0, geteuid() == 0 else {
            throw VPNApplicationDestinationStageError.requiresRoot
        }
        let destination = open("/Applications", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard destination >= 0 else { throw VPNApplicationDestinationStageError.unsafeDestination }
        defer { close(destination) }
        return try perform(base: base, destination: destination, release: release,
                           productionDestination: true, checkpoint: { _ in })
    }

    #if VPN_APPLICATION_DESTINATION_TESTING
    static func testPrepare(inTrustedDirectory base: Int32, destination: Int32,
                            release: VerifiedVPNRelease,
                            checkpoint: (String) throws -> Void = { _ in }) throws -> Outcome {
        guard getuid() != 0, geteuid() == getuid() else { throw VPNPeerAuthenticationError.denied }
        return try perform(base: base, destination: destination, release: release,
                           productionDestination: false, checkpoint: checkpoint)
    }
    #endif

    private static func perform(base: Int32, destination: Int32,
                                release: VerifiedVPNRelease,
                                productionDestination: Bool,
                                checkpoint: (String) throws -> Void) throws -> Outcome {
        let lease = try VPNLifecycleOwnership.acquire(inTrustedDirectory: base)
        defer { lease.release() }
        try checkDestination(destination, production: productionDestination)
        let current = openat(base, "current", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard current >= 0 else { throw VPNApplicationDestinationStageError.unsafeStorage }
        defer { close(current) }
        try VPNStagedApplication.requireExclusiveBundle(inTrustedDirectory: current)
        let source = try VPNStagedApplication.inspect(inTrustedDirectory: current, release: release)

        if let existing = try directory(destination, stageName) {
            defer { close(existing) }
            try checkStage(parent: destination, stage: existing,
                           productionDestination: productionDestination)
            try VPNStagedApplication.requireExclusiveBundle(inTrustedDirectory: existing)
            let copy = try VPNStagedApplication.inspect(inTrustedDirectory: existing, release: release)
            try VPNStagedApplication.synchronize(copy, inTrustedDirectory: existing)
            try lease.check()
            try VPNStagedApplication.revalidate(source, inTrustedDirectory: current)
            try checkDestination(destination, production: productionDestination)
            try checkStage(parent: destination, stage: existing,
                           productionDestination: productionDestination)
            try VPNStagedApplication.revalidate(copy, inTrustedDirectory: existing)
            return .alreadyStaged
        }

        guard cloneDirectChild(base, "current", destination, stageName) == 0 else {
            if errno == ENOTSUP || errno == EXDEV {
                throw VPNApplicationDestinationStageError.cloneUnavailable
            }
            throw VPNApplicationDestinationStageError.unsafeDestination
        }
        try checkpoint("afterClone")
        guard let staged = try directory(destination, stageName) else {
            throw VPNApplicationDestinationStageError.stagingUncertain
        }
        defer { close(staged) }
        do {
            try checkStage(parent: destination, stage: staged,
                           productionDestination: productionDestination)
            try VPNStagedApplication.requireExclusiveBundle(inTrustedDirectory: staged)
            let copy = try VPNStagedApplication.inspect(inTrustedDirectory: staged, release: release)
            try VPNStagedApplication.synchronize(copy, inTrustedDirectory: staged)
            try checkpoint("beforeCommit")
            try lease.check()
            try checkDestination(destination, production: productionDestination)
            try checkStage(parent: destination, stage: staged,
                           productionDestination: productionDestination)
            try VPNStagedApplication.requireExclusiveBundle(inTrustedDirectory: current)
            try VPNStagedApplication.revalidate(source, inTrustedDirectory: current)
            try VPNStagedApplication.requireExclusiveBundle(inTrustedDirectory: staged)
            try VPNStagedApplication.revalidate(copy, inTrustedDirectory: staged)
            guard fsync(destination) == 0 else {
                throw VPNApplicationDestinationStageError.stagingUncertain
            }
            try checkDestination(destination, production: productionDestination)
            try checkStage(parent: destination, stage: staged,
                           productionDestination: productionDestination)
            try VPNStagedApplication.revalidate(copy, inTrustedDirectory: staged)
            return .staged
        } catch let error as VPNStagedApplicationError {
            throw error
        } catch let error as VPNLifecycleOwnershipError {
            throw error
        } catch let error as VPNApplicationDestinationStageError {
            throw error
        } catch {
            throw VPNApplicationDestinationStageError.stagingUncertain
        }
    }

    /// macOS 14 rejects CLONE_RESOLVE_BENEATH with EINVAL. These are fixed
    /// single-component names under already validated descriptors; on that one
    /// legacy result, confirm the destination is still absent and retry with the
    /// older no-follow/no-owner-copy contract. Other errors never downgrade.
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

    private static func checkDestination(_ destination: Int32, production: Bool) throws {
        var attributes = stat(), filesystem = statfs()
        guard fstat(destination, &attributes) == 0,
              attributes.st_mode & S_IFMT == S_IFDIR, attributes.st_nlink > 0,
              fstatfs(destination, &filesystem) == 0,
              filesystem.f_flags & UInt32(MNT_LOCAL) != 0,
              attributes.st_mode & S_IWOTH == 0 else {
            throw VPNApplicationDestinationStageError.unsafeDestination
        }
        if production {
            guard attributes.st_uid == 0 else {
                throw VPNApplicationDestinationStageError.unsafeDestination
            }
            let named = open("/Applications", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard named >= 0 else { throw VPNApplicationDestinationStageError.unsafeDestination }
            defer { close(named) }
            var current = stat()
            guard fstat(named, &current) == 0,
                  current.st_dev == attributes.st_dev,
                  current.st_ino == attributes.st_ino else {
                throw VPNApplicationDestinationStageError.unsafeDestination
            }
        } else {
            guard attributes.st_uid == geteuid(), attributes.st_mode & 0o7777 == 0o700 else {
                throw VPNApplicationDestinationStageError.unsafeDestination
            }
        }
    }

    private static func checkStage(parent: Int32, stage: Int32,
                                   productionDestination: Bool) throws {
        try checkDestination(parent, production: productionDestination)
        var held = stat(), named = stat(), parentState = stat()
        guard fstat(stage, &held) == 0, fstat(parent, &parentState) == 0,
              fstatat(parent, stageName, &named, AT_SYMLINK_NOFOLLOW) == 0,
              held.st_mode & S_IFMT == S_IFDIR, held.st_uid == geteuid(),
              held.st_mode & 0o7777 == 0o700, held.st_nlink > 0,
              held.st_dev == parentState.st_dev,
              held.st_dev == named.st_dev, held.st_ino == named.st_ino else {
            throw VPNApplicationDestinationStageError.unsafeDestination
        }
    }

    private static func directory(_ parent: Int32, _ name: String) throws -> Int32? {
        var attributes = stat()
        if fstatat(parent, name, &attributes, AT_SYMLINK_NOFOLLOW) != 0 {
            guard errno == ENOENT else { throw VPNApplicationDestinationStageError.unsafeDestination }
            return nil
        }
        guard attributes.st_mode & S_IFMT == S_IFDIR else {
            throw VPNApplicationDestinationStageError.unsafeDestination
        }
        let opened = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard opened >= 0 else { throw VPNApplicationDestinationStageError.unsafeDestination }
        var actual = stat()
        guard fstat(opened, &actual) == 0,
              actual.st_dev == attributes.st_dev, actual.st_ino == attributes.st_ino else {
            close(opened)
            throw VPNApplicationDestinationStageError.unsafeDestination
        }
        return opened
    }
}
