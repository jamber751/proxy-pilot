import Darwin
import Foundation

enum VPNApplicationDestinationExchangeError: Error {
    case requiresRoot, invalidTransition, unsafeStorage, invalidLayout
    case exchangeFailed, commitUncertain
}

/// Atomically exchanges the exact installed A name with the already prepared B
/// below `.ProxyPilot.vpn-update`. It never deletes either side, advances the
/// selector, launches B or claims durable installed/live-B state.
enum VPNApplicationDestinationExchange {
    enum Outcome { case exchanged, alreadyExchanged }
    private static let app = "ProxyPilot.app"
    private enum ExecutorMode {
        case ordinary(required: Bool)
        #if VPN_EXPLICIT_RESCUE
        case rescue(VPNRescueExecutor)
        #endif
    }

    static func exchange(inTrustedDirectory base: Int32,
                         previous: VerifiedVPNRelease,
                         previousOwnerUserID: uid_t,
                         candidate: VerifiedVPNRelease,
                         transition: VerifiedVPNUpdateTransition,
                         authorizeMutation: () throws -> Void,
                         checkpoint: (String) throws -> Void = { _ in }) throws -> Outcome {
        guard getuid() == 0, geteuid() == 0 else {
            throw VPNApplicationDestinationExchangeError.requiresRoot
        }
        let destination = open("/Applications", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard destination >= 0 else { throw VPNApplicationDestinationExchangeError.unsafeStorage }
        defer { close(destination) }
        return try perform(base: base, destination: destination, previous: previous,
                           previousOwnerUserID: previousOwnerUserID,
                           candidate: candidate, transition: transition,
                           productionDestination: true, executorMode: .ordinary(required: true),
                           authorizeMutation: authorizeMutation, checkpoint: checkpoint)
    }

    #if VPN_APPLICATION_DESTINATION_TESTING
    static func testExchange(inTrustedDirectory base: Int32, destination: Int32,
                             previous: VerifiedVPNRelease,
                             previousOwnerUserID: uid_t,
                             candidate: VerifiedVPNRelease,
                             transition: VerifiedVPNUpdateTransition,
                             requireExecutor: Bool = false,
                             authorizeMutation: () throws -> Void = {},
                             checkpoint: (String) throws -> Void = { _ in }) throws -> Outcome {
        #if VPN_APPLICATION_DESTINATION_ROOT_TESTING
        // Dedicated VM fixture build only. Production never includes this entry.
        guard getuid() == 0, geteuid() == 0 else { throw VPNPeerAuthenticationError.denied }
        #else
        guard getuid() != 0, geteuid() == getuid() else { throw VPNPeerAuthenticationError.denied }
        #endif
        return try perform(base: base, destination: destination, previous: previous,
                           previousOwnerUserID: previousOwnerUserID,
                           candidate: candidate, transition: transition,
                           productionDestination: false, executorMode: .ordinary(required: requireExecutor),
                           authorizeMutation: authorizeMutation, checkpoint: checkpoint)
    }
    #endif

    #if VPN_EXPLICIT_RESCUE && VPN_APPLICATION_DESTINATION_ROOT_TESTING
    /// Root VM integration only. The live proof is separately authorized for
    /// this exact signed edge; it never impersonates the frozen executor A.
    /// Production publication remains unavailable until the journal/recovery
    /// coordinator enforces pending-state and cleanup boundaries.
    static func testRescueExchange(inTrustedDirectory base: Int32, destination: Int32,
                                  previous: VerifiedVPNRelease, previousOwnerUserID: uid_t,
                                  candidate: VerifiedVPNRelease,
                                  transition: VerifiedVPNUpdateTransition,
                                  executor: VPNRescueExecutor,
                                  authorizeMutation: () throws -> Void,
                                  checkpoint: (String) throws -> Void = { _ in }) throws -> Outcome {
        guard getuid() == 0, geteuid() == 0 else {
            throw VPNApplicationDestinationExchangeError.requiresRoot
        }
        return try perform(base: base, destination: destination, previous: previous,
                           previousOwnerUserID: previousOwnerUserID, candidate: candidate,
                           transition: transition, productionDestination: false,
                           executorMode: .rescue(executor), authorizeMutation: authorizeMutation,
                           checkpoint: checkpoint)
    }
    #endif

    private struct Identity: Equatable {
        let device: dev_t
        let inode: ino_t
        init(_ value: stat) { device = value.st_dev; inode = value.st_ino }
    }

    private static func perform(base: Int32, destination: Int32,
                                previous: VerifiedVPNRelease,
                                previousOwnerUserID: uid_t,
                                candidate: VerifiedVPNRelease,
                                transition: VerifiedVPNUpdateTransition,
                                productionDestination: Bool,
                                executorMode: ExecutorMode,
                                authorizeMutation: () throws -> Void,
                                checkpoint: (String) throws -> Void) throws -> Outcome {
        guard transition.matchesSource(previous), transition.matchesDestination(candidate),
              !previous.isSameRelease(as: candidate) else {
            throw VPNApplicationDestinationExchangeError.invalidTransition
        }
        let lease = try VPNLifecycleOwnership.acquire(inTrustedDirectory: base)
        defer { lease.release() }
        let current = try openSlot(base, "current")
        let oldCopy = try openSlot(base, "candidate")
        let stage = try openStage(destination)
        defer { close(current); close(oldCopy); close(stage) }
        try VPNStagedApplication.requireExclusiveBundle(inTrustedDirectory: current)
        try VPNStagedApplication.requireExclusiveBundle(inTrustedDirectory: oldCopy)
        try VPNStagedApplication.requireExclusiveBundle(inTrustedDirectory: stage)
        let protectedB = try VPNStagedApplication.inspect(inTrustedDirectory: current,
                                                          release: candidate)
        let protectedA = try VPNStagedApplication.inspect(inTrustedDirectory: oldCopy,
                                                          release: previous)
        let revalidateExecutor: () throws -> Void
        switch executorMode {
        case .ordinary(let required):
            let executor = required
                ? try VPNReplacementExecutor.inspect(inTrustedDirectory: base, release: previous) : nil
            revalidateExecutor = { try executor?.revalidate() }
        #if VPN_EXPLICIT_RESCUE
        case .rescue(let executor):
            guard executor.authorization.matchesSource(previous),
                  executor.authorization.matchesDestination(candidate),
                  executor.authorization.matchesTransition(transition) else {
                throw VPNApplicationDestinationExchangeError.invalidTransition
            }
            try executor.revalidate()
            // A must still be present and valid. Static evidence of A is not
            // claimed as live A authentication; rescue proves its own identity.
            let retainedExecutor = try VPNReplacementExecutor.inspectPrepared(
                inTrustedDirectory: base, release: previous)
            revalidateExecutor = {
                try executor.revalidate()
                try retainedExecutor.revalidatePrepared()
            }
        #endif
        }

        func checkProtected() throws {
            try lease.check()
            try checkStageBinding(destination: destination, stage: stage,
                                  production: productionDestination)
            try VPNStagedApplication.requireExclusiveBundle(inTrustedDirectory: current)
            try VPNStagedApplication.requireExclusiveBundle(inTrustedDirectory: oldCopy)
            try VPNStagedApplication.requireExclusiveBundle(inTrustedDirectory: stage)
            try VPNStagedApplication.revalidate(protectedB, inTrustedDirectory: current)
            try VPNStagedApplication.revalidate(protectedA, inTrustedDirectory: oldCopy)
            try revalidateExecutor()
        }
        try checkProtected()

        func inspectPreviousInstalled() throws -> VPNStagedApplicationInspection {
            #if VPN_EXPLICIT_RESCUE
            if case .rescue = executorMode {
                return try VPNStagedApplication.inspectInstalled(
                    inApplicationsDirectory: destination, ownerUserID: 0,
                    productionParent: productionDestination, release: previous)
            }
            #endif
            return try VPNStagedApplication.inspectInstalledForUpdate(
                inApplicationsDirectory: destination, previousOwnerUserID: previousOwnerUserID,
                productionParent: productionDestination, release: previous)
        }
        func inspectPreviousRetained() throws -> VPNStagedApplicationInspection {
            #if VPN_EXPLICIT_RESCUE
            if case .rescue = executorMode {
                return try VPNStagedApplication.inspectProtected(
                    inTrustedDirectory: stage, contentOwnerUserID: 0, release: previous)
            }
            #endif
            return try VPNStagedApplication.inspectRetainedUpdateSource(
                inTrustedDirectory: stage, previousOwnerUserID: previousOwnerUserID,
                release: previous)
        }
        let before = (try? inspectPreviousInstalled()) != nil
            && matchesProtected(stage, owner: geteuid(), release: candidate)
        let after = matchesInstalled(destination, owner: geteuid(),
                                     production: productionDestination, release: candidate)
            && (try? inspectPreviousRetained()) != nil
        guard before != after else { throw VPNApplicationDestinationExchangeError.invalidLayout }

        if after {
            do {
                try authorizeMutation()
                try checkProtected()
                let installed = try VPNStagedApplication.inspectInstalled(
                    inApplicationsDirectory: destination, ownerUserID: geteuid(),
                    productionParent: productionDestination, release: candidate)
                let retained = try inspectPreviousRetained()
                try sync(destination, stage)
                try VPNStagedApplication.revalidate(installed, inTrustedDirectory: destination)
                try VPNStagedApplication.revalidate(retained, inTrustedDirectory: stage)
                return .alreadyExchanged
            } catch { throw VPNApplicationDestinationExchangeError.commitUncertain }
        }

        let installedA = try inspectPreviousInstalled()
        let stagedB = try VPNStagedApplication.inspect(inTrustedDirectory: stage,
                                                       release: candidate)
        let oldInstalled = try childIdentity(destination)
        let oldStaged = try childIdentity(stage)
        try checkpoint("beforeExchange")
        try checkProtected()
        try VPNStagedApplication.revalidate(installedA, inTrustedDirectory: destination)
        try VPNStagedApplication.revalidate(stagedB, inTrustedDirectory: stage)
        try authorizeMutation()
        try checkProtected()
        try VPNStagedApplication.revalidate(installedA, inTrustedDirectory: destination)
        try VPNStagedApplication.revalidate(stagedB, inTrustedDirectory: stage)
        guard renameatx_np(stage, app, destination, app, UInt32(RENAME_SWAP)) == 0 else {
            throw VPNApplicationDestinationExchangeError.exchangeFailed
        }
        do {
            try checkpoint("afterExchange")
            try sync(destination, stage)
            try checkpoint("afterSync")
            try checkProtected()
            try checkpoint("afterProtectedValidation")
            guard try childIdentity(destination) == oldStaged,
                  try childIdentity(stage) == oldInstalled else {
                throw VPNApplicationDestinationExchangeError.invalidLayout
            }
            try checkpoint("afterIdentityValidation")
            let installedB = try VPNStagedApplication.inspectInstalled(
                inApplicationsDirectory: destination, ownerUserID: geteuid(),
                productionParent: productionDestination, release: candidate)
            try checkpoint("afterCandidateInspection")
            let retainedA = try inspectPreviousRetained()
            try checkpoint("afterPreviousInspection")
            try VPNStagedApplication.revalidate(installedB, inTrustedDirectory: destination)
            try checkpoint("afterCandidateRevalidation")
            try VPNStagedApplication.revalidate(retainedA, inTrustedDirectory: stage)
        } catch {
            throw VPNApplicationDestinationExchangeError.commitUncertain
        }
        return .exchanged
    }

    private static func matchesInstalled(_ parent: Int32, owner: uid_t, production: Bool,
                                         release: VerifiedVPNRelease) -> Bool {
        (try? VPNStagedApplication.inspectInstalled(inApplicationsDirectory: parent,
            ownerUserID: owner, productionParent: production, release: release)) != nil
    }

    private static func matchesProtected(_ parent: Int32, owner: uid_t,
                                         release: VerifiedVPNRelease) -> Bool {
        (try? VPNStagedApplication.inspectProtected(inTrustedDirectory: parent,
            contentOwnerUserID: owner, release: release)) != nil
    }

    private static func sync(_ destination: Int32, _ stage: Int32) throws {
        guard fsync(destination) == 0, fsync(stage) == 0 else {
            throw VPNApplicationDestinationExchangeError.commitUncertain
        }
    }

    private static func childIdentity(_ parent: Int32) throws -> Identity {
        var value = stat()
        guard fstatat(parent, app, &value, AT_SYMLINK_NOFOLLOW) == 0,
              value.st_mode & S_IFMT == S_IFDIR else {
            throw VPNApplicationDestinationExchangeError.invalidLayout
        }
        return Identity(value)
    }

    private static func openSlot(_ base: Int32, _ name: String) throws -> Int32 {
        let descriptor = openat(base, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else { throw VPNApplicationDestinationExchangeError.unsafeStorage }
        return descriptor
    }

    private static func openStage(_ destination: Int32) throws -> Int32 {
        let descriptor = openat(destination, VPNApplicationDestinationStage.stageName,
                                O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else { throw VPNApplicationDestinationExchangeError.unsafeStorage }
        return descriptor
    }

    private static func checkStageBinding(destination: Int32, stage: Int32,
                                          production: Bool) throws {
        var held = stat(), named = stat(), parent = stat(), filesystem = statfs()
        guard fstat(destination, &parent) == 0,
              parent.st_mode & S_IFMT == S_IFDIR, parent.st_nlink > 0,
              fstatfs(destination, &filesystem) == 0,
              filesystem.f_flags & UInt32(MNT_LOCAL) != 0,
              parent.st_mode & S_IWOTH == 0,
              fstat(stage, &held) == 0,
              fstatat(destination, VPNApplicationDestinationStage.stageName,
                      &named, AT_SYMLINK_NOFOLLOW) == 0,
              held.st_mode & S_IFMT == S_IFDIR, held.st_uid == geteuid(),
              held.st_mode & 0o7777 == 0o700, held.st_nlink > 0,
              held.st_dev == parent.st_dev,
              Identity(held) == Identity(named) else {
            throw VPNApplicationDestinationExchangeError.unsafeStorage
        }
        if production {
            guard parent.st_uid == 0 else { throw VPNApplicationDestinationExchangeError.unsafeStorage }
            let actual = open("/Applications", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard actual >= 0 else { throw VPNApplicationDestinationExchangeError.unsafeStorage }
            defer { close(actual) }
            var value = stat()
            guard fstat(actual, &value) == 0, Identity(value) == Identity(parent) else {
                throw VPNApplicationDestinationExchangeError.unsafeStorage
            }
        } else {
            guard parent.st_uid == geteuid(), parent.st_mode & 0o7777 == 0o700 else {
                throw VPNApplicationDestinationExchangeError.unsafeStorage
            }
        }
    }
}
