import Foundation

#if VPN_RESCUE_PREPARATION
/// The start role requires BOTH exact-edge authorizations for the same live
/// rescue artifact. Neither token alone authorizes staging, journal mutation,
/// or system actions; those boundaries remain deliberately unwired.
final class VPNRescuePreparationExecutor {
    let authorization: VerifiedVPNRescuePreparationAuthorization
    private let executor: VPNRescueExecutor
    private let previous: VerifiedVPNRelease
    private let candidate: VerifiedVPNRelease
    private let transition: VerifiedVPNUpdateTransition

    private init(executor: VPNRescueExecutor, authorization: VerifiedVPNRescuePreparationAuthorization,
                 previous: VerifiedVPNRelease, candidate: VerifiedVPNRelease,
                 transition: VerifiedVPNUpdateTransition) {
        self.executor = executor; self.authorization = authorization
        self.previous = previous; self.candidate = candidate; self.transition = transition
    }

    #if !VPN_RESCUE_SYSTEM_ENTRY
    @available(*, unavailable, message: "Explicit preparation lifecycle boundary is not implemented.")
    #endif
    static func inspect(executor: VPNRescueExecutor, authorization: VerifiedVPNRescuePreparationAuthorization,
                        previous: VerifiedVPNRelease, candidate: VerifiedVPNRelease,
                        transition: VerifiedVPNUpdateTransition) throws -> VPNRescuePreparationExecutor {
        try make(executor: executor, authorization: authorization, previous: previous,
                 candidate: candidate, transition: transition)
    }

    #if VPN_RESCUE_EXECUTOR_TESTING
    static func testInspect(executor: VPNRescueExecutor, authorization: VerifiedVPNRescuePreparationAuthorization,
                            previous: VerifiedVPNRelease, candidate: VerifiedVPNRelease,
                            transition: VerifiedVPNUpdateTransition) throws -> VPNRescuePreparationExecutor {
        try make(executor: executor, authorization: authorization, previous: previous,
                 candidate: candidate, transition: transition)
    }
    #endif

    private static func make(executor: VPNRescueExecutor, authorization: VerifiedVPNRescuePreparationAuthorization,
                             previous: VerifiedVPNRelease, candidate: VerifiedVPNRelease,
                             transition: VerifiedVPNUpdateTransition) throws -> VPNRescuePreparationExecutor {
        let result = VPNRescuePreparationExecutor(executor: executor, authorization: authorization,
            previous: previous, candidate: candidate, transition: transition)
        try result.revalidate()
        return result
    }

    func validateEdge(previous: VerifiedVPNRelease, candidate: VerifiedVPNRelease,
                      transition: VerifiedVPNUpdateTransition) throws {
        try revalidate()
        guard self.previous.isSameRelease(as: previous), self.candidate.isSameRelease(as: candidate),
              authorization.matchesTransition(transition), executor.authorization.matchesTransition(transition) else {
            throw VPNRescuePreparationAuthorizationError.wrongEdge
        }
    }

    func revalidate() throws {
        guard authorization.matchesSource(previous), authorization.matchesDestination(candidate),
              authorization.matchesTransition(transition),
              executor.authorization.matchesSource(previous),
              executor.authorization.matchesDestination(candidate),
              executor.authorization.matchesTransition(transition) else {
            throw VPNRescuePreparationAuthorizationError.wrongEdge
        }
        try executor.revalidatePreparationArtifact(authorization: authorization)
    }
}
#endif
