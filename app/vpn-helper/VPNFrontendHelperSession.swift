import Darwin
import Dispatch

enum VPNFrontendHelperSessionError: Error {
    case wrongOwner
}

/// The only production entry from the ordinary desktop process to tunnel IPC.
/// Discovery data is never trusted directly: its release signature authorizes
/// the exact helper CDHashes used by VPNHelperSession's mutual peer checks.
enum VPNFrontendHelperSession {
    static func open(timeoutMilliseconds: Int = 2_000) throws -> VPNHelperSession {
        guard (1...5_000).contains(timeoutMilliseconds) else {
            throw VPNHelperSessionError.timeout
        }
        let authority = try VPNReleaseTrust.authority()
        let receipt = try VPNPublicReleaseReceipt.loadSystem(authority: authority)
        guard receipt.ownerUserID == geteuid() else {
            throw VPNFrontendHelperSessionError.wrongOwner
        }
        let deadline = DispatchTime.now().uptimeNanoseconds
            + UInt64(timeoutMilliseconds) * 1_000_000
        let socket = try VPNEndpointDirectory.connectSystem(deadline: deadline)
        return try VPNHelperSession.open(takingSocket: socket,
            release: receipt.release, timeoutMilliseconds: timeoutMilliseconds)
    }
}
