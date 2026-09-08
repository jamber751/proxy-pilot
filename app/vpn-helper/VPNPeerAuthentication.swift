import Darwin
import Foundation
import Security

enum VPNPeerAuthenticationError: Error {
    case invalidPolicy
    case denied
}

/// Installer-owned policy, NOT a wire format. Never construct this from client
/// messages, a path supplied by the client, or a user-writable preferences file.
/// Pin provisioning/rotation and production integration are not implemented yet.
struct VPNPeerPolicy {
    fileprivate let userID: uid_t
    fileprivate let signingIdentifier: String
    fileprivate let codeDirectoryHashes: Set<Data>

    init(userID: uid_t, signingIdentifier: String, codeDirectoryHashes: Set<Data>) throws {
        guard userID != 0 else { throw VPNPeerAuthenticationError.invalidPolicy }
        try self.init(trustedUserID: userID, signingIdentifier: signingIdentifier, codeDirectoryHashes: codeDirectoryHashes)
    }

    /// The server role always requires root; a caller cannot enroll another UID.
    static func helper(codeDirectoryHashes: Set<Data>) throws -> VPNPeerPolicy {
        try VPNPeerPolicy(trustedUserID: 0, signingIdentifier: "kz.documentolog.proxypilot.vpn-helper",
                          codeDirectoryHashes: codeDirectoryHashes)
    }

    /// The exact signed frontend build running its authorized installation mode.
    /// Root alone is NOT sufficient. This role may only probe readiness, never
    /// submit the owner's profile/commands on this connection.
    static func installer(codeDirectoryHashes: Set<Data>) throws -> VPNPeerPolicy {
        try VPNPeerPolicy(trustedUserID: 0, signingIdentifier: "kz.documentolog.proxypilot",
                          codeDirectoryHashes: codeDirectoryHashes)
    }

    #if VPN_HELPER_READINESS_TESTING
    // Only for unprivileged disposable process tests, absent in normal builds.
    static func testHelper(codeDirectoryHashes: Set<Data>) throws -> VPNPeerPolicy {
        try VPNPeerPolicy(trustedUserID: geteuid(), signingIdentifier: "kz.documentolog.proxypilot.vpn-helper",
                          codeDirectoryHashes: codeDirectoryHashes)
    }
    #endif

    private init(trustedUserID userID: uid_t, signingIdentifier: String, codeDirectoryHashes: Set<Data>) throws {
        guard userID != uid_t.max,
              !signingIdentifier.isEmpty, signingIdentifier.utf8.count <= 255,
              signingIdentifier.utf8.allSatisfy({
                  (48...57).contains($0) || (65...90).contains($0) ||
                  (97...122).contains($0) || $0 == 45 || $0 == 46
              }),
              !codeDirectoryHashes.isEmpty, codeDirectoryHashes.count <= 16,
              codeDirectoryHashes.allSatisfy({ $0.count == 20 }) else {
            throw VPNPeerAuthenticationError.invalidPolicy
        }
        self.userID = userID
        self.signingIdentifier = signingIdentifier
        self.codeDirectoryHashes = codeDirectoryHashes
    }
}

/// Isolated gate; not linked into the application or any installed service.
/// The caller must own the accepted AF_UNIX stream descriptor, keep it open and
/// serialize its use through authentication and bounded request dispatch. Recheck
/// on every request; never cache an allow decision across requests or reconnects.
/// This authenticates the connector, not a process to which it passes the fd.
enum VPNPeerAuthentication {
    /// Preflight for the exact app executable entering an already authorized
    /// installer mode. Read our live code identity, never argv, a bundle path or
    /// updater metadata. This verifies identity, NOT system authorization, and
    /// does not replace mutual authentication with the running helper.
    static func validateCurrentProcess(policy: VPNPeerPolicy) throws {
        guard getuid() == policy.userID, geteuid() == policy.userID else {
            throw VPNPeerAuthenticationError.denied
        }
        var code: SecCode?
        guard SecCodeCopySelf([], &code) == errSecSuccess, let code = code else {
            throw VPNPeerAuthenticationError.denied
        }
        try validate(code: code, policy: policy)
    }

    static func validate(connectedSocket socket: Int32, policy: VPNPeerPolicy) throws {
        func deny() throws -> Never { throw VPNPeerAuthenticationError.denied }

        var kind: Int32 = 0
        var kindSize = socklen_t(MemoryLayout.size(ofValue: kind))
        guard getsockopt(socket, SOL_SOCKET, SO_TYPE, &kind, &kindSize) == 0,
              kind == SOCK_STREAM else { try deny() }

        var address = sockaddr_storage()
        var addressSize = socklen_t(MemoryLayout.size(ofValue: address))
        let addressResult = withUnsafeMutablePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                getpeername(socket, $0, &addressSize)
            }
        }
        guard addressResult == 0, address.ss_family == sa_family_t(AF_UNIX) else { try deny() }

        var userID: uid_t = 0
        var groupID: gid_t = 0
        guard getpeereid(socket, &userID, &groupID) == 0,
              userID == policy.userID else { try deny() }

        // A kernel-provided audit token includes the process incarnation, unlike
        // a PID supplied by a caller (or a PID-only lookup subject to PID reuse).
        var token = audit_token_t()
        var tokenSize = socklen_t(MemoryLayout.size(ofValue: token))
        guard getsockopt(socket, SOL_LOCAL, LOCAL_PEERTOKEN, &token, &tokenSize) == 0,
              tokenSize == MemoryLayout.size(ofValue: token) else { try deny() }
        let tokenData = withUnsafeBytes(of: token) { Data($0) }
        let attributes = [kSecGuestAttributeAudit as String: tokenData] as CFDictionary
        var code: SecCode?
        guard SecCodeCopyGuestWithAttributes(nil, attributes, [], &code) == errSecSuccess,
              let code = code else { try deny() }
        try validate(code: code, policy: policy)
    }

    /// Shared live-code gate for our own installer and a kernel-identified peer.
    /// Keeping one policy avoids weaker self-checks than the helper will apply.
    private static func validate(code: SecCode, policy: VPNPeerPolicy) throws {
        func deny() throws -> Never { throw VPNPeerAuthenticationError.denied }
        guard SecCodeCheckValidity(code, [], nil) == errSecSuccess else { try deny() }
        var information: CFDictionary?
        let informationFlags = SecCSFlags(rawValue: kSecCSSigningInformation | kSecCSDynamicInformation)
        // This C API explicitly accepts either a dynamic or a static reference;
        // Swift imports only the static parameter type. Preserve the dynamic
        // object (SecCodeCopyStaticCode would lose the runtime status).
        let dynamicReference = unsafeBitCast(code, to: SecStaticCode.self)
        guard SecCodeCopySigningInformation(dynamicReference, informationFlags, &information) == errSecSuccess,
              let info = information as? [String: Any],
              let identifier = info[kSecCodeInfoIdentifier as String] as? String,
              identifier == policy.signingIdentifier,
              let hash = info[kSecCodeInfoUnique as String] as? Data,
              policy.codeDirectoryHashes.contains(hash),
              let flags = info[kSecCodeInfoFlags as String] as? NSNumber,
              let status = info[kSecCodeInfoStatus as String] as? NSNumber else { try deny() }

        // A hash alone cannot protect an injectable/debuggable signed process.
        // Keep this deliberately stricter than today's ad-hoc Sparkle app. Do not
        // weaken it to make that app pass; solve production compatibility first.
        let requiredFlags = SecCodeSignatureFlags.runtime.rawValue | SecCodeSignatureFlags.forceHard.rawValue | SecCodeSignatureFlags.forceKill.rawValue
        let requiredStatus = SecCodeStatus.valid.rawValue | SecCodeStatus.hard.rawValue | SecCodeStatus.kill.rawValue
        guard flags.uint32Value & requiredFlags == requiredFlags,
              status.uint32Value & requiredStatus == requiredStatus,
              status.uint32Value & SecCodeStatus.debugged.rawValue == 0 else { try deny() }

        // No runtime exceptions, task access, JIT or unknown entitlements in the
        // initial policy. Future exceptions require an explicit security review.
        if let entitlements = info[kSecCodeInfoEntitlementsDict as String] {
            guard let dictionary = entitlements as? [String: Any], dictionary.isEmpty else { try deny() }
        }
        // Refresh dynamic validity after reading signing metadata, fail closed.
        guard SecCodeCheckValidity(code, [], nil) == errSecSuccess else { try deny() }
    }
}
