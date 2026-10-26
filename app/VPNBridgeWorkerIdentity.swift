import Darwin
import Foundation
import Security

extension VPNBridgeWorkerProcess {
    /// Kernel audit identity AND owned incarnation AND fixed live signed code.
    /// PID/UID or a matching disk image alone never authorizes the API peer.
    func authenticate(_ token: audit_token_t) throws {
        guard role == .gost else { throw VPNBridgeWorkerError.unavailable }
        try checkLive()
        guard Int32(bitPattern:token.val.5)==child.pid else { throw VPNBridgeWorkerError.unavailable }
        let audit=withUnsafeBytes(of:token) { Data($0) }
        #if arch(arm64)
        let expected="f853a72a626e8b59dd768dc3b011b3d617626602"
        #else
        let expected="a29dc60b0d6ffb7de83e24cbaa91528c6aef7fb0"
        #endif
        try authenticateOwnedCode(attributes:[kSecGuestAttributeAudit as String:audit],
            identifier:"kz.documentolog.proxypilot.bridge.gost",hash:expected)
    }

    /// Only the fixed resolver's inherited stdout travels through the private
    /// supervisor channel. Its live code is checked while that sole owner/reaper
    /// still holds the child incarnation. This is NOT authentication of an
    /// arbitrary socket peer by PID; API peers must continue using audit tokens.
    func authenticateResolverOutput() throws {
        guard role == .systemResolver else { throw VPNBridgeWorkerError.unavailable }
        #if arch(arm64)
        let expected="7a9452fca18d77d7dfa8894b550d73b2797c9387"
        #else
        let expected="bc859eaa7dbae1cd550060e54c6a7cf8e2089022"
        #endif
        try authenticateOwnedCode(attributes:[kSecGuestAttributePid as String:NSNumber(value:child.pid)],
            identifier:"kz.documentolog.proxypilot.system-resolver",hash:expected)
    }
    private func authenticateOwnedCode(attributes: [String:Any],identifier: String,hash expected: String) throws {
        try checkLive()
        let initial=try VPNBridgeWorkerStamp.live(child.pid)
        guard initial==child else { throw VPNBridgeWorkerError.unavailable }
        var code:SecCode?
        guard SecCodeCopyGuestWithAttributes(nil,attributes as CFDictionary,[],&code)==errSecSuccess,let code,
              SecCodeCheckValidity(code,SecCSFlags(rawValue:kSecCSStrictValidate),nil)==errSecSuccess else {
            throw VPNBridgeWorkerError.unavailable
        }
        var raw:CFDictionary?
        let dynamic=unsafeBitCast(code,to:SecStaticCode.self)
        guard SecCodeCopySigningInformation(dynamic,SecCSFlags(rawValue:kSecCSSigningInformation),&raw)==errSecSuccess,
              let info=raw as? [String:Any],
              info[kSecCodeInfoIdentifier as String] as? String==identifier,
              let hash=info[kSecCodeInfoUnique as String] as? Data else { throw VPNBridgeWorkerError.unavailable }
        guard hash.map({ String(format:"%02x",$0) }).joined()==expected else { throw VPNBridgeWorkerError.unavailable }
        try checkLive()
        guard try VPNBridgeWorkerStamp.live(child.pid)==initial else { throw VPNBridgeWorkerError.unavailable }
    }
}
