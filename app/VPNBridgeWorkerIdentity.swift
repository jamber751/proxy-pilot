import Darwin
import Foundation
import Security

extension VPNBridgeWorkerProcess {
    /// Kernel audit identity AND owned incarnation AND fixed live signed code.
    /// PID/UID or a matching disk image alone never authorizes the API peer.
    func authenticate(_ token: audit_token_t) throws {
        try checkLive()
        guard Int32(bitPattern:token.val.5)==child.pid else { throw VPNBridgeWorkerError.unavailable }
        let initial=try VPNBridgeWorkerStamp.live(child.pid)
        guard initial==child else { throw VPNBridgeWorkerError.unavailable }
        let audit=withUnsafeBytes(of:token) { Data($0) }
        var code:SecCode?
        let attributes=[kSecGuestAttributeAudit as String:audit] as CFDictionary
        guard SecCodeCopyGuestWithAttributes(nil,attributes,[],&code)==errSecSuccess,let code,
              SecCodeCheckValidity(code,SecCSFlags(rawValue:kSecCSStrictValidate),nil)==errSecSuccess else {
            throw VPNBridgeWorkerError.unavailable
        }
        var raw:CFDictionary?
        let dynamic=unsafeBitCast(code,to:SecStaticCode.self)
        guard SecCodeCopySigningInformation(dynamic,SecCSFlags(rawValue:kSecCSSigningInformation),&raw)==errSecSuccess,
              let info=raw as? [String:Any],
              info[kSecCodeInfoIdentifier as String] as? String=="kz.documentolog.proxypilot.bridge.gost",
              let hash=info[kSecCodeInfoUnique as String] as? Data else { throw VPNBridgeWorkerError.unavailable }
        #if arch(arm64)
        let expected="f853a72a626e8b59dd768dc3b011b3d617626602"
        #else
        let expected="a29dc60b0d6ffb7de83e24cbaa91528c6aef7fb0"
        #endif
        guard hash.map({ String(format:"%02x",$0) }).joined()==expected else { throw VPNBridgeWorkerError.unavailable }
        try checkLive()
        guard try VPNBridgeWorkerStamp.live(child.pid)==initial else { throw VPNBridgeWorkerError.unavailable }
    }
}
