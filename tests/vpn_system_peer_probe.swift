import Darwin
import Dispatch
import Foundation
import Security

/// Explicit, read-only system acceptance diagnostic. No commands/profile bytes
/// are sent. This unpinned process is EXPECTED to be refused by the helper; it
/// only reports whether the ordinary user can inspect the kernel-identified peer.
@main
enum VPNSystemPeerProbe {
  static func main() {
    guard getuid() != 0, getuid() == geteuid(),
      CommandLine.arguments == [CommandLine.arguments[0], "--inspect-system-peer"]
    else { exit(64) }
    do {
      let socket = try VPNEndpointDirectory.connectSystem(
        deadline: DispatchTime.now().uptimeNanoseconds + 2_000_000_000)
      defer { close(socket) }
      print("endpoint=ok")
      var uid: uid_t = 0
      var gid: gid_t = 0
      print("peerUIDQuery=\(getpeereid(socket, &uid, &gid)) root=\(uid == 0)")
      var token = audit_token_t()
      var count = socklen_t(MemoryLayout<audit_token_t>.size)
      let tokenResult = getsockopt(socket, SOL_LOCAL, LOCAL_PEERTOKEN, &token, &count)
      print("auditToken=\(tokenResult)")
      guard tokenResult == 0 else { exit(1) }
      let data = withUnsafeBytes(of: token) { Data($0) }
      for memoryOnly in [false, true] {
        var attributes: [String: Any] = [kSecGuestAttributeAudit as String: data]
        if memoryOnly { attributes[kSecGuestAttributeDynamicCode as String] = true }
        var code: SecCode?
        let result = SecCodeCopyGuestWithAttributes(nil, attributes as CFDictionary, [], &code)
        print("copyGuest(memory=\(memoryOnly))=\(result)")
        guard let code = code, result == errSecSuccess else { continue }
        print("validity=\(SecCodeCheckValidity(code, [], nil))")
        var info: CFDictionary?
        let resultInfo = SecCodeCopySigningInformation(
          unsafeBitCast(code, to: SecStaticCode.self),
          SecCSFlags(rawValue: kSecCSSigningInformation | kSecCSDynamicInformation), &info)
        print("signingInformation=\(resultInfo)")
        if let info = info as? [String: Any] {
          print(
            "identifierMatches=\((info[kSecCodeInfoIdentifier as String] as? String) == "kz.documentolog.proxypilot.vpn-helper")"
          )
        }
      }
    } catch {
      print("endpoint=failed")
      exit(1)
    }
  }
}
