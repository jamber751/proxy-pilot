import Darwin
import Foundation
import Security
import CoreGraphics
import CryptoKit

// Experiment only. Never link into the app. Single-threaded child processes
// serialize the process-wide legacy UI setting; no production policy implied.
@main enum VPNLegacyKeychainVMChecks {
    static let service = "kz.documentolog.proxypilot.synthetic-vm-password"
    static let account = "synthetic-profile-only"
    static let secret = Data("synthetic-not-a-vpn-password".utf8)
    static let password = Data("synthetic-keychain-unlock-only".utf8)
    #if LEGACY_KEYCHAIN_V2
    static let build = "v2-different-code"
    #else
    static let build = "v1-original-code"
    #endif

    static func require(_ condition: Bool) {
        if !condition { exit(77) }
    }

    static func safeDirectory(_ path: String) -> String {
        let url = URL(fileURLWithPath: path)
        let canonical = url.resolvingSymlinksInPath().path
        require(canonical == path && url.lastPathComponent.hasPrefix("pp-legacy-keychain-vm-"))
        require(url.deletingLastPathComponent().path == "/private/tmp")
        var info = stat()
        require(lstat(path, &info) == 0 && info.st_mode & S_IFMT == S_IFDIR
                && info.st_uid == getuid() && info.st_mode & 0o7777 == 0o700)
        return path + "/experiment.keychain"
    }

    static func windows() -> [String: Any] {
        let session = CGSessionCopyCurrentDictionary() as? [String: Any]
        let gui = session?[kCGSessionOnConsoleKey as String] as? Bool == true
        guard let list = CGWindowListCopyWindowInfo(.optionOnScreenOnly, kCGNullWindowID)
                as? [[String: Any]] else { return ["consoleSession": gui, "windowMetadata": false] }
        let count = list.filter {
            (($0[kCGWindowOwnerName as String] as? String) ?? "").lowercased().contains("securityagent")
        }.count
        // No titles, account names, other app identities or window content.
        return ["consoleSession": gui, "windowMetadata": true, "securityAgentWindows": count]
    }

    static func preferenceMetadata() throws -> String {
        func path(_ keychain: SecKeychain) throws -> String {
            var count: UInt32 = 4096
            var bytes = [CChar](repeating: 0, count: Int(count))
            guard SecKeychainGetPath(keychain, &count, &bytes) == errSecSuccess else { throw CheckError.operation }
            return String(cString: bytes)
        }
        // References/paths only, no item queries; never print paths or change
        // any preference. A different snapshot FAILS, without compensation.
        var list: CFArray?
        guard SecKeychainCopySearchList(&list) == errSecSuccess,
              let references = list as? [SecKeychain] else { throw CheckError.operation }
        var currentDefault: SecKeychain?
        let status = SecKeychainCopyDefault(&currentDefault)
        guard status == errSecSuccess || status == errSecNoDefaultKeychain else { throw CheckError.operation }
        let defaultPath = try currentDefault.map { try path($0) }
        let canonical = try JSONSerialization.data(withJSONObject: [
            "search": try references.map { try path($0) }, "default": defaultPath ?? "", "status": status
        ], options: .sortedKeys)
        return SHA256.hash(data: canonical).map { String(format: "%02x", $0) }.joined()
    }

    static func main() {
        let env = ProcessInfo.processInfo.environment
        // Must precede ANY Security API, including the interaction-flag getter.
        guard env["GITHUB_ACTIONS"] == "true",
              env["PROXYPILOT_VM_KEYCHAIN_TESTS"] == "1",
              getuid() == geteuid(), getuid() >= 500,
              CommandLine.arguments.count == 3 else { exit(77) }
        let action = CommandLine.arguments[1]
        guard ["create", "read", "locked-read", "delete", "observe", "metadata"].contains(action) else { exit(64) }
        let path = safeDirectory(CommandLine.arguments[2])
        if action == "observe" {
            let data = try! JSONSerialization.data(withJSONObject: windows(), options: .sortedKeys)
            print(String(decoding: data, as: UTF8.self)); return
        }
        var prior: DarwinBoolean = false
        require(SecKeychainGetUserInteractionAllowed(&prior) == errSecSuccess)
        var result: [String: Any] = ["build": build, "priorInteraction": prior.boolValue]
        // No early exits inside this scope: always restore before reporting.
        do {
            defer {
                let status = SecKeychainSetUserInteractionAllowed(prior.boolValue)
                var restored = DarwinBoolean(!prior.boolValue)
                let checked = SecKeychainGetUserInteractionAllowed(&restored)
                result["interactionRestored"] = status == errSecSuccess
                    && checked == errSecSuccess && restored.boolValue == prior.boolValue
            }
            guard SecKeychainSetUserInteractionAllowed(false) == errSecSuccess else { throw CheckError.operation }
            var disabled: DarwinBoolean = true
            guard SecKeychainGetUserInteractionAllowed(&disabled) == errSecSuccess,
                  !disabled.boolValue else { throw CheckError.operation }
            if action == "metadata" {
                result["preferences"] = try preferenceMetadata()
            } else {
            var keychain: SecKeychain?
            let opened: OSStatus
            if action == "create" {
                var info = stat()
                guard lstat(path, &info) != 0 && errno == ENOENT,
                      lstat(path + "-db", &info) != 0 && errno == ENOENT else { throw CheckError.unsafe }
                opened = password.withUnsafeBytes {
                    SecKeychainCreate(path, UInt32($0.count), $0.baseAddress, false, nil, &keychain)
                }
            } else {
                // Open only a regular, private, user-owned file in our directory.
                var info = stat()
                let actual = FileManager.default.fileExists(atPath: path + "-db") ? path + "-db" : path
                guard lstat(actual, &info) == 0, info.st_mode & S_IFMT == S_IFREG,
                      info.st_uid == getuid(), info.st_mode & 0o077 == 0,
                      info.st_nlink == 1 else { throw CheckError.unsafe }
                opened = SecKeychainOpen(path, &keychain)
            }
            result["openStatus"] = opened
            guard opened == errSecSuccess, let keychain else { throw CheckError.operation }
            if action == "delete" {
                result["status"] = SecKeychainDelete(keychain)
            } else {
                if action == "create" {
                    // Default creator ACL only. No custom ACL, trusted app list,
                    // partition-list rewrite or allow-all policy.
                    let attrs: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                        kSecAttrService as String: service, kSecAttrAccount as String: account,
                        kSecUseKeychain as String: keychain, kSecValueData as String: secret]
                    let added = SecItemAdd(attrs as CFDictionary, nil)
                    result["addStatus"] = added
                    guard added == errSecSuccess else { throw CheckError.operation }
                }
                if action == "locked-read" {
                    let locked = SecKeychainLock(keychain)
                    result["lockStatus"] = locked
                    guard locked == errSecSuccess else { throw CheckError.operation }
                }
                var value: CFTypeRef?
                // Fixed custom search list, never ambient login/System search.
                // Legacy process UI setting is the experiment, not optional
                // SecItem authentication-UI flags with unproved legacy effect.
                let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                    kSecAttrService as String: service, kSecAttrAccount as String: account,
                    kSecMatchSearchList as String: [keychain], kSecMatchLimit as String: kSecMatchLimitOne,
                    kSecReturnData as String: true]
                let status = SecItemCopyMatching(query as CFDictionary, &value)
                result["status"] = status
                result["secretMatches"] = status == errSecSuccess && (value as? Data) == secret
            }
            }
        } catch { result["setupFailed"] = true }
        let data = try! JSONSerialization.data(withJSONObject: result, options: .sortedKeys)
        print(String(decoding: data, as: UTF8.self))
    }
    enum CheckError: Error { case unsafe, operation }
}
