import Foundation

enum OpenVPNManagementParseError: Error { case malformed, unsupportedEncoding }

enum OpenVPNManagementParser {
    static let maximumLineBytes = 4096

    /// Parses only the protocol surface needed by the tunnel coordinator.
    /// `nil` means a bounded, intentionally ignored notification (for example
    /// LOG or BYTECOUNT); no ignored text is retained or returned.
    static func parse(line bytes: [UInt8]) throws -> OpenVPNManagementEvent? {
        guard !bytes.isEmpty, bytes.count <= maximumLineBytes,
              !bytes.contains(0),
              bytes.allSatisfy({ $0 >= 32 }),
              let line = String(bytes: bytes, encoding: .utf8) else {
            throw OpenVPNManagementParseError.unsupportedEncoding
        }

        if line.hasPrefix(">INFO:") { return .ready }
        if line.hasPrefix("SUCCESS:") { return .commandSucceeded }
        if line.hasPrefix("ERROR:") { return .commandFailed }
        if line.hasPrefix(">HOLD:") { return .hold }
        if line.hasPrefix(">FATAL:") { return .fatal }
        if line.hasPrefix(">STATE:") { return try parseState(String(line.dropFirst(7))) }
        if line.hasPrefix(">PASSWORD:") { return try parsePassword(line) }

        // Known asynchronous messages are noise for this minimal client. The
        // caller caps how many may be skipped before yielding an error.
        if line.first == ">" { return nil }
        throw OpenVPNManagementParseError.malformed
    }

    private static func parseState(_ body: String) throws -> OpenVPNManagementEvent {
        let fields = body.split(separator: ",", omittingEmptySubsequences: false)
        guard fields.count >= 2, fields[0].count <= 20, !fields[0].isEmpty,
              fields[0].utf8.allSatisfy({ (48...57).contains($0) }),
              let state = OpenVPNConnectionState(rawValue: String(fields[1])) else {
            throw OpenVPNManagementParseError.malformed
        }
        return .state(state)
    }

    private static func parsePassword(_ line: String) throws -> OpenVPNManagementEvent {
        let rejected = line.hasPrefix(">PASSWORD:Verification Failed:")
        let required = line.hasPrefix(">PASSWORD:Need '")
        guard rejected || required else { throw OpenVPNManagementParseError.malformed }

        let kind: OpenVPNCredentialKind
        if line.contains("Private Key") {
            kind = .privateKeyPassphrase
        } else if line.contains("Static Challenge") || line.contains("SC:") {
            kind = .staticChallenge
        } else if line.contains("'Auth'") {
            kind = .usernameAndPassword
        } else {
            throw OpenVPNManagementParseError.malformed
        }
        return rejected ? .credentialRejected(kind) : .credentialRequired(kind)
    }
}
