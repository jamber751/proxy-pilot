import Foundation

enum OpenVPNManagementParseError: Error {
    case malformed, unsupportedEncoding, invalidStateHeader, invalidConnectedShape(Int)
    case invalidTunnelAddress, invalidPeerEndpoint, invalidLocalEndpoint
}

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
        if line == "END" { return .commandCompleted }
        if line.hasPrefix(">HOLD:") { return .hold }
        if line.hasPrefix(">FATAL:") { return .fatal }
        if line.hasPrefix(">STATE:") { return try parseState(String(line.dropFirst(7))) }
        // OpenVPN owns this transient session token. It is not a credential
        // challenge or connection proof, and must never become an event/log.
        if line.hasPrefix(">PASSWORD:Auth-Token:") { return nil }
        if line.hasPrefix(">PASSWORD:") { return try parsePassword(line) }
        // A direct `state` command returns the same CSV state without the
        // asynchronous prefix, followed by an END marker.
        if line.first?.isNumber == true, line.contains(",") { return try parseState(line) }

        // Known asynchronous messages are noise for this minimal client. The
        // caller caps how many may be skipped before yielding an error.
        if line.first == ">" { return nil }
        throw OpenVPNManagementParseError.malformed
    }

    static func parseStateEvidence(_ body: String) throws -> OpenVPNStateEvidence {
        let fields = body.split(separator: ",", omittingEmptySubsequences: false)
        guard (2...9).contains(fields.count), fields.allSatisfy({ $0.utf8.count <= 255 }),
              fields[0].count <= 10, !fields[0].isEmpty,
              fields[0].utf8.allSatisfy({ (48...57).contains($0) }),
              let timestamp = UInt64(fields[0]), timestamp <= OpenVPNStateEvidence.maximumTimestamp,
              let state = OpenVPNConnectionState(rawValue: String(fields[1])) else {
            throw OpenVPNManagementParseError.invalidStateHeader
        }
        guard state == .connected else {
            return OpenVPNStateEvidence(timestamp: timestamp, state: state, connected: nil)
        }
        // OpenVPN 2.x omits the final tunnel IPv6 column on IPv4-only tunnels.
        // Modern IPv4 replies therefore have eight fields, not nine.
        guard fields.count == 6 || fields.count == 8 || fields.count == 9 else {
            throw OpenVPNManagementParseError.invalidConnectedShape(fields.count)
        }
        let local4 = try optionalAddress(fields[3], family: .ipv4)
        let remote: (OpenVPNIPAddress, UInt16)
        do { remote = try endpoint(address: fields[4], port: fields[5]) }
        catch { throw OpenVPNManagementParseError.invalidPeerEndpoint }
        let local6 = fields.count == 9 ? try optionalAddress(fields[8], family: .ipv6) : nil
        if fields.count >= 8, !(fields[6].isEmpty && fields[7].isEmpty) {
            // OpenVPN emits two empty columns when its UDP socket remains
            // bound to an unspecified address. This optional transport address
            // is not tunnel evidence; the peer and tunnel are still required.
            let localTransport: (OpenVPNIPAddress, UInt16)
            do { localTransport = try endpoint(address: fields[6], port: fields[7]) }
            catch { throw OpenVPNManagementParseError.invalidLocalEndpoint }
            guard localTransport.0.family == remote.0.family else {
                throw OpenVPNManagementParseError.invalidLocalEndpoint
            }
        }
        guard local4 != nil || local6 != nil else {
            throw OpenVPNManagementParseError.invalidTunnelAddress
        }
        let connected = OpenVPNConnectedEvidence(tunnelLocalIPv4: local4,
            tunnelLocalIPv6: local6, remoteAddress: remote.0, remotePort: remote.1)
        return OpenVPNStateEvidence(timestamp: timestamp, state: state, connected: connected)
    }

    private static func parseState(_ body: String) throws -> OpenVPNManagementEvent {
        .state(try parseStateEvidence(body))
    }

    private static func optionalAddress(_ text: Substring,
                                        family: OpenVPNIPAddressFamily) throws -> OpenVPNIPAddress? {
        guard !text.isEmpty else { return nil }
        do { return try OpenVPNIPAddress(parsing: text, family: family) }
        catch { throw OpenVPNManagementParseError.invalidTunnelAddress }
    }

    private static func endpoint(address: Substring, port: Substring) throws
        -> (OpenVPNIPAddress, UInt16) {
        guard !address.isEmpty, !port.isEmpty, port.utf8.count <= 5,
              port.utf8.allSatisfy({ (48...57).contains($0) }),
              let parsed = UInt16(port), parsed > 0 else {
            throw OpenVPNManagementParseError.malformed
        }
        if let value = try? OpenVPNIPAddress(parsing: address, family: .ipv4) {
            return (value, parsed)
        }
        if let value = try? OpenVPNIPAddress(parsing: address, family: .ipv6) {
            return (value, parsed)
        }
        throw OpenVPNManagementParseError.malformed
    }

    private static func parsePassword(_ line: String) throws -> OpenVPNManagementEvent {
        let requiredPrefix = ">PASSWORD:Need "
        if line.hasPrefix(requiredPrefix) {
            let body = line.dropFirst(requiredPrefix.count)
            if body == "'Auth' username/password" {
                return .credentialRequired(.usernameAndPassword)
            }
            if body == "'Private Key' password" {
                return .credentialRequired(.privateKeyPassphrase)
            }
            let staticPrefix = "'Auth' username/password SC:"
            if body.hasPrefix(staticPrefix), body.dropFirst(staticPrefix.count).utf8.count > 0,
               body.dropFirst(staticPrefix.count).utf8.count <= 255 {
                return .credentialRequired(.staticChallenge)
            }
            throw OpenVPNManagementParseError.malformed
        }
        let rejectedPrefix = ">PASSWORD:Verification Failed: "
        guard line.hasPrefix(rejectedPrefix) else {
            throw OpenVPNManagementParseError.malformed
        }
        let body = line.dropFirst(rejectedPrefix.count)
        for (label, kind) in [("'Auth'", OpenVPNCredentialKind.usernameAndPassword),
                              ("'Private Key'", OpenVPNCredentialKind.privateKeyPassphrase)] {
            if body == label { return .credentialRejected(kind) }
            let prefix = label + " ['"
            if body.hasPrefix(prefix), body.hasSuffix("']"),
               body.count > prefix.count + 2, body.utf8.count <= 512 {
                // The server's explanation is deliberately discarded. A
                // rejected credential remains rejected regardless of wording.
                return .credentialRejected(kind)
            }
        }
        throw OpenVPNManagementParseError.malformed
    }
}
