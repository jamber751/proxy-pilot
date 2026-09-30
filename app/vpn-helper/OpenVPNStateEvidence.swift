import Darwin
import Foundation

enum OpenVPNIPAddressFamily: UInt8, Equatable {
    case ipv4 = 4
    case ipv6 = 6
}

enum OpenVPNStateEvidenceError: Error { case invalidAddress }

/// A binary-only address. Management descriptions and peer address strings do
/// not cross the parser boundary, which keeps diagnostics redacted by design.
struct OpenVPNIPAddress: Equatable {
    let family: OpenVPNIPAddressFamily
    let bytes: [UInt8]

    init(parsing text: Substring, family: OpenVPNIPAddressFamily) throws {
        guard !text.isEmpty, text.utf8.count <= Int(INET6_ADDRSTRLEN) else {
            throw OpenVPNStateEvidenceError.invalidAddress
        }
        var result = [UInt8](repeating: 0, count: family == .ipv4 ? 4 : 16)
        let nativeFamily = family == .ipv4 ? AF_INET : AF_INET6
        guard String(text).withCString({ source in
            result.withUnsafeMutableBytes { inet_pton(nativeFamily, source, $0.baseAddress!) }
        }) == 1 else { throw OpenVPNStateEvidenceError.invalidAddress }
        self.family = family
        bytes = result
    }

    init(family: OpenVPNIPAddressFamily, bytes: [UInt8]) throws {
        guard bytes.count == (family == .ipv4 ? 4 : 16) else {
            throw OpenVPNStateEvidenceError.invalidAddress
        }
        self.family = family
        self.bytes = bytes
    }
}

struct OpenVPNConnectedEvidence: Equatable {
    let tunnelLocalIPv4: OpenVPNIPAddress?
    let tunnelLocalIPv6: OpenVPNIPAddress?
    let remoteAddress: OpenVPNIPAddress
    let remotePort: UInt16
}

struct OpenVPNStateEvidence: Equatable {
    static let maximumTimestamp: UInt64 = 4_102_444_800 // 2100-01-01 UTC

    let timestamp: UInt64
    let state: OpenVPNConnectionState
    let connected: OpenVPNConnectedEvidence?
}
