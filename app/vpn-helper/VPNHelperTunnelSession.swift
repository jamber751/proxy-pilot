import Foundation

extension VPNHelperSession {
    func apply(_ specification: VPNApplicationSpec) throws -> VPNHelperStatus {
        let (status, _) = try request(.applyConfiguration, payload: [UInt8](try specification.encoded()))
        return status
    }

    func connect() throws -> (VPNHelperStatus, VPNCredentialChallenge?) {
        let (status, body) = try request(.connect)
        let challenge = status == .needsCredential
            ? try VPNCredentialChallenge.decodeCanonical(Data(body)) : nil
        return (status, challenge)
    }

    func disconnectTunnel() throws -> VPNHelperStatus { try request(.disconnect).0 }

    func tunnelStatus() throws -> (VPNHelperStatus, VPNTunnelSnapshot?) {
        let (status, body) = try request(.tunnelStatus)
        guard status == .ok else { return (status, nil) }
        let snapshot = try JSONDecoder().decode(VPNTunnelSnapshot.self, from: Data(body))
        try snapshot.validate()
        guard try snapshot.encoded() == Data(body) else { throw VPNHelperSessionError.invalidResponse }
        return (status, snapshot)
    }

    func submitCredential(_ response: VPNCredentialResponse) throws -> VPNHelperStatus {
        try request(.submitCredential, payload: [UInt8](try response.encoded())).0
    }

    func cancelCredential(_ challenge: VPNCredentialChallenge) throws -> VPNHelperStatus {
        try request(.cancelCredential, payload: [UInt8](try challenge.encoded())).0
    }
}
