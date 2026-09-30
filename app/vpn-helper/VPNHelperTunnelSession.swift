import Foundation

extension VPNHelperSession {
    func storeProfile(_ profile: Data) throws -> VPNHelperStatus {
        try request(.storeProfile, payload: [UInt8](profile)).0
    }

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

    func submitCredentialExchange(_ response: inout VPNCredentialResponse) throws
        -> (VPNHelperStatus, VPNCredentialChallenge?) {
        var payload = try response.encoded()
        defer {
            payload.resetBytes(in: 0..<payload.count)
            payload.removeAll(keepingCapacity: false)
            response.secret.resetBytes(in: 0..<response.secret.count)
            response.secret.removeAll(keepingCapacity: false)
        }
        let (status, body) = try request(.submitCredential, payload: [UInt8](payload))
        let challenge = status == .needsCredential
            ? try VPNCredentialChallenge.decodeCanonical(Data(body)) : nil
        return (status, challenge)
    }

    func cancelCredential(_ challenge: VPNCredentialChallenge) throws -> VPNHelperStatus {
        try request(.cancelCredential, payload: [UInt8](try challenge.encoded())).0
    }
}
