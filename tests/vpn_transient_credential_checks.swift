import Foundation

enum CredentialCheckError: Error { case failed(String), sink }
final class ZeroizationObservations { var values = [Bool]() }

@main enum VPNTransientCredentialChecks {
    static func require(_ condition: @autoclosure () -> Bool, _ message: String) throws {
        if !condition() { throw CredentialCheckError.failed(message) }
    }

    static func application(mode: VPNAuthenticationMode, login: String?,
                            vpn: Bool, key: Bool, revision: UInt64 = 1) throws
        -> VPNValidatedApplication {
        let resource = try VPNResource(address: "10.20.0.0/16")
        let authentication = try VPNAuthentication(mode: mode, login: login)
        let spec = try VPNApplicationSpec(revision: revision,
            profileSHA256: String(repeating: "a", count: 64), resources: [resource],
            corporateDNS: [], authentication: authentication)
        return VPNValidatedApplication(spec: spec, requiresVPNCredentials: vpn,
                                       requiresPrivateKeyPassword: key)
    }

    static func challenge(_ kind: VPNCredentialKind, generation: UInt64 = 7) -> VPNCredentialChallenge {
        VPNCredentialChallenge(generation: generation,
            identifier: UUID(uuidString: "11111111-2222-3333-4444-555555555555")!, kind: kind)
    }

    static func observers() -> ZeroizationObservations {
        let observations = ZeroizationObservations()
        OpenVPNTransientCredential.testZeroizationObserver = { bytes in
            observations.values.append(bytes.allSatisfy { $0 == 0 })
        }
        OpenVPNCredentialCommandEncoder.testZeroizationObserver = { bytes in
            observations.values.append(bytes.allSatisfy { $0 == 0 })
        }
        return observations
    }

    static func password() throws {
        let observations = observers()
        let app = try application(mode: .password, login: "u\"\\ser", vpn: true, key: false)
        let token = challenge(.vpnPassword)
        var response = VPNCredentialResponse(challenge: token, secret: Data([112, 34, 92, 97, 115, 115]))
        let transient = try OpenVPNTransientCredential(response: &response, application: app)
        try require(response.secret.isEmpty, "wire secret retained")
        var commands = [[UInt8]]()
        try transient.consume(matching: token, application: app,
                              managementPrompt: .usernameAndPassword) {
            commands.append(Array($0))
        }
        let expectedUser = Array("username \"Auth\" \"u\\\"\\\\ser\"\n".utf8)
        let expectedPassword = Array("password \"Auth\" \"p\\\"\\\\ass\"\n".utf8)
        try require(commands == [expectedUser, expectedPassword], "management escaping")
        commands.indices.forEach { index in
            commands[index].withUnsafeMutableBytes {
                _ = $0.initializeMemory(as: UInt8.self, repeating: 0)
            }
        }
        try require(transient.testIsSpent && transient.testByteCount == 0, "credential retained")
        try require(!observations.values.isEmpty && observations.values.allSatisfy { $0 }, "zeroization")
        do {
            try transient.consume(matching: token, application: app,
                                  managementPrompt: .usernameAndPassword) { _ in }
            throw CredentialCheckError.failed("replay accepted")
        } catch OpenVPNCredentialCommandError.alreadyConsumed {}
        print("password passed")
    }

    static func otp() throws {
        let app = try application(mode: .oneTimePassword, login: "employee", vpn: true, key: false)
        let token = challenge(.vpnPassword)
        var rejected = VPNCredentialResponse(challenge: token, secret: Data("123456".utf8))
        let unsupported = try OpenVPNTransientCredential(response: &rejected, application: app)
        do {
            try unsupported.consume(matching: token, application: app,
                                    managementPrompt: .staticChallenge) { _ in }
            throw CredentialCheckError.failed("combined static challenge accepted")
        } catch OpenVPNCredentialCommandError.unsupportedChallenge {}
        try require(unsupported.testByteCount == 0, "unsupported OTP retained")

        var response = VPNCredentialResponse(challenge: token, secret: Data("123456".utf8))
        let codeOnly = try OpenVPNTransientCredential(response: &response, application: app)
        var commands = [[UInt8]]()
        try codeOnly.consume(matching: token, application: app,
                             managementPrompt: .usernameAndPassword) { commands.append(Array($0)) }
        try require(commands.count == 2,
                    "OTP command count")
        try require(commands[1] == Array("password \"Auth\" \"123456\"\n".utf8),
                    "OTP must be code-only")
        print("otp passed")
    }

    static func privateKey() throws {
        let app = try application(mode: .certificate, login: nil, vpn: false, key: true)
        let token = challenge(.privateKeyPassword)
        var response = VPNCredentialResponse(challenge: token, secret: Data("key pass".utf8))
        let transient = try OpenVPNTransientCredential(response: &response, application: app)
        var commands = [[UInt8]]()
        try transient.consume(matching: token, application: app,
                              managementPrompt: .privateKeyPassphrase) { commands.append(Array($0)) }
        try require(commands == [Array("password \"Private Key\" \"key pass\"\n".utf8)],
                    "private key command")
        print("private key passed")
    }

    static func mismatch() throws {
        let app = try application(mode: .password, login: "employee", vpn: true, key: false)
        var response = VPNCredentialResponse(challenge: challenge(.vpnPassword), secret: Data("secret".utf8))
        let stale = try OpenVPNTransientCredential(response: &response, application: app)
        do {
            try stale.consume(matching: challenge(.vpnPassword, generation: 8), application: app,
                              managementPrompt: .usernameAndPassword) { _ in }
            throw CredentialCheckError.failed("stale accepted")
        } catch OpenVPNCredentialCommandError.staleChallenge {}
        try require(stale.testIsSpent && stale.testByteCount == 0, "stale secret retained")

        var second = VPNCredentialResponse(challenge: challenge(.vpnPassword), secret: Data("secret".utf8))
        let bound = try OpenVPNTransientCredential(response: &second, application: app)
        let changed = try application(mode: .password, login: "other", vpn: true, key: false, revision: 2)
        do {
            try bound.consume(matching: challenge(.vpnPassword), application: changed,
                              managementPrompt: .usernameAndPassword) { _ in }
            throw CredentialCheckError.failed("application mismatch accepted")
        } catch OpenVPNCredentialCommandError.mismatchedApplication {}
        try require(bound.testByteCount == 0, "mismatch retained")

        var wrongKind = VPNCredentialResponse(challenge: challenge(.privateKeyPassword),
                                              secret: Data("secret".utf8))
        do {
            _ = try OpenVPNTransientCredential(response: &wrongKind, application: app)
            throw CredentialCheckError.failed("kind mismatch accepted")
        } catch OpenVPNCredentialCommandError.mismatchedKind {}
        try require(wrongKind.secret.isEmpty, "kind mismatch retained")

        var zeroGeneration = VPNCredentialResponse(
            challenge: challenge(.vpnPassword, generation: 0), secret: Data("secret".utf8))
        do {
            _ = try OpenVPNTransientCredential(response: &zeroGeneration, application: app)
            throw CredentialCheckError.failed("zero generation accepted")
        } catch OpenVPNCredentialCommandError.staleChallenge {}
        try require(zeroGeneration.secret.isEmpty, "invalid challenge retained")
        print("mismatch rejected")
    }

    static func bounds() throws {
        let app = try application(mode: .password, login: "employee", vpn: true, key: false)
        for secret in [Data(), Data("line\nbreak".utf8),
                       Data([65, 127, 66]),
                       Data(repeating: 65, count: OpenVPNCredentialCommandEncoder.maximumSecretBytes + 1)] {
            var response = VPNCredentialResponse(challenge: challenge(.vpnPassword), secret: secret)
            do {
                _ = try OpenVPNTransientCredential(response: &response, application: app)
                throw CredentialCheckError.failed("invalid secret accepted")
            } catch OpenVPNCredentialCommandError.invalidCredential {}
            try require(response.secret.isEmpty, "rejected wire secret retained")
        }
        print("bounds rejected")
    }

    static func failureAndDeinit() throws {
        let observations = observers()
        let app = try application(mode: .password, login: "employee", vpn: true, key: false)
        let token = challenge(.vpnPassword)
        var response = VPNCredentialResponse(challenge: token, secret: Data("secret".utf8))
        let transient = try OpenVPNTransientCredential(response: &response, application: app)
        do {
            try transient.consume(matching: token, application: app,
                                  managementPrompt: .usernameAndPassword) { _ in
                throw CredentialCheckError.sink
            }
            throw CredentialCheckError.failed("sink failure ignored")
        } catch CredentialCheckError.sink {}
        try require(transient.testByteCount == 0, "sink failure retained")
        do {
            var abandoned = VPNCredentialResponse(challenge: token, secret: Data("abandoned".utf8))
            _ = try OpenVPNTransientCredential(response: &abandoned, application: app)
        }
        var cancelledResponse = VPNCredentialResponse(challenge: token, secret: Data("cancelled".utf8))
        let cancelled = try OpenVPNTransientCredential(response: &cancelledResponse, application: app)
        try cancelled.cancel()
        try require(cancelled.testIsSpent && cancelled.testByteCount == 0, "cancel retained")
        do { try cancelled.cancel(); throw CredentialCheckError.failed("cancel replay") }
        catch OpenVPNCredentialCommandError.alreadyConsumed {}
        try require(observations.values.count >= 4 && observations.values.allSatisfy { $0 },
                    "failure/deinit wipe")
        print("failure passed")
    }

    static func main() throws {
        guard CommandLine.arguments.count == 2 else { exit(64) }
        switch CommandLine.arguments[1] {
        case "password": try password()
        case "otp": try otp()
        case "private-key": try privateKey()
        case "mismatch": try mismatch()
        case "bounds": try bounds()
        case "failure": try failureAndDeinit()
        default: exit(64)
        }
    }
}
