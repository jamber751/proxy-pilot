import Foundation

enum HeldExchangeCheckError: Error { case failed(String), transport }

final class RecordingCredentialTransport: OpenVPNCredentialByteTransport {
    var commands = [[UInt8]]()
    var abortCount = 0
    var failOnWrite: Int?

    func writeCredentialCommand(_ bytes: UnsafeRawBufferPointer) throws {
        if failOnWrite == commands.count { throw HeldExchangeCheckError.transport }
        commands.append(Array(bytes))
    }

    func abortCredentialExchange() { abortCount += 1 }

    func wipe() {
        commands.indices.forEach { index in
            commands[index].withUnsafeMutableBytes {
                _ = $0.initializeMemory(as: UInt8.self, repeating: 0)
            }
            commands[index].removeAll(keepingCapacity: false)
        }
    }
}

@main enum VPNHeldCredentialExchangeChecks {
    static func require(_ condition: @autoclosure () -> Bool, _ message: String) throws {
        if !condition() { throw HeldExchangeCheckError.failed(message) }
    }

    static func application(mode: VPNAuthenticationMode = .password,
                            login: String? = "employee",
                            vpn: Bool = true, key: Bool = false) throws
        -> VPNValidatedApplication {
        let resource = try VPNResource(address: "10.20.0.0/16")
        let authentication = try VPNAuthentication(mode: mode, login: login)
        let spec = try VPNApplicationSpec(revision: 9,
            profileSHA256: String(repeating: "a", count: 64), resources: [resource],
            corporateDNS: [], authentication: authentication)
        return VPNValidatedApplication(spec: spec, requiresVPNCredentials: vpn,
                                       requiresPrivateKeyPassword: key)
    }

    static func challenge(_ kind: VPNCredentialKind,
                          generation: UInt64 = 44) -> VPNCredentialChallenge {
        VPNCredentialChallenge(generation: generation,
            identifier: UUID(uuidString: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")!, kind: kind)
    }

    static func transient(_ bytes: [UInt8], challenge: VPNCredentialChallenge,
                          application: VPNValidatedApplication) throws
        -> OpenVPNTransientCredential {
        var response = VPNCredentialResponse(challenge: challenge, secret: Data(bytes))
        let value = try OpenVPNTransientCredential(response: &response, application: application)
        try require(response.secret.isEmpty, "wire secret retained")
        return value
    }

    static func password() throws {
        let app = try application()
        let token = challenge(.vpnPassword)
        let secret = try transient(Array("secret".utf8), challenge: token, application: app)
        let transport = RecordingCredentialTransport()
        let exchange = try OpenVPNHeldCredentialExchange(challenge: token, application: app,
                                                         transport: transport)
        try exchange.observe(.ready)
        try exchange.observe(.credentialRequired(.usernameAndPassword))
        try exchange.submit(secret)
        try require(transport.commands == [Array("username \"Auth\" \"employee\"\n".utf8),
                                           Array("password \"Auth\" \"secret\"\n".utf8)],
                    "wrong commands")
        try require(exchange.testIsFinished && secret.testIsSpent && secret.testByteCount == 0,
                    "secret not burned")
        try require(transport.abortCount == 0, "successful transport aborted")
        transport.wipe()
        print("password passed")
    }

    static func privateKey() throws {
        let app = try application(mode: .certificate, login: nil, vpn: false, key: true)
        let token = challenge(.privateKeyPassword)
        let secret = try transient(Array("key pass".utf8), challenge: token, application: app)
        let transport = RecordingCredentialTransport()
        let exchange = try OpenVPNHeldCredentialExchange(challenge: token, application: app,
                                                         transport: transport)
        try exchange.observe(.credentialRequired(.privateKeyPassphrase))
        try exchange.submit(secret)
        try require(transport.commands == [Array("password \"Private Key\" \"key pass\"\n".utf8)],
                    "wrong key command")
        transport.wipe()
        print("private key passed")
    }

    static func otp() throws {
        let app = try application(mode: .oneTimePassword)
        let token = challenge(.vpnPassword)
        let secret = try transient(Array("123456".utf8), challenge: token, application: app)
        let transport = RecordingCredentialTransport()
        let exchange = try OpenVPNHeldCredentialExchange(challenge: token, application: app,
                                                         transport: transport)
        try exchange.observe(.credentialRequired(.usernameAndPassword))
        try exchange.submit(secret)
        try require(transport.commands == [Array("username \"Auth\" \"employee\"\n".utf8),
                                           Array("password \"Auth\" \"123456\"\n".utf8)],
                    "OTP was not code-only")
        transport.wipe()
        print("otp passed")
    }

    static func noPrompt() throws {
        let app = try application()
        let token = challenge(.vpnPassword)
        let secret = try transient(Array("secret".utf8), challenge: token, application: app)
        let transport = RecordingCredentialTransport()
        let exchange = try OpenVPNHeldCredentialExchange(challenge: token, application: app,
                                                         transport: transport)
        do {
            try exchange.submit(secret)
            throw HeldExchangeCheckError.failed("unprompted secret accepted")
        } catch OpenVPNHeldCredentialExchangeError.promptNotObserved {}
        try require(secret.testIsSpent && secret.testByteCount == 0, "unprompted secret retained")
        try require(transport.commands.isEmpty && transport.abortCount == 1, "not fail closed")
        print("unprompted rejected")
    }

    static func mismatch() throws {
        let app = try application()
        let token = challenge(.vpnPassword)
        let transport = RecordingCredentialTransport()
        let exchange = try OpenVPNHeldCredentialExchange(challenge: token, application: app,
                                                         transport: transport)
        do {
            try exchange.observe(.credentialRequired(.privateKeyPassphrase))
            throw HeldExchangeCheckError.failed("wrong prompt accepted")
        } catch OpenVPNHeldCredentialExchangeError.unexpectedPrompt {}
        let secret = try transient(Array("secret".utf8), challenge: token, application: app)
        do {
            try exchange.submit(secret)
            throw HeldExchangeCheckError.failed("terminal exchange reused")
        } catch OpenVPNHeldCredentialExchangeError.exchangeFinished {}
        try require(secret.testIsSpent && secret.testByteCount == 0, "mismatch secret retained")
        try require(transport.commands.isEmpty && transport.abortCount == 2, "mismatch not closed")
        print("mismatch rejected")
    }

    static func duplicatePrompt() throws {
        let app = try application()
        let token = challenge(.vpnPassword)
        let transport = RecordingCredentialTransport()
        let exchange = try OpenVPNHeldCredentialExchange(challenge: token, application: app,
                                                         transport: transport)
        try exchange.observe(.credentialRequired(.usernameAndPassword))
        do {
            try exchange.observe(.credentialRequired(.usernameAndPassword))
            throw HeldExchangeCheckError.failed("duplicate prompt accepted")
        } catch OpenVPNHeldCredentialExchangeError.unexpectedPrompt {}
        try require(transport.abortCount == 1, "duplicate prompt transport open")
        print("duplicate rejected")
    }

    static func transportFailure() throws {
        let app = try application()
        let token = challenge(.vpnPassword)
        let secret = try transient(Array("secret".utf8), challenge: token, application: app)
        let transport = RecordingCredentialTransport()
        let exchange = try OpenVPNHeldCredentialExchange(challenge: token, application: app,
                                                         transport: transport)
        transport.failOnWrite = 1
        try exchange.observe(.credentialRequired(.usernameAndPassword))
        do {
            try exchange.submit(secret)
            throw HeldExchangeCheckError.failed("transport failure ignored")
        } catch HeldExchangeCheckError.transport {}
        try require(secret.testIsSpent && secret.testByteCount == 0, "failed secret retained")
        try require(exchange.testIsFinished && transport.abortCount == 1, "failed transport open")
        do {
            try exchange.submit(secret)
            throw HeldExchangeCheckError.failed("failed attempt replayed")
        } catch OpenVPNHeldCredentialExchangeError.exchangeFinished {}
        transport.wipe()
        print("transport failure passed")
    }

    static func otpPolicy() throws {
        let app = try application(mode: .oneTimePassword)
        let token = challenge(.vpnPassword)
        let transport = RecordingCredentialTransport()
        let exchange = try OpenVPNHeldCredentialExchange(challenge: token, application: app,
                                                         transport: transport)
        do {
            try exchange.observe(.credentialRequired(.staticChallenge))
            throw HeldExchangeCheckError.failed("static challenge accepted")
        } catch OpenVPNHeldCredentialExchangeError.unexpectedPrompt {}
        try require(transport.abortCount == 1, "static challenge transport open")
        print("otp policy passed")
    }

    static func rejection() throws {
        let app = try application()
        let token = challenge(.vpnPassword)
        let transport = RecordingCredentialTransport()
        let exchange = try OpenVPNHeldCredentialExchange(challenge: token, application: app,
                                                         transport: transport)
        do {
            try exchange.observe(.credentialRejected(.usernameAndPassword))
            throw HeldExchangeCheckError.failed("credential rejection accepted")
        } catch OpenVPNHeldCredentialExchangeError.engineRejectedCredential {}
        try require(exchange.testIsFinished && transport.abortCount == 1,
                    "rejected credential transport open")
        print("rejection passed")
    }

    static func main() throws {
        guard CommandLine.arguments.count == 2 else { exit(64) }
        switch CommandLine.arguments[1] {
        case "password": try password()
        case "private-key": try privateKey()
        case "otp": try otp()
        case "no-prompt": try noPrompt()
        case "mismatch": try mismatch()
        case "duplicate": try duplicatePrompt()
        case "transport-failure": try transportFailure()
        case "otp-policy": try otpPolicy()
        case "rejection": try rejection()
        default: exit(64)
        }
    }
}
