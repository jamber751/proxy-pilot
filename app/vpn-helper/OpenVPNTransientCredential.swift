import Darwin
import Foundation

enum OpenVPNCredentialCommandError: Error, Equatable {
    case invalidCredential
    case staleChallenge
    case mismatchedApplication
    case mismatchedKind
    case unsupportedChallenge
    case alreadyConsumed
}

/// Byte-only management command construction. Credential bytes are never
/// converted to String. Every value is quoted, with only quote and backslash
/// escaped; line/control bytes are rejected before a command is emitted.
enum OpenVPNCredentialCommandEncoder {
    // Leaves ample room for worst-case quote/backslash escaping inside one
    // bounded management line; the outer IPC permits more only for forwards
    // compatibility and is not the engine command limit.
    static let maximumSecretBytes = 1024
    static let maximumLoginBytes = 255
    static let maximumCommandBytes = 4096

    #if VPN_TRANSIENT_CREDENTIAL_TESTING
    static var testZeroizationObserver: (([UInt8]) -> Void)?
    #endif

    static func emit(authentication: VPNAuthentication,
                     prompt: OpenVPNCredentialKind,
                     secret: UnsafeRawBufferPointer,
                     sink: (UnsafeRawBufferPointer) throws -> Void) throws {
        guard valid(secret, maximum: maximumSecretBytes) else {
            throw OpenVPNCredentialCommandError.invalidCredential
        }
        switch prompt {
        case .staticChallenge:
            // OpenVPN static challenge can mean password+OTP. ProxyPilot's OTP
            // policy is code-only, so guessing or concatenating is forbidden.
            throw OpenVPNCredentialCommandError.unsupportedChallenge
        case .usernameAndPassword:
            guard authentication.mode != .certificate, let login = authentication.login else {
                throw OpenVPNCredentialCommandError.mismatchedKind
            }
            let loginBytes = Array(login.utf8)
            let loginValid = loginBytes.withUnsafeBytes { valid($0, maximum: maximumLoginBytes) }
            guard loginValid else {
                throw OpenVPNCredentialCommandError.invalidCredential
            }
            try loginBytes.withUnsafeBytes {
                try emitCommand(verb: Array("username".utf8), label: Array("Auth".utf8),
                                value: $0, sink: sink)
            }
            try emitCommand(verb: Array("password".utf8), label: Array("Auth".utf8),
                            value: secret, sink: sink)
        case .privateKeyPassphrase:
            try emitCommand(verb: Array("password".utf8), label: Array("Private Key".utf8),
                            value: secret, sink: sink)
        }
    }

    private static func emitCommand(verb: [UInt8], label: [UInt8],
                                    value: UnsafeRawBufferPointer,
                                    sink: (UnsafeRawBufferPointer) throws -> Void) throws {
        var command = verb
        command.append(32)
        label.withUnsafeBytes { appendQuoted($0, to: &command) }
        command.append(32)
        appendQuoted(value, to: &command)
        command.append(10)
        defer { wipe(&command) }
        guard command.count <= maximumCommandBytes else {
            throw OpenVPNCredentialCommandError.invalidCredential
        }
        try command.withUnsafeBytes(sink)
    }

    private static func appendQuoted(_ value: UnsafeRawBufferPointer, to output: inout [UInt8]) {
        output.append(34)
        for byte in value {
            if byte == 34 || byte == 92 { output.append(92) }
            output.append(byte)
        }
        output.append(34)
    }

    private static func valid(_ value: UnsafeRawBufferPointer, maximum: Int) -> Bool {
        !value.isEmpty && value.count <= maximum && value.allSatisfy {
            $0 >= 32 && $0 != 127
        }
    }

    private static func wipe(_ bytes: inout [UInt8]) {
        bytes.withUnsafeMutableBytes { buffer in
            if let base = buffer.baseAddress, !buffer.isEmpty {
                _ = memset_s(base, buffer.count, 0, buffer.count)
            }
        }
        #if VPN_TRANSIENT_CREDENTIAL_TESTING
        testZeroizationObserver?(bytes)
        #endif
        bytes.removeAll(keepingCapacity: false)
    }
}

/// One challenge-bound credential attempt. Construction transfers bytes out of
/// the wire response and immediately clears it. The first consume/cancel/fail
/// burns the object; all paths explicitly zero the owned allocation.
final class OpenVPNTransientCredential {
    private let challenge: VPNCredentialChallenge
    private let application: VPNValidatedApplication
    private var bytes: [UInt8]
    private var spent = false

    #if VPN_TRANSIENT_CREDENTIAL_TESTING
    static var testZeroizationObserver: (([UInt8]) -> Void)?
    var testIsSpent: Bool { spent }
    var testByteCount: Int { bytes.count }
    #endif

    init(response: inout VPNCredentialResponse,
         application: VPNValidatedApplication) throws {
        defer {
            response.secret.resetBytes(in: 0..<response.secret.count)
            response.secret.removeAll(keepingCapacity: false)
        }
        try application.validate()
        guard response.challenge.schemaVersion == VPNCredentialChallenge.schema,
              response.challenge.generation > 0 else {
            throw OpenVPNCredentialCommandError.staleChallenge
        }
        var candidate = [UInt8](response.secret)
        guard !candidate.isEmpty, candidate.count <= Self.maximumBytes,
              candidate.allSatisfy({ $0 >= 32 && $0 != 127 }) else {
            Self.wipe(&candidate)
            throw OpenVPNCredentialCommandError.invalidCredential
        }
        switch response.challenge.kind {
        case .vpnPassword:
            guard application.requiresVPNCredentials,
                  application.spec.authentication.mode != .certificate else {
                Self.wipe(&candidate)
                throw OpenVPNCredentialCommandError.mismatchedKind
            }
        case .privateKeyPassword:
            guard application.requiresPrivateKeyPassword else {
                Self.wipe(&candidate)
                throw OpenVPNCredentialCommandError.mismatchedKind
            }
        }
        challenge = response.challenge
        self.application = application
        bytes = candidate
    }

    deinit { wipe() }

    func consume(matching suppliedChallenge: VPNCredentialChallenge,
                 application suppliedApplication: VPNValidatedApplication,
                 managementPrompt: OpenVPNCredentialKind,
                 sink: (UnsafeRawBufferPointer) throws -> Void) throws {
        guard !spent else { throw OpenVPNCredentialCommandError.alreadyConsumed }
        spent = true
        defer { wipe() }
        guard suppliedChallenge == challenge else {
            throw OpenVPNCredentialCommandError.staleChallenge
        }
        guard suppliedApplication == application else {
            throw OpenVPNCredentialCommandError.mismatchedApplication
        }
        let expected: OpenVPNCredentialKind = challenge.kind == .privateKeyPassword
            ? .privateKeyPassphrase : .usernameAndPassword
        guard managementPrompt == expected else {
            if managementPrompt == .staticChallenge {
                throw OpenVPNCredentialCommandError.unsupportedChallenge
            }
            throw OpenVPNCredentialCommandError.mismatchedKind
        }
        try bytes.withUnsafeBytes {
            try OpenVPNCredentialCommandEncoder.emit(
                authentication: application.spec.authentication,
                prompt: managementPrompt, secret: $0, sink: sink)
        }
    }

    func cancel() throws {
        guard !spent else { throw OpenVPNCredentialCommandError.alreadyConsumed }
        spent = true
        wipe()
    }

    func fail() {
        guard !spent else { return }
        spent = true
        wipe()
    }

    private static let maximumBytes = OpenVPNCredentialCommandEncoder.maximumSecretBytes

    private func wipe() {
        Self.wipe(&bytes)
    }

    private static func wipe(_ value: inout [UInt8]) {
        value.withUnsafeMutableBytes { buffer in
            if let base = buffer.baseAddress, !buffer.isEmpty {
                _ = memset_s(base, buffer.count, 0, buffer.count)
            }
        }
        #if VPN_TRANSIENT_CREDENTIAL_TESTING
        testZeroizationObserver?(value)
        #endif
        value.removeAll(keepingCapacity: false)
    }
}
