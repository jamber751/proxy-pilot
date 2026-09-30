import Foundation

enum OpenVPNHeldCredentialExchangeError: Error, Equatable {
    case invalidBinding
    case unexpectedPrompt
    case promptNotObserved
    case exchangeFinished
    case engineRejectedCredential
}

/// Synchronous, byte-only boundary to the already authenticated local
/// management connection. Implementations must either write the complete
/// buffer before returning or throw. `abort()` must make further writes
/// impossible (normally by closing that management connection).
protocol OpenVPNCredentialByteTransport: AnyObject {
    func writeCredentialCommand(_ bytes: UnsafeRawBufferPointer) throws
    func abortCredentialExchange()
}

/// Binds exactly one transient credential to exactly one prompt observed from
/// an OpenVPN process that is still held. This type deliberately has no API for
/// releasing the management hold and owns no persistent representation of a
/// secret.
final class OpenVPNHeldCredentialExchange {
    private enum State {
        case waitingForPrompt
        case promptObserved(OpenVPNCredentialKind)
        case finished
    }

    private let challenge: VPNCredentialChallenge
    private let application: VPNValidatedApplication
    private let expectedPrompt: OpenVPNCredentialKind
    private let transport: OpenVPNCredentialByteTransport
    private let lock = NSLock()
    private var state: State = .waitingForPrompt

    init(challenge: VPNCredentialChallenge,
         application: VPNValidatedApplication,
         transport: OpenVPNCredentialByteTransport) throws {
        try application.validate()
        guard challenge.schemaVersion == VPNCredentialChallenge.schema,
              challenge.generation > 0 else {
            throw OpenVPNHeldCredentialExchangeError.invalidBinding
        }
        switch challenge.kind {
        case .vpnPassword:
            guard application.requiresVPNCredentials,
                  application.spec.authentication.mode != .certificate else {
                throw OpenVPNHeldCredentialExchangeError.invalidBinding
            }
            expectedPrompt = .usernameAndPassword
        case .privateKeyPassword:
            guard application.requiresPrivateKeyPassword else {
                throw OpenVPNHeldCredentialExchangeError.invalidBinding
            }
            expectedPrompt = .privateKeyPassphrase
        }
        self.challenge = challenge
        self.application = application
        self.transport = transport
    }

    /// Accepts only the credential prompt for this exact challenge. Any other
    /// credential prompt or an explicit rejection permanently closes the
    /// exchange. Non-credential management events do not alter the binding.
    func observe(_ event: OpenVPNManagementEvent) throws {
        lock.lock()
        defer { lock.unlock() }
        switch state {
        case .finished:
            transport.abortCredentialExchange()
            throw OpenVPNHeldCredentialExchangeError.exchangeFinished
        case .promptObserved:
            switch event {
            case .credentialRequired, .credentialRejected:
                state = .finished
                transport.abortCredentialExchange()
                throw OpenVPNHeldCredentialExchangeError.unexpectedPrompt
            default:
                return
            }
        case .waitingForPrompt:
            switch event {
            case .credentialRequired(let prompt):
                guard prompt == expectedPrompt else {
                    state = .finished
                    transport.abortCredentialExchange()
                    throw OpenVPNHeldCredentialExchangeError.unexpectedPrompt
                }
                state = .promptObserved(prompt)
            case .credentialRejected:
                state = .finished
                transport.abortCredentialExchange()
                throw OpenVPNHeldCredentialExchangeError.engineRejectedCredential
            default:
                return
            }
        }
    }

    /// Consumes the attempt before the first transport write. Thus a partial
    /// write, timeout, disconnect, encoder error or retry can never reuse it.
    /// On every failure the transport is aborted and the transient secret is
    /// explicitly burned by `OpenVPNTransientCredential.consume`.
    func submit(_ credential: OpenVPNTransientCredential) throws {
        let prompt: OpenVPNCredentialKind
        lock.lock()
        switch state {
        case .waitingForPrompt:
            state = .finished
            lock.unlock()
            credential.fail()
            transport.abortCredentialExchange()
            throw OpenVPNHeldCredentialExchangeError.promptNotObserved
        case .finished:
            lock.unlock()
            credential.fail()
            transport.abortCredentialExchange()
            throw OpenVPNHeldCredentialExchangeError.exchangeFinished
        case .promptObserved(let value):
            prompt = value
            state = .finished
        }

        do {
            try credential.consume(matching: challenge,
                                   application: application,
                                   managementPrompt: prompt) { bytes in
                try transport.writeCredentialCommand(bytes)
            }
        } catch {
            lock.unlock()
            transport.abortCredentialExchange()
            throw error
        }
        lock.unlock()
    }

    /// Cancelling is terminal even if a prompt has not arrived. There is no
    /// retained credential to erase here; callers cancel their transient
    /// credential separately or submit it and receive a terminal failure.
    func cancel() throws {
        lock.lock()
        guard case .finished = state else {
            state = .finished
            lock.unlock()
            transport.abortCredentialExchange()
            return
        }
        lock.unlock()
        throw OpenVPNHeldCredentialExchangeError.exchangeFinished
    }

    #if VPN_HELD_CREDENTIAL_EXCHANGE_TESTING
    var testIsFinished: Bool {
        lock.lock()
        defer { lock.unlock() }
        if case .finished = state { return true }
        return false
    }
    #endif
}
