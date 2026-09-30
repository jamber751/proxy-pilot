import Foundation

/// Production binding between the one-shot credential exchange and the exact
/// authenticated local OpenVPN management connection that observed its prompt.
extension OpenVPNManagementClient: OpenVPNCredentialByteTransport {
    func writeCredentialCommand(_ bytes: UnsafeRawBufferPointer) throws {
        try sendCredentialCommand(bytes)
    }

    func abortCredentialExchange() { close() }
}
