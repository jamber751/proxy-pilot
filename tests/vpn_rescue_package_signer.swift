import CryptoKit
import Darwin
import Foundation

/// Synthetic-only test signer. No Keychain function is ever invoked here.
@main enum VPNRescuePackageSigner {
    static func main() throws {
        let a = CommandLine.arguments
        let key = try Curve25519.Signing.PrivateKey(rawRepresentation: Data(repeating: 0x42, count: 32))
        guard a.count >= 2 else { exit(64) }
        if a[1] == "public" {
            print(key.publicKey.rawRepresentation.base64EncodedString())
        } else if ["sign-rescue", "sign-rescue-preparation"].contains(a[1]) {
            guard a.count == 11, let inputs = VPNReleaseKeyTool.rescueInputs(a) else { exit(77) }
            let signature = try a[1] == "sign-rescue"
                ? VPNReleaseKeyTool.validatedRescueSignature(inputs, key: key)
                : VPNReleaseKeyTool.validatedRescuePreparationSignature(inputs, key: key)
            VPNReleaseKeyTool.write(signature.base64EncodedString() + "\n", to: a[10])
            print("Signed synthetic package statement")
        } else {
            // These commands use only public keys and signed input files.
            guard ["verify", "verify-transition", "verify-rescue", "verify-rescue-preparation"].contains(a[1]) else { exit(64) }
            VPNReleaseKeyTool.main()
        }
    }
}
