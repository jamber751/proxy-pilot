import CryptoKit
import Darwin
import Foundation

final class VPNHelperFixtureOwnership { var owns = false }

// Thin launcher around the production listener, used both by the listener tests
// and by launchd. It reads the authenticated selection from protected storage,
// serves the readiness handshake and does nothing else: no privileged operation,
// no profile, no routes, no DNS. The trusted key here is a disposable fixture
// key; production must embed its own and must not read trust from storage.
@main
enum VPNHelperService {
    static func main() {
        #if VPN_ENGINE_SUPERVISOR_FIXTURE
        if let status = VPNEngineSupervisorEntry.runIfRequested(arguments: CommandLine.arguments) {
            exit(status)
        }
        #endif
        let args = CommandLine.arguments
        if args.count == 3, args[1] == "recover-update",
           args[2] == "/Library/Application Support/ProxyPilot/VPN" {
            sleep(30)
            exit(0)
        }
        guard (3...7).contains(args.count), ["serve", "seed"].contains(args[1]) else { exit(64) }
        let ready = args.count < 4 || args[3] != "not-ready"
        let directory = open(args[2], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard directory >= 0 else { exit(70) }
        do {
            let key = try Curve25519.Signing.PrivateKey(rawRepresentation: Data(repeating: 0x42, count: 32))
            #if VPN_ENGINE_DELIVERY_TESTING
            let authority = try VPNReleaseAuthority.engineCandidateAuthority(
                trustedPublicKey: key.publicKey.rawRepresentation, minimumSequence: 1)
            #else
            let authority = try VPNReleaseAuthority(trustedPublicKey: key.publicKey.rawRepresentation,
                                                    minimumSequence: 1, supportedProtocol: 1)
            #endif
            let store = try VPNReleaseStore(trustedDirectoryDescriptor: directory, authority: authority)
            if args[1] == "seed" {
                guard args.count == 5 else { exit(64) }
                let payload = try Data(contentsOf: URL(fileURLWithPath: args[3]))
                let helper = try Data(contentsOf: URL(fileURLWithPath: args[4]))
                let signature = try key.signature(for: VPNReleaseAuthority.signatureDomain + payload)
                let seeded = try store.bootstrapDeployment(payload: payload, signature: signature,
                                                           helper: helper, trustedOwnerUserID: geteuid())
                print("selected:\(seeded.release.sequence)")
                exit(0)
            }
            let deployment = try store.loadDeployment()
            let listener: VPNHelperListener
            #if VPN_HELPER_LISTENER_TESTING
            if args.count == 7,
               ["installer-transition-test", "helper-transition-test"].contains(args[3]) {
                func hash(_ value: String) -> Data? {
                    guard value.utf8.count == 40 else { return nil }
                    var bytes = [UInt8]()
                    bytes.reserveCapacity(20)
                    var index = value.startIndex
                    for _ in 0..<20 {
                        let next = value.index(index, offsetBy: 2)
                        guard let byte = UInt8(value[index..<next], radix: 16) else { return nil }
                        bytes.append(byte)
                        index = next
                    }
                    return Data(bytes)
                }
                guard let arm = hash(args[4]), let intel = hash(args[5]) else { exit(64) }
                let transitionPolicy = try VPNPeerPolicy(
                    userID: deployment.ownerUserID,
                    signingIdentifier: args[3] == "helper-transition-test"
                        ? "kz.documentolog.proxypilot.vpn-helper"
                        : "kz.documentolog.proxypilot",
                    codeDirectoryHashes: Set([arm, intel]))
                let state = args[6]
                listener = try VPNHelperListener.testBindInstaller(
                    inTrustedDirectory: directory, release: deployment.release,
                    ownerUserID: deployment.ownerUserID,
                    additionalReadinessPolicies: {
                        guard let value = try? String(contentsOfFile: state, encoding: .utf8) else {
                            return []
                        }
                        if value == "retire-after-first-check" {
                            try? FileManager.default.removeItem(atPath: state)
                        }
                        return [transitionPolicy]
                    })
            } else if args.count >= 4, args[3] == "installer-test" {
                listener = try VPNHelperListener.testBindInstaller(inTrustedDirectory: directory, release: deployment.release,
                                                                   ownerUserID: deployment.ownerUserID)
            } else {
                var endpoint: Int32?
                if args.count == 5, args[3] == "shared" {
                    endpoint = open(args[4], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
                }
                defer { if let endpoint = endpoint { close(endpoint) } }
                let tunnelFixture = args.count == 5
                    && ["tunnel-test", "tunnel-once", "managed-tunnel-test",
                        "managed-connected-test"].contains(args[3])
                    ? args[4] : nil
                func appendTrace(_ value: String) throws {
                    guard let path = tunnelFixture else { return }
                    let file = open(path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0o600)
                    guard file >= 0 else { throw VPNHelperListenerError.unavailable }
                    defer { close(file) }
                    let bytes = Array((value + "\n").utf8)
                    guard write(file, bytes, bytes.count) == bytes.count else {
                        throw VPNHelperListenerError.unavailable
                    }
                }
                let ownership = VPNHelperFixtureOwnership()
                let managedMode = args.count == 5 ? args[3] : ""
                let managed = managedMode == "managed-tunnel-test"
                    || managedMode == "managed-connected-test"
                listener = try VPNHelperListener.bind(inTrustedDirectory: directory,
                    release: deployment.release, ownerUserID: deployment.ownerUserID,
                    endpointDirectory: endpoint,
                    startTunnel: { try appendTrace("start-held"); return true },
                    startManagedTunnel: managed ? { binding, state in
                        if managedMode == "managed-connected-test" {
                            try appendTrace("routes-verified")
                            _ = try state.activateForRouting(binding)
                            _ = try state.markConnected(binding)
                        } else {
                            try appendTrace("management-prompt")
                            _ = try state.issueChallenge(binding: binding, kind: .vpnPassword)
                        }
                        ownership.owns = true
                        return true
                    } : nil,
                    submitManagedCredential: managed ? { response, state in
                        let binding = try state.claimCredential(response.challenge)
                        let transient = try OpenVPNTransientCredential(
                            response: &response, application: binding.application)
                        transient.fail()
                        _ = try state.completeCredentialPrompt(binding: binding)
                        try appendTrace("credential-claimed")
                    } : nil,
                    stopTunnel: {
                        let snapshot = try VPNTunnelStateStore(
                            trustedDirectoryDescriptor: directory).load()
                        try appendTrace(snapshot.desiredEnabled ? "stop-before-off" : "stop-after-off")
                        ownership.owns = false
                    }, tunnelIsOwned: { managed ? ownership.owns : false })
            }
            #else
            let runtime = try VPNHelperRuntime(storageDirectory: directory)
            defer { _ = runtime }
            listener = try VPNHelperListener.bind(inTrustedDirectory: directory, deployment: deployment,
                                                  ownerUserID: deployment.ownerUserID,
                                                  runtimeLease: runtime.tunnelLifecycleLease)
            #endif
            print("listening"); fflush(stdout)
            let ownerRequestsAllowed = !args.contains("owner-blocked")
            if args.contains("tunnel-once") {
                _ = try? listener.serveOnce(
                    isReady: { ready }, allowOwnerRequests: { ownerRequestsAllowed })
                listener.close()
                exit(0)
            }
            while true {
                _ = try? listener.serveOnce(
                    isReady: { ready }, allowOwnerRequests: { ownerRequestsAllowed })
            }
        } catch {
            FileHandle.standardError.write(Data("service:\(error)\n".utf8))
            exit(71)
        }
    }
}
