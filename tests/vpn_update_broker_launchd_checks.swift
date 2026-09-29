import CryptoKit
import Darwin
import Dispatch
import Foundation

@_silgen_name("launch_activate_socket")
private func launchActivateSocket(
    _ name: UnsafePointer<CChar>,
    _ descriptors: UnsafeMutablePointer<UnsafeMutablePointer<Int32>?>,
    _ count: UnsafeMutablePointer<Int>
) -> Int32

/// Disposable user-domain fixture for the production broker launchd adapter.
/// The same universal, signed executable acts as the selected helper and as the
/// driver; production configuration is never weakened by this fixture.
@main
enum VPNUpdateBrokerLaunchdChecks {
    static func deadline(_ seconds: UInt64 = 20) -> UInt64 {
        DispatchTime.now().uptimeNanoseconds + seconds * 1_000_000_000
    }

    static func main() {
        let arguments = CommandLine.arguments
        if arguments.count == 2,
           arguments[1] == VPNUpdateBrokerLaunchdJob.brokerArgument {
            serve()
        }
        guard geteuid() != 0, arguments.count >= 6 else { exit(64) }
        let action = arguments[1]
        let storagePath = arguments[2]
        let plistDirectory = URL(fileURLWithPath: arguments[3], isDirectory: true)
        let endpoint = URL(fileURLWithPath: arguments[4])
        let label = arguments[5]
        let storage = open(storagePath, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard storage >= 0 else { exit(77) }
        defer { close(storage) }
        do {
            if action == "system" {
                do {
                    _ = try VPNUpdateBrokerLaunchdJob.system(storageDirectory: storage)
                    print("system:accepted")
                } catch {
                    print("system:\(error)")
                }
                return
            }
            let authority = try testAuthority()
            let store = try VPNReleaseStore(
                trustedDirectoryDescriptor: storage, authority: authority)
            if action == "seed" {
                guard arguments.count == 8 else { exit(64) }
                let payload = try Data(contentsOf: URL(fileURLWithPath: arguments[6]))
                let helper = try Data(contentsOf: URL(fileURLWithPath: arguments[7]))
                let key = try Curve25519.Signing.PrivateKey(
                    rawRepresentation: Data(repeating: 0x42, count: 32))
                let signature = try key.signature(
                    for: VPNReleaseAuthority.signatureDomain + payload)
                _ = try store.bootstrapDeployment(
                    payload: payload, signature: signature, helper: helper,
                    trustedOwnerUserID: geteuid())
                print("seeded")
                return
            }
            let job = try VPNUpdateBrokerLaunchdJob.testUserDomain(
                label: label, plistDirectory: plistDirectory,
                endpoint: endpoint, storageDirectory: storage)
            if action == "install" {
                try job.installAndStart(try store.loadDeployment(), deadline: deadline())
                print("installed")
            } else if action == "remove" {
                try job.remove(deadline: deadline())
                print("removed")
            } else {
                exit(64)
            }
        } catch {
            print("rejected:\(error)")
            exit(77)
        }
    }

    private static func testAuthority() throws -> VPNReleaseAuthority {
        let key = try Curve25519.Signing.PrivateKey(
            rawRepresentation: Data(repeating: 0x42, count: 32))
        return try VPNReleaseAuthority(
            trustedPublicKey: key.publicKey.rawRepresentation,
            minimumSequence: 1, supportedProtocol: 1)
    }

    private static func serve() -> Never {
        var descriptors: UnsafeMutablePointer<Int32>?
        var count = 0
        let status = "Broker".withCString {
            launchActivateSocket($0, &descriptors, &count)
        }
        guard status == 0, count == 1, let descriptors else { exit(70) }
        let listener = descriptors[0]
        free(descriptors)
        while true {
            let connection = accept(listener, nil, nil)
            if connection < 0 {
                if errno == EINTR { continue }
                exit(71)
            }
            // The launchd adapter's readiness connection intentionally carries
            // no broker request. Closing it after live identity proof must not
            // terminate this disposable server before the behavioral probe.
            var noSignal: Int32 = 1
            _ = setsockopt(connection, SOL_SOCKET, SO_NOSIGPIPE, &noSignal,
                           socklen_t(MemoryLayout.size(ofValue: noSignal)))
            _ = "broker-ready".withCString { bytes in
                write(connection, bytes, strlen(bytes))
            }
            close(connection)
        }
    }
}
