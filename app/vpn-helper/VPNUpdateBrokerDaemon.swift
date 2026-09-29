import Darwin
import Dispatch
import Foundation

@_silgen_name("launch_activate_socket")
private func brokerLaunchActivateSocket(
    _ name: UnsafePointer<CChar>,
    _ descriptors: UnsafeMutablePointer<UnsafeMutablePointer<Int32>?>,
    _ count: UnsafeMutablePointer<Int>
) -> Int32

enum VPNUpdateBrokerDaemonError: Error {
    case requiresRoot, invalidArguments, unavailable, unsafeEndpoint
}

/// Release-bound, deliberately inert update-broker service. launchd owns the
/// public socket, so the pathname survives a broker crash without either the
/// old or the replacement process unlinking another process's endpoint. The
/// signed owner application may read bounded status; submit is refused until
/// the inbox/authorization/preparation handler is connected in a later stage.
enum VPNUpdateBrokerDaemon {
    static let entryArgument = "serve-update-broker"
    static let privateStatePath = "/Library/Application Support/ProxyPilot/Broker"
    static let endpointParentPath = "/Library/Application Support/kz.documentolog.proxypilot.vpn"
    static let endpointPath = endpointParentPath + "/update-broker.sock"
    private static let socketKey = "Broker"

    static func runSystem(arguments: [String]) throws {
        guard getuid() == 0, geteuid() == 0 else {
            throw VPNUpdateBrokerDaemonError.requiresRoot
        }
        guard arguments.count == 2, arguments[1] == entryArgument else {
            throw VPNUpdateBrokerDaemonError.invalidArguments
        }
        let service = try VPNDirectoryProvisioner.openSystemDirectory(create: false)
        defer { close(service) }
        let privateState = try VPNDirectoryProvisioner.openSystemBrokerDirectory(create: true)
        defer { close(privateState) }
        let endpoint = try VPNEndpointDirectory.openSystem(create: false)
        defer { close(endpoint) }
        let listener = try activatedListener(endpointDirectory: endpoint)
        defer { close(listener) }
        let authority = try VPNReleaseTrust.authority()
        let status = try VPNUpdateBrokerStatusStore(
            trustedDirectoryDescriptor: privateState)
        try serve(listener: listener, serviceDirectory: service,
                  authority: authority, status: status)
    }

    private static func serve(listener: Int32, serviceDirectory: Int32,
                              authority: VPNReleaseAuthority,
                              status: VPNUpdateBrokerStatusStore) throws {
        while true {
            let store = try VPNReleaseStore(
                trustedDirectoryDescriptor: serviceDirectory,
                authority: authority)
            let selected = try store.loadDeployment()
            // This process is the exact content-addressed helper of selected A,
            // not merely any root process or a mutable application executable.
            try VPNPeerAuthentication.validateCurrentProcess(
                policy: selected.release.helperPolicy())
            let client = try acceptOne(listener)
            defer { close(client) }
            do {
                let clientPolicy: VPNPeerPolicy = try selected.release
                    .clientPolicy(forTrustedUserID: selected.ownerUserID)
                let deadline = DispatchTime.now().uptimeNanoseconds
                    + 2_000_000_000
                let received = try VPNUpdateBrokerTransport.receive(
                    socket: client, clientPolicy: clientPolicy,
                    deadline: deadline)
                let response: VPNUpdateBrokerResponse
                switch received.request.operation {
                case .status:
                    response = try status.load().response
                        ?? VPNUpdateBrokerResponse(
                            state: .complete,
                            fromSequence: selected.release.sequence,
                            toSequence: selected.release.sequence,
                            revision: 0)
                case .submit:
                    // Consume and close the descriptor, but make no copy and no
                    // durable claim until the explicit transaction handler is
                    // wired and independently accepted.
                    let directory = try received.takeCandidateDirectory()
                    close(directory)
                    response = VPNUpdateBrokerResponse(
                        state: .failed,
                        fromSequence: received.request.expectedFromSequence,
                        toSequence: 0,
                        revision: (try status.load()).revision)
                }
                try VPNUpdateBrokerTransport.send(
                    response, socket: client, deadline: deadline)
            } catch {
                // A refused connection carries no diagnostic payload. The next
                // peer gets a fresh live-code check and independent deadline.
            }
        }
    }

    private static func activatedListener(endpointDirectory: Int32) throws -> Int32 {
        var descriptors: UnsafeMutablePointer<Int32>?
        var count = 0
        let result = socketKey.withCString {
            brokerLaunchActivateSocket($0, &descriptors, &count)
        }
        guard result == 0, count == 1, let descriptors else {
            if let descriptors { free(descriptors) }
            throw VPNUpdateBrokerDaemonError.unavailable
        }
        let listener = descriptors[0]
        free(descriptors)
        guard listener >= 0 else { throw VPNUpdateBrokerDaemonError.unavailable }
        do {
            guard fcntl(listener, F_SETFD, FD_CLOEXEC) == 0 else {
                throw VPNUpdateBrokerDaemonError.unsafeEndpoint
            }
            var kind: Int32 = 0
            var kindSize = socklen_t(MemoryLayout.size(ofValue: kind))
            var address = sockaddr_un()
            var addressSize = socklen_t(MemoryLayout<sockaddr_un>.size)
            let named = withUnsafeMutablePointer(to: &address) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    getsockname(listener, $0, &addressSize)
                }
            }
            let actualPath = withUnsafeBytes(of: address.sun_path) { bytes -> String? in
                let values = bytes.bindMemory(to: UInt8.self)
                guard let end = values.firstIndex(of: 0), end > 0 else { return nil }
                return String(bytes: values[..<end], encoding: .utf8)
            }
            var endpointInfo = stat()
            guard getsockopt(listener, SOL_SOCKET, SO_TYPE,
                             &kind, &kindSize) == 0,
                  kind == SOCK_STREAM, named == 0,
                  address.sun_family == sa_family_t(AF_UNIX),
                  actualPath == endpointPath,
                  fstatat(endpointDirectory,
                          VPNUpdateBrokerTransport.socketName,
                          &endpointInfo, AT_SYMLINK_NOFOLLOW) == 0,
                  endpointInfo.st_mode & S_IFMT == S_IFSOCK,
                  endpointInfo.st_uid == 0,
                  endpointInfo.st_nlink == 1,
                  endpointInfo.st_mode & 0o7777 == 0o666 else {
                throw VPNUpdateBrokerDaemonError.unsafeEndpoint
            }
            return listener
        } catch {
            close(listener)
            throw error
        }
    }

    private static func acceptOne(_ listener: Int32) throws -> Int32 {
        while true {
            let client = Darwin.accept(listener, nil, nil)
            if client < 0, errno == EINTR { continue }
            guard client >= 0,
                  fcntl(client, F_SETFD, FD_CLOEXEC) == 0 else {
                if client >= 0 { close(client) }
                throw VPNUpdateBrokerDaemonError.unavailable
            }
            return client
        }
    }
}
