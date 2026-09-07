import Foundation
import Darwin

// Installation/IPC experiment only. Do not add privileged operations here.
// There is intentionally no profile, subprocess, routing, DNS, or file-write API.
@objc protocol VPNProbeProtocol {
    func probe(_ protocolVersion: Int, reply: @escaping (Data) -> Void)
}

private let probeLabel = "kz.documentolog.proxypilot.vpn-probe"
private let wireVersion = 1
#if PROBE_UPGRADE
private let buildVersion = "0.0.2"
#else
private let buildVersion = "0.0.1"
#endif

private struct ProbeReply: Codable {
    let compatible: Bool
    let protocolVersion: Int
    let buildVersion: String
    let processID: Int32
    let effectiveUserID: UInt32
    let privilegedOperations: [String]
}

private final class ProbeService: NSObject, VPNProbeProtocol, NSXPCListenerDelegate {
    func probe(_ protocolVersion: Int, reply: @escaping (Data) -> Void) {
        let response = ProbeReply(compatible: protocolVersion == wireVersion,
                                  protocolVersion: wireVersion, buildVersion: buildVersion,
                                  processID: getpid(), effectiveUserID: geteuid(),
                                  privilegedOperations: [])
        reply((try? JSONEncoder().encode(response)) ?? Data())
    }

    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        // Public, inert diagnostic endpoint, NOT an authenticated root-command channel.
        connection.exportedInterface = NSXPCInterface(with: VPNProbeProtocol.self)
        connection.exportedObject = self
        connection.resume()
        return true
    }
}

private enum ProbeError: Error { case unavailable, malformedReply, incompatible }

// XPC failure, interruption and reply can race. Complete exactly once.
private final class ReplyBox {
    private let lock = NSLock()
    private let done = DispatchSemaphore(value: 0)
    private var result: Result<ProbeReply, ProbeError>?

    func complete(_ value: Result<ProbeReply, ProbeError>) {
        lock.lock()
        defer { lock.unlock() }
        guard result == nil else { return }
        result = value
        done.signal()
    }

    func wait() throws -> ProbeReply {
        guard done.wait(timeout: .now() + 5) == .success else { throw ProbeError.unavailable }
        lock.lock()
        defer { lock.unlock() }
        guard let result else { throw ProbeError.unavailable }
        return try result.get()
    }
}

private func request(_ connection: NSXPCConnection, version: Int = wireVersion) throws -> ProbeReply {
    let box = ReplyBox()
    connection.remoteObjectInterface = NSXPCInterface(with: VPNProbeProtocol.self)
    connection.invalidationHandler = { box.complete(.failure(.unavailable)) }
    connection.interruptionHandler = { box.complete(.failure(.unavailable)) }
    connection.resume()
    defer { connection.invalidate() }
    let remote = connection.remoteObjectProxyWithErrorHandler { _ in box.complete(.failure(.unavailable)) }
    guard let service = remote as? VPNProbeProtocol else { throw ProbeError.unavailable }
    service.probe(version) { data in
        guard data.count <= 1024, let reply = try? JSONDecoder().decode(ProbeReply.self, from: data),
              reply.protocolVersion == wireVersion, reply.processID > 0,
              reply.privilegedOperations.isEmpty else {
            box.complete(.failure(.malformedReply))
            return
        }
        box.complete(.success(reply))
    }
    return try box.wait()
}

private func emit(_ reply: ProbeReply) throws {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys]
    FileHandle.standardOutput.write(try encoder.encode(reply))
    FileHandle.standardOutput.write(Data("\n".utf8))
}

@main private enum VPNProbe {
    static func main() {
        guard CommandLine.arguments.count == 2 else { fail("Expected one probe mode.", code: 64) }
        do {
            switch CommandLine.arguments[1] {
            case "--describe":
                try emit(ProbeReply(compatible: true, protocolVersion: wireVersion,
                                    buildVersion: buildVersion, processID: getpid(),
                                    effectiveUserID: geteuid(), privilegedOperations: []))
            case "--serve":
                guard geteuid() == 0 else { fail("The installed probe must run as root.", code: 77) }
                let service = ProbeService()
                let listener = NSXPCListener(machServiceName: probeLabel)
                listener.delegate = service
                listener.resume()
                withExtendedLifetime((listener, service)) { dispatchMain() }
            case "--check-installed":
                let reply = try request(NSXPCConnection(machServiceName: probeLabel, options: .privileged))
                guard reply.compatible, reply.effectiveUserID == 0,
                      reply.buildVersion == buildVersion else { throw ProbeError.incompatible }
                try emit(reply)
            case "--self-test":
                // Real anonymous XPC transport, no launchd registration or elevated process.
                let service = ProbeService()
                let listener = NSXPCListener.anonymous()
                listener.delegate = service
                listener.resume()
                defer { listener.invalidate() }
                try withExtendedLifetime(service) {
                    for version in [wireVersion, -1, Int.max, wireVersion] {
                        let reply = try request(NSXPCConnection(listenerEndpoint: listener.endpoint), version: version)
                        guard reply.compatible == (version == wireVersion), reply.effectiveUserID == geteuid(),
                              reply.processID == getpid(), reply.buildVersion == buildVersion else {
                            throw ProbeError.malformedReply
                        }
                    }
                }
                print("Anonymous XPC checks passed; no service installed.")
            default:
                fail("Unknown probe mode.", code: 64)
            }
        } catch ProbeError.incompatible {
            fail("The installed probe version or privilege does not match.", code: 65)
        } catch {
            fail("The probe is unavailable or returned an invalid reply.", code: 69)
        }
    }

    private static func fail(_ message: String, code: Int32) -> Never {
        FileHandle.standardError.write(Data((message + "\n").utf8))
        exit(code)
    }
}
