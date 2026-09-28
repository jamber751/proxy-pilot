import Darwin
import Foundation

@main enum VPNUpdateBrokerTransportFixture {
    static func json(_ values: [String: Any]) throws {
        let data = try JSONSerialization.data(withJSONObject: values, options: [.sortedKeys])
        FileHandle.standardOutput.write(data)
        FileHandle.standardOutput.write(Data("\n".utf8))
    }

    static func serve(takingSocket socket: Int32, allowPeer: Bool = true) throws {
        var requestsHandled = 0
        let observation = try VPNUpdateBrokerTransport.testServeOnce(
            takingSocket: socket, timeoutMilliseconds: 100,
            authorize: { credential in
                // The source UID is the live kernel peer credential. There is
                // no claimed UID field in the frame or callback. Production
                // obtains it through LOCAL_PEERCRED on Darwin (SO_PEERCRED on
                // platforms where that is the native live-credential seam).
                allowPeer && credential.userID == geteuid()
            }, handle: { request, directory, credential in
                requestsHandled += 1 // one request per connection
                switch request.operation {
                case .submit:
                    guard directory != nil else {
                        throw VPNUpdateBrokerTransportError.missingDescriptor
                    }
                case .status:
                    guard directory == nil else {
                        throw VPNUpdateBrokerTransportError.unexpectedDescriptor
                    }
                }
                return VPNUpdateBrokerResponse(
                    state: .accepted, fromSequence: request.expectedFromSequence,
                    toSequence: request.expectedFromSequence == 0 ? 0
                        : request.expectedFromSequence + 1,
                    revision: 0)
            })
        try json([
            "result": observation.result.rawValue,
            "reason": observation.reason?.rawValue ?? "",
            "requestsHandled": requestsHandled,
            "peerUserID": UInt64(observation.peerUserID ?? uid_t.max),
            "sourceUserID": UInt64(observation.sourceUserID ?? uid_t.max),
            "credentialSource": observation.credentialSource == .kernelPeerCredential
                ? "kernelPeerCredential" : "invalid",
            "descriptorWasCloexec": observation.descriptorWasCloexec,
            "descriptorWasClosed": observation.descriptorWasClosed,
            "messageControlTruncated": observation.messageControlTruncated,
        ])
    }

    static func endpoint(inTrustedDirectory parent: Int32) throws {
        let observation = try VPNUpdateBrokerTransport.testBindEndpoint(
            inTrustedDirectory: parent)
        guard observation.endpointName == "update-broker.sock",
              observation.endpointMode == 0o600,
              observation.endpointInsideTrustedParent,
              !observation.acceptedCallerPath else {
            throw NSError(domain: "broker-transport-endpoint", code: 1)
        }
        try json([
            "endpointName": observation.endpointName,
            "endpointMode": observation.endpointMode,
            "endpointInsideTrustedParent": observation.endpointInsideTrustedParent,
            "acceptedCallerPath": observation.acceptedCallerPath,
        ])
    }

    static func main() throws {
        guard CommandLine.arguments.count == 3,
              let descriptor = Int32(CommandLine.arguments[2]) else { exit(64) }
        switch CommandLine.arguments[1] {
        case "serve": try serve(takingSocket: descriptor)
        case "deny": try serve(takingSocket: descriptor, allowPeer: false)
        case "endpoint": try endpoint(inTrustedDirectory: descriptor)
        default: exit(64)
        }
    }
}
