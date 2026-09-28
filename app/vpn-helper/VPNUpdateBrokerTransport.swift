import Darwin
import Dispatch
import Foundation

enum VPNUpdateBrokerTransportError: Error {
    case unsafeSocket, authenticationFailed, timeout, truncatedControl
    case invalidAncillaryData, invalidDescriptor, invalidRequest, appendedData, eof
    case missingDescriptor, extraDescriptor, unexpectedDescriptor, extraAncillary
    case notDirectory
}

/// Owns the descriptor until the broker explicitly consumes it. Every denial
/// path and an abandoned request close it automatically.
final class VPNUpdateBrokerReceivedRequest {
    let request: VPNUpdateBrokerRequest
    let peerUserID: uid_t
    private var candidateDirectory: Int32

    fileprivate init(request: VPNUpdateBrokerRequest, peerUserID: uid_t,
                     candidateDirectory: Int32) {
        self.request = request
        self.peerUserID = peerUserID
        self.candidateDirectory = candidateDirectory
    }

    deinit { if candidateDirectory >= 0 { close(candidateDirectory) } }

    func takeCandidateDirectory() throws -> Int32 {
        guard request.operation == .submit, candidateDirectory >= 0 else {
            throw VPNUpdateBrokerTransportError.invalidDescriptor
        }
        let result = candidateDirectory
        candidateDirectory = -1
        return result
    }
}

/// One authenticated AF_UNIX connection carries exactly one fixed request and
/// one fixed response. Submit receives exactly one SCM_RIGHTS directory; status
/// receives none. The source UID comes from the kernel peer, never the frame.
enum VPNUpdateBrokerTransport {
    static let socketName = "update-broker.sock"
    private static let controlCapacity = 64
    private static let headerBytes = MemoryLayout<cmsghdr>.size
    private static let alignment = MemoryLayout<UInt32>.size

    static func receive(socket: Int32, clientPolicy: VPNPeerPolicy,
                        deadline: UInt64) throws
        -> VPNUpdateBrokerReceivedRequest {
        do { try VPNPeerAuthentication.validate(connectedSocket: socket,
                                                 policy: clientPolicy) }
        catch { throw VPNUpdateBrokerTransportError.authenticationFailed }
        let peer = try peerUserID(socket)
        return try receive(socket: socket, authenticatedPeerUserID: peer,
                           deadline: deadline)
    }

    #if VPN_UPDATE_BROKER_TRANSPORT_TESTING
    static func testReceive(socket: Int32, authenticatedPeerUserID: uid_t,
                            deadline: UInt64) throws
        -> VPNUpdateBrokerReceivedRequest {
        try receive(socket: socket, authenticatedPeerUserID: authenticatedPeerUserID,
                    deadline: deadline)
    }
    #endif

    static func send(_ response: VPNUpdateBrokerResponse, socket: Int32,
                     deadline: UInt64) throws {
        try VPNHelperProtocol.write(
            VPNUpdateBrokerProtocol.encode(response), socket: socket,
            deadline: deadline)
    }

    private static func receive(socket: Int32, authenticatedPeerUserID: uid_t,
                                deadline: UInt64) throws
        -> VPNUpdateBrokerReceivedRequest {
        try validateSocket(socket)
        var bytes = [UInt8](repeating: 0, count: VPNUpdateBrokerProtocol.requestBytes)
        var control = [UInt64](repeating: 0,
                               count: controlCapacity / MemoryLayout<UInt64>.size)
        var received = -1, controlLength = 0, messageFlags: Int32 = 0
        while received < 0 {
            do { try VPNHelperProtocol.wait(socket, events: Int16(POLLIN), deadline: deadline) }
            catch { throw VPNUpdateBrokerTransportError.timeout }
            received = bytes.withUnsafeMutableBytes { dataBytes in
                control.withUnsafeMutableBytes { controlBytes in
                    controlBytes.initializeMemory(as: UInt8.self, repeating: 0)
                    var vector = iovec(iov_base: dataBytes.baseAddress,
                                       iov_len: dataBytes.count)
                    return withUnsafeMutablePointer(to: &vector) { vectorPointer in
                        var message = msghdr(
                            msg_name: nil, msg_namelen: 0,
                            msg_iov: vectorPointer, msg_iovlen: 1,
                            msg_control: controlBytes.baseAddress,
                            msg_controllen: socklen_t(controlBytes.count),
                            msg_flags: 0)
                        let result = recvmsg(socket, &message, MSG_DONTWAIT)
                        controlLength = Int(message.msg_controllen)
                        messageFlags = message.msg_flags
                        return result
                    }
                }
            }
            if received < 0, [EINTR, EAGAIN, EWOULDBLOCK].contains(errno) { continue }
            guard received > 0 else { throw VPNUpdateBrokerTransportError.eof }
        }

        if messageFlags & MSG_CTRUNC != 0 {
            if let partial = try? parseDescriptors(control: &control, length: controlLength) {
                partial.descriptors.forEach { close($0) }
            }
            throw VPNUpdateBrokerTransportError.truncatedControl
        }
        let ancillary = try parseDescriptors(control: &control, length: controlLength)
        var descriptors = ancillary.descriptors
        var transferred = false
        defer { if !transferred { descriptors.forEach { close($0) } } }
        guard received <= bytes.count else {
            throw VPNUpdateBrokerTransportError.invalidRequest
        }
        if received < bytes.count {
            let rest: [UInt8]
            do {
                rest = try VPNHelperProtocol.read(
                    count: bytes.count - received, socket: socket, deadline: deadline)
            } catch { throw VPNUpdateBrokerTransportError.invalidRequest }
            bytes.replaceSubrange(received..<bytes.count, with: rest)
        }
        var extra: UInt8 = 0
        let peeked = recv(socket, &extra, 1, MSG_DONTWAIT | MSG_PEEK)
        if peeked > 0 { throw VPNUpdateBrokerTransportError.appendedData }
        if peeked < 0, ![EAGAIN, EWOULDBLOCK, EINTR].contains(errno) {
            throw VPNUpdateBrokerTransportError.invalidRequest
        }

        let request: VPNUpdateBrokerRequest
        do { request = try VPNUpdateBrokerProtocol.decodeRequest(bytes) }
        catch { throw VPNUpdateBrokerTransportError.invalidRequest }
        switch request.operation {
        case .status:
            guard descriptors.isEmpty else { throw VPNUpdateBrokerTransportError.unexpectedDescriptor }
            transferred = true
            return VPNUpdateBrokerReceivedRequest(
                request: request, peerUserID: authenticatedPeerUserID,
                candidateDirectory: -1)
        case .submit:
            guard ancillary.groups <= 1 else { throw VPNUpdateBrokerTransportError.extraAncillary }
            guard !descriptors.isEmpty else { throw VPNUpdateBrokerTransportError.missingDescriptor }
            guard descriptors.count == 1 else { throw VPNUpdateBrokerTransportError.extraDescriptor }
            let directory = descriptors.removeFirst()
            var info = stat()
            let flags = fcntl(directory, F_GETFD)
            guard flags >= 0,
                  fcntl(directory, F_SETFD, flags | FD_CLOEXEC) == 0,
                  fstat(directory, &info) == 0 else {
                close(directory)
                throw VPNUpdateBrokerTransportError.invalidDescriptor
            }
            guard info.st_mode & S_IFMT == S_IFDIR, info.st_nlink > 0 else {
                close(directory)
                throw VPNUpdateBrokerTransportError.notDirectory
            }
            transferred = true
            return VPNUpdateBrokerReceivedRequest(
                request: request, peerUserID: authenticatedPeerUserID,
                candidateDirectory: directory)
        }
    }

    private static func parseDescriptors(control: inout [UInt64], length: Int) throws
        -> (descriptors: [Int32], groups: Int) {
        guard length > 0 else { return ([], 0) }
        var result: [Int32] = [], offset = 0, groups = 0, valid = true
        control.withUnsafeMutableBytes { bytes in
            while offset + headerBytes <= length {
                let pointer = bytes.baseAddress!.advanced(by: offset)
                let header = pointer.assumingMemoryBound(to: cmsghdr.self).pointee
                let size = Int(header.cmsg_len)
                guard size >= headerBytes, size <= length - offset else {
                    valid = false; return
                }
                if header.cmsg_level != SOL_SOCKET || header.cmsg_type != SCM_RIGHTS {
                    valid = false; return
                }
                let payload = size - headerBytes
                guard payload > 0, payload % MemoryLayout<Int32>.size == 0 else {
                    valid = false; return
                }
                let descriptorBytes = pointer.advanced(by: headerBytes)
                groups += 1
                for index in 0..<(payload / MemoryLayout<Int32>.size) {
                    result.append(descriptorBytes.load(
                        fromByteOffset: index * MemoryLayout<Int32>.size,
                        as: Int32.self))
                }
                offset += aligned(size)
            }
        }
        guard valid, offset == length else {
            result.forEach { close($0) }
            throw VPNUpdateBrokerTransportError.invalidAncillaryData
        }
        return (result, groups)
    }

    private static func aligned(_ value: Int) -> Int {
        (value + alignment - 1) & ~(alignment - 1)
    }

    private static func peerUserID(_ socket: Int32) throws -> uid_t {
        var user: uid_t = 0, group: gid_t = 0
        guard getpeereid(socket, &user, &group) == 0, user != uid_t.max else {
            throw VPNUpdateBrokerTransportError.authenticationFailed
        }
        return user
    }

    private static func validateSocket(_ socket: Int32) throws {
        var kind: Int32 = 0
        var size = socklen_t(MemoryLayout.size(ofValue: kind))
        var local = sockaddr_storage(), peer = sockaddr_storage()
        var localSize = socklen_t(MemoryLayout.size(ofValue: local))
        var peerSize = socklen_t(MemoryLayout.size(ofValue: peer))
        let localResult = withUnsafeMutablePointer(to: &local) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                getsockname(socket, $0, &localSize)
            }
        }
        let peerResult = withUnsafeMutablePointer(to: &peer) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                getpeername(socket, $0, &peerSize)
            }
        }
        guard getsockopt(socket, SOL_SOCKET, SO_TYPE, &kind, &size) == 0,
              kind == SOCK_STREAM, localResult == 0, peerResult == 0,
              local.ss_family == sa_family_t(AF_UNIX),
              peer.ss_family == sa_family_t(AF_UNIX) else {
            throw VPNUpdateBrokerTransportError.unsafeSocket
        }
    }
}

#if VPN_UPDATE_BROKER_TRANSPORT_TESTING
struct VPNUpdateBrokerTestCredential {
    let userID: uid_t
}

enum VPNUpdateBrokerTestCredentialSource { case kernelPeerCredential, invalid }
enum VPNUpdateBrokerTestResult: String { case accepted, refused, eof, timeout }
enum VPNUpdateBrokerTestReason: String {
    case missingDescriptor, extraDescriptor, notDirectory, unauthorizedPeer
    case unexpectedDescriptor, invalidFrame, extraAncillary, controlTruncated
}
struct VPNUpdateBrokerTestObservation {
    let result: VPNUpdateBrokerTestResult
    let reason: VPNUpdateBrokerTestReason?
    let peerUserID: uid_t?
    let sourceUserID: uid_t?
    let credentialSource: VPNUpdateBrokerTestCredentialSource
    let descriptorWasCloexec: Bool
    let descriptorWasClosed: Bool
    let messageControlTruncated: Bool
}
struct VPNUpdateBrokerTestEndpointObservation {
    let endpointName: String
    let endpointMode: mode_t
    let endpointInsideTrustedParent: Bool
    let acceptedCallerPath: Bool
}

extension VPNUpdateBrokerTransport {
    static func testServeOnce(
        takingSocket socket: Int32, timeoutMilliseconds: Int,
        authorize: (VPNUpdateBrokerTestCredential) -> Bool,
        handle: (VPNUpdateBrokerRequest, Int32?, VPNUpdateBrokerTestCredential) throws
            -> VPNUpdateBrokerResponse
    ) throws -> VPNUpdateBrokerTestObservation {
        defer { close(socket) }
        let deadline = DispatchTime.now().uptimeNanoseconds
            + UInt64(max(1, timeoutMilliseconds)) * 1_000_000
        let peer: uid_t
        do { peer = try peerUserID(socket) }
        catch {
            return observation(.refused, .unauthorizedPeer, nil, nil)
        }
        let credential = VPNUpdateBrokerTestCredential(userID: peer)
        guard authorize(credential) else {
            return observation(.refused, .unauthorizedPeer, peer, nil)
        }
        do {
            let received = try receive(
                socket: socket, authenticatedPeerUserID: peer, deadline: deadline)
            var directory: Int32? = nil
            var cloexec = false
            if received.request.operation == .submit {
                directory = try received.takeCandidateDirectory()
                if let directory {
                    let flags = fcntl(directory, F_GETFD)
                    cloexec = flags >= 0 && flags & FD_CLOEXEC != 0
                }
            }
            defer { if let directory { close(directory) } }
            let response = try handle(received.request, directory, credential)
            try send(response, socket: socket, deadline: deadline)
            let closed = directory.map { descriptor in
                close(descriptor)
                directory = nil
                return fcntl(descriptor, F_GETFD) == -1 && errno == EBADF
            } ?? true
            return VPNUpdateBrokerTestObservation(
                result: .accepted, reason: nil, peerUserID: peer,
                sourceUserID: peer, credentialSource: .kernelPeerCredential,
                descriptorWasCloexec: received.request.operation == .status || cloexec,
                descriptorWasClosed: closed, messageControlTruncated: false)
        } catch let error as VPNUpdateBrokerTransportError {
            switch error {
            case .eof:
                return observation(.eof, nil, peer, nil)
            case .timeout:
                return observation(.timeout, nil, peer, nil)
            case .missingDescriptor:
                return observation(.refused, .missingDescriptor, peer, nil)
            case .extraDescriptor:
                return observation(.refused, .extraDescriptor, peer, nil)
            case .notDirectory, .invalidDescriptor:
                return observation(.refused, .notDirectory, peer, nil)
            case .unexpectedDescriptor:
                return observation(.refused, .unexpectedDescriptor, peer, nil)
            case .extraAncillary:
                return observation(.refused, .extraAncillary, peer, nil)
            case .truncatedControl:
                return VPNUpdateBrokerTestObservation(
                    result: .refused, reason: .controlTruncated,
                    peerUserID: peer, sourceUserID: nil,
                    credentialSource: .kernelPeerCredential,
                    descriptorWasCloexec: false, descriptorWasClosed: true,
                    messageControlTruncated: true)
            default:
                return observation(.refused, .invalidFrame, peer, nil)
            }
        }
    }

    static func testBindEndpoint(inTrustedDirectory parent: Int32) throws
        -> VPNUpdateBrokerTestEndpointObservation {
        var root = stat()
        guard fstat(parent, &root) == 0,
              root.st_mode & S_IFMT == S_IFDIR, root.st_uid == geteuid(),
              root.st_mode & 0o7777 == 0o700, root.st_nlink > 0 else {
            throw VPNUpdateBrokerTransportError.unsafeSocket
        }
        var path = [CChar](repeating: 0, count: Int(MAXPATHLEN))
        guard fcntl(parent, F_GETPATH, &path) == 0 else {
            throw VPNUpdateBrokerTransportError.unsafeSocket
        }
        let folder = String(cString: path)
        var named = stat()
        guard lstat(folder, &named) == 0,
              named.st_dev == root.st_dev, named.st_ino == root.st_ino else {
            throw VPNUpdateBrokerTransportError.unsafeSocket
        }
        let endpoint = folder + "/" + socketName
        guard unlinkat(parent, socketName, 0) != 0, errno == ENOENT else {
            throw VPNUpdateBrokerTransportError.unsafeSocket
        }
        let descriptor = socket(AF_UNIX, SOCK_STREAM, 0)
        guard descriptor >= 0 else { throw VPNUpdateBrokerTransportError.unsafeSocket }
        defer { close(descriptor); unlinkat(parent, socketName, 0) }
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        let bytes = Array(endpoint.utf8) + [0]
        guard bytes.count <= MemoryLayout.size(ofValue: address.sun_path) else {
            throw VPNUpdateBrokerTransportError.unsafeSocket
        }
        withUnsafeMutableBytes(of: &address.sun_path) { $0.copyBytes(from: bytes) }
        let previousMask = umask(0o177)
        let bound = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(descriptor, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        umask(previousMask)
        guard bound == 0, listen(descriptor, 4) == 0 else {
            throw VPNUpdateBrokerTransportError.unsafeSocket
        }
        var socketInfo = stat()
        guard fstatat(parent, socketName, &socketInfo, AT_SYMLINK_NOFOLLOW) == 0,
              socketInfo.st_mode & S_IFMT == S_IFSOCK,
              socketInfo.st_uid == geteuid(),
              socketInfo.st_mode & 0o7777 == 0o600 else {
            throw VPNUpdateBrokerTransportError.unsafeSocket
        }
        return VPNUpdateBrokerTestEndpointObservation(
            endpointName: socketName, endpointMode: socketInfo.st_mode & 0o7777,
            endpointInsideTrustedParent: true, acceptedCallerPath: false)
    }

    private static func observation(
        _ result: VPNUpdateBrokerTestResult,
        _ reason: VPNUpdateBrokerTestReason?, _ peer: uid_t?, _ source: uid_t?
    ) -> VPNUpdateBrokerTestObservation {
        VPNUpdateBrokerTestObservation(
            result: result, reason: reason, peerUserID: peer, sourceUserID: source,
            credentialSource: .kernelPeerCredential,
            descriptorWasCloexec: false, descriptorWasClosed: true,
            messageControlTruncated: false)
    }
}
#endif
