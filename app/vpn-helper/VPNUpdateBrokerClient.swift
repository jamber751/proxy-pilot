import Darwin
import Dispatch
import Foundation

enum VPNUpdateBrokerClientError: Error {
    case invalidRequest, unavailable, transport, deadlineExceeded
    case mismatchedTransaction
}

enum VPNUpdateBrokerSubmitOutcome {
    case response(VPNUpdateBrokerResponse)
    case indeterminate
}

/// Ordinary-user side of the fixed update-broker protocol. The caller supplies
/// an already-open candidate directory, never a path. Each exchange uses a new
/// AF_UNIX connection; no root authority or mutable endpoint enters this API.
enum VPNUpdateBrokerClient {
    private static let endpoint = "/Library/Application Support/kz.documentolog.proxypilot.vpn/update-broker.sock"
    private static let socketName = "update-broker.sock"

    static func submit(candidateDirectory: Int32,
                       expectedFromSequence: UInt64,
                       deadline: UInt64) throws -> VPNUpdateBrokerSubmitOutcome {
        guard candidateDirectory >= 0, expectedFromSequence > 0,
              DispatchTime.now().uptimeNanoseconds < deadline else {
            throw VPNUpdateBrokerClientError.invalidRequest
        }
        var info = stat()
        guard fstat(candidateDirectory, &info) == 0,
              info.st_mode & S_IFMT == S_IFDIR, info.st_nlink > 0 else {
            throw VPNUpdateBrokerClientError.invalidRequest
        }
        let request = try VPNUpdateBrokerRequest.submit(
            expectedFromSequence: expectedFromSequence)
        let socket = try connect(deadline: deadline)
        do {
            try sendSubmit(
                request, candidateDirectory: candidateDirectory,
                socket: socket, deadline: deadline)
        } catch SubmitWriteError.indeterminate {
            close(socket)
            return .indeterminate
        } catch {
            close(socket)
            throw error
        }
        let response: VPNUpdateBrokerResponse
        do {
            response = try receive(socket: socket, deadline: deadline)
        } catch {
            close(socket)
            return .indeterminate
        }
        close(socket)
        // A valid response for another transaction is not a rotation signal.
        do {
            try validate(response, expectedFromSequence: expectedFromSequence)
        } catch VPNUpdateBrokerClientError.mismatchedTransaction {
            throw VPNUpdateBrokerClientError.mismatchedTransaction
        }
        return .response(response)
    }

    /// Called by the newly installed application B. It sends no descriptor and
    /// does not infer authority from a receipt; broker B authenticates live B.
    static func status(deadline: UInt64) throws -> VPNUpdateBrokerResponse {
        guard DispatchTime.now().uptimeNanoseconds < deadline else {
            throw VPNUpdateBrokerClientError.deadlineExceeded
        }
        let socket = try connect(deadline: deadline)
        defer { close(socket) }
        try VPNHelperProtocol.write(
            VPNUpdateBrokerProtocol.encode(VPNUpdateBrokerRequest.status),
            socket: socket, deadline: deadline)
        return try receive(socket: socket, deadline: deadline)
    }

    private static func sendSubmit(_ request: VPNUpdateBrokerRequest,
                                   candidateDirectory: Int32,
                                   socket: Int32, deadline: UInt64) throws
        -> Void {
        let bytes = VPNUpdateBrokerProtocol.encode(request)
        let headerSize = MemoryLayout<cmsghdr>.size
        let alignment = MemoryLayout<UInt32>.size
        let controlSize = (headerSize + MemoryLayout<Int32>.size + alignment - 1)
            & ~(alignment - 1)
        var control = [UInt8](repeating: 0, count: controlSize)
        var sent = -1
        while sent < 0 {
            try VPNHelperProtocol.wait(socket, events: Int16(POLLOUT),
                                       deadline: deadline)
            sent = bytes.withUnsafeBytes { payload in
                control.withUnsafeMutableBytes { ancillary in
                    let header = ancillary.baseAddress!
                        .assumingMemoryBound(to: cmsghdr.self)
                    header.pointee.cmsg_len = socklen_t(
                        headerSize + MemoryLayout<Int32>.size)
                    header.pointee.cmsg_level = SOL_SOCKET
                    header.pointee.cmsg_type = SCM_RIGHTS
                    ancillary.baseAddress!.advanced(by: headerSize)
                        .storeBytes(of: candidateDirectory, as: Int32.self)
                    var vector = iovec(iov_base:
                        UnsafeMutableRawPointer(mutating: payload.baseAddress),
                        iov_len: payload.count)
                    return withUnsafeMutablePointer(to: &vector) { pointer in
                        var message = msghdr(
                            msg_name: nil, msg_namelen: 0,
                            msg_iov: pointer, msg_iovlen: 1,
                            msg_control: ancillary.baseAddress,
                            msg_controllen: socklen_t(ancillary.count),
                            msg_flags: 0)
                        return sendmsg(socket, &message, MSG_DONTWAIT | MSG_NOSIGNAL)
                    }
                }
            }
            if sent < 0, errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK {
                continue
            }
            guard sent > 0 else { throw VPNUpdateBrokerClientError.transport }
        }
        if sent < bytes.count {
            do {
                try VPNHelperProtocol.write(Array(bytes[sent...]), socket: socket,
                                            deadline: deadline)
            } catch {
                throw SubmitWriteError.indeterminate
            }
        }
    }

    private static func receive(socket: Int32, deadline: UInt64) throws
        -> VPNUpdateBrokerResponse {
        do {
            return try VPNUpdateBrokerProtocol.decodeResponse(
                VPNHelperProtocol.read(
                    count: VPNUpdateBrokerProtocol.responseBytes,
                    socket: socket, deadline: deadline))
        } catch {
            throw VPNUpdateBrokerClientError.transport
        }
    }

    private static func validate(_ response: VPNUpdateBrokerResponse,
                                 expectedFromSequence: UInt64) throws {
        guard response.fromSequence == expectedFromSequence else {
            throw VPNUpdateBrokerClientError.mismatchedTransaction
        }
        switch response.state {
        case .busy, .stale:
            guard response.toSequence == 0
                    || response.toSequence > expectedFromSequence else {
                throw VPNUpdateBrokerClientError.mismatchedTransaction
            }
        case .ready:
            guard response.toSequence > expectedFromSequence,
                  response.revision > 0 else {
                throw VPNUpdateBrokerClientError.mismatchedTransaction
            }
        case .accepted, .checking, .installing, .complete, .failed:
            throw VPNUpdateBrokerClientError.mismatchedTransaction
        }
    }

    private enum SubmitWriteError: Error { case indeterminate }

    private static func connect(deadline: UInt64) throws -> Int32 {
        let directory = try VPNEndpointDirectory.openSystem(create: false)
        defer { close(directory) }
        var endpointInfo = stat()
        guard fstatat(directory, socketName,
                      &endpointInfo, AT_SYMLINK_NOFOLLOW) == 0,
              endpointInfo.st_mode & S_IFMT == S_IFSOCK,
              endpointInfo.st_uid == 0, endpointInfo.st_nlink == 1,
              endpointInfo.st_mode & 0o7777 == 0o666 else {
            throw VPNUpdateBrokerClientError.unavailable
        }
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        let path = Array(endpoint.utf8) + [0]
        guard path.count <= MemoryLayout.size(ofValue: address.sun_path) else {
            throw VPNUpdateBrokerClientError.unavailable
        }
        withUnsafeMutableBytes(of: &address.sun_path) { $0.copyBytes(from: path) }
        let socket = Darwin.socket(AF_UNIX, SOCK_STREAM, 0)
        guard socket >= 0 else { throw VPNUpdateBrokerClientError.unavailable }
        do {
            guard fcntl(socket, F_SETFD, FD_CLOEXEC) == 0,
                  fcntl(socket, F_SETFL, O_NONBLOCK) == 0 else {
                throw VPNUpdateBrokerClientError.unavailable
            }
            let result = withUnsafePointer(to: &address) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    Darwin.connect(socket, $0,
                        socklen_t(MemoryLayout<sockaddr_un>.size))
                }
            }
            if result != 0 {
                guard [EINPROGRESS, EAGAIN, EWOULDBLOCK].contains(errno) else {
                    throw VPNUpdateBrokerClientError.unavailable
                }
                try VPNHelperProtocol.wait(socket, events: Int16(POLLOUT),
                                           deadline: deadline)
                var error: Int32 = 0
                var size = socklen_t(MemoryLayout<Int32>.size)
                guard getsockopt(socket, SOL_SOCKET, SO_ERROR,
                                 &error, &size) == 0, error == 0 else {
                    throw VPNUpdateBrokerClientError.unavailable
                }
            }
            return socket
        } catch {
            close(socket)
            throw error
        }
    }

}
