import Darwin
import Dispatch
import Foundation

enum OpenVPNManagementClientError: Error {
    case closed, invalidEndpoint, invalidCommand, timeout, transport, lineTooLong,
         tooManyIgnoredMessages
}

/// Only local transports are representable: an absolute Unix socket or an
/// explicit IPv4 loopback port. There is no hostname or remote-address input.
enum OpenVPNManagementEndpoint: Equatable {
    case unixSocket(String)
    case loopbackTCP(UInt16)
}

final class OpenVPNManagementClient {
    static let maximumIgnoredMessages = 32
    static let maximumCredentialCommandBytes = 4096
    private var descriptor: Int32
    private var buffered = [UInt8]()

    static func connect(to endpoint: OpenVPNManagementEndpoint,
                        timeoutMilliseconds: Int = 2000) throws -> OpenVPNManagementClient {
        guard (1...10_000).contains(timeoutMilliseconds) else {
            throw OpenVPNManagementClientError.invalidEndpoint
        }
        let deadline = DispatchTime.now().uptimeNanoseconds
            + UInt64(timeoutMilliseconds) * 1_000_000
        let socket: Int32
        switch endpoint {
        case .unixSocket(let path): socket = try connectUnix(path: path, deadline: deadline)
        case .loopbackTCP(let port): socket = try connectLoopback(port: port, deadline: deadline)
        }
        return try OpenVPNManagementClient(takingConnectedSocket: socket)
    }

    /// Test seam for a deterministic local fake server. Ownership transfers to
    /// the client and the descriptor is always switched to non-blocking mode.
    init(takingConnectedSocket descriptor: Int32) throws {
        guard descriptor >= 0 else { throw OpenVPNManagementClientError.transport }
        self.descriptor = descriptor
        let flags = fcntl(descriptor, F_GETFL)
        guard flags >= 0, fcntl(descriptor, F_SETFD, FD_CLOEXEC) == 0,
              fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) == 0 else {
            Darwin.close(descriptor)
            self.descriptor = -1
            throw OpenVPNManagementClientError.transport
        }
    }

    deinit { close() }

    func close() {
        if descriptor >= 0 { Darwin.close(descriptor); descriptor = -1 }
        buffered.removeAll(keepingCapacity: false)
    }

    func send(_ command: OpenVPNManagementCommand, timeoutMilliseconds: Int = 2000) throws {
        guard descriptor >= 0 else { throw OpenVPNManagementClientError.closed }
        do {
            let deadline = try Self.deadline(timeoutMilliseconds)
            try write(command.bytes, deadline: deadline)
            VPNFlowDiagnostics.command(command)
        } catch {
            close()
            throw error
        }
    }

    /// Byte-only credential path. Exactly one printable management command is
    /// accepted, so a malformed encoder/caller cannot append another command.
    func sendCredentialCommand(_ bytes: UnsafeRawBufferPointer,
                               timeoutMilliseconds: Int = 2_000) throws {
        guard descriptor >= 0 else { throw OpenVPNManagementClientError.closed }
        guard (2...Self.maximumCredentialCommandBytes).contains(bytes.count),
              bytes.last == 10,
              bytes.dropLast().allSatisfy({ $0 >= 32 && $0 != 127 && $0 != 10 && $0 != 13 }) else {
            close()
            throw OpenVPNManagementClientError.invalidCommand
        }
        do {
            let deadline = try Self.deadline(timeoutMilliseconds)
            try write(bytes, deadline: deadline)
            VPNFlowDiagnostics.credentialWritten()
        } catch {
            close()
            throw error
        }
    }

    func readEvent(timeoutMilliseconds: Int = 2000) throws -> OpenVPNManagementEvent {
        guard descriptor >= 0 else { throw OpenVPNManagementClientError.closed }
        do {
            let deadline = try Self.deadline(timeoutMilliseconds)
            for _ in 0..<Self.maximumIgnoredMessages {
                let line = try readLine(deadline: deadline)
                if let event = try OpenVPNManagementParser.parse(line: line) {
                    VPNFlowDiagnostics.management(event)
                    return event
                }
            }
            throw OpenVPNManagementClientError.tooManyIgnoredMessages
        } catch {
            close()
            throw error
        }
    }

    private static func deadline(_ milliseconds: Int) throws -> UInt64 {
        guard (1...10_000).contains(milliseconds) else {
            throw OpenVPNManagementClientError.invalidEndpoint
        }
        return DispatchTime.now().uptimeNanoseconds + UInt64(milliseconds) * 1_000_000
    }

    private func readLine(deadline: UInt64) throws -> [UInt8] {
        while true {
            if let newline = buffered.firstIndex(of: 10) {
                var line = Array(buffered[..<newline])
                buffered.removeFirst(newline + 1)
                if line.last == 13 { line.removeLast() }
                guard line.count <= OpenVPNManagementParser.maximumLineBytes else {
                    throw OpenVPNManagementClientError.lineTooLong
                }
                return line
            }
            guard buffered.count <= OpenVPNManagementParser.maximumLineBytes else {
                throw OpenVPNManagementClientError.lineTooLong
            }
            try wait(events: Int16(POLLIN), deadline: deadline)
            let chunkSize = 512
            var chunk = [UInt8](repeating: 0, count: chunkSize)
            let count = chunk.withUnsafeMutableBytes {
                recv(descriptor, $0.baseAddress, chunkSize, MSG_DONTWAIT)
            }
            if count < 0, [EINTR, EAGAIN, EWOULDBLOCK].contains(errno) { continue }
            guard count > 0 else { throw OpenVPNManagementClientError.transport }
            buffered.append(contentsOf: chunk.prefix(count))
        }
    }

    private func write(_ bytes: [UInt8], deadline: UInt64) throws {
        try bytes.withUnsafeBytes { try write($0, deadline: deadline) }
    }

    private func write(_ bytes: UnsafeRawBufferPointer, deadline: UInt64) throws {
        var offset = 0
        while offset < bytes.count {
            try wait(events: Int16(POLLOUT), deadline: deadline)
            let count = Darwin.send(descriptor, bytes.baseAddress!.advanced(by: offset),
                                    bytes.count - offset, MSG_DONTWAIT | MSG_NOSIGNAL)
            if count < 0, [EINTR, EAGAIN, EWOULDBLOCK].contains(errno) { continue }
            guard count > 0 else { throw OpenVPNManagementClientError.transport }
            offset += count
        }
    }

    private func wait(events: Int16, deadline: UInt64) throws {
        while true {
            let now = DispatchTime.now().uptimeNanoseconds
            guard now < deadline else { throw OpenVPNManagementClientError.timeout }
            var item = pollfd(fd: descriptor, events: events, revents: 0)
            let result = poll(&item, 1, Int32((deadline - now + 999_999) / 1_000_000))
            if result < 0, errno == EINTR { continue }
            guard result >= 0 else { throw OpenVPNManagementClientError.transport }
            if result == 0 { continue }
            guard item.revents & Int16(POLLNVAL | POLLERR) == 0,
                  item.revents & (events | Int16(POLLHUP)) != 0 else {
                throw OpenVPNManagementClientError.transport
            }
            return
        }
    }

    private static func finishConnect(_ socket: Int32, deadline: UInt64) throws -> Int32 {
        do {
            var item = pollfd(fd: socket, events: Int16(POLLOUT), revents: 0)
            while true {
                let now = DispatchTime.now().uptimeNanoseconds
                guard now < deadline else { throw OpenVPNManagementClientError.timeout }
                let result = poll(&item, 1, Int32((deadline - now + 999_999) / 1_000_000))
                if result < 0, errno == EINTR { continue }
                guard result > 0 else { continue }
                var error: Int32 = 0
                var length = socklen_t(MemoryLayout<Int32>.size)
                guard getsockopt(socket, SOL_SOCKET, SO_ERROR, &error, &length) == 0, error == 0 else {
                    throw OpenVPNManagementClientError.transport
                }
                return socket
            }
        } catch {
            Darwin.close(socket)
            throw error
        }
    }

    private static func connectLoopback(port: UInt16, deadline: UInt64) throws -> Int32 {
        guard port != 0 else { throw OpenVPNManagementClientError.invalidEndpoint }
        let fd = try newSocket(domain: AF_INET)
        var address = sockaddr_in(sin_len: UInt8(MemoryLayout<sockaddr_in>.size),
                                  sin_family: sa_family_t(AF_INET),
                                  sin_port: port.bigEndian,
                                  sin_addr: in_addr(s_addr: inet_addr("127.0.0.1")),
                                  sin_zero: (0, 0, 0, 0, 0, 0, 0, 0))
        let result = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard result == 0 || errno == EINPROGRESS else {
            Darwin.close(fd); throw OpenVPNManagementClientError.transport
        }
        return result == 0 ? fd : try finishConnect(fd, deadline: deadline)
    }

    private static func connectUnix(path: String, deadline: UInt64) throws -> Int32 {
        guard path.hasPrefix("/"), !path.utf8.contains(0) else {
            throw OpenVPNManagementClientError.invalidEndpoint
        }
        var before = stat()
        guard lstat(path, &before) == 0, before.st_mode & S_IFMT == S_IFSOCK,
              before.st_uid == geteuid(), before.st_nlink == 1 else {
            throw OpenVPNManagementClientError.invalidEndpoint
        }
        let pathBytes = Array(path.utf8) + [0]
        var address = sockaddr_un()
        guard pathBytes.count <= MemoryLayout.size(ofValue: address.sun_path) else {
            throw OpenVPNManagementClientError.invalidEndpoint
        }
        address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        address.sun_family = sa_family_t(AF_UNIX)
        withUnsafeMutableBytes(of: &address.sun_path) { destination in
            destination.copyBytes(from: pathBytes)
        }
        let fd = try newSocket(domain: AF_UNIX)
        let result = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard result == 0 || errno == EINPROGRESS else {
            Darwin.close(fd); throw OpenVPNManagementClientError.transport
        }
        let connected = result == 0 ? fd : try finishConnect(fd, deadline: deadline)
        var after = stat()
        guard lstat(path, &after) == 0, after.st_mode & S_IFMT == S_IFSOCK,
              after.st_uid == geteuid(), after.st_nlink == 1,
              before.st_dev == after.st_dev, before.st_ino == after.st_ino else {
            Darwin.close(connected); throw OpenVPNManagementClientError.invalidEndpoint
        }
        return connected
    }

    /// Set close-on-exec before connect so a future concurrent child spawn can
    /// never inherit a management descriptor during this small setup window.
    private static func newSocket(domain: Int32) throws -> Int32 {
        let fd = socket(domain, SOCK_STREAM, 0)
        guard fd >= 0 else { throw OpenVPNManagementClientError.transport }
        let flags = fcntl(fd, F_GETFL)
        guard flags >= 0, fcntl(fd, F_SETFD, FD_CLOEXEC) == 0,
              fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0 else {
            Darwin.close(fd)
            throw OpenVPNManagementClientError.transport
        }
        return fd
    }
}
