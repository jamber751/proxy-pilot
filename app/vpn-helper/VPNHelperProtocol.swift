import Darwin
import Dispatch

enum VPNHelperTransportError: Error { case timeout, transport }

/// The whole vocabulary the privileged helper understands. Fixed frames, fixed
/// sizes, no strings, no paths and no shell: a caller can name an operation from
/// this list and nothing else. Adding an operation is a deliberate change here,
/// not something a client can request or a payload can imply.
enum VPNHelperOperation: UInt16 {
    case status = 1
    /// Hands the helper profile bytes to re-validate and keep. It never makes
    /// the helper connect, route or resolve anything.
    case storeProfile = 2
    case applyConfiguration = 3
    case connect = 4
    case disconnect = 5
    case tunnelStatus = 6
    case submitCredential = 7
    case cancelCredential = 8
}

enum VPNHelperStatus: UInt16 {
    case ok = 0
    case unsupported = 1
    case invalidRequest = 2
    case failed = 3
    case needsCredential = 4
    case notReady = 5
}

enum VPNHelperProtocol {
    /// One definition of the endpoint name, shared by the helper that binds it
    /// and the adapter that waits for, connects to and removes it.
    static let socketName = "helper.sock"
    static let requestMagic = Array("PPVNOP01".utf8)
    static let responseMagic = Array("PPVNRS01".utf8)
    /// A request header is magic, operation, revision and payload length.
    static let headerBytes = 8 + 2 + 8 + 4
    // Match the importer's 1 MiB ceiling. Still one bounded frame, never an
    // unbounded stream; peers reject the length before allocating/reading it.
    static let maximumPayloadBytes = 1_048_576
    /// One connection is one short conversation, not a session to keep open.
    static let maximumRequestsPerConnection = 8
    /// Per request, because re-authenticating a peer costs real time; the
    /// conversation as a whole is capped separately so a slow or idle client
    /// cannot hold the single-threaded helper for the sum of every deadline.
    static let requestTimeoutMilliseconds = 5000
    static let conversationTimeoutMilliseconds = 30000
    static let credentialInputTimeoutMilliseconds = 90000

    static func encode(_ value: UInt64) -> [UInt8] {
        (0..<8).reversed().map { UInt8(truncatingIfNeeded: value >> ($0 * 8)) }
    }

    static func encode(_ value: UInt32) -> [UInt8] {
        (0..<4).reversed().map { UInt8(truncatingIfNeeded: value >> ($0 * 8)) }
    }

    static func encode(_ value: UInt16) -> [UInt8] {
        [UInt8(truncatingIfNeeded: value >> 8), UInt8(truncatingIfNeeded: value)]
    }

    static func number(_ bytes: ArraySlice<UInt8>) -> UInt64 {
        bytes.reduce(0) { ($0 << 8) | UInt64($1) }
    }

    /// Requests carry the release revision the client believes it is talking to.
    /// A helper that was replaced mid-conversation refuses instead of applying an
    /// operation meant for another build.
    static func request(_ operation: VPNHelperOperation, revision: UInt64, payload: [UInt8]) -> [UInt8] {
        requestMagic + encode(operation.rawValue) + encode(revision)
            + encode(UInt32(payload.count)) + payload
    }

    static func response(_ status: VPNHelperStatus, payload: [UInt8]) -> [UInt8] {
        responseMagic + encode(status.rawValue) + encode(UInt32(payload.count)) + payload
    }
}

/// Deadline-bounded framing shared by both ends. Every read and write is exact:
/// no unbounded buffering, no partial frame accepted, no blocking without a
/// deadline. Both sides own their descriptor; this never closes it for them.
extension VPNHelperProtocol {
    static func wait(_ socket: Int32, events: Int16, deadline: UInt64) throws {
        while true {
            let now = DispatchTime.now().uptimeNanoseconds
            guard now < deadline else { throw VPNHelperTransportError.timeout }
            var descriptor = pollfd(fd: socket, events: events, revents: 0)
            let result = poll(&descriptor, 1, Int32((deadline - now + 999_999) / 1_000_000))
            if result < 0, errno == EINTR { continue }
            guard result >= 0 else { throw VPNHelperTransportError.transport }
            if result == 0 { continue }
            guard descriptor.revents & Int16(POLLNVAL | POLLERR) == 0 else { throw VPNHelperTransportError.transport }
            // Allow a final buffered read on HUP; a zero-length recv rejects EOF.
            guard descriptor.revents & (events | Int16(POLLHUP)) != 0 else { continue }
            return
        }
    }

    static func write(_ bytes: [UInt8], socket: Int32, deadline: UInt64) throws {
        var offset = 0
        while offset < bytes.count {
            try wait(socket, events: Int16(POLLOUT), deadline: deadline)
            let sent = bytes.withUnsafeBytes {
                send(socket, $0.baseAddress!.advanced(by: offset), bytes.count - offset, MSG_DONTWAIT)
            }
            if sent < 0, [EINTR, EAGAIN, EWOULDBLOCK].contains(errno) { continue }
            guard sent > 0 else { throw VPNHelperTransportError.transport }
            offset += sent
        }
    }

    static func read(count: Int, socket: Int32, deadline: UInt64) throws -> [UInt8] {
        guard let bytes = try read(count: count, socket: socket, deadline: deadline, allowingClose: false) else {
            throw VPNHelperTransportError.transport
        }
        return bytes
    }

    /// `allowingClose` distinguishes "the peer finished and hung up" from "the
    /// peer vanished mid-frame": only the former may end a conversation quietly.
    static func read(count: Int, socket: Int32, deadline: UInt64, allowingClose: Bool) throws -> [UInt8]? {
        var bytes = [UInt8](repeating: 0, count: count), offset = 0
        while offset < count {
            try wait(socket, events: Int16(POLLIN), deadline: deadline)
            let received = bytes.withUnsafeMutableBytes {
                recv(socket, $0.baseAddress!.advanced(by: offset), count - offset, MSG_DONTWAIT)
            }
            if received < 0, [EINTR, EAGAIN, EWOULDBLOCK].contains(errno) { continue }
            if received == 0, offset == 0, allowingClose { return nil }
            guard received > 0 else { throw VPNHelperTransportError.transport }
            offset += received
        }
        return bytes
    }
}
