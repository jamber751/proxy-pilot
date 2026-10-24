import Darwin
import Dispatch
import Foundation

enum VPNPasswordWorkerError: Error { case denied, invalid, transport, timeout, unavailable }
enum VPNPasswordWorkerOperation: String, Codable { case add, read, delete }
enum VPNPasswordWorkerStatus: UInt8, Codable { case success = 0, notFound, denied, unavailable, failed, indeterminate, definitelyNoIO }

/// Transient private IPC, never a Codable secret or a persistent receipt.
enum VPNPasswordWorkerWire {
    static let maximumSecretBytes = OpenVPNCredentialCommandEncoder.maximumSecretBytes
    // A maximum valid locator/ref with quoted path/login needs >8 KiB.
    // Canonical unescaped slashes keep base64 expansion within this budget.
    static let maximumMetadataBytes = 12288
    static let maximumFrameBytes = 16384
    static let nonceBytes = 16
    private static let requestMagic = Data("PPPWGO02".utf8)
    private static let responseMagic = Data("PPPWRS02".utf8)

    struct Metadata: Codable, Equatable {
        let operation: VPNPasswordWorkerOperation
        let reference: VPNPasswordReference
        let revision: UInt64
        let locator: VPNPasswordItemLocator?
        init(operation: VPNPasswordWorkerOperation, reference: VPNPasswordReference, revision: UInt64,
             locator: VPNPasswordItemLocator? = nil) {
            self.operation = operation; self.reference = reference; self.revision = revision; self.locator = locator
        }
        func encoded() throws -> Data {
            guard revision > 0, reference.profileSHA256.utf8.count == 64,
                  reference.profileSHA256.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }),
                  try VPNAuthentication(mode: .password, login: reference.login).login == reference.login else {
                throw VPNPasswordWorkerError.invalid
            }
            if operation == .add {
                guard locator == nil else { throw VPNPasswordWorkerError.invalid }
            } else {
                guard let locator else { throw VPNPasswordWorkerError.invalid }
                try locator.validate()
            }
            let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
            let data = try encoder.encode(self)
            guard data.count <= maximumMetadataBytes else { throw VPNPasswordWorkerError.invalid }
            return data
        }
    }

    struct Request {
        let metadata: Metadata
        var secret: Data
    }
    private struct ResponseMetadata: Codable {
        let status: VPNPasswordWorkerStatus
        let locator: VPNPasswordItemLocator?
        func encoded() throws -> Data {
            let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
            let bytes = try encoder.encode(self)
            guard bytes.count <= maximumMetadataBytes else { throw VPNPasswordWorkerError.invalid }
            return bytes
        }
    }
    struct Response {
        let status: VPNPasswordWorkerStatus
        var secret: Data
        let locator: VPNPasswordItemLocator?
        init(status: VPNPasswordWorkerStatus, secret: Data, locator: VPNPasswordItemLocator? = nil) {
            self.status = status; self.secret = secret; self.locator = locator
        }
        func validate(operation: VPNPasswordWorkerOperation) throws {
            if status == .success, operation == .add {
                guard let locator else { throw VPNPasswordWorkerError.invalid }
                try locator.validate()
            } else if locator != nil { throw VPNPasswordWorkerError.invalid }
            guard status != .definitelyNoIO || operation == .add,
                  operation == .read && status == .success ? validSecret(secret) : secret.isEmpty
            else { throw VPNPasswordWorkerError.invalid }
        }
        var addOutcome: VPNPasswordAddOutcome {
            guard (try? validate(operation: .add)) != nil else { return .indeterminate }
            if status == .success, let locator { return .added(locator) }
            if status == .definitelyNoIO { return .definitelyNoIO }
            return .indeterminate
        }
    }

    static func clear(_ data: inout Data) {
        data.resetBytes(in: 0..<data.count); data.removeAll(keepingCapacity: false)
    }

    static func request(_ value: Request, nonce: Data) throws -> Data {
        let metadata = try value.metadata.encoded()
        guard nonce.count == nonceBytes,
              value.metadata.operation == .add ? validSecret(value.secret) : value.secret.isEmpty else {
            throw VPNPasswordWorkerError.invalid
        }
        var data = requestMagic + nonce
        data.append(contentsOf: number16(metadata.count)); data.append(contentsOf: number16(value.secret.count))
        data.append(metadata); data.append(value.secret)
        guard data.count <= maximumFrameBytes else { throw VPNPasswordWorkerError.invalid }
        return data
    }

    static func decodeRequest(_ data: Data, nonce: Data) throws -> Request {
        let offset = 8 + nonceBytes
        guard data.count >= offset + 4, data.count <= maximumFrameBytes, data.prefix(8) == requestMagic,
              data.subdata(in: 8..<offset) == nonce else { throw VPNPasswordWorkerError.invalid }
        let metadataCount = Int(data[offset]) << 8 | Int(data[offset + 1])
        let secretCount = Int(data[offset + 2]) << 8 | Int(data[offset + 3])
        guard metadataCount > 0, metadataCount <= maximumMetadataBytes, secretCount <= maximumSecretBytes,
              data.count == offset + 4 + metadataCount + secretCount else { throw VPNPasswordWorkerError.invalid }
        let raw = data.subdata(in: (offset + 4)..<(offset + 4 + metadataCount))
        let metadata = try JSONDecoder().decode(Metadata.self, from: raw)
        guard try metadata.encoded() == raw else { throw VPNPasswordWorkerError.invalid }
        let secret = data.subdata(in: (offset + 4 + metadataCount)..<data.count)
        guard metadata.operation == .add ? validSecret(secret) : secret.isEmpty else { throw VPNPasswordWorkerError.invalid }
        return Request(metadata: metadata, secret: secret)
    }

    static func response(_ value: Response, nonce: Data, operation: VPNPasswordWorkerOperation) throws -> Data {
        guard nonce.count == nonceBytes else { throw VPNPasswordWorkerError.invalid }
        try value.validate(operation: operation)
        let metadata = try ResponseMetadata(status: value.status, locator: value.locator).encoded()
        var data = responseMagic + nonce
        data.append(contentsOf: number16(metadata.count)); data.append(contentsOf: number16(value.secret.count))
        data.append(metadata); data.append(value.secret)
        guard data.count <= maximumFrameBytes else { throw VPNPasswordWorkerError.invalid }
        return data
    }

    static func decodeResponse(_ data: Data, nonce: Data, operation: VPNPasswordWorkerOperation) throws -> Response {
        let offset = 8 + nonceBytes
        guard data.count >= offset + 4, data.count <= maximumFrameBytes,
              data.prefix(8) == responseMagic, data.subdata(in: 8..<offset) == nonce else {
            throw VPNPasswordWorkerError.invalid
        }
        let metadataCount = Int(data[offset]) << 8 | Int(data[offset + 1])
        let secretCount = Int(data[offset + 2]) << 8 | Int(data[offset + 3])
        guard metadataCount > 0, metadataCount <= maximumMetadataBytes, secretCount <= maximumSecretBytes,
              data.count == offset + 4 + metadataCount + secretCount else { throw VPNPasswordWorkerError.invalid }
        let raw = data.subdata(in: (offset + 4)..<(offset + 4 + metadataCount))
        let metadata = try JSONDecoder().decode(ResponseMetadata.self, from: raw)
        guard try metadata.encoded() == raw else { throw VPNPasswordWorkerError.invalid }
        let value = Response(status: metadata.status,
            secret: data.subdata(in: (offset + 4 + metadataCount)..<data.count), locator: metadata.locator)
        try value.validate(operation: operation)
        return value
    }

    static func validSecret(_ data: Data) -> Bool {
        !data.isEmpty && data.count <= maximumSecretBytes && data.allSatisfy { $0 >= 32 && $0 != 127 }
    }

    static func send(_ data: Data, socket: Int32, deadline: UInt64) throws {
        guard !data.isEmpty, data.count <= maximumFrameBytes else { throw VPNPasswordWorkerError.invalid }
        var prefix = Data(number32(data.count))
        defer { clear(&prefix) }
        try write(prefix, socket: socket, deadline: deadline)
        try write(data, socket: socket, deadline: deadline)
    }

    /// One nonblocking GO attempt while the short Store authority gate is
    /// held. A partial/error send is uncertain; never wait, poll or retry it.
    #if VPN_PASSWORD_WORKER_TESTING
    static var testImmediateLimit: Int?
    static var testImmediateSendCalls = 0
    #endif
    static func sendImmediate(_ data: Data, socket: Int32) throws {
        guard !data.isEmpty, data.count <= maximumFrameBytes else { throw VPNPasswordWorkerError.invalid }
        var frame = Data(number32(data.count)); frame.append(data)
        defer { clear(&frame) }
        var limit = frame.count
        #if VPN_PASSWORD_WORKER_TESTING
        testImmediateSendCalls += 1
        if let requested = testImmediateLimit { limit = max(0, min(limit, requested)) }
        #endif
        let sent = frame.withUnsafeBytes { Darwin.send(socket, $0.baseAddress, limit, MSG_DONTWAIT | MSG_NOSIGNAL) }
        guard sent == frame.count else {
            shutdown(socket, SHUT_WR) // An incomplete GO can never be completed later.
            throw VPNPasswordWorkerError.transport
        }
    }

    static func receive(socket: Int32, deadline: UInt64) throws -> Data {
        let length = try read(4, socket: socket, deadline: deadline)
        let count = length.reduce(0) { $0 << 8 | Int($1) }
        guard count > 0, count <= maximumFrameBytes else { throw VPNPasswordWorkerError.invalid }
        return try read(count, socket: socket, deadline: deadline)
    }

    private static func read(_ count: Int, socket: Int32, deadline: UInt64) throws -> Data {
        var data = Data(count: count)
        do {
            var offset = 0
            while offset < count {
                try wait(socket, event: Int16(POLLIN), deadline: deadline)
                let n = data.withUnsafeMutableBytes { recv(socket, $0.baseAddress!.advanced(by: offset), count - offset, MSG_DONTWAIT) }
                if n < 0, errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK { continue }
                guard n > 0 else { throw VPNPasswordWorkerError.transport }
                offset += n
            }
            return data
        } catch { clear(&data); throw error }
    }

    private static func write(_ data: Data, socket: Int32, deadline: UInt64) throws {
        var offset = 0
        while offset < data.count {
            try wait(socket, event: Int16(POLLOUT), deadline: deadline)
            let n = data.withUnsafeBytes { Darwin.send(socket, $0.baseAddress!.advanced(by: offset), data.count - offset, MSG_DONTWAIT | MSG_NOSIGNAL) }
            if n < 0, errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK { continue }
            guard n > 0 else { throw VPNPasswordWorkerError.transport }
            offset += n
        }
    }

    private static func wait(_ socket: Int32, event: Int16, deadline: UInt64) throws {
        while true {
            let now = DispatchTime.now().uptimeNanoseconds
            guard now < deadline else { throw VPNPasswordWorkerError.timeout }
            let remaining = deadline - now
            var descriptor = pollfd(fd: socket, events: event, revents: 0)
            let result = poll(&descriptor, 1, Int32(min(1000, (remaining + 999_999) / 1_000_000)))
            if result < 0, errno == EINTR { continue }
            guard result >= 0, descriptor.revents & Int16(POLLERR | POLLNVAL) == 0 else { throw VPNPasswordWorkerError.transport }
            if result > 0 { return }
        }
    }
    private static func number16(_ n: Int) -> [UInt8] { [UInt8(n >> 8), UInt8(n & 255)] }
    private static func number32(_ n: Int) -> [UInt8] { (0..<4).reversed().map { UInt8((n >> ($0 * 8)) & 255) } }
}
