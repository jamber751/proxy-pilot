import Darwin
import Dispatch
import Foundation

enum VPNPasswordWorkerError: Error { case denied, invalid, transport, timeout, unavailable }
enum VPNPasswordWorkerOperation: String, Codable { case add, read, delete }
enum VPNPasswordWorkerStatus: UInt8 { case success = 0, notFound, denied, unavailable, failed, indeterminate }

/// Transient private IPC, never a Codable secret or a persistent receipt.
enum VPNPasswordWorkerWire {
    static let maximumSecretBytes = OpenVPNCredentialCommandEncoder.maximumSecretBytes
    static let maximumFrameBytes = 4096
    static let nonceBytes = 16
    private static let requestMagic = Data("PPPWGO01".utf8)
    private static let responseMagic = Data("PPPWRS01".utf8)

    struct Metadata: Codable, Equatable {
        let operation: VPNPasswordWorkerOperation
        let reference: VPNPasswordReference
        let revision: UInt64
        func encoded() throws -> Data {
            guard revision > 0, reference.profileSHA256.utf8.count == 64,
                  reference.profileSHA256.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }),
                  try VPNAuthentication(mode: .password, login: reference.login).login == reference.login else {
                throw VPNPasswordWorkerError.invalid
            }
            let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
            let data = try encoder.encode(self)
            guard data.count <= 1024 else { throw VPNPasswordWorkerError.invalid }
            return data
        }
    }

    struct Request {
        let metadata: Metadata
        var secret: Data
    }
    struct Response {
        let status: VPNPasswordWorkerStatus
        var secret: Data
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
        return data
    }

    static func decodeRequest(_ data: Data, nonce: Data) throws -> Request {
        let offset = 8 + nonceBytes
        guard data.count >= offset + 4, data.prefix(8) == requestMagic,
              data.subdata(in: 8..<offset) == nonce else { throw VPNPasswordWorkerError.invalid }
        let metadataCount = Int(data[offset]) << 8 | Int(data[offset + 1])
        let secretCount = Int(data[offset + 2]) << 8 | Int(data[offset + 3])
        guard metadataCount > 0, metadataCount <= 1024, secretCount <= maximumSecretBytes,
              data.count == offset + 4 + metadataCount + secretCount else { throw VPNPasswordWorkerError.invalid }
        let raw = data.subdata(in: (offset + 4)..<(offset + 4 + metadataCount))
        let metadata = try JSONDecoder().decode(Metadata.self, from: raw)
        guard try metadata.encoded() == raw else { throw VPNPasswordWorkerError.invalid }
        let secret = data.subdata(in: (offset + 4 + metadataCount)..<data.count)
        guard metadata.operation == .add ? validSecret(secret) : secret.isEmpty else { throw VPNPasswordWorkerError.invalid }
        return Request(metadata: metadata, secret: secret)
    }

    static func response(_ value: Response, nonce: Data) throws -> Data {
        guard nonce.count == nonceBytes, value.secret.isEmpty || (value.status == .success && validSecret(value.secret)) else {
            throw VPNPasswordWorkerError.invalid
        }
        var data = responseMagic + nonce
        data.append(value.status.rawValue); data.append(value.secret)
        return data
    }

    static func decodeResponse(_ data: Data, nonce: Data, operation: VPNPasswordWorkerOperation) throws -> Response {
        let offset = 8 + nonceBytes
        guard data.count >= offset + 1, data.prefix(8) == responseMagic,
              data.subdata(in: 8..<offset) == nonce,
              let status = VPNPasswordWorkerStatus(rawValue: data[offset]) else { throw VPNPasswordWorkerError.invalid }
        let secret = data.subdata(in: (offset + 1)..<data.count)
        guard operation == .read && status == .success ? validSecret(secret) : secret.isEmpty else {
            throw VPNPasswordWorkerError.invalid
        }
        return Response(status: status, secret: secret)
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
