import Foundation
import Darwin

/// Private inherited pipes, never a named/public endpoint. Reads and writes are
/// nonblocking, bounded and off the UI thread. The channel owns duplicated FDs.
final class UpdateChannel {
    private final class Descriptor {
        let value: Int32
        init(_ value: Int32) { self.value = value }
        deinit { Darwin.close(value) }
    }
    private let queue = DispatchQueue(label: "kz.documentolog.proxypilot.update-channel")
    private let key = DispatchSpecificKey<Bool>()
    private var input: Descriptor?
    private var output: Descriptor?
    private let receivesCommands: Bool
    private let receive: (UpdateMessage) -> Void
    private let disconnected: () -> Void
    private var reader: DispatchSourceRead?
    private var writer: DispatchSourceWrite?
    private var timer: DispatchSourceTimer?
    private var decoder = UpdateWire.Decoder()
    private var pending = Data()
    private var partialSince: DispatchTime?
    private var writeSince: DispatchTime?
    private var closed = false

    init(read: Int32, write: Int32, receivesCommands: Bool,
         receive: @escaping (UpdateMessage) -> Void, disconnected: @escaping () -> Void) throws {
        let inputFD = fcntl(read, F_DUPFD_CLOEXEC, 3)
        guard inputFD >= 0 else { throw UpdateWire.Failure.malformed }
        input = Descriptor(inputFD)
        let outputFD = fcntl(write, F_DUPFD_CLOEXEC, 3)
        guard outputFD >= 0 else { throw UpdateWire.Failure.malformed }
        output = Descriptor(outputFD)
        self.receivesCommands = receivesCommands
        self.receive = receive
        self.disconnected = disconnected
        guard fcntl(inputFD, F_SETFL, fcntl(inputFD, F_GETFL) | O_NONBLOCK) == 0,
              fcntl(outputFD, F_SETFL, fcntl(outputFD, F_GETFL) | O_NONBLOCK) == 0,
              fcntl(outputFD, F_SETNOSIGPIPE, 1) == 0 else {
            throw UpdateWire.Failure.malformed
        }
        queue.setSpecific(key: key, value: true)
    }

    func start() {
        queue.async { [self] in
            guard !closed, reader == nil, let input = input else { return }
            let source = DispatchSource.makeReadSource(fileDescriptor: input.value, queue: queue)
            source.setEventHandler { [weak self] in self?.readAvailable() }
            source.setCancelHandler { [input] in withExtendedLifetime(input) {} }
            reader = source; source.resume()
            let deadline = DispatchSource.makeTimerSource(queue: queue)
            deadline.schedule(deadline: .now() + 1, repeating: 1)
            deadline.setEventHandler { [weak self] in
                guard let self = self else { return }
                let now = DispatchTime.now().uptimeNanoseconds
                for start in [self.partialSince, self.writeSince].compactMap({ $0 }) {
                    if now - start.uptimeNanoseconds >= 10_000_000_000 { self.finish(notify: true); return }
                }
            }
            timer = deadline; deadline.resume()
        }
    }

    func send(_ message: UpdateMessage) {
        queue.async { [self] in
            guard !closed else { return }
            do {
                guard message.isCommand != receivesCommands else { throw UpdateWire.Failure.malformed }
                let frame = try UpdateWire.frame(message)
                guard pending.count + frame.count <= 16 * 1024 else { throw UpdateWire.Failure.oversized }
                if pending.isEmpty { writeSince = .now() }
                pending.append(frame)
                flush()
            } catch { finish(notify: true) }
        }
    }

    func close() {
        if DispatchQueue.getSpecific(key: key) == true { finish(notify: false) }
        else { queue.sync { finish(notify: false) } }
    }

    deinit { close() }

    private func readAvailable() {
        guard !closed, let input = input else { return }
        var bytes = [UInt8](repeating: 0, count: UpdateWire.maximumPayload)
        // Bound each dispatch turn as well as each frame.
        for _ in 0..<16 {
            let count = Darwin.read(input.value, &bytes, bytes.count)
            if count == 0 { finish(notify: true); return }
            if count < 0 {
                if errno == EINTR { continue }
                if errno != EAGAIN && errno != EWOULDBLOCK { finish(notify: true) }
                return
            }
            do {
                for message in try decoder.append(Data(bytes.prefix(count))) {
                    guard message.isCommand == receivesCommands else { throw UpdateWire.Failure.malformed }
                    receive(message)
                    if closed { return }
                }
                if !decoder.hasPartialFrame { partialSince = nil }
                else if partialSince == nil { partialSince = .now() }
            } catch { finish(notify: true); return }
        }
    }

    private func flush() {
        guard !closed, let output = output else { return }
        while !pending.isEmpty {
            let count = pending.withUnsafeBytes { Darwin.write(output.value, $0.baseAddress, $0.count) }
            if count > 0 { pending.removeFirst(count); continue }
            if count < 0 && errno == EINTR { continue }
            if count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK) {
                if writer == nil {
                    let source = DispatchSource.makeWriteSource(fileDescriptor: output.value, queue: queue)
                    source.setEventHandler { [weak self] in self?.flush() }
                    source.setCancelHandler { [output] in withExtendedLifetime(output) {} }
                    writer = source; source.resume()
                }
                return
            }
            finish(notify: true); return
        }
        writeSince = nil
        writer?.cancel(); writer = nil
    }

    private func finish(notify: Bool) {
        guard !closed else { return }
        closed = true
        reader?.cancel(); reader = nil
        writer?.cancel(); writer = nil
        timer?.cancel(); timer = nil
        input = nil; output = nil
        pending.removeAll(); decoder = UpdateWire.Decoder()
        if notify { disconnected() }
    }
}
