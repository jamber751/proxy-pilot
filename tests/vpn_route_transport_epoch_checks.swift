import Foundation
import Dispatch
import Darwin

private enum Failure: Error { case check }
private func check(_ value: @autoclosure () -> Bool) throws {
    guard value() else { throw Failure.check }
}

/// Finite broadcast receive queues. A write can succeed while its reply is
/// dropped because the socket has accumulated unsolicited idle messages.
private final class IO: VPNRouteSocketIO {
    var next: Int32 = 1000
    var queues: [Int32: [Data]] = [:]
    var opened = [Int32](), closed = [Int32]()
    var writes = [(Int32, Data, UInt64)]()
    var reads = [(Int32, Int, UInt64)]()
    var failOpen = false, failSend = false
    var dropped = 0
    func open() throws -> Int32 {
        if failOpen { failOpen = false; throw VPNRouteSocketTransportError.posix(EMFILE) }
        next += 1; queues[next] = []; opened.append(next); return next
    }
    func close(_ descriptor: Int32) {
        closed.append(descriptor); queues.removeValue(forKey: descriptor)
    }
    func broadcast() {
        for descriptor in Array(queues.keys) { queues[descriptor] = [Data([1]), Data([2])] }
    }
    static func reply(_ query: Data) -> Data { Data([0xa1]) + query }
    func send(_ message: Data, descriptor: Int32, deadline: DispatchTime) throws {
        writes.append((descriptor, message, deadline.uptimeNanoseconds))
        if failSend { throw VPNRouteSocketTransportError.posix(EIO) }
        guard let queue = queues[descriptor] else { throw Failure.check }
        if queue.count < 2 { queues[descriptor]!.append(Self.reply(message)) }
        else { dropped += 1 }
    }
    func receive(descriptor: Int32, maximumBytes: Int, deadline: DispatchTime) throws -> Data {
        reads.append((descriptor, maximumBytes, deadline.uptimeNanoseconds))
        guard let queue = queues[descriptor], !queue.isEmpty else { throw VPNRouteSocketTransportError.timeout }
        return queues[descriptor]!.removeFirst()
    }
}

@main private enum Checks {
    static func main() throws {
        let io = IO(), query = Data([7, 8, 9])
        let deadline = DispatchTime(uptimeNanoseconds: 123_456)
        let name = CommandLine.arguments[1]
        switch name {
        case "initial-failure":
            io.failOpen = true
            do { _ = try VPNDarwinRouteSocketTransport(io: io); throw Failure.check }
            catch VPNRouteSocketTransportError.posix(let code) { try check(code == EMFILE) }
            try check(io.opened.isEmpty && io.closed.isEmpty && io.writes.isEmpty)
        case "idle-full", "between-full":
            let transport = try VPNDarwinRouteSocketTransport(io: io)
            if name == "between-full" {
                try transport.send(query, deadline: deadline)
                let first = try transport.receive(maximumBytes: 4096, deadline: deadline)
                try check(first == IO.reply(query))
            }
            io.broadcast()
            try transport.send(query, deadline: deadline)
            let answer = try transport.receive(maximumBytes: 4096, deadline: deadline)
            try check(answer == IO.reply(query) && io.dropped == 0)
        case "open-failure":
            var transport: VPNDarwinRouteSocketTransport? = try VPNDarwinRouteSocketTransport(io: io)
            io.failOpen = true
            do { try transport!.send(query, deadline: deadline); throw Failure.check }
            catch VPNRouteSocketTransportError.posix(let code) { try check(code == EMFILE) }
            try check(io.writes.isEmpty && io.closed.isEmpty && io.opened.count == 1)
            transport = nil
            try check(io.closed == io.opened)
        case "write-failure":
            var transport: VPNDarwinRouteSocketTransport? = try VPNDarwinRouteSocketTransport(io: io)
            io.failSend = true
            do { try transport!.send(query, deadline: deadline); throw Failure.check }
            catch VPNRouteSocketTransportError.posix(let code) { try check(code == EIO) }
            try check(io.writes.count == 1 && io.opened.count == 2 && io.closed.count == 1)
            transport = nil
            try check(Set(io.closed) == Set(io.opened) && io.closed.count == io.opened.count)
        case "lifetime":
            var transport: VPNDarwinRouteSocketTransport? = try VPNDarwinRouteSocketTransport(io: io)
            for _ in 0..<3 {
                try transport!.send(query, deadline: deadline)
                _ = try transport!.receive(maximumBytes: 4096, deadline: deadline)
            }
            try check(io.opened.count == 4 && io.closed.count == 3)
            transport = nil
            try check(io.closed == io.opened)
        case "deadline":
            let transport = try VPNDarwinRouteSocketTransport(io: io)
            try transport.send(query, deadline: deadline)
            _ = try transport.receive(maximumBytes: 73, deadline: deadline)
            try check(io.writes.count == 1 && io.reads.count == 1 &&
                io.writes[0].0 == io.reads[0].0 && io.writes[0].1 == query &&
                io.writes[0].2 == deadline.uptimeNanoseconds &&
                io.reads[0].1 == 73 && io.reads[0].2 == deadline.uptimeNanoseconds)
        default: throw Failure.check
        }
        print("PASS route-transport-epoch")
    }
}
