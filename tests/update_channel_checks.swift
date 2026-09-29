import Foundation
import Darwin

@main
enum Checks {
    static func rejects(_ operation: () throws -> Void) {
        do { try operation(); fatalError("Accepted malformed input") } catch {}
    }

    static func main() throws {
        let mode = CommandLine.arguments[1]
        let state = UpdateSnapshot(canCheck: true, automatic: false, inProgress: false, availableVersion: "1.5.1", jointUpdate: false)
        if mode == "wire" {
            let token = UUID()
            let messages: [UpdateMessage] = [.check, .automatic(true), .automatic(false), .resume(token),
                .armJointRelaunch(token), .jointRelaunchArmed(token),
                .state(state), .state(UpdateSnapshot(canCheck: false, automatic: true, inProgress: true, availableVersion: nil, jointUpdate: true)),
                .present, .aborted, .prepare(token), .failed]
            var decoder = UpdateWire.Decoder()
            for message in messages {
                let frame = try UpdateWire.frame(message)
                var result: [UpdateMessage] = []
                for byte in frame { result += try decoder.append(Data([byte])) }
                precondition(result == [message] && !decoder.hasPartialFrame)
            }
            let batched = try messages.reduce(into: Data()) { $0.append(try UpdateWire.frame($1)) }
            let decoded = try decoder.append(batched)
            precondition(decoded == messages)
        } else if mode == "malformed" {
            for value in ["{}", "[]", "{\"version\":2,\"kind\":\"check\"}",
                          "{\"version\":1,\"kind\":\"shell\"}",
                          "{\"version\":1,\"kind\":\"check\",\"path\":\"/tmp\"}",
                          "{\"version\":1,\"kind\":\"automatic\"}",
                          "{\"version\":1,\"kind\":\"resume\",\"token\":\"invalid\"}",
                          "{\"version\":1,\"kind\":\"state\",\"state\":{\"canCheck\":true}}"] {
                rejects { _ = try UpdateWire.decode(Data(value.utf8)) }
            }
            rejects { _ = try UpdateWire.frame(.state(UpdateSnapshot(canCheck: true, automatic: true, inProgress: false, availableVersion: String(repeating: "a", count: 65), jointUpdate: false))) }
            rejects { _ = try UpdateWire.frame(.state(UpdateSnapshot(canCheck: true, automatic: true, inProgress: false, availableVersion: "1.0\nInjected", jointUpdate: false))) }
            for header in [[UInt8](repeating: 0, count: 4), [0, 0, 16, 1], [255, 255, 255, 255]] {
                rejects { var decoder = UpdateWire.Decoder(); _ = try decoder.append(Data(header)) }
            }
        } else {
            let incoming = Pipe(), outgoing = Pipe()
            let signal = DispatchSemaphore(value: 0)
            var channel: UpdateChannel? = try UpdateChannel(read: incoming.fileHandleForReading.fileDescriptor,
                                                            write: outgoing.fileHandleForWriting.fileDescriptor,
                                                            receivesCommands: true, receive: { message in
                precondition(mode == "receive" && message == .check)
                signal.signal()
            }, disconnected: { signal.signal() })
            channel!.start()
            incoming.fileHandleForReading.closeFile(); outgoing.fileHandleForWriting.closeFile()
            switch mode {
            case "receive":
                let frame = try UpdateWire.frame(.check)
                for byte in frame { incoming.fileHandleForWriting.write(Data([byte])) }
            case "direction": incoming.fileHandleForWriting.write(try UpdateWire.frame(.present))
            case "eof": incoming.fileHandleForWriting.closeFile()
            case "broken-pipe": outgoing.fileHandleForReading.closeFile(); channel!.send(.state(state))
            case "oversized": incoming.fileHandleForWriting.write(Data([0, 0, 16, 1]))
            case "partial-timeout": incoming.fileHandleForWriting.write(Data([0]))
            case "backpressure":
                for _ in 0..<4000 { channel!.send(.state(state)) }
            case "close":
                channel!.close() // EOF must not depend on deinitializing the channel.
                let data = outgoing.fileHandleForReading.readDataToEndOfFile()
                precondition(data.isEmpty); signal.signal()
            case "duplex":
                channel!.send(.state(state))
                var decoder = UpdateWire.Decoder()
                let decoded = try decoder.append(outgoing.fileHandleForReading.availableData)
                precondition(decoded == [.state(state)])
                signal.signal()
            default: fatalError("Unknown mode")
            }
            precondition(signal.wait(timeout: .now() + 13) == .success, "Channel did not finish")
            channel!.close(); channel = nil
        }
        print("PASS \(mode)")
    }
}
