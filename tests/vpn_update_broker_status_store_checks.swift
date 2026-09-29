import Darwin
import Foundation

private enum Injected: Error { case crash }

@main enum VPNUpdateBrokerStatusStoreChecks {
    static func require(_ value: @autoclosure () -> Bool) throws {
        guard value() else { throw NSError(domain: "broker-status", code: 1) }
    }

    static func rejects(_ expected: VPNUpdateBrokerStatusStoreError,
                        _ body: () throws -> Void) throws {
        do {
            try body()
            throw NSError(domain: "broker-status", code: 2)
        } catch let error as VPNUpdateBrokerStatusStoreError {
            try require(error == expected)
        }
    }

    static func directory(_ path: String) throws -> Int32 {
        try FileManager.default.createDirectory(atPath: path,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700])
        let fd = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw Injected.crash }
        return fd
    }

    static func roundTrip(_ path: String) throws {
        let fd = try directory(path); defer { close(fd) }
        let store = try VPNUpdateBrokerStatusStore(trustedDirectoryDescriptor: fd)
        let absent = try store.load()
        try require(absent == .idle)
        let first = try store.publish(state: .checking, fromSequence: 41,
                                      toSequence: 42, expectedRevision: 0)
        try require(first == VPNUpdateBrokerResponse(state: .checking,
            fromSequence: 41, toSequence: 42, revision: 1))
        let repeated = try store.publish(state: .checking, fromSequence: 41,
                                         toSequence: 42, expectedRevision: 0)
        try require(repeated == first)
        let second = try store.publish(state: .ready, fromSequence: 41,
                                       toSequence: 42, expectedRevision: 1)
        try require(second.revision == 2)
        try rejects(.staleRevision) {
            _ = try store.publish(state: .installing, fromSequence: 41,
                                  toSequence: 42, expectedRevision: 1)
        }
        let loaded = try store.load()
        try require(loaded.response == second && loaded.state == .ready)
    }

    static func crash(_ path: String, checkpoint: String) throws {
        let fd = try directory(path); defer { close(fd) }
        let store = try VPNUpdateBrokerStatusStore(trustedDirectoryDescriptor: fd)
        VPNUpdateBrokerStatusStore.checkpoint = { point in
            if point == checkpoint { throw Injected.crash }
        }
        if checkpoint == "before-rename" {
            do {
                _ = try store.publish(state: .accepted, fromSequence: 8,
                                      toSequence: 9, expectedRevision: 0)
                throw NSError(domain: "broker-status", code: 3)
            } catch Injected.crash { }
            VPNUpdateBrokerStatusStore.checkpoint = nil
            let absent = try store.load()
            try require(absent == .idle)
        } else {
            try rejects(.commitUncertain) {
                _ = try store.publish(state: .accepted, fromSequence: 8,
                                      toSequence: 9, expectedRevision: 0)
            }
            VPNUpdateBrokerStatusStore.checkpoint = nil
        }
        let retried = try store.publish(state: .accepted, fromSequence: 8,
                                        toSequence: 9, expectedRevision: 0)
        try require(retried.revision == 1)
        let advanced = try store.publish(state: .checking, fromSequence: 8,
                                         toSequence: 9, expectedRevision: 1)
        try require(advanced.revision == 2)
    }

    static func hostile(_ path: String, kind: String) throws {
        let fd = try directory(path); defer { close(fd) }
        let store = try VPNUpdateBrokerStatusStore(trustedDirectoryDescriptor: fd)
        _ = try store.publish(state: .accepted, fromSequence: 1, toSequence: 2)
        let name = VPNUpdateBrokerStatusStore.fileName
        switch kind {
        case "corrupt":
            let file = openat(fd, name, O_RDWR | O_NOFOLLOW | O_CLOEXEC)
            guard file >= 0 else { throw Injected.crash }
            var byte: UInt8 = 0xff
            guard pwrite(file, &byte, 1, 20) == 1 else { throw Injected.crash }
            close(file)
        case "extra":
            let file = openat(fd, name, O_WRONLY | O_APPEND | O_NOFOLLOW | O_CLOEXEC)
            guard file >= 0 else { throw Injected.crash }
            var byte: UInt8 = 0
            guard Darwin.write(file, &byte, 1) == 1 else { throw Injected.crash }
            close(file)
        case "writable":
            guard fchmodat(fd, name, 0o660, 0) == 0 else { throw Injected.crash }
        case "linked":
            guard linkat(fd, name, fd, "status-hardlink", 0) == 0 else {
                throw Injected.crash
            }
        case "symlink":
            guard unlinkat(fd, name, 0) == 0,
                  symlinkat("status-hardlink", fd, name) == 0 else {
                throw Injected.crash
            }
        default: throw Injected.crash
        }
        try rejects(kind == "corrupt" || kind == "extra" ? .invalidState : .unsafeStorage) {
            _ = try store.load()
        }
    }

    static func unsafeDirectory(_ path: String) throws {
        let fd = try directory(path); defer { close(fd) }
        guard fchmod(fd, 0o755) == 0 else { throw Injected.crash }
        try rejects(.unsafeStorage) {
            _ = try VPNUpdateBrokerStatusStore(trustedDirectoryDescriptor: fd)
        }
    }

    static func main() throws {
        guard CommandLine.arguments.count == 3 else { exit(64) }
        let test = CommandLine.arguments[1], path = CommandLine.arguments[2]
        switch test {
        case "roundtrip": try roundTrip(path)
        case "before-rename", "after-rename": try crash(path, checkpoint: test)
        case "corrupt", "extra", "writable", "linked", "symlink":
            try hostile(path, kind: test)
        case "unsafe-directory": try unsafeDirectory(path)
        default: exit(64)
        }
        print("\(test) checks passed")
    }
}
