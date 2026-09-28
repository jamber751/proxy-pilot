import Darwin
import Foundation

@main enum VPNUpdateBrokerDirectoryChecks {
    static func require(_ value: @autoclosure () -> Bool) throws {
        guard value() else { throw NSError(domain: "broker-directory", code: 1) }
    }

    static func expect(_ expected: VPNUpdateBrokerError,
                       _ work: () throws -> Void) throws {
        do {
            try work()
            throw NSError(domain: "broker-directory", code: 2)
        } catch let error as VPNUpdateBrokerError {
            switch (expected, error) {
            case (.malformedRequest, .malformedRequest),
                 (.missingDirectoryDescriptor, .missingDirectoryDescriptor),
                 (.extraDirectoryDescriptor, .extraDirectoryDescriptor),
                 (.unsafeDirectory, .unsafeDirectory),
                 (.unexpectedSibling, .unexpectedSibling),
                 (.invalidLayout, .invalidLayout): return
            default: throw NSError(domain: "broker-directory", code: 3)
            }
        }
    }

    static func main() throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("pp-broker-dir-\(UUID().uuidString)")
        try FileManager.default.createDirectory(
            at: root, withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: root) }
        let app = root.appendingPathComponent("ProxyPilot.app")
        try FileManager.default.createDirectory(
            at: app, withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700])
        for name in VPNUpdateBroker.fixedLayout where name != "ProxyPilot.app" {
            let path = root.appendingPathComponent(name).path
            guard FileManager.default.createFile(
                atPath: path, contents: Data([0x01]),
                attributes: [.posixPermissions: 0o600]) else {
                throw NSError(domain: "broker-directory", code: 4)
            }
        }
        let directory = open(root.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        try require(directory >= 0)
        defer { close(directory) }
        let submit = VPNUpdateBrokerProtocol.encode(
            try .submit(expectedFromSequence: 41))
        let decoded = try VPNUpdateBroker.validateSubmission(
            requestBytes: submit, directoryDescriptors: [directory])
        let expected = try VPNUpdateBrokerRequest.submit(expectedFromSequence: 41)
        try require(decoded == expected)

        try expect(.missingDirectoryDescriptor) {
            _ = try VPNUpdateBroker.validateSubmission(
                requestBytes: submit, directoryDescriptors: [])
        }
        try expect(.extraDirectoryDescriptor) {
            _ = try VPNUpdateBroker.validateSubmission(
                requestBytes: submit, directoryDescriptors: [directory, directory])
        }
        try expect(.malformedRequest) {
            _ = try VPNUpdateBroker.validateSubmission(
                requestBytes: VPNUpdateBrokerProtocol.encode(.status),
                directoryDescriptors: [directory])
        }

        let extra = root.appendingPathComponent("unexpected")
        _ = FileManager.default.createFile(atPath: extra.path, contents: Data([1]))
        try expect(.unexpectedSibling) {
            try VPNUpdateBroker.validateCandidateDirectory(directory)
        }
        try FileManager.default.removeItem(at: extra)

        let helper = root.appendingPathComponent("vpn-helper")
        try FileManager.default.removeItem(at: helper)
        try FileManager.default.createSymbolicLink(
            at: helper, withDestinationURL: root.appendingPathComponent("vpn-engine"))
        try expect(.invalidLayout) {
            try VPNUpdateBroker.validateCandidateDirectory(directory)
        }
        try FileManager.default.removeItem(at: helper)
        _ = FileManager.default.createFile(
            atPath: helper.path, contents: Data([1]),
            attributes: [.posixPermissions: 0o600])

        try FileManager.default.setAttributes(
            [.posixPermissions: 0o777], ofItemAtPath: root.path)
        try expect(.unsafeDirectory) {
            try VPNUpdateBroker.validateCandidateDirectory(directory)
        }
        print("broker directory checks passed")
    }
}
