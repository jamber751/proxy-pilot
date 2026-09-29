import Darwin
import Foundation

enum VPNRouteJournalError: Error, Equatable {
    case unsafeStorage, missing, alreadyExists, invalidState, stale, writeFailed
}

/// Typed output of a future kernel-route inspection. It cannot be constructed
/// from IPC strings; the interface name is resolved from its kernel index.
struct VPNRouteKernelEvidence {
    let family: VPNRouteAddressFamily
    let gatewayBytes: [UInt8]?
    let interfaceIndex: UInt32
    let interfaceName: String
    let flags: UInt32

    init(gateway: in_addr?, interfaceIndex: UInt32, flags: UInt32) throws {
        try self.init(family: .ipv4, gatewayBytes: gateway.map(Self.bytes),
                      interfaceIndex: interfaceIndex, flags: flags)
    }

    init(gateway: in6_addr?, interfaceIndex: UInt32, flags: UInt32) throws {
        try self.init(family: .ipv6, gatewayBytes: gateway.map(Self.bytes),
                      interfaceIndex: interfaceIndex, flags: flags)
    }

    private init(family: VPNRouteAddressFamily, gatewayBytes: [UInt8]?,
                 interfaceIndex: UInt32, flags: UInt32) throws {
        let size = family == .ipv4 ? 4 : 16
        guard (gatewayBytes == nil || gatewayBytes?.count == size),
              interfaceIndex > 0, flags != 0 else {
            throw VPNRoutePlanError.invalidKernelEvidence
        }
        var name = [CChar](repeating: 0, count: Int(IFNAMSIZ))
        guard if_indextoname(interfaceIndex, &name) != nil else {
            throw VPNRoutePlanError.invalidKernelEvidence
        }
        self.family = family; self.gatewayBytes = gatewayBytes
        self.interfaceIndex = interfaceIndex; interfaceName = String(cString: name)
        self.flags = flags
    }

    private static func bytes<T>(_ value: T) -> [UInt8] {
        var copy = value
        return withUnsafeBytes(of: &copy) { Array($0) }
    }
}

/// Exact identity to compare with a later kernel snapshot before deletion. It
/// is evidence owned by this journal, not evidence that the route is present.
struct VPNOwnedRouteIdentity: Codable, Equatable, Comparable {
    let role: VPNPlannedRouteRole
    let destination: VPNRoutePrefix
    let gatewayBytes: [UInt8]?
    let interfaceIndex: UInt32
    let interfaceName: String
    let flags: UInt32

    init(planned: VPNPlannedRoute, evidence: VPNRouteKernelEvidence) throws {
        try planned.validate()
        guard planned.destination.family == evidence.family else {
            throw VPNRoutePlanError.invalidKernelEvidence
        }
        role = planned.role; destination = planned.destination
        gatewayBytes = evidence.gatewayBytes; interfaceIndex = evidence.interfaceIndex
        interfaceName = evidence.interfaceName; flags = evidence.flags
        if role == .peerBypass {
            guard planned.physicalGatewayBytes == gatewayBytes,
                  planned.interfaceIndex == interfaceIndex,
                  planned.interfaceName == interfaceName else {
                throw VPNRoutePlanError.invalidKernelEvidence
            }
        }
        try validate()
    }

    static func < (left: Self, right: Self) -> Bool {
        if left.role.rawValue != right.role.rawValue { return left.role.rawValue < right.role.rawValue }
        if left.destination != right.destination { return left.destination < right.destination }
        if left.interfaceIndex != right.interfaceIndex { return left.interfaceIndex < right.interfaceIndex }
        if left.gatewayBytes != right.gatewayBytes {
            return (left.gatewayBytes ?? []).lexicographicallyPrecedes(right.gatewayBytes ?? [])
        }
        return left.flags < right.flags
    }

    func validate() throws {
        try destination.validate()
        let size = destination.family == .ipv4 ? 4 : 16
        guard gatewayBytes == nil || gatewayBytes?.count == size,
              interfaceIndex > 0, !interfaceName.isEmpty,
              interfaceName.utf8.count < IFNAMSIZ,
              !interfaceName.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains),
              flags != 0 else { throw VPNRoutePlanError.invalidKernelEvidence }
    }
}

enum VPNRouteJournalPhase: String, Codable {
    case planned, installing, applied, removing, retired
}

enum VPNRouteJournalAction: String, Codable { case install, remove }

struct VPNRouteJournalOperation: Codable, Equatable {
    let action: VPNRouteJournalAction
    let entry: VPNOwnedRouteIdentity
}

/// Durable ownership ledger only. `applied` means a future mutator recorded an
/// exact compare-before-delete identity after its own verification; this type
/// itself never executes or observes a route command.
struct VPNRouteJournalSnapshot: Codable, Equatable {
    static let schema = 1
    let schemaVersion: Int
    let plan: VPNRoutePlan
    let phase: VPNRouteJournalPhase
    let applied: [VPNOwnedRouteIdentity]
    let operation: VPNRouteJournalOperation?

    func validate() throws {
        guard schemaVersion == Self.schema else { throw VPNRouteJournalError.invalidState }
        try plan.validate()
        guard applied == applied.sorted(), Set(applied.map(Self.key)).count == applied.count else {
            throw VPNRouteJournalError.invalidState
        }
        for entry in applied { try Self.match(entry, plan: plan) }
        if let operation = operation { try Self.match(operation.entry, plan: plan) }
        switch phase {
        case .planned:
            guard applied.isEmpty, operation == nil else { throw VPNRouteJournalError.invalidState }
        case .installing:
            guard applied.count < plan.routes.count else { throw VPNRouteJournalError.invalidState }
            if let operation = operation {
                guard operation.action == .install,
                      !applied.contains(where: { Self.key($0) == Self.key(operation.entry) }) else {
                    throw VPNRouteJournalError.invalidState
                }
            }
        case .applied:
            guard applied.count == plan.routes.count, operation == nil else {
                throw VPNRouteJournalError.invalidState
            }
        case .removing:
            guard !applied.isEmpty else { throw VPNRouteJournalError.invalidState }
            if let operation = operation {
                guard operation.action == .remove, applied.contains(operation.entry) else {
                    throw VPNRouteJournalError.invalidState
                }
            }
        case .retired:
            guard applied.isEmpty, operation == nil else { throw VPNRouteJournalError.invalidState }
        }
    }

    fileprivate static func key(_ entry: VPNOwnedRouteIdentity) -> String {
        "\(entry.role.rawValue):\(entry.destination.family.rawValue):"
            + entry.destination.bytes.map { String(format: "%02x", $0) }.joined()
            + "/\(entry.destination.prefixLength)"
    }

    fileprivate static func key(_ route: VPNPlannedRoute) -> String {
        "\(route.role.rawValue):\(route.destination.family.rawValue):"
            + route.destination.bytes.map { String(format: "%02x", $0) }.joined()
            + "/\(route.destination.prefixLength)"
    }

    fileprivate static func match(_ entry: VPNOwnedRouteIdentity, plan: VPNRoutePlan) throws {
        try entry.validate()
        guard let planned = plan.routes.first(where: {
            $0.role == entry.role && $0.destination == entry.destination
        }) else { throw VPNRouteJournalError.invalidState }
        if entry.role == .peerBypass {
            guard planned.physicalGatewayBytes == entry.gatewayBytes,
                  planned.interfaceIndex == entry.interfaceIndex,
                  planned.interfaceName == entry.interfaceName else {
                throw VPNRouteJournalError.invalidState
            }
        }
    }
}

final class VPNRouteJournal {
    static let name = "route-journal.json"
    static let maximumBytes = 512 * 1024
    private var directory: Int32
    private let owner = geteuid()

    init(trustedDirectoryDescriptor: Int32) throws {
        directory = fcntl(trustedDirectoryDescriptor, F_DUPFD_CLOEXEC, 64)
        guard directory >= 0 else { throw VPNRouteJournalError.unsafeStorage }
        do { try checkDirectory() }
        catch { close(directory); directory = -1; throw error }
    }

    deinit { if directory >= 0 { close(directory) } }

    func load() throws -> VPNRouteJournalSnapshot {
        guard let data = try read() else { throw VPNRouteJournalError.missing }
        return try decode(data)
    }

    @discardableResult
    func create(_ plan: VPNRoutePlan) throws -> VPNRouteJournalSnapshot {
        try plan.validate()
        guard try read() == nil else { throw VPNRouteJournalError.alreadyExists }
        let value = VPNRouteJournalSnapshot(schemaVersion: 1, plan: plan, phase: .planned,
                                            applied: [], operation: nil)
        try write(value); return value
    }

    @discardableResult
    func beginInstall(_ entry: VPNOwnedRouteIdentity, generation: UInt64,
                      revision: UInt64) throws -> VPNRouteJournalSnapshot {
        let old = try bound(generation: generation, revision: revision)
        let installedKeys = Set(old.applied.map(VPNRouteJournalSnapshot.key))
        let expected = old.plan.routes.first {
            !installedKeys.contains(VPNRouteJournalSnapshot.key($0))
        }
        guard [.planned, .installing].contains(old.phase), old.operation == nil,
              expected?.role == entry.role, expected?.destination == entry.destination,
              !old.applied.contains(where: {
                  VPNRouteJournalSnapshot.key($0) == VPNRouteJournalSnapshot.key(entry)
              }) else { throw VPNRouteJournalError.invalidState }
        try VPNRouteJournalSnapshot.match(entry, plan: old.plan)
        let next = VPNRouteJournalSnapshot(schemaVersion: 1, plan: old.plan, phase: .installing,
            applied: old.applied, operation: VPNRouteJournalOperation(action: .install, entry: entry))
        try write(next); return next
    }

    /// Resolve only after comparing the exact in-flight identity with a trusted
    /// kernel snapshot. `present` is not derived or checked by this journal.
    @discardableResult
    func resolveInstall(_ entry: VPNOwnedRouteIdentity, present: Bool,
                        generation: UInt64, revision: UInt64) throws -> VPNRouteJournalSnapshot {
        let old = try bound(generation: generation, revision: revision)
        guard old.phase == .installing,
              old.operation == VPNRouteJournalOperation(action: .install, entry: entry) else {
            throw VPNRouteJournalError.stale
        }
        var entries = old.applied
        if present { entries.append(entry); entries.sort() }
        let phase: VPNRouteJournalPhase = entries.count == old.plan.routes.count ? .applied : .installing
        let next = VPNRouteJournalSnapshot(schemaVersion: 1, plan: old.plan, phase: phase,
                                           applied: entries, operation: nil)
        try write(next); return next
    }

    @discardableResult
    func beginRemove(_ entry: VPNOwnedRouteIdentity, generation: UInt64,
                     revision: UInt64) throws -> VPNRouteJournalSnapshot {
        let old = try bound(generation: generation, revision: revision)
        guard [.installing, .applied, .removing].contains(old.phase), old.operation == nil,
              old.applied.last == entry else { throw VPNRouteJournalError.invalidState }
        let next = VPNRouteJournalSnapshot(schemaVersion: 1, plan: old.plan, phase: .removing,
            applied: old.applied, operation: VPNRouteJournalOperation(action: .remove, entry: entry))
        try write(next); return next
    }

    /// A later remover must pass `present == false` only after exact comparison;
    /// a mismatched/foreign route remains owned in the ledger and is not erased.
    @discardableResult
    func resolveRemove(_ entry: VPNOwnedRouteIdentity, present: Bool,
                       generation: UInt64, revision: UInt64) throws -> VPNRouteJournalSnapshot {
        let old = try bound(generation: generation, revision: revision)
        guard old.phase == .removing,
              old.operation == VPNRouteJournalOperation(action: .remove, entry: entry) else {
            throw VPNRouteJournalError.stale
        }
        var entries = old.applied
        if !present { entries.removeAll { $0 == entry } }
        let phase: VPNRouteJournalPhase = entries.isEmpty ? .retired : .removing
        let next = VPNRouteJournalSnapshot(schemaVersion: 1, plan: old.plan, phase: phase,
                                           applied: entries, operation: nil)
        try write(next); return next
    }

    private func bound(generation: UInt64, revision: UInt64) throws -> VPNRouteJournalSnapshot {
        let value = try load()
        guard generation > 0, revision > 0,
              value.plan.generation == generation, value.plan.revision == revision else {
            throw VPNRouteJournalError.stale
        }
        return value
    }

    private func decode(_ data: Data) throws -> VPNRouteJournalSnapshot {
        guard !data.isEmpty, data.count <= Self.maximumBytes,
              let value = try? JSONDecoder().decode(VPNRouteJournalSnapshot.self, from: data) else {
            throw VPNRouteJournalError.invalidState
        }
        try value.validate()
        guard try encode(value) == data else { throw VPNRouteJournalError.invalidState }
        return value
    }

    private func encode(_ value: VPNRouteJournalSnapshot) throws -> Data {
        try value.validate()
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
        let data = try encoder.encode(value)
        guard data.count <= Self.maximumBytes else { throw VPNRouteJournalError.invalidState }
        return data
    }

    private func read() throws -> Data? {
        try checkDirectory()
        let file = openat(directory, Self.name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard file >= 0 else {
            guard errno == ENOENT else { throw VPNRouteJournalError.unsafeStorage }
            return nil
        }
        defer { close(file) }
        try checkFile(file)
        var data = Data(), buffer = [UInt8](repeating: 0, count: 4096)
        while true {
            let count = Darwin.read(file, &buffer, buffer.count)
            if count < 0, errno == EINTR { continue }
            guard count >= 0, data.count + max(0, count) <= Self.maximumBytes else {
                throw VPNRouteJournalError.invalidState
            }
            if count == 0 { return data }
            data.append(contentsOf: buffer.prefix(count))
        }
    }

    private func write(_ value: VPNRouteJournalSnapshot) throws {
        let data = try encode(value)
        let temporary = ".route-journal-\(UUID().uuidString).tmp"
        let file = openat(directory, temporary,
                          O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard file >= 0 else { throw VPNRouteJournalError.writeFailed }
        defer { close(file); unlinkat(directory, temporary, 0) }
        try checkFile(file)
        try data.withUnsafeBytes { bytes in
            var offset = 0
            while offset < bytes.count {
                let count = Darwin.write(file, bytes.baseAddress!.advanced(by: offset), bytes.count - offset)
                if count < 0, errno == EINTR { continue }
                guard count > 0 else { throw VPNRouteJournalError.writeFailed }
                offset += count
            }
        }
        guard fsync(file) == 0,
              renameat(directory, temporary, directory, Self.name) == 0,
              fsync(directory) == 0 else { throw VPNRouteJournalError.writeFailed }
    }

    private func checkDirectory() throws {
        var info = stat()
        guard directory >= 0, geteuid() == owner,
              fstat(directory, &info) == 0, info.st_mode & S_IFMT == S_IFDIR,
              info.st_uid == owner, info.st_nlink > 0,
              info.st_mode & 0o7777 == 0o700 else {
            throw VPNRouteJournalError.unsafeStorage
        }
    }

    private func checkFile(_ file: Int32) throws {
        var info = stat()
        guard fstat(file, &info) == 0, info.st_mode & S_IFMT == S_IFREG,
              info.st_uid == owner, info.st_nlink == 1,
              info.st_mode & 0o7777 == 0o600 else {
            throw VPNRouteJournalError.unsafeStorage
        }
    }
}
