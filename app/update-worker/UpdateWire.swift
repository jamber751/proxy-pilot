import Foundation

// This channel carries updater UI state only. It is NOT a VPN authorization
// channel: no paths, commands, credentials, profiles or helper requests belong here.
struct UpdateSnapshot: Codable, Equatable {
    let canCheck: Bool
    let automatic: Bool
    let inProgress: Bool
    let availableVersion: String?
    let jointUpdate: Bool
    let jointReleaseID: String?

    init(canCheck: Bool, automatic: Bool, inProgress: Bool,
         availableVersion: String?, jointUpdate: Bool,
         jointReleaseID: String? = nil) {
        self.canCheck = canCheck
        self.automatic = automatic
        self.inProgress = inProgress
        self.availableVersion = availableVersion
        self.jointUpdate = jointUpdate
        self.jointReleaseID = jointReleaseID
    }
}

enum UpdateMessage: Equatable {
    case check, automatic(Bool), resume(UUID), armJointRelaunch(UUID)
    case state(UpdateSnapshot), present, aborted, prepare(UUID), jointRelaunchArmed(UUID), failed

    var isCommand: Bool {
        switch self {
        case .check, .automatic, .resume, .armJointRelaunch: return true
        default: return false
        }
    }
}

enum UpdateWire {
    static let maximumPayload = 4096
    enum Failure: Error { case malformed, oversized }

    private struct Envelope: Codable {
        let version: Int
        let kind: String
        var enabled: Bool?
        var token: UUID?
        var state: UpdateSnapshot?
    }

    static func frame(_ message: UpdateMessage) throws -> Data {
        var envelope = Envelope(version: 1, kind: "")
        switch message {
        case .check: envelope = Envelope(version: 1, kind: "check")
        case .automatic(let enabled): envelope = Envelope(version: 1, kind: "automatic", enabled: enabled)
        case .resume(let token): envelope = Envelope(version: 1, kind: "resume", token: token)
        case .armJointRelaunch(let token): envelope = Envelope(version: 1, kind: "armJointRelaunch", token: token)
        case .state(let state): envelope = Envelope(version: 1, kind: "state", state: state)
        case .present: envelope = Envelope(version: 1, kind: "present")
        case .aborted: envelope = Envelope(version: 1, kind: "aborted")
        case .prepare(let token): envelope = Envelope(version: 1, kind: "prepare", token: token)
        case .jointRelaunchArmed(let token): envelope = Envelope(version: 1, kind: "jointRelaunchArmed", token: token)
        case .failed: envelope = Envelope(version: 1, kind: "failed")
        }
        let payload = try JSONEncoder().encode(envelope)
        _ = try decode(payload) // Apply the same bounds to outgoing state.
        let count = UInt32(payload.count)
        var data = Data([UInt8(count >> 24), UInt8((count >> 16) & 255), UInt8((count >> 8) & 255), UInt8(count & 255)])
        data.append(payload)
        return data
    }

    static func decode(_ data: Data) throws -> UpdateMessage {
        guard !data.isEmpty, data.count <= maximumPayload else { throw Failure.oversized }
        guard let fields = try JSONSerialization.jsonObject(with: data) as? [String: Any] else { throw Failure.malformed }
        let envelope = try JSONDecoder().decode(Envelope.self, from: data)
        guard envelope.version == 1 else { throw Failure.malformed }
        var keys: Set<String> = ["version", "kind"]
        let message: UpdateMessage
        switch envelope.kind {
        case "check": message = .check
        case "automatic":
            guard let enabled = envelope.enabled else { throw Failure.malformed }
            keys.insert("enabled"); message = .automatic(enabled)
        case "resume", "prepare", "armJointRelaunch", "jointRelaunchArmed":
            guard let token = envelope.token else { throw Failure.malformed }
            keys.insert("token")
            switch envelope.kind {
            case "resume": message = .resume(token)
            case "prepare": message = .prepare(token)
            case "armJointRelaunch": message = .armJointRelaunch(token)
            default: message = .jointRelaunchArmed(token)
            }
        case "state":
            guard let state = envelope.state, let values = fields["state"] as? [String: Any],
                  Set(values.keys).isSubset(of: ["canCheck", "automatic", "inProgress", "availableVersion", "jointUpdate", "jointReleaseID"]) else { throw Failure.malformed }
            if let version = state.availableVersion {
                guard !version.isEmpty, version.utf8.count <= 64,
                      !version.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) else { throw Failure.malformed }
            }
            if let release = state.jointReleaseID {
                guard Self.canonicalVersion(release) else { throw Failure.malformed }
            }
            guard state.jointUpdate == (state.jointReleaseID != nil) else {
                throw Failure.malformed
            }
            keys.insert("state"); message = .state(state)
        case "present": message = .present
        case "aborted": message = .aborted
        case "failed": message = .failed
        default: throw Failure.malformed
        }
        guard Set(fields.keys) == keys else { throw Failure.malformed }
        return message
    }

    private static func canonicalVersion(_ value: String) -> Bool {
        let parts = value.components(separatedBy: ".")
        guard parts.count == 3 else { return false }
        return parts.allSatisfy { part in
            !part.isEmpty && part.utf8.count <= 19
                && (part == "0" || !part.hasPrefix("0"))
                && part.utf8.allSatisfy { (48...57).contains($0) }
                && UInt64(part).map { $0 <= UInt64(Int64.max) } == true
        }
    }

    struct Decoder {
        private var buffer = Data()
        // Call with bounded chunks, draining complete frames after each chunk.
        mutating func append(_ chunk: Data) throws -> [UpdateMessage] {
            guard chunk.count <= maximumPayload, buffer.count + chunk.count <= maximumPayload * 2 + 4 else { throw Failure.oversized }
            buffer.append(chunk)
            var messages: [UpdateMessage] = []
            while buffer.count >= 4 {
                let size = buffer.prefix(4).reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
                guard size > 0, size <= maximumPayload else { throw Failure.oversized }
                let end = Int(size) + 4
                guard buffer.count >= end else { break }
                messages.append(try decode(Data(buffer.dropFirst(4).prefix(Int(size)))))
                buffer = Data(buffer.dropFirst(end))
            }
            return messages
        }
        var hasPartialFrame: Bool { !buffer.isEmpty }
    }
}
