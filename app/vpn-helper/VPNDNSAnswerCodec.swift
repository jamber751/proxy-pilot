import Foundation

/// Positive-answer subset only. Negative SOA caching, EDNS/DNSSEC, authority and
/// additional sections remain unsupported; failures are NOT synthesized NXDOMAIN.
/// Wire grammar: RFC 1035 §§4.1, 4.1.4; CNAME exclusivity: RFC 2181 §10.1.
/// https://www.rfc-editor.org/rfc/rfc1035 https://www.rfc-editor.org/rfc/rfc2181
/// Pure/inert: no resolver, socket, route mutation, or runtime factory.
enum VPNDNSAnswerError: Error, Equatable {
    case malformed, capacity, questionMismatch, unsupported, unsupportedNegative
    case upstreamFailure(UInt8), provenance, stale, permit, checkpoint, outputAlreadyIssued
}

enum VPNDNSQuestionType: UInt16 { case a = 1, aaaa = 28 }

struct VPNDNSAnswerRequest: Equatable {
    let identifier: UUID
    let resource: VPNResource
    let generation: UInt64
    let revision: UInt64
    let transactionID: UInt16
    let type: VPNDNSQuestionType
    /// Absolute monotonic nanoseconds; caller's original budget, never reset.
    let deadline: UInt64

    init(resource: VPNResource, generation: UInt64, revision: UInt64,
         transactionID: UInt16, type: VPNDNSQuestionType, deadline: UInt64) throws {
        try resource.validate()
        guard resource.kind == .domain, generation > 0, revision > 0, deadline > 0 else {
            throw VPNDNSAnswerError.provenance
        }
        identifier = UUID(); self.resource = resource; self.generation = generation
        self.revision = revision; self.transactionID = transactionID
        self.type = type; self.deadline = deadline
    }
}

struct VPNDNSValidatedAnswer: Equatable {
    struct Record: Equatable {
        let owner: String
        let type: UInt16
        let ttl: UInt32
        let alias: String?
        let address: VPNRoutePrefix?
    }
    let identifier: UUID
    // Caller must source wire from the mandatory bound corporate transport.
    // Parsing alone authenticates neither upstream endpoint nor OS DNS selection.
    let request: VPNDNSAnswerRequest
    let receivedAt: UInt64
    let records: [Record]
    let canonicalChain: [String]
    let addresses: [VPNRoutePrefix]
    let minimumTTL: UInt32
    fileprivate let recursionDesired: Bool

    fileprivate init(identifier: UUID, request: VPNDNSAnswerRequest, receivedAt: UInt64,
                     records: [Record], canonicalChain: [String], addresses: [VPNRoutePrefix],
                     minimumTTL: UInt32, recursionDesired: Bool) {
        self.identifier = identifier; self.request = request; self.receivedAt = receivedAt
        self.records = records; self.canonicalChain = canonicalChain; self.addresses = addresses
        self.minimumTTL = minimumTTL; self.recursionDesired = recursionDesired
    }

    func checkTime(_ now: UInt64) throws {
        guard now >= receivedAt, now < request.deadline else { throw VPNDNSAnswerError.stale }
        // TTL 0 permits this bounded one-shot response but authorizes no cache.
        if minimumTTL > 0, (now - receivedAt) / 1_000_000_000 >= UInt64(minimumTTL) {
            throw VPNDNSAnswerError.stale
        }
    }

    /// Fresh canonical bytes, never unchecked upstream bytes. No AD/RA/AA claim.
    /// TTL age is rounded UP to avoid extending upstream lifetime by fractions.
    func encoded(at now: UInt64) throws -> Data {
        try checkTime(now)
        let elapsed = now - receivedAt
        let age = elapsed / 1_000_000_000 + (elapsed % 1_000_000_000 == 0 ? 0 : 1)
        var bytes = [UInt8]()
        func word(_ value: UInt16) { bytes += [UInt8(value >> 8), UInt8(value & 255)] }
        func name(_ value: String) {
            for label in value.split(separator: ".") { bytes.append(UInt8(label.utf8.count)); bytes += label.utf8 }
            bytes.append(0)
        }
        word(request.transactionID); word(0x8000 | (recursionDesired ? 0x0100 : 0))
        word(1); word(UInt16(records.count)); word(0); word(0)
        name(request.resource.address); word(request.type.rawValue); word(1)
        for record in records {
            name(record.owner); word(record.type); word(1)
            let ttl = UInt32(UInt64(minimumTTL) > age ? UInt64(minimumTTL) - age : 0)
            bytes += [UInt8(ttl >> 24), UInt8((ttl >> 16) & 255), UInt8((ttl >> 8) & 255), UInt8(ttl & 255)]
            if let alias = record.alias {
                word(UInt16(alias.utf8.count + 2)); name(alias)
            } else if let address = record.address {
                word(UInt16(address.bytes.count)); bytes += address.bytes
            } else { throw VPNDNSAnswerError.malformed }
        }
        guard bytes.count <= 65535 else { throw VPNDNSAnswerError.capacity }
        return Data(bytes)
    }
}

enum VPNDNSAnswerCodec {
    static let maximumRecords = 128
    static let maximumAliases = 16
    static let maximumTTL: UInt32 = 86400

    static func decode(_ wire: Data, request: VPNDNSAnswerRequest,
                       receivedAt: UInt64) throws -> VPNDNSValidatedAnswer {
        guard wire.count >= 12, wire.count <= 65535 else { throw VPNDNSAnswerError.capacity }
        guard receivedAt < request.deadline else { throw VPNDNSAnswerError.stale }
        var reader = Reader(bytes: Array(wire))
        guard try reader.word() == request.transactionID else { throw VPNDNSAnswerError.questionMismatch }
        let flags = try reader.word()
        guard flags & 0x8000 != 0, flags & 0x7800 == 0, flags & 0x0200 == 0,
              flags & 0x0040 == 0 else { throw VPNDNSAnswerError.unsupported }
        let questions = try reader.word(), count = Int(try reader.word())
        let authority = try reader.word(), additional = try reader.word()
        guard questions == 1 else { throw VPNDNSAnswerError.questionMismatch }
        let question = try reader.name()
        guard question == request.resource.address, try reader.word() == request.type.rawValue,
              try reader.word() == 1 else { throw VPNDNSAnswerError.questionMismatch }
        let code = UInt8(flags & 15)
        // No unvalidated error is ever sent to the client by this subset.
        if code == 3 { throw VPNDNSAnswerError.unsupportedNegative }
        if code != 0 { throw VPNDNSAnswerError.upstreamFailure(code) }
        guard count > 0 else { throw VPNDNSAnswerError.unsupportedNegative }
        guard count <= maximumRecords else { throw VPNDNSAnswerError.capacity }
        guard authority == 0, additional == 0 else { throw VPNDNSAnswerError.unsupported }
        var records = [VPNDNSValidatedAnswer.Record]()
        for _ in 0..<count {
            let owner = try reader.name(), type = try reader.word(), cls = try reader.word()
            let rawTTL = try reader.dword()
            // RFC 2181 §8: the high bit makes a received TTL zero, not huge.
            let ttl = rawTTL & 0x8000_0000 != 0 ? 0 : min(rawTTL, maximumTTL)
            let size = Int(try reader.word())
            guard cls == 1, reader.offset + size <= reader.bytes.count else { throw VPNDNSAnswerError.malformed }
            let end = reader.offset + size
            if type == 5 {
                let alias = try reader.name()
                guard reader.offset == end else { throw VPNDNSAnswerError.malformed }
                records.append(.init(owner: owner, type: type, ttl: ttl, alias: alias, address: nil))
            } else if type == 1 || type == 28 {
                guard size == (type == 1 ? 4 : 16), type == request.type.rawValue else {
                    throw VPNDNSAnswerError.provenance
                }
                let address = try VPNRoutePrefix(hostBytes: Array(reader.bytes[reader.offset..<end]),
                                                family: type == 1 ? .ipv4 : .ipv6)
                reader.offset = end
                records.append(.init(owner: owner, type: type, ttl: ttl, alias: nil, address: address))
            } else { throw VPNDNSAnswerError.unsupported }
        }
        guard reader.offset == reader.bytes.count else { throw VPNDNSAnswerError.malformed }
        var chain = [question], consumed = Set<Int>(), canonical = [VPNDNSValidatedAnswer.Record]()
        while true {
            let owner = chain.last!
            let indices = records.indices.filter { records[$0].owner == owner }
            guard !indices.isEmpty else { throw VPNDNSAnswerError.provenance }
            let aliases = indices.filter { records[$0].alias != nil }
            if !aliases.isEmpty {
                guard aliases.count == 1, indices.count == 1,
                      chain.count <= maximumAliases, let target = records[aliases[0]].alias,
                      !chain.contains(target) else { throw VPNDNSAnswerError.provenance }
                consumed.insert(aliases[0]); canonical.append(records[aliases[0]]); chain.append(target)
            } else {
                for index in indices { consumed.insert(index); canonical.append(records[index]) }
                break
            }
        }
        guard consumed.count == records.count else { throw VPNDNSAnswerError.provenance }
        let addresses = canonical.compactMap(\.address).sorted()
        guard !addresses.isEmpty, Set(addresses.map(\.canonical)).count == addresses.count else {
            throw VPNDNSAnswerError.provenance
        }
        return VPNDNSValidatedAnswer(identifier: UUID(), request: request, receivedAt: receivedAt,
                                     records: canonical, canonicalChain: chain, addresses: addresses,
                                     minimumTTL: canonical.map(\.ttl).min()!, recursionDesired: flags & 0x0100 != 0)
    }

    private struct Reader {
        let bytes: [UInt8]
        var offset = 0
        // Compression targets must be earlier recognized label boundaries, not
        // arbitrary header/address bytes that happen to resemble a name.
        var boundaries = Set<Int>()
        mutating func word() throws -> UInt16 {
            guard offset + 2 <= bytes.count else { throw VPNDNSAnswerError.malformed }
            defer { offset += 2 }; return UInt16(bytes[offset]) << 8 | UInt16(bytes[offset + 1])
        }
        mutating func dword() throws -> UInt32 { UInt32(try word()) << 16 | UInt32(try word()) }
        mutating func name() throws -> String {
            var cursor = offset, resumed: Int?, labels = [String](), visited = Set<Int>(), jumps = 0, length = 1
            while true {
                guard cursor < bytes.count, visited.insert(cursor).inserted else { throw VPNDNSAnswerError.malformed }
                let byte = bytes[cursor]
                if byte & 0xC0 == 0xC0 {
                    guard cursor + 1 < bytes.count else { throw VPNDNSAnswerError.malformed }
                    let target = Int(byte & 63) << 8 | Int(bytes[cursor + 1])
                    guard target < cursor, boundaries.contains(target), jumps < 16 else { throw VPNDNSAnswerError.malformed }
                    boundaries.insert(cursor)
                    if resumed == nil { resumed = cursor + 2 }
                    jumps += 1; cursor = target; continue
                }
                guard byte & 0xC0 == 0 else { throw VPNDNSAnswerError.malformed }
                boundaries.insert(cursor); cursor += 1
                if byte == 0 { offset = resumed ?? cursor; break }
                let count = Int(byte)
                guard count <= 63, cursor + count <= bytes.count else { throw VPNDNSAnswerError.malformed }
                let value = Array(bytes[cursor..<cursor + count])
                guard value.allSatisfy({ (65...90).contains($0) || (97...122).contains($0) || (48...57).contains($0) || $0 == 45 }),
                      value.first != 45, value.last != 45 else { throw VPNDNSAnswerError.unsupported }
                labels.append(String(bytes: value, encoding: .ascii)!.lowercased())
                length += count + 1
                guard length <= 255, labels.count <= 127 else { throw VPNDNSAnswerError.capacity }
                cursor += count
            }
            guard !labels.isEmpty else { throw VPNDNSAnswerError.unsupported }
            return labels.joined(separator: ".")
        }
    }
}
