import Foundation

/// Bounded positive and SOA-backed negative subset. EDNS/DNSSEC, additional
/// data and SOA+NS forms remain unsupported. Transport failures are never NXDOMAIN.
/// Negative semantics: https://www.rfc-editor.org/rfc/rfc2308 §§2,3,5.
/// Wire grammar: RFC 1035 §§4.1, 4.1.4; CNAME exclusivity: RFC 2181 §10.1.
/// https://www.rfc-editor.org/rfc/rfc1035 https://www.rfc-editor.org/rfc/rfc2181
/// Pure/inert: no resolver, socket, route mutation, or runtime factory.
enum VPNDNSAnswerError: Error, Equatable {
    case malformed, capacity, questionMismatch, unsupported, unsupportedNegative
    case provenance, stale, permit, checkpoint, outputAlreadyIssued
}

enum VPNDNSQuestionType: UInt16 { case a = 1, aaaa = 28 }

/// Sealed proof of an actual original client query, not reconstructed metadata.
/// Only the bounded query decoder below can construct this value. Exact original
/// question bytes retain client spelling and QTYPE/QCLASS. This is relay echo
/// behavior, not validation of an upstream case-randomization challenge.
struct VPNDNSClientQuestion: Equatable {
    let resource: VPNResource
    let transactionID: UInt16
    let type: VPNDNSQuestionType
    let recursionDesired: Bool
    fileprivate let questionBytes: Data

    fileprivate init(resource: VPNResource, transactionID: UInt16, type: VPNDNSQuestionType,
                     recursionDesired: Bool, questionBytes: Data) {
        self.resource = resource; self.transactionID = transactionID; self.type = type
        self.recursionDesired = recursionDesired; self.questionBytes = questionBytes
    }
}

struct VPNDNSAnswerRequest: Equatable {
    let identifier: UUID
    let clientQuestion: VPNDNSClientQuestion
    let generation: UInt64
    let revision: UInt64
    let upstreamTransactionID: UInt16
    var resource: VPNResource { clientQuestion.resource }
    var transactionID: UInt16 { clientQuestion.transactionID }
    var type: VPNDNSQuestionType { clientQuestion.type }
    /// Absolute monotonic nanoseconds; caller's original budget, never reset.
    let deadline: UInt64

    init(clientQuestion: VPNDNSClientQuestion, generation: UInt64, revision: UInt64,
         upstreamTransactionID: UInt16, deadline: UInt64) throws {
        guard generation > 0, revision > 0, deadline > 0 else { throw VPNDNSAnswerError.provenance }
        identifier = UUID(); self.clientQuestion = clientQuestion; self.generation = generation
        self.revision = revision; self.upstreamTransactionID = upstreamTransactionID; self.deadline = deadline
    }

    /// A standard one-question query only; no unvalidated client flag/section is
    /// copied upstream. Endpoint binding and unique live ID allocation are the
    /// future transport owner's responsibility, not proven by this pure encoder.
    func upstreamQuery() -> Data {
        var bytes = [UInt8(upstreamTransactionID >> 8), UInt8(upstreamTransactionID & 255)]
        bytes += [clientQuestion.recursionDesired ? 1 : 0, 0, 0, 1, 0, 0, 0, 0, 0, 0]
        return Data(bytes) + clientQuestion.questionBytes
    }
}

/// Binary DNS labels, including root and mailbox labels containing literal dots.
/// No lossy joined string/UTF-8 conversion is used for SOA RDATA names.
struct VPNDNSWireName: Equatable {
    let labels: [Data]
    fileprivate init(labels: [Data]) { self.labels = labels }
    fileprivate var encoded: [UInt8] {
        labels.flatMap { [UInt8($0.count)] + $0 } + [0]
    }
}

enum VPNDNSAnswerOutcome: Equatable {
    case positive, nxDomain, noData, upstreamError(UInt8)
    fileprivate var rcode: UInt8 {
        switch self { case .nxDomain: return 3; case .upstreamError(let code): return code; default: return 0 }
    }
}

/// IN class only. NXDOMAIN targets the terminal canonical name, never its aliases;
/// NODATA additionally binds QTYPE. A key is not permission to remove IP fences.
enum VPNDNSNegativeCacheKey: Equatable {
    case nxDomain(terminal: String)
    case noData(terminal: String, type: VPNDNSQuestionType)
}
struct VPNDNSNegativeCacheDirective: Equatable {
    /// Scope metadata to this corporate origin/resource/generation/revision;
    /// this is not a global negative-cache grant for unselected clients.
    let request: VPNDNSAnswerRequest
    let key: VPNDNSNegativeCacheKey
    let remainingTTL: UInt32
    /// Original monotonic SOA/chain expiry, never access-time + fresh TTL.
    let expiresAt: UInt64
}

struct VPNDNSValidatedAnswer: Equatable {
    struct Record: Equatable {
        let owner: String
        let type: UInt16
        let ttl: UInt32
        let alias: String?
        let address: VPNRoutePrefix?
    }
    /// Structural evidence from the configured resolver, not authenticated denial.
    struct SOA: Equatable {
        let owner: String
        let nameserver: VPNDNSWireName
        let mailbox: VPNDNSWireName
        let serial: UInt32
        let refresh: UInt32
        let retry: UInt32
        let expire: UInt32
        let minimum: UInt32
        let ttl: UInt32
        var negativeTTL: UInt32 { min(ttl, minimum) }
    }
    let outcome: VPNDNSAnswerOutcome
    let soa: SOA?
    let identifier: UUID
    // Caller must source wire from the mandatory bound corporate transport.
    // Parsing alone authenticates neither upstream endpoint nor OS DNS selection.
    let request: VPNDNSAnswerRequest
    let receivedAt: UInt64
    let records: [Record]
    let canonicalChain: [String]
    let addresses: [VPNRoutePrefix]
    let minimumTTL: UInt32
    fileprivate init(identifier: UUID, request: VPNDNSAnswerRequest, receivedAt: UInt64,
                     records: [Record], canonicalChain: [String], addresses: [VPNRoutePrefix],
                     minimumTTL: UInt32, outcome: VPNDNSAnswerOutcome = .positive, soa: SOA? = nil) {
        self.identifier = identifier; self.request = request; self.receivedAt = receivedAt
        self.records = records; self.canonicalChain = canonicalChain; self.addresses = addresses
        self.minimumTTL = minimumTTL; self.outcome = outcome; self.soa = soa
    }

    /// No actual cache exists here. TTL0/error yields no caching directive. The
    /// lifetime is never restarted by re-encoding or obtaining this metadata.
    func negativeCacheDirective(at now: UInt64) throws -> VPNDNSNegativeCacheDirective? {
        let ttl = try remainingTTL(at: now)
        guard ttl > 0 else { return nil }
        let key: VPNDNSNegativeCacheKey
        switch outcome {
        case .nxDomain: key = .nxDomain(terminal: canonicalChain.last!)
        case .noData: key = .noData(terminal: canonicalChain.last!, type: request.type)
        default: return nil
        }
        let (expiry, overflow) = receivedAt.addingReportingOverflow(UInt64(minimumTTL) * 1_000_000_000)
        guard !overflow else { throw VPNDNSAnswerError.stale }
        return VPNDNSNegativeCacheDirective(request: request, key: key, remainingTTL: ttl, expiresAt: expiry)
    }

    private func remainingTTL(at now: UInt64) throws -> UInt32 {
        try checkTime(now)
        let elapsed = now - receivedAt
        let age = elapsed / 1_000_000_000 + (elapsed % 1_000_000_000 == 0 ? 0 : 1)
        return UInt32(UInt64(minimumTTL) > age ? UInt64(minimumTTL) - age : 0)
    }

    func checkTime(_ now: UInt64) throws {
        guard now >= receivedAt, now < request.deadline else { throw VPNDNSAnswerError.stale }
        // TTL 0 permits this bounded one-shot response but authorizes no cache.
        // A TTL0 prerequisite permits no caching, but must not hide expiry of
        // OTHER nonzero-lived records needed by this same one-shot answer.
        var requiredLifetimes = records.map(\.ttl).filter { $0 > 0 }
        if let soa = soa, soa.negativeTTL > 0 { requiredLifetimes.append(soa.negativeTTL) }
        if let lifetime = requiredLifetimes.min(), (now - receivedAt) / 1_000_000_000 >= UInt64(lifetime) {
            throw VPNDNSAnswerError.stale
        }
    }

    /// Fresh canonical bytes, never unchecked upstream bytes. No AD/RA/AA claim.
    /// TTL age is rounded UP to avoid extending upstream lifetime by fractions.
    func encoded(at now: UInt64) throws -> Data {
        let ttl = try remainingTTL(at: now)
        var bytes = [UInt8]()
        func word(_ value: UInt16) { bytes += [UInt8(value >> 8), UInt8(value & 255)] }
        func dword(_ value: UInt32) {
            bytes += [UInt8(value >> 24), UInt8((value >> 16) & 255), UInt8((value >> 8) & 255), UInt8(value & 255)]
        }
        func name(_ value: String) {
            for label in value.split(separator: ".") { bytes.append(UInt8(label.utf8.count)); bytes += label.utf8 }
            bytes.append(0)
        }
        word(request.transactionID); word(0x8000 | (request.clientQuestion.recursionDesired ? 0x0100 : 0) | UInt16(outcome.rcode))
        word(1); word(UInt16(records.count)); word(soa == nil ? 0 : 1); word(0)
        bytes += request.clientQuestion.questionBytes
        for record in records {
            name(record.owner); word(record.type); word(1)
            dword(ttl)
            if let alias = record.alias {
                word(UInt16(alias.utf8.count + 2)); name(alias)
            } else if let address = record.address {
                word(UInt16(address.bytes.count)); bytes += address.bytes
            } else { throw VPNDNSAnswerError.malformed }
        }
        if let soa = soa {
            name(soa.owner); word(6); word(1); dword(ttl)
            word(UInt16(soa.nameserver.encoded.count + soa.mailbox.encoded.count + 20))
            bytes += soa.nameserver.encoded; bytes += soa.mailbox.encoded
            for value in [soa.serial, soa.refresh, soa.retry, soa.expire, soa.minimum] { dword(value) }
        }
        guard bytes.count <= 65535 else { throw VPNDNSAnswerError.capacity }
        return Data(bytes)
    }
}

enum VPNDNSAnswerCodec {
    static let maximumRecords = 128
    static let maximumAliases = 16
    static let maximumTTL: UInt32 = 86400

    /// Initial supported client grammar: standard uncompressed single IN A/AAAA
    /// question, RD only, no answer/authority/additional data. EDNS, CD/DNSSEC and
    /// other query operations are explicitly unsupported, not converted to errors
    /// on the wire. A resolver suffix/descendant is never an exact host grant.
    static func clientQuestion(_ wire: Data, resource: VPNResource) throws -> VPNDNSClientQuestion {
        try resource.validate()
        guard resource.kind == .domain else { throw VPNDNSAnswerError.provenance }
        guard wire.count >= 12, wire.count <= 271 else { throw VPNDNSAnswerError.capacity }
        var reader = Reader(bytes: Array(wire))
        let identifier = try reader.word(), flags = try reader.word()
        guard flags & 0xfeff == 0 else { throw VPNDNSAnswerError.unsupported }
        guard try reader.word() == 1 else { throw VPNDNSAnswerError.questionMismatch }
        guard try reader.word() == 0, try reader.word() == 0, try reader.word() == 0 else {
            throw VPNDNSAnswerError.unsupported
        }
        guard try reader.name() == resource.address else { throw VPNDNSAnswerError.questionMismatch }
        guard let type = VPNDNSQuestionType(rawValue: try reader.word()), try reader.word() == 1 else {
            throw VPNDNSAnswerError.unsupported
        }
        guard !reader.usedCompression, reader.offset == reader.bytes.count else { throw VPNDNSAnswerError.malformed }
        return VPNDNSClientQuestion(resource: resource, transactionID: identifier, type: type,
                                    recursionDesired: flags & 0x0100 != 0, questionBytes: Data(wire.dropFirst(12)))
    }

    static func decode(_ wire: Data, request: VPNDNSAnswerRequest,
                       receivedAt: UInt64) throws -> VPNDNSValidatedAnswer {
        guard wire.count >= 12, wire.count <= 65535 else { throw VPNDNSAnswerError.capacity }
        guard receivedAt < request.deadline else { throw VPNDNSAnswerError.stale }
        var reader = Reader(bytes: Array(wire))
        guard try reader.word() == request.upstreamTransactionID else { throw VPNDNSAnswerError.questionMismatch }
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
        guard count <= maximumRecords else { throw VPNDNSAnswerError.capacity }
        guard authority <= 1, additional == 0 else { throw VPNDNSAnswerError.unsupported }
        if code != 0 && code != 3 {
            // Only explicit known query errors in the initial profile, and only
            // after validating the COMPLETE empty-section grammar and tail.
            guard [1,2,4,5].contains(code), count == 0, authority == 0,
                  reader.offset == reader.bytes.count else { throw VPNDNSAnswerError.unsupported }
            return VPNDNSValidatedAnswer(identifier: UUID(), request: request, receivedAt: receivedAt,
                records: [], canonicalChain: [question], addresses: [], minimumTTL: 0, outcome: .upstreamError(code))
        }
        var records = [VPNDNSValidatedAnswer.Record]()
        for _ in 0..<count {
            let owner = try reader.name(), type = try reader.word(), cls = try reader.word()
            let rawTTL = try reader.dword()
            // RFC 2181 §8: the high bit makes a received TTL zero, not huge.
            let ttl = normalizedTTL(rawTTL)
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
        var soa: VPNDNSValidatedAnswer.SOA?
        if authority == 1 {
            let owner = try reader.name(allowRoot: true)
            guard try reader.word() == 6, try reader.word() == 1 else { throw VPNDNSAnswerError.unsupported }
            let ttl = normalizedTTL(try reader.dword()), length = Int(try reader.word())
            guard reader.offset + length <= reader.bytes.count else { throw VPNDNSAnswerError.malformed }
            let end = reader.offset + length
            let nameserver = try reader.wireName(limit: end), mailbox = try reader.wireName(limit: end)
            guard reader.offset + 20 == end else { throw VPNDNSAnswerError.malformed }
            soa = try .init(owner: owner, nameserver: nameserver, mailbox: mailbox,
                serial: reader.dword(), refresh: reader.dword(), retry: reader.dword(),
                expire: reader.dword(), minimum: reader.dword(), ttl: ttl)
        }
        guard reader.offset == reader.bytes.count else { throw VPNDNSAnswerError.malformed }
        var chain = [question], consumed = Set<Int>(), canonical = [VPNDNSValidatedAnswer.Record]()
        while true {
            let owner = chain.last!
            let indices = records.indices.filter { records[$0].owner == owner }
            if indices.isEmpty { break }
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
        guard Set(addresses.map(\.canonical)).count == addresses.count else { throw VPNDNSAnswerError.provenance }
        if !addresses.isEmpty {
            guard code == 0, soa == nil else { throw VPNDNSAnswerError.provenance }
            return VPNDNSValidatedAnswer(identifier: UUID(), request: request, receivedAt: receivedAt,
                records: canonical, canonicalChain: chain, addresses: addresses, minimumTTL: canonical.map(\.ttl).min()!)
        }
        // No SOA: incomplete CNAME chain, uncacheable negative or referral remains
        // unsupported. No terminal requery or invented NODATA is performed here.
        guard let soa = soa else { throw VPNDNSAnswerError.unsupportedNegative }
        let terminal = chain.last!
        guard soa.owner.isEmpty || terminal == soa.owner || terminal.hasSuffix("." + soa.owner) else {
            throw VPNDNSAnswerError.provenance
        }
        let lifetime = min(soa.negativeTTL, canonical.map(\.ttl).min() ?? maximumTTL)
        return VPNDNSValidatedAnswer(identifier: UUID(), request: request, receivedAt: receivedAt,
            records: canonical, canonicalChain: chain, addresses: [], minimumTTL: lifetime,
            outcome: code == 3 ? .nxDomain : .noData, soa: soa)
    }

    private static func normalizedTTL(_ value: UInt32) -> UInt32 {
        value & 0x8000_0000 != 0 ? 0 : min(value, maximumTTL)
    }

    private struct Reader {
        let bytes: [UInt8]
        var offset = 0
        var usedCompression = false
        // Compression targets must be earlier recognized label boundaries, not
        // arbitrary header/address bytes that happen to resemble a name.
        var boundaries = Set<Int>()
        mutating func word() throws -> UInt16 {
            guard offset + 2 <= bytes.count else { throw VPNDNSAnswerError.malformed }
            defer { offset += 2 }; return UInt16(bytes[offset]) << 8 | UInt16(bytes[offset + 1])
        }
        mutating func dword() throws -> UInt32 { UInt32(try word()) << 16 | UInt32(try word()) }
        mutating func name(allowRoot: Bool = false) throws -> String {
            let decoded = try wireName()
            guard allowRoot || !decoded.labels.isEmpty else { throw VPNDNSAnswerError.unsupported }
            var labels = [String]()
            for label in decoded.labels {
                let value = Array(label)
                guard value.allSatisfy({ (65...90).contains($0) || (97...122).contains($0) || (48...57).contains($0) || $0 == 45 }),
                      value.first != 45, value.last != 45,
                      let ascii = String(bytes: value, encoding: .ascii) else { throw VPNDNSAnswerError.unsupported }
                labels.append(ascii.lowercased())
            }
            return labels.joined(separator: ".")
        }
        mutating func wireName(limit: Int? = nil) throws -> VPNDNSWireName {
            var cursor = offset, resumed: Int?, labels = [Data](), visited = Set<Int>(), jumps = 0, length = 1
            while true {
                let extent = resumed == nil ? (limit ?? bytes.count) : bytes.count
                guard cursor < extent, visited.insert(cursor).inserted else { throw VPNDNSAnswerError.malformed }
                let byte = bytes[cursor]
                if byte & 0xC0 == 0xC0 {
                    usedCompression = true
                    guard cursor + 1 < extent else { throw VPNDNSAnswerError.malformed }
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
                guard count <= 63, cursor + count <= extent else { throw VPNDNSAnswerError.malformed }
                labels.append(Data(bytes[cursor..<cursor + count]))
                length += count + 1
                guard length <= 255, labels.count <= 127 else { throw VPNDNSAnswerError.capacity }
                cursor += count
            }
            return VPNDNSWireName(labels: labels)
        }
    }
}
