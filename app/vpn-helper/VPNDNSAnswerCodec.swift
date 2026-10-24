import Foundation

/// Bounded positive/SOA-negative/EDNS0 DO0 subset. DNSSEC, non-OPT additional
/// data and SOA+NS remain unsupported. Transport failures are never NXDOMAIN.
/// EDNS transactions: https://www.rfc-editor.org/rfc/rfc6891 §§6,7.
/// Negative semantics: https://www.rfc-editor.org/rfc/rfc2308 §§2,3,5.
/// Wire grammar: RFC 1035 §§4.1, 4.1.4; CNAME exclusivity: RFC 2181 §10.1.
/// https://www.rfc-editor.org/rfc/rfc1035 https://www.rfc-editor.org/rfc/rfc2181
/// Pure/inert: no resolver, socket, route mutation, or runtime factory.
enum VPNDNSAnswerError: Error, Equatable {
    case malformed, capacity, questionMismatch, unsupported, unsupportedNegative
    case provenance, stale, permit, checkpoint, outputAlreadyIssued
    case unsupportedDNSSEC, unsupportedVersion(UInt8), unsupportedRCODE(UInt16)
}

enum VPNDNSQuestionType: UInt16 { case a = 1, aaaa = 28 }
/// Trusted listener metadata, not a transport chosen by bytes in the DNS query.
enum VPNDNSClientIngress: Equatable { case udp, tcp }
struct VPNDNSClientEDNS: Equatable {
    let version: UInt8
    let advertisedUDPPayload: UInt16
    fileprivate init(version: UInt8, advertisedUDPPayload: UInt16) {
        self.version = version; self.advertisedUDPPayload = advertisedUDPPayload
    }
}

/// Sealed proof of an actual original client query, not reconstructed metadata.
/// Only the bounded query decoder below can construct this value. Exact original
/// question bytes retain client spelling and QTYPE/QCLASS. This is relay echo
/// behavior, not validation of an upstream case-randomization challenge.
struct VPNDNSClientQuestion: Equatable {
    let resource: VPNResource
    let transactionID: UInt16
    let type: VPNDNSQuestionType
    let recursionDesired: Bool
    let ingress: VPNDNSClientIngress
    let edns: VPNDNSClientEDNS?
    /// Per-transaction implementation cap, not a path-MTU/no-fragmentation proof.
    var udpResponseLimit: Int {
        min(max(Int(edns?.advertisedUDPPayload ?? 512), 512), VPNDNSAnswerCodec.udpPayloadCap)
    }
    fileprivate let questionBytes: Data

    fileprivate init(resource: VPNResource, transactionID: UInt16, type: VPNDNSQuestionType,
                     recursionDesired: Bool, ingress: VPNDNSClientIngress,
                     edns: VPNDNSClientEDNS?, questionBytes: Data) {
        self.resource = resource; self.transactionID = transactionID; self.type = type
        self.recursionDesired = recursionDesired; self.ingress = ingress
        self.edns = edns; self.questionBytes = questionBytes
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
    /// Absolute continuous-clock time (including sleep); caller's original budget, never reset.
    let deadline: VPNDNSContinuousInstant

    init(clientQuestion: VPNDNSClientQuestion, generation: UInt64, revision: UInt64,
         upstreamTransactionID: UInt16, deadline: VPNDNSContinuousInstant) throws {
        guard generation > 0, revision > 0, deadline.nanoseconds > 0 else { throw VPNDNSAnswerError.provenance }
        identifier = UUID(); self.clientQuestion = clientQuestion; self.generation = generation
        self.revision = revision; self.upstreamTransactionID = upstreamTransactionID; self.deadline = deadline
    }

    /// A standard one-question query only; no unvalidated client flag/section is
    /// copied upstream. Endpoint binding and unique live ID allocation are the
    /// future transport owner's responsibility, not proven by this pure encoder.
    func upstreamQuery() throws -> Data {
        if let edns = clientQuestion.edns, edns.version != 0 { throw VPNDNSAnswerError.unsupportedVersion(edns.version) }
        var bytes = [UInt8(upstreamTransactionID >> 8), UInt8(upstreamTransactionID & 255)]
        bytes += [clientQuestion.recursionDesired ? 1 : 0, 0, 0, 1, 0, 0, 0, 0, 0, 0]
        var result = Data(bytes) + clientQuestion.questionBytes
        if clientQuestion.edns != nil {
            result[11] = 1
            result += VPNDNSAnswerCodec.optRecord(payload: UInt16(VPNDNSAnswerCodec.udpPayloadCap), rcode: 0)
        }
        return result
    }
    var upstreamUDPLimit: Int { clientQuestion.edns == nil ? 512 : VPNDNSAnswerCodec.udpPayloadCap }
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
    case positive, nxDomain, noData, upstreamError(UInt16), protocolError(VPNDNSClientProtocolError)
    fileprivate var rcode: UInt16 {
        switch self {
        case .nxDomain: return 3
        case .upstreamError(let code): return code
        case .protocolError(.badVersion): return 16
        default: return 0
        }
    }
}

enum VPNDNSClientProtocolError: Equatable { case badVersion }

/// Grammar/original-query receipt ONLY, not endpoint/route attestation. A future
/// coordinator must keep the SAME captured corporate server/binding, fresh full
/// authority and ORIGINAL deadline, allowing at most ONE TCP attempt. No default
/// resolver/EDNS downgrade/retry loop is provided here. Never an answer permit.
struct VPNDNSNeedsTCP: Equatable {
    enum Reason: Equatable { case truncated, oversizedUDP }
    let request: VPNDNSAnswerRequest
    let receivedAt: VPNDNSContinuousInstant
    let reason: Reason
    fileprivate init(request: VPNDNSAnswerRequest, receivedAt: VPNDNSContinuousInstant, reason: Reason) {
        self.request = request; self.receivedAt = receivedAt; self.reason = reason
    }
}
enum VPNDNSUpstreamInspection {
    case answer(VPNDNSValidatedAnswer)
    case needsTCP(VPNDNSNeedsTCP)
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
    /// Original continuous-clock SOA/chain expiry, never access-time + fresh TTL.
    let expiresAt: VPNDNSContinuousInstant
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
    let receivedAt: VPNDNSContinuousInstant
    let records: [Record]
    let canonicalChain: [String]
    let addresses: [VPNRoutePrefix]
    let minimumTTL: UInt32
    fileprivate init(identifier: UUID, request: VPNDNSAnswerRequest, receivedAt: VPNDNSContinuousInstant,
                     records: [Record], canonicalChain: [String], addresses: [VPNRoutePrefix],
                     minimumTTL: UInt32, outcome: VPNDNSAnswerOutcome = .positive, soa: SOA? = nil) {
        self.identifier = identifier; self.request = request; self.receivedAt = receivedAt
        self.records = records; self.canonicalChain = canonicalChain; self.addresses = addresses
        self.minimumTTL = minimumTTL; self.outcome = outcome; self.soa = soa
    }

    /// No actual cache exists here. TTL0/error yields no caching directive. The
    /// lifetime is never restarted by re-encoding or obtaining this metadata.
    func negativeCacheDirective(at now: VPNDNSContinuousInstant) throws -> VPNDNSNegativeCacheDirective? {
        let ttl = try remainingTTL(at: now)
        guard ttl > 0 else { return nil }
        let key: VPNDNSNegativeCacheKey
        switch outcome {
        case .nxDomain: key = .nxDomain(terminal: canonicalChain.last!)
        case .noData: key = .noData(terminal: canonicalChain.last!, type: request.type)
        default: return nil
        }
        let expiry: VPNDNSContinuousInstant
        do { expiry = try receivedAt.addingChecked(UInt64(minimumTTL) * 1_000_000_000) }
        catch { throw VPNDNSAnswerError.stale }
        return VPNDNSNegativeCacheDirective(request: request, key: key, remainingTTL: ttl, expiresAt: expiry)
    }

    private func remainingTTL(at now: VPNDNSContinuousInstant) throws -> UInt32 {
        try checkTime(now)
        let elapsed = try now.elapsed(since: receivedAt)
        let age = elapsed / 1_000_000_000 + (elapsed % 1_000_000_000 == 0 ? 0 : 1)
        return UInt32(UInt64(minimumTTL) > age ? UInt64(minimumTTL) - age : 0)
    }

    func checkTime(_ now: VPNDNSContinuousInstant) throws {
        guard now >= receivedAt, now < request.deadline else { throw VPNDNSAnswerError.stale }
        // TTL 0 permits this bounded one-shot response but authorizes no cache.
        // A TTL0 prerequisite permits no caching, but must not hide expiry of
        // OTHER nonzero-lived records needed by this same one-shot answer.
        var requiredLifetimes = records.map(\.ttl).filter { $0 > 0 }
        if let soa = soa, soa.negativeTTL > 0 { requiredLifetimes.append(soa.negativeTTL) }
        if let lifetime = requiredLifetimes.min(), (try now.elapsed(since: receivedAt)) / 1_000_000_000 >= UInt64(lifetime) {
            throw VPNDNSAnswerError.stale
        }
    }

    /// Fresh canonical bytes, never unchecked upstream bytes. No AD/RA/AA claim.
    /// TTL age is rounded UP to avoid extending upstream lifetime by fractions.
    func encoded(at now: VPNDNSContinuousInstant) throws -> Data {
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
        word(request.transactionID); word(0x8000 | (request.clientQuestion.recursionDesired ? 0x0100 : 0) | (outcome.rcode & 15))
        word(1); word(UInt16(records.count)); word(soa == nil ? 0 : 1); word(request.clientQuestion.edns == nil ? 0 : 1)
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
        if request.clientQuestion.edns != nil {
            bytes += VPNDNSAnswerCodec.optRecord(payload: UInt16(VPNDNSAnswerCodec.udpPayloadCap), rcode: outcome.rcode)
        }
        guard bytes.count <= 65535 else { throw VPNDNSAnswerError.capacity }
        if request.clientQuestion.ingress == .udp, bytes.count > request.clientQuestion.udpResponseLimit {
            // Whole RRsets omitted: no partial CNAME/address/SOA proof escapes.
            var minimal = Array(bytes.prefix(12))
            minimal[2] |= 2; minimal[6] = 0; minimal[7] = 0; minimal[8] = 0; minimal[9] = 0
            minimal += request.clientQuestion.questionBytes
            if request.clientQuestion.edns != nil {
                minimal += VPNDNSAnswerCodec.optRecord(payload: UInt16(VPNDNSAnswerCodec.udpPayloadCap), rcode: outcome.rcode)
            }
            guard minimal.count <= request.clientQuestion.udpResponseLimit else { throw VPNDNSAnswerError.capacity }
            return Data(minimal)
        }
        return Data(bytes)
    }
}

enum VPNDNSAnswerCodec {
    static let maximumRecords = 128
    static let maximumAliases = 16
    static let maximumTTL: UInt32 = 86400

    // Explicit implementation bounds. 1232 is not a discovered path MTU.
    static let udpPayloadCap = 1232
    static let maximumClientBytes = 4096
    static let maximumOptions = 64

    /// Query metadata is sealed only after the COMPLETE packet/TLV grammar.
    /// Unknown option values and reserved EDNS Z bits are ignored, not retained,
    /// echoed or forwarded. Query DO/CD and DNSSEC RRs remain unsupported.
    static func clientQuestion(_ wire: Data, resource: VPNResource,
                               ingress: VPNDNSClientIngress) throws -> VPNDNSClientQuestion {
        try resource.validate()
        guard resource.kind == .domain else { throw VPNDNSAnswerError.provenance }
        guard wire.count >= 12, wire.count <= maximumClientBytes else { throw VPNDNSAnswerError.capacity }
        var reader = Reader(bytes: Array(wire))
        let identifier = try reader.word(), flags = try reader.word()
        // RFC6840 §5.7: query AD signals interest, not a DO/CD request. Ignore
        // it; this non-validating relay neither forwards nor asserts AD.
        // https://www.rfc-editor.org/rfc/rfc6840.html#section-5.7
        if flags & 0x0010 != 0 { throw VPNDNSAnswerError.unsupportedDNSSEC }
        guard flags & 0xfedf == 0 else { throw VPNDNSAnswerError.unsupported }
        guard try reader.word() == 1 else { throw VPNDNSAnswerError.questionMismatch }
        guard try reader.word() == 0, try reader.word() == 0 else { throw VPNDNSAnswerError.unsupported }
        let additional = try reader.word()
        guard additional <= 1 else { throw VPNDNSAnswerError.unsupported }
        guard try reader.name() == resource.address else { throw VPNDNSAnswerError.questionMismatch }
        guard let type = VPNDNSQuestionType(rawValue: try reader.word()), try reader.word() == 1 else {
            throw VPNDNSAnswerError.unsupported
        }
        let questionEnd = reader.offset
        guard !reader.usedCompression else { throw VPNDNSAnswerError.malformed }
        let opt = additional == 1 ? try reader.opt(query: true) : nil
        guard reader.offset == reader.bytes.count else { throw VPNDNSAnswerError.malformed }
        guard (opt?.extendedRCODE ?? 0) == 0 else { throw VPNDNSAnswerError.unsupported }
        let edns = opt.map { VPNDNSClientEDNS(version: $0.version, advertisedUDPPayload: $0.payload) }
        return VPNDNSClientQuestion(resource: resource, transactionID: identifier, type: type,
            recursionDesired: flags & 0x0100 != 0, ingress: ingress, edns: edns,
            questionBytes: Data(reader.bytes[12..<questionEnd]))
    }

    /// An unsupported client EDNS version can produce ONLY an origin-bound
    /// BADVERS token, still requiring the normal authority/permits/leased output.
    /// Malformed queries and unsupported DNSSEC flags do not acquire this token.
    static func clientProtocolError(request: VPNDNSAnswerRequest, receivedAt: VPNDNSContinuousInstant) throws -> VPNDNSValidatedAnswer {
        guard receivedAt < request.deadline else { throw VPNDNSAnswerError.stale }
        guard let edns = request.clientQuestion.edns, edns.version != 0 else { throw VPNDNSAnswerError.provenance }
        return VPNDNSValidatedAnswer(identifier: UUID(), request: request, receivedAt: receivedAt,
            records: [], canonicalChain: [request.resource.address], addresses: [], minimumTTL: 0,
            outcome: .protocolError(.badVersion))
    }

    /// TC/oversize never validates the RR body or yields addresses/negative
    /// evidence. The bounded original question/header alone can request TCP.
    static func inspectUpstream(_ wire: Data, request: VPNDNSAnswerRequest, receivedAt: VPNDNSContinuousInstant,
                                transport: VPNDNSUpstreamTransport) throws -> VPNDNSUpstreamInspection {
        let preamble = try responsePreamble(wire, request: request, receivedAt: receivedAt)
        if preamble.flags & 0x0200 != 0 || (transport == .udp && wire.count > request.upstreamUDPLimit) {
            guard transport == .udp else { throw VPNDNSAnswerError.unsupported }
            let reason: VPNDNSNeedsTCP.Reason = preamble.flags & 0x0200 != 0 ? .truncated : .oversizedUDP
            return .needsTCP(VPNDNSNeedsTCP(request: request, receivedAt: receivedAt, reason: reason))
        }
        return .answer(try decode(wire, request: request, receivedAt: receivedAt, transport: transport))
    }

    fileprivate static func optRecord(payload: UInt16, rcode: UInt16) -> [UInt8] {
        // New per-hop OPT; VERSION=0, DO=0, options empty, never a cached RR.
        [0,0,41,UInt8(payload >> 8),UInt8(payload & 255),UInt8(rcode >> 4),0,0,0,0,0]
    }

    private static func responsePreamble(_ wire: Data, request: VPNDNSAnswerRequest,
                                         receivedAt: VPNDNSContinuousInstant) throws -> (reader: Reader, flags: UInt16, count: Int, authority: UInt16, additional: UInt16) {
        guard wire.count >= 12, wire.count <= 65535 else { throw VPNDNSAnswerError.capacity }
        guard receivedAt < request.deadline else { throw VPNDNSAnswerError.stale }
        if let edns = request.clientQuestion.edns, edns.version != 0 { throw VPNDNSAnswerError.unsupportedVersion(edns.version) }
        var reader = Reader(bytes: Array(wire))
        guard try reader.word() == request.upstreamTransactionID else { throw VPNDNSAnswerError.questionMismatch }
        let flags = try reader.word()
        guard flags & 0x8000 != 0, flags & 0x7800 == 0, flags & 0x0040 == 0 else { throw VPNDNSAnswerError.unsupported }
        if flags & 0x0010 != 0 { throw VPNDNSAnswerError.unsupportedDNSSEC }
        let questions = try reader.word(), count = Int(try reader.word())
        let authority = try reader.word(), additional = try reader.word()
        guard questions == 1 else { throw VPNDNSAnswerError.questionMismatch }
        guard try reader.name() == request.resource.address, try reader.word() == request.type.rawValue,
              try reader.word() == 1 else { throw VPNDNSAnswerError.questionMismatch }
        return (reader, flags, count, authority, additional)
    }

    /// Full answer entry requires trusted received-transport metadata as well.
    /// UDP TC/over-cap is not accepted here: use inspectUpstream for its receipt.
    static func decode(_ wire: Data, request: VPNDNSAnswerRequest, receivedAt: VPNDNSContinuousInstant,
                       transport: VPNDNSUpstreamTransport) throws -> VPNDNSValidatedAnswer {
        let preamble = try responsePreamble(wire, request: request, receivedAt: receivedAt)
        guard preamble.flags & 0x0200 == 0,
              transport == .tcp || wire.count <= request.upstreamUDPLimit else { throw VPNDNSAnswerError.unsupported }
        var reader = preamble.reader
        let count = preamble.count, authority = preamble.authority, additional = preamble.additional
        guard count <= maximumRecords else { throw VPNDNSAnswerError.capacity }
        guard authority <= 1, additional <= 1 else { throw VPNDNSAnswerError.unsupported }
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
        let opt = additional == 1 ? try reader.opt(query: false) : nil
        // RFC6891 §7 forbids unsolicited OPT for a non-EDNS query. Reject it,
        // rather than masking an extended error into NOERROR/NXDOMAIN.
        guard opt == nil || request.clientQuestion.edns != nil else { throw VPNDNSAnswerError.unsupported }
        if let opt = opt, opt.version != 0 { throw VPNDNSAnswerError.unsupportedVersion(opt.version) }
        guard reader.offset == reader.bytes.count else { throw VPNDNSAnswerError.malformed }
        // Missing OPT is an explicitly accepted legacy reply: extRCODE=0. It
        // neither claims upstream EDNS support nor triggers a downgrade/retry.
        let code = UInt16(opt?.extendedRCODE ?? 0) << 4 | (preamble.flags & 15)
        if code != 0 && code != 3 {
            guard [1,2,4,5,16].contains(code) else { throw VPNDNSAnswerError.unsupportedRCODE(code) }
            guard count == 0, authority == 0 else { throw VPNDNSAnswerError.unsupported }
            return VPNDNSValidatedAnswer(identifier: UUID(), request: request, receivedAt: receivedAt,
                records: [], canonicalChain: [request.resource.address], addresses: [], minimumTTL: 0,
                outcome: .upstreamError(code))
        }
        var chain = [request.resource.address], consumed = Set<Int>(), canonical = [VPNDNSValidatedAnswer.Record]()
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
        struct OPT {
            let payload: UInt16
            let extendedRCODE: UInt8
            let version: UInt8
        }
        mutating func opt(query: Bool) throws -> OPT {
            guard offset < bytes.count, bytes[offset] == 0 else { throw VPNDNSAnswerError.malformed }
            offset += 1
            guard try word() == 41 else { throw VPNDNSAnswerError.unsupported }
            let payload = try word(), control = try dword(), length = Int(try word())
            guard length <= VPNDNSAnswerCodec.maximumClientBytes, offset + length <= bytes.count else { throw VPNDNSAnswerError.capacity }
            let end = offset + length
            var options = 0
            while offset < end {
                guard offset + 4 <= end else { throw VPNDNSAnswerError.malformed }
                _ = try word(); let size = Int(try word())
                guard offset + size <= end else { throw VPNDNSAnswerError.malformed }
                options += 1
                guard options <= VPNDNSAnswerCodec.maximumOptions else { throw VPNDNSAnswerError.capacity }
                offset += size // Unknown well-formed option: discard opaque bytes.
            }
            // RFC6840 §5.6 requires ignoring DO in RESPONSES. Query DO stays
            // unsupported. This flag never permits DNSSEC RRs or asserts AD.
            // https://www.rfc-editor.org/rfc/rfc6840.html#section-5.6
            if query && control & 0x8000 != 0 { throw VPNDNSAnswerError.unsupportedDNSSEC }
            return OPT(payload: payload, extendedRCODE: UInt8(control >> 24), version: UInt8((control >> 16) & 255))
        }
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
