import Foundation
import Dispatch

private func dnsTime(_ value: UInt64) -> VPNDNSContinuousInstant { VPNDNSContinuousInstant(nanoseconds: value) }
private enum Failure: Error { case check }
private func require(_ value: @autoclosure () -> Bool) throws { if !value() { throw Failure.check } }
private func rejects(_ operation: () throws -> Void) throws {
    do { try operation() } catch is Failure { throw Failure.check } catch { return }
    throw Failure.check
}
private func word(_ value: UInt16) -> [UInt8] { [UInt8(value >> 8), UInt8(value & 255)] }
private func dword(_ value: UInt32) -> [UInt8] {
    [UInt8(value >> 24),UInt8((value >> 16) & 255),UInt8((value >> 8) & 255),UInt8(value & 255)]
}
private func name(_ value: String) -> [UInt8] {
    value.split(separator: ".").flatMap { [UInt8($0.utf8.count)] + Array($0.utf8) } + [0]
}
private struct RR {
    var owner = "app.corp.test", type: UInt16 = 1, ttl: UInt32 = 60
    var data: [UInt8] = [192, 0, 2, 9]
    var compressed = false
    func wire() -> [UInt8] {
        (compressed ? [0xc0, 0x0c] : name(owner)) + word(type) + word(1)
            + [UInt8(ttl >> 24), UInt8((ttl >> 16) & 255), UInt8((ttl >> 8) & 255), UInt8(ttl & 255)]
            + word(UInt16(data.count)) + data
    }
}
private func query(_ domain: String = "app.corp.test", id: UInt16 = 0x1234,
                   type: UInt16 = 1, flags: UInt16 = 0x0100) -> Data {
    var bytes = word(id) + word(flags)
    bytes += word(1) + word(0) + word(0) + word(0)
    bytes += name(domain) + word(type) + word(1)
    return Data(bytes)
}
private func request(type: VPNDNSQuestionType = .a, resource: VPNResource? = nil,
                     deadline: UInt64 = 100_000_000_000, clientRD: Bool = true,
                     originalName: String? = nil, upstreamID: UInt16 = 0x1234) throws -> VPNDNSAnswerRequest {
    let resource = try resource ?? VPNResource(address: "app.corp.test")
    let original = query(originalName ?? resource.address, type:type.rawValue,flags:clientRD ? 0x0100 : 0)
    let client = try VPNDNSAnswerCodec.clientQuestion(original,resource:resource, ingress: .udp)
    return try VPNDNSAnswerRequest(clientQuestion:client,generation:7,revision:9,
                                   upstreamTransactionID:upstreamID,deadline:dnsTime(deadline))
}

private func wire(_ request: VPNDNSAnswerRequest, _ records: [RR] = [RR()], flags: UInt16 = 0x8180,
                  authority: UInt16 = 0, additional: UInt16 = 0, questionName: String? = nil) -> Data {
    var bytes = word(request.upstreamTransactionID) + word(flags)
    bytes += word(1) + word(UInt16(records.count))
    bytes += word(authority) + word(additional)
    bytes += name(questionName ?? request.resource.address) + word(request.type.rawValue) + word(1)
    for record in records { bytes += record.wire() }
    return Data(bytes)
}
private func answer(_ request: VPNDNSAnswerRequest? = nil) throws -> VPNDNSValidatedAnswer {
    let req = try request ?? selfRequest()
    return try VPNDNSAnswerCodec.decode(wire(req), request: req, receivedAt:dnsTime(1_000_000_000), transport: .tcp)
}
private func selfRequest() throws -> VPNDNSAnswerRequest { try request() }

private final class Fake: VPNDNSAnswerReleaseAuthority, VPNDNSAnswerCheckpointSink {
    let permitIssuer = VPNDNSAnswerPermitIssuer()
    let foreign = VPNDNSAnswerPermitIssuer()
    var events = [String](), stages = [VPNDNSAnswerCheckpoint]()
    var now: UInt64 = 1_000_000_000
    var sleepAt: String?, clockFailure = false, backwards = false
    var failClockAt: VPNDNSAnswerCheckpoint?
    var active = true, leased = false, foreignPermit = false, skipLease = false, repeatLease = false
    var concurrentLease = false, swallowLeaseErrors = false
    var failStage: VPNDNSAnswerCheckpoint?, failAfterStage: VPNDNSAnswerCheckpoint?, revokeStage: VPNDNSAnswerCheckpoint?
    var denyUnknown = false, routeUnknown = false, denyObligation = false, routeObligation = false, wrongRoutePermit = false
    var other: VPNDNSValidatedAnswer?, expireDuringCheck = false
    var expected: VPNDNSAnswerRequest?
    var cachedFences = Set<String>()
    func checkCurrent(_ answer: VPNDNSValidatedAnswer) throws {
        events.append("current")
        guard active, expected == nil || expected == answer.request else { throw VPNDNSAnswerError.provenance }
        if expireDuringCheck { now = answer.request.deadline.nanoseconds }
        if backwards { now = 999_999_999 }
        if sleepAt == "current" { now += 120_000_000_000; sleepAt = nil }
    }
    func record(_ stage: VPNDNSAnswerCheckpoint, answer: VPNDNSValidatedAnswer) throws {
        events.append(stage.rawValue)
        if failStage == stage { throw VPNDNSAnswerError.checkpoint }
        stages.append(stage)
        if failClockAt == stage { clockFailure = true }
        if sleepAt == stage.rawValue { now += 120_000_000_000; sleepAt = nil }
        if failAfterStage == stage { throw VPNDNSAnswerError.checkpoint }
        if revokeStage == stage { active = false }
    }
    func establishDeny(_ answer: VPNDNSValidatedAnswer) throws -> VPNDNSBarrierPermit {
        events.append("deny"); denyObligation = true
        cachedFences.formUnion(answer.addresses.map(\.canonical))
        if sleepAt == "deny" { now += 120_000_000_000; sleepAt = nil }
        if denyUnknown { throw VPNDNSAnswerError.checkpoint }
        return (foreignPermit ? foreign : permitIssuer).barrier(for: other ?? answer)
    }
    func establishRoutes(_ answer: VPNDNSValidatedAnswer, barrier: VPNDNSBarrierPermit) throws -> VPNDNSAnswerRoutePermit {
        events.append("routes"); routeObligation = true
        if sleepAt == "routes" { now += 120_000_000_000; sleepAt = nil }
        if routeUnknown { throw VPNDNSAnswerError.checkpoint }
        return (wrongRoutePermit ? foreign : permitIssuer).routes(for: other ?? answer)
    }
    func withVerifiedLease(answer: VPNDNSValidatedAnswer, barrier: VPNDNSBarrierPermit,
                           routes: VPNDNSAnswerRoutePermit, body: () throws -> Void) throws {
        events.append("verify")
        guard active else { throw VPNDNSAnswerError.provenance }
        if skipLease { return }
        leased = true; defer { leased = false }
        if sleepAt == "verify" { now += 120_000_000_000; sleepAt = nil }
        if concurrentLease {
            withoutActuallyEscaping(body) { callback in
                DispatchQueue.concurrentPerform(iterations: 2) { _ in do { try callback() } catch {} }
            }
        } else if swallowLeaseErrors {
            do { try body() } catch {}
        } else {
            try body()
            if repeatLease { try body() }
        }
    }
    func transaction(_ answer: VPNDNSValidatedAnswer) -> VPNDNSAnswerRelease {
        VPNDNSAnswerRelease(answer: answer, authority: self, sink: self, now: {
            if self.clockFailure { throw VPNDNSContinuousClockError.unavailable }
            return dnsTime(self.now)
        })
    }
}

@main private enum Checks {
    private static func negative(_ which: String, req: VPNDNSAnswerRequest) throws {
        func soa(owner: String = "corp.test", ttl: UInt32 = 60, minimum: UInt32 = 30,
                 names: [UInt8]? = nil, suffix: [UInt8] = []) -> RR {
            let fields = [UInt32(11),22,33,44,minimum].flatMap(dword)
            return RR(owner:owner,type:6,ttl:ttl,
                      data:(names ?? (name("ns.corp.test") + name("hostmaster.corp.test"))) + fields + suffix)
        }
        func packet(_ aliases: [RR] = [], proof: RR? = nil, code: UInt16 = 3,
                    request: VPNDNSAnswerRequest? = nil) -> Data {
            let request = request ?? req
            return wire(request,aliases,flags:0x8180 | code,authority:proof == nil ? 0 : 1)
                + Data(proof?.wire() ?? [])
        }
        func parse(_ packet: Data, request: VPNDNSAnswerRequest? = nil) throws -> VPNDNSValidatedAnswer {
            try VPNDNSAnswerCodec.decode(packet,request:request ?? req,receivedAt:dnsTime(1_000_000_000), transport: .tcp)
        }
        let proof = soa()
        let nx = try parse(packet(proof:proof))
        switch which {
        case "negative-nxdomain":
            try require(nx.outcome == .nxDomain && nx.addresses.isEmpty && nx.records.isEmpty)
            let directive = try nx.negativeCacheDirective(at:dnsTime(1_000_000_000))
            try require(directive?.key == .nxDomain(terminal:req.resource.address) && directive?.remainingTTL == 30 && directive?.request == req && directive?.expiresAt == dnsTime(31_000_000_000))
        case "negative-nodata":
            for type in [VPNDNSQuestionType.a,.aaaa] {
                let request = try request(type:type)
                let result = try parse(packet(proof:proof,code:0,request:request),request:request)
                let directive = try result.negativeCacheDirective(at:dnsTime(1_000_000_000))
                try require(result.outcome == .noData && directive?.key == .noData(terminal:req.resource.address,type:type))
            }
        case "negative-cname":
            let aliases = [RR(type:5,ttl:20,data:name("edge.other.test"))]
            let result = try parse(packet(aliases,proof:soa(owner:"other.test")))
            let directive = try result.negativeCacheDirective(at:dnsTime(1_000_000_000))
            try require(result.canonicalChain == [req.resource.address,"edge.other.test"])
            try require(directive?.key == .nxDomain(terminal:"edge.other.test") && directive?.remainingTTL == 20)
            let response = try result.encoded(at:dnsTime(1_000_000_000))
            let round = try parse(response)
            try require(round.canonicalChain == result.canonicalChain && round.soa?.owner == "other.test")
        case "negative-wrong-zone":
            try rejects { _ = try parse(packet([RR(type:5,data:name("edge.other.test"))],proof:proof)) }
        case "negative-label-suffix":
            try rejects { _ = try parse(packet([RR(type:5,data:name("evil-corp.test"))],proof:proof)) }
        case "negative-no-soa":
            for code: UInt16 in [0,3] {
                try rejects { _ = try parse(packet(code:code)) }
                try rejects { _ = try parse(packet([RR(type:5,data:name("external.test"))],code:code)) }
            }
        case "negative-referral":
            try rejects { _ = try parse(packet(proof:RR(owner:"corp.test",type:2,data:name("ns.corp.test")),code:0)) }
        case "negative-soa-plus-ns", "negative-duplicate-soa":
            var bytes = Array(packet(proof:proof)); bytes[9] = 2
            bytes += (which == "negative-soa-plus-ns" ? RR(owner:"corp.test",type:2,data:name("ns.corp.test")) : proof).wire()
            try rejects { _ = try parse(Data(bytes)) }
        case "negative-positive-conflict":
            for code: UInt16 in [0,3] { try rejects { _ = try parse(packet([RR()],proof:proof,code:code)) } }
        case "negative-compressed-soa":
            var names: [UInt8] = [2] + Array("ns".utf8)
            names += [0xc0,16,10]; names += Array("hostmaster".utf8); names += [0xc0,16]
            let result = try parse(packet(proof:soa(names:names)))
            try require(result.soa?.nameserver.labels == [Data("ns".utf8),Data("corp".utf8),Data("test".utf8)])
            let round = try parse(result.encoded(at:dnsTime(1_000_000_000)))
            try require(round.soa?.nameserver == result.soa?.nameserver && round.soa?.mailbox == result.soa?.mailbox)
        case "negative-root-binary":
            // Root MNAME; binary RNAME includes a literal dot and non-UTF8 byte
            // INSIDE one label. A joined String would corrupt this mailbox.
            let names: [UInt8] = [0,3,0xff,46,0,0]
            let result = try parse(packet(proof:soa(owner:"",names:names)))
            try require(result.soa?.owner == "" && result.soa?.nameserver.labels == [])
            try require(result.soa?.mailbox.labels == [Data([0xff,46,0])])
            let round = try parse(result.encoded(at:dnsTime(1_000_000_000)))
            try require(round.soa?.mailbox == result.soa?.mailbox)
        case "negative-rdata-short":
            let bytes = packet(proof:proof)
            for size in (bytes.count - 22)..<bytes.count { try rejects { _ = try parse(Data(bytes.prefix(size))) } }
            try rejects { _ = try parse(packet(proof:RR(owner:"corp.test",type:6,data:[0xc0]))) }
        case "negative-rdata-tail": try rejects { _ = try parse(packet(proof:soa(suffix:[0]))) }
        case "negative-rdata-pointer":
            try rejects { _ = try parse(packet(proof:soa(names:[0xc0,4,0]))) }
            let rdataStart = 12 + name(req.resource.address).count + 4 + name("corp.test").count + 10
            try rejects { _ = try parse(packet(proof:soa(names:[0xc0,UInt8(rdataStart),0]))) }
        case "negative-rdata-count":
            var bytes = proof.data; bytes.removeLast()
            try rejects { _ = try parse(packet(proof:RR(owner:"corp.test",type:6,data:bytes))) }
        case "negative-ttl":
            for (ttl,minimum,expected): (UInt32,UInt32,UInt32) in [(80,12,12),(10,80,10),(0x7fff_ffff,UInt32.max,86400)] {
                let result = try parse(packet(proof:soa(ttl:ttl,minimum:minimum)))
                try require(result.minimumTTL == expected && result.soa?.minimum == minimum)
            }
        case "negative-high-bit":
            let highTTL = try parse(packet(proof:soa(ttl:0x8000_0000,minimum:30)))
            let unsignedMinimum = try parse(packet(proof:soa(ttl:60,minimum:0x8000_0000)))
            try require(highTTL.minimumTTL == 0 && unsignedMinimum.minimumTTL == 60)
        case "negative-ttl-zero":
            let result = try parse(packet(proof:soa(minimum:0)))
            try require(result.minimumTTL == 0)
            let directive = try result.negativeCacheDirective(at:dnsTime(2_000_000_000))
            try require(directive == nil)
            _ = try result.encoded(at:dnsTime(2_000_000_000))
        case "negative-aging":
            let directive = try nx.negativeCacheDirective(at:dnsTime(11_000_000_001))
            try require(directive?.remainingTTL == 19)
            let response = try nx.encoded(at:dnsTime(11_000_000_001))
            let round = try VPNDNSAnswerCodec.decode(response,request:req,receivedAt:dnsTime(11_000_000_001), transport: .tcp)
            try require(round.soa?.ttl == 19 && round.soa?.minimum == 30)
            let later = try round.negativeCacheDirective(at:dnsTime(21_000_000_001))
            let original = try nx.negativeCacheDirective(at:dnsTime(21_000_000_001))
            try require(later?.remainingTTL == 9 && later?.remainingTTL == original?.remainingTTL)
            try require(later?.key == original?.key && later?.request == original?.request)
            try require(later!.expiresAt <= original!.expiresAt)
            try rejects { _ = try nx.encoded(at:dnsTime(31_000_000_000)) }
        case "negative-upstream-errors":
            for code: UInt16 in [1,2,4,5] {
                let result = try parse(packet(code:code))
                try require(result.outcome == .upstreamError(UInt16(code)) && result.soa == nil && result.addresses.isEmpty)
                let directive = try result.negativeCacheDirective(at:dnsTime(1_000_000_000))
                try require(directive == nil)
                let encoded = try result.encoded(at:dnsTime(1_000_000_000))
                try require(encoded[3] & 15 == code)
            }
        case "negative-error-tail": try rejects { _ = try parse(packet(code:2) + Data([0])) }
        case "negative-error-sections":
            for code: UInt16 in [2,5] {
                try rejects { _ = try parse(packet(proof:proof,code:code)) }
                try rejects { _ = try parse(packet([RR()],code:code)) }
            }
        case "negative-unknown-rcode": try rejects { _ = try parse(packet(code:15)) }
        case "negative-error-origin":
            let request = try request(clientRD:false,originalName:"App.Corp.Test",upstreamID:0xabcd)
            let result = try parse(packet(code:2,request:request),request:request)
            let fake = Fake(), transaction = fake.transaction(result)
            var count = 0
            try transaction.release { bytes in
                try require(fake.leased && Array(bytes.prefix(4)) == [0x12,0x34,0x80,2])
                try require(Array(bytes.dropFirst(12)) == name("App.Corp.Test") + word(1) + word(1))
                count += 1
            }
            try require(count == 1)
        case "negative-release", "negative-release-revoke", "negative-release-required", "negative-release-fence":
            for code: UInt16 in [0,2,3,5] {
                let result = try parse(packet(proof:(code == 0 || code == 3) ? proof : nil,code:code))
                let fake = Fake()
                let old = try answer(req)
                try fake.transaction(old).release { _ in try require(fake.leased) }
                let oldFences = fake.cachedFences
                try require(oldFences == Set(["192.0.2.9"]))
                fake.stages.removeAll(); fake.events.removeAll()
                if which == "negative-release-revoke" { fake.revokeStage = .outputIssued }
                if which == "negative-release-required" { fake.skipLease = true }
                if which == "negative-release-fence" { fake.concurrentLease = true }
                var outputs = 0
                let transaction = fake.transaction(result)
                func output(_ bytes: Data) throws { try require(fake.leased); outputs += 1 }
                if which == "negative-release" { try transaction.release(output:output) }
                else { try rejects { try transaction.release(output:output) } }
                try require(outputs == ((which == "negative-release" || which == "negative-release-fence") ? 1 : 0))
                try require(fake.cachedFences == oldFences && fake.events.contains("deny") && fake.events.contains("routes") && fake.events.contains("verify"))
                try rejects { try transaction.release(output:output) }
            }
        case "negative-checkpoint-crash":
            for stage in [VPNDNSAnswerCheckpoint.received,.denyEstablished,.routesEstablished,.verified,.outputIssued,.released] {
                let fake = Fake(); fake.failAfterStage = stage
                let transaction = fake.transaction(nx); var outputs = 0
                try rejects { try transaction.release { _ in outputs += 1 } }
                try require(outputs == (stage == .released ? 1 : 0))
                try rejects { try transaction.release { _ in outputs += 1 } }
            }
        case "negative-mixed-zero-ttl":
            let result = try parse(packet([RR(type:5,ttl:5,data:name("edge.corp.test"))],proof:soa(minimum:0)))
            try rejects { _ = try result.encoded(at:dnsTime(6_000_000_000)) }
            let positive = try VPNDNSAnswerCodec.decode(wire(req,[RR(type:5,ttl:0,data:name("edge.corp.test")),RR(owner:"edge.corp.test",ttl:5)]),request:req,receivedAt:dnsTime(1_000_000_000), transport: .tcp)
            try rejects { _ = try positive.encoded(at:dnsTime(6_000_000_000)) }
        case "negative-expiry-overflow":
            let far = try request(deadline:UInt64.max)
            let result = try VPNDNSAnswerCodec.decode(packet(proof:proof,request:far),request:far,receivedAt:dnsTime(UInt64.max - 100), transport: .tcp)
            try rejects { _ = try result.negativeCacheDirective(at:dnsTime(UInt64.max - 100)) }
        case "negative-late":
            let fake = Fake(); fake.now = 31_000_000_000
            try rejects { try fake.transaction(nx).release { _ in throw Failure.check } }
            try require(fake.events.isEmpty)
        default: throw Failure.check
        }
    }

    private static func edns(_ which: String, resource: VPNResource) throws {
        func option(_ code: UInt16, _ data: [UInt8]) -> [UInt8] { word(code) + word(UInt16(data.count)) + data }
        func opt(payload: UInt16 = 1232, version: UInt8 = 0, extended: UInt8 = 0,
                 flags: UInt16 = 0, options: [UInt8] = []) -> [UInt8] {
            var bytes: [UInt8] = [0,0,41]
            bytes += word(payload); bytes += [extended,version]; bytes += word(flags)
            bytes += word(UInt16(options.count)); bytes += options; return bytes
        }
        func original(payload: UInt16 = 1232, version: UInt8 = 0, extended: UInt8 = 0,
                      flags: UInt16 = 0, options: [UInt8] = [], dnsFlags: UInt16 = 0x0100) -> Data {
            var bytes = Array(query("ApP.CoRp.TeSt",flags:dnsFlags)); bytes[11] = 1
            bytes += opt(payload:payload,version:version,extended:extended,flags:flags,options:options)
            return Data(bytes)
        }
        func request(_ data: Data? = nil, ingress: VPNDNSClientIngress = .udp) throws -> VPNDNSAnswerRequest {
            let client = try VPNDNSAnswerCodec.clientQuestion(data ?? original(),resource:resource,ingress:ingress)
            return try VPNDNSAnswerRequest(clientQuestion:client,generation:7,revision:9,upstreamTransactionID:0x1234,deadline:dnsTime(100_000_000_000))
        }
        func response(_ request: VPNDNSAnswerRequest, records: [RR] = [RR()], rcode: UInt16 = 0,
                      version: UInt8 = 0, flags: UInt16 = 0, options: [UInt8] = []) -> Data {
            var bytes = Array(wire(request,records,flags:0x8180 | (rcode & 15),additional:1))
            bytes += opt(version:version,extended:UInt8(rcode >> 4),flags:flags,options:options)
            return Data(bytes)
        }
        func decode(_ wire: Data, _ request: VPNDNSAnswerRequest, transport: VPNDNSUpstreamTransport = .tcp) throws -> VPNDNSValidatedAnswer {
            try VPNDNSAnswerCodec.decode(wire,request:request,receivedAt:dnsTime(1_000_000_000),transport:transport)
        }
        func host(encodedLength: Int, character: Character) -> String {
            var remaining = encodedLength - 2, labels = [String]()
            while remaining > 63 { labels.append(String(repeating:String(character),count:63)); remaining -= 64 }
            labels.append(String(repeating:String(character),count:remaining))
            return labels.joined(separator:".")
        }
        // Two aliases/two A records give exact client datagram boundaries without
        // padding, partial RRsets or opaque additional records.
        func records(first: Int, terminal: Int) -> [RR] {
            let a = host(encodedLength:first,character:"a"), b = host(encodedLength:terminal,character:"b")
            return [RR(type:5,data:name(a)),RR(owner:a,type:5,data:name(b)),
                    RR(owner:b),RR(owner:b,data:[192,0,2,10])]
        }
        let req = try request()
        switch which {
        case "edns-query-ad":
            for desired in [false,true] {
                for withOPT in [false,true] {
                    let flags: UInt16 = (desired ? 0x0100 : 0) | 0x0020
                    let incoming = withOPT ? original(dnsFlags:flags) : query(flags:flags)
                    let request = try request(incoming)
                    let upstream = try request.upstreamQuery()
                    try require(upstream[3] & 0x20 == 0 && (upstream[2] & 1 != 0) == desired)
                    var reply = Array(withOPT ? response(request) : wire(request))
                    reply[3] |= 0x20 // Even upstream AD is not our validation claim.
                    let answer = try decode(Data(reply),request)
                    let fake = Fake(); var outputs = 0
                    try fake.transaction(answer).release { bytes in
                        try require(fake.leased && bytes[3] & 0x20 == 0 && (bytes[2] & 1 != 0) == desired)
                        outputs += 1
                    }
                    try require(outputs == 1)
                }
            }
        case "edns-question":
            try require(req.clientQuestion.edns?.version == 0 && req.clientQuestion.edns?.advertisedUDPPayload == 1232)
            let upstream = try req.upstreamQuery()
            try require(upstream.count == query("ApP.CoRp.TeSt").count + 11 && upstream[11] == 1)
            try require(Array(upstream.dropFirst(12).prefix(name("ApP.CoRp.TeSt").count + 4)) == name("ApP.CoRp.TeSt") + word(1) + word(1))
            let parsed = try decode(response(req),req)
            let encoded = try parsed.encoded(at:dnsTime(1_000_000_000))
            try require(encoded[11] == 1 && Array(encoded.suffix(11)) == opt())
        case "edns-privacy":
            let opaque = option(8,[203,0,113,77]) + option(10,[0xde,0xad,0xbe,0xef]) + option(65001,[])
            let req = try request(original(options:opaque))
            let upstream = try req.upstreamQuery()
            try require(upstream.count == query("ApP.CoRp.TeSt").count + 11 && Array(upstream.suffix(11)) == opt())
            let parsed = try decode(response(req,options:opaque),req)
            let encoded = try parsed.encoded(at:dnsTime(1_000_000_000))
            try require(Array(encoded.suffix(11)) == opt())
        case "edns-z-bits":
            let req = try request(original(flags:0x7fff))
            let upstream = try req.upstreamQuery()
            try require(Array(upstream.suffix(11)) == opt())
            let answer = try decode(response(req,flags:0x7fff),req)
            let encoded = try answer.encoded(at:dnsTime(1_000_000_000))
            try require(Array(encoded.suffix(11)) == opt())
        case "edns-payload":
            for payload: UInt16 in [0,1,511,512,1232,4096,65535] {
                let req = try request(original(payload:payload))
                try require(req.clientQuestion.udpResponseLimit == min(max(Int(payload),512),1232))
                let upstream = try req.upstreamQuery()
                try require(Array(upstream.suffix(11)) == opt())
            }
        case "edns-client-version":
            for version: UInt8 in [1,255] {
                let req = try request(original(version:version))
                try rejects { _ = try req.upstreamQuery() }
                let error = try VPNDNSAnswerCodec.clientProtocolError(request:req,receivedAt:dnsTime(1_000_000_000))
                try require(error.outcome == .protocolError(.badVersion) && error.addresses.isEmpty)
                let encoded = try error.encoded(at:dnsTime(1_000_000_000))
                try require(encoded[3] & 15 == 0 && Array(encoded.suffix(11)) == opt(extended:1))
                let directive = try error.negativeCacheDirective(at:dnsTime(1_000_000_000))
                try require(directive == nil)
            }
            try rejects { _ = try VPNDNSAnswerCodec.clientProtocolError(request:req,receivedAt:dnsTime(1)) }
        case "edns-badvers-lease":
            let req = try request(original(version:3))
            let answer = try VPNDNSAnswerCodec.clientProtocolError(request:req,receivedAt:dnsTime(1_000_000_000))
            let fake = Fake(); fake.cachedFences = ["192.0.2.9"]
            var outputs = 0
            let transaction = fake.transaction(answer)
            try transaction.release { bytes in
                try require(fake.leased && transaction.stage == .outputIssued)
                try require(Array(bytes.suffix(11)) == opt(extended:1)); outputs += 1
            }
            try require(outputs == 1 && fake.cachedFences == ["192.0.2.9"])
            try rejects { try transaction.release { _ in outputs += 1 } }
            try require(outputs == 1)
        case "edns-upstream-version":
            try rejects { _ = try decode(response(req,version:1),req) }
        case "edns-extended-rcode":
            let error = try decode(response(req,records:[],rcode:16),req)
            try require(error.outcome == .upstreamError(16) && error.soa == nil && error.addresses.isEmpty)
            let encoded = try error.encoded(at:dnsTime(1_000_000_000))
            try require(encoded[3] & 15 == 0 && Array(encoded.suffix(11)) == opt(extended:1))
            try rejects { _ = try decode(response(req,records:[],rcode:19),req) }
            try rejects { _ = try decode(response(req,records:[RR()],rcode:16),req) }
        case "edns-legacy-opt":
            let legacy = try request(query())
            try rejects { _ = try decode(response(legacy,records:[],rcode:16),legacy) }
            let answer = try decode(wire(legacy),legacy)
            let encoded = try answer.encoded(at:dnsTime(1_000_000_000))
            try require(encoded[11] == 0)
        case "edns-legacy-upstream":
            // Explicit compatibility: no OPT from an old upstream has extRCODE0;
            // still synthesize a NEW OPT for our independent EDNS client hop.
            let answer = try decode(wire(req),req)
            let encoded = try answer.encoded(at:dnsTime(1_000_000_000))
            try require(encoded[11] == 1 && Array(encoded.suffix(11)) == opt())
        case "edns-dnssec":
            try rejects { _ = try request(original(flags:0x8000)) }
            for flags: UInt16 in [0x0110,0x0130] { try rejects { _ = try request(original(dnsFlags:flags)) } }
            // A DNSSEC RR is still unsupported even if response DO is ignored.
            try rejects { _ = try decode(response(req,records:[RR(type:46,data:[0])],flags:0x8000),req) }
        case "edns-response-do-positive":
            var reply = Array(response(req,flags:0x8000)); reply[3] |= 0x20
            let answer = try decode(Data(reply),req)
            try require(answer.outcome == .positive && answer.addresses.map(\.canonical) == ["192.0.2.9"])
            let encoded = try answer.encoded(at:dnsTime(1_000_000_000))
            try require(Array(encoded.suffix(11)) == opt() && encoded[3] & 0x20 == 0)
            try rejects { _ = try request(original(flags:0x8000)) }
        case "edns-response-do-error":
            for code: UInt16 in [2,5,16] {
                let answer = try decode(response(req,records:[],rcode:code,flags:0x8000),req)
                try require(answer.outcome == .upstreamError(code) && answer.addresses.isEmpty)
                let encoded = try answer.encoded(at:dnsTime(1_000_000_000))
                try require(Array(encoded.suffix(11)) == opt(extended:UInt8(code >> 4)) && encoded[3] & 0x20 == 0)
                let cache = try answer.negativeCacheDirective(at:dnsTime(1_000_000_000))
                try require(cache == nil)
            }
        case "edns-response-do-negative":
            let soa = RR(owner:"corp.test",type:6,ttl:60,data:name("ns.corp.test") + name("hostmaster.corp.test") + [UInt32(1),2,3,4,30].flatMap(dword))
            for code: UInt16 in [0,3] {
                var packet = Array(wire(req,[],flags:0x8180 | code,authority:1,additional:1))
                packet += soa.wire(); packet += opt(flags:0x8000)
                let answer = try decode(Data(packet),req)
                try require(answer.outcome == (code == 0 ? .noData : .nxDomain))
                let cache = try answer.negativeCacheDirective(at:dnsTime(11_000_000_000))
                try require(cache?.remainingTTL == 20 && cache?.expiresAt == dnsTime(31_000_000_000))
                let encoded = try answer.encoded(at:dnsTime(11_000_000_000))
                try require(Array(encoded.suffix(11)) == opt() && encoded[3] & 0x20 == 0)
            }
        case "edns-response-do-lease":
            let soa = RR(owner:"corp.test",type:6,ttl:60,data:name("ns.corp.test") + name("hostmaster.corp.test") + [UInt32(1),2,3,4,30].flatMap(dword))
            var negative = Array(wire(req,[],flags:0x8183,authority:1,additional:1))
            negative += soa.wire(); negative += opt(flags:0x8000)
            let answers = try [decode(response(req,flags:0x8000),req),
                               decode(response(req,records:[],rcode:2,flags:0x8000),req),
                               decode(Data(negative),req)]
            for answer in answers {
                for mode in ["allowed","no-lease","revoked","foreign","concurrent"] {
                    let fake = Fake(); fake.cachedFences = ["198.51.100.99"]
                    if mode == "no-lease" { fake.skipLease = true }
                    if mode == "revoked" { fake.revokeStage = .outputIssued }
                    if mode == "foreign" { fake.foreignPermit = true }
                    if mode == "concurrent" { fake.concurrentLease = true }
                    let transaction = fake.transaction(answer); var outputs = 0
                    func output(_ bytes: Data) throws {
                        try require(fake.leased && transaction.stage == .outputIssued)
                        try require(Array(bytes.suffix(11)) == opt() && bytes[3] & 0x20 == 0)
                        outputs += 1
                    }
                    if mode == "allowed" { try transaction.release(output:output) }
                    else { try rejects { try transaction.release(output:output) } }
                    try require(outputs == ((mode == "allowed" || mode == "concurrent") ? 1 : 0))
                    try require(fake.cachedFences.contains("198.51.100.99") && fake.events.contains("deny"))
                    if mode != "foreign" { try require(fake.events.contains("routes") && fake.events.contains("verify")) }
                    try rejects { try transaction.release(output:output) }
                }
            }
        case "edns-root-type":
            let packet = original()
            for (offset,value): (Int,UInt8) in [(packet.count - 11,1),(packet.count - 9,1)] {
                var bytes = Array(packet); bytes[offset] = value
                try rejects { _ = try request(Data(bytes)) }
            }
        case "edns-query-extended": try rejects { _ = try request(original(extended:1)) }
        case "edns-duplicate":
            var bytes = Array(original()); bytes[11] = 2; bytes += opt()
            try rejects { _ = try request(Data(bytes)) }
            var upstream = Array(response(req)); upstream[11] = 2; upstream += opt()
            try rejects { _ = try decode(Data(upstream),req) }
        case "edns-tlv-truncation":
            for opaque: [UInt8] in [[0],[0,1],[0,1,0],[0,1,0,2,9]] {
                try rejects { _ = try request(original(options:opaque)) }
                try rejects { _ = try decode(response(req,options:opaque),req) }
            }
            let packet = original(options:option(1,[1,2,3]))
            for count in (packet.count - 8)..<packet.count {
                try rejects { _ = try request(Data(packet.prefix(count))) }
            }
        case "edns-option-count":
            _ = try request(original(options:Array(repeating:option(65001,[]),count:64).flatMap{$0}))
            try rejects { _ = try request(original(options:Array(repeating:option(65001,[]),count:65).flatMap{$0})) }
        case "edns-query-bound":
            let exact = original(options:option(65001,Array(repeating:0xaa,count:4050)))
            try require(exact.count == 4096)
            _ = try request(exact)
            try rejects { _ = try request(exact + Data([0])) }
        case "edns-tail":
            try rejects { _ = try request(original() + Data([0])) }
            try rejects { _ = try decode(response(req) + Data([0]),req) }
        case "edns-slice":
            let prefix = Data([9,8,7]), data = original()
            let sliced = (prefix + data).dropFirst(prefix.count)
            let req = try request(sliced)
            try require(req.clientQuestion.resource == resource)
        case "edns-udp-boundary", "edns-legacy-boundary":
            let withOPT = which == "edns-udp-boundary"
            for delta in [-1,0,1] {
                let originalQuery = withOPT ? original() : query()
                let tcp = try request(originalQuery,ingress:.tcp)
                let udp = try request(originalQuery,ingress:.udp)
                let records = withOPT ? records(first:232 - delta,terminal:221 + delta) : records(first:56 - delta,terminal:102 + delta)
                let full = try decode(withOPT ? response(tcp,records:records) : wire(tcp,records),tcp)
                let fullBytes = try full.encoded(at:dnsTime(1_000_000_000))
                let limit = withOPT ? 1232 : 512
                try require(fullBytes.count == limit + delta)
                let outgoing = try decode(fullBytes,udp)
                let encoded = try outgoing.encoded(at:dnsTime(1_000_000_000))
                try require(encoded.count <= limit && (encoded[2] & 2 != 0) == (delta > 0))
                if delta > 0 { try require(encoded[6] == 0 && encoded[7] == 0 && encoded[8] == 0 && encoded[9] == 0) }
            }
        case "edns-small-payload":
            for payload: UInt16 in [511,512,1232,65535] {
                let request = try request(original(payload:payload))
                let answer = try decode(response(request,records:records(first:56,terminal:102)),request)
                let bytes = try answer.encoded(at:dnsTime(1_000_000_000))
                try require((bytes[2] & 2 != 0) == (payload <= 512))
                try require(bytes.count <= request.clientQuestion.udpResponseLimit)
            }
        case "edns-large-negative":
            let tcp = try request(ingress:.tcp), udp = try request()
            var aliases = [RR](), owner = resource.address
            for byte in UInt8(97)...UInt8(112) {
                let terminal = host(encodedLength:240,character:Character(UnicodeScalar(byte)))
                aliases.append(RR(owner:owner,type:5,data:name(terminal))); owner = terminal
            }
            let mname = host(encodedLength:255,character:"x"), rname = host(encodedLength:255,character:"y")
            var rdata = name(mname) + name(rname); rdata += [UInt32(1),2,3,4,30].flatMap(dword)
            let soa = RR(owner:owner,type:6,ttl:60,data:rdata)
            var packet = Array(wire(tcp,aliases,flags:0x8183,authority:1,additional:1))
            packet += soa.wire(); packet += opt()
            let full = try decode(Data(packet),tcp)
            let fullBytes = try full.encoded(at:dnsTime(1_000_000_000))
            try require(fullBytes.count > 8000 && fullBytes[2] & 2 == 0 && fullBytes[7] == 16 && fullBytes[9] == 1)
            let answer = try decode(Data(packet),udp)
            let fake = Fake(); fake.cachedFences = ["192.0.2.9"]
            var outputs = 0
            try fake.transaction(answer).release { bytes in
                try require(fake.leased && bytes[2] & 2 != 0 && bytes[7] == 0 && bytes[9] == 0 && bytes[11] == 1)
                try require(bytes.count == query("ApP.CoRp.TeSt").count + 11)
                outputs += 1
            }
            try require(outputs == 1 && fake.cachedFences == ["192.0.2.9"])
        case "edns-tcp-independent":
            let req = try request(original(payload:512),ingress:.tcp)
            let many = (0..<80).map { RR(data:[192,0,2,UInt8($0)]) }
            let answer = try decode(response(req,records:many),req)
            let bytes = try answer.encoded(at:dnsTime(1_000_000_000))
            try require(bytes.count > 1232 && bytes[2] & 2 == 0 && bytes[7] == 80)
        case "edns-upstream-tc", "edns-upstream-oversize":
            var packet = response(req)
            let expected: VPNDNSNeedsTCP.Reason
            if which == "edns-upstream-tc" {
                var bytes = Array(packet); bytes[2] |= 2
                packet = Data(bytes.prefix(34)); expected = .truncated // Incomplete RR body deliberately ignored.
            } else {
                let many = (0..<50).map { RR(data:[192,0,2,UInt8($0)]) }
                packet = response(req,records:many); expected = .oversizedUDP
            }
            switch try VPNDNSAnswerCodec.inspectUpstream(packet,request:req,receivedAt:dnsTime(1_000_000_000),transport:.udp) {
            case .needsTCP(let receipt): try require(receipt.request == req && receipt.request.deadline == dnsTime(100_000_000_000) && receipt.reason == expected)
            case .answer: throw Failure.check
            }
            try rejects { _ = try decode(packet,req,transport:.udp) }
            if which == "edns-upstream-tc" { try rejects { _ = try VPNDNSAnswerCodec.inspectUpstream(packet,request:req,receivedAt:dnsTime(1),transport:.tcp) } }
        case "edns-tc-provenance":
            var valid = Array(response(req)); valid[2] |= 2
            for offset in [0,2,4,12,29,30] {
                var invalid = valid
                if offset == 2 { invalid[2] &= 0x7f } else { invalid[offset] ^= 1 }
                try rejects { _ = try VPNDNSAnswerCodec.inspectUpstream(Data(invalid),request:req,receivedAt:dnsTime(1),transport:.udp) }
            }
            try rejects { _ = try VPNDNSAnswerCodec.inspectUpstream(Data(valid),request:req,receivedAt:req.deadline,transport:.udp) }
        case "edns-leased-tc":
            let many = (0..<50).map { RR(data:[192,0,2,UInt8($0)]) }
            let answer = try decode(response(req,records:many),req)
            let fake = Fake(); fake.cachedFences = ["198.51.100.99"]
            let transaction = fake.transaction(answer); var outputs = 0
            try transaction.release { bytes in
                try require(fake.leased && transaction.stage == .outputIssued && bytes[2] & 2 != 0 && bytes[7] == 0)
                try require(Array(bytes.suffix(11)) == opt()); outputs += 1
            }
            try require(outputs == 1 && fake.cachedFences.contains("198.51.100.99") && fake.cachedFences.count == 51)
            try rejects { try transaction.release { _ in outputs += 1 } }
        case "edns-tc-revoked":
            let answer = try decode(response(req,records:(0..<50).map { RR(data:[192,0,2,UInt8($0)]) }),req)
            let fake = Fake(); fake.revokeStage = .outputIssued
            try rejects { try fake.transaction(answer).release { _ in throw Failure.check } }
        case "edns-negative-opt":
            let soa = RR(owner:"corp.test",type:6,ttl:60,data:name("ns.corp.test") + name("hostmaster.corp.test") + [UInt32(1),2,3,4,30].flatMap(dword))
            var packet = Array(wire(req,[],flags:0x8183,authority:1,additional:1))
            packet += soa.wire(); packet += opt(options:option(8,[1,2,3]))
            let answer = try decode(Data(packet),req)
            try require(answer.outcome == .nxDomain)
            let directive = try answer.negativeCacheDirective(at:dnsTime(11_000_000_000))
            try require(directive?.remainingTTL == 20 && directive?.expiresAt == dnsTime(31_000_000_000))
            let bytes = try answer.encoded(at:dnsTime(11_000_000_000))
            try require(Array(bytes.suffix(11)) == opt())
            let fake = Fake(); fake.cachedFences = ["192.0.2.9"]
            try fake.transaction(answer).release { _ in try require(fake.leased) }
            try require(fake.cachedFences == ["192.0.2.9"])
        case "edns-inspect-complete":
            switch try VPNDNSAnswerCodec.inspectUpstream(response(req),request:req,receivedAt:dnsTime(1_000_000_000),transport:.udp) {
            case .answer(let answer): try require(answer.outcome == .positive)
            case .needsTCP: throw Failure.check
            }
        default: throw Failure.check
        }
    }

    static func main() throws {
        let which = CommandLine.arguments[1], req = try request()
        func parse(_ records: [RR], flags: UInt16 = 0x8180) throws -> VPNDNSValidatedAnswer {
            try VPNDNSAnswerCodec.decode(wire(req, records, flags: flags), request: req, receivedAt:dnsTime(1_000_000_000), transport: .tcp)
        }
        if which.hasPrefix("edns-") {
            try edns(which,resource:req.resource)
            print("pure DNS answer checks passed"); return
        }
        if which.hasPrefix("negative-") {
            try negative(which, req: req)
            print("pure DNS answer checks passed"); return
        }
        if which.hasPrefix("sleep-") || which.hasPrefix("clock-release-") {
            let long = try request(deadline: which == "sleep-zero-query" ? 20_000_000_000:1_000_000_000_000)
            let positive = try VPNDNSAnswerCodec.decode(wire(long,[RR(ttl:which == "sleep-zero-query" ? 0:30)]),request:long,receivedAt:dnsTime(1_000_000_000),transport:.tcp)
            if which == "sleep-ttl" {
                try rejects { _ = try positive.encoded(at:dnsTime(121_000_000_000)) }
            } else if which == "sleep-negative-ttl" {
                let proof = RR(owner:"corp.test",type:6,ttl:30,data:[0,0] + [UInt32(1),2,3,4,30].flatMap(dword))
                let negative = try VPNDNSAnswerCodec.decode(wire(long,[],flags:0x8183,authority:1)+Data(proof.wire()),request:long,receivedAt:dnsTime(1_000_000_000),transport:.tcp)
                try rejects { _ = try negative.negativeCacheDirective(at:dnsTime(121_000_000_000)) }
            } else {
                let fake = Fake(); fake.cachedFences = ["192.0.2.200/32"]
                if which == "sleep-zero-query" { fake.now = 121_000_000_000 }
                else if which == "clock-release-failed" { fake.clockFailure = true }
                else if which == "clock-release-checkpoint-failed" { fake.failClockAt = .outputIssued }
                else if which == "clock-release-backwards" { fake.backwards = true }
                else { fake.sleepAt = String(which.dropFirst(6)) }
                let transaction = fake.transaction(positive)
                var outputs = 0
                try rejects { try transaction.release { _ in outputs += 1 } }
                try require(outputs == 0 && fake.cachedFences.contains("192.0.2.200/32"))
                try rejects { try transaction.release { _ in outputs += 1 } }
                try require(outputs == 0)
            }
            print("pure DNS answer checks passed"); return
        }
        switch which {
        case "client-remap":
            let remapped = try request(upstreamID:0x9876)
            let upstream = Array(try remapped.upstreamQuery())
            try require(Array(upstream.prefix(2)) == [0x98,0x76])
            let parsed = try VPNDNSAnswerCodec.decode(wire(remapped),request:remapped,receivedAt:dnsTime(1), transport: .tcp)
            let response = Array(try parsed.encoded(at:dnsTime(1)))
            try require(Array(response.prefix(2)) == [0x12,0x34])
            var wrong = Array(wire(remapped)); wrong[0] = 0x12; wrong[1] = 0x34
            try rejects { _ = try VPNDNSAnswerCodec.decode(Data(wrong),request:remapped,receivedAt:dnsTime(1), transport: .tcp) }
        case "client-rd":
            for desired in [false,true] {
                let request = try request(clientRD:desired)
                let upstream = try request.upstreamQuery()
                try require(upstream[2] & 1 == (desired ? 1 : 0))
                // Intentionally DIFFERENT upstream RD cannot change client RD.
                let parsed = try VPNDNSAnswerCodec.decode(wire(request,flags:desired ? 0x8080 : 0x8180),request:request,receivedAt:dnsTime(1), transport: .tcp)
                let response = try parsed.encoded(at:dnsTime(1))
                try require(response[2] & 1 == (desired ? 1 : 0))
            }
        case "client-case":
            let request = try request(originalName:"ApP.CoRp.TeSt")
            let parsed = try VPNDNSAnswerCodec.decode(wire(request),request:request,receivedAt:dnsTime(1), transport: .tcp)
            let response = try parsed.encoded(at:dnsTime(1))
            let question = name("ApP.CoRp.TeSt") + word(1) + word(1)
            try require(Array(response.dropFirst(12).prefix(question.count)) == question)
            let upstream = try request.upstreamQuery()
            try require(Array(upstream.dropFirst(12)) == question)
        case "client-domain-boundary":
            for candidate in ["badapp.corp.test","app.corp.test.evil","other.corp.test","corp.test"] {
                try rejects { _ = try VPNDNSAnswerCodec.clientQuestion(query(candidate),resource:req.resource, ingress: .udp) }
            }
            let nonDomain = try VPNResource(address:"192.0.2.9")
            try rejects { _ = try VPNDNSAnswerCodec.clientQuestion(query(),resource:nonDomain, ingress: .udp) }
        case "client-domain-descendants":
            for original in ["app.corp.test", "mail.app.corp.test", "Deep.Mail.App.Corp.Test"] {
                for type in [VPNDNSQuestionType.a, .aaaa] {
                    let child = try request(type:type, resource:req.resource, originalName:original)
                    let canonical = original.lowercased()
                    let record = RR(owner:canonical, type:type.rawValue,
                        data:type == .a ? [192,0,2,9] : [0x20,1,0x0d,0xb8] + Array(repeating:0,count:11) + [9])
                    let decoded = try VPNDNSAnswerCodec.decode(wire(child,[record],questionName:canonical),request:child,receivedAt:dnsTime(1),transport:.tcp)
                    try require(child.resource == req.resource && decoded.canonicalChain == [canonical] && decoded.addresses.count == 1)
                    let bytes = try decoded.encoded(at:dnsTime(1))
                    let originalQuestion = name(original) + word(type.rawValue) + word(1)
                    try require(Array(bytes.dropFirst(12).prefix(originalQuestion.count)) == originalQuestion)
                }
            }
        case "client-domain-answer-boundary":
            let child = try request(resource:req.resource,originalName:"mail.app.corp.test")
            for wrong in ["app.corp.test","other.app.corp.test","deep.mail.app.corp.test"] {
                try rejects { _ = try VPNDNSAnswerCodec.decode(wire(child,[RR(owner:wrong)],questionName:wrong),request:child,receivedAt:dnsTime(1),transport:.tcp) }
            }
            // A matching question still cannot authorize unrelated parent records.
            try rejects { _ = try VPNDNSAnswerCodec.decode(wire(child,[RR()],questionName:"mail.app.corp.test"),request:child,receivedAt:dnsTime(1),transport:.tcp) }
        case "client-domain-negative":
            let domain = "mail.app.corp.test"
            let child = try request(resource:req.resource,originalName:domain)
            let fields = [UInt32(11),22,33,44,30].flatMap(dword)
            let soa = RR(owner:"corp.test",type:6,data:name("ns.corp.test") + name("hostmaster.corp.test") + fields)
            let packet = wire(child,[],flags:0x8183,authority:1,questionName:domain) + Data(soa.wire())
            let decoded = try VPNDNSAnswerCodec.decode(packet,request:child,receivedAt:dnsTime(1),transport:.tcp)
            let directive = try decoded.negativeCacheDirective(at:dnsTime(1))
            try require(decoded.request.resource == req.resource && decoded.canonicalChain == [domain] && directive?.key == .nxDomain(terminal:domain) && directive?.request == child)
        case "client-domain-error":
            let domain = "mail.app.corp.test"
            let child = try request(resource:req.resource,originalName:domain)
            let decoded = try VPNDNSAnswerCodec.decode(wire(child,[],flags:0x8182,questionName:domain),request:child,receivedAt:dnsTime(1),transport:.tcp)
            try require(decoded.outcome == .upstreamError(2) && decoded.canonicalChain == [domain] && decoded.addresses.isEmpty && decoded.request.resource == req.resource)
        case "client-domain-badvers":
            let domain = "mail.app.corp.test"
            var original = query(domain); original[11] = 1
            original += Data([0,0,41,4,208,0,1,0,0,0,0])
            let question = try VPNDNSAnswerCodec.clientQuestion(original,resource:req.resource,ingress:.udp)
            let child = try VPNDNSAnswerRequest(clientQuestion:question,generation:7,revision:9,upstreamTransactionID:99,deadline:dnsTime(1000))
            let decoded = try VPNDNSAnswerCodec.clientProtocolError(request:child,receivedAt:dnsTime(1))
            try require(decoded.outcome == .protocolError(.badVersion) && decoded.canonicalChain == [domain] && decoded.request.resource == req.resource)
        case "client-flags":
            for flag: UInt16 in [0x8000,0x0800,0x0400,0x0200,0x0080,0x0040,0x0010,0x0001] {
                try rejects { _ = try VPNDNSAnswerCodec.clientQuestion(query(flags:flag),resource:req.resource, ingress: .udp) }
            }
        case "client-sections":
            for offset in [4,6,8,10] {
                var bytes = Array(query()); bytes[offset + 1] = offset == 4 ? 2 : 1
                try rejects { _ = try VPNDNSAnswerCodec.clientQuestion(Data(bytes),resource:req.resource, ingress: .udp) }
            }
            try rejects { _ = try VPNDNSAnswerCodec.clientQuestion(wire(req),resource:req.resource, ingress: .udp) }
        case "client-types":
            for type: UInt16 in [0,5,15,255] {
                try rejects { _ = try VPNDNSAnswerCodec.clientQuestion(query(type:type),resource:req.resource, ingress: .udp) }
            }
            var bytes = Array(query()); bytes[bytes.count - 1] = 3
            try rejects { _ = try VPNDNSAnswerCodec.clientQuestion(Data(bytes),resource:req.resource, ingress: .udp) }
        case "client-bounds":
            let valid = query()
            for size in valid.indices {
                try rejects { _ = try VPNDNSAnswerCodec.clientQuestion(Data(valid.prefix(size)),resource:req.resource, ingress: .udp) }
            }
            try rejects { _ = try VPNDNSAnswerCodec.clientQuestion(valid + Data([0]),resource:req.resource, ingress: .udp) }
            try rejects { _ = try VPNDNSAnswerCodec.clientQuestion(Data(repeating:0,count:272),resource:req.resource, ingress: .udp) }
            // Forged compression into header is not a client question proof.
            var bytes = Array(valid); bytes[12] = 0xc0; bytes[13] = 4
            try rejects { _ = try VPNDNSAnswerCodec.clientQuestion(Data(bytes),resource:req.resource, ingress: .udp) }
        case "client-release":
            let request = try request(clientRD:false,originalName:"App.Corp.Test",upstreamID:0xabcd)
            let parsed = try VPNDNSAnswerCodec.decode(wire(request),request:request,receivedAt:dnsTime(1_000_000_000), transport: .tcp)
            let fake = Fake(), transaction = fake.transaction(parsed)
            var calls = 0
            try transaction.release { bytes in
                try require(fake.leased && transaction.stage == .outputIssued)
                calls += 1
                try require(Array(bytes.prefix(4)) == [0x12,0x34,0x80,0])
                let question = name("App.Corp.Test") + word(1) + word(1)
                try require(Array(bytes.dropFirst(12).prefix(question.count)) == question)
            }
            try require(calls == 1)
        case "a":
            let result = try answer(req)
            try require(result.addresses.map(\.canonical) == ["192.0.2.9"])
            try require(result.request == req && result.canonicalChain == [req.resource.address])
        case "aaaa":
            let req6 = try request(type: .aaaa), rr = RR(type: 28, data: [0x20,1,0x0d,0xb8] + [UInt8](repeating: 0, count: 11) + [9])
            let result = try VPNDNSAnswerCodec.decode(wire(req6, [rr]), request: req6, receivedAt:dnsTime(1), transport: .tcp)
            try require(result.addresses[0].canonical == "2001:db8::9")
        case "multi":
            let result = try parse([RR(), RR(data: [192,0,2,10])]); try require(result.addresses.count == 2)
            try rejects { _ = try parse([RR(), RR()]) }
        case "cname":
            let result = try parse([RR(owner: "edge.other.test", ttl: 50),
                                    RR(type: 5, ttl: 17, data: name("edge.other.test"))])
            try require(result.canonicalChain == [req.resource.address,"edge.other.test"] && result.minimumTTL == 17)
            let round = try VPNDNSAnswerCodec.decode(result.encoded(at:dnsTime(1_000_000_000)), request: req, receivedAt:dnsTime(1_000_000_000), transport: .tcp)
            try require(round.addresses == result.addresses && round.canonicalChain == result.canonicalChain)
        case "compressed-cname":
            let result = try parse([RR(type:5,data:[4] + Array("edge".utf8) + [0xc0,16]),
                                    RR(owner:"edge.corp.test", compressed:false)])
            try require(result.canonicalChain == [req.resource.address,"edge.corp.test"])
        case "compression":
            let result = try parse([RR(compressed: true)])
            try require(result.addresses.count == 1)
        case "ttl":
            let result = try parse([RR(ttl: 0x7fff_ffff)])
            try require(result.minimumTTL == 86400)
            let encoded = try result.encoded(at:dnsTime(2_000_000_001))
            let aged = try VPNDNSAnswerCodec.decode(encoded, request: req, receivedAt:dnsTime(2_000_000_001), transport: .tcp)
            try require(aged.minimumTTL == 86398)
            try rejects { _ = try answer(req).encoded(at:dnsTime(61_000_000_000)) }
        case "ttl-high-bit":
            let result = try parse([RR(ttl: UInt32.max)])
            try require(result.minimumTTL == 0)
        case "rrset-ttl":
            let result = try parse([RR(ttl: 80),RR(ttl: 15,data:[192,0,2,10])])
            let rebuilt = try VPNDNSAnswerCodec.decode(result.encoded(at:dnsTime(1_000_000_000)),request:req,receivedAt:dnsTime(1_000_000_000), transport: .tcp)
            try require(rebuilt.records.map(\.ttl) == [15,15])
        case "zero-ttl":
            let result = try parse([RR(ttl: 0)])
            _ = try result.encoded(at:dnsTime(2_000_000_000))
            try require(result.minimumTTL == 0)
        case "bounds":
            try rejects { _ = try VPNDNSAnswerCodec.decode(Data(repeating: 0, count: 65536), request: req, receivedAt:dnsTime(1), transport: .tcp) }
            try rejects { _ = try parse([RR](repeating: RR(), count: 129)) }
        case "question":
            var bytes = Array(wire(req)); bytes[0] ^= 1
            try rejects { _ = try VPNDNSAnswerCodec.decode(Data(bytes), request: req, receivedAt:dnsTime(1), transport: .tcp) }
            let other = try request(resource: VPNResource(address: "child.app.corp.test"))
            try rejects { _ = try VPNDNSAnswerCodec.decode(wire(other), request: req, receivedAt:dnsTime(1), transport: .tcp) }
        case "mutated-corpus":
            var random: UInt64 = 0x12345678
            let seed = Array(wire(req))
            for _ in 0..<2048 {
                random = random &* 6364136223846793005 &+ 1
                var bytes = seed
                let position = Int(random % UInt64(bytes.count))
                bytes[position] ^= UInt8((random >> 32) & 255)
                do {
                    let parsed = try VPNDNSAnswerCodec.decode(Data(bytes),request:req,receivedAt:dnsTime(1), transport: .tcp)
                    let rebuilt = try VPNDNSAnswerCodec.decode(parsed.encoded(at:dnsTime(1)),request:req,receivedAt:dnsTime(1), transport: .tcp)
                    try require(parsed.addresses == rebuilt.addresses && parsed.canonicalChain == rebuilt.canonicalChain)
                } catch is Failure { throw Failure.check } catch {}
            }
        case "headers":
            for flags: UInt16 in [0x0180,0x8980,0x8380,0x81c0] { try rejects { _ = try parse([RR()], flags: flags) } }
        case "pointer-loop", "pointer-foreign":
            var bytes = Array(wire(req, [RR(compressed: true)]))
            let start = 12 + name(req.resource.address).count + 4
            bytes[start + 1] = which == "pointer-loop" ? UInt8(start) : 4
            try rejects { _ = try VPNDNSAnswerCodec.decode(Data(bytes), request: req, receivedAt:dnsTime(1), transport: .tcp) }
        case "malformed":
            let valid = wire(req)
            for n in valid.indices { try rejects { _ = try VPNDNSAnswerCodec.decode(Data(valid.prefix(n)), request: req, receivedAt:dnsTime(1), transport: .tcp) } }
            try rejects { _ = try VPNDNSAnswerCodec.decode(valid + Data([0]), request: req, receivedAt:dnsTime(1), transport: .tcp) }
            try rejects { _ = try parse([RR(data: [1,2,3])]) }
        case "alias-cycle":
            try rejects { _ = try parse([RR(type: 5, data: name("edge.test")), RR(owner: "edge.test",type: 5,data: name(req.resource.address))]) }
        case "alias-conflict":
            try rejects { _ = try parse([RR(), RR(type: 5, data: name("edge.test"))]) }
        case "alias-depth":
            var records = [RR(type: 5, data: name("n0.test"))]
            for n in 0..<17 { records.append(RR(owner:"n\(n).test",type:5,data:name("n\(n+1).test"))) }
            records.append(RR(owner:"n17.test")); try rejects { _ = try parse(records) }
        case "unrelated":
            try rejects { _ = try parse([RR(), RR(owner: "unselected.test")]) }
            try rejects { _ = try parse([RR(type:5,data:name("external.test"))]) }
        case "family": try rejects { _ = try parse([RR(type:28,data:[UInt8](repeating: 0,count:16))]) }
        case "negative":
            do { _ = try parse([],flags:0x8183); throw Failure.check }
            catch VPNDNSAnswerError.unsupportedNegative {}
            let failure = try parse([],flags:0x8182)
            try require(failure.outcome == .upstreamError(2) && failure.addresses.isEmpty)
            do { _ = try parse([]); throw Failure.check }
            catch VPNDNSAnswerError.unsupportedNegative {}
        case "sections":
            for (ns, ar): (UInt16,UInt16) in [(1,0),(0,1)] {
                try rejects { _ = try VPNDNSAnswerCodec.decode(wire(req,authority:ns,additional:ar),request:req,receivedAt:dnsTime(1), transport: .tcp) }
            }
        default:
            let result = try answer(req), fake = Fake(), transaction = fake.transaction(result)
            var outputs = 0
            func output(_ bytes: Data) throws {
                try require(fake.leased && transaction.stage == .outputIssued)
                outputs += 1
                _ = try VPNDNSAnswerCodec.decode(bytes,request:req,receivedAt:dnsTime(fake.now), transport: .tcp)
                if which == "output-failure" || which == "lease-suppressed-output-error" { throw VPNDNSAnswerError.checkpoint }
            }
            switch which {
            case "release":
                try transaction.release(output: output)
                try require(fake.stages == [.received,.denyEstablished,.routesEstablished,.verified,.outputIssued,.released])
                try require(outputs == 1 && !fake.leased)
                try require(fake.events.firstIndex(of:"deny")! < fake.events.firstIndex(of:"routes")!)
                try require(fake.events.firstIndex(of:"routes")! < fake.events.firstIndex(of:"verify")!)
            case "foreign-permit": fake.foreignPermit = true
            case "other-answer": fake.other = try answer(req)
            case "revoked": fake.revokeStage = .routesEstablished
            case "late": fake.now = req.deadline.nanoseconds
            case "deny-unknown": fake.denyUnknown = true
            case "route-unknown": fake.routeUnknown = true
            case "wrong-route-permit": fake.wrongRoutePermit = true
            case "revoke-before-output": fake.revokeStage = .outputIssued
            case "checkpoint-failure", "crash-after-checkpoint":
                for stage in [VPNDNSAnswerCheckpoint.received,.denyEstablished,.routesEstablished,.verified,.outputIssued,.released] {
                    let f = Fake()
                    if which == "crash-after-checkpoint" { f.failAfterStage = stage } else { f.failStage = stage }
                    let t = f.transaction(result); var count = 0
                    try rejects { try t.release { _ in count += 1 } }
                    try require(count == (stage == .released ? 1 : 0))
                    try rejects { try t.release { _ in count += 1 } }
                    try require(count == (stage == .released ? 1 : 0))
                }
                print("pure DNS answer checks passed"); return
            case "output-failure": break
            case "one-shot":
                try transaction.release(output: output)
                try rejects { try transaction.release(output: output) }; try require(outputs == 1)
                print("pure DNS answer checks passed"); return
            case "lease-required": fake.skipLease = true
            case "lease-repeat": fake.repeatLease = true
            case "lease-concurrent": fake.concurrentLease = true
            case "lease-suppressed-output-error": fake.swallowLeaseErrors = true
            case "lease-suppressed-check-error": fake.swallowLeaseErrors = true; fake.revokeStage = .verified
            case "deadline-during-check": fake.expireDuringCheck = true
            case "changed-resource": fake.expected = try request(resource: VPNResource(address:"app.corp.test"))
            case "generation", "revision":
                fake.expected = try VPNDNSAnswerRequest(clientQuestion:req.clientQuestion,
                    generation:which == "generation" ? 8 : 7, revision:which == "revision" ? 10 : 9,
                    upstreamTransactionID:req.upstreamTransactionID,deadline:req.deadline)
            default: throw Failure.check
            }
            if which != "release" {
                try rejects { try transaction.release(output: output) }
                if which == "deny-unknown" { try require(fake.denyObligation && !fake.routeObligation && transaction.stage == .received) }
                if which == "route-unknown" { try require(fake.denyObligation && fake.routeObligation && transaction.stage == .denyEstablished) }
                try require(outputs == ((["output-failure","lease-repeat","lease-concurrent","lease-suppressed-output-error"].contains(which)) ? 1 : 0))
                try rejects { try transaction.release(output: output) }
            }
        }
        print("pure DNS answer checks passed")
    }
}
