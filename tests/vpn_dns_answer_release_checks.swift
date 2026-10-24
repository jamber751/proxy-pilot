import Foundation
import Dispatch

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
    let client = try VPNDNSAnswerCodec.clientQuestion(original,resource:resource)
    return try VPNDNSAnswerRequest(clientQuestion:client,generation:7,revision:9,
                                   upstreamTransactionID:upstreamID,deadline:deadline)
}

private func wire(_ request: VPNDNSAnswerRequest, _ records: [RR] = [RR()], flags: UInt16 = 0x8180,
                  authority: UInt16 = 0, additional: UInt16 = 0) -> Data {
    var bytes = word(request.upstreamTransactionID) + word(flags)
    bytes += word(1) + word(UInt16(records.count))
    bytes += word(authority) + word(additional)
    bytes += name(request.resource.address) + word(request.type.rawValue) + word(1)
    for record in records { bytes += record.wire() }
    return Data(bytes)
}
private func answer(_ request: VPNDNSAnswerRequest? = nil) throws -> VPNDNSValidatedAnswer {
    let req = try request ?? selfRequest()
    return try VPNDNSAnswerCodec.decode(wire(req), request: req, receivedAt: 1_000_000_000)
}
private func selfRequest() throws -> VPNDNSAnswerRequest { try request() }

private final class Fake: VPNDNSAnswerReleaseAuthority, VPNDNSAnswerCheckpointSink {
    let permitIssuer = VPNDNSAnswerPermitIssuer()
    let foreign = VPNDNSAnswerPermitIssuer()
    var events = [String](), stages = [VPNDNSAnswerCheckpoint]()
    var now: UInt64 = 1_000_000_000
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
        if expireDuringCheck { now = answer.request.deadline }
    }
    func record(_ stage: VPNDNSAnswerCheckpoint, answer: VPNDNSValidatedAnswer) throws {
        events.append(stage.rawValue)
        if failStage == stage { throw VPNDNSAnswerError.checkpoint }
        stages.append(stage)
        if failAfterStage == stage { throw VPNDNSAnswerError.checkpoint }
        if revokeStage == stage { active = false }
    }
    func establishDeny(_ answer: VPNDNSValidatedAnswer) throws -> VPNDNSBarrierPermit {
        events.append("deny"); denyObligation = true
        cachedFences.formUnion(answer.addresses.map(\.canonical))
        if denyUnknown { throw VPNDNSAnswerError.checkpoint }
        return (foreignPermit ? foreign : permitIssuer).barrier(for: other ?? answer)
    }
    func establishRoutes(_ answer: VPNDNSValidatedAnswer, barrier: VPNDNSBarrierPermit) throws -> VPNDNSAnswerRoutePermit {
        events.append("routes"); routeObligation = true
        if routeUnknown { throw VPNDNSAnswerError.checkpoint }
        return (wrongRoutePermit ? foreign : permitIssuer).routes(for: other ?? answer)
    }
    func withVerifiedLease(answer: VPNDNSValidatedAnswer, barrier: VPNDNSBarrierPermit,
                           routes: VPNDNSAnswerRoutePermit, body: () throws -> Void) throws {
        events.append("verify")
        guard active else { throw VPNDNSAnswerError.provenance }
        if skipLease { return }
        leased = true; defer { leased = false }
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
        VPNDNSAnswerRelease(answer: answer, authority: self, sink: self, now: { self.now })
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
            try VPNDNSAnswerCodec.decode(packet,request:request ?? req,receivedAt:1_000_000_000)
        }
        let proof = soa()
        let nx = try parse(packet(proof:proof))
        switch which {
        case "negative-nxdomain":
            try require(nx.outcome == .nxDomain && nx.addresses.isEmpty && nx.records.isEmpty)
            let directive = try nx.negativeCacheDirective(at:1_000_000_000)
            try require(directive?.key == .nxDomain(terminal:req.resource.address) && directive?.remainingTTL == 30 && directive?.request == req && directive?.expiresAt == 31_000_000_000)
        case "negative-nodata":
            for type in [VPNDNSQuestionType.a,.aaaa] {
                let request = try request(type:type)
                let result = try parse(packet(proof:proof,code:0,request:request),request:request)
                let directive = try result.negativeCacheDirective(at:1_000_000_000)
                try require(result.outcome == .noData && directive?.key == .noData(terminal:req.resource.address,type:type))
            }
        case "negative-cname":
            let aliases = [RR(type:5,ttl:20,data:name("edge.other.test"))]
            let result = try parse(packet(aliases,proof:soa(owner:"other.test")))
            let directive = try result.negativeCacheDirective(at:1_000_000_000)
            try require(result.canonicalChain == [req.resource.address,"edge.other.test"])
            try require(directive?.key == .nxDomain(terminal:"edge.other.test") && directive?.remainingTTL == 20)
            let response = try result.encoded(at:1_000_000_000)
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
            let round = try parse(result.encoded(at:1_000_000_000))
            try require(round.soa?.nameserver == result.soa?.nameserver && round.soa?.mailbox == result.soa?.mailbox)
        case "negative-root-binary":
            // Root MNAME; binary RNAME includes a literal dot and non-UTF8 byte
            // INSIDE one label. A joined String would corrupt this mailbox.
            let names: [UInt8] = [0,3,0xff,46,0,0]
            let result = try parse(packet(proof:soa(owner:"",names:names)))
            try require(result.soa?.owner == "" && result.soa?.nameserver.labels == [])
            try require(result.soa?.mailbox.labels == [Data([0xff,46,0])])
            let round = try parse(result.encoded(at:1_000_000_000))
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
            let directive = try result.negativeCacheDirective(at:2_000_000_000)
            try require(directive == nil)
            _ = try result.encoded(at:2_000_000_000)
        case "negative-aging":
            let directive = try nx.negativeCacheDirective(at:11_000_000_001)
            try require(directive?.remainingTTL == 19)
            let response = try nx.encoded(at:11_000_000_001)
            let round = try VPNDNSAnswerCodec.decode(response,request:req,receivedAt:11_000_000_001)
            try require(round.soa?.ttl == 19 && round.soa?.minimum == 30)
            let later = try round.negativeCacheDirective(at:21_000_000_001)
            let original = try nx.negativeCacheDirective(at:21_000_000_001)
            try require(later?.remainingTTL == 9 && later?.remainingTTL == original?.remainingTTL)
            try require(later?.key == original?.key && later?.request == original?.request)
            try require(later!.expiresAt <= original!.expiresAt)
            try rejects { _ = try nx.encoded(at:31_000_000_000) }
        case "negative-upstream-errors":
            for code: UInt16 in [1,2,4,5] {
                let result = try parse(packet(code:code))
                try require(result.outcome == .upstreamError(UInt8(code)) && result.soa == nil && result.addresses.isEmpty)
                let directive = try result.negativeCacheDirective(at:1_000_000_000)
                try require(directive == nil)
                let encoded = try result.encoded(at:1_000_000_000)
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
            try rejects { _ = try result.encoded(at:6_000_000_000) }
            let positive = try VPNDNSAnswerCodec.decode(wire(req,[RR(type:5,ttl:0,data:name("edge.corp.test")),RR(owner:"edge.corp.test",ttl:5)]),request:req,receivedAt:1_000_000_000)
            try rejects { _ = try positive.encoded(at:6_000_000_000) }
        case "negative-expiry-overflow":
            let far = try request(deadline:UInt64.max)
            let result = try VPNDNSAnswerCodec.decode(packet(proof:proof,request:far),request:far,receivedAt:UInt64.max - 100)
            try rejects { _ = try result.negativeCacheDirective(at:UInt64.max - 100) }
        case "negative-late":
            let fake = Fake(); fake.now = 31_000_000_000
            try rejects { try fake.transaction(nx).release { _ in throw Failure.check } }
            try require(fake.events.isEmpty)
        default: throw Failure.check
        }
    }

    static func main() throws {
        let which = CommandLine.arguments[1], req = try request()
        func parse(_ records: [RR], flags: UInt16 = 0x8180) throws -> VPNDNSValidatedAnswer {
            try VPNDNSAnswerCodec.decode(wire(req, records, flags: flags), request: req, receivedAt: 1_000_000_000)
        }
        if which.hasPrefix("negative-") {
            try negative(which, req: req)
            print("pure DNS answer checks passed"); return
        }
        switch which {
        case "client-remap":
            let remapped = try request(upstreamID:0x9876)
            let upstream = Array(remapped.upstreamQuery())
            try require(Array(upstream.prefix(2)) == [0x98,0x76])
            let parsed = try VPNDNSAnswerCodec.decode(wire(remapped),request:remapped,receivedAt:1)
            let response = Array(try parsed.encoded(at:1))
            try require(Array(response.prefix(2)) == [0x12,0x34])
            var wrong = Array(wire(remapped)); wrong[0] = 0x12; wrong[1] = 0x34
            try rejects { _ = try VPNDNSAnswerCodec.decode(Data(wrong),request:remapped,receivedAt:1) }
        case "client-rd":
            for desired in [false,true] {
                let request = try request(clientRD:desired)
                let upstream = request.upstreamQuery()
                try require(upstream[2] & 1 == (desired ? 1 : 0))
                // Intentionally DIFFERENT upstream RD cannot change client RD.
                let parsed = try VPNDNSAnswerCodec.decode(wire(request,flags:desired ? 0x8080 : 0x8180),request:request,receivedAt:1)
                let response = try parsed.encoded(at:1)
                try require(response[2] & 1 == (desired ? 1 : 0))
            }
        case "client-case":
            let request = try request(originalName:"ApP.CoRp.TeSt")
            let parsed = try VPNDNSAnswerCodec.decode(wire(request),request:request,receivedAt:1)
            let response = try parsed.encoded(at:1)
            let question = name("ApP.CoRp.TeSt") + word(1) + word(1)
            try require(Array(response.dropFirst(12).prefix(question.count)) == question)
            try require(Array(request.upstreamQuery().dropFirst(12)) == question)
        case "client-exact":
            for candidate in ["child.app.corp.test","other.corp.test","corp.test"] {
                try rejects { _ = try VPNDNSAnswerCodec.clientQuestion(query(candidate),resource:req.resource) }
            }
            let nonDomain = try VPNResource(address:"192.0.2.9")
            try rejects { _ = try VPNDNSAnswerCodec.clientQuestion(query(),resource:nonDomain) }
        case "client-flags":
            for flag: UInt16 in [0x8000,0x0800,0x0400,0x0200,0x0080,0x0040,0x0020,0x0010,0x0001] {
                try rejects { _ = try VPNDNSAnswerCodec.clientQuestion(query(flags:flag),resource:req.resource) }
            }
        case "client-sections":
            for offset in [4,6,8,10] {
                var bytes = Array(query()); bytes[offset + 1] = offset == 4 ? 2 : 1
                try rejects { _ = try VPNDNSAnswerCodec.clientQuestion(Data(bytes),resource:req.resource) }
            }
            try rejects { _ = try VPNDNSAnswerCodec.clientQuestion(wire(req),resource:req.resource) }
        case "client-types":
            for type: UInt16 in [0,5,15,255] {
                try rejects { _ = try VPNDNSAnswerCodec.clientQuestion(query(type:type),resource:req.resource) }
            }
            var bytes = Array(query()); bytes[bytes.count - 1] = 3
            try rejects { _ = try VPNDNSAnswerCodec.clientQuestion(Data(bytes),resource:req.resource) }
        case "client-bounds":
            let valid = query()
            for size in valid.indices {
                try rejects { _ = try VPNDNSAnswerCodec.clientQuestion(Data(valid.prefix(size)),resource:req.resource) }
            }
            try rejects { _ = try VPNDNSAnswerCodec.clientQuestion(valid + Data([0]),resource:req.resource) }
            try rejects { _ = try VPNDNSAnswerCodec.clientQuestion(Data(repeating:0,count:272),resource:req.resource) }
            // Forged compression into header is not a client question proof.
            var bytes = Array(valid); bytes[12] = 0xc0; bytes[13] = 4
            try rejects { _ = try VPNDNSAnswerCodec.clientQuestion(Data(bytes),resource:req.resource) }
        case "client-release":
            let request = try request(clientRD:false,originalName:"App.Corp.Test",upstreamID:0xabcd)
            let parsed = try VPNDNSAnswerCodec.decode(wire(request),request:request,receivedAt:1_000_000_000)
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
            let result = try VPNDNSAnswerCodec.decode(wire(req6, [rr]), request: req6, receivedAt: 1)
            try require(result.addresses[0].canonical == "2001:db8::9")
        case "multi":
            let result = try parse([RR(), RR(data: [192,0,2,10])]); try require(result.addresses.count == 2)
            try rejects { _ = try parse([RR(), RR()]) }
        case "cname":
            let result = try parse([RR(owner: "edge.other.test", ttl: 50),
                                    RR(type: 5, ttl: 17, data: name("edge.other.test"))])
            try require(result.canonicalChain == [req.resource.address,"edge.other.test"] && result.minimumTTL == 17)
            let round = try VPNDNSAnswerCodec.decode(result.encoded(at: 1_000_000_000), request: req, receivedAt: 1_000_000_000)
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
            let encoded = try result.encoded(at: 2_000_000_001)
            let aged = try VPNDNSAnswerCodec.decode(encoded, request: req, receivedAt: 2_000_000_001)
            try require(aged.minimumTTL == 86398)
            try rejects { _ = try answer(req).encoded(at: 61_000_000_000) }
        case "ttl-high-bit":
            let result = try parse([RR(ttl: UInt32.max)])
            try require(result.minimumTTL == 0)
        case "rrset-ttl":
            let result = try parse([RR(ttl: 80),RR(ttl: 15,data:[192,0,2,10])])
            let rebuilt = try VPNDNSAnswerCodec.decode(result.encoded(at:1_000_000_000),request:req,receivedAt:1_000_000_000)
            try require(rebuilt.records.map(\.ttl) == [15,15])
        case "zero-ttl":
            let result = try parse([RR(ttl: 0)])
            _ = try result.encoded(at: 2_000_000_000)
            try require(result.minimumTTL == 0)
        case "bounds":
            try rejects { _ = try VPNDNSAnswerCodec.decode(Data(repeating: 0, count: 65536), request: req, receivedAt: 1) }
            try rejects { _ = try parse([RR](repeating: RR(), count: 129)) }
        case "question":
            var bytes = Array(wire(req)); bytes[0] ^= 1
            try rejects { _ = try VPNDNSAnswerCodec.decode(Data(bytes), request: req, receivedAt: 1) }
            let other = try request(resource: VPNResource(address: "child.app.corp.test"))
            try rejects { _ = try VPNDNSAnswerCodec.decode(wire(other), request: req, receivedAt: 1) }
        case "mutated-corpus":
            var random: UInt64 = 0x12345678
            let seed = Array(wire(req))
            for _ in 0..<2048 {
                random = random &* 6364136223846793005 &+ 1
                var bytes = seed
                let position = Int(random % UInt64(bytes.count))
                bytes[position] ^= UInt8((random >> 32) & 255)
                do {
                    let parsed = try VPNDNSAnswerCodec.decode(Data(bytes),request:req,receivedAt:1)
                    let rebuilt = try VPNDNSAnswerCodec.decode(parsed.encoded(at:1),request:req,receivedAt:1)
                    try require(parsed.addresses == rebuilt.addresses && parsed.canonicalChain == rebuilt.canonicalChain)
                } catch is Failure { throw Failure.check } catch {}
            }
        case "headers":
            for flags: UInt16 in [0x0180,0x8980,0x8380,0x81c0] { try rejects { _ = try parse([RR()], flags: flags) } }
        case "pointer-loop", "pointer-foreign":
            var bytes = Array(wire(req, [RR(compressed: true)]))
            let start = 12 + name(req.resource.address).count + 4
            bytes[start + 1] = which == "pointer-loop" ? UInt8(start) : 4
            try rejects { _ = try VPNDNSAnswerCodec.decode(Data(bytes), request: req, receivedAt: 1) }
        case "malformed":
            let valid = wire(req)
            for n in valid.indices { try rejects { _ = try VPNDNSAnswerCodec.decode(Data(valid.prefix(n)), request: req, receivedAt: 1) } }
            try rejects { _ = try VPNDNSAnswerCodec.decode(valid + Data([0]), request: req, receivedAt: 1) }
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
                try rejects { _ = try VPNDNSAnswerCodec.decode(wire(req,authority:ns,additional:ar),request:req,receivedAt:1) }
            }
        default:
            let result = try answer(req), fake = Fake(), transaction = fake.transaction(result)
            var outputs = 0
            func output(_ bytes: Data) throws {
                try require(fake.leased && transaction.stage == .outputIssued)
                outputs += 1
                _ = try VPNDNSAnswerCodec.decode(bytes,request:req,receivedAt:fake.now)
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
            case "late": fake.now = req.deadline
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
