import Foundation
import Dispatch

private enum Failure: Error { case check }
private func require(_ value: @autoclosure () -> Bool) throws { if !value() { throw Failure.check } }
private func rejects(_ operation: () throws -> Void) throws {
    do { try operation() } catch is Failure { throw Failure.check } catch { return }
    throw Failure.check
}
private func word(_ value: UInt16) -> [UInt8] { [UInt8(value >> 8), UInt8(value & 255)] }
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
private func request(type: VPNDNSQuestionType = .a, resource: VPNResource? = nil,
                     deadline: UInt64 = 100_000_000_000) throws -> VPNDNSAnswerRequest {
    try VPNDNSAnswerRequest(resource: resource ?? VPNResource(address: "app.corp.test"),
                            generation: 7, revision: 9, transactionID: 0x1234, type: type, deadline: deadline)
}
private func wire(_ request: VPNDNSAnswerRequest, _ records: [RR] = [RR()], flags: UInt16 = 0x8180,
                  authority: UInt16 = 0, additional: UInt16 = 0) -> Data {
    var bytes = word(request.transactionID) + word(flags)
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
    static func main() throws {
        let which = CommandLine.arguments[1], req = try request()
        func parse(_ records: [RR], flags: UInt16 = 0x8180) throws -> VPNDNSValidatedAnswer {
            try VPNDNSAnswerCodec.decode(wire(req, records, flags: flags), request: req, receivedAt: 1_000_000_000)
        }
        switch which {
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
            do { _ = try parse([],flags:0x8182); throw Failure.check }
            catch VPNDNSAnswerError.upstreamFailure(2) {}
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
                fake.expected = try VPNDNSAnswerRequest(resource:req.resource,
                    generation:which == "generation" ? 8 : 7, revision:which == "revision" ? 10 : 9,
                    transactionID:req.transactionID,type:req.type,deadline:req.deadline)
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
