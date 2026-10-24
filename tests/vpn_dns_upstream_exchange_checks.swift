import Darwin
import Dispatch
import Foundation

@_cdecl("if_indextoname")
func exchangeInterface(_ index: UInt32, _ output: UnsafeMutablePointer<CChar>?) -> UnsafeMutablePointer<CChar>? {
    guard let output, let name = [7:"en7",42:"utun42"][index] else { return nil }
    for (index,byte) in name.utf8CString.enumerated() { output[index] = byte }; return output
}
private enum Failure: Error { case check }
private func check(_ value: @autoclosure () throws -> Bool) throws { if try !value() { throw Failure.check } }
private func rejects(_ body: () throws -> Void) throws {
    do { try body() } catch is Failure { throw Failure.check } catch { return }; throw Failure.check
}
private func word(_ value: UInt16) -> [UInt8] { [UInt8(value >> 8),UInt8(value & 255)] }
private func dword(_ value: UInt32) -> [UInt8] { [UInt8(value >> 24),UInt8((value >> 16)&255),UInt8((value >> 8)&255),UInt8(value&255)] }
private func name(_ value: String) -> [UInt8] { value.split(separator:".").flatMap{[UInt8($0.utf8.count)]+$0.utf8}+[0] }

private final class Authority: VPNDNSUpstreamAuthority {
    let expected: VPNDNSUpstreamBinding
    var valid = true, held = false
    var deadlines = [UInt64](), checks = 0
    weak var calls: Calls?
    var before: (() -> Void)?, after: (() -> Void)?
    init(_ expected: VPNDNSUpstreamBinding) { self.expected = expected }
    func withCurrentAuthority<T>(binding: VPNDNSUpstreamBinding, deadline: DispatchTime,
                                _ body: () throws -> T) throws -> T {
        try check(!held); checks += 1; deadlines.append(deadline.uptimeNanoseconds)
        before?()
        guard valid, binding == expected else { throw VPNBoundDNSUpstreamError.invalidBinding }
        held = true; defer { held = false }
        let result = try body(); after?(); return result
    }
}
private final class Calls: VPNDNSUpstreamSyscalls {
    struct State { let transport: VPNDNSUpstreamTransport; var input: Data; var output = Data(); var bound: UInt32 = 0 }
    weak var authority: Authority?
    var clock: UInt64 = 1_000_000_000, timeReads = 0
    var snapshot: VPNKernelInterfaceSnapshot
    var state: State?, created = [VPNDNSUpstreamTransport](), closed = [VPNDNSUpstreamTransport]()
    var outgoing = [Data](), endpoints = [VPNDNSUpstreamBinding](), events = [String]()
    var udp = Data(), tcp = Data(), readAgain = Set<String>(), connectAgain = Set<String>()
    var sendSteps = [Int](), pollErrors = [Int32](), polls = [Int32](), pollZero = false
    var receiveAdvance: UInt64 = 0, pollAdvance: UInt64?
    var onSocket: (() -> Void)?, onSend: (() throws -> Void)?, onPoll: (() -> Void)?, onClose: (() -> Void)?
    init(_ snapshot: VPNKernelInterfaceSnapshot) { self.snapshot = snapshot }
    var lastEvent = ""
    private func event(_ value: String) throws { try check(authority?.held == true); events.append(value); lastEvent = value }
    func now() -> UInt64 { timeReads += 1; return clock }
    func interfaces() throws -> VPNKernelInterfaceSnapshot { try event("interfaces"); return snapshot }
    func socket(family: Int32, transport: VPNDNSUpstreamTransport) throws -> Int32 {
        try event("socket"); try check(state == nil)
        created.append(transport)
        let input = transport == .udp ? udp : Data(word(UInt16(tcp.count))) + tcp
        state = State(transport:transport,input:input)
        onSocket?(); return 77 // Intentionally reused between UDP and TCP.
    }
    func configure(_ descriptor: Int32) throws { try check(descriptor == 77); try event("configure") }
    func bindInterface(_ descriptor: Int32, family: Int32, index: UInt32) throws {
        try event("bind"); try check(descriptor == 77 && index == 42); state!.bound = index
    }
    func boundInterface(_ descriptor: Int32, family: Int32) throws -> (UInt32,Int) {
        try event("getBinding"); try check(descriptor == 77); return (state!.bound,4)
    }
    func connect(_ descriptor: Int32, binding: VPNDNSUpstreamBinding) throws {
        try event("connect"); try check(descriptor == 77 && state!.bound == 42)
        endpoints.append(binding)
        let kind = state!.transport == .udp ? "udp":"tcp"
        if connectAgain.remove(kind) != nil { throw VPNBoundDNSUpstreamError.posix(EINPROGRESS) }
    }
    func connectionError(_ descriptor: Int32) throws -> Int32 { try event("connectionError"); return 0 }
    func send(_ descriptor: Int32, bytes: Data, offset: Int) throws -> Int {
        try event("send"); try check(descriptor == 77 && state!.bound == 42)
        let next = sendSteps.isEmpty ? bytes.count - offset : sendSteps.removeFirst()
        if next < 0 { throw VPNBoundDNSUpstreamError.posix(Int32(-next)) }
        try check(next > 0 && next <= bytes.count - offset)
        state!.output.append(bytes.dropFirst(offset).prefix(next)); try onSend?(); return next
    }
    func receive(_ descriptor: Int32, maximum: Int, datagram: Bool) throws -> (Data,Bool) {
        try event("receive"); try check(descriptor == 77 && datagram == (state!.transport == .udp))
        let kind = datagram ? "udp":"tcp"
        if readAgain.remove(kind) != nil { throw VPNBoundDNSUpstreamError.posix(EAGAIN) }
        let count = min(maximum,state!.input.count), bytes = Data(state!.input.prefix(count))
        state!.input.removeFirst(count); clock += receiveAdvance; return (bytes,false)
    }
    func poll(_ descriptor: Int32, events: Int16, milliseconds: Int32) throws -> Int16 {
        try check(authority?.held == false && descriptor == 77 && milliseconds > 0 && milliseconds <= 100)
        self.events.append("poll"); polls.append(milliseconds)
        clock += pollAdvance ?? UInt64(milliseconds) * 1_000_000
        onPoll?()
        if !pollErrors.isEmpty { throw VPNBoundDNSUpstreamError.posix(pollErrors.removeFirst()) }
        return pollZero ? 0:events
    }
    func close(_ descriptor: Int32) {
        precondition(authority?.held == false && descriptor == 77 && state != nil)
        events.append("close"); closed.append(state!.transport); outgoing.append(state!.output)
        state = nil; onClose?()
    }
}
@main private enum Checks {
    static func snapshot() throws -> VPNKernelInterfaceSnapshot {
        try VPNKernelInterfaceSnapshot(interfaces:[VPNKernelInterfaceRecord(index:42,name:"utun42",isUp:true,isRunning:true,isPointToPoint:true,
            addresses:[OpenVPNIPAddress(parsing:"10.255.254.1",family:.ipv4),OpenVPNIPAddress(parsing:"fd00::1",family:.ipv6)])])
    }
    static func binding(_ server: String) throws -> VPNDNSUpstreamBinding {
        var peer = in_addr(); precondition("198.51.100.9".withCString{inet_pton(AF_INET,$0,&peer)} == 1)
        let tunnel = try VPNTunnelInterfaceResolver.resolve(baseline:VPNKernelInterfaceSnapshot(interfaces:[]),after:snapshot(),
            management:OpenVPNConnectedEvidence(tunnelLocalIPv4:OpenVPNIPAddress(parsing:"10.255.254.1",family:.ipv4),
                tunnelLocalIPv6:OpenVPNIPAddress(parsing:"fd00::1",family:.ipv6),
                remoteAddress:OpenVPNIPAddress(parsing:"198.51.100.9",family:.ipv4),remotePort:443))
        let network = try VPNDomainNetworkPlan(generation:7,revision:11,resources:[VPNResource(address:"portal.corp.test")],
            corporateDNS:["10.44.0.53","2001:db8::53"],peer:VPNRoutePeerEvidence(peer:peer,gateway:nil,interfaceIndex:7),tunnel:tunnel)
        let proof = try VPNRouteAppliedProof(generation:7,revision:11,identities:VPNRouteIdentityFactory.make(plan:network.staticRoutes))
        return try VPNDNSUpstreamBinding(networkPlan:network,routeProof:proof,tunnel:tunnel,server:VPNRoutePrefix(resource:VPNResource(address:server)))
    }
    static func request(_ binding: VPNDNSUpstreamBinding, resource: VPNResource? = nil,
                        generation: UInt64 = 7, revision: UInt64 = 11, end: UInt64 = 101_000_000_000,
                        version: UInt8? = nil, questionType: VPNDNSQuestionType = .a,
                        ingress: VPNDNSClientIngress = .udp) throws -> VPNDNSAnswerRequest {
        let resource = resource ?? binding.networkPlan.domainResources[0]
        var query = word(0xabcd) + word(0x0100)
        query += word(1)+word(0)+word(0)+word(version == nil ? 0:1)
        query += name(resource.address)+word(questionType.rawValue)+word(1)
        if let version { query += [0,0,41,4,208,0,version,0,0,0,0] }
        return try VPNDNSAnswerRequest(clientQuestion:VPNDNSAnswerCodec.clientQuestion(Data(query),resource:resource,ingress:ingress),
            generation:generation,revision:revision,upstreamTransactionID:0x1234,deadline:end)
    }
    static func reply(_ request: VPNDNSAnswerRequest, truncated: Bool = false, negative: Bool = false,
                      ttl: UInt32 = 30, count: Int = 1) -> Data {
        var bytes = word(request.upstreamTransactionID)+word(truncated ? 0x8380:(negative ? 0x8183:0x8180))
        bytes += word(1)+word(UInt16(negative ? 0:count))+word(negative ? 1:0)+word(0)
        bytes += name(request.resource.address)+word(request.type.rawValue)+word(1)
        if truncated { return Data(bytes+[0xc0]) }
        if negative {
            bytes += name("corp.test")+word(6)+word(1)+dword(ttl)+word(22)
            bytes += [0,0]; bytes += [UInt32(1),2,3,4,ttl].flatMap(dword)
        } else {
            for value in 0..<count {
                let address: [UInt8] = request.type == .a ? [192,0,2,UInt8(value)] : [0x20,1,0x0d,0xb8] + [UInt8](repeating:0,count:11) + [UInt8(value)]
                bytes += [0xc0,0x0c]; bytes += word(request.type.rawValue)+word(1)
                bytes += dword(ttl); bytes += word(UInt16(address.count)); bytes += address
            }
        }
        return Data(bytes)
    }
    static func run(_ mode: String) throws {
        let bound = try binding(mode.hasSuffix("6") ? "2001:db8::53":"10.44.0.53")
        let aaaa = ["udp-aaaa","tc-aaaa","tcp-client"].contains(mode)
        var req = try request(bound,version:mode == "oversize" ? 0:nil,
            questionType:aaaa ? .aaaa:.a,ingress:mode == "tcp-client" ? .tcp:.udp)
        if mode == "binding-uuid" { req = try request(bound,resource:VPNResource(address:"portal.corp.test")) }
        if mode == "binding-host" { req = try request(bound,resource:VPNResource(id:bound.networkPlan.domainResources[0].id,address:"other.corp.test")) }
        if mode == "binding-generation" { req = try request(bound,generation:8) }
        if mode == "binding-revision" { req = try request(bound,revision:12) }
        if mode == "unsupported-version" { req = try request(bound,version:1) }
        if mode == "original-deadline" { req = try request(bound,end:1_500_000_000) }
        let authority = Authority(bound), calls = try Calls(snapshot()), token = VPNDNSUpstreamCancellation()
        calls.authority = authority; authority.calls = calls
        calls.udp = reply(req); calls.tcp = reply(req)
        if mode.hasPrefix("binding-") || mode == "unsupported-version" {
            try rejects { _ = try VPNDNSUpstreamExchange(request:req,binding:bound,authority:authority,cancellation:token,syscalls:calls) }
            try check(calls.events.isEmpty && calls.timeReads == 0); return
        }
        if mode == "server-error" {
            let req = try request(bound,version:0)
            for code: UInt16 in [2,5,16] {
                let authority = Authority(bound), calls = try Calls(snapshot()), token = VPNDNSUpstreamCancellation()
                calls.authority = authority
                var response = word(req.upstreamTransactionID)+word(0x8180 | (code & 15))
                response += word(1)+word(0)+word(0)+word(code == 16 ? 1:0)
                response += name(req.resource.address)+word(1)+word(1)
                if code == 16 { response += [0,0,41,4,208,1,0,0,0,0,0] }
                calls.udp = Data(response)
                let exchange = try VPNDNSUpstreamExchange(request:req,binding:bound,authority:authority,cancellation:token,syscalls:calls)
                let answer = try exchange.exchange()
                try check(answer.outcome == .upstreamError(code) && answer.addresses.isEmpty && calls.created.count == 1 && calls.closed.count == 1)
            }
            return
        }
        let exchange = try VPNDNSUpstreamExchange(request:req,binding:bound,authority:authority,cancellation:token,syscalls:calls)
        if mode == "init-pure" { try check(calls.events.isEmpty && calls.timeReads == 0); return }
        let fallback = ["tc4","tc6","tc-aaaa","tcp-client","tcp-tc","tcp-malformed","cancel-tcp-poll","revoked","interface-dead","partial","cancel-partial","cancel-tcp-read-poll","cancel-tcp-allocation","single-budget","original-deadline","oversize"].contains(mode)
        if fallback { calls.udp = reply(req,truncated:mode != "oversize",count:mode == "oversize" ? 100:1) }
        if mode == "tcp-tc" { calls.tcp = reply(req,truncated:true) }
        if mode == "tcp-malformed" { calls.tcp = Data([0x12,0x34,0x81,0]) }
        if mode == "malformed" { calls.udp[0] ^= 1 }
        if mode == "malformed-tc" { calls.udp = reply(req,truncated:true); calls.udp[5] = 2 }
        if mode == "transport" { calls.sendSteps = [-Int(EIO)] }
        if mode == "expired" { calls.clock = req.deadline }
        if mode == "pre-cancel" { token.cancel() }
        if mode == "cancel-allocation" || mode == "cancel-tcp-allocation" {
            calls.onSocket = { if mode == "cancel-allocation" || calls.created.count == 2 { token.cancel() } }
        }
        if mode == "authority-overrun" { authority.before = { calls.clock += 30_000_000_000 } }
        if mode == "cancel-udp-poll" || mode == "cancel-tcp-poll" || mode == "cancel-tcp-read-poll" {
            calls.readAgain = [mode == "cancel-udp-poll" ? "udp":"tcp"]
            if mode == "cancel-tcp-poll" { calls.connectAgain = ["tcp"] }
            calls.pollZero = true; calls.onPoll = { token.cancel() }
        }
        if mode == "cancel-partial" {
            calls.sendSteps = [try req.upstreamQuery().count,2]
            calls.onSend = { if calls.state!.transport == .tcp { token.cancel() } }
        }
        if mode == "revoked" { calls.onClose = { if calls.closed.count == 1 { authority.valid = false } } }
        if mode == "interface-dead" { calls.onClose = { if calls.closed.count == 1 { calls.snapshot = try! VPNKernelInterfaceSnapshot(interfaces:[]) } } }
        if mode == "partial" { calls.sendSteps = [try req.upstreamQuery().count,1,-Int(EINTR),-Int(EAGAIN),2]; calls.connectAgain = ["tcp"] }
        if mode == "poll-timeout" || mode == "poll-zero-ready" {
            calls.readAgain = ["udp"]; calls.pollZero = true
            if mode == "poll-zero-ready" { calls.onPoll = { if calls.polls.count == 3 { calls.pollZero = false } } }
        }
        if mode == "poll-retry" || mode == "poll-cancel-retry" {
            calls.readAgain = ["udp"]; calls.pollErrors = [EINTR,EAGAIN]
            if mode == "poll-cancel-retry" { calls.onPoll = { token.cancel() } }
        }
        if mode == "single-budget" || mode == "original-deadline" {
            calls.onClose = { if calls.closed.count == 1 { calls.clock = mode == "single-budget" ? 21_000_000_000:req.deadline } }
        }
        if mode.hasPrefix("slow-") || mode.hasPrefix("expired-") && mode != "expired" {
            let expired = mode.hasPrefix("expired-")
            calls.udp = reply(req,negative:mode.hasSuffix("negative"),ttl:expired ? 5:30)
            authority.after = { if calls.lastEvent == "receive" { calls.clock += 10_000_000_000 } }
        }
        if mode == "reentrant" { calls.onSend = { try rejects { _ = try exchange.exchange() } } }
        if mode == "close-busy" {
            var socket: VPNBoundDNSUpstreamSocket? = try VPNBoundDNSUpstreamSocket.prepare(binding:bound,transport:.udp,
                authority:authority,deadline:DispatchTime(uptimeNanoseconds:req.deadline),syscalls:calls)
            calls.onSend = { do { try socket!.close(); throw Failure.check } catch VPNBoundDNSUpstreamError.busy {} }
            _ = try socket!.exchange(question:req.upstreamQuery(),deadline:DispatchTime(uptimeNanoseconds:req.deadline))
            try check(calls.closed.isEmpty); try socket!.close(); socket = nil
            try check(calls.closed.count == 1); return
        }
        if mode == "concurrent" {
            let lock = NSLock(); var successes = 0, used = 0
            DispatchQueue.concurrentPerform(iterations:2) { _ in
                do { _ = try exchange.exchange(); lock.lock(); successes += 1; lock.unlock() }
                catch VPNDNSUpstreamExchangeError.alreadyUsed { lock.lock(); used += 1; lock.unlock() }
                catch { }
            }
            try check(successes == 1 && used == 1 && calls.created.count == 1 && calls.closed.count == 1); return
        }
        let failure = ["malformed","malformed-tc","transport","tcp-tc","tcp-malformed","single-budget","original-deadline","expired","pre-cancel","cancel-allocation","cancel-tcp-allocation","authority-overrun","cancel-udp-poll","cancel-tcp-poll","cancel-tcp-read-poll","cancel-partial","revoked","interface-dead","poll-cancel-retry","poll-timeout","expired-positive","expired-negative"].contains(mode)
        var answer: VPNDNSValidatedAnswer?
        if failure { try rejects { _ = try exchange.exchange() } }
        else { answer = try exchange.exchange() }
        try rejects { _ = try exchange.exchange() }
        try check(calls.state == nil && calls.created.count == calls.closed.count)
        try check(calls.endpoints.allSatisfy{$0 == bound})
        try check(Set(authority.deadlines).count <= 1)
        let expectedEnd = min(req.deadline,21_000_000_000)
        try check(authority.deadlines.allSatisfy{$0 == expectedEnd})
        if ["expired","pre-cancel","authority-overrun"].contains(mode) { try check(calls.created.isEmpty) }
        if ["cancel-allocation","malformed","malformed-tc","transport","cancel-udp-poll","revoked","interface-dead","poll-cancel-retry","poll-timeout","single-budget","original-deadline"].contains(mode) { try check(calls.created.count == 1) }
        if ["cancel-udp-poll","cancel-tcp-poll","cancel-tcp-read-poll","poll-cancel-retry"].contains(mode) { try check(calls.polls == [100]) }
        if ["udp4","udp6","one-shot","reentrant","poll-retry","slow-positive","slow-negative"].contains(mode) { try check(calls.created.count == 1) }
        if mode == "cancel-partial" {
            try check(calls.created.count == 2 && calls.outgoing[1].count == 2)
        }
        if mode == "cancel-allocation" { try check(!calls.events.contains("configure")) }
        if mode == "cancel-tcp-allocation" {
            try check(calls.created.count == 2 && calls.closed.count == 2 && calls.events.filter{$0 == "configure"}.count == 1)
        }
        if mode == "poll-timeout" { try check(calls.polls.count == 200 && calls.polls.reduce(0,+) == 20_000) }
        if mode == "poll-zero-ready" { try check(calls.polls == [100,100,100]) }
        if !failure {
            try check(answer?.request == req)
            if fallback { try check(calls.created.count == 2 && calls.closed.count == 2) }
            let query = try req.upstreamQuery()
            if aaaa {
                try check(answer!.request.type == .aaaa && answer!.addresses.count == 1 && answer!.addresses[0].family == .ipv6 && answer!.addresses[0].bytes.count == 16)
                try check(answer!.request.clientQuestion.ingress == (mode == "tcp-client" ? .tcp:.udp))
                // Independent wire checks, beyond comparing the shared encoder.
                try check(Array(calls.outgoing[0].suffix(4)) == [0,28,0,1])
                if fallback { try check(Array(calls.outgoing[1].suffix(4)) == [0,28,0,1]) }
                let encoded = Array(try answer!.encoded(at:calls.clock)), questionStart = 12 + name(req.resource.address).count
                try check(Array(encoded.prefix(2)) == [0xab,0xcd])
                try check(Array(encoded[questionStart..<questionStart+4]) == [0,28,0,1])
                try check(calls.created.count == (fallback ? 2:1))
            }
            try check(calls.outgoing[0] == query)
            if calls.outgoing.count == 2 { try check(calls.outgoing[1] == Data(word(UInt16(query.count))) + query) }
        }
        if mode == "slow-positive" || mode == "slow-negative" {
            try check(answer?.receivedAt == 1_000_000_000)
            if mode == "slow-negative" {
                let cache = try answer!.negativeCacheDirective(at:calls.clock)
                try check(cache?.remainingTTL == 20 && cache?.expiresAt == 31_000_000_000)
            } else {
                let bytes = Array(try answer!.encoded(at:calls.clock)), offset = bytes.count - 10
                let ttl = UInt32(bytes[offset]) << 24 | UInt32(bytes[offset+1]) << 16 | UInt32(bytes[offset+2]) << 8 | UInt32(bytes[offset+3])
                try check(ttl == 20)
            }
        }
    }
    static func main() {
        do { try run(CommandLine.arguments[1]); print("pure bound DNS exchange checks passed") }
        catch { print("pure bound DNS exchange failure"); exit(1) }
    }
}
